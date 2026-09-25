# syntax=docker/dockerfile:1
# Cache mounts persist between builds. Railway requires ids of the form
# s/<service id>-<path> with the service id written literally (no ARG/env).
# Service `pavise` in project incredible-clarity:
# 2bd6af3c-a9aa-4a51-b465-7715a71780b6
# Other builders (docker compose, local) treat them as plain cache names.

# ── Frontend build stage ─────────────────────────────────────────────────────
FROM node:22-slim AS frontend

WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN --mount=type=cache,id=s/2bd6af3c-a9aa-4a51-b465-7715a71780b6-/root/.npm,target=/root/.npm \
    npm ci
COPY web/ .
RUN npm run build

# ── Rust build stage ────────────────────────────────────────────────────────
FROM rust:1.88-slim AS builder

WORKDIR /app

# Cargo's download cache and target/ persist across builds, so a deploy
# recompiles only what changed (a dependency bump rebuilds just that crate).
# target/ lives in the cache, so the binary is copied out in the same step.
# Touch the crate's sources and embedded files (include_str!/include_bytes!):
# a checkout or upload can carry mtimes older than the cached build, and cargo
# decides freshness by mtime.
# On small (4 GB) build hosts, set CARGO_BUILD_JOBS=2 to avoid OOM.
COPY . .
RUN --mount=type=cache,id=s/2bd6af3c-a9aa-4a51-b465-7715a71780b6-/usr/local/cargo/registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=s/2bd6af3c-a9aa-4a51-b465-7715a71780b6-/usr/local/cargo/git,target=/usr/local/cargo/git \
    --mount=type=cache,id=s/2bd6af3c-a9aa-4a51-b465-7715a71780b6-/app/target,target=/app/target,sharing=locked \
    find src rules templates assets Cargo.toml -type f -exec touch {} + \
    && cargo build --release --bin pavise-server \
    && cp target/release/pavise-server /usr/local/bin/pavise-server

# ── Runtime stage ───────────────────────────────────────────────────────────
FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/ahmetmutlugun/pavise"
LABEL org.opencontainers.image.description="Fast iOS IPA static security analyzer"
LABEL org.opencontainers.image.licenses="MIT"

# ca-certs for outbound HTTPS (ip-api.com geolocation); chromium prints the
# PDF report (templates/report.pdf.tera, fonts embedded; DejaVu/Liberation cover non-Latin fallback);
# wget is used by the HEALTHCHECK below to probe /healthz.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    chromium \
    fonts-dejavu-core \
    fonts-liberation \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Point headless_chrome at the distro browser (it reads $CHROME).
ENV CHROME=/usr/bin/chromium

WORKDIR /app

COPY --from=builder /usr/local/bin/pavise-server /app/pavise-server
COPY --from=frontend /app/web/dist /app/web/dist
COPY rules/  /app/rules/
COPY data/   /app/data/

# Upload/temp directory — mount a volume here for large file support.
# File logging is opt-in (PAVISE_LOG_DIR, set by docker-compose.yml); on
# Railway stderr is already captured, so the image doesn't write log files.
RUN mkdir -p /app/uploads /app/logs
ENV PAVISE_UPLOAD_DIR=/app/uploads
ENV PAVISE_DIST_DIR=/app/web/dist

# glibc malloc tuning: a fixed mmap threshold returns freed scan buffers to
# the OS instead of keeping them in heap arenas, and two arenas stop
# per-thread fragmentation. Measured on 8 CPUs: RSS after scans 280 MB -> 24 MB,
# peak over 4 concurrent scans 681 MB -> 399 MB, same scan times.
ENV MALLOC_ARENA_MAX=2 \
    MALLOC_MMAP_THRESHOLD_=131072 \
    MALLOC_TRIM_THRESHOLD_=131072

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- --tries=1 --timeout=4 http://127.0.0.1:3000/healthz || exit 1

CMD ["/app/pavise-server"]
