# ── Frontend build stage ─────────────────────────────────────────────────────
FROM node:22-slim AS frontend

WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci
COPY web/ .
RUN npm run build

# ── Rust build stage ────────────────────────────────────────────────────────
FROM rust:1.88-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Limit parallelism to survive 4GB VM builds
RUN CARGO_BUILD_JOBS=2 cargo build --release --bin pavise-server

# ── Runtime stage ───────────────────────────────────────────────────────────
FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/ahmetmutlugun/pavise"
LABEL org.opencontainers.image.description="Fast iOS IPA static security analyzer"
LABEL org.opencontainers.image.licenses="MIT"

# ca-certs for outbound HTTPS (ip-api.com geolocation); fonts for Typst PDF;
# wget is used by the HEALTHCHECK below to probe /healthz.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    fonts-dejavu-core \
    fonts-liberation \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/pavise-server /app/pavise-server
COPY --from=frontend /app/web/dist /app/web/dist
COPY rules/  /app/rules/
COPY data/   /app/data/

# Upload/temp directory — mount a volume here for large file support
RUN mkdir -p /app/uploads /app/logs
ENV PAVISE_UPLOAD_DIR=/app/uploads
ENV PAVISE_LOG_DIR=/app/logs
ENV PAVISE_DIST_DIR=/app/web/dist

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- --tries=1 --timeout=4 http://127.0.0.1:3000/healthz || exit 1

CMD ["/app/pavise-server"]
