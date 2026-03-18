# ── Build stage ──────────────────────────────────────────────────────────────
FROM rust:1.88-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cargo build --release --bin pavise-server

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/ahmetmutlugun/pavise"
LABEL org.opencontainers.image.description="Fast iOS IPA static security analyzer"
LABEL org.opencontainers.image.licenses="MIT"

# ca-certs for outbound HTTPS (ip-api.com geolocation); fonts for Typst PDF
RUN apt-get update && apt-get install -y \
    ca-certificates \
    fonts-dejavu-core \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/pavise-server /app/pavise-server
COPY rules/  /app/rules/
COPY data/   /app/data/
# templates/ is embedded at compile time via include_str! — no runtime copy needed

# Upload/temp directory — mount a volume here for large file support
RUN mkdir -p /app/uploads
ENV PAVISE_UPLOAD_DIR=/app/uploads

EXPOSE 3000

CMD ["/app/pavise-server"]
