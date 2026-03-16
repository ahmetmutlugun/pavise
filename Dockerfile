# ── Build stage ──────────────────────────────────────────────────────────────
FROM rust:1.84-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cargo build --release --bin quickscan-server

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# ca-certs for outbound HTTPS (ip-api.com geolocation); fonts for Typst PDF
RUN apt-get update && apt-get install -y \
    ca-certificates \
    fonts-dejavu-core \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/quickscan-server /app/quickscan-server
COPY rules/  /app/rules/
COPY data/   /app/data/
# templates/ is embedded at compile time via include_str! — no runtime copy needed

EXPOSE 3000

CMD ["/app/quickscan-server"]
