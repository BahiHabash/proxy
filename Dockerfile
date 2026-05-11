# ─── Build stage ──────────────────────────────────────────────
FROM rust:1.94-slim AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY tests/ tests/

RUN cargo test
RUN cargo build --release

# ─── Runtime stage ────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/socks5-proxy /usr/local/bin/socks5-proxy

EXPOSE 1080

ENTRYPOINT ["socks5-proxy"]
