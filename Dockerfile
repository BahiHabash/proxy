# ─── Build stage ──────────────────────────────────────────────
FROM rust:1.94-slim AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./

# Cache dependencies
RUN mkdir src tests && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs && \
    cargo test && \
    cargo build --release && \
    rm -r src tests

# Build real source
COPY src/ src/
COPY tests/ tests/

RUN touch src/main.rs src/lib.rs
RUN cargo test
RUN cargo build --release

# ─── Runtime stage ────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/proxy /usr/local/bin/proxy

EXPOSE 1080

ENTRYPOINT ["proxy"]
