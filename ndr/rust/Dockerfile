
# ── Build stage ────────────────────────────────────────────────────
FROM rust:1-bookworm AS builder

WORKDIR /app

ARG CACHEBUST=1

COPY provigil-common ./provigil-common
COPY ndr-engine      ./ndr-engine

WORKDIR /app/ndr-engine

RUN apt-get update && apt-get install -y \
    cmake libssl-dev pkg-config \
    libsasl2-dev build-essential libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release

# ── Runtime stage ──────────────────────────────────────────────────
FROM docker:cli AS docker-cli

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 libsasl2-2 libcurl4 curl \
    zstd tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

WORKDIR /app/ndr-engine

COPY --from=builder /app/ndr-engine/target/release/ndr-engine .

CMD ["/app/ndr-engine/ndr-engine"]
