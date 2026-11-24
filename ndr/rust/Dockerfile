
# ── Build stage ────────────────────────────────────────────────────
# Build context: the repository root (one codebase with the SIEM; the shared crates live in
# wazuh-rust-angular/backend-rust/crates). The repository layout is recreated under /build.
FROM rust:1-bookworm AS builder

WORKDIR /app

ARG CACHEBUST=1

COPY wazuh-rust-angular/backend-rust/crates/provigil-common /build/wazuh-rust-angular/backend-rust/crates/provigil-common
COPY ndr/rust/ndr-engine /build/ndr/rust/ndr-engine

WORKDIR /build/ndr/rust/ndr-engine

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

COPY --from=builder /build/ndr/rust/ndr-engine/target/release/ndr-engine .

CMD ["/app/ndr-engine/ndr-engine"]
