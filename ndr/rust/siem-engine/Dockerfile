# Build context: the repository root (one codebase with the SIEM; the shared crates live in
# wazuh-rust-angular/backend-rust/crates). The repository layout is recreated under /build.
FROM rust:1-bookworm AS builder
COPY wazuh-rust-angular/backend-rust/crates/provigil-common /build/wazuh-rust-angular/backend-rust/crates/provigil-common
COPY ndr/rust/siem-engine /build/ndr/rust/siem-engine

WORKDIR /build/ndr/rust/siem-engine

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev build-essential cmake \
    libsasl2-dev libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget libssl3 libsasl2-2 libcurl4 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/ndr/rust/siem-engine/target/release/siem-engine /usr/local/bin/siem-engine
EXPOSE 3002
CMD ["siem-engine"]
