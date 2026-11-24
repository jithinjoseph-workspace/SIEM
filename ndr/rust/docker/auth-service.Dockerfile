# Build context: the repository root (one codebase with the SIEM; the shared crates live in
# wazuh-rust-angular/backend-rust/crates). The repository layout is recreated under /build.
FROM rust:1-bookworm AS builder
COPY wazuh-rust-angular/backend-rust/crates/provigil-common /build/wazuh-rust-angular/backend-rust/crates/provigil-common
COPY wazuh-rust-angular/backend-rust/crates/auth-service /build/wazuh-rust-angular/backend-rust/crates/auth-service

WORKDIR /build/wazuh-rust-angular/backend-rust/crates/auth-service

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/wazuh-rust-angular/backend-rust/crates/auth-service/target/release/auth-service /usr/local/bin/auth-service
EXPOSE 3001
CMD ["auth-service"]
