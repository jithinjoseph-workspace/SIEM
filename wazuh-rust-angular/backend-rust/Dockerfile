# Multi-stage Dockerfile for high-performance Rust SIEM API microservice
FROM rust:1.80-slim-bookworm as builder

WORKDIR /usr/src/app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev build-essential g++ && rm -rf /var/lib/apt/lists/*

# Copy workspace source files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY ruleset ./ruleset

# Build optimized release binary
RUN cargo build --release -p siem-api

# Minimal runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates curl libstdc++6 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary and detection rules from builder
COPY --from=builder /usr/src/app/target/release/siem-api /app/siem-api
COPY --from=builder /usr/src/app/ruleset /app/ruleset

EXPOSE 8088

ENV RUST_LOG=info
ENV SIEM_PORT=8088

CMD ["/app/siem-api"]
