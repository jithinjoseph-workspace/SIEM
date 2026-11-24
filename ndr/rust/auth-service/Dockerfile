# Build context: ./rust  (one level above this file)
FROM rust:1-bookworm AS builder
WORKDIR /app

COPY provigil-common ./provigil-common
COPY auth-service    ./auth-service

WORKDIR /app/auth-service

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/auth-service/target/release/auth-service /usr/local/bin/auth-service
EXPOSE 3001
CMD ["auth-service"]
