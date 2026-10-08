# Build context: ./rust  (one level above this file)
FROM rust:1-bookworm AS builder
WORKDIR /app

COPY provigil-common ./provigil-common
COPY siem-engine     ./siem-engine

WORKDIR /app/siem-engine

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev build-essential cmake \
    libsasl2-dev libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget libssl3 libsasl2-2 libcurl4 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/siem-engine/target/release/siem-engine /usr/local/bin/siem-engine
EXPOSE 3002
CMD ["siem-engine"]
