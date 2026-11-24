# siem-api on Linux, for container installs (NDR's stack runs it as the platform server).
# Build context: the repository root (see the root .dockerignore).
FROM rust:1-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev build-essential cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build/wazuh-rust-angular/backend-rust
COPY wazuh-rust-angular/backend-rust/Cargo.toml wazuh-rust-angular/backend-rust/Cargo.lock ./
COPY wazuh-rust-angular/backend-rust/crates ./crates
# files compiled into siem-api (the agent kit's scripts, configuration-check rules)
COPY wazuh-rust-angular/backend-rust/deploy ./deploy
COPY wazuh-rust-angular/backend-rust/ruleset/sca ./ruleset/sca
COPY wazuh-rust-angular/backend-rust/specs/sca-manifest ./specs/sca-manifest
# old-code/ is only a test-only (dev-dependency) reference for comparison tests, not part of any
# program; it is not copied, so those references go
RUN sed -i '/old-code\//d' crates/*/Cargo.toml
# a big crate: few parallel jobs keep the build inside a small Docker VM's memory
ARG JOBS=4
RUN cargo build --release -j ${JOBS} -p siem-api

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates wget libssl3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/wazuh-rust-angular/backend-rust/target/release/siem-api /usr/local/bin/siem-api
COPY wazuh-rust-angular/backend-rust/data/sigma /app/data/sigma
# The platform role: cases, settings, admin, SIEM pages' API. PROVIGIL_MANAGER=0 = without the
# SIEM's own log pipeline (set it to 1 where SIEM agents report to this install).
ENV SIEM_PORT=8088 PROVIGIL_MANAGER=0
EXPOSE 8088
HEALTHCHECK CMD wget -q --spider http://127.0.0.1:8088/api/health || exit 1
CMD ["siem-api"]
