# siem-api on Linux, for container installs (NDR's stack runs it as the platform server), with
# what SIEM agents need beside it: the agents' gateway (gRPC 8089, TLS 8443), the manager's
# programs (agent database, rules engine, modules, responses, agentless), the default ruleset and
# the agent package the console's install command downloads. Same set as the Windows MSI.
# Build context: the repository root (see the root .dockerignore).
# the Rust the workspace is built and checked with here (a newer one adds new warnings)
FROM rust:1.98-bookworm AS src
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

FROM src AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev build-essential cmake \
    && rm -rf /var/lib/apt/lists/*
RUN cargo build --release -j ${JOBS} -p siem-api -p provigil-gateway -p provigil-agentdb \
    -p provigil-analysisd -p provigil-modulesd -p provigil-execd -p provigil-agentlessd \
    -p siem-active-response

# the Windows agent package (cross-built, as tools/build-winagent.sh does)
FROM src AS winagent
RUN apt-get update && apt-get install -y gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 cmake perl make \
    && rm -rf /var/lib/apt/lists/* && rustup target add x86_64-pc-windows-gnu
ENV CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
    CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc \
    CXX_x86_64_pc_windows_gnu=x86_64-w64-mingw32-g++ \
    AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar
RUN cargo build --release -j ${JOBS} --target x86_64-pc-windows-gnu -p provigil-agent -p siem-active-response \
    && mkdir /out && cd target/x86_64-pc-windows-gnu/release \
    && cp provigil-agent.exe netsh.exe restart-agent.exe route-null.exe kill-process.exe quarantine-file.exe \
          isolate-host.exe yara-scan.exe live-response.exe tamper-protect.exe /out/

FROM debian:bookworm-slim
# expect: the agentless monitoring scripts
RUN apt-get update && apt-get install -y ca-certificates wget libssl3 expect && rm -rf /var/lib/apt/lists/*
# The manager's service user: the rules engine and agentless monitoring drop to it. Its home is
# group provigil with set-group-ID folders, so what the root programs make there (sockets, logs)
# is the group's too (siem-api-start sets umask 002 and fixes an older volume).
RUN groupadd -r provigil && useradd -r -g provigil -d /app/data/manager -s /usr/sbin/nologin provigil \
    && mkdir -p /app/data/manager /app/data/tls && chown root:provigil /app/data/manager && chmod 2775 /app/data/manager
WORKDIR /app
ARG REL=/build/wazuh-rust-angular/backend-rust/target/release
COPY --from=builder ${REL}/siem-api ${REL}/provigil-gateway ${REL}/provigil-db ${REL}/provigil-analysisd \
     ${REL}/provigil-modulesd ${REL}/provigil-execd ${REL}/provigil-agentlessd ${REL}/provigil-mitredb \
     ${REL}/firewall-drop /usr/local/bin/
# the default ruleset siem-api copies into the manager's home on every start (PROVIGIL_SOURCE_DIR)
ARG B=wazuh-rust-angular/backend-rust
COPY ${B}/ruleset/decoders /app/ruleset-src/ruleset/decoders
COPY ${B}/ruleset/rules /app/ruleset-src/ruleset/rules
COPY ${B}/ruleset/lists /app/ruleset-src/ruleset/lists
COPY ${B}/ruleset/mitre /app/ruleset-src/ruleset/mitre
COPY ${B}/etc/internal_options.conf ${B}/etc/local_decoder.xml ${B}/etc/local_rules.xml /app/ruleset-src/etc/
COPY ${B}/data/manager/agentless /app/ruleset-src/src/agentlessd/scripts
COPY ${B}/data/sigma /app/data/sigma
COPY ${B}/data/agent-dist /app/data/agent-dist
COPY --from=winagent /out/ /app/data/agent-dist/windows/
COPY ${B}/docker/siem-api-start.sh /usr/local/bin/siem-api-start
# Unix line ends whatever the checkout did
RUN sed -i 's/\r$//' /usr/local/bin/siem-api-start && chmod 755 /usr/local/bin/siem-api-start
# PROVIGIL_MANAGER=0: the platform role only (cases, settings, admin, the console's API); the
# installer sets 1 when the licence has SIEM, which also starts the gateway.
ENV SIEM_PORT=8088 PROVIGIL_MANAGER=0 PROVIGIL_SOURCE_DIR=/app/ruleset-src PROVIGIL_MANAGER_HOME=/app/data/manager
EXPOSE 8088 8089 8443
HEALTHCHECK CMD wget -q --spider http://127.0.0.1:8088/api/health || exit 1
CMD ["siem-api-start"]
