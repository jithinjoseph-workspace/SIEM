# Next-Gen Unified XDR Platform (NDR + SIEM)

A high-performance, enterprise-grade **Extended Detection and Response (XDR)** platform combining **Network Detection & Response (NDR)** and **Host SIEM/EDR** into a single, unified SOC portal.

Built with **Rust** for microsecond detection and memory safety, **ClickHouse** for petabyte-scale columnar analytics, **Caddy** for automated TLS and edge microservice routing, and **Angular** for a single-pane-of-glass analyst console.

> 📖 **Full Migrated Rust Feature List:** See [`README_FEATURES.md`](./README_FEATURES.md) for the exhaustive specification of all 14 subsystems, 1,435 rules, 10 OOTB correlations, and 37 crates fully migrated and active in Rust.

---

## 📁 Repository Structure

```text
wazuh-rust-angular/
├── backend-rust/                     # Rust Microservices & Endpoint Agents Workspace
│   ├── Cargo.toml                    # Root workspace manifest
│   ├── Dockerfile                    # Multi-stage production container build
│   ├── crates/
│   │   ├── siem-core/                # Shared telemetry models, ossec.conf & client.keys parser
│   │   ├── siem-engine/              # AnalysisEngine (Wazuh XML decoders, hierarchical rules, MITRE ATT&CK)
│   │   ├── siem-api/                 # Tokio/Axum SIEM Manager REST API & WebSocket server
│   │   │   └── src/db.rs             # Native ClickHouse streaming client & query engine
│   │   ├── siem-agent/               # Windows Agent (EventChannel, FIM, Registry, Active Response, SCM)
│   │   └── siem-agent-linux/         # Linux Agent (Logcollector, Syscheck, Rootcheck, Execd)
│   ├── ruleset/                      # Wazuh XML decoders and detection rules
│   ├── active-response/              # Remediation command scripts (firewall-drop, host-deny, kill-proc)
│   ├── run-siem-api.bat              # Fast local launcher for SIEM backend
│   └── build-release.bat             # Release compiler script
│
├── frontend-angular/                 # Single Unified SOC Analyst Portal
│   ├── src/
│   │   ├── app/                      # Angular components (SIEM, NDR, XDR correlation, threat globe)
│   │   │   ├── core/                 # Models, ClickHouse/SIEM/NDR API services, WebSocket streams
│   │   │   └── components/           # Threat maps, incident feeds, alerts tables, agent managers
│   └── package.json                  # Frontend dependencies
│
├── caddy/                            # Production Edge Reverse Proxy
│   └── Caddyfile                     # Unified routing: /api/siem/*, /api/ndr/*, /ws/*, SPA fallback
│
├── clickhouse/                       # Columnar Database Configuration
│   └── init.sql                      # Auto-provisioning schema (siem_events, siem_alerts, ndr_flows, xdr_incidents)
│
├── nginx/                            # Alternative On-Premise Load Balancer
│   └── nginx.conf                    # NGINX reverse proxy configuration
│
├── dist/                             # Compiled production build artifacts
│   └── frontend-angular/             # Static SPA bundle served by Caddy/NGINX
│
├── docker-compose.yml                # Primary Unified Stack (Caddy + ClickHouse + siem-api)
├── docker-compose.caddy.yml          # Caddy-specific compose file
├── docker-compose.nginx.yml          # NGINX-specific compose file
├── docker-compose.clickhouse.yml     # Standalone ClickHouse compose file
│
├── start-siem.bat                    # Windows one-click local SIEM server launcher
├── start-agent.bat                   # Windows one-click agent launcher
└── package-windows-agent.ps1         # Windows agent packaging and installer script
```

---

## 🌐 Network & Microservice Topology

| Service | Port | Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| **Caddy Reverse Proxy** | `80`, `443`, `443/udp` | HTTP/HTTPS/HTTP3 | Auto-HTTPS edge router, serves Angular UI, proxies API and WebSockets |
| **SIEM API Microservice** | `8088` (Internal) | HTTP & WSS | Event correlation engine, active response dispatcher, agent keepalives |
| **NDR API Microservice** | `8090` (Internal) | HTTP & WSS | Network flow inspection, Suricata/Zeek alerts, C2 detection |
| **ClickHouse Database** | `8123` (HTTP), `9000` (Native) | TCP / Binary | Columnar storage for raw events, alerts, network flows, and XDR incidents |

---

## 🚀 Quick Start Guide

### 1. Launch the Unified Production Stack (Docker)
Ensure Docker is installed and running, then execute:

```bash
docker compose up -d
```

This will automatically:
1. Boot **ClickHouse** and execute `clickhouse/init.sql` to provision all tables.
2. Compile and start the **Rust SIEM API** microservice.
3. Start **Caddy** with automatic TLS and microservice reverse proxying on ports `80` and `443`.

### 2. Run Locally in Development Mode

**Step A: Start ClickHouse**
```bash
docker compose -f docker-compose.clickhouse.yml up -d
```

**Step B: Start Rust SIEM Backend**
```cmd
cd backend-rust
cargo run --release -p siem-api
```

**Step C: Start Angular Frontend**
```cmd
cd frontend-angular
npm install
npm start
```
The dashboard will be available at `http://localhost:4200`.

---

## 🛡️ Database Retention Policies (TTL)
Configured in `clickhouse/init.sql`:
* `wazuh_siem.siem_events`: **90 Days** (ZSTD compressed)
* `wazuh_siem.siem_alerts`: **365 Days** (PCI-DSS & SOC2 compliance)
* `wazuh_siem.ndr_network_flows`: **30 Days**
* `wazuh_siem.ndr_threats`: **180 Days**
* `wazuh_siem.xdr_incidents`: Persistent correlated incident records
