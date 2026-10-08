# NDR / SIEM Platform

A multi-tenant Network Detection & Response (NDR) platform with an optional SIEM
module, built as a self-hosted or cloud-deployed product. This document exists
so someone new to the codebase can understand what it does and how data moves
through it without having to read every file first.

## What this actually does

Sensors installed on a customer's network capture traffic (via Zeek/Suricata,
managed by a host agent script), ship real events and detections into this
platform, and the platform correlates, scores, and surfaces them to analysts
and admins through a web UI. Detection uses Sigma rules (a shared community
set plus per-tenant custom rules), entity risk scoring, beacon detection,
lateral-movement detection, and threat-intel feed correlation — all running as
real background jobs, not simulated.

## Architecture at a glance

```
Sensor (Zeek/Suricata + host agent)
        │  events/hits over Kafka
        ▼
   Kafka (3 brokers) ──► ndr-engine (×3, leader-elected) ──► ClickHouse
                                │                                │
                                │  background jobs:              │  per-tenant
                                │  entity scoring, beacon         │  databases
                                │  detection, lateral movement,   │  (see below)
                                │  threat intel correlation,      │
                                │  chain matching, asset intel    │
                                ▼                                ▼
                          Redis (sessions,               ndr-ui (Angular)
                          rate limiting, cache)           served via nginx
                                ▲
                                │  JWT-based auth
                          auth-service (login, users, tenants, licensing)
```

- **`ndr-engine`** — the core Rust service. Runs the detection pipeline,
  serves the bulk of the REST API (`/api/...`), and runs the background
  threat-analysis jobs. Deployed as 3 replicas with Raft-style leader
  election; only the leader runs certain periodic jobs.
- **`auth-service`** — a separate Rust service handling login, JWT issuance,
  user/tenant management, and RSA-signed license verification. Split out from
  `ndr-engine` so auth keeps working independently of the detection pipeline.
- **`siem-engine`** — the optional SIEM correlation engine (log ingestion,
  correlation rules), used when a deployment has the SIEM product enabled
  alongside or instead of NDR.
- **`provigil-common`** — a shared Rust crate (JWT validation, SOAR action
  types, etc.) used by the other three services so auth/permission logic
  isn't duplicated across them.
- **`ndr-ui`** — the Angular frontend. Three main areas: Super Admin
  (platform-wide management), Tenant Admin (a customer's own admin view),
  and Analyst (day-to-day investigation UI).
- **ClickHouse** (2-node replicated cluster + a keeper for coordination) —
  the primary datastore for events, hits, users, tenants, rules, and
  everything else. See "Multi-tenancy" below — this is not one flat database.
- **Kafka** (3 brokers) — the real-time ingestion pipeline between sensors
  and `ndr-engine`.
- **Redis (Valkey)** — sessions, rate limiting, and the sensor-key cache.
- **nginx** — reverse proxy in front of the UI and both Rust services.

## Multi-tenancy: how customer data is actually isolated

This is the most important architectural fact to know before changing
anything data-related. Each tenant gets its **own ClickHouse database**:

- The platform's own/default tenant uses the `ndr` database.
- Every other tenant gets `ndr_<tenant_id>` — a full copy of the schema
  (events, hits, rules, etc.), created when the tenant is provisioned.

Application code resolves which database to query via a `tenant_db(tenant_id)`
helper (in `ndr-engine/src/storage/clickhouse.rs`), using the caller's
`tenant_id` claim from their JWT. This is why a bug that skips this scoping,
or trusts a tenant_id/user_id from a request body without verifying it,
is a serious cross-tenant data exposure risk — always check ownership before
writing to or reading a tenant-scoped resource on behalf of a request.

A separate, smaller set of tables (`ndr.tenants`, `ndr.users`, community
Sigma rules, global settings) lives only in the default `ndr` database and is
shared/looked-up across tenants — these are the exception to the
per-tenant-database rule, not the norm.

## Licensing and feature gating (two independent layers)

1. **RSA-signed license (JWT)** — verified once at boot in both
   `auth-service` and `ndr-engine`. Contains `tenant_id`, `max_sensors`, and a
   `features` list. This is the "is this install/tenant allowed to run at
   all" check.
2. **Per-tenant `features` column** — a plain comma-separated string (e.g.
   `"ndr,ai,soar"`) on the `ndr.tenants` row, checked per-request to decide
   what a specific tenant sees in the UI (e.g. whether the SOAR or AI pages
   are visible). This is the finer-grained "what does this specific customer
   see" layer, independent of the license check.

## Installing / running

- **`install-customer.sh`** — on-prem/self-hosted installer. Generates real
  random secrets per install (JWT secret, ClickHouse password, RSA license
  keypair).
- **`install-cloud.sh`** — cloud installer, same idea, generates its own
  per-install secrets.
- **`docker-compose.yml`** — the full stack definition (Kafka, ClickHouse
  cluster, Redis, nginx, ndr-engine ×3, siem-engine, auth-service, ndr-ui).
- **Local frontend development**: `cd ndr-ui && ng serve` — proxies `/api` to
  the backend; auto-rebuilds on save, so a separate full `ng build` usually
  isn't needed while it's running.
- **Local backend development**: `cargo check -p ndr-engine` (or
  `auth-service` / `siem-engine`) for a fast compile check; the real stack
  runs in Docker via `docker-compose.yml`.

## Repo layout

```
rust/               Rust workspace: ndr-engine, auth-service, siem-engine, provigil-common
ndr-ui/             Angular frontend
config/clickhouse/  Schema (init.sql) and cluster config
docs/               Feature-specific documentation (platform features, admin config, etc.)
qa/                 QA tracking
install.sh           On-prem installer used directly by TLS_SETUP.md and referenced in-code; not the same as install-customer.sh
install-customer.sh On-prem installer
install-cloud.sh    Cloud installer
docker-compose.yml  Full stack definition
```

## Known gaps (as of this writing)

- Backend errors are logged via `tracing` to stdout only (no external
  aggregation/alerting service wired up yet); a handler panic in `ndr-engine`
  or `auth-service` is now caught by a `tower_http::catch_panic` layer and
  logged as a structured `tracing::error!` instead of an unlogged stderr
  dump, but there's still no alerting on top of the logs themselves.
  Frontend errors are captured by a global Angular error handler into
  `ndr.client_errors` and are now actually surfaced to a human — visible on
  the Super Admin Telemetry page — rather than just aging out unread.
- Frontend per-page clock-timer duplication has been fully consolidated onto
  the shared `services/clock/` service; some other page-structure duplication
  (e.g. `admin/trusted-domains` vs `tenant-admin/trusted-domains`,
  `admin/rules` vs `analyst/rules`) still exists and would benefit from the
  same base-class extraction already used for `support`/`setup`.
- The `admin`/`tenant-admin` seed accounts in `config/clickhouse/init.sql`
  ship with a fixed, publicly-known password. Login no longer silently
  accepts it — the backend flags `must_reset_password: true` in the login
  response — but there's no forced-change screen in the frontend yet to act
  on that flag, so it's currently just a signal, not an enforced block.
- No backup/disaster-recovery strategy for the ClickHouse cluster exists yet
  — replication across the 2 nodes protects against a single node failing,
  not against host/disk loss or accidental data deletion.
