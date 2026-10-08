# SIEM & NDR Unified Architecture & Development Rules

## 1. Core Principle: Isolated SIEM Development, Common Shared Backend
- **Dedicated SIEM Frontend**: `e:\wazhu-Siem-code\wazuh-rust-angular\frontend-angular` is the primary environment for developing and testing all SIEM UI components, pages, and services independently without touching NDR code.
- **Unified NDR UI Integration**: `e:\wazhu-Siem-code\ndr\ndr-ui` is the unified production container. SIEM features developed in `frontend-angular` are copied into `ndr-ui/src/components/siem/`, `src/services/siem/`, and `src/pages/siem/`.
- **Do Not Modify Pure NDR Pages**: Never directly alter core NDR analyst pages (`assets`, `rules`, `logs`, `alerts`) unless explicitly requested to call SIEM components inside them. Keep NDR pages separated and pristine.

## 2. Common Shared Backend & Libraries
- **Shared Rust Crates**:
  - `auth-service` (Port 3001): Production auth service using `provigil-common` crate for JWT authentication, multi-tenancy, and role permissions.
  - `siem-api` (Port 8088): High-performance Wazuh event processing engine, syslog receivers (UDP 514 / TCP 601), and ClickHouse `wazuh_siem` tables.
- **Shared Databases**:
  - ClickHouse (Ports 8123 / 9000): Contains `ndr` and `wazuh_siem` databases.
  - Valkey / Redis (Port 6379): Shared user sessions.
- **Both Frontends Share the Exact Same API Endpoints**:
  - `POST /api/auth/login` → `auth-service:3001`
  - `GET /api/v1/agents` → `siem-api:8088`
  - `GET /api/v1/rules` → `siem-api:8088`
  - `GET /api/v1/events` → `siem-api:8088`
  - `GET /api/v1/stats` → `siem-api:8088`
  - `WS /ws/alerts` → `siem-api:8088` (WebSocket stream)

## 3. Modular SIEM Component Structure
All SIEM features must be implemented as standalone Angular 21 components inside:
- `components/siem/agents/` (`<app-siem-agents>`)
- `components/siem/rules/` (`<app-siem-rules>`)
- `components/siem/logs/` (`<app-siem-logs>`)
- `components/siem/alerts/` (`<app-siem-alerts>`)
- `components/siem/dashboard/` (`<app-siem-dashboard>`)

## 4. Separated API Services
All API calls must be organized in separated service files coordinated by a full service:
- `siem-agents.service.ts`: Agent fleet, inventory, remote commands.
- `siem-rules.service.ts`: Wazuh detection rule catalog.
- `siem-logs.service.ts`: Raw telemetry and syslog streaming.
- `siem-alerts.service.ts`: Alerts and real-time WebSocket connection.
- `siem-stats.service.ts`: Overview statistics and throughput metrics.
- `siem.service.ts`: Full service facade that unifies the sub-services.

## 5. Reverse Proxy & Dev Server Ports
- **Caddy (Port 80/443)**: Serves `dist/ndr-ui/browser`, routes `/api/auth/*` to 3001 and `/api/*` to 8088.
- **Angular Dev Server (`ng serve` on Port 4200)**: Uses `proxy.conf.json` with HTTP targets (not HTTPS):
  - `/api/auth` → `http://127.0.0.1:3001`
  - `/api/v1` → `http://127.0.0.1:8088`
  - `/ws` → `ws://127.0.0.1:8088`
- **Continuous Watch Build**: `npm run watch` (or `npx ng build --watch`) auto-updates the disk bundle for Caddy without manual rebuilds.
