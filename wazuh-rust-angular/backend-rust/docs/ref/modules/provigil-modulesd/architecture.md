# provigil-modulesd Architecture

## Process Model

`provigil-modulesd` runs as an asynchronous, Tokio-powered multi-threaded service. Each hosted module executes inside its own dedicated runtime task or supervisor thread.

```text
               ┌───────────────────────────────┐
               │       provigil-modulesd       │
               │         (Supervisor)          │
               └──────────────┬────────────────┘
                              │
       ┌──────────────────────┼──────────────────────┐
       ▼                      ▼                      ▼
[Task Manager]       [Vulnerability Coord]    [Message Router]
  - Fleet upgrades     - Inventory deltas       - Manager IPC
  - Status tracking    - Scheduled scans        - Event routing
  - Task DB updates    - provigil-vulnscan      - Pub/Sub bus
```

## Hosted Submodules

### 1. Task Manager (`tasks/`)
- Manages agent lifecycle tasks initiated via `siem-api` or automated workflows.
- Coordinates with `provigil-agentdb` via `task` actor commands (`task upgrade`, `task update_status`, `task cancel`).
- Monitors agent keepalive timeouts to mark unresponsive agents as `Timeout` or `Failed`.

### 2. Vulnerability Coordinator (`vulnscan/`)
- Coordinates with `provigil-vulnscan` to scan agent software packages whenever syscollector inventory updates arrive.
- Integrates with the offline agent queue to trigger scans against cached software inventories.

### 3. Message Router (`router/`)
- Replaces legacy `siem-router`.
- Provides a fast, in-memory publish-subscribe broker for manager components.
- Subscribes to inventory changes emitted by `provigil-agentdb` and dispatches notification events to consumers.
