# provigil-agentdb Architecture

## Storage and Concurrency Model

```text
               [Client Daemons: analysisd, modulesd, siem-api]
                                     │
                                     ▼
                    [DbSocket: queue/db/wdb]
                                     │
                   ┌─────────────────┴─────────────────┐
                   ▼                                   ▼
             [Router / Parser]                 [Connection Pool]
                   │
         ┌─────────┼───────────────────────────┐
         ▼         ▼                           ▼
   [Global Actor] [Task Actor]           [Per-Agent Actors]
   (global.db)    (tasks.db)             (queue/db/<id>.db)
   - Agent list   - Upgrade tasks        - Agent 001.db
   - Groups       - Bulk operations      - Agent 002.db
   - Node status  - Status moves         - Agent N.db
```

## Internal Architecture

### 1. Per-Agent Database Layout (`queue/db/<agent_id>.db`)
Each agent database contains independent tables:
- `sys_osinfo`: Operating system details, kernel release, architecture.
- `sys_programs`: Installed applications, package versions, architectures, and install timestamps.
- `sys_hotfixes`: Installed Windows updates and KB hotfixes.
- `sys_ports`: Open listening ports and associated PIDs.
- `fim_entry`: Watched file paths, SHA-1/SHA-256 hashes, sizes, inode, permissions, and scan metadata.
- `sca_check`: SCA policy compliance check results and remediation details.

### 2. Global Database (`queue/db/global.db`)
Stores manager-wide state:
- `agent`: Master agent registry, keys metadata, enrollment status, last keepalive, and IP address.
- `belongs`: Agent group associations.
- `labels`: Agent metadata labels (used dynamically by `provigil-analysisd`).

### 3. Task Database (`queue/db/tasks.db`)
Maintains transactional records of asynchronous manager operations:
- Agent upgrade execution states (`In queue`, `Updating`, `Updated`, `Failed`, `Timeout`).
- Custom command deployment status and execution history.

### 4. Backup & Maintenance
- Automated backup creation and atomic restore operations.
- VACUUM and fragmentation control runs during scheduled maintenance windows.
