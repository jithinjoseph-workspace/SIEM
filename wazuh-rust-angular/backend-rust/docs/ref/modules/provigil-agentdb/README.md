# provigil-agentdb

## Overview

`provigil-agentdb` is the dedicated high-performance state and inventory database service of the ProVigil Manager, replacing the earlier `siem-wdb` database.

It maintains authoritative per-agent state in dedicated SQLite databases alongside a shared global database. This design isolates write contention across thousands of agents, guarantees atomicity for inventory synchronizations, provides persistence for task management, and exposes a Unix domain socket server (`queue/db/wdb`) for low-latency queries from `provigil-analysisd`, `provigil-modulesd`, and `siem-api`.

## Key Capabilities

- **Isolated Per-Agent Storage**: One SQLite database file per agent (`queue/db/<agent_id>.db`), preventing global database lock contention.
- **Actor-Based Concurrency**: Dedicated actor threads for global operations, task management, and per-agent database access.
- **Full Inventory & FIM Tracking**:
  - System hardware, network interfaces, and OS information.
  - Installed packages, running processes, and open ports.
  - File Integrity Monitoring (FIM) file checksums, attributes, Windows permissions, and diffs.
  - Security Configuration Assessment (SCA) compliance results and check states.
- **High-Performance In-Memory Synchronization**: Sync markers and checksum comparison for rapid delta syncing from agent syscollector.
- **Live Query Interface**: Low-latency query API used by the console and vulnerability scanner.
