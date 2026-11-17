# provigil-modulesd

## Overview

`provigil-modulesd` is the supervisor daemon responsible for managing, scheduling, and orchestrating ProVigil Manager background modules. It replaces the legacy `siem-modulesd` and hosts core platform subsystems, including:

1. **Task Manager (`task_manager`)**: Manages asynchronous management tasks across the fleet (such as agent upgrades, configuration pushes, and bulk operations) with persistent state tracking in `provigil-db`.
2. **Vulnerability Scanner Coordinator**: Triggers scheduled and on-demand CVE scans across agent software inventories.
3. **Database Maintenance & Pruning**: Periodically prunes historical task records and agent database sync markers.
4. **Message Router**: High-throughput IPC router that brokers pub/sub events and command delivery between manager daemons.

## Key Capabilities

- **Resilient Worker Supervision**: Automatically restarts failing module subroutines with exponential backoff.
- **Unified IPC Framework**: Uses `provigil-ipc` for seamless Unix domain socket communication with `provigil-agentdb` and `provigil-gateway`.
- **Fleet Upgrade Orchestration**: Tracks multi-step agent upgrade transactions (`in_queue` -> `updating` -> `updated` or `failed`), with rollback validation.
- **Zero-Downtime Hot Reloading**: Dynamic configuration reloading via SIGHUP signals.
