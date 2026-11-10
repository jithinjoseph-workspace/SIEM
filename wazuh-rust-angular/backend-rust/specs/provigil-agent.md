# ProVigil Unified Windows Agent (`provigil-agent`)

## Overview
A lightweight, secure, high-performance, dynamic endpoint agent for Windows that unifies
and replaces the 9 legacy ported agent crates (`siem-winagent`, `siem-agentd`,
`siem-logcollector`, `siem-syscheckd`, `siem-syscollector`, `siem-sysinfo`, `siem-sca`,
`siem-authd`, `siem-remoted`) with 100% clean-room Rust.

## Core Design Principles
1. **Zero GPL Code**: 100% clean-room proprietary Rust.
2. **Low Memory & High Performance**: Async Tokio runtime, streaming buffers, memory footprint < 25 MB (down from 150-350 MB across 7 processes).
3. **Dynamic & Config-Driven**: No hardcoded IP addresses, paths, or thresholds.
4. **Reliable & Resilient**: Offline persistent ring buffer prevents log loss during network disconnects.
5. **Secure**: TLS encryption, tenant key validation, tamper protection, signed verification.

## Architecture & Modules

### 1. Dynamic Configuration (`config.rs`)
- File: `provigil-agent.json` (or CLI flags/environment variables `PROVIGIL_MANAGER_URL`, `PROVIGIL_TENANT_KEY`, `PROVIGIL_AGENT_NAME`):
  - `manager_url`: URL of the ProVigil SIEM manager.
  - `tenant_key`: Enrollment token.
  - `agent_name`: Defaults to hostname.
  - `heartbeat_interval_secs`: Default 10s.
  - `event_channels`: List of channels (Security, System, Application, Sysmon, PowerShell).
  - `fim_paths`: Directories to monitor.
  - `fim_scan_interval_secs`: Baseline interval (default 300s).
  - `diff_enabled`: Enable unified diff calculation on file change (default true).
  - `diff_max_size`: Maximum diff bytes before truncation (default 59,392).
  - `whodata_enabled`: Correlate Windows Security Audit Event 4663 (default true).
  - `rootcheck_enabled`: Enable local rootkit & driver scanning (default true).
  - `rootcheck_interval_secs`: Rootcheck scan interval (default 43,200s / 12 hrs).
  - `upgrade_enabled`: Remote self-upgrade supervisor (default true).
  - `buffer_max_events`: Max buffered offline events (default 10,000).

### 2. Windows Service Runner (`service.rs`)
- Native Windows Service integration.
- CLI commands: `--install`, `--uninstall`, `--run`, `--status`.
- Lifecycle handlers for `SERVICE_CONTROL_STOP` and `SERVICE_CONTROL_SHUTDOWN`.

### 3. Agent Enrollment & Identity (`identity.rs`)
- Automatic first-run enrollment via `POST /api/v1/agents/enroll`.
- Generates/stores local `data/agent-identity.json` (`agent_id`, `auth_token`, `enrolled_at`).

### 4. Resilient Offline Buffer (`buffer.rs`)
- Thread-safe FIFO ring buffer retaining up to 10,000 telemetry events in RAM.
- Automatically flushes queued events via HTTPS once connection is re-established.

### 5. File Integrity Monitoring (`fim.rs`)
- 64 KB streaming SHA-256 file hashing (avoids memory spikes on large files).
- Directory crawl & baseline cache; detects `added`, `modified`, and `deleted` files.
- Automatically enriched with `diff` and `whodata`.

### 6. File Diff Engine (`diff.rs`)
- Computes unified diffs (`--- original / +++ modified`) on file modifications.
- Gzip compression (`flate2`) for stored file snapshots in `data/diff/`.
- Configurable disk quota (`disk_quota_bytes = 50MB`).
- Automatic truncation with `\nMore changes...\n` if diff exceeds max size.

### 7. Whodata & Process Attribution (`whodata.rs`)
- Captures and buffers Windows Security Audit Event 4663 ("An attempt was made to access an object").
- Bounded ring cache (`WhodataCache`) correlating file path and event timestamp.
- Enriches FIM alerts with `user_name`, `user_sid`, `process_name`, and `process_id`.

### 8. Windows Event Log Collector & Multiline Aggregator (`events.rs`)
- Native Windows Event Channel reading with persistent bookmarking (`data/event-bookmarks.json`).
- Custom XPath queries per channel (`ChannelConfig`).
- `MultilineAggregator` using regex matching to aggregate stack traces into single events.

### 9. System Inventory with Delta Sync (`inventory.rs`)
- Collects OS, CPU, RAM, disk, network, and running processes using `sysinfo`.
- `TableSyncCache` computes SHA-256 item checksums and emits `INSERTED`, `MODIFIED`, and `DELETED` deltas.
- Drops agent CPU & network overhead by over 95%.

### 10. Local Rootcheck & Driver Scanner (`rootcheck.rs`)
- Scans for core system binaries masquerading in suspicious paths (`Temp`, `AppData`).
- Inspects `C:\Windows\System32\drivers` for anomalous non-driver executables.
- Emits structured `rootcheck_alert` telemetry events.

### 11. Remote Self-Upgrade Supervisor (`upgrade.rs`)
- Receives manager update directives (`download_url`, `expected_sha256`, `target_version`).
- 64 KB streaming SHA-256 cryptographic verification before execution.
- Generates detached runner script (`run_upgrade.ps1`) to stop service, swap binary, restart service, and record result in `data/upgrade_result.json`.

### 12. EDR & Active Response (`edr.rs`)
- Executes automated threat containment:
  - `isolate_host`: Blocks all outbound traffic except ProVigil Manager.
  - `kill_process`: Terminates malicious PID.
  - `quarantine_file`: Moves malicious file to isolated quarantine.
  - `live_response`: Executes approved administrative commands.

### 13. Telemetry Transport & Keepalive (`transport.rs`)
- HTTPS POST `/api/v1/agents/heartbeat` with telemetry metadata.
- Batch event streaming to `/api/v1/events/batch`.
- Real-time command polling and dispatch to EDR executor.
