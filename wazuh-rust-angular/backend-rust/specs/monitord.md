# Monitord: Agent Health Monitoring & Log Rotation

## Purpose
Continuous background monitoring of agent connectivity, emitting disconnection and
removal alerts, and managing log file rotation, compression, checksum signing, and retention.

## Features Required

### 1. Agent Disconnection Monitoring (`agent_monitor.rs`)
- **Interval**: Scans registered and active agents every `check_interval` (default 30s).
- **Threshold**: An agent is considered disconnected when `now - last_keepalive > disconnection_timeout` (default 600s / 10 minutes).
- **Grace Period / Alert Delay**: `disconnection_alert_delay` (default 0s). An alert is emitted only if disconnected longer than this delay to avoid flapping alerts.
- **Alert Event (Rule 504)**:
  - Generates JSON alert:
    - `rule.id`: "504"
    - `rule.level`: 3 (or 5)
    - `rule.description`: "Agent disconnected"
    - `rule.groups`: `["ossec", "agent_monitor"]`
    - `agent`: `{"id": id, "name": name, "ip": ip}`
    - `full_log`: `1:provigil-monitord:ossec: Agent disconnected: '<name>-<ip>'.`
    - `location`: "provigil-monitord"
- **Auto-Removal of Stale Agents (Rule 505)**:
  - When `auto_delete_timeout` > 0 (e.g. 30 days):
  - If an agent remains disconnected for longer than `disconnection_timeout + auto_delete_timeout`:
    - Automatically purges agent enrollment and keys.
    - Generates JSON alert:
      - `rule.id`: "505"
      - `rule.level`: 3
      - `rule.description`: "Agent removed from database"
      - `full_log`: `ossec: Agent removed: '<name>-<ip>'.`

### 2. Log Rotation & Retention (`log_rotator.rs`)
- **Target Files**: `provigil.log`, `provigil.json`, or manager log directories.
- **Rotation Triggers**:
  - Daily: At midnight, or when day changes.
  - Size-based: When active log file exceeds `max_size_bytes` (e.g. 500 MB).
- **Archive Path Structure**:
  - Organized as `logs/<year>/<Mon>/<file>-<day>[-<counter>].<ext>`.
- **Gzip Compression**:
  - When `compress: true`, compresses rotated files to `.gz` using standard `flate2` and removes uncompressed original.
- **Integrity Signatures**:
  - Generates `.sum` file containing SHA-256 (and MD5/SHA-1) digest of rotated log file.
- **Retention**:
  - Deletes archives older than `keep_log_days` (default 31 days).

