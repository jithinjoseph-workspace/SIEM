# provigil-analysisd

## Overview

`provigil-analysisd` is the core real-time log analysis and detection daemon for the ProVigil Manager. It receives pre-parsed event streams and raw syslog messages from connected agents (via `provigil-gateway` or legacy queue sockets), applies pre-decoding and XML/JSON decoders, matches rules hierarchically against the compiled ruleset, correlates stateful attacks, executes active responses, tracks MITRE ATT&CK coverage, and writes alert/archive streams to ClickHouse and local logs.

It represents the high-performance Rust reimplementation of the detection engine, maintaining full backward compatibility with the rule and decoder definitions while delivering enhanced multi-threaded throughput and zero-file-copy streaming to `siem-api`.

## Key Capabilities

- **High-Throughput Ingestion Queue**: Lockless multi-kind message queueing with sender backpressure signals (`FROM_API`, `FROM_GATEWAY`).
- **Comprehensive Decoding Pipeline**:
  - Pre-decoding (timestamps, hostnames, program names).
  - XML decoders with regex and dynamic field extraction.
  - Windows Event Channel and Sysmon native decoding.
  - Built-in database decoders (FIM / syscheck, rootcheck, syscollector, SCA, dbsync, upgrade, CIS-CAT).
- **Hierarchical Rule Engine**:
  - Fast rule lookups by ID and categorization.
  - Stateful frequency/composite matching (timeframes, same_source_ip, etc.).
  - Dynamic agent label lookups with async caching and TTL invalidation.
- **Output & Alert Dispatch**:
  - Direct zero-copy streaming to `siem-api` over Unix domain stream.
  - Daily rotated local alert logs (`alerts.log`, `alerts.json`, `archives.log`, `archives.json`, `firewall.log`).
  - Syslog forwarding over TCP/UDP with automatic reconnection and flow control (`ENOBUFS`).
- **Logtest Socket**: Interactive session-based log testing daemon running concurrently on `queue/sockets/logtest`.
- **First-Time Seen (FTS) Database**: Tracking new programs, users, and locations for anomaly detection.
- **Active Response Engine**: Manager-side and agent-side automated mitigation with whitelist validation.
