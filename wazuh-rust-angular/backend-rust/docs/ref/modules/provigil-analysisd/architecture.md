# provigil-analysisd Architecture

## Data Flow Pipeline

```text
[Agents / Gateways / Syslog]
              │
              ▼
    [Input Socket / Stream]
              │ (Framing & Sender Backpressure)
              ▼
       [Input Queues] (Event, Syscheck, SCA, Syscollector, Rootcheck, Winevt, ...)
              │
              ▼
      [Worker Threads] (DB Decoders: SQLite state via provigil-db)
              │
              ▼
   [Pre-decoding & Decoders] (Regex, Windows Event Channel, JSON, XML)
              │
              ▼
      [Rules Engine] (Hierarchical matching, FTS, Frequency accumulators, MITRE tags)
              │
        ┌─────┴──────────────────┐
        ▼                        ▼
[Active Response]       [Outputs / Dispatcher]
  - Whitelist check       - Alert Stream -> siem-api -> ClickHouse
  - Exec queue            - Local Log Rotation (alerts.json, archives.json)
  - Agent AR queue        - Syslog Forwarder (TCP/UDP)
```

## Core Components

### 1. Ingestion and Queueing (`queues.rs`)
`provigil-analysisd` uses segregated ring queues per message kind (`Kind::Event`, `Kind::Syscheck`, `Kind::Rootcheck`, `Kind::Hostinfo`, `Kind::Winevt`, `Kind::Sca`, `Kind::Upgrade`, `Kind::Syscollector`, etc.). 
- When an input queue is full, the daemon applies backpressure back to `provigil-gateway` or `siem-api` by holding the Unix domain stream read buffer.
- Tracks sender load per gateway instance via atomic bit-encoded usage counters (`load: Arc<Vec<AtomicU64>>`).

### 2. Multi-threaded Database Workers (`builtin.rs`)
Messages requiring per-agent database state lookups (such as FIM checks and Rootcheck) are dispatched across a pool of dedicated worker threads (`DB_WORKERS = 4`). Each agent's state is serialized to preserve causality while maximizing concurrent throughput across distinct agent IDs.

### 3. Rule Matching Engine (`engine.rs` & `rules.rs`)
- Rules are pre-compiled into a hierarchical execution tree indexed by level, group, and rule ID.
- Accommodates fast pre-filtering on `program_name`, `category`, and extracted decoder fields.
- Dynamic label expansion: When matching rules that evaluate agent labels (e.g. environment, department), the daemon queries `provigil-db` via `LabelCache` with TTL caching to avoid blocking detection loops.

### 4. Alert & Output Dispatch (`daemon.rs` & `outputs.rs`)
- **Stream Mode**: Directly streams alerts and archives in JSON format to `siem-api` over high-speed IPC Unix domain sockets (`stream::ALERT`, `stream::EVENT`), eliminating disk I/O bottlenecks.
- **File Mode**: Writes to daily subdirectories (`logs/alerts/YYYY/Mon/ossec-alerts-DD.json`) with automated interval-based or size-based rotation and symlink management (`alerts.json`).
- **Syslog Forwarder**: Delivers RFC-compliant syslog alerts to external SIEMs/receivers via UDP or TCP streams.

### 5. Logtest Service (`logtest.rs`)
Hosts an asynchronous multi-session socket service on `queue/sockets/logtest`. Clients send candidate log lines and receive full evaluation JSON trees displaying extracted fields, matched decoders, rule phase execution, and triggered active responses.
