# NDR Engine

A high-performance, real-time Network Detection and Response (NDR) correlation engine written in Rust.

This engine ingests logs from **Zeek** and **Suricata** via Vector, correlates them in memory using `community_id`, enriches the data with GeoIP/ASN and Threat Intelligence, and scores the combined flow for risk. Resulting hits are broadcasted live to an embedded WebSocket dashboard and persisted to SQLite.

## Architecture

The project features a clean, modular architecture broken down into 7 components:

1. **`normalizer/` (ECS-Compatible Data Model)**
   - Parses incoming JSON from Vector.
   - Maps both Zeek (`conn.log` TSV) and Suricata (`eve.json`) into a shared canonical `NormalizedEvent`.
   - Filters out known noise immediately (e.g. `stats`, `capture_loss`, `fileinfo`).

2. **`correlator/` (High-Performance Caching)**
   - Replaced a global `Mutex<HashMap>` with a lock-free concurrent `DashMap` for the correlation cache, eliminating bottlenecking during high traffic.
   - **Protocol-aware TTL Caching**: The engine caches flows looking for a `community_id` match. Drawing from Security Onion's defaults, TCP sessions have an extended 600s TTL, while UDP and other protocols have a 300s TTL. 
   - A background async task sweeps the `DashMap` every 30 seconds to aggressively drop expired un-correlated flows and keep memory usage lean.

3. **`enrichment/`**
   - **GeoIP & ASN**: Native `maxminddb` parsing for GeoLite2 databases. Identifies countries and ISP organisations for external IPs.
   - **Threat Intel**: Real-time evaluation against the Abuse.ch Feodo Tracker IP blocklist. Refreshes natively in a background task every 60 minutes.
   - **Directional Tagging**: Detects RFC1918 traffic bounds and classifies traffic cleanly as `internal`, `inbound`, `outbound`, or `external`.

4. **`scoring/` (Risk Engine)**
   - Computes a dynamic 0-100 risk score and categorises hits securely into `Info`, `Low`, `Medium`, `High`, and `Critical`.
   - Weights take into consideration Suricata Alert severity, anomalous Zeek connection states (e.g. `REJ`, `S0`), destination port signatures (e.g. 445 SMB, 3389 RDP, C2 ports), unencrypted protocol usages, and GeoIP blocks against sensitive country codes.

5. **`detection/` (SIGMA Rule Engine)**
   - Loads custom YAML signature files (`rules/`) dynamically on boot.
   - A bespoke rule matching backend evaluating equality, partial substring matches (`contains`, `startswith`, `endswith`), Regular Expressions, and boolean Logic Operations (`AND`, `OR`, `NOT`). 

6. **`storage/`**
   - Implements `rusqlite` to write every hit along with its rule triggers, raw strings, and risk scores natively into SQLite (`ndr.db`). 
   - Database is configured to run in `WAL` mode (Write-Ahead Logging) to prevent block contention between HTTP event writes and subsequent analysis reads.

7. **`api/`**
   - Runs an `axum` HTTP server on port **3000**.
   - Accepts Vector ingestion blindly mapping to `/event`.
   - Hosts a fully responsive, rich client WebSocket real-time UI dashboard on `/`. 

## How The Log Caching Works

**The primary challenge in NDR processing is that Zeek (conn.logs) and Suricata (alerts) arrive asynchronously, often seconds or minutes apart, despite detailing the exact same network conversation.**

The new NDR Engine manages this latency with a concurrent, memory-safe sliding cache:
1. When Vector ships an event, the `normalizer` generates its `community_id`.
2. The `correlator` retrieves the lock-free session from the `DashMap` via the `community_id` key.
3. If it's a first-time sighting, the engine initializes a `Session` block and stores the event.
    - If the incoming protocol is TCP, it is given a **10-minute TTL** (Time To Live).
    - If the incoming protocol is UDP/ICMP, it is given a **5-minute TTL**.
4. If the corresponding opposing event (e.g., the Suricata alert for a resting Zeek conn flow) arrives within the TTL threshold, the Engine fires a correlation interrupt, joins the data pairs immediately, executes scoring & SIGMA detection over the combined dataset, and finally shoots it out downstream (Websocket + SQLite).
5. A background `tokio::task` aggressively sweeps and truncates abandoned `Sessions` every 30 seconds that missed their matching pair TTL window, guaranteeing linear memory footprint regardless of traffic saturation.
