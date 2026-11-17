# provigil-vulnscan Architecture

## Detection & Scanning Pipeline

```text
[External CTI Feeds] (NVD, CISA KEV, Vendor feeds)
              │
              ▼
   [Content Feed Updater] (Incremental fetch & decompression)
              │
              ▼
     [CVE / CPE Cache] (RocksDB / SQLite normalized indexed schema)
              │
              ├── Correlates against ──┐
              │                        │
  [Agent Software Inventory] ──────────┘
  (Fetched from provigil-agentdb)
              │
              ▼
   [Version & Hotfix Evaluator]
              │
        ┌─────┴─────────────────────┐
        ▼                           ▼
[Active Vulnerabilities]    [Mitigated / Superseded]
        │                           │
        ▼                           ▼
 [Alert Stream / ClickHouse]   [State DB Updated]
 (siem_vulnerabilities table)
```

## Internal Architecture

### 1. Feed Processing Subsystem (`updater/`)
- Downloads daily and hourly CVE diffs from the ProVigil CTI distribution endpoint.
- Validates cryptographic checksums and parses JSON CVE 5.0 specifications.
- Builds an indexed local cache storing CPE criteria, vulnerable version ranges, fixed-in versions, and CVSS v3.1/v4.0 metrics.

### 2. Inventory Ingestion (`inventory.rs`)
- Interacts with `provigil-agentdb` via `DbSocket` to retrieve inventory snapshots:
  - Installed applications and package architectures.
  - OS patch levels and Microsoft KB hotfixes.
- Monitors syscollector deltas to perform targeted scans on changed packages rather than full fleet rescans.

### 3. Version Matching Engine (`matcher/`)
- Implements specialized version comparison algorithms:
  - `DpkgVersion`: Debian / Ubuntu packaging logic.
  - `RpmVersion`: Epoch, version, and release comparison.
  - `WindowsVersion`: Revision, UBR (Update Build Revision), and KB supersedence checking.
- Accurately discounts patched vulnerabilities when cumulative rollups or hotfixes are installed.
