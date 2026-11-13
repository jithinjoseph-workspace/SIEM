# Old code, kept for comparison only

The upstream-derived versions of crates that ProVigil has replaced with its own code. Kept
by the owner's decision (2026-11-03) to compare old against new, feature by feature.

- Nothing here is built: these folders are not members of the workspace.
- Whoever writes the NEW code for a crate must never open this folder (clean room). Only the
  description side (feature lists, old-vs-new reviews) reads it.
- Do not ship anything from here.

| Folder | Replaced by |
|---|---|
| `siem-cdb` | `crates/siem-cdb` (new) |
| `siem-core` | `crates/siem-core` (new) |
| `siem-engine` | `crates/siem-engine` (new) |
| `siem-active-response` | `crates/siem-active-response` (new shared code, 4 programs, `dll_guard`) |
| `siem-reportd` | `crates/siem-api/src/tenant_reports.rs` |
| `siem-rootcheck` | the agent's own scan (step 4) |
| `siem-task-manager` | siem-modulesd's task manager (step 5) |
| `siem-regex` | `crates/provigil-regex` (review: `specs/rewrite-review-regex.md`) |
| `siem-crypto` | `crates/provigil-crypto` (review: `specs/rewrite-review-crypto-fileop.md`) |
| `siem-fileop` | `crates/provigil-fileop` (review: `specs/rewrite-review-crypto-fileop.md`) |
| `siem-agentd` | `crates/provigil-agent` (review: `specs/FEATURES.md`, siem-agentd and siem-winagent) |
| `siem-winagent` | `crates/provigil-agent` (same review) |
| `siem-authd` | `crates/siem-api` (`specs/siem-authd.md`, review in `specs/FEATURES.md`) |
| `siem-shared` | nothing: used only by siem-authd and siem-util |
| `siem-syscheckd` | `crates/provigil-agent` (`fim.rs`, `registry.rs`, `realtime.rs`, `whodata.rs`) |
| `siem-logcollector` | `crates/provigil-agent` (`wevt.rs`, `logfiles.rs`) |
| `siem-remoted` | `crates/provigil-gateway` |
| `siem-sysinfo` | `crates/provigil-agent` (`osinfo.rs`, `syscollector/win.rs`) |
| `siem-dbsync` | `crates/provigil-agent` (`syscollector/delta.rs`) |
| `siem-syscollector` | `crates/provigil-agent` (`syscollector.rs`, `inventory.rs`) |
| `siem-agent` | `crates/provigil-agent` (early prototype) |
| `siem-sca` | `crates/provigil-agent` (`sca/`) |
| `siem-util` | console and API (agent list, control, reports) |
| `siem-shared-modules` | nothing: used only by moved crates |
| `siem-harvester` | nothing: inventory is read from provigil-db |
| `siem-vulnerability-scanner` | `crates/provigil-vulnscan` (own code from `specs/vulnerability-scanner.md`; matched old vs new, 12 Nov 2026) |

Each later replaced crate is moved here instead of being deleted.
| `siem-wdb` | `crates/provigil-agentdb` (own code; its comparison tests still use this folder as a library, `specs/provigil-db.md`) |
| `siem-modulesd`, `siem-router`, `siem-njson` | `crates/provigil-modulesd` (own code; its comparison test still uses `siem-modulesd` as a library, `specs/provigil-modulesd.md`) |
