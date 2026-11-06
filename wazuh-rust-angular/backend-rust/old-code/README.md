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

Each later replaced crate is moved here instead of being deleted.
