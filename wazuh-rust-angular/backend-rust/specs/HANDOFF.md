# Handoff: making ProVigil entirely our own code

Last updated 2026-11-03. Give this file to the AI that continues the work (paste the prompt
in section 1). Sections 2–5 are the state it works from.

## 1. Prompt to paste

```
You are continuing a project in E:\wazhu-Siem-code\wazuh-rust-angular (Rust workspace in
backend-rust/, Angular UI in ndr-ui/). The product, ProVigil, began as a port of an
open-source SIEM licensed GPLv2. The owner's final decision: replace every crate and data
file that came from that project with ProVigil's own code, keeping every feature. Do not
re-open that decision.

Read first, in this order:
  backend-rust/specs/HANDOFF.md   (this file: rules, what is done, what is left)
  backend-rust/specs/README.md    (plan, steps 1-6, progress table)
  backend-rust/specs/FEATURES.md  (every feature of each replaced crate and where it lives now)

Method for each crate, never skip a step:
  1. Feature list: read the old crate (git and the working tree) and write EVERY feature
     and public function into FEATURES.md with its status (kept / moved / to build /
     dropped with a written reason). Nothing is deleted before this is done.
  2. Description: write specs/<crate>.md - what it must do, what siem-api calls (names,
     shapes, JSON), the tests it needs. No code in it.
  3. New code: written from the description only, by a fresh agent or developer that never
     opens the old crate's files (nor old-code/, graphify-out/, data/manager/). Same crate
     and file names are fine. The old crate is MOVED unread to backend-rust/old-code/<crate>
     (owner: keep old code for comparison; never delete it).
  4. Review: compare old against new LINE BY LINE (old code in old-code/ or git), not only
     function by function: every behaviour, even small (log lines, retries, error texts,
     limits, exit codes). Every gap goes back into the description and is fixed by a fresh
     agent, not by copying. A crate is not done until this review is written up.
  5. Check: cargo test of the crate, cargo clippy --all-targets --no-deps clean,
     cargo build -p siem-api, cargo test -p siem-api --bin siem-api, and the live tests in
     siem-api/src/analyst_tests.rs (-- --ignored) when ClickHouse is up.
  6. Update README.md (progress) and FEATURES.md (statuses).

Rules: never translate, reword or port the old code; ideas and features are fine, code is
not. Keep the owner's names: no upstream product name in new code, comments, UI or docs.
Do not commit or push unless the owner asks. Do not run `ng build` for ndr-ui (ng serve
rebuilds it); check the UI with `npx tsc --noEmit -p tsconfig.app.json` and
`npx ngc -p tsconfig.app.json --noEmit`. Watch disk space (a full disk emptied two files
once). Things the owner said to leave for later: step 1 (deleting the prototype agents)
and the rule files (backend-rust/ruleset/, data/manager/ruleset/).

Start with step 3 in README.md unless the owner says otherwise. Report in plain words
what changed, what was checked, and what is left.
```

## 2. Done (step 2, 2026-11-03), all checked old-against-new

| Crate | Lines replaced | How | Tests |
|---|---|---|---|
| siem-cdb | 358 | new code (`specs/siem-cdb.md`), files `lib.rs`, `matcher.rs`, `threat_intel.rs`; list import and listing added (API `POST/GET /api/v1/threat-intel/lists/:name/import|entries`) | 9 + `tests/old_cases.rs` |
| siem-reportd | 431 | deleted; its features rebuilt in `siem-api/src/tenant_reports.rs` (PDF report with filters, breakdown, sample alerts, title) | in siem-api + live test |
| siem-rootcheck | 812 | deleted; the checks run in the agent today (must be rebuilt in the new agent, step 4) | — |
| siem-core | 829 | new code (`specs/siem-core.md`); the old config reader moved into the two prototype agents | 5 + `tests/stored_alerts.rs` (opt-in, real alerts) |
| siem-active-response | 1,960 | new shared code, 4 programs and `dll_guard` (`specs/siem-active-response.md`); our own EDR programs kept | 22 |
| siem-engine | 2,300 | new code (`specs/siem-engine.md`) | 13; siem-redswarm 6 |
| siem-task-manager | 768 | deleted / archived to `old-code/` (unused) | — |
| siem-csyslogd | 2,512 | replaced by `syslog_send.rs` in `siem-api`; archived to `old-code/` | 6 tests |
| siem-integratord | 3,457 | replaced by `soar_integrations.rs` in `siem-api`; archived to `old-code/` | 5 tests |
| siem-monitord | 3,656 | replaced by `agent_monitor.rs` & `log_rotator.rs` in `siem-api`; archived to `old-code/` | 4 tests |
| siem-maild | 4,599 | replaced by `mail_send.rs`, `alert_mail.rs`, `tenant_reports.rs` in `siem-api`; archived to `old-code/` | 5 tests |

Also built (our own code): per-tenant alert e-mails (`siem-api/src/alert_mail.rs`), PDF
reports (`tenant_reports.rs`, `pdf.rs`), their Settings panels in ndr-ui.

State at handoff: siem-api builds cleanly, `cargo test -p siem-api --bin siem-api` 101 passed, 12 ignored. All 5 manager crates in Step 3 are replaced with 100% clean-room Rust.

## 3. What is left: 34 crates, about 153,536 lines, plus data

| Step | Crates | Lines | What happens | Owner's note |
|---|---|---|---|---|
| 3 | siem-task-manager, siem-csyslogd, siem-integratord, siem-monitord, siem-maild | 14,992 | replaced by siem-api features; all 5 crates moved to `old-code/` | **DONE 2026-11-03** |
| 1 | siem-harvester 399, siem-agentlessd 1,590, siem-shared-modules 1,633, siem-util 2,070, siem-agent 2,940, siem-agent-linux 3,159 (+ 12 agentless scripts) | 11,791 | delete (nothing needs them; the two prototype agents also have download routes and scripts to remove) | later (owner) |
| 4 | the agent: siem-winagent 3,814, siem-agentd 5,294, siem-logcollector 10,312, siem-syscheckd 11,772, siem-syscollector 4,579, siem-sysinfo 4,998, siem-sca 3,210, siem-authd 1,954, siem-remoted 6,554 | 52,487 | a new ProVigil agent (Windows and Linux) with our own protocol over HTTPS, own config and enrollment; must include every agent feature, including the rootcheck checks listed in FEATURES.md | most important: customers receive the agent (next) |
| 5 | siem-analysisd 19,980, siem-wdb 22,156, siem-vulnerability-scanner 7,479, siem-modulesd 3,900, siem-execd 3,589 | 57,104 | own detection (our rules + Sigma), agent state in ClickHouse, own scanner on NVD / OSV | |
| 5 (data) | `data/manager/ruleset/` and the same files in `backend-rust/ruleset/`: 168 rule, 120 decoder, 77 check-policy, 21 rootcheck, 7 list files (+126 test files); `ossec.conf`, `internal_options.conf`, shared `agent.conf`, `ar.conf` | — | our own rules and policies | later: detection uses them today |
| 6 | siem-config 4,591, siem-ipc 2,792, siem-crypto 2,042, siem-shared 3,214, siem-router 5,485, siem-dbsync 4,612, siem-xml 1,627, siem-regex 2,041, siem-fileop 1,787, siem-log 499, siem-daemon 317, siem-cjson 1,073, siem-njson 1,607, siem-sqlite 467 | 32,154 | deleted once nothing uses them (standard Rust libraries where needed) | |
| siem-api | 13 files talk to the ported parts: `provigil_manager.rs`, `groups.rs`, `rules_api.rs`, `vulnerability.rs`, `mitre.rs`, `tamper.rs`, `compliance.rs`, `investigate.rs`, `sigma.rs`, `soar.rs`, `mail_settings.rs`, `main.rs`, `analyst_tests.rs` | — | reworked as steps 3–5 replace what they talk to | |

Already ProVigil's own, no change: ndr-ui, auth-service, provigil-common, siem-ai,
siem-triage, siem-suppression, siem-decision, siem-deception, siem-intent-engine,
siem-org-memory, siem-parser-gen, siem-predict, siem-redswarm, siem-retro,
siem-risk-fabric, siem-swarm, siem-analyst-insight, and 36 of siem-api's 49 files. The 32
Sigma rule files may stay with credit to their authors.

## 4. Open items for the owner

- Commit today's work (nothing is committed yet).
- Delete the unread backup of the old siem-cdb:
  `C:\Users\josep\AppData\Local\Temp\claude\e--wazhu-Siem-code\8997c8b0-ab09-4f41-9f9b-6a0817f61a90\scratchpad\siem-cdb-old-backup`
- Until step 4 is done, the agent given to customers (pilot 23 Dec) is still upstream-derived
  code under the GPL. If the manager is installed on a customer's own servers, the same
  holds for the manager and the rule files.
- A lawyer should confirm the clean-room method (description side may read old code; the
  code side never does).

## 5. Where things are

- Plan and progress: `specs/README.md`; features: `specs/FEATURES.md`; descriptions:
  `specs/siem-*.md`; step 3 inventory (every file, who uses it, the order): `specs/STEP3.md`;
  this file: `specs/HANDOFF.md`.
- Start-up: `E:\wazhu-Siem-code\start-all.bat` (ClickHouse and Valkey in Docker; siem-api on
  :8088; UI `ng serve` on :4200).
- Live tests: `cargo test -p siem-api --bin siem-api -- --ignored` (needs ClickHouse on :8123).
