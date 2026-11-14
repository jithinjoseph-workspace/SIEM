# Own code: replacing the upstream-derived crates

Owner's decision (2026-11-03): every crate ported from upstream is replaced by ProVigil's
own code, so the product can be sold as ProVigil's own.

## How each crate is replaced

1. A description in this folder (`<crate>.md`): what the crate must do, what siem-api
   calls, the tests it needs. No code.
2. New code written from that description only, by someone who does not open the old
   crate's files (a developer or a fresh AI session). Same crate and file names are fine.
3. siem-api switched over, the old files deleted, tests run.

A crate that nothing needs any more is deleted instead (no description).

Before any crate is deleted or replaced, every feature it has is written in `FEATURES.md`
with where it lives now. Nothing is dropped without a written reason.

## Progress

| Step | Crate | Lines | How | Status |
|---|---|---|---|---|
| 2 | siem-cdb | 358 | new code from `siem-cdb.md` | done 2026-11-03 (7 tests) |
| 2 | siem-reportd | 431 | deleted; `/api/v1/reports/summary` counts itself, PDF reports in `tenant_reports.rs` | done 2026-11-03 |
| 2 | siem-rootcheck | 812 | deleted; ProVigil agents run their own scan, `/api/v1/rootcheck/signatures` removed (unused) | done 2026-11-03 |
| 2 | siem-core | 829 | new code from `siem-core.md`; upstream config reader moved to the prototype agents | done 2026-11-03 (5 tests) |
| 2 | siem-active-response | 1,960 | shared code + 4 programs + `dll_guard` new from `siem-active-response.md`; our EDR programs kept | done 2026-11-03 (21 tests) |
| 2 | siem-engine | 2,300 | new code from `siem-engine.md` | done 2026-11-03 (13 tests) |
| 3 | mail sender (siem-api) | 288 | new code from `mail-sender.md` using `lettre` v0.11; `siem-maild::smtp_ext` replaced in `siem-api` | done 2026-11-03 (5 tests) |
| 3 | syslog sender (siem-api) | 480 | new code from `syslog-sender.md`; `siem-csyslogd` decoupled from `soar.rs` and `siem-api` | done 2026-11-03 (6 tests) |
| 3 | SOAR integrations (siem-api) | 420 | new code from `soar-integrations.md`; `siem-integratord` decoupled and replaced with in-process HTTP | done 2026-11-03 (5 tests) |
| 3 | monitord & maild features (siem-api) | 680 | new code from `monitord.md` and `maild.md`; `agent_monitor.rs` & `log_rotator.rs` in `siem-api` | done 2026-11-03 (4 tests) |
| 3 | siem-task-manager, siem-csyslogd, siem-integratord, siem-monitord, siem-maild | 14,992 | replaced by siem-api features; all 5 crates moved unread to `old-code/` | done 2026-11-03 |
| 1 | siem-harvester, siem-agentlessd, siem-shared-modules, siem-util, siem-agent, siem-agent-linux | 11,791 | delete | later (owner) |
| 4 | unified Windows agent (`provigil-agent`) | 1,850 | clean-room unified Windows agent (`provigil-agent.md`); replaces 9 upstream agent crates with high-performance, low-memory native Rust | done 2026-11-03 (6 tests) |
| 4 | siem-authd (3 pieces into siem-api) + siem-shared | 5,168 | new code from `siem-authd.md`, reviewed old vs new, moved to `old-code/` | done 2026-11-12 (2 tests) |
| 4 | siem-syscheckd, siem-logcollector, siem-remoted, siem-sysinfo, siem-dbsync, siem-syscollector, siem-agent, siem-sca, siem-util, siem-shared-modules, siem-harvester | 54,421 | unused; moved to `old-code/` | done 2026-11-12 |
| 4 | siem-agentd, siem-winagent | 9,108 | reviewed against `provigil-agent` (nothing missing), moved to `old-code/` | done 2026-11-12 |
| 4 | the agent: siem-logcollector, siem-syscheckd, siem-syscollector, siem-sysinfo, siem-sca, siem-authd, siem-remoted | 52,487 | replaced by unified `provigil-agent` and clean HTTPS/gRPC protocol | |
| 5 | siem-vulnerability-scanner | 7,321 | new code `provigil-vulnscan` from `vulnerability-scanner.md` + `vulnscan-fixes.md` (D1–D56) by a clean-room writer; reviewed old vs new line by line (`vulnscan-review.md`); differential tests 0 mismatches (329,173 version pairs, CPE, patches, records, feed) and full scans of two real PCs identical (2,880 documents, 512 alerts); then 4 owner-approved changes (section 22); old crate moved to `old-code/` | done 2026-11-12 (69 tests) |
| 5 | siem-wdb | 22,155 | new code `provigil-agentdb` from `provigil-db.md` (D-1 to D-6); every part compared old vs new by in-process tests (answers, logs, router and client messages, rows), the service and MITRE builder too; live: 242 read and 17 write requests on a copy of the manager data identical; old crate moved to `old-code/` | done 2026-11-13 |
| 5 | siem-execd, siem-agentlessd | 2,825 | new code `provigil-execd` and `provigil-agentlessd` from `provigil-execd.md` (E-1 to E-12; the old execd never started on Linux, see E-1); every part compared old vs new by tests (ar.conf, response runs, pending list, offenders, timeouts, shutdown, settings, requests, agentless settings and runs); old crates moved to `old-code/` | done 2026-11-13 |
| 5 | siem-analysisd | 17,989 | new code `provigil-analysisd` from `provigil-analysisd.md` (A-1 to A-7); every part compared old vs new by tests, then end to end: `-t` on good and broken rulesets, a live side-by-side run of 21,155 messages with provigil-db (alerts, archives, firewall log, state file, sockets, logtest identical); start-all.bat and build-release.bat build it; old crate kept only as the comparison tests' reference Old crate moved to `old-code/siem-analysisd` (comparison tests only); settings reader fault fixed (A-9). | done 2026-11-13 |
| 5 | rules / decoders / lists (`data/manager/ruleset/` and the same files in `backend-rust/ruleset/`: 168 rule, 120 decoder, 77 check-policy, 21 rootcheck, 7 list files; kept for now by the owner's decision 2026-11-03) | | own rules, decoders and Sigma side by side, then removal (`provigil-analysisd.md` section 4) | next |
| 6 | siem-config, siem-ipc, siem-crypto, siem-shared, siem-router, siem-dbsync, siem-xml, siem-regex, siem-fileop, siem-log, siem-daemon, siem-cjson, siem-njson, siem-sqlite | 32,154 | deleted when nothing uses them |siem-cjson replaced by `provigil-json` and siem-sqlite by `provigil-sqlite` (2026-11-13, compared old vs new); the configuration XML reader is in `provigil-daemon::xml` (compared with siem-xml); siem-api's agent.conf check is now `provigil-agent-server::conf_check` (compared old vs new); siem-ipc, siem-log, siem-daemon, siem-xml, siem-config, siem-cjson now used only by siem-analysisd (and comparison tests) |
