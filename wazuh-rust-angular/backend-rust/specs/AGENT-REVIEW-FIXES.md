# provigil-agent: fixes from the old-vs-new review (2026-11-04)

From a line-by-line review of the old Windows agent against `crates/provigil-agent` (description
only; fixers do not open the old crates). Each item: what is wrong, the fix. Grouped by who fixes it.

## A. Agent core (edr.rs, service.rs, lib.rs, transport.rs, identity.rs, config.rs, logfiles.rs, main.rs, upgrade.rs)

1. **Restart from the console leaves the agent stopped.** `edr.rs` `run` spawns response programs with
   `kill_on_drop(true)`; when the service stops (`service.rs` drops the runtime), `restart-wazuh.exe` is
   killed after stopping the service and before starting it. Fix: for the restart program, spawn detached
   (`DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`, no kill-on-drop), as `upgrade.rs` `launch` does.
2. **Group configuration can run any shell command on agents.** `agent_config.rs` `translate` turns
   `<localfile><log_format>command|full_command` into agent `localfiles` command entries, run by
   `logfiles.rs` `CommandJob`. The old agent refused commands from the central configuration unless the
   local option `logcollector.remote_commands=1`. Fix: command entries that come from the group are
   dropped (logged once) unless local `provigil-agent.json` has `"allow_remote_commands": true`
   (default false). Local command entries keep working.
3. **Timed response undos are lost on stop / restart / upgrade** (host stays isolated, IP stays
   blocked). Fix: persist pending undos to `data\ar_timeouts.json` (program, arguments, due time); at
   start run the overdue ones and re-arm the rest. A repeated command for a key that is already active
   extends its timeout (instead of aborting). A key with timeout 0 must not stay "active" forever.
4. **No re-enrollment** when the manager refuses the key or the agent was removed: keepalive fails
   forever. Fix: after 3 consecutive keepalive answers 401/404/410 (not network errors), delete
   `data\agent-identity.json` and run the existing enrollment loop (with the tenant key), log it.
5. **Manager URL silently falls back to `http://127.0.0.1:8088`** and a `provigil-agent.json` that fails
   to parse is ignored without a log line (`config.rs` `load_or_default`). Fix: log the parse error; no
   127.0.0.1 fallback (the "no manager address" wait in `lib.rs` then works).
6. **Batches over the server limit are dropped silently** (413). Fix in `transport.rs` `flush_events`:
   on 413 split the batch in halves and re-queue; a single event that is still too big is dropped with
   an error log naming its type.
7. **Private CA**: optional `ca_file` (PEM) in the config, added to the trusted roots of the HTTPS
   (reqwest) and gRPC (rustls) clients.
8. **Response command names**: only `[A-Za-z0-9_-]` allowed (`..\` could reach outside
   `active-response\bin`); optional `active_response_enabled` (default true).
9. **Agent log**: rotate while running (at 10 MB rename to `.1`, keep 5); honour the config
   `log_level` (RUST_LOG still wins).
10. **"Agent started"** event at start (`event_type: "agent_status"`, message
    `ProVigil agent started`) and a final keepalive with `"status": "stopping"` at service stop.
11. **Log files**: send an event `ProVigil logcollector: File rotated (inode changed): '<path>'.` /
    `ProVigil logcollector: File size reduced (inode remained): '<path>'.` when `read` detects
    replacement / truncation (the manager's rules key on "File rotated" / "File size reduced"); expand
    `%Y %m %d %y %H` date patterns and `%VAR%` environment variables in `location`.
12. **Enrollment details**: send the group(s) from config and a cleaned name (letters, digits, `.`,
    `_`, `-`); send `os_type` (gRPC reads `os_type`); one version string everywhere
    (`CARGO_PKG_VERSION`, also in `--help`); restrict `data\agent-identity.json` to SYSTEM and
    Administrators.
13. **Group sync status**: keepalive carries `"group_config_version"` (the applied version).

## B. FIM (fim.rs, diff.rs, realtime.rs, config.rs defaults)

1. Record and compare **owner SID, DACL (SDDL), attributes, mtime** and **md5 + sha1 + sha256**; report
   `changed_attributes` (`size`, `permission`, `uid`/owner, `attributes`, `mtime`, `md5`, `sha1`,
   `sha256`) with old/new values in the event. Reuse `registry.rs`'s security helpers.
2. Defaults like the old agent: `fim_scan_interval_secs` 43200, `diff_enabled` false (report_changes off
   unless configured; then per path list `fim_report_changes`).
3. `crawl`: recursion limit 256 (`fim_recursion_level`), do not follow reparse points (junctions /
   symlinks) — no loops.
4. `fim_ignore`: exact path or folder boundary (`C:\a\tmp` must not ignore `C:\a\tmpfile`); entries
   starting with `regex:` are case-insensitive regexes. `fim_nodiff` list; `fim_file_limit` 100000.
5. diff: snapshot names must not collide (hash of the full path); refresh / delete snapshots of deleted
   files; when the quota is full say so in the event instead of a stale diff.
6. Real-time must not wait for the whole scheduled scan (lock only per file update).

## C. Server (siem-api: main.rs ingest, http_agent_state.rs, agent_config.rs)

1. **FIM and registry events go through the analysis engine** like the old agents' (syscheck queue
   `'8'`, the old syscheck event JSON the engine's syscheck decoder reads), so rules 550–554 / 594–598,
   compliance tags, active-response triggers and the `fim_entry` table with full attributes work. The
   hand-written `fim_file` / `registry_value` writers in `http_agent_state.rs` then go (they store one
   row per key, values overwrite each other, arch always x64, data in `value_name`).
2. `DefaultBodyLimit::max(16 MiB)` on the agent ingest route.
3. `agent_config.rs` `translate`: `arch="both"` → both views; `<ignore type="sregex">` → `regex:`;
   `<syscheck><disabled>yes` → `fim_enabled: false`; `<sca><enabled>no` → `sca_enabled: false`;
   `<wodle name="syscollector"><interval>` → `inventory_interval_secs`; `report_changes` / `nodiff`
   / `recursion_level` directory attributes; never emit command localfiles unless flagged (agent A2
   still refuses them).
4. Keepalive `group_config_version` → global.db `group_config_status = 'synced'` when it equals the
   current version for that agent, else `'not synced'`.
5. Remove the dead `http_agent_state.rs` `sca` writer path (new agents send `message` strings).

## D. Inventory (osinfo.rs, syscollector/win.rs)

1. Hotfixes from all sources: WMI QFE, Windows Update history, CBS `Packages` registry
   (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`, `KB\d+` in
   names, installed state), and the HotFix / Installer registry keys; de-duplicated.
2. Packages also from the Microsoft Store (AppX for all users), Python packages (site-packages
   `*.dist-info` / `*.egg-info` of installed Pythons) and global npm packages
   (`%APPDATA%\npm\node_modules`, `Program Files\nodejs\node_modules`), with the source as `format`
   (`win`, `appx`? / `pypi` / `npm`) as the vulnerability scanner expects.

## E. SCA (sca/mod.rs, rootcheck.rs reg helper)

1. Registry reads: 64-bit view, then the 32-bit view when the key is missing.
2. REG_MULTI_SZ text: strings joined by a space with a trailing space; REG_QWORD as hex bytes like the
   old engine (check the dialect with the existing manifest tests).
3. A `policies` message per scan listing the policy ids scanned, so the manager removes results of
   policies no longer scanned.
4. `sca_enabled` (default true), `sca_disabled_policies` list, default interval 43200 s.

## Later / to decide

- Remote upgrade: signature check of the new exe (Authenticode via `dll_guard::verify`) and shipping
  the response programs with the agent.
- Command wodle (hash-checked binaries), osquery: decide whether needed.
- Remote config / state queries from the manager.

## F. Transport and server load (from the gRPC measurements, 2026-11-04)

Measured: gRPC transport ~238k events/s per agent (HTTPS ~162k), 1,000 agents fine with a no-op
handler. The real limit is the server-side handler. Bench files: `siem-api/src/agent_grpc_bench.rs`,
`provigil-agent/src/transport_bench.rs` (all `#[ignore]`).

1. `siem-engine` `process_event` holds one `std::sync::Mutex` over the whole rule loop and the
   frequency check scans every stored hit (up to 50,000) per rule per event: 0.3 → 5 ms per event,
   blocks tokio workers. Fix: count only hits inside the time window (iterate newest first, stop at
   the window start); run the engine step in `ingest` via `spawn_blocking` / `block_in_place`.
2. `agent_keepalive` removes the agent's queued commands, then awaits provigil-db writes
   (`http_agent_state::keepalive`, `labels`); with provigil-db down that takes 15 s, the agent times out
   and the commands are lost. Fix: run those two writes in `tokio::spawn`.
3. Agent `buffer.rs` batch: stop adding events at ~1 MiB of JSON (a >16 MiB gRPC batch is re-queued
   forever today; >2 MiB HTTPS is 413).
4. Agent `transport.rs` `grpc_fail`: `Code::Unknown` / `Code::Cancelled` (connection reset / dropped) →
   `Fail::Down`, so failover/fallback treat them as network errors.
5. HTTP/2 keepalive: client `grpc_channel` `.http2_keep_alive_interval(30s)
   .keep_alive_timeout(10s).keep_alive_while_idle(true).connect_timeout(5s)`; server `serve`
   `.http2_keepalive_interval(Some(60s)).tcp_keepalive(Some(60s))`.
6. `agent_grpc.rs` `upgrade`: stream the file in 1 MiB chunks from `tokio::fs::File` (today the whole
   package is copied per download: ~18 MiB each).
7. `agent_grpc.rs` `serve`: `.concurrency_limit_per_connection(8).timeout(14s)`.
8. Batch id: the agent adds a `batch_id` (uuid) to each events request (gRPC `EventsRequest` and the
   HTTPS body); the server keeps the last 64 ids per agent and answers OK without re-processing a
   repeat.
9. Agent fallback: before switching back to gRPC after the 10-minute HTTPS period, one probe call
   (keepalive) decides; `send_result` re-queues a result that could not be sent (in memory, max 100).
10. Deployment (not code): a TLS certificate and `SIEM_GRPC_TLS_CERT` / `SIEM_GRPC_TLS_KEY` in the start
    scripts, and HTTPS on 8088, so agent keys never travel in clear text.

## G. Remaining old-agent features (owner: "no gaps", 2026-11-04)

Described from the review; written as ProVigil's own design. Each item: agent side, the group
configuration translation in siem-api `agent_config.rs` `translate`, and a test.

### G-a (agent: new modules, logfiles.rs, rootcheck.rs, edr.rs, config.rs, lib.rs; server: agent_config.rs)

1. **Scheduled commands** (`commands` in config): `[{name, command, interval_secs, run_on_start,
   ignore_output, timeout_secs, sha256?}]`. Runs each command on its interval (first run at start when
   `run_on_start`), with a timeout (default 600 s, process tree killed); when `sha256` is set, the
   program (first word of the command, resolved through PATH) must have that SHA-256 or the run is
   refused and logged. Output (stdout + stderr, unless `ignore_output`) is sent as one event per line,
   `event_type: "command"`, location `command_<name>`, so the manager's rules see it like the old
   command module. Commands from the group run only when local `allow_remote_commands` is true (same
   gate as command log files). Group: `<wodle name="command">` (`tag` → name, `command`, `interval`,
   `run_on_start`, `ignore_output`, `timeout`, `verify_sha256`).
2. **osquery**: `osquery: {enabled (false), log_path (default
   C:\Program Files\osquery\log\osqueryd.results.log), run_daemon (true), bin_path (default
   C:\Program Files\osquery\osqueryd\osqueryd.exe), config_path (optional)}`. When enabled and the
   daemon is installed: start it if `run_daemon` and not already running (restart it if it stops, at
   most every 60 s), and tail the results log (JSON lines) like a `json` log file, location `osquery`,
   so its results reach the manager. Not installed: one warning, nothing else. Group: `<wodle
   name="osquery">` (`disabled`, `run_daemon`, `bin_path`, `log_path`, `config_path`).
3. **Rootcheck per-check switches**: `rootcheck_checks: {files, trojans, policies, ads, processes,
   ports, masquerading, drivers}` (all true by default) honoured by `rootcheck.rs` (`RootcheckConfig`
   already has flags); `rootcheck_base_directory` (default `C:\`). Group: `<rootcheck>` `check_files`,
   `check_trojans`, `check_winapps`/`check_winmalware`/`check_winaudit` (policies), `base_directory`,
   `disabled`.
4. **Log formats** in `logfiles.rs`: `mssql_log` (an entry starts with a `yyyy-mm-dd hh:mm:ss` timestamp;
   following lines are joined), `postgresql_log` (an entry starts with a `yyyy-mm-dd hh:mm:ss`
   timestamp; lines starting with a tab are joined), `snort-full` (blocks separated by an empty line,
   joined); `max_size` per log file (when reading from the start, skip to the last `max_size` bytes);
   per-log-file `labels` (`{key: value}` added to each event of that file as `labels`). Group:
   `<localfile><label key="">`, `<max-size>`.
5. **Repeated offenders** (`edr.rs`): `ar_repeated_offenders: [minutes, ...]` (e.g. `[30, 60, 120]`); a
   timed response for a key that already ran N times in the last 24 h gets the N-th entry as its
   timeout (last entry when more). Kept in `data\ar_timeouts.json` with the undos. Group:
   `<active-response><repeated_offenders>30,60,120</repeated_offenders>`.

### G-b (after part F; agent: upgrade.rs, registry.rs, buffer.rs, transport.rs, edr.rs; server: provigil_manager.rs, main.rs)

6. **Upgrade signature and response programs**: the upgrade command may carry `files: [{name, url,
   sha256}]` (the agent exe plus the response programs); every file is downloaded and checked, and the
   helper swaps all of them (rollback restores all). When the running `provigil-agent.exe` is
   Authenticode-signed, the new exe must be signed by the same subject (check with
   `dll_guard::verify` + subject comparison) or the upgrade fails. Server `queue_http_upgrade` lists the
   published response programs with their SHA-256.
7. **Manager queries**: commands `{"type":"getconfig"}` (the effective settings, keys and tenant key
   removed) and `{"type":"getstate"}` (versions, connected manager and transport, buffer size and state,
   last keepalive, last scan times per module, event counts) answered as command results with the
   JSON. Server: `GET /api/v1/agents/:id/live/config` and `/live/state` (console auth) queue the command
   and wait up to 30 s for that `command_id`'s result (store results by id; today `response_result`
   only logs them).
8. **Registry restrict and report_changes**: `registry_restrict_key` / `registry_restrict_value` (regex
   lists: only matching keys / values are monitored), `registry_report_changes` (keys whose value data
   is sent with changes; others send hashes only, no data). Group: `<windows_registry
   restrict_key="" restrict_value="" report_changes="yes">`.
9. **min_eps**: buffer `min_eps` (default 50); `events_per_second` is never below it.

## H. 10,000 agents on the new path (siem-api), 2026-11-05

The old path (remoted) was load tested to 10,000 agents (`docs/LOAD_TEST_RESULTS.md`). The new path was
only measured to 1,000 with a no-op handler and 100 with the real handler, ClickHouse off.

1. `agent_keepalive` and `ingest` do one awaited single-row ClickHouse INSERT per keepalive / batch
   (`db.rs` `insert_or_update_agent`). Fix: write the `siem_agents` row at most every 60 s per agent, or
   at once when its status, name, IP or version changes; never awaited on the request path.
2. `http_agent_state::keepalive` makes one `global.db` UPDATE per agent every 10 s. Fix: one background
   flusher every 10 s: `UPDATE agent SET last_keepalive = ?, connection_status = 'active', ... WHERE id IN
   (...)` in chunks; version, node and IP only when changed. Labels written only when they changed.
3. `/api/server-info`, enrollment, and the agents list must stay usable at 10,000 agents; check the console
   agents page (list size, paging) too.
4. **Load test tool**: simulated agents speaking the real protocol (gRPC, and HTTPS as an option): enroll N
   agents in a dedicated tenant, keepalive every 10 s, EPS per agent as an option, realistic Windows event
   payloads, a burst of SCA / inventory. Reports: events sent vs stored in ClickHouse, keepalive and batch
   latency p50/p99, errors, analysisd queue usage and drops, siem-api CPU and memory. Runs 1,000 / 5,000 /
   10,000 agents like the 16 Oct test, same targets: 5,000 agents at 5,000 EPS and 10,000 at ~4,000 EPS,
   no event lost. Cleans up its tenant and agents afterwards.

## I. TLS for agent traffic (owner: fix before the pilot, 2026-11-05)

Goal: no agent key, tenant key or event crosses the network in clear text, with no public CA and no
manual certificate work. Today 8088 is plain HTTP, 8089 plain gRPC, and the install script enrolls over
plain HTTP, so the agent's key is returned in clear.

**Server (siem-api)**
1. At start, a server certificate from a private CA (reuse the CA and `server_cert` code in
   `syslog_tenancy.rs` if it is install-wide and persisted; else an install-wide CA in `data/tls/`,
   key file readable only by the service account). SANs: `SIEM_LAN_IP`, the host name, `localhost`,
   `127.0.0.1`. Re-issued from the same CA when the host list changes or the certificate is near
   expiry (agents trust the CA, so they keep working).
2. gRPC 8089 uses it by default (`SIEM_GRPC_TLS_CERT` / `_KEY` still override it): `grpcs://`.
3. New HTTPS listener on `SIEM_TLS_PORT` (default 8443) serving the same router, with the same body
   limits. 8088 stays for the console.
4. On plain 8088, agent routes (enroll, keepalive, ingest, response_result, config, yara-rules,
   commands, agent state) from non-loopback addresses answer 426 Upgrade Required, unless
   `SIEM_AGENT_PLAIN=1`. Loopback stays allowed (local tests, the load tool).
5. `/api/server-info` adds `https_url`, `grpc_url` (`grpcs://`), `ca_pem`, and `agent_files` (`{name:
   sha256}` of the published agent files, cached by file time).

**Install (ndr-ui `agent-deploy.ts`)**
6. The console fetches `/api/server-info` and embeds in the generated command: the CA PEM (written to
   `<install>\ca.pem`), `manager_url` = the `https_url` on the host the console is reached at,
   `grpc_url`, `ca_file`, and the SHA-256 of each file (each download checked with `Get-FileHash`; a
   mismatch stops the install).
7. The script no longer enrolls. It writes `provigil-agent.json`, removes the old identity, starts the
   service; the **agent enrolls itself over TLS** with the pinned CA. The script waits up to 60 s for
   `data\agent-identity.json` and prints the agent id and name, or a clear error.
8. Agent `identity.rs`: send `force: true` when `provigil-agent.json` has `"force_enroll": true`, which
   the script sets (a re-deploy must get a new key).
9. Linux: the install script and `siem-agent-linux` use the `https_url` and `ca_pem` the same way
   (`SIEM_CA_FILE`), and enrollment goes over TLS.

**Load tool**: `provigil-loadtest` takes `--ca <file>` so the live test uses TLS as real agents do.

**Tests**: real TLS end to end with generated certificates, gRPC and HTTPS: agent connects with the
CA; another CA is refused; a wrong host name is refused; the plain port answers 426 for a non-loopback
agent route and works for loopback; the certificate is re-issued when the host list changes and the
old CA still verifies it; `force_enroll`; server-info fields; the generated script text (CA written,
hash check, no enroll call, no key in it).

## J. FIM baseline on the manager (found in the live check, 2026-11-05)

The old agent synced its whole baseline, so the console's FIM tab lists every monitored file and registry
value. Ours sends only changes: an unchanged file never appears, and a re-enrolled agent starts empty.

1. Agent: after a new enrollment (a new agent id; remember the last synced id in `data\fim_synced.json`)
   and after the first scan has a baseline, send the baseline once as `event_type: "fim_state"` events:
   batches of 200 entries (`entries: [...]`, files and registry values, with the same field names as the
   `*_after` fields of a change event), paced so it does not crowd out events. Later changes keep coming
   as normal events, so the state stays current. A batch that fails is retried (normal buffer rules).
2. Server: `fim_state` is written to `fim_entry` through provigil-db (`syscheck save2`), **without** the
   analysis engine, so no alert fires: a baseline is not a change. Rows must match what the syscheck
   decoder writes for the same path (same key: `full_path` for files, the index hash for registry values),
   so a later change updates the row instead of adding a second one.
3. At 10,000 agents this is a one-time load per enrollment; the registry baseline is ~27,000 rows on a
   real PC. Measure the write rate on the real provigil-db and report it; pace the agent so a fleet-wide
   enrollment cannot flood it (`fim_state` at most 1 batch per second per agent).

## K. Vulnerabilities per agent and Excel reports (owner, 2026-11-05)

**Page (`ndr-ui/src/pages/analyst/vulnerabilities/`)**
1. Default view **Agents**: one row per agent: name, id, OS, Critical / High / Medium / Low, total, sorted
   by critical then high; search; paged (100 per page). Click a row: that agent's CVE list (the existing
   table), a back button, and Export. The fleet **By CVE** view stays as a second tab.
2. `fixed_version`: `vulnerability.rs` `from_doc` fills it from the scanner's condition
   (`Package less than X` / `less than or equal to X`, the `X`) when the document has none; all 492 rows
   today show N/A. `equal to` conditions: none.
3. **Check flag**: a Windows package whose fixed version's major number is at least 3 above and twice the
   installed one (different numbering, e.g. Steam 2.10.91.91, WebAdvisor 4.1.2.131 vs an 8.x fix):
   `needs_review: true` on the item; a small "Verify" badge on the page. Nothing is hidden.

**Excel report (server, new `crates/siem-api/src/vuln_report.rs`, `rust_xlsxwriter`, MIT)**
`GET /api/v1/vulnerabilities/report.xlsx?agents=079,080&severity=critical,high&columns=...` with console
auth, scoped like `/api/v1/vulnerabilities` (`agent_in_scope`; an agent outside the scope is refused).
`agents` empty = all in scope. File name `ProVigil-Vulnerabilities-<agent or Fleet>-<yyyy-mm-dd>.xlsx`.

Layout follows the owner's tracker (layout only, none of its content):
- Sheet **Summary**: table Risk / Total: rows Critical, High, Medium, Low, then Total as a `=SUM()`
  formula. Header bold, fill `D0CECE`; risk cells filled Critical `FF0000`, High `FF6600`, Medium `FFC000`,
  Low `92D050`. Below: Agent(s), OS, Generated at, Report by ProVigil. For a fleet report, also a table per
  agent (Agent, Critical, High, Medium, Low, Total).
- Sheet **Details**: font Aptos 11; header bold white, centred, fill `7030A0`; header row frozen; auto
  filter; long columns wrap. Default columns, in order:

  | Column | From | Width |
  |---|---|---|
  | Risk (cell coloured as above) | severity | 12 |
  | CVE ID (link to reference) | id | 18 |
  | Vulnerability Title | title | 43 |
  | Description | description | 65 |
  | CVSS Score | score | 10 |
  | Agent | agent name + id | 22 |
  | Package | package name | 32 |
  | Installed Version | version | 16 |
  | Fixed Version | fixed_version | 16 |
  | Location | package path | 49 |
  | Recommendation | `Update <package> to <fixed> or later.` / `No fixed version listed; check the vendor.` | 49 |
  | Published / Detected | dates | 14 each |
  | Reference | url | 40 |
  | Check | `Verify: version numbering differs` when `needs_review` | 22 |
  | Status | dropdown (data validation): Open, In Progress, Fixed, False Positive, Accepted Risk; default Open | 15 |

- Fleet with several agents: one Details sheet per agent (sheet name = agent name, max 31 chars, unique), up
  to 200 agents; beyond that one Details sheet with the Agent column. A single-agent report leaves out
  Agent. Rows sorted by CVSS, highest first.
- `columns` picks and orders the columns (unknown names refused); empty = the default set.

**Console**: an Export dialog on both views: agents (the current one, selected ones, or all), severities,
column checkboxes (remembered in `localStorage` with try/catch), Download. Fetch with the auth header and
save the blob (no token in the URL).

**Tests**: `from_doc` fixed version; `needs_review`; the workbook read back (sheets, headers, Summary formula,
one row per CVE, the Status dropdown); `columns` order and refusal; a scope refusal; UI type-check.

## L. Last Windows-agent gaps (2026-11-05)

1. **Shutdown in ~2 s**: on service stop the runtime still waits the full 10 s `shutdown_timeout` for a
   blocked task (seen live at 09:37: pipeline stopped at :16, service stopped at :26). Find every
   blocking loop (event channel readers, who-data, real-time `ReadDirectoryChangesW`, log files,
   scheduled commands, osquery, FIM/registry/SCA/rootcheck scans, inventory) and make each one notice
   the stop flag within ~1 s: bounded waits (e.g. `WaitForMultipleObjects` with a stop event or a 500 ms
   timeout), cancel I/O (`CancelIoEx`) where a call blocks, scans that check the flag between files.
   Test: a live-style test that starts the collection loops and measures stop time; log at stop which
   tasks were still running (names) when the 10 s limit is hit.
2. **Registry subkeys**: when a key is deleted, also send deleted events for every subkey and value below
   it in the baseline (today only the key and its direct values), so `fim_entry` has no stale rows.
3. **osquery on stop**: if the agent started `osqueryd`, stop it when the agent stops (not one the user
   runs on their own).
4. **FIM baseline at fleet scale**: the server hands out baseline-sync slots in the keepalive answer
   (`fim_state_allowed: true` for at most 20 agents per tenant at a time, freed when that agent's
   last `fim_state` batch arrives or after 10 min); the agent sends `fim_state` only while allowed.
   Normal events never wait behind a baseline.
5. **Service recovery check**: a test that the install sets the recovery actions (read back with
   `sc qfailure` in a live ignored test).

## M. Event store throughput (live load test, 2026-11-05)

Run 1 (1,000 agents x 1 EPS, 3 min, TLS): agent side perfect (0 errors, keepalive p99 3.5 ms, batch p99 5 ms),
analysisd received everything (0 dropped at its input). Lost after it: siem-api did not drain the analysisd
stream fast enough; `siem-ipc/src/platform_stream.rs` dropped ~109,000 lines (queue of 50,000 full) between
10:53 and 10:56; the vulnerability connector's stream dropped ~678,000 lines (scans of the 1,000 fake
inventories). Stored: 123,789 of 165,015 Windows events, 48,065 of 61,000 SCA messages. siem-api peaked at
1.8 GB and ~2.3 cores. On 16 Oct the same path stored 5,000 EPS with no loss.

1. Measure where siem-api's stream consumer spends its time (`provigil_manager.rs` `stream_conn` ->
   `on_alerts` / `on_events` / vulnerabilities): per-line work (rules, Sigma, tamper, YARA, parsers, UEBA,
   posture, incident correlation...) vs ClickHouse inserts; compare with the 16 Oct path. Fix the hot spots:
   batch ClickHouse inserts, move per-event extras off the hot path, run independent work concurrently.
   Target: >= 10,000 lines/s drained on this PC.
2. No silent loss: `platform_stream.rs` spills to a bounded on-disk spool (`queue/stream-spool/`, e.g.
   1 GB) when the memory queue is full, and replays it in order when siem-api catches up; drops only when
   the spool is full (counted). Same for the vulnerability connector.
3. Vulnerability flood: why 1,000 inventories of 150 made-up packages produce ~678,000 stream lines; make a
   re-scan emit only changed documents.
4. Re-run the live load test (1,000 / 5,000 / 10,000) after these.

## N. No loss on crash, no files for intent dossiers (2026-11-05)

1. **Write-ahead stream with acknowledgement** (`siem-ipc/src/platform_stream.rs`, siem-api `stream_conn`):
   every line is appended to the on-disk spool first (sequential writes); the memory queue only speeds
   sending. Each frame carries a sequence number; siem-api answers `stored up to N` only after ClickHouse
   accepted that batch (all its inserts). The spool is truncated only up to the acknowledged N. On
   reconnect or restart of either side, sending resumes after the last acknowledged N (at-least-once).
   Duplicates: each event/alert keeps a stable id (the frame's sequence + source) and ClickHouse stores it
   once (ReplacingMergeTree by id, or skip ids already seen in the last window). Same for the vulnerability
   connector. Graceful stop flushes the memory queue to the spool.
   Tests: kill the sender mid-stream (no loss, order kept); siem-api dies after receiving but before storing
   (replayed); duplicate replay stored once; spool size bound still holds; throughput measured (target:
   >= 10,000 lines/s with the private ClickHouse bench).
2. **Intent dossiers in ClickHouse** (`siem-intent-engine`): a dossier is a row per (tenant, agent), written
   for the agents that changed in a batch; loaded at start; the dossier file goes (migrate it once if present).
3. **Backpressure on siem-api -> analysisd (UDP)**: siem-api compares its sent count with analysisd's
   received counter (state file or a cheap query); when analysisd falls behind by more than a threshold,
   agent ingest answers 429 (agents keep the batch and retry later) instead of overrunning the UDP buffer.
   Test: a slow fake engine makes ingest answer 429 and nothing is lost.

## O. Analysis engine capacity (live load test, 2026-11-05, new build with parts M and N)

| Run | Result |
|---|---|
| 1,000 agents x 1 EPS, 3 min | 165,015 of 165,015 stored, 0 duplicates, keepalive p99 5 ms |
| 5,000 agents x 1 EPS, 3 min | engine "Windows eventchannel decoder queue is full" at 13:45:11, SCA queue full at 13:46:32; 432,172 dropped at engine input; keepalive p50 783 ms; connection refused (876+) |
| 1,000 agents x 5 EPS, 2 min | 1,937 EPS accepted; 429 backpressure fired 27,555 times, yet the engine still dropped 72,106, which equals the missing 71,925 |

(Drive E: filled at 13:51, after the event phase of run 2: not the cause. Fixed by clearing target/debug/incremental.)
So the engine now tops out well under the 5,000 EPS it did on 16 Oct. Differences since then: the runs include SCA bursts and inventories (the 16 Oct test sent only Windows events), and part N's write-ahead runs on the engine's thread.

1. Measure the engine alone (real ruleset, `siem-analysisd` bench): Windows events/s with the stream off, with the write-ahead on, and with SCA messages mixed in. Find what stalls its single thread: expected are the SCA decoder's synchronous provigil-db queries per check, labels for agents seen the first time, and the WAL writes.
2. Fix the stalls: internal decoders' provigil-db work goes to its own worker thread and queue, never on the analysis thread; WAL appends are batched / written by a writer thread with a small buffer (keep part N's guarantees for a process crash as far as possible; state what changes). Target: >= 5,000 Windows EPS sustained with SCA bursts on this PC, measured live.
3. Backpressure must act before the engine drops: lower threshold and fresher signal than a 5 s state file (e.g. engine queue usage read every 500 ms), count only siem-api's own datagrams. Test: an overloaded engine makes ingest answer 429 and `events_dropped` stays 0.
4. Enrollment: 21-24/s normally, 2/s with timeouts after a mass removal. `agent_keys_store::save` re-encrypts and re-inserts every key per change: make it per-key. Target: >= 50/s, and enroll timeouts must not leave agents the client does not know (7 were left behind).
5. Connection refused at 5,000 connections in a burst: check the gRPC listener's accept backlog and connection ramp.
6. Is the load tool's `events sent` honest when 429s happen: re-queue like a real agent, so sent == eventually accepted.

## P. Send only what changed: SCA and inventory (owner, 2026-11-05)

Our agent sends every SCA check each scan and the whole inventory each hour; the old agent sent changes
only. At 10,000 agents that is the difference between almost no load and a flood.

**SCA**
1. The agent keeps each policy's last results locally (agent id, policy id, policy file hash, check id ->
   result), in `data\fim.db` or its own SQLite file.
2. Full send (every check, then the summary): no saved state; another agent id; the policy text changed
   (`hash_file`); or the manager asks. Otherwise send only the checks whose result changed, then the
   summary, always (it carries the hash of all results).
3. Manager asks for a full send when its hash differs from the summary's (a new or wiped database): find how
   the analysis engine's SCA decoder requests a dump (it was written for agents reachable over the old
   channel) and turn that into a queued `{"type":"sca_full","policy_id":...}` command for HTTP agents.
   Without it a wiped database never refills: this path must be tested.

**Inventory**
4. The agent keeps a hash per item per table (packages, hotfixes, ports, processes, services, users, groups,
   network, browser extensions, hardware, OS). First send: the full list. Then a `system_inventory_delta`
   event: per table `added` / `changed` / `removed` items, plus each table's item count and a hash of all its
   items. Nothing changed: no event at all, except a heartbeat of counts and hashes once a day.
   Processes change constantly: keep them out of the delta path's noise: send process changes at most
   hourly and leave out CPU and memory figures from their hash, or the delta is as big as the full list.
5. siem-api applies a delta to the SQLite tables (`http_agent_state.rs`), and compares counts and hashes: on
   a mismatch it queues `{"type":"inventory_full"}`. A vulnerability scan is requested only when packages or
   hotfixes changed.

**Tests**: an unchanged second scan sends only summaries and no inventory; one changed check or package sends
exactly that; a removed item is removed from SQLite; a wiped manager database refills through the full-send
path (SCA and inventory); a new agent id sends everything; the console pages show the same data as a full send.
Load tool: agents send the first full list, then only deltas, like real agents.

## R. Names, two EDR gaps, package size (2026-11-05)

1. **ProVigil names everywhere a customer can see**: the manager daemons' names in their log lines, counter
   (`*.state`) files, pid files, the daemon lists in siem-api, process titles, the console: `wazuh-analysisd`
   -> `provigil-analysisd`, `wazuh-db` -> `provigil-db`, `wazuh-remoted` -> `provigil-remoted`,
   `wazuh-modulesd` -> `provigil-modulesd`, and the same for execd, agentlessd, maild, monitord, integratord,
   csyslogd. Every reader of a renamed file follows (siem-api, `provigil-loadtest`, scripts); for one release
   an old-named counter file is still read if the new one is missing. Check the detection rules and decoders
   that match the manager's own log lines (read `ruleset/` for this; edit only if a match would break, and
   list every such rule). Finish with a grep of the manager crates, siem-api, ndr-ui and the start/stop scripts
   for `wazuh` that a customer could see (log text, UI text, file and process names); report what is left and
   why (internal identifiers, the ruleset text, comments).
2. **Engine-triggered responses reach ProVigil agents**: today the analysis engine sends rule-driven active
   responses only to remoted's queue, which cannot reach HTTP agents. Give siem-api that path: the engine also
   delivers responses for agents marked as ProVigil (HTTP) agents to a queue siem-api reads, and siem-api
   turns them into the agent's command (`queue_http_command`). Test end to end: a rule with an active response
   fires for a ProVigil agent and the agent's next keepalive carries the command.
3. **Durable command queue**: the ProVigil agents' queued commands and the "this agent is a ProVigil agent"
   mark move from memory to ClickHouse (a table with expiry per command, cap 200 per agent, results by command
   id), so a siem-api restart loses nothing and routes correctly at once. Design it so `provigil-gateway`
   (`specs/provigil-gateway.md`) can use the same table later.
4. **Package size**: `live-response.exe` links the whole agent (31 MB). Move the agent's `processes()`,
   `ports()`, `services()` (and what they need) into a small crate both use. Add a release profile that strips
   symbols; try `lto = "thin"` and measure exe sizes and build time; keep it only if worth it. Target: the
   response programs back near their old size, the package well under half of today's ~115 MB.
