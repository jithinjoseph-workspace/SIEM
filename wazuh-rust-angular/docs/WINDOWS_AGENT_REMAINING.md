# Windows agent: what is left (for later)

Status on 2026-10-16: the Windows agent (`wazuh-agent.exe`, crate `siem-winagent`) has every
part most deployments use, each compared line for line with the original Wazuh 4.14.7 C agent:
agentd, logcollector (eventchannel/eventlog/files), execd + active responses, FIM (files,
registry, report_changes, realtime, whodata), rootcheck, SCA, syscollector, agent-upgrade,
and the `command` and `osquery` modules. Progress notes: `backend-rust/AGENTD_PORT_PROGRESS.md`.

This page lists what was deliberately left for later and why.

## 1. Modules not ported (low priority)

| Module | What it does | Size of the C code | Why it can wait |
|---|---|---|---|
| `github` | Pulls the audit log of a GitHub organization | ~660 lines | Usually configured on the manager, not on agents |
| `office365` | Pulls Microsoft 365 management-activity logs | ~1,100 lines | Same: usually on the manager |
| `ms-graph` | Pulls Microsoft Graph security logs (Defender, Entra ID) | ~970 lines | Same: usually on the manager |
| `cis-cat` | Runs the CIS-CAT Java scanner and sends its report | ~1,800 lines | Old, needs Java and a paid CIS licence; SCA covers CIS checks |

Today the agent accepts these sections in its configuration and skips them silently, as the C
agent does for a module that is compiled out. (`open-scap`, `aws`, `docker`, `azure`, `gcp`
do not run on Windows agents in C either; the port gives the same warnings.)

How to port them when needed:
- Same method as `command`/`osquery`: port `wazuh_modules/wm_<name>.c` and
  `config/wmodules-<name>.c` into `siem-winagent/src/wm_<name>.rs`, add the module to
  `wmodules.rs` (reader, start, getconfig dump), then compare with the C agent in a
  `winoracle/<name>` scenario.
- `github`/`office365`/`ms-graph` need an HTTP client in the agent (`wurl_http_request`).
  `siem-modulesd/src/download.rs` already ports `wurl_*` on reqwest for the manager; reuse it.
- They cannot be tested against the real services here without accounts: use a small fake
  HTTPS server that replays recorded API responses (pagination, rate limits, errors).
- Estimate: 1–2 days for the three cloud modules together, 1 day for `cis-cat`.

## 2. Small known differences from the C agent

- **32-bit vs 64-bit**: the C agent is 32-bit, so for paths under `C:\Windows\System32` Windows
  shows it the 32-bit files in `SysWOW64`. The Rust agent is 64-bit and sees the real System32.
  Visible in the `command` module checksums (`verify_md5/sha1/sha256` of System32 programs).
  Kept as is: a hash taken with normal 64-bit tools now matches.
- **Group editor check (siem-api)**: when an admin saves a group's `agent.conf`, siem-api checks the
  structure and `<localfile>` blocks, but not the option values of `<syscheck>`/`<rootcheck>`/wodles.
  Agents check those themselves before applying (and refuse a bad file). A server-side check would
  need per-OS readers (Linux agents accept options Windows does not).

## 3. Other planned work (separate documents)

- Code signing and MSI installer: `WINDOWS_AGENT_SIGNING_AND_MSI.md`.
- Agent releases and "update all agents": `AGENT_RELEASE_AND_UPDATE_PLAN.md`.
- Manager capacity: `LOAD_TEST_RESULTS.md`.

## 4. Not Windows-agent work, noticed on the way

- `siem-syscheckd` does not compile on Linux (`siem_ipc` used in `diff.rs`, `run_check.rs`,
  `create_db.rs` without a Unix dependency); this predates 2026-10-16 and belongs to the Linux agent work.
