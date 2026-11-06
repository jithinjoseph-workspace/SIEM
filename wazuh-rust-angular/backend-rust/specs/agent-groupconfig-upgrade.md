# provigil-agent: central group configuration and remote upgrade

Written 2026-11-04. Describes what the new agent code must do. Contains no code. Written from this
description only; no old agent code is opened. Both are ProVigil's own designs (the old agent's
mechanisms — merged shared files over its own protocol, signed WPK packages — are not copied).

## 1. Central configuration (the console's Groups page)

Server (already built): `GET <manager>/api/v1/agents/<id>/config` with the agent's key
(`Authorization: Bearer <key>`) returns `{"version": "<hex>", "config": {...}}`. `config` holds
the same field names as `provigil-agent.json` (any subset): `event_channels`,
`event_channel_queries`, `localfiles`, `fim_paths`, `fim_realtime`, `fim_whodata`, `fim_ignore`,
`fim_scan_interval_secs`, `registry_keys`, `registry_ignore`, `rootcheck_enabled`,
`rootcheck_interval_secs`, `sca_interval_secs`, `labels`, `buffer`.

Agent:
- Fetch at start (after enrollment) and every 300 s, through the transport (failover applies).
- Save the last received answer to `data\group_config.json` and use it at the next start before
  the first fetch succeeds (the agent works offline with the last known group settings).
- Effective settings = `provigil-agent.json` (local) overlaid by the group `config` (revised 2026-11-04: every list is ADDED to the local one, like the old agent's agent.conf; channel queries merged per channel). Original text: for list
  fields the group list REPLACES the local one when present and not empty, except `labels`,
  `localfiles`, `fim_paths` and `registry_keys`, which are the union (local first, duplicates
  removed); scalar and object fields from the group replace the local value.
- When `version` changes: log `Group configuration changed (version <v>); applying.` and apply.
  Applying = stop the collection loops (event channels, log files, FIM / real-time / who-data,
  registry, rootcheck, SCA, inventory) cleanly, then start them again with the new effective
  settings. The transport, buffer contents, identity, keepalive and command handling are not
  interrupted; no event in the buffer is lost.
- A config that cannot be parsed: logged, ignored, the current settings stay.
- The effective settings are logged at info (one line per changed field) when applied.

## 2. Remote upgrade

Server side (to be added in siem-api): an upgrade command for this agent is queued like the
other commands (keepalive answer): `{"command_id": "...", "type": "upgrade", "url": "<https or
manager-relative URL of the new provigil-agent.exe>", "sha256": "<hex>", "version": "<x.y.z>"}`.

Agent:
- On an `upgrade` command: download the file (through the manager's address when the URL is
  relative; at most 200 MB; 10 min timeout) to `upgrade\provigil-agent-<version>.exe`, verify the
  SHA-256 (mismatch → result `failed` with reason, file deleted).
- Report the start: result `{"command_id", "status": "in_progress", "version"}`.
- Write `upgrade\upgrade_result.json` with `{"status":"pending","version","from_version","timestamp"}`.
- Start a detached helper (a small PowerShell or cmd script generated in `upgrade\`) that: waits
  for the agent service to stop, renames the current `provigil-agent.exe` to
  `provigil-agent.exe.bak`, moves the new one into place, starts the service, and after 60 s checks
  the service is running; if not, restores the `.bak`, starts the service, and writes
  `{"status":"rolled_back", ...}` to the result file; on success writes `{"status":"done", ...}`.
  Then the agent stops its own service.
- At start (existing `check_previous_upgrade_result`): a result file with `done` / `rolled_back`
  / `failed` is reported once as an `upgrade_notification` event and as a command result, then
  removed.
- The keepalive carries `"version": "<agent version>"` (the crate version) so the manager shows it.
- Only one upgrade at a time; a second command while one runs is answered `failed` ("upgrade in
  progress").

## Tests

- Overlay rules: replace vs union per field; scalar replace; unparsable config ignored.
- Saved group config used at start before the server answers (fake transport).
- Apply on version change: loops restarted with new settings (a test hook counts restarts), the
  buffer is untouched; same version → nothing restarted.
- Upgrade: SHA-256 mismatch → failed and file removed; the generated helper script contains the
  rename, move, start and rollback steps in that order (text checks); result file reported once
  at next start; second upgrade refused while one runs.

Then `cargo test -p provigil-agent`, clippy clean on the files changed (`--no-deps`), build.
