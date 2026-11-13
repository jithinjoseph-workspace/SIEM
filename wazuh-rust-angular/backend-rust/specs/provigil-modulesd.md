# provigil-modulesd: own code for the manager modules service

Replaces `crates/siem-modulesd` (4,013 lines, ported) and the message router it hosts
(`crates/siem-router` 5,485 + `crates/siem-njson` 1,607 lines, used only here). New crates:
`provigil-modulesd` (the service), `provigil-ipc` (agent-database client, local sockets, and the
platform stream moved out of `siem-ipc`) and `provigil-daemon` (log writer, settings, `ossec.conf`
reading, PID file; also used by `provigil-db`). Method as for `provigil-db.md`: every feature listed,
own code, old vs new compared, live check, old code to `old-code/`.

## 1. Features of the old service, and where each goes

| Old file | Feature | New |
|---|---|---|
| `bin/provigil-modulesd.rs` | flags `-d` (more log, repeatable) `-f` `-t` (check settings, stop) `-h` (help) | same (`provigil-modulesd`) |
| | home folder, chdir; log `logs/ossec.log` with tags `provigil-modulesd:<module>` | same (cwd is the home; siem-api starts it there) |
| | internal options `provigil_modules.debug` (0–2), `rlimit_nofile` (8192–1048576), `max_eps` (1–1000, invalid = stop) | same keys and ranges; `rlimit_nofile` is Unix only (no effect on Windows, as before) |
| | PID file `var/run/provigil-modulesd-<pid>.pid`, `Started (pid: N).` | same |
| | module start order: agent-upgrade, task-manager, router, vulnerability scanner, database, download | router, scanner, database (see M-1 for the others) |
| `database.rs` + `wdb.rs` | manager row (agent 0): host name, node name, OS fields from this machine, version, statuses | same |
| | agents of the key table (client.keys or siem-api's key service) inserted into global.db; agents without a key removed with their database, diff folder, counter and timestamp line | same |
| | registration date from `queue/agents-timestamp` | same |
| | groups: one per folder of `etc/shared`, removed when the folder goes | same |
| | legacy group files `queue/agent-groups/<id>` imported then deleted (worker nodes delete only) | same |
| | dangling agent databases (`queue/db/<id>.db` of no agent) removed | same |
| | interval loop: key table changes (file stamp, or the key service's version) re-sync on worker nodes; groups every cycle; `Cycle completed`, `Time interval exceeded by N seconds.` | same |
| | settings `wazuh_database.sync_agents` (module on/off) `real_time` `interval` (0–86400) `max_queued_events` | keys renamed `provigil_database.*` (same ranges); see M-3 for `real_time` |
| | Linux inotify real-time watching of `etc/` and `etc/shared` | M-3 |
| `vulnscan_host.rs` | starts the own scanner (`provigil-vulnscan`) with the daemon log (scanner tags), router and siem-api stream | same |
| siem-router (hosted) | per-topic broker on `queue/router/<topic>` (port file on Windows): `P` frames from publishers delivered to subscribers; remote subscriber registration (`{"subscriberId":..}` → `{"Result":"OK"}`, then each message on that connection); registration socket `queue/router/subscription.sock` (`InitProvider`, `RemoveSubscriber`) | own broker, same wire format and messages (M-2) |
| | flatbuffer topics `deltas-syscollector`, `rsync` decoded to JSON for the scanner | M-2 |
| `agent_upgrade.rs`, `task_manager.rs`, `task_general.rs` | WPK upgrades of old-protocol agents through `queue/sockets/remote`; the task socket `queue/tasks/task` keeping upgrade tasks in provigil-db | M-1 |
| `download.rs` | `queue/sockets/download` HTTP download helper (`wazuh_download.enabled`) | M-1 |

## 2. Decisions

**M-1 (13 Nov 2026): agent-upgrade, task-manager and download are not carried over.** They serve
agents of the old protocol only: the upgrade module sends the package through the old agent
receiver's socket (`queue/sockets/remote`), which nothing serves since that receiver was retired
(agents connect only through provigil-gateway; port 1514 is closed). ProVigil agents upgrade over
HTTPS from siem-api (`queue_http_upgrade`). The task manager only records those upgrades, and the
download helper has no caller. siem-api's upgrade endpoints answer for ProVigil agents without the
module (POST: queued with the next keepalive; GET: no task recorded), and for other agents say the
old protocol cannot be upgraded. The old code stays in `old-code/` for reference.

**M-2 (13 Nov 2026): the router is a small own broker.** The only publishers are provigil-db,
agent-server and siem-api (JSON on `wdb-agent-events` and `wdb-inventory-events`) and the only
subscriber is the scanner in this process. The broker keeps the wire format (`[u32 size][u32 header
size][header][body]`, little endian), the `P` publish frames, remote subscribers and the
registration socket, so any client of the old one works. The binary (flatbuffer) topics
`deltas-syscollector` and `rsync` had one publisher, the retired agent receiver; their messages are
now delivered only when they are JSON (a binary message is dropped and counted in the log).

**M-3 (13 Nov 2026): no inotify; the interval loop everywhere.** The platform runs on Windows,
where the old service already used the interval loop. Key-table and group changes are picked up
within `interval` seconds (60 in the shipped settings) on every system; `real_time` and
`max_queued_events` are read and checked but have no other effect.

**M-4 (13 Nov 2026): an empty key list removes nothing.** The old service removed every agent
(with its database) when the key list came back empty, which happens when it starts without
siem-api's key service and without `client.keys` (a manual start). Now an empty list while agents
are registered only logs `The key list is empty: none of the N registered agents is removed.`; a
list that lacks some agents still removes those (`tests/compare_database.rs`).

- **M-5 Manager version (2026-11-13).** The manager row (agent 0) carries `ProVigil v<version>` (the service's own version), no longer the upstream product name and version. Nothing reads it to decide anything; the console's agent list comes from siem-api's registry.

## 3. Progress

Done 13 Nov 2026: `provigil-ipc` (stream moved, db client, local sockets), `provigil-daemon` (with the
exact cluster rules of the old reader: a cluster section without `node_type` counts as a worker for
the database module; single node unless an enabled cluster has a node type; also fixed in the
`provigil-db` program), the database module (`tests/compare_database.rs`: start-up of old and new on
the same manager setup, as worker and as master, gives the same requests, rows, files and log
lines), the router broker (`router::tests`), the scanner host and the service program
(`provigil-modules` until switch-over).

Switch-over done 13 Nov 2026: siem-api's upgrade endpoints no longer use the module (M-1); the
program is `provigil-modulesd`; settings keys `provigil_database.*`; `siem-modulesd`, `siem-router`
and `siem-njson` moved to `old-code/` (outside the workspace; the comparison test uses
`siem-modulesd` as a library). Smoke test on a copy of the manager data: starts, opens the
router, runs the database module's start-up. Live under siem-api (13 Nov 11:55): all services
started without errors, the router opened its five topics, the agents loaded from siem-api's key
service, heartbeats written, and a re-scan request sent through the router was scanned and its
results stored in ClickHouse 2 seconds later.
