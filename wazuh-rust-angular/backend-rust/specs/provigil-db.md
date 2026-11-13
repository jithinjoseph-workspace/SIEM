# provigil-db: the agent database (replacement for siem-wdb)

Status: **inventory ~60% (global, task, agent command layer done); code started 13 Nov 2026.**
**Global actor done 13 Nov 2026**: `tests/compare_global.rs` sends ~130 global requests (every
command, valid and invalid, backups) to the old and the new implementation; answers, result codes,
log lines, router messages, messages to the client and every row of the six global tables are
identical (backup create/restore compared on Linux; on Windows covered by `backups_work`, D-4).
**Task actor done 13 Nov 2026**: `tests/compare_task.rs` (50 requests: every upgrade-task command,
status move, time-out, cancel and error) identical to the old implementation.
**Agent actor so far (13 Nov 2026)**, each with its comparison test, all identical to the old code:
request layer + generic commands (`compare_agent_base.rs`), rootcheck + CIS-CAT
(`compare_rootcheck_ciscat.rs`, plus the C-style decimal reader on 4,350 inputs), SCA
(`compare_sca.rs`), legacy inventory + package/hotfix lists (`compare_inventory_legacy.rs`),
FIM + integrity commands (`compare_fim.rs`: scan info, control, old-format save with Windows
permissions/attributes, load, delete, cleandb, JSON save v1/v2/v3, `integrity_check_*` on all five
FIM components incl. the duplicate-key removal, `integrity_clear`; run with and without router).
Still to do in the agent actor: `dbsync` (13 delta tables),
`syscollector_<kind> save2` (13 kinds). Then: `wazuhdb remove`, `mitre`, background jobs,
socket server, statistics, MITRE builder, wiring.
Code progress: `crates/provigil-agentdb` created (workspace member), dev-dependency on the old
`siem-wdb` as the reference; `tests/old_schema.rs` dumps the old layout (saved in
`specs/provigil-db-layout.md`). Order: (1) core: dispatch, database files and layout, row-to-JSON,
statistics hooks; (2) `global` actor + comparison test `tests/compare_global.rs`; (3) `task`;
(4) `agent` (FIM, inventory, SCA, legacy, rootcheck, dbsync, integrity); (5) `mitre`, backups,
daemon (socket server with `.port` file on Windows), `getstats`/`getconfig`; (6) MITRE builder;
(7) wire into the binary and siem-api, live test, move the old crate.
Facts learned: a fresh global DB gets agent 0 = the manager (`localhost`, `127.0.0.1`, keep-alive
253402300799, `date_add` = real time); every new agent DB gets `sync_info` rows per component and
`metadata.db_version` 16 (global 7). Old crate: `crates/siem-wdb` (22,155 lines
incl. tests). New crate: `crates/provigil-agentdb` (not started). Proof: an in-process comparison
test sends the same requests to the old library and the new one and requires identical answers,
published messages, log lines and database rows (the old crate stays in the workspace until done).

## 0. What the old crate contains

| Part | Lines | Used by | Replace? |
|---|---|---|---|
| `src/wdb/*` + `src/bin/provigil-db.rs`: the daemon (socket `queue/db/wdb`, ~110 commands, per-agent / global / tasks / MITRE SQLite databases, backups, vacuum, schema upgrades, router publications) | ~18,000 | scanner, gateway, agent-server, siem-api, analysis daemon | yes: this spec |
| `src/wdb/http.rs`, `httplib.rs`: HTTP API (Linux only) | 2,755 | nothing on the Windows server | list features; decide |
| `src/bin/provigil-mitredb.rs`: builds the MITRE database | 617 | siem-api start-up | yes |
| `src/lib.rs`, `models.rs`, `*_store.rs`, `global_db.rs`, `wire_protocol.rs`, `agent_db.rs`, `manager_db.rs`, `integrity.rs`: in-memory store `ProVigilDbManager` | ~1,200 | siem-api (`AppState.wdb`) | check if still needed |
| `src/wdb/daemon.rs` (Linux) / `daemon_portable.rs` (Windows, what runs on this server) | 430 / 271 | the daemon | yes |

## 1. Request dispatch

A request is one text line: `<actor> <rest>`. Leading spaces and newlines are skipped. Answers
start with one of `ok`, `due`, `err`, `ign`, `unk`.

| Case | Answer | Log |
|---|---|---|
| no space after the actor | `err Invalid DB query syntax, near '<first 32 bytes>'` | DEBUG1 `Invalid DB query syntax.`, DEBUG2 `DB query: <request>` |
| unknown actor | `err Invalid DB query actor: '<actor, 32 bytes>'` | DEBUG1 `DB(000) Invalid DB query actor: <actor>` |

Actors: `agent`, `wazuhdb` (see L-names), `mitre`, `global`, `task`. Every request increments the
total query counter (statistics, `getstats`).

### 1.1 `agent <id> <command> [args]`

1. No space after the id: `err Invalid DB query syntax, near '<id>'` (DEBUG1 `Invalid DB query
   syntax.`, DEBUG2 `DB query error near: <id>`).
2. Id must be all digits (empty allowed, = 0): else `err Invalid agent ID '<id>'` (DEBUG1
   `Invalid agent ID '<id>'`). The id is printed with 3 digits (`%03d`) in logs.
3. DEBUG2 `Agent <id3> query: <rest>`.
4. Id ≠ 0: open the global database (fail: `err Couldn't open DB global`, DEBUG2 `Couldn't open
   DB global: queue/db/global.db`); disabled: `err DB global disabled.`; agent not in it:
   `err Agent not found` (DEBUG2 `No agent with id <id3> found.`).
5. Open the agent's database (fail: ERROR `Couldn't open DB for agent '<id3>'`, answer
   `err Couldn't open DB for agent <id>`); the open time is added to the statistics.
6. The command is the next word; its arguments the rest. Commands without arguments where they
   need some: `err Invalid DB query syntax, near '<command>'` (DEBUG1 `DB(<id3>) Invalid DB query
   syntax.`, DEBUG2 `DB(<id3>) query error near: <command>`), except: FIM commands
   `err Invalid Syscheck query syntax, near ...` (DEBUG1 `DB(<id3>) Invalid <FIM|FIM file|FIM
   registry|FIM registry key|FIM registry value> query syntax.`), `rootcheck`
   `err Invalid Rootcheck query syntax, near ...`, `syscollector_*` `err Invalid Syscollector query
   syntax, near ...`.

| Command | Handler (section) | Counter |
|---|---|---|
| `syscheck`, `fim_file`, `fim_registry`, `fim_registry_key`, `fim_registry_value` | FIM (§ FIM) with component file / registry / key / value | per command, with time |
| `sca` | SCA | yes |
| `netinfo`, `netproto`, `netaddr`, `osinfo`, `hardware`, `port`, `package`, `hotfix`, `process` | legacy inventory (deprecated counters) | yes |
| `dbsync` | delta sync | yes |
| `ciscat` | CIS-CAT results | yes |
| `rootcheck` | rootcheck | yes |
| `sql <statement>` | run SQL on the agent DB: `ok <json rows>`; fail `err Cannot execute SQL query` (DEBUG1 `DB(<id3>) Cannot execute SQL query.`, DEBUG2 `DB(<id3>) SQL query: <sql>`) | yes |
| `remove` | close and delete the agent DB files: `ok`; `err Cannot close database` / `err Cannot remove database` | yes |
| `begin` / `commit` | transaction: `ok`; `err Cannot begin transaction` / `err Cannot end transaction` | yes |
| `close` | close the agent DB: `ok` / `err Cannot close database` | yes |
| `syscoll*` (any word starting with `syscoll`) | inventory sync (§ Syscollector) | per kind |
| `vacuum` | § 1.6 | yes |
| `get_fragmentation` | § 1.7 | yes |
| `sleep <ms>` | § 1.8 | yes |
| anything else | `err Invalid DB query syntax, near '<command>'` (DEBUG1 `DB(<id3>) Invalid DB query syntax.`, DEBUG2 `DB(<id3>) query error near: <command>`) | |

After any `err` (invalid result) of an `agent` or `global` command: if the database file
`queue/db/<id>.db` cannot be opened any more, WARNING `DB(queue/db/<id>.db) not found. This
behavior is unexpected, the database will be recreated.` and the cached handle is closed (the next
request recreates the file).

### 1.6 `vacuum` (agent and global; `<who>` = `DB(<id3>)` or the global label)
1. Commit any open transaction; fail: `err Cannot end transaction` (DEBUG1 `<who> Cannot end
   transaction.`), no vacuum.
2. Drop all prepared statements, run VACUUM; fail: `err Cannot vacuum database` (DEBUG1 `<who>
   Cannot vacuum database.`).
3. Read the fragmentation; fail: `err Vacuum performed, but couldn't get fragmentation information
   after vacuum` (DEBUG1 `<who> Couldn't get fragmentation after vacuum for the database.`).
4. Store last-vacuum time and value in the metadata table; fail: `err Vacuum performed, but last
   vacuum information couldn't be updated in the metadata table` (DEBUG1 `<who> Couldn't update last
   vacuum info for the database.`).
5. `ok {"fragmentation_after_vacuum":<n>}`.

### 1.7 `get_fragmentation`
`ok {"fragmentation":<n>,"free_pages_percentage":<p>}`; either value unreadable: `err Cannot get
database fragmentation` (DEBUG1 `<who> Cannot get database fragmentation.`).

### 1.8 `sleep <ms>`
Number parsed like C `strtoul` (leading whitespace, optional sign, `-n` wraps modulo 2^64,
overflow = max); missing or max: `err Invalid DB query syntax, near '<command>'` (DEBUG1 `<who>
Invalid DB query syntax.`, DEBUG2 `<who> query error near: <command>`); else sleeps that many ms
and answers `ok ` (with a trailing space).

### 1.2 `wazuhdb remove <ids>` (actor name: L-name, see § 20)
No space after the command: `err Invalid DB query syntax, near '<cmd>'`. `remove`: removes several
agents' databases (§ global remove-multiple), answer `ok <json>` (a null result prints `ok (null)`);
any other command: `err No agents id provided` (DEBUG1 `Invalid DB query syntax.`).

### 1.3 `mitre sql <statement>`
DEBUG2 `Mitre query: <rest>`. Open `queue/db/mitre.db` (fail: `err Couldn't open DB mitre`).
No space: `err Invalid DB query syntax, near ...`. `sql`: `ok <json rows>`; fail
`err Cannot execute Mitre database query; <sqlite error>` (DEBUG1 `Mitre DB Cannot execute SQL
query; err database queue/db/mitre.db: <error>`, DEBUG2 `Mitre DB SQL query: <sql>`). Other
commands: `err Invalid DB query syntax, near ...`.

### 1.4 `global <command> [args]`
DEBUG2 `Global query: <rest>`. Open the global DB (fail `err Couldn't open DB global`, disabled
`err DB global disabled.`); open time counted. Commands: § 3.

### 1.5 `task <command> <args>`
DEBUG2 `Task query: <rest>`. Open `queue/tasks/tasks.db` (fail `err Couldn't open DB task`). No
space: `err Invalid DB query syntax, near ...`. Commands: § 5.

## 3. `global` commands

Common rules:
- A command that needs arguments and has none: `err Invalid DB query syntax, near '<cmd>'` (DEBUG1
  `Global DB Invalid DB query syntax for <cmd>.`, DEBUG2 `Global DB query error near: <cmd>`).
  `sql` without arguments logs DEBUG1 `Global DB Invalid DB query syntax.` instead. Unknown command:
  DEBUG1 `Invalid DB query syntax.`, DEBUG2 `Global DB query error near: <cmd>`, same answer.
- JSON arguments are parsed strictly (nothing may follow the JSON). Bad JSON: DEBUG1 `<command
  message>`, DEBUG2 `Global DB JSON error near: <text from the error position>`, answer
  `err Invalid JSON syntax, near '<input, 32 bytes>'`. JSON with wrong or missing fields:
  `err Invalid JSON data, near '<input, 32 bytes>'`.
- An SQL failure: `err Cannot execute Global database query; <sqlite error>` (DEBUG1 `Global DB
  Cannot execute SQL query; err database queue/db/global.db: <error>`).
- Every command has a usage counter and a time counter (`getstats`).
- "Validated sync status": the requested `sync_status` after the database's rule (§ 3.x, from
  global.rs).

| Command | Arguments | Required | Effect / answer | Error texts (DEBUG1 = same text unless shown) |
|---|---|---|---|---|
| `sql <statement>` | SQL | | `ok <json rows>` | DEBUG2 `Global DB SQL query: <sql>` |
| `insert-agent <json>` | `id` number, `name` text, `date_add` number; optional `ip`, `register_ip`, `internal_key`, `group` | id, name, date_add | inserts the agent; clears the group-hash cache; `ok` | JSON syntax DEBUG1 `Global DB Invalid JSON syntax when inserting agent.`; data DEBUG1 `Global DB Invalid JSON data when inserting agent. Not compliant with constraints defined in the database.` |
| `update-agent-name <json>` | `id` number, `name` text | both | `ok` | `... when updating agent name.` (syntax / data) |
| `update-agent-data <json>` | `id` number; optional `os_name`, `os_version`, `os_major`, `os_minor`, `os_codename`, `os_platform`, `os_build`, `os_uname`, `os_arch`, `version`, `config_sum`, `merged_sum`, `manager_host`, `node_name`, `agent_ip`, `connection_status`, `group_config_status`, `sync_status` (default `synced`), `labels` | id | updates those columns with the validated sync status; then replaces the agent's labels: `labels` is `key:value` lines; missing labels removes them all; answer as `set-agent-labels` (`ok`) | `... when updating agent version.` (syntax / data) |
| `get-labels <id>` | id (atoi) | | `ok <json>` | `err Error getting agent labels from global.db.` |
| (labels helper) `<id> k1:v1\nk2:v2` | | | deletes the agent's labels, inserts each `key:value` line (lines without `:` skipped); `ok` | no id: `err Invalid DB query syntax, near ...` (DEBUG2 `DB query error near: ...`) |
| `update-keepalive <json>` | `id` number, `connection_status` text, `sync_status` text | all | updates keep-alive time, connection status, validated sync status; `ok` | `... when updating agent keepalive.` |
| `update-connection-status <json>` | `id`, `connection_status`, `sync_status`, `status_code` number | all | `ok` | `... when updating agent connection status.` |
| `update-status-code <json>` | `id`, `status_code`, `sync_status`; optional `version` text | id, status_code, sync_status | `ok` | `... when updating agent status code.` |
| `delete-agent <id>` | id (atoi) | | deletes the agent row; publishes on the agent router topic `{"agent_info":{"agent_id":"<id3>"},"action":"deleteAgent"}` (when the router is on); clears the group-hash cache; `ok` | `err Error deleting agent from agent table in global.db.` |
| `select-agent-name <id>` | | | `ok <json>` | `err Error getting agent name from global.db.` |
| `select-agent-group <id>` | | | `ok <json>` | `err Error getting agent group from global.db.` |
| `find-agent <json>` | `name` text, `ip` text | both | `ok <json>`; SQL failure as above | `... when finding agent id.` |
| `find-group <name>` | | | `ok <json>` | `err Error getting group id from global.db.` |
| `insert-agent-group <name>` | | | `ok` | `err Error inserting group in global.db.` |
| `select-group-belong <id>` | | | `ok <json>` | `err Error getting agent groups information from global.db.` |
| `get-group-agents <group> last_id <n>` | space separated | all | `<ok\|due> <json>` (paged, status from the query) | `err Invalid arguments, group name not found.` / `err Invalid arguments, 'last_id' not found.` / `err Invalid arguments, last agent id not found.` / `err Error getting group agents from global.db.` |
| `delete-group <name>` | | | `ok` | `err Error deleting group in global.db.` |
| `select-groups` | none | | `ok <json>` | `err Error getting groups from global.db.` |
| `set-agent-groups <json>` | `mode` text, `data` array; optional `sync_status` (default `synced`) | mode, data | modes `override`, `append`, `empty_only`, `remove`; result `ok`; other result: `<status> An error occurred during the set of the groups` | syntax DEBUG1 `Global DB Invalid JSON syntax when parsing set_agent_groups`; missing: `err Invalid JSON data, missing required fields` (DEBUG1 `Missing mandatory fields in set_agent_groups command.`); bad mode: `err Invalid mode '<m>' in set_agent_groups command` (DEBUG1 same with `.`) |
| `sync-agent-groups-get <json>` | optional `condition` (`sync_status` / `all` / other = invalid condition / missing = none), `last_id` number ≥ 0 (default 0), `set_synced` bool, `get_global_hash` bool, `agent_registration_delta` number ≥ 0 (default 0) | | `<ok\|due> <json>`; a response longer than the maximum response size: `err Invalid response from wdb_global_sync_agent_groups_get`; no response: `err Could not obtain a response from wdb_global_sync_agent_groups_get` | syntax DEBUG1 `Global DB Invalid JSON syntax when parsing sync-agent-groups-get`; wrong types: `err Invalid JSON data, invalid alternative fields data` (DEBUG1 `Invalid alternative fields data in sync-agent-groups-get command.`) |
| `sync-agent-info-get [last_id <n>]` | optional | | uses a shared "last id" cursor (set by `last_id <n>`), answer `<ok\|due> <json>`; the cursor goes back to 0 unless the answer is `due` | none |
| `sync-agent-info-set <json array>` | agents | | per agent: stores its synced info; when it has a `labels` array: needs a numeric `id` (else `err Cannot update labels due to invalid id.`, DEBUG1 `Global DB Cannot execute SQL query; incorrect agent id in labels array.`), deletes its labels and inserts each `{key,value,id}` with text key/value and numeric id (others skipped); `ok` | syntax DEBUG1 `Global DB Invalid JSON syntax updating unsynced agents.` |
| `get-groups-integrity <sha1 hex>` | ≥ 40 characters (first 40 used) | | `ok <json>` | shorter: `err Hash hex-digest does not have the expected length. Expected (40) got (<len>)` (DEBUG1 same text); `err Error getting groups integrity information from global.db.` |
| `recalculate-agent-group-hashes` | none | | `ok` | WARNING `Error recalculating group hash of agents in global.db.`, answer `err Error recalculating group hash of agents in global.db` |
| `get-agent-info <id>` | id (atoi) | | `ok <json array>` | `err Error getting agent information from global.db.` |
| `get-agents-by-connection-status <last_id> <status> [<node> <limit>]` | space separated | last_id, status; limit required when node given | `<ok\|due> <json>` | `err Invalid arguments 'last_id' not found` / `err Invalid arguments 'connection_status' not found` / `err Invalid arguments 'limit' not found` (DEBUG1 with `.`); `err Error getting agents by connection status from global.db.` |
| `get-all-agents last_id <n>` | | | `<ok\|due> <json>` | first word not `last_id`/`context`: `err Invalid arguments 'last_id' or 'context' not found`; no number: `err Invalid arguments 'last_id' not found`; `err Error getting agents from global.db.` |
| `get-all-agents context` | | | sends the agents to the caller first (§ 3.x), then answers `ok []`; failure: `err Error getting agents from global.db.` with the failure code | |
| `get-distinct-groups [<last hash>]` | optional | | `<ok\|due> <json>` | `err Error getting agent groups from global.db.` |
| `reset-agents-connection <sync_status>` | | | `ok`; SQL error as above | |
| `disconnect-agents <last_id> <keepalive> <sync_status>` | space separated | all | `<ok\|due> <json>` of agents set to disconnected | `err Invalid arguments last id not found` / `err Invalid arguments keepalive not found` / `err Invalid arguments sync_status not found` (DEBUG1 with `.`); `err Error getting agents to be disconnected from global.db.` |
| `backup <action> ...` | | | § 3.y | |
| `vacuum`, `get_fragmentation`, `sleep <ms>` | | | § 1.6–1.8 with `<who>` = `Global DB` | |

### 3.y `global backup <action>`
| Action | Effect / answer |
|---|---|
| (none) | `err Missing backup action` |
| `create` | snapshot of the global DB now (§ backups); its answer; on failure ERROR `Creating Global DB snapshot on demand failed: <answer>` |
| `get` | `ok <json list of snapshots>`; folder unreadable: `err Cannot execute backup get command, unable to open 'backup/db' folder` (the backup folder path) |
| `restore [<json>]` | optional JSON `{"snapshot":"<name>","save_pre_restore_state":<bool>}` (non-bool = false); bad non-empty JSON: `err Invalid JSON syntax, near ...` (DEBUG1 `Invalid backup JSON syntax when restoring snapshot.`, DEBUG2 `JSON error near: ...`); restores (§ backups) and returns its answer |
| other | `err Invalid backup action: <action>` |

## 5. `task` commands (upgrade tasks, `queue/tasks/tasks.db`)

Arguments are JSON, parsed leniently (trailing text allowed); unparsable: `err Invalid command
parameters, near '<args, 32 bytes>'`. Every answer is `ok <json>` with `"error":<code>` (0 = success)
unless a required field is missing. Usage and time counters per command.

| Command | Required fields (number unless said) | Missing-field answer | Success answer |
|---|---|---|---|
| `upgrade`, `upgrade_custom` | `agent`, `node` text, `module` text | `err Error insert task: 'parsing <agent\|node\|module> error'` | inserts a task with the command name; `ok {"error":0,"task_id":<id>}`; failure `ok {"error":<code>}` |
| `upgrade_get_status` | `agent`, `node` | `err Error get upgrade task status: 'parsing <field> error'` | `ok {"error":<code>[,"status":"<s>"]}` (status only on success and when set) |
| `upgrade_update_status` | `agent`, `node`, `status` text; optional `error_msg` | `err Error upgrade update status task: 'parsing <field> error'` | `ok {"error":<code>}` |
| `upgrade_result` | `agent` | `err Error upgrade result task: 'parsing agent error'` | found: `ok {"error":0,"task_id":<id>[,"node","module","command","status","error_msg" when set],"create_time":<t>,"update_time":<t>}`; else `ok {"error":<code>}` |
| `upgrade_cancel_tasks` | `node` text | `err Error upgrade cancel task: 'parsing node error'` | `ok {"error":<code>}` |
| `set_timeout` | `now`, `interval` | `err Error set timeout task: 'parsing <now\|interval> error'` | `ok {"error":<code>[,"timestamp":<next timeout>]}` (timestamp on success; default now+interval) |
| `delete_old` | `timestamp` | `err Error delete old task: 'parsing timestamp error'` | `ok {"error":<code>}` |
| `sql <statement>` | | | `ok <json rows>`; fail `err Cannot execute Tasks database query; <error>` (DEBUG1 `Tasks DB Cannot execute SQL query; err database queue/tasks/tasks.db: <error>`, DEBUG2 `Tasks DB SQL query: <sql>`) |
| other | | | `err Invalid DB query syntax, near '<cmd>'` (DEBUG1 `Invalid DB query syntax.`, DEBUG2 `Task DB query error near: <cmd>`) |

Note: "number" fields take the integer part of the JSON number.

## 2. `agent <id>` commands

### 2.1 FIM: `syscheck | fim_file | fim_registry | fim_registry_key | fim_registry_value <sub> [args]`
The component is file (`syscheck` = generic FIM, `fim_file`), registry, registry key or registry
value. No space after `<sub>`: `err Invalid FIM query syntax, near '<sub>'` (DEBUG2 `DB(<id>) Invalid
FIM query syntax: <sub>`). `<id>` in these logs is the database id as stored (e.g. `001`).

| Sub-command | Effect / answer | Failure (answer; DEBUG1) |
|---|---|---|
| `scan_info_get <field>` | `ok <value>` of the `fim` scan-info field | `err Cannot get fim scan info.`; `DB(<id>) Cannot get FIM scan info.` |
| `updatedate <args>` | updates the FIM date field (§ fim); `ok` | `err Cannot update fim date field.`; `DB(<id>) Cannot update fim date field.` |
| `cleandb` | removes old FIM entries; `ok` | `err Cannot clean fim database.`; `DB(<id>) Cannot clean fim database.` |
| `scan_info_update <field> <ts>` | sets that field of `fim` scan info (ts parsed with strtol); `ok` | no space: `err Invalid Syscheck query syntax, near '<field>'` (DEBUG1 `DB(<id>) Invalid scan_info fim query syntax.`); fail `err Cannot save fim control message`; `DB(<id>) Cannot save fim control message.` |
| `control <value>` | FIM check-control message; `ok` | `err Cannot save fim control message`; `DB(<id>) Cannot save fim check_control message.` |
| `load <file>` | `ok <stored checksum line>` (max 65,520 bytes) | `err Cannot load Syscheck`; `DB(<id>) Cannot load FIM.` |
| `delete <path>` | deletes the entry; `ok` | `err Cannot delete Syscheck`; `DB(<id>) Cannot delete FIM entry.` |
| `save <file\|registry> <checksum> <path>` | `\ ` in the checksum part before the first `!` becomes a space; saves (§ fim); `ok` | missing parts or other type: `err Invalid Syscheck query syntax, near '...'` (DEBUG1 `DB(<id>) Invalid FIM query syntax.`, DEBUG2 `DB(<id>) FIM query: <rest>`; when the path is missing the DEBUG2 is `FIM query: <rest>` without the prefix); fail `err Cannot save Syscheck`; `DB(<id>) Cannot save FIM.` |
| `save2 <json>` | saves a JSON FIM entry; `ok` | `err Cannot save Syscheck`; `DB(<id>) Cannot save FIM.` |
| `integrity_check_<action> <payload>` | range checksum (§ integrity): `ok no_data`, `ok checksum_fail` or `ok ` | `err Cannot perform range checksum`; `DB(<id>) Cannot query FIM range checksum.` |
| `integrity_clear <payload>` | clears the component (§ integrity); `ok ` | same as above |
| other | | `err Invalid Syscheck query syntax, near '<sub>'` (DEBUG1 `DB(<id>) Invalid FIM query syntax.`, DEBUG2 `DB query error near: <sub>`) |

### 2.2 `syscollector_<kind> <sub> <payload>` (inventory sync)
Kinds: `processes`, `packages`, `hotfixes`, `ports`, `network_protocol`, `network_address`,
`network_iface`, `hwinfo`, `osinfo`, `users`, `groups`, `browser_extensions`, `services` (each has
its usage counter). Other kinds: `err Invalid Syscollector query syntax, near '<kind>'` (DEBUG2
`DB(<id>) Invalid Syscollector query : <kind>`). DEBUG2 `DB(<id>) <query> Syscollector query. `. No
space after `<sub>`: `err Invalid Syscollector query syntax, near '<sub>'` (DEBUG2 `DB(<id>)
Invalid Syscollector query syntax: <sub>`). The command's result code is the kind (used for the
per-kind timing counters).

| Sub-command | Effect / answer | Failure |
|---|---|---|
| `save2 <json>` | stores a row (§ syscollector); `ok` | `err Cannot save Syscollector` (DEBUG1 `DB(<id>) Cannot save Syscollector.`) |
| `integrity_check_<action> <payload>` | `ok no_data` / `ok checksum_fail` / `ok ` | `err Cannot perform range checksum` (DEBUG1 `DB(<id>) Cannot query Syscollector range checksum.`) |

| `integrity_clear*` (any sub starting so) `<payload>` | clears the kind (§ integrity); `ok ` | as above |
| other | | `err Invalid Syscollector query syntax, near '<sub>'` (DEBUG1 `DB(<id>) Invalid Syscollector query syntax.`, DEBUG2 `DB query error near: <sub>`) |

### 2.3 `sca <sub> <args>` (fields separated by `|`)
`<S>` = `Invalid Security Configuration Assessment query syntax`, `<C>` = `Invalid configuration
assessment query syntax`. No space after `<sub>`: DEBUG1 `<S>.`, DEBUG2 `Security Configuration
Assessment query: <args>`, answer `err <S>, near '...'`. A missing `|`: the same with `<S>` (or with
`<C>` and DEBUG2 `configuration assessment query: ...`, as marked). "Found" answers: `ok not found`,
`ok found <value>`, or the error (DEBUG1 `Cannot query Security Configuration Assessment.`).
Numbers are parsed with strtol; `NULL` scan id means "none" (-1).

| Sub | Fields | Answer / error |
|---|---|---|
| `query <check id>` | | found / `err Cannot query Security Configuration Assessment` |
| `update <check id>\|<result>\|<reason>\|<scan id or NULL>` | `<S>` | `ok`; fail `err Cannot update Security Configuration Assessment information.` (DEBUG1 same text) |
| `insert <json>` | | § 2.3.1 |
| `delete_policy <policy>` | | `ok`; `err Cannot delete Security Configuration Assessment information.` |
| `delete_check_distinct <policy>\|<scan id or NULL>` | `<S>` | deletes checks of other scans, then orphan compliance and rule rows; `ok`; `err Cannot delete Security Configuration Assessment checks.` |
| `delete_check <policy>` | | deletes the policy's checks, then orphan compliance and rule rows; `ok`; `err Cannot delete Security Configuration Assessment check information.` (DEBUG1 `Cannot delete Security Configuration Assessment information.`) |
| `query_results <policy>` | | found / `err Cannot query Security Configuration Assessment global` |
| `query_scan <policy>` | | found / `err Cannot query Security Configuration Assessment scan` |
| `query_policies` | | found / `err Cannot query Security Configuration Assessment scan` |
| `query_policy <policy>` | | found / `err Cannot query policy scan` |
| `query_policy_sha256 <policy>` | | found / `err Cannot query policy scan` |
| `insert_policy f1\|f2\|f3\|f4\|f5\|f6` | 6 fields, `<S>` | `ok`; `err Cannot save Security Configuration Assessment global information.` (DEBUG1 `Cannot save Security Configuration Assessment information.`) |
| `insert_rules <check id>\|<a>\|<b>` / `insert_compliance ...` | first `\|` `<S>`, second `<C>` | `ok`; `err Cannot save configuration assessment global information.` (DEBUG1 `Cannot save configuration assessment information.`) |
| `insert_scan_info <n1>\|<n2>\|<n3>\|<policy>\|<p>\|<f>\|<i>\|<t>\|<score>\|<hash>` | `<C>`; empty number fields read as 0 | `ok`; `err Cannot save configuration assessment information.` |
| `update_scan_info <module>\|<x><end scan>` | `<C>`; **quirk**: one character after `\|` is skipped before the number | `ok`; same error |
| `update_scan_info_start <policy>\|<start>\|<end>\|<scan id>\|5 numbers\|<hash>` | `<C>`; **quirk**: start and end are both read from the `<start>` field | `ok`; same error |
| other | | **quirk**: `err Invalid Rootcheck query syntax, near '<sub>'` (DEBUG1 `Invalid configuration assessment query syntax.`, DEBUG2 `DB query error near: <sub>`) |

#### 2.3.1 `sca insert <json>`
JSON parsed leniently. Required: `id` number ≥ 0 (scan id), `policy_id` text, `check` object with
`id` number and `title` text. Optional texts in `check`: `description`, `rationale`,
`remediation`, `references`, `file`, `condition`, `directory`, `process`, `registry`, `command`,
`result` (default `not applicable`), `reason`; present but not a text is an error. Saves the check
(§ sca); `ok`; fail `err Cannot save Security Configuration Assessment information.`.
Errors (DEBUG1 text; answer): JSON missing/invalid or no `id`: `Invalid Security Configuration
Assessment query syntax. JSON object not found or invalid`, `id` not a number `Malformed JSON: field
'id' must be a number`, negative `... field 'id' cannot be negative`, `policy_id` missing/not text
`... field 'policy_id' not found` / `must be a string`: answer `err Invalid Security Configuration
Assessment query syntax, near '...'`. **Quirk:** errors in `check` (`field 'check' not found`,
`field 'id' not found`, `'id' must be a number`, `'title' not found`, `'title' must be a string`,
`field '<name>' must be a string` with `reference` for `references`) return an **empty answer**.

### 2.4 Legacy inventory commands (deprecated, `|`-separated, `NULL` = no value)
Every legacy row gets the fixed legacy checksum value (L-name) and no item id unless given. A
missing `|`: `err Invalid <X> query syntax, near '<rest>'` with DEBUG1 `Invalid <X> query syntax.`
and DEBUG2 `<X> query: <previous field>` (exact per-field wording: text catalog, § 19). Unknown
action: DEBUG1 per command, DEBUG2 `DB query error near: <action>`, `err Invalid <cmd> query syntax,
near ...`. Numbers: strtol; empty number fields read as 0 unless noted.

| Command | Actions and fields (in order) | Answers |
|---|---|---|
| `netinfo` (`<X>` = `Network`) | `save scan_id\|scan_time\|name\|adapter\|type\|state\|mtu\|mac\|tx_packets\|rx_packets\|tx_bytes\|rx_bytes\|tx_errors\|rx_errors\|tx_dropped\|rx_dropped`; `del <scan_id>` | `ok`; `err Cannot save Network information.` / `err Cannot delete old network information.`; unknown action `err Invalid netinfo query syntax` (DEBUG1 `Invalid netinfo query syntax.`) |
| `netproto` (`netproto`) | `save scan_id\|iface\|type\|gateway\|dhcp\|metric` (a missing `\|` after `type` uses the `Network` wording) | `ok`; `err Cannot save netproto information.` |
| `netaddr` (`netaddr`) | `save scan_id\|iface\|proto\|address\|netmask\|broadcast` (after `proto`: `Network` wording) | `ok`; `err Cannot save netaddr information.` |
| `osinfo` | `get` → `ok <json rows of sys_osinfo>` (fail `err Cannot get sys_osinfo database table information; SQL err: <error>`); `set scan_id\|scan_time\|hostname\|architecture\|os_name\|os_version\|os_codename\|os_major\|os_minor\|os_build\|os_platform\|sysname\|release\|version\|os_release\|os_patch\|os_display_version` | no action `err Missing osinfo action`; other `err Invalid osinfo action: <a>`; set: missing `\|` in the first 15 fields `err Invalid OS info query syntax` (no "near"; DEBUG1 `Invalid OS info query syntax.`), at `os_patch` the "near" form; `ok` / `err Cannot save OS information.` |
| `hardware` (`HW info`) | `save scan_id\|scan_time\|serial\|cpu_name\|cpu_cores\|cpu_mhz(decimal)\|ram_total\|ram_free\|ram_usage` | `ok`; `err Cannot save HW information.` (DEBUG1 `wdb_parse_hardware(): Cannot save HW information.`, see L-names) |
| `port` (`Port`) | `save scan_id\|scan_time\|protocol\|local_ip\|local_port\|remote_ip\|remote_port\|tx_queue\|rx_queue\|inode(64-bit)\|state\|pid\|process` (`NULL…` process = none; this save replaces existing rows) ; `del <scan_id>` | `ok`; `err Cannot save Port information.` / `err Cannot delete old Port information.` |
| `package` | `save` with 16 fields `scan_id\|scan_time\|format\|name\|priority\|section\|size\|vendor\|install_time\|version\|architecture\|multiarch\|source\|description\|location\|item_id` (a field exactly `NULL` = none; size starting with `NULL` = -1); `get` (§ 2.5) ... | no action: `err Invalid package info query syntax. Missing action` (DEBUG1 same + `.`?, DEBUG2 `DB query error. Missing action`); missing `\|`: `err Invalid package info query syntax, near ...` (DEBUG2 `Package info query: <field>`) |

(Package save: `size` is the 7th field, read as a number; all other fields are texts.)

| `package` (cont.) | `save` result: `ok` / `err Cannot save package information.`; after a good save the packages "sync attempt" time is set (§ integrity, legacy). `del <scan_id>`: first marks scanned packages (DEBUG1 `Cannot update scanned packages.` on failure, continues), then deletes rows of other scans: `ok` and the "sync completion" time is set / `err Cannot delete old package information.`. `get`: § 2.5. Other: `err Invalid package info query syntax, near ...` | |
| `hotfix` | `save scan_id\|scan_time\|hotfix` (3 `\|`-tokens, empty tokens skipped like strtok; `NULL` = none); `del <scan_id>` (+ completion time); `get` (§ 2.5) | no action `err Invalid hotfix info query syntax. Missing action` (DEBUG2 `DB query error. Missing action`); missing token `err Invalid hotfix info query syntax, near '<last token>'` (DEBUG2 `Hotfix info query: ...`); `ok` + attempt time / `err Cannot save hotfix information.`; `err Cannot delete old hotfix information.` |
| `process` (`Process`) | `save scan_id\|scan_time\|pid\|name\|state\|ppid\|utime\|stime\|cmd\|argvs\|euser\|ruser\|suser\|egroup\|rgroup\|sgroup\|fgroup\|priority\|nice(NULL→0)\|size\|vm_size\|resident\|share\|start_time(NULL→-1, strtoul)\|pgrp\|session\|nlwp\|tgid\|tty\|processor`; `del <scan_id>` | `ok`; `err Cannot save Process information.` / `err Cannot delete old Process information.` |
| `ciscat` (`CISCAT`) | `save scan_id\|scan_time\|benchmark\|profile\|pass\|fail\|error\|notchecked\|unknown\|score` | `ok`; `err Cannot save CISCAT information.` |

### 2.6 `rootcheck <sub>`
Bad syntax: `err Invalid rootcheck query syntax, near '<sub>'` (DEBUG2 `DB(<id>) Invalid rootcheck
query syntax: <sub>`).
- `delete`: deletes all rootcheck rows: `ok 0`; fail `err Error deleting rootcheck PM tuple`.
- `save <timestamp> <log line>`: timestamp (strtol) negative or max: DEBUG2 `DB(<id>) Invalid
  rootcheck date timestamp: <ts>`, syntax error answer. Updates the row with the same log (last
  date): updated → `ok 1`; not found → inserts (first = last = ts) → `ok 2`; update failure ERROR
  `DB(<id>) Error updating rootcheck PM tuple on SQLite database`, insert failure ERROR `DB(<id>)
  Error inserting rootcheck PM tuple on SQLite database for agent`; both answer `err Error updating
  rootcheck PM tuple`.

### 2.7 `dbsync <table key> <operation> <json>`
Missing parts or empty JSON: `err Invalid dbsync query syntax, near '<table key>'` (DEBUG2 `DBSYNC
query: <table key>`). The table key is matched (first 255 bytes) against the delta table map (§
tables). JSON parsed strictly; bad JSON: DEBUG1 `(5217): Could not parse syscollector delta
information as JSON.`, DEBUG2 `JSON error near: ...`. `INSERTED`/`MODIFIED`: upsert; `DELETED`:
delete (always "success"); other: DEBUG1 `Invalid operation type: <op>`. Answer `ok ` on success,
`err` (no text) otherwise, including an unknown table key.

### 2.5 `package get` / `hotfix get` (inventory read used by the scanner)
Answer `ok <json>` with the rows, or `err <json>` on failure; when sending to the caller failed
(socket error) the connection is closed and **no** answer is sent. Rows larger than one answer are
streamed as `due <json>` parts before the final answer (§ streaming).

<!-- parser files done -->

## 6. Storage: files, schema, statements

| Database | File | Schema | Upgrades |
|---|---|---|---|
| per agent | `queue/db/<id3>.db` (agent 0 = the manager) | 24 tables (inventory `sys_*`, FIM, SCA, rootcheck, CIS-CAT, scan info, sync info, metadata) | 16 steps (v1..v16) from older files |
| global | `queue/db/global.db` | 6 tables (agent, labels, group, belongs, metadata, ...) | 7 steps (v1..v7) |
| tasks | `queue/tasks/tasks.db` | 2 tables | none |
| MITRE | `queue/db/mitre.db` | built by `provigil-mitredb` | none |

- The **on-disk layout must stay exactly the same** (tables, columns, types, defaults, indexes,
  the metadata version row), so existing files keep working and siem-api / the scanner read them as
  today. The new code states the schema in its own SQL text; the comparison test dumps every table
  of both and requires identical rows.
- 264 prepared statements in the old code; each is one effect on one table. The new code writes its
  own queries; the comparison test is the proof of the same effect (rows, order of answers).
- 13 delta tables for `dbsync` (key → table, single-row or not, columns with type and default):
  `network_iface`→`sys_netiface` (17 fields), `network_protocol`→`sys_netproto` (7),
  `network_address`→`sys_netaddr` (7), and the rest from `tables.rs` (to list with their columns
  when the dbsync part is written).

**Decision for the owner (D-1):** the 23 upgrade steps exist to convert database files written by
older versions of the original product. Every ProVigil installation is already at the latest
version (v16 / global v7). Options: (a) keep all 23 steps, exactly as today; (b) support only the
current version and refuse older files with a clear error.
**Decided 13 Nov 2026: (b).** ProVigil never receives files of the original product; 23 conversion
steps would be code to own for nothing. An older file is refused with a clear error (exact text in
§ 8 when written); a missing file is created at the current version, as today.

**Decision D-3 (13 Nov 2026): reuse `siem-cjson` and `siem-sqlite`.** `siem-cjson` is a Rust port
of cJSON (MIT licence, not GPL) and gives byte-identical JSON output, parsing and error positions;
`siem-sqlite` is SQLite 3.50.4 (public domain, with the DBSTAT table the fragmentation numbers need)
behind a thin call wrapper. Neither is code of the original product. Licence note: cJSON's MIT
notice must ship with the product (licence files are still pending, see the licence reminder).

**Decision D-4 (13 Nov 2026): backups work on Windows.** The backup file name holds the time
`hh:mm:ss`; Windows does not allow `:` in file names, so on the Windows server every global backup
(daily and on demand) failed with `unable to open database` in the old code. On Windows the time is
written `hh-mm-ss`; Linux keeps the old name. Tested: create, list, restore round trip.

## 7. Global database rules

### 7.1 Sync status (agent column `sync_status`)
Values: `synced`, `syncreq`, `syncreq_status`, `syncreq_keepalive`. A requested value is accepted
only if allowed by the current one; otherwise the current value stays:

| Current | Accepted requests |
|---|---|
| `synced`, `syncreq_keepalive` | any |
| `syncreq_status` | any except `syncreq_keepalive` |
| `syncreq` | any except `syncreq_keepalive` and `syncreq_status` |
| anything else | none (current stays) |

When the current value cannot be read: WARNING `Failed to get old sync_status for agent '<id>'` and
the request is used as is.

### 7.2 `sync-agent-info-get` (cluster sync of changed agents)
Inside a transaction (begun if none; failure `Cannot begin transaction` with status error).
Three passes, each starting from the given last id: agents with `syncreq` (full info + their labels
when they have any), then `syncreq_status`, then `syncreq_keepalive`. Each agent row found (one
at a time, ids increasing) is appended to a JSON array while the answer stays below the maximum
response size (else status `due` and stop); appended agents get `synced` (failure: ERROR `Cannot set
sync_status for agent <id>`, answer text the same, status error). A row without a numeric id
advances the id by one. Errors `Cannot cache statement` (DEBUG1), `Cannot bind sql statement` (ERROR
`DB(<id>) sqlite3_bind_int(): <error>`). Answer `[...]` (no `]` on error; the error text replaces
the body).

### 7.3 Delete group
Lists the group's agents, deletes the group (failure: DEBUG1 `SQLite: <error>`). Then for each of
those agents: if it has no group left it gets the default group, and its group hash is recalculated
with sync status `synced` on a single node or cluster worker, `syncreq` on a cluster master; a
failure: ERROR `Couldn't recalculate hash group for agent: '<id3>'` and stop (command fails).

### 7.4 Group list / group agents
`select-groups`: all groups, limited to the maximum response size (exceeded: WARNING `The groups
exceed the socket maximum response size.`; other failure DEBUG1 `Failed to get groups: <error>.`).
`get-group-agents`: ids of the group's agents after `last_id`, single column, sized: `ok` when all
fit, `due` when more remain.

### 7.5 Group hash
`groups_hash` = the first 8 hex characters (group hash size) of SHA-256 of the agent's group text
(comma-separated). When the group text cannot be read: DEBUG2 `Unable to get group column for agent
'<id>'. The groups_hash column won't be updated` and nothing changes. A one-time adjustment
recalculates it for every agent and commits (failure ERROR `DB(<id>) The commit statement could not
be executed.`; step errors DEBUG1 `SQLite: <error>`).

### 7.6 Insert agent
When `group` is given, every name in it (split on the multigroup separator `,`, empty names
skipped) must be a valid group name (§ 7.x); else ERROR `Invalid group name '<name>' in multigroup
'<groups>' for agent <id>` and the insert fails (SQL error answer).
`update-connection-status`: the disconnection time is "now" when the status is `disconnected`,
else 0.

### 7.7 Group names and limits
Valid group name: 1–255 characters from `A-Z a-z 0-9 _ . -` and **backslash** (quirk of the old
pattern: the backslashes in its bracket expression are literal), not `.` or `..`. Warnings: `Invalid
group name. The group '<g>' exceeds the maximum length of 255 characters permitted`, `Invalid group
name. '<g>' contains invalid characters`, `Invalid group name. '.' represents the current directory
in unix systems`, `Invalid group name. '..' represents the parent directory in unix systems`.
At most **128** groups per agent (existing + new): WARNING `The groups assigned to agent <id3>
exceed the maximum of 128 permitted.`.

**Decision for the owner (D-2):** siem-api allows 256 groups per agent (`groups::MAX_GROUPS`), the
agent database 128. Today an agent with 129–256 groups passes siem-api and fails here. Options:
keep both as is, or set siem-api to 128.
**Decided 13 Nov 2026: siem-api set to 128** (`groups::MAX_GROUPS`, test and `specs/siem-authd.md`
updated): the database is the hard limit, so siem-api refuses what it would refuse.

### 7.8 `set-agent-groups` (modes)
For each `{id, groups[], name?}` item (missing numeric `id` or `groups` array: DEBUG1 `Invalid
groups set information`, item skipped, result error):
- `remove`: for each group (non-text: DEBUG1 `Invalid groups remove information`): find its id
  (not found: WARNING `Unable to find the id of the group '<g>'`; bad answer WARNING `Invalid
  response from wdb_global_find_group.`), delete the agent–group link (fail DEBUG1 `Unable to delete
  group '<g>' for agent '<id>'`), then give the default group if none is left. Failure: ERROR
  `There was an error un-assigning the groups to agent '<id3>'`.
- `override`: delete all the agent's links first (fail ERROR `There was an error cleaning the
  previous agent groups`); `append` / `empty_only`: start at the agent's highest priority + 1;
  `empty_only` with existing groups: DEBUG1 `Agent group set in empty_only mode ignored because the
  agent already contains groups`, item skipped.
- Validate the groups (count ≤ 128 and names, § 7.7); then assign each in order with increasing
  priority:
  - group not found: WARNING as above;
  - link insert fails and no `name` given (non-override): DEBUG1 `Unable to insert group '<g>' for
    agent '<id>', agent not found.`;
  - link insert fails, `name` given, agent does not exist: create the agent (`0.0.0.0` address,
    now) in never-connected state (fail DEBUG1 `Unable to create agent '<id>' in never_connected
    state`), retry the link (fail DEBUG1 `Unable to insert group '<g>' for agent '<id>', retry
    failed after creating agent in never_connected state.`);
  - agent exists but insert failed: DEBUG1 `Unable to insert group '<g>' for agent '<id>', agent
    already exists, groups not synced.`; undefined error: `..., undefined error.`.
  Override without `name`: on a cluster worker ERROR `Agent name is required when overriding groups
  for agent '<id3>'` (item skipped), else DEBUG1 `Agent name is not provided for agent '<id3>', the
  agent not will not be created if it does not exist`. Assignment failure: ERROR `There was an error
  assigning the groups to agent '<id3>'`.
- After valid groups: recalculate the agent's group text and hash with the given sync status
  (failure ERROR `Couldn't recalculate hash group for agent: '<id3>'`).
- "Default group if none left": when the agent has no group: assign `default` (DEBUG1 `Agent
  '<id3>' reassigned to 'default' group`; fail ERROR `There was an error assigning the agent
  '<id3>' to default group`).

### 7.9 Group text and integrity
Group text = the agent's group names in priority order joined with `,`, stopping before it would
exceed the maximum response size (DEBUG1 `The agent's groups exceed the socket maximum response
size.`); a NULL name: DEBUG1 `Group hash is NULL`, skipped; step failure DEBUG1 `SQL statement
execution failed`. `get-groups-integrity <hash>`: `["syncreq"]` when any agent needs group sync;
else `["synced"]` when the global group hash equals the given one, `["hash_mismatch"]` otherwise;
SQL failure DEBUG1 `DB(<id>) SQLite: <error>`. Group context / hash set failures: DEBUG1 `Error
executing setting the agent group context: <error>` / `Error executing setting the agent group hash:
<error>`.

### 7.10 Recalculate group hash
After a group change: group text and hash recomputed (empty: WARNING `The groups were empty right
after the set for agent '<id3>'`, both stored as NULL), stored with the sync status (failure ERROR
`There was an error assigning the groups context to agent '<id3>'`); the cached global group hash is
cleared. `recalculate-agent-group-hashes` (all agents): per agent the text is recomputed (none:
DEBUG1 `No groups in belongs table for agent '<id3>'`) and stored only when it differs from the
stored `group` column (failure ERROR `There was an error assigning the groups hash to agent
'<id3>'`, then ERROR `Couldn't recalculate hash group for agent: '<id3>'` and the command fails).

### 7.11 `sync-agent-groups-get`
Condition `sync_status`: agents needing group sync; `all`: all agents; invalid: DEBUG1 `Invalid
groups sync condition`, error. With a condition (inside a transaction; `Cannot begin transaction`):
agents registered before now − `agent_registration_delta`, after `last_id`, one by one; each gets
`groups` (its group list, or `[]`); appended while the answer stays below the maximum size (else
`due`); with `set_synced` each appended agent's group sync status becomes `synced` (failure ERROR
`Cannot set group_sync_status for agent <id>`). At the end, with `get_global_hash`, the global group
hash is added as `"hash"` (null when empty; failure ERROR `Cannot obtain the global group hash`), or
`due` when it would not fit. Without a condition: only the hash (when asked) or an empty list.
Answer shape: `[{"data":[...]{,"hash":...}}]`.

### 7.12 `sync-agent-info-set` (per agent)
Updates every known agent column present in the JSON (numbers and texts; others ignored) and sets
`sync_status` = `synced`.

### 7.13 `disconnect-agents`
Agents after `last_id` whose keep-alive is older than the given time, sized (`ok`/`due`); each is
set `disconnected` with the given sync status and "no keep-alive" status code (failure ERROR `Cannot
set connection_status for agent <id>`; a row without id ERROR `Invalid element returned by
disconnect query`; both make the status error but the list is still returned).

### 7.14 Other reads
`get-all-agents context`: the agents' context rows are **sent to the caller as separate messages**
before the final `ok []` (the scanner's agent list). `get-all-agents last_id`: sized list.
`agent exists`: DEBUG1 `DB(<id>) SQLite: <error>` on failure. `reset-agents-connection`: every
agent's status becomes "reset by manager" with the sync status (bind failure ERROR `DB(<id>)
sqlite3_bind_text(): <error>`). `get-agents-by-connection-status`: inside a transaction, by status
(and node with a limit), sized.

### 7.15 Global database backups (`backup/db`, files `global.db-backup-<YYYY-MM-DD-hh:mm:ss>[tag].gz`)
- **Create** (on demand, and by the backup timer): commit the open transaction (fail `err Cannot
  commit current transaction to create backup`); drop prepared statements; `VACUUM INTO` the backup
  path (prepare/bind failures `err DB(<id>) sqlite3_prepare_v2(): <error>` / `err DB(<id>)
  sqlite3_bind_text(): <error>`, run failure `err SQLite: <error>`); gzip it (same compression
  output as zlib), remove the plain copy; INFO `Created Global database backup "<file>.gz"`; delete
  the oldest backups beyond the configured maximum number of files (INFO `Deleted Global database
  backup: "<file>"`); answer `ok ["<file>.gz"]`; compression failure `err Failed during database
  backup compression`. The time stamp is local time (`/` and space replaced by `-`).
- **List**: names in the folder starting with the backup name, directory order; folder unreadable
  DEBUG1 `Unable to open backup directory 'backup/db'`.
- **Restore** `[snapshot]`: default = the newest by file time (ties: the later one in directory
  order). With `save_pre_restore_state`, first a backup tagged `-pre_restore` (failure ERROR
  `Creating pre-restore Global DB snapshot failed. Backup restore stopped: <answer>`). No snapshot:
  `err Unable to found a snapshot to restore` (text as is). Decompress to `global.db.back`, close
  the database, delete `global.db`, rename (failure ERROR `Renaming <a> to <b>: <os error>`), `ok`;
  decompression failure `err Failed during backup decompression`.
- Oldest = largest age (ties: later in directory order).
- `get-distinct-groups [hash]`: distinct group texts/hashes after the given hash, sized.

<!-- next: fim.rs (recalculate hash, sync-agent-groups-get, agent info set, disconnect, backups), then fim.rs, syscollector.rs, sca.rs, agentdb.rs, delta.rs, integrity.rs, state.rs (getstats), config.rs, pool/upgrade/metadata, daemon_portable + bin, mitredb, ProVigilDbManager -->


<!-- next after that: parser_agent.rs (§ 2), task.rs (§ 5), global.rs internals -->

