# provigil-execd and provigil-agentlessd: own code for the manager's responses and agentless monitoring

Replaces `crates/siem-execd` (2,011 lines, ported) and `crates/siem-agentlessd` (814 lines,
ported). Both run only on a Linux manager: siem-api starts them there (`-f -D <home>`); on
Windows the manager runs neither (as before). New crates:

- `provigil-execd`: the service and its process helper (also used by agentlessd);
- `provigil-agentlessd`: the service;
- `provigil-daemon`: gained `xml` (the configuration XML reader) and `privs` (user, group,
  background, signal names).

They also use the earlier own crates `provigil-json`, `provigil-ipc`, `provigil-fileop` and
`provigil-regex`. Method as for `provigil-db.md`: every feature listed, own code, old vs new
compared by tests, old code to `old-code/`.

## 1. Features of the old services, and where each goes

### provigil-execd

| Feature | New |
|---|---|
| Flags `-V -h -d -t -f -g <group> -c <config>` | Same, plus `-D <home>` (E-1). |
| Home folder and chdir; log `logs/ossec.log`; debug level from `execd.debug`. | Same. |
| Group switch to the old service group. | Group `provigil`, only when started as root (E-2). |
| Settings: `<active-response><disabled>` (yes/no, else error 1235 and stop with 1202). | Same. |
| Settings: the first `<repeated_offenders>` of any `<active-response>` in any root. Up to 5 comma parts, the last keeps the rest; empty parts skipped; at most 6 values; a 0 ends the list; "Adding offenders timeout" lines. | Same. |
| Unreadable XML: critical (1226) and stop. | Same. |
| PID file; `Started (pid: N).`; `(1350): Active response disabled.` | Same. |
| Disabled: only the request thread runs. | Same, and a stop signal now ends it cleanly. |
| Queue `queue/alerts/execq`: messages up to the zero byte, logged at debug 2. | Same. |
| `ar.conf` table (`etc/shared/ar.conf`): lines of at most 65,535 bytes, `name - program - timeout`. | Same, including every rule below. |
| ↳ A `!` first character, or no ` - ` separator, is error 1313; blank lines count too. | Same. |
| ↳ Names cut to 256 bytes (error 1318). | Same. |
| ↳ A `..` program is refused. | Same. |
| ↳ A missing program is logged once (on the first reading). | Same. |
| ↳ A repeated name fills an empty program, otherwise the first entry wins. | Same. |
| ↳ At most 65 commands. | Same. |
| ↳ Timeouts read as C `atoi`. | Same. |
| Command lookup: an unknown name re-reads `ar.conf` (error 1311); `!program` runs `active-response/bin/<program>` with no timeout. | Same. A path that is too long shows the first 32 characters (E-8). |
| The agent-restart command name: `restart.sh agent`. | Same (Unix). |
| Response protocol: `command` becomes `add`, `origin.module` becomes `provigil-execd`, `parameters.program` is added, then the message is written to the program. | Same JSON byte for byte (`provigil-json`). |
| ↳ The program's first line: `check_keys` with `parameters.keys` gives the key `<program>-k1-k2...` (at most 4,095 bytes, with a warning). | Same. |
| ↳ Repeated offenders: the key's count picks the timeout (minutes × 60), the last one repeats. | Same. |
| ↳ Already pending: the time is renewed and the program gets `abort`. | Same. |
| ↳ Otherwise the response is added to the pending list with the `delete` message, and the program gets `continue`. | Same. |
| ↳ No answer line: debug, not added. | Same. A program that never answers is stopped after `execd.request_timeout` (E-4). |
| Timeouts: due responses are undone (the program gets `delete`) every second. | Same. |
| Shutdown on INT, QUIT, TERM, ALRM: undo all pending (1314), log 1225, remove the PID file. HUP is ignored. | Same. |
| Requests on `queue/sockets/com`: | |
| ↳ `unmerge` | Same answers and logs. |
| ↳ `uncompress` (gzip or a plain copy; jail to `var/incoming`) | Same answers and logs. |
| ↳ `restart` (and its old alias), `reload` (honouring the restart lock; `restart.sh` or `bin/provigil-control`) | Same answers and logs. |
| ↳ `lock_restart` (`execd.max_restart_lock`; -1 or more than the maximum means the maximum; < -1 is an error but still locks) | Same answers and logs. |
| ↳ `getconfig active-response`, `logging`, `internal`, `cluster` | Same answers and logs, except E-5 and E-6. |
| ↳ `check-manager-configuration` | Same answers and logs, except E-7. |
| ↳ Unknown command | Same answers and logs. |
| Request server: one request per connection, errors logged. | Same, plus a 30 s read limit per client (E-4). |
| Windows parts: `WinExecdStart`, the 127-message queue, the Windows restart program and process start. These ran only inside the old Windows agent. | Not carried: the Windows agent is `provigil-agent` with its own responses. |
| `wm_exec` helper (agent modules, Windows children list). | Only what execd uses (`process::capture`); the rest served the old agent. |

### provigil-agentlessd

| Feature | New |
|---|---|
| Flags `-V -h -d -t -f -u -g -c -D`. | Same. |
| Settings: each `<agentless>` section (`frequency`, `port`, `host` with `use_su`/`use_sudo`, `type`, `run_command`, `arguments`, `state`). | Same values and errors (1231, 1235, 1230, 7102, 7103, "Invalid Agentless type", "Unable to find"). |
| Settings: the check every service made of the whole file. Only `<ossec_config>` roots; only the known sections, with the "needs child elements" rule; the `database_output` warning. Errors 1230 and 1202, then 7101 and stop. | Same (`config::SECTIONS`). |
| No sections: `Not configured. Exiting.` | Same. |
| User and group switch (the old service user and group). | `provigil`, only when started as root; a missing user or group stops it (E-3). |
| PID, signals, `Started`, the 2 s settle time. | Same. |
| Event queue with reconnect and resend once (1224). A full queue drops the event and warns once. | Same. The connection retry waits 10 s, 15 s, ... at most 60 s (E-9). |
| Schedule: every minute each due periodic section, a pause of index+1 seconds after each; the first round only tests the scripts (`<script> test test`). | Same. |
| ↳ Sections given up after 10 failures. | Same. |
| ↳ A failing test gives the section up. | Same. |
| Script run: `agentless/<type> [use_sudo\|use_su] <host> <arguments...>`, standard output and error read line by line (2,047 bytes). | Same. |
| ↳ `ERROR:` (logged, counted, stops reading) and `INFO:` lines. | Same. |
| ↳ `FWD:` lines become integrity events (`syscheck` queue) and `LOG:` lines log events, location `(<type>) <host>->syscheck`. | Same. |
| ↳ `STORE:` with `periodic_diff` stores the following lines. | Same. |
| ↳ Other lines are logged at debug. | Same. |
| ↳ A script its user can write is refused (exit 127). | Same. |
| Stored states (`queue/diff/<host>-><type>/`): the first run is kept; the same content again is dropped; a change keeps `state.<time>`, runs `diff`, writes `diff.<time>`, and sends `ossec: agentless: Change detected:` with the differences (cut at a line end with "More changes..." at 65,024 bytes). | Same. |
| Host list `queue/agentless/(<type>) <host>` (`type: syscheck` or `type: diff`). | Same. |
| Requests on `queue/sockets/agentless`: `getconfig agentless`. | Same answers and logs. |

## 2. Decisions

- **E-1 `-D <home>`.** siem-api starts every Linux daemon with `-f -D <home>`. The old execd did
  not know `-D`: it printed "invalid option" and exited, so manager-side responses never ran on
  Linux. The new execd accepts it.
- **E-2 Execd group.** Execd keeps the root user (responses change the firewall) and switches to
  the group `provigil` only when started as root. If the group does not exist it warns and keeps
  the current group, rather than stopping as before. A missing group on a fresh Linux server
  must not switch off active response.
- **E-3 Agentless user.** As root, agentlessd switches to user and group `provigil`. A missing
  user or group stops it, as before, because remote-login scripts must not run as root. As a
  non-root user it keeps its user: switching would fail anyway, and the old code then stopped.
- **E-4 Time limits.** A response program gets `execd.request_timeout` seconds (60, range
  1–3600) to answer the `add` message, and as long again to end after the last message. After
  that it is stopped and logged. A request client gets 30 s to send its request. Before, either
  case blocked the service for ever.
- **E-5 `getconfig internal`.** It reports `request_timeout` and `max_restart_lock` read at start
  (defaults 60 and 600 when the options are absent). The old service never read
  `request_timeout`, so it reported 0.
- **E-6 `getconfig logging` and `cluster`.**
  - `logging` reports `plain: yes, json: no`, what the log writer does.
  - `cluster` answers "Unable to connect" when the cluster socket is absent, which is always true
    today. The old cluster request protocol is not carried: ProVigil's cluster
    (`provigil-cluster.md`) defines its own.
- **E-7 `check-manager-configuration`.**
  - It runs the programs a ProVigil manager has, each with `-t`: provigil-db, provigil-analysisd,
    provigil-modulesd, provigil-execd and provigil-agentlessd. The old list named 13 upstream
    programs, most of which no longer exist, so it always failed.
  - The error text is now whole. The old one lost its last character.
- **E-8 Path too long.** The warning shows the first 32 characters of the name. The old one padded
  the name to 32 characters.
- **E-9 Queue retry.** Agentlessd retries the event queue every 10 s, 15 s, ... at most 60 s. The
  old wait grew without a limit.
- **E-10 Paths.** Both services take the home folder explicitly and also chdir to it. The file
  helper's own error lines about unmerging show full paths.
- **E-11 Internal options.** A missing `execd.*` option uses its shipped default. Before, a
  missing option stopped the service.
- **E-12 Not carried.** The debug line about the request thread's stack size: no stack size is
  set.

## 3. Comparison (old vs new, `tests/compare_old.rs` in each crate)

- **XML reader** (`provigil-daemon/tests/compare_xml.rs`):
  - 300,000 random texts;
  - 180,000 generated documents, whole, cut short, or with one byte changed;
  - the size, nesting and attribute limits.

  Elements, attributes, contents, listings (including `var`), path lookups, error texts and
  error lines are identical.
- **execd:**
  - the `ar.conf` table (every rule above, long names, 71 commands);
  - 19 response runs against a stand-in program (what it received, the pending list after each,
    repeated offenders 1/5/10 minutes, key truncation, malformed answers), then timeouts,
    shutdown, and the log lines of each;
  - 10 settings files;
  - 22 requests (answers, files, logs).

  All identical. Not compared:
  - `getconfig cluster`: the old code had it on Unix only. A unit test covers the new answer.
  - `restart`, and the new `check-manager-configuration` list: unit tests cover them.
  - A debug line only the old Windows start-up code wrote (the command line).
- **agentlessd:**
  - 24 settings files: every field rule, every section-check rule, other roots, `var`
    elements, XML errors;
  - 6 requests;
  - section runs against a stand-in script, in normal, test-round and stored-state modes. The
    events on the queue, the files kept and the log lines are identical.

  On Windows, `diff` ends with exit code 1, not the Unix status 256, and `host->type` folder
  names are invalid. So both versions stop before the change event there, and the change path
  has a Linux-only unit test.
- **Running the tests on Windows:** the old Windows start-up code depends on the current-folder
  search of `CreateProcess`. Run the comparisons with `NoDefaultCurrentDirectoryInExePath`
  unset.

## 4. Progress

- 2026-11-13: both crates written, compared, old crates moved to `old-code/`. The Linux-only
  tests (the change event, the process start on Unix) have not run yet: the WSL Ubuntu on the
  dev PC has no Rust toolchain.
