# siem-active-response: shared response handling and the four basic responses

Written 2026-11-03 for ProVigil's own replacement of part of this crate. Describes what the
new code must do. Contains no code. The new code is written from this description only; the
replaced files are not opened.

## Scope

Replaced (written new): the crate's shared module `src/lib.rs` and the four programs
`src/bin/firewall_drop.rs`, `src/bin/netsh.rs`, `src/bin/route_null.rs`,
`src/bin/restart_wazuh.rs`, plus a new `src/dll_guard.rs`.

Kept as they are (ProVigil's own work, may be read and edited): `src/edr.rs`, `src/live.rs`,
`src/tamper.rs`, `src/yara.rs` and the programs `isolate_host`, `kill_process`,
`quarantine_file`, `yara_scan`, `live_response`, `tamper_protect`. They must keep working
on the new shared module; adjust them where its message type changes.

The program names stay (the agent starts them by these names): `firewall-drop`, `netsh`,
`route-null`, `restart-wazuh` and the six above. Keep the crate's `[[bin]]` entries and its
other dependencies; drop `siem-cjson`, `siem-log` and `siem-ipc` from it when nothing in
the crate uses them any more (use `serde_json` for JSON).

## How a response program is run

The agent starts the program with no arguments and writes one line of JSON to its standard
input:

```
{"version":1,"origin":{"name":"...","module":"..."},"command":"add","parameters":{"extra_args":["..."],"alert":{ ...the alert... }}}
```

- `command` is `add` (do it) or `delete` (undo it, e.g. when a block's time is up).
- A line that is not JSON, or lacks a numeric `version`, an object `origin`, a text
  `command` or an object `parameters`, is refused (logged, program exits).
- A line is at most 64 KiB. On Windows a line may end in `\r\n`.

**Asking before adding (stateful responses).** Before an `add`, a response that can be
undone sends one line back on standard output and waits for one answer line on input:

```
{"version":1,"origin":{"name":"<program file name>","module":"active-response"},"command":"check_keys","parameters":{"keys":["<key>"]}}
```

The answer is a message as above whose `command` is `continue` (go on) or `abort` (the same
key is already active: stop quietly, exit code 0). Anything else is an error (exit code
-1). On Windows, lines written to standard output end in `\r\n`.

## Shared module: what it offers

Names and shapes the kept programs call (keep exactly):

- `argv0() -> String`: the program name as started (first command-line argument).
- `write_debug_file(program: &str, message: &[u8])`: appends one line
  `YYYY/MM/DD HH:MM:SS <program>: <message>` (local time) to the response log:
  `logs/active-responses.log` on Linux, `active-response\active-responses.log` on Windows
  (relative to the agent's folder, the program's working directory). Errors are ignored.
  Expose the path as `LOG_FILE`.
- `enum Action { Add, Delete, Continue, Abort }`.
- `setup_and_check_message(program: &str) -> Option<(Action, serde_json::Value)>`: logs
  "Starting", reads and logs the input line, checks it (see above), returns `Add` or
  `Delete` and the whole message; logs why and returns none otherwise.
- `check_keys(program: &str, key: &str) -> Result<(), i32>`: the asking round trip above;
  `Ok` on continue, `Err(0)` on abort (logs "Aborted"), `Err(-1)` on any error.
- `get_binary_path(name: &str) -> (bool, String)`: an absolute path is checked as is;
  otherwise each folder of `PATH` is tried; returns whether it was found and the full path
  (or the name itself when not found).
- `run(path: &str, args: &[&str]) -> bool`: runs the program, waits, true when it could be
  started (its exit code does not matter). Its output is discarded.
- `run_output(path: &str, args: &[&str]) -> Option<Vec<u8>>`: same, returns what it printed.
- `lock(lock_dir: &str, pid_file: &str, program: &str, process_name: &str) -> bool` and
  `unlock(lock_dir: &str, program: &str)`: only one copy of a response runs its critical
  part at a time. The lock is held while the lock folder exists, with the holder's process
  id in the pid file. A second copy waits (growing pauses, about a minute in all); if the
  holder has not changed by then, the holder is treated as stuck: on Linux it is ended
  (found by `process_name` among running processes) and the lock taken over; when it
  cannot be ended the stale lock is removed and taken. Problems are logged under `program`.

Also offered (used by the four programs):

- Attacker IP of the alert: in `parameters.alert.data`, the Windows event field
  `win.eventdata.ipAddress`, else `win.eventdata.destinationIp`, else `srcip`; only when it
  is a valid IPv4 or IPv6 address.
- IP version of a text: 4, 6, or none.
- Extra arguments: the text items of `parameters.extra_args` joined with single spaces,
  at most 4 KiB.

## Windows: DLL guard (module `dll_guard`, Windows only)

Every one of the ten programs calls it first thing on Windows (replacing their former
include of the agent's DLL check file, which must not be used).

- Checks every module already loaded into the process, then registers for the loader's
  "DLL loaded" notifications and checks each DLL loaded later.
- A module passes when its file has a valid Authenticode signature, or its hash is in a
  Windows security catalog (system files signed that way).
- Mode, a constant in the module: off, warn (default: log a warning naming the file and go
  on) or strict (log and end the program).
- When the machine cannot verify signatures at all (test: a Windows system DLL such as
  `kernel32.dll` does not pass), log that once and skip the checks, so a broken trust store
  does not stop every response.
- Messages go to the response log through `write_debug_file`.
- When a file fails the check, the log line names the file and gives the reason Windows
  reported for each method (signature, catalog) as its error code and message text.
- Uses the `windows-sys` crate already in the dependencies (add features as needed).

## Starting other programs

`run` and `run_output` start programs with no input. On Windows they start them without a
console window, and pass each argument as written (no extra quoting), because the Windows
tools these programs call (`netsh`, `route`, `reg`) expect their arguments that way.

## Exit codes

A program ends with exit code -1 when the request cannot be read or checked, or when it
cannot take its lock; 0 when it was aborted by the agent or finished.

## The four programs

Each one: get the message (stop on error), log "Ended" at the end.

**firewall-drop (Linux).** Needs the attacker IP (log and stop without it). On `add`, ask
first with the IP as key. Uses `iptables` for IPv4, `ip6tables` for IPv6 (found with
`get_binary_path`; log when missing). Under the lock (lock folder
`active-response/bin/fw-drop`, pid file inside it): on `add` insert a DROP rule for that
source IP into the `INPUT` and `FORWARD` chains; on `delete` remove both. Log each failure.
When a command fails (it cannot start or exits non-zero, e.g. while another program holds
the firewall lock), try it again, up to 5 tries per chain, pausing 1, 2, 3, 4 seconds
between tries; log when the last try fails.
On any other system: log "Invalid system".

**netsh (Windows).** Needs the attacker IP. On `add`, ask first with the IP as key. Uses
`netsh.exe`. On `add`: add two firewall rules named `PROVIGIL ACTIVE RESPONSE BLOCKED IP`,
blocking that IP (`/32` for IPv4, `/128` for IPv6) inbound and outbound on any interface.
On `delete`: delete the rules with that name and IP, and also those named
`WAZUH ACTIVE RESPONSE BLOCKED IP` (blocks made before this version). Before adding, check
the Windows firewall profiles (Domain, Private, Public) in the registry (`reg.exe`) and log
a warning naming each profile that is off, since a block has no effect there.

**route-null (Windows).** Needs the attacker IP. On `add`, ask first with the IP as key.
Find the default gateway (the `0.0.0.0` destination of the route table, e.g. from
`route.exe print 0.0.0.0`; when there are several, any one), then add a persistent host
route for the IP (mask `255.255.255.255`) to that gateway with `route.exe`. On `delete`,
remove the route. Log when the gateway cannot be found or `route.exe` fails.

**restart-wazuh (restart the agent).** On Windows: stop and start the `ProVigilSvc`
service (`net.exe` from the Windows system folder). On Linux: run `bin/wazuh-control
restart` from the agent's folder, with no input or output. Log errors.

## Tests

- message checks: a good `add` and `delete` line; each missing or wrong-typed field refused;
  a `\r\n` line accepted
- the `check_keys` line written is exactly the JSON above (key order free) and
  continue / abort / other answers give `Ok`, `Err(0)`, `Err(-1)`
- attacker IP: Windows `ipAddress` wins over `destinationIp` wins over `srcip`; an invalid IP
  gives none; IPv6 accepted
- extra arguments joined, non-text items skipped, length limit kept
- `get_binary_path` with an absolute path and with a name found on a test `PATH`
- the debug line format (time, program, message)
- lock: a second lock attempt fails while the first is held (short waits in the test)
- firewall-drop retry: a failing command is tried 5 times with the pauses above (make the
  pause unit configurable inside the crate for the test)

Then: `cargo build` and `cargo test` for this crate, `cargo clippy -p siem-active-response
--all-targets --no-deps` clean, and `cargo build -p siem-api` (it uses `live` and `yara`).
