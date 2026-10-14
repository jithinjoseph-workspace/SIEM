# Agent daemons port: progress notes (updated 2026-10-09)

This covers roadmap step 6: wazuh-agentd (done, below) and wazuh-logcollector (done, see the logcollector section).

Roadmap step 6: a faithful port of Wazuh 4.14.7's `wazuh-agentd` (`src/client-agent/`).

## Status: ported, and checked against the C agent

The new crate `crates/siem-agentd` (binary `wazuh-agentd`, Unix only) has one module per C file:

| Module | C source |
|---|---|
| `agentd` | agentd.c |
| `start_agent` | start_agent.c |
| `sendmsg` | sendmsg.c + event-forward.c |
| `buffer` | buffer.c |
| `notify` | notify.c |
| `receiver` | receiver.c |
| `request` | request.c + request_op.c |
| `agcom` | agcom.c |
| `state` | state.c |
| `config` | config.c |
| `reload` | reload_agent.c |
| `rotate_log` | rotate_log.c + monitord `w_rotate_log` / `remove_old_logs` / `OS_CompressLog` |
| `keys` | the agent side of keys.c / msgs.c: counters, ReloadCounter, StoreCounter, stats |
| `enrollment` | enrollment_op.c + `os_ssl_keys` + check_cert.c (OpenSSL, vendored) |
| `uninstall` | the anti-tampering API check in agentd.c |
| `bin/wazuh-agentd.rs` | main.c |

Supporting work in other crates:

- **siem-ipc**:
  - `os_net` is registered.
  - New `mq_op` module: `StartMQ`, `MQReconnectPredicated`, `SendMSG`, and the wait_op.c functions.
- **siem-crypto**:
  - New `create_sec_msg_sized`.
  - `ReadOptions.client`: on the agent, the configured cipher is kept, as in the C CLIENT build.
  - `last_reject_reason()` exposes the reject reason so the agent can log what C's `ReadSecMSG` logs.
  - `parse_counter` is now public.
- **siem-config**: `<agent_config>` filters log the `os_read_agent_name` / `os_read_agent_profile` debug lines.

### Oracle test

- **Files:** `crates/siem-agentd/tests/oracle/`:
  - `run_diff.sh [scenario]`;
  - `scenarios/*.env`;
  - `script*.txt`;
  - `fake_authd.py`;
  - the fake manager, `examples/fake_manager.rs` (TCP and UDP).
- **What it does:** runs the C agent and the Rust agent side by side. Each gets its own fake manager (and a fake authd for the enrollment scenarios). The script compares:
  - `ossec.log`;
  - the decrypted manager-side streams;
  - the authd requests and `client.keys`;
  - the state file;
  - the rotated logs.
- **How to run it:**

  ```
  wsl -d Ubuntu-20.04 -u root -- bash run_diff.sh <scenario>
  ```

  Build the binaries first with `cargo build -p siem-agentd --bins --examples` in WSL, with `CARGO_TARGET_DIR=~/rs-target`.

All scenarios pass. The only differences left are thread-scheduling order and which single event wins a race for a just-freed buffer slot.

| Scenario | What it covers |
|---|---|
| default | requests (getconfig, getstate, errors), active response, junk, a traversal attempt, `merged.mg` push, force_reconnect, a dropped connection, SIGUSR1, SIGTERM and the shutdown message |
| udp | UDP transport, including the request ACK / retransmit exchange |
| flood | buffer WARNING, FULL, FLOOD and NORMAL, then shrinking on reload |
| grow | buffer growth on reload |
| verify | `remoted.verify_msg_id=1` and `recv_counter_flush=10` |
| enroll | auto-enrollment with `authd.pass`, name and groups |
| enroll_error | the manager replies with `ERROR:`, then retries |
| enroll_ca | `server_ca_path` certificate verification |
| rotate | size-based rotation to `logs/wazuh/YYYY/Mon/ossec-DD.log.gz` |

Bugs the oracle found, now fixed:

- The agent must keep its configured cipher. C's CLIENT `ReadSecMSG` does not auto-detect it from the message prefix.
- `rand` used thread-local storage, which made the atexit shutdown message panic. The port now uses `random(3)` like `os_random`.
- The buffer arithmetic must use the configured `agt->buflength`, which a reload changes before the resize, not the ring's own size.

## Known gaps

1. **`verifyRemoteConf`:** the localfile check is real now (`siem_config::localfile`). The syscheck, rootcheck and wodle checks still accept their sections until syscheckd and modulesd are ported.
2. **Compressed rotated logs:** flate2 output is not byte-identical to zlib `gzopen` output. The file format and content are the same, as verified by the rotate scenario.
3. **siem-crypto `KeyStore::parse`** (remoted) now uses the C `INVALID_KEY` text; it still logs through `tracing`, not `ossec.log`.

## wazuh-logcollector (done 2026-10-09)

- **Crate:** `crates/siem-logcollector`, binary `wazuh-logcollector`, Linux build. The old tokio/regex prototype is kept, uncompiled, in `legacy/`.
- **Shared parts:**
  - `<localfile>` parsing is in `siem-config/src/localfile.rs` (`Read_Localfile`, `Remove_Localfile`, journald filters and merge). agentd's `Test_Localfile` uses it too.
  - `siem-ipc` fix: `SendMSG` now sends the trailing NUL, as `OS_SendUnix(q, msg, 0)` does. The logcollector oracle caught this.
- **Modules:**

  | Module | C source |
  |---|---|
  | `cfile` | glibc `FILE*` behaviour |
  | `collector` | logcollector.c |
  | `readers/*` | every Linux reader, including multiline_regex |
  | `journal` | journal_log.c + read_journald.c, libsystemd through dlopen |
  | `read_alert` | `GetAlertData` |
  | `status` | file_status.json and the SHA1 contexts |
  | `state` | state.c |
  | `output` | queues, output threads, `SendMSGtoSCK` |
  | `logbuilder` | log_builder.c |
  | `lccom` | lccom.c, including the 64 KB getstate paging |
  | `config` | config.c |

- **Oracle:** `crates/siem-logcollector/tests/oracle/run_diff.sh` (with `sink.py` and `lccom.py`).
  - The test drives every format: syslog, json with labels, multi-line, multiline_regex, audit, mysql, mssql, postgresql, djb, nmapg, ossecalert and snort-full. It also covers globs with exclusion and a binary file, date-based names, command and full_command, `out_format` to a `<socket>` target, ignore/restrict, rotation, truncation, journald with a filter, and the lccom requests.
  - Results are identical for the queue, the socket target, `file_status.json`, getconfig, getstate (sorted, because C hash order is random) and `ossec.log`.
- **Scenarios** (`run_diff.sh <scenario>`, knobs in `tests/oracle/scenarios/*.env`):

  | Scenario | Covers |
  |---|---|
  | default | includes `age` (an aged file is ignored, a fresh one is read) |
  | reload | `force_reload=1`, `reload_interval=2`, `reload_delay=300` |
  | threads | 4 input threads, queue compared as a sorted list |
  | journal_rotate | `journalctl --rotate` between journal messages |

  All match C. The remaining differences come from thread scheduling: message interleaving, the second shown in DJB headers, and how many `(9005) not the owner` debug lines non-owner threads log (C itself varies between runs).
- **Gaps:** the macOS readers (`macos_log`, `read_macos`) are not ported. The Windows readers are now ported (see the Windows agent section).

## Windows agent: wazuh-agent.exe (2026-10-09)

On Windows one process (`wazuh-agent.exe`) runs agentd and logcollector, plus execd, syscheck and the modules, as threads. The C oracle is `wazuh-agent-eventchannel.exe`, cross-compiled in WSL (`make TARGET=winagent`, mingw-w64). The Rust agent is also cross-compiled in WSL (`--target x86_64-pc-windows-gnu`): vendored OpenSSL needs `make` and `perl`.

- **New crate `siem-winagent`** (bin `wazuh-agent`):
  - `main.rs`: `win_agent.c main` (`install-service`, `uninstall-service`, `start`, help) and `win_utils.c local_start`.
  - `service.rs`: `win_service.c` (the WazuhSvc service, the control handler, `WinSetError` as the fatal hook of the `*_exit` log functions).
  - `components.rs`: the execd / syscheck / modules entry points (see Gaps).
- **siem-agentd on Windows** (`win.rs`):
  - `SendMSGAction` under `hMutex`, straight into the buffer or to the manager;
  - `receiver_messages`;
  - `WinHooks` for the in-process targets (`req_receiver` dispatch, execd queue, syscom, wmcom_sync, SCA);
  - Windows paths (`ossec.conf`, `client.keys`, `rids`, `shared`, `.agent_info`, `<name>.state` written in place);
  - Winsock error texts (`win_strerror`), UDP socket non-blocking, `CryptGenRandom` `os_random` (`RAND_MAX` 32767), enrollment key store with `wfopen("w")`.
- **siem-logcollector on Windows**, all the `#ifdef WIN32` branches of logcollector.c:
  - file identity `nFileIndexLow + nFileIndexHigh`, 32-bit `off_t` sizes;
  - no seek in `handle_file`; the seek happens at start-up and after read errors;
  - `expand_win32_wildcards` and the Windows exclusion regex;
  - `set_read`: snort-full keeps `read_snortfull`, ossecalert reads as syslog, UCS-2 selection;
  - check loop through `CreateFile`; the age check uses `ftLastWriteTime`;
  - the 200-file limit; no lccom socket (agentd calls `lccom_dispatch`);
  - `SendMSGtoSCK` always goes to the manager;
  - `get_agent_ip_legacy_win32` (sysinfo networks) for `$(host_ip)`, msvcrt `strftime`, `win32` DJB host.
  - Readers: `eventchannel.rs` (EvtSubscribe, bookmarks, provider messages, reconnection), `eventlog.rs` (legacy EventLog API, vista_sec.txt), `readers/ucs2.rs` (LE/BE with the C quirks), and the per-reader CR / empty / comment handling.
  - `CFile` follows msvcrt: EOF is not sticky, and `popen` runs `%COMSPEC% /c` with a text-mode pipe.
- **Shared**:
  - siem-ipc `os_net_win.rs` (Winsock) and the Windows `mq_op` (StartMQ stubs, `__wait_lock`);
  - siem-fileop `crt.rs` (msvcrt text-mode streams for `wfopen` "r"/"w": MD5 of shared files, unmerge, state and status files) and `win_version.rs` (`get_win_version`, the Windows `getuname`);
  - siem-config: Windows localfile branches (environment expansion, network-path refusal, `*`/`?` globs), msvcrt `strftime`, `Platform::AGENT`, internal options in the install directory;
  - siem-log: Windows log paths, CRLF on stderr, `plain_*` logging, pid 0 before init, `cexit` (msvcrt `atexit`/`exit` + fatal hook).
- **Oracle test** (scratchpad scripts):
  - `winrun.ps1` runs both agents side by side, each with its own native `fake_manager.exe` (ports 25142/25143; 15063-15162 are reserved by Windows here).
  - `wingen.ps1` writes the file data; `dbg/ev.exe` writes Application events (no admin needed).
  - `windiff.sh` normalises and diffs.
  - Scenarios: `default` (eventchannel with a query) and `files` (syslog/json/multi-line/UCS-2/glob+exclude/age/snort-full/ossecalert/command/full_command/eventlog System/eventchannel).
  - Result: the manager views are identical, and the logs match line for line once sorted. Only the syscheck line differs (not ported), plus timing counts of periodic lines.
- **Added 2026-10-10:**
  - **Image trust checks** (`siem-winagent/src/dll_verify.rs`: `dll_load_notify.c` + `cryptography.c`). `WinVerifyTrust` / catalog hash for every loaded module and every later DLL load (`LdrRegisterDllNotification`), only when `CA_NAME` is in the ROOT store. Build-time `IMAGE_TRUST_CHECKS` (default 1) and `CA_NAME`, as the Makefile. Against a C build with `IMAGE_TRUST_CHECKS=1`: same warnings for the unsigned agent, same debug lines for the system DLLs.
  - **execd**: new faithful `siem-execd` (the old prototype is in `siem-execd/legacy`).
    - `config.c` (disabled, repeated_offenders, getconfig sections), `exec.c` (ar.conf table, `!command`), `execd.c` (`ExecdRun` with the check_keys / continue / abort protocol, the timeout list, the repeated offenders, `ExecdShutdown` at exit, Unix `ExecdStart`, `WinExecdStart` + `win_exec_main` and the 127-message queue), `wcom.c` (all `com` commands; Windows `wm_exec` with `CreateProcessW`), `exec_op.c` `wpopenv`/`wpclose` (Unix fork/execvp, Windows CreateProcess with binary pipes), and the Unix `wazuh-execd` binary.
    - The AR message `origin.module` is `wazuh-execd` even in the Windows agent (execd's own ARGV0).
    - Windows oracle scenario `arsc` (`dbg/arprog.c` test response, `shared/ar.conf` with a missing script and a bad line, repeated offenders, `!custom`, invalid name / JSON, com getconfig / lock_restart / restart / check-manager-configuration / unmerge / bogus): the AR program receives identical input, the manager view is identical, and the logs match.
  - **Command line / service**: `install-service`, `uninstall-service` (no admin rights), help, unknown option and the service dispatcher path match C byte for byte (exit code, stdout, stderr, log; `wincli.ps1`).
    - Bug fixed: stdout/stderr are text-mode CRT streams on Windows (LF -> CR LF, so C's "
" is "
"); `siem_log::crt_stream` / `crt_print`.
- **Gaps (Windows):**
  - syscheck (FIM + registry + whodata), rootcheck and the modules (syscollector, SCA, agent upgrade, ...) are not ported yet: shared with the Unix daemons, they are the next level and plug into `components.rs` / `WinHooks`. The service stop hook (`wm_kill_children`, `stop_wmodules`, `fim_db_teardown`) comes with them.
  - The service itself (SCM install / start / stop) needs an elevated shell to test.
  - The Unix `wazuh-execd` binary is ported but not yet diffed against the C daemon.

## Next steps

1. Windows: test the service mode in an elevated shell; diff the Unix wazuh-execd against C.
2. **macOS** readers (`macos_log`, `read_macos`): port and type-check with the Darwin target. They cannot be oracle-tested here without a Mac.
3. **syscheckd** (FIM, realtime/whodata, Windows registry, on siem-dbsync), then **modulesd/syscollector**, **execd**, **rootcheck** and **agent upgrade**, each wired into both the Unix daemons and `wazuh-agent.exe`.
4. Merge the old prototype agent crates (siem-agent, siem-agent-linux) onto the faithful daemons.
5. Roadmap step 7: wodles.

## Syscollector (2026-10-14)

* `siem-sysinfo` — port of `data_provider` for Windows (`sysInfoWin.cpp`, the network / ports / packages / OS helpers, the extended sources for users, groups, services and browser extensions, the WMI + WUA hotfix queries). Oracle: the 32-bit `sysinfo.dll` of the C agent through `dbg/sidump.c`; all 11 categories identical (processes differ only by the two dump processes themselves). Emulates the 32-bit agent: registry opens without `KEY_WOW64_*` use the 32-bit view; `%ProgramFiles%` & co expand to their WOW64 values.
* `siem-syscollector::port` — `syscollectorImp.cpp`, `syscollectorNormalizer.cpp`, `syscollectorTablesDef.hpp` (generated byte for byte), `wm_syscollector.c` and `config/wmodules-syscollector.c`, on `siem-dbsync` (dbsync + rsync). Oracle: `syscollector.dll` via `dbg/scdump.c` vs `syscollector-run`: same logs, same rsync messages, identical integrity checksums for every stable table.
* `siem-winagent::wmodules` — `wm_config` / `wm_check` / module threads / `modulesSync` / `wmcom_dispatch` (getconfig, query, sync); syscollector runs in `wazuh-agent.exe`.
* End to end: agent 013 → remoted → analysisd → wazuh-db holds the full inventory (sys_* tables); siem-api serves it at `/api/v1/agents/:id/inventory`.
* Not ported yet: the other wodles (command, osquery, open-scap, cis-cat), SCA, agent-upgrade, syscheck/rootcheck.
