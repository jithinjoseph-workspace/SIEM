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
* Not ported yet: the other wodles (command, osquery, open-scap, cis-cat). (SCA, syscheck/rootcheck and agent-upgrade: see below.)

## SCA (wm_sca) — 2026-10-14
- New crate `siem-sca`: yaml2json (unsafe-libyaml), schedule_scan, the rule engine (f/d/c/p/r, n: compare, && / ! / NOT), registry (ANSI API, C buffers), process list (32-bit agent view), module (events, cis_db + integrity hashes, summary, dump thread, sca-dump requests), `<sca>` config reader. CRT calls (strtod/strtol/atoi/stat/opendir/strerror/mktime) go through msvcrt/mingwex like the C agent.
- `siem-execd::wm_exec` is now the shared public `wm_exec` (timeout, wm_task_nice priority, 1 s reader wait); wcom uses it.
- Wired into `siem-winagent` wmodules (`Section::Sca`, `sca_push` hook, getconfig dump). siem-api serves the 8 Windows CIS policies; the install script picks one like the MSI.
- Verified: YAML→JSON byte-identical to libyaml 0.1.7+cJSON on all 77 bundled policies + edge cases; C vs Rust agent: all events identical for a 17-check feature policy and the full CIS Win11 run with dump (487 events). E2E: agent 013 → manager wazuh-db sca tables (482 checks).
- Known gaps (shortcut comments): Unix wm_exec/process list simplified; libyaml 0.2.5 vs 0.1.7 on exotic syntax; C logs an uninitialized result_code when a command can't start.

## syscheck (FIM) — step 1/6 config — 2026-10-14
- `siem-syscheckd/src/port/`: `config.rs` (config/syscheck-config.c: directories/registry readers, env + wildcard expansion incl. registry `*`/`?`, diff/sync/whodata/limits, prefilter, Read_Syscheck_Config adjustments, getSyscheckConfig/getSyscheckInternalOptions dumps), `syscheck.rs` (read_internal, config part of Start_win32_Syscheck with its log lines, syscom_dispatch/getconfig). The crate-root modules are an older prototype (unused).
- winagent: `skthread` loads it; requests to target `syscheck` go to syscom_dispatch.
- `timeday.rs` moved from siem-analysisd to siem-config (shared validate_op.c); siem-config no longer logs an empty ConfigError (a reader that already logged returns "").
- Verified vs the C agent (scenario winoracle/skcfg2): getconfig syscheck/internal + error replies byte-identical; config-stage log lines identical as a set.
- Next: update_wildcards_config + FIM DB (db/*.cpp on siem-dbsync), create_db.c scans (files, registry), run_check.c scheduler/sync, fim_diff_changes.c, realtime + Windows whodata; rootcheck getconfig still "err".

## syscheck (FIM) — steps 2–6 (scan, registry, daemon, report_changes, realtime) — 2026-10-15
- `port/fimdb.rs` (FIMDB/DB on siem-dbsync + rsync), `create_db.rs` (fim_scan/checker/directory/file/get_data, transaction callbacks, events, DB-state alerts, wildcards update), `registry.rs` (registry.c + events.c incl. the C quirks: key checksum drops `:arch`, old `gid` falls back to `uid`), `run_check.rs` (fim_initialize, start_daemon loop with scan_time/scan_day, restart), `diff.rs` (fim_diff_changes.c on zlib + `fc /n`), `realtime.rs` (ReadDirectoryChangesW + completion routines in an alertable wait, fim_realtime_event, missing-entry deletes).
- winagent: `skthread` runs `syscheck::start` (realtime_start → fim_initialize → start_daemon); syscom `fim_*` go to `push_message`, `restart` triggers a scan.
- Verified vs the C agent (scenario winoracle/fim: files with ignore/restrict/recursion, registry both arches with ignore/restrict/recursion, report_changes files + registry + nodiff, realtime add/modify/delete/dir removal, sync): manager messages identical (53/53 when both run the same number of scans); all FIM event payloads byte-identical; ossec.log identical line for line apart from scan-count timing.
- Fixed while verifying: `remove_path` sent `data:[[…]]` (realtime deletes failed); log formatting kept non-UTF-8 bytes lossily (cfmt now returns bytes).
- Windows whodata (`whodata.rs`, win_whodata.c): SACL set/restore/refresh, auditpol backup/restore with retries, LSA policy check, Security-channel subscription (4656/4663/4658/4719), device→drive mapping, state checker thread, fallback to realtime. Verified (non-admin): the fallback path is identical line for line (SACL 1314 errors, 6 auditpol attempts, 6710, directories moved to realtime). The admin path (real whodata events) needs an elevated run to verify.
- Rootcheck (`port/rootcheck.rs`): rootcheck_init + config reader + getRootcheckConfig, w_rootcheck_thread, run_rk_check, rkcl policy engine (vars incl. the comma-list truncation quirk, f/r/p/d, all/any/none/required, references), check_rc_files, check_rc_sys (Windows: top-level entries + NTFS ADS via BackupRead), registry (32+64-bit views, first-byte DWORD quirk), process list shared with siem-sca. Verified vs the C agent (scenario winoracle/rk, two scans): 29 manager messages and 546 rootcheck log lines (debug 2) byte-identical; getconfig rootcheck/internal identical.

## agent-upgrade (agent side, Windows) — 2026-10-15
- `siem-winagent/src/upgrade.rs`: `<agent-upgrade>` reader (default module + the deprecated `<active-response>` ca_verification/ca_store, `wcom_ca_store`, wait start/max/factor with msvcrt `strtol` base 0), dump, `wm_agent_upgrade_start_agent_module` (upgrade_result → `upgrade_update_status` ACKs with backoff on `u:upgrade_module`, `allow_upgrades`), `wm_agent_upgrade_process_command` (`clear_upgrade_result`, open/write/close/sha1/upgrade with the C error codes, base64 as `decode_base64`, 4 KB stdio buffer, text mode), `_unsign`/`_uncompress`, `w_wpk_unsign` + `wpk_verify_cert` (OpenSSL: CA file/dir store, RSA-SHA256). Wired as the first wmodule and the `upgrade` request target.
- siem-fileop: `w_ref_parent_folder` now matches C (Windows `\..`, C search order); `mkstemp_ex` (Windows: Administrators+SYSTEM DACL), `rename_ex` (Windows: ReplaceFile) and `UnmergeFiles` use them; `wfopen` errno = GetLastError on Windows; messages go to the daemon log (`set_logger`).
- Verified vs the C agent (scenario winoracle/up, packages from scratchpad/upgen): 60 manager messages and 37 module log lines identical (getconfig, ACK backoff, clear, every command error path, CA verification failures, bad signature, unmerge).
- Not verified vs C: the successful unmerge + installer run. Non-elevated, both agents cannot reopen their Admin/SYSTEM temp file (as designed); the Rust agent ran the installer (status 3) before the DACL port. Needs an elevated run.
- Not ported: the C agent crashes on a `write` without "buffer"; the Rust port answers "Cannot write file". For an unmerged name with `..`, C renames an empty temp file over the outside path; the port refuses.

## agent-upgrade (manager side), task-manager, download — 2026-10-15
- `siem-modulesd`: `agent_upgrade.rs` (wm_agent_upgrade_manager/parsing/commands/tasks/tasks_callbacks/validate/upgrades + the manager `<agent-upgrade>` reader: chunk_size, max_threads, wpk_repository), `task_manager.rs` (wm_task_manager*: socket, parsing, wazuh-db `task ...` commands, timeout/cleanup thread, `<task-manager>` reader), `download.rs` (wm_download + `wurl_request` / `wurl_get` / `wurl_http_get` on reqwest), `task_general.rs`. `wazuh-modulesd` starts them in the C list order (agent-upgrade, task-manager, database, download) and reads `etc/ossec.conf`.
- Worker nodes send task requests through the cluster socket (`w_send_clustered_message`), as C; there is no cluster daemon yet.
- siem-api: `POST /api/v1/agents/:id/upgrade` (version, wpk_repo, use_http, force, package_type; `file_path` + `installer` = upgrade_custom) and `GET` (upgrade_result) talk to `queue/tasks/upgrade` (tenant admin of the agent's tenant). The old prototype crate `siem-agent-upgrade` is removed.
- Verified vs C (WSL harness scratchpad/upgen/oracle: `build.sh` compiles the C modules with the server flags from ~/wazuh-server-src; `run.py c|rs` runs the same scenario against the Rust wazuh-db, a fake remoted, a local WPK repo; `cmpall.sh` diffs): 75/75 API answers, 81/81 agent requests (JSON and legacy `com` transfers, sha1 mismatch, open retries, clear_upgrade_result) and 327/327 log lines identical (3 start-up lines differ in order only: thread scheduling).
- Live: API -> modulesd -> remoted -> the Rust Windows agent: open/write/close/sha1/upgrade, WPK signature checked with the agent's CA; non-elevated, the agent's unmerge fails as C's does (Admin/SYSTEM temp files).
- Not ported: the wmcom getconfig dumps of these modules (the Rust modulesd has no wmcom socket yet); curl error texts other than HTTP status errors.
