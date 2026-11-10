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

1. **`verifyRemoteConf`:** the localfile check is real now (`siem_config::localfile`). Since 2026-10-16 the Windows agent also runs the real syscheck, rootcheck and wodle readers (`Agentd::conf_tests`); the Unix agentd still accepts those sections until it registers its own.
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
  - (done since: syscheck incl. registry/whodata, rootcheck, syscollector, SCA, agent-upgrade and the service stop hook; service mode tested elevated 2026-10-16.)
  - The Unix `wazuh-execd` binary is ported but not yet diffed against the C daemon.

## Next steps

1. Diff the Unix wazuh-execd against C.
2. **macOS** readers (`macos_log`, `read_macos`): port and type-check with the Darwin target. They cannot be oracle-tested here without a Mac.
3. Done for `wazuh-agent.exe` (see the sections below); the Unix daemons are the Linux agent's work.
4. Merge the old prototype agent crates (siem-agent, siem-agent-linux) onto the faithful daemons.
5. Roadmap step 7: wodles.

## Syscollector (2026-10-14)

* `siem-sysinfo` — port of `data_provider` for Windows (`sysInfoWin.cpp`, the network / ports / packages / OS helpers, the extended sources for users, groups, services and browser extensions, the WMI + WUA hotfix queries). Oracle: the 32-bit `sysinfo.dll` of the C agent through `dbg/sidump.c`; all 11 categories identical (processes differ only by the two dump processes themselves). Emulates the 32-bit agent: registry opens without `KEY_WOW64_*` use the 32-bit view; `%ProgramFiles%` & co expand to their WOW64 values.
* `siem-syscollector::port` — `syscollectorImp.cpp`, `syscollectorNormalizer.cpp`, `syscollectorTablesDef.hpp` (generated byte for byte), `wm_syscollector.c` and `config/wmodules-syscollector.c`, on `siem-dbsync` (dbsync + rsync). Oracle: `syscollector.dll` via `dbg/scdump.c` vs `syscollector-run`: same logs, same rsync messages, identical integrity checksums for every stable table.
* `siem-winagent::wmodules` — `wm_config` / `wm_check` / module threads / `modulesSync` / `wmcom_dispatch` (getconfig, query, sync); syscollector runs in `wazuh-agent.exe`.
* End to end: agent 013 → remoted → analysisd → wazuh-db holds the full inventory (sys_* tables); siem-api serves it at `/api/v1/agents/:id/inventory`.
* Not ported yet: open-scap (not used on Windows), cis-cat, github, office365, ms-graph (command and osquery: done 2026-10-16, see below; plan in docs/WINDOWS_AGENT_REMAINING.md). (SCA, syscheck/rootcheck and agent-upgrade: see below.)

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
- (Those next steps are done; see the sections below.)

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
- Verified elevated 2026-10-16 (admin_checks.ps1): the full unmerge + installer run matches C (see below).
- Not ported: the C agent crashes on a `write` without "buffer"; the Rust port answers "Cannot write file". For an unmerged name with `..`, C renames an empty temp file over the outside path; the port refuses.

## agent-upgrade (manager side), task-manager, download — 2026-10-15
- `siem-modulesd`: `agent_upgrade.rs` (wm_agent_upgrade_manager/parsing/commands/tasks/tasks_callbacks/validate/upgrades + the manager `<agent-upgrade>` reader: chunk_size, max_threads, wpk_repository), `task_manager.rs` (wm_task_manager*: socket, parsing, wazuh-db `task ...` commands, timeout/cleanup thread, `<task-manager>` reader), `download.rs` (wm_download + `wurl_request` / `wurl_get` / `wurl_http_get` on reqwest), `task_general.rs`. `wazuh-modulesd` starts them in the C list order (agent-upgrade, task-manager, database, download) and reads `etc/ossec.conf`.
- Worker nodes send task requests through the cluster socket (`w_send_clustered_message`), as C; there is no cluster daemon yet.
- siem-api: `POST /api/v1/agents/:id/upgrade` (version, wpk_repo, use_http, force, package_type; `file_path` + `installer` = upgrade_custom) and `GET` (upgrade_result) talk to `queue/tasks/upgrade` (tenant admin of the agent's tenant). The old prototype crate `siem-agent-upgrade` is removed.
- Verified vs C (WSL harness scratchpad/upgen/oracle: `build.sh` compiles the C modules with the server flags from ~/wazuh-server-src; `run.py c|rs` runs the same scenario against the Rust wazuh-db, a fake remoted, a local WPK repo; `cmpall.sh` diffs): 75/75 API answers, 81/81 agent requests (JSON and legacy `com` transfers, sha1 mismatch, open retries, clear_upgrade_result) and 327/327 log lines identical (3 start-up lines differ in order only: thread scheduling).
- Live: API -> modulesd -> remoted -> the Rust Windows agent: open/write/close/sha1/upgrade, WPK signature checked with the agent's CA; non-elevated, the agent's unmerge fails as C's does (Admin/SYSTEM temp files).
- Not ported: the wmcom getconfig dumps of these modules (the Rust modulesd has no wmcom socket yet); curl error texts other than HTTP status errors.

## Console agent actions on Wazuh agents + active-response programs — 2026-10-15
- siem-api sends agent actions the way the Wazuh API does (remoted's `queue/alerts/ar`): restart (`restart-wazuh0` JSON), FIM + rootcheck scan (`syscheck restart`), Block IP (`netsh<timeout>` on Windows, `firewall-drop<timeout>` on Unix). The manager ossec.conf gets the `firewall-drop` / `netsh` commands with 600/3600/86400 s active responses at level 20 (never rule-triggered), so `ar.conf` carries them. SCA/inventory scans have no on-demand Wazuh command (schedule + agent start); unblock is the agent's timeout. Old `siem-agent` (HTTP polling) agents keep the command queue.
- FIM and rootcheck per agent read wazuh-db (`fim_entry`, `pm_event`); the vulnerability rescan uses the packages in `sys_programs` (no hard-coded packages); the CVE feed import is platform-admin only.
- New crate `siem-active-response`: active_responses.c helpers + `netsh` (Windows), `restart-wazuh`, `firewall-drop` (Linux iptables branch). Byte-identical to the C programs (Windows: 12 runs incl. CRLF input, 65 log lines, 17 netsh/reg command lines with a recording fake; Linux: iptables/ip6tables and wazuh-control calls, 43 log lines). The C 4.14.7 netsh.exe never calls WSAStartup, so its IP check always fails ("Cannot read 'srcip'"): the oracle used a copy with WSAStartup added; the port keeps the intended behaviour.
- The Windows agent package (`data/agent-dist/windows`) serves netsh.exe and restart-wazuh.exe; the install script puts them in `active-response\bin`.
- UI: agent details tabs File Integrity, Rootcheck, Upgrade (tenant admins); block duration; Active Response pages (analyst + classic console) pick the agent; tenant settings show/rotate the agent key; Vulnerabilities page: fleet rescan + CVE feed upload (platform admins).
- Not ported: the ipf/AIX branches of firewall-drop; the Linux deploy still installs siem-agent-linux, not the ported wazuh-agentd.

## Agent groups / centralized agent.conf (siem-api + UI) — 2026-10-16
- `crates/siem-api/src/groups.rs`: list/create/delete groups, get/put `agent.conf`, `PUT /api/v1/agents/:id/groups`.
  Mirrors the Wazuh API (`create_group` template folder, `delete_groups`, `set-agent-groups` override) and
  tells wazuh-db at once (`insert-agent-group` / `delete-group`, what wm_database does on its next sync).
- Per tenant: tenant `acm`'s group `web` is the manager group `acm.web`; `default` is shared, edited by the platform admin only.
- `agent.conf` is checked with siem-config `read_config_xml` (CAGENT_CONFIG + the agent's Test_* modules, localfile reader).
- Enrollment now refuses groups that do not exist (authd "Invalid group") and registers the manager names.
- Live check: 14/14 API status codes (roles, tenants, bad names, bad XML); remoted built `acm.winsrv/merged.mg`;
  the installed Windows agent received it and unmerged the group's agent.conf.
- UI: agents page "Agent groups" panel (create/delete/edit agent.conf), "Groups" tab per agent, deploy wizard group select.

## Load test with simulated agents — 2026-10-16
- Tool: `tools/loadgen` (standalone crate + scripts); results and how to rerun: `docs/LOAD_TEST_RESULTS.md`.
- 10,000 connected agents OK; event capacity ~2,000 Windows EPS per manager (analysisd single thread,
  blocking wazuh-db label lookups). Fix order in the report (analysisd thread pools first).
- Fixed: concurrent enrollments got the same agent id (`next_free_agent_id`, atomic fetch_add).
- Fixed (Windows manager build): analysisd restart lost all events until remoted restarted
  (siem-ipc receiver re-binds its old UDP port; siem-api supervisor keeps the port file).
- Known: deleting an agent leaves its `queue/rids/<id>` file (C removes it).

## Whodata admin path verified live — 2026-10-16
- Bug fixed: `set_sacl` passed the new SACL in the DACL slot of `SetNamedSecurityInfoW` (and NULL as the SACL), so
  set_winsacl / w_update_sacl / restore_sacls *deleted* the SACL of every whodata directory; the state checker then
  reported (6021) and moved it to realtime. Never caught by the oracle runs (non-admin fallback path only).
- Live test on the installed agent (service, LocalSystem), config via the groups API: SACL "Everyone / Success" set;
  add/modify/delete alerts in mode whodata with audit user and process (powershell.exe, cmd.exe).
- Compared with the C agent on the admin path 2026-10-16: identical (see the elevated runs below).
- Elevated C-vs-Rust runs (admin_checks.ps1, 2026-10-16, after the SACL fix):
  - whodata/FIM (`runs/fim-20261016-095116`): 57 manager messages identical (incl. the whodata event with audit data);
    agent log identical except C's (6267)/(6263) SACL-setup lines: both agents watch the same folder and C set the SACL first.
  - upgrade (`runs/up-20261016-095219`): full install path ran on both (`upgraded`); messages identical; log differs only in the install dir.
  - rootcheck as administrator (`runs/rk-20261016-095350`): 49 manager messages and 1,059 log lines identical.
  - service stop on the installed agent: "Exit completed successfully", clean restart.

## verifyRemoteConf readers + small fixes — 2026-10-16
- `Agentd::conf_tests`: the Windows agent registers `SyscheckTest`, `RootcheckTest`, `WModuleTest` (Test_Syscheck/Test_Rootcheck/Test_WModule); a received agent.conf with bad values is refused with (1207) and not applied. Test: siem-syscheckd `test_readers`.
- siem-api agent delete also removes `queue/rids/<id>` (OS_RemoveCounter).
- Known: siem-syscheckd does not build on Linux (pre-existing, `siem_ipc` use in diff.rs/run_check.rs/create_db.rs).

## command wodle (Windows agent) — 2026-10-16
- `siem-winagent/src/wm_command.rs`: wm_command.c + wmodules-command.c (reader, Read_WModule reuse of a "command"-tagged
  module, schedule via siem-sca sched, w_strtok/get_binary_path/isabspath, MD5/SHA1/SHA256 checks, remote_commands for
  agent.conf commands, output lines to queue 1 with location `command_<tag>`, getconfig dump). siem-sca `crt::strtol0`.
- Verified vs C (scenario winoracle/cmd, 15 commands: output, exit codes, checksums ok/bad/skip, missing binary, timeout,
  ignore_output, disabled, no/empty tags, hex interval, time): 53 manager messages identical per command; 204 log lines
  identical as a set (threads interleave); getconfig wmodules identical.
- Known platform difference: the C agent is 32-bit, so `System32` paths it hashes are the SysWOW64 files; the Rust agent is
  64-bit and hashes the real System32 files (a verify_* hash taken with 64-bit tools now matches).

## osquery wodle (Windows agent) — 2026-10-16
- `siem-winagent/src/wm_osquery.rs`: wm_osquery_monitor.c + wmodules-osquery-monitor.c (Read_Log follower with
  pack/subquery split, truncation/rotation/deletion; Execute_Osquery with stderr classification, already-running and
  restart rules, child handle registered for the stop hook; packs + label decorators written to tmp/osquery.conf.tmp,
  json_fread with json_strip; getconfig dump). siem-execd `Wfd::process_handle`.
- Verified vs C: scenario osq1 (reader: lines, bad JSON, CRLF, truncate, delete/recreate) 8/8 manager messages and
  19/19 log lines identical; scenario osq2 (fake osqueryd stderr, packs, labels, commented config) 6/6 manager messages
  identical, tmp/osquery.conf.tmp byte-identical, log identical as a set (retry-line count depends on the run window).
- Details matched: the osqueryd stderr pipe is binary (CRLF lines keep '\r'); waccess errors use the CRT errno mapping.

## Analyst page permissions — 2026-10-16
- UI `AuthService.hasPermission` and siem-api `AuthCtx::has_permission` now share one rule: admin roles see everything;
  others need the page permission, `all`, or (SIEM pages) the `siem` suite. Analysts no longer see every SIEM page by
  role alone (the API refused their data). Test: tenancy `page_permissions`; live check 403/403/200/200/200.

## Manager speed fix — 2026-10-16
- siem-remoted: the sender counter file is kept open and rewritten in place (C `StoreSenderCounter`),
  not open/write/close per sent message (~4 ms per keepalive ACK on Windows, serializing the workers).
- siem-analysisd: expired agent-label cache entries are served while a background task refreshes
  them (own wazuh-db connection); rules stored as `Arc<RuleInfo>` (clone-on-write via `Arc::make_mut`)
  and borrowed values in `check_if_rule_match`. siem-xml: `CBuf` instead of zero-filled 20 KB buffers.
- `siem-analysisd/examples/bench_events.rs`: engine benchmark + Linux sampling profiler (`profile`),
  `live` mode with the daemon's own wazuh-db environment.
- Oracles after the change: siem-xml 20,305 docs, ruleset 1,770/1,770, logtest 64,091 events 0 diffs,
  analysisd daemon 13 outputs byte-identical. Load: see docs/LOAD_TEST_RESULTS.md (no loss at 5k/10k agents).

## UI/API fixes — 2026-10-16
- FIM page (`/api/v1/fim/summary`): built only from real FIM alerts (Wazuh `syscheck` block, now kept in the alert data):
  removed the demo records, fake hashes/diffs/sizes/timestamps and the wrong rule mapping; new "changed by"
  column (whodata user + program, else the mode). Limit: the alert data block is not stored in ClickHouse, so after a
  siem-api restart the page lists changes since the restart.
- New platform-admin page "SIEM Manager" (`/admin/siem-manager`, API `GET /api/v1/manager/status`): agents connected,
  events/s, remoted queue + discarded, analysisd queues + dropped, alerts written, running daemons.
- Block IP on Windows agents: method "Firewall rule (netsh)" or "Null route (route-null)"; `route-null` added to the
  manager's AR commands (`AR_COMMANDS`, existing ossec.conf files get the missing ones).
- route-null.exe: gateway trimmed. C 4.14.7 passes it with a trailing newline, and route.exe refuses it ("The parameter
  is incorrect", checked elevated), so C's route-null never adds the route on Windows. Verified live: API -> manager ->
  agent 024 -> route 203.0.113.254 via the default gateway added (removed by the agent after the timeout).

## wazuh-monitord (manager) — 2026-10-16
- New faithful port in `crates/siem-monitord` (the earlier quick_xml prototype, unused, moved to `legacy/`):
  main loop + time control, agent disconnection (`global disconnect-agents`), rule-504 "Agent disconnected" alerts
  after `agents_disconnection_alert_time`, `delete_old_agents` through the authd socket, `ossec.log`/`ossec.json`
  rotation by size and by day into `logs/wazuh/<year>/<Mon>/` (gzip, `daily_rotations`, `keep_log_days`), signing
  (`.sum` MD5/SHA1/SHA256 chained with the previous day) and compression of alerts/archives/firewall logs,
  `getconfig` on `queue/sockets/monitor`, `<reports>` config reader.
- Oracle: `crates/siem-monitord/tests/oracle` (real C sources + shared fake wazuh-db/queue/authd): 9 scenarios
  identical. It caught one bug, fixed: `<x type="relation">y</x>` relates x to the *content* y.
- Wired: `wazuh-monitord` is the 5th supervised daemon in siem-api; the manager home now has `logs/wazuh/`
  (C monitord exits on its first rotation without it); start-all/stop-all build and stop it.
- Live on the Windows manager: starts, "Manager started" -> rule 502 alert, `getconfig internal` answered, wazuh-db reached.
- Not ported yet: the daily e-mail reports (`generate_reports`), which need maild + reportd (next backlog steps).
  `delete_old_agents` (off by default) needs an authd socket; enrollment lives in siem-api, so with it enabled
  monitord logs "could not connect to Authd" and removes nothing.

## wazuh-maild + daily reports (manager) — 2026-10-16
- New faithful port in `crates/siem-maild` (unused prototype moved to `legacy/`): `MailConf` + `<email_alerts>`
  reader, alerts.json (`jqueue`) and alerts.log (`file-queue` + `read-alert`) sources, the e-mail text
  (`OS_RecvMailQ[_JSON]`, `PrintTable`), granular rules (level, rule_id, group, event_location, sms,
  do_not_delay, do_not_group), grouping and `email_maxperhour` (`OS_Run`; forked children are threads with a
  copy of the state), SMTP dialog (`OS_Sendmail`, `OS_Sendsms`, `OS_SendCustomEmail`) or a sendmail program,
  `getconfig` on `queue/sockets/mail`. `shared/report_op.c` is ported there too, and monitord's
  `generate_reports` now sends the `<reports>` e-mails with it.
- Oracle `crates/siem-maild/tests/oracle`: 12/12 scenarios byte-identical (incl. every SMTP byte); the real
  daemons on one alert timeline send the same e-mails. Deliberate differences: C can e-mail an alert twice
  (fork + stdio re-read, see the oracle README); the report's 5 s wait at end of file is skipped.
- Extension (not in Wazuh, used only when `etc/smtp_auth.conf` exists): STARTTLS (587) or implicit TLS (465)
  with AUTH PLAIN and certificate checks (webpki roots), CRLF + dot-stuffing of the message text. Checked live
  against smtp.gmail.com on 587 and 465 (reaches AUTH; a fake password gets 535), and an expired certificate is
  refused. `cargo run -p siem-maild --example smtp_check -- <host> <port> <starttls|tls|none> <user> <pass> <to>`.
- Platform: the super-admin SMTP page was a placeholder (GET returned fixed values, POST discarded them). Now
  `GET/POST /api/settings/smtp` store the settings in `ndr.settings` (`global_smtp_*`, which auth-service
  already reads for password-reset mail, plus `global_alert_email_*`), and `POST /api/settings/smtp/test`
  sends a test e-mail. Saving writes `etc/smtp_auth.conf` (0600, git-ignored) and the `<global>` e-mail fields
  + `<email_alert_level>` of ossec.conf, then restarts analysisd/maild/monitord. siem-api applies the stored
  settings at startup too. maild is the 6th supervised daemon; with notifications off it exits 0 and waits
  for new settings. Alert e-mails cover every tenant's agents, so recipients are platform operators.

## wazuh-integratord + integration scripts (manager) — 2026-10-17
- `crates/siem-integratord` (unused prototype moved to `legacy/`, siem-api's fake `/api/v1/integrations/dispatch`
  removed): `Read_Integrator`, `getconfig` on `queue/sockets/integrator`, `OS_IntegratorD` (alerts.json, level /
  group / rule_id / event_location filters, json or legacy alert file with C's character rewriting and `max_log`,
  options file, the `OS_StrBreak`-built argv incl. the literal `> /dev/null 2>&1` argument, exit status handling,
  refusing writable scripts).
- The five Python scripts as one Rust program `integrations` (installed as `integrations/<name>`): slack,
  pagerduty, virustotal (results back to analysisd), shuffle, maltiverse. `pyjson.rs` reproduces Python's
  `json.load`/`json.dumps`/`repr` so request bodies and logs are byte-identical; Python exceptions map to the same
  exit codes. The manager no longer needs Python for integrations.
- Oracle `crates/siem-integratord/tests/oracle`: scripts 24/24 identical vs the original .py; daemons 9/9 script
  calls identical (debug and non-debug).
- Wired: 7th supervised daemon; siem-api installs `integrations/*` (0550 on Unix); maild and integratord, which exit
  0 when not configured, now start again when ossec.conf changes. start/stop-all updated.
- Not done: a UI to configure `<integration>` blocks (today: ossec.conf), Python tracebacks are only the last line.

## wazuh-csyslogd (manager) — 2026-10-17
- `crates/siem-csyslogd` (unused prototype moved to `legacy/`, siem-api's unused `/api/v1/syslog-forwarder/format`
  removed): `Read_CSyslog`, `getconfig` on `queue/sockets/csyslog`, `OS_CSyslogD` reading alerts.log (default,
  CEF, Splunk) and alerts.json (json) with level / rule_id / group / location filters, the four message formats
  with C's field helpers (including their skip test that only drops "(none)", and the log truncation that ends
  in ".."), hostname resolution ("name/ip"), reconnects, `use_fqdn`.
- Oracle `crates/siem-csyslogd/tests/oracle`: 14/14 datagrams identical on 6 servers.
- Deliberate difference: C's `getconfig` walks past its single OSMatch for group/location (undefined behaviour);
  the port lists that matcher's patterns. The legacy location filter matches the part after "->" as a C string
  (C passes the full length and reads past it).
- Wired: 8th supervised daemon (idle until ossec.conf changes when no `<syslog_output>`); start/stop-all.
- Also: the socket-thread start now fails like C when `wazuh.thread_stack_size` is missing (maild, monitord,
  integratord, csyslogd).

## wazuh-execd on the manager (Linux) — 2026-10-17
- The Unix `wazuh-execd` of `crates/siem-execd` (ported with the Windows agent, never diffed) now matches the real C
  daemon: oracle `crates/siem-execd/tests/oracle-unix`, 6/6 script calls and the log identical (check_keys /
  continue / abort, timeouts, repeated offenders, invalid messages, shutdown deletes). It now logs the
  thread-stack line and fails like C when `wazuh.thread_stack_size` is missing.
- Wired on Linux only: 9th supervised daemon, `active-response/bin/firewall-drop` installed in the manager home.
  A Windows (dev) manager has no execd: its response programs would be Linux ones. `restart.sh` (used by C for
  `restart-wazuh`) is not shipped.

## Vulnerability scanner — part 1/3: version matchers — 2026-10-17
- New crate `crates/siem-vulnerability-scanner` (the old `siem-vuln-detector` prototype is still what siem-api
  uses until the port is complete). `version_matcher.rs`: CalVer, PEP 440, MajorMinor, SemVer, dpkg, rpm and the
  strategies (Unspecified tries them in C++'s order; Windows/macOS/pkg/pacman/snap use dpkg; apk falls back to
  Unspecified), with C++'s exceptions (stoul/stoi overflow, substr range, splitToNumbers) as errors.
- Oracle `tests/oracle-version-matcher`: the real C++ headers vs the port on 1.2M fuzzed pairs, 0 differences.
- Next: part 2, the CVE feed (CTI snapshot 346 MB + JSON-patch offsets, decoder chain, stores and global maps);
  part 3, the scan orchestrator (inventory events, package/OS/hotfix scans, alerts and the vulnerability inventory).

## Vulnerability scanner — part 2/3: CVE feed — 2026-10-17
- `feed.rs` (databaseFeedManager): processMessage ("raw" snapshot JSON-lines, "offsets" change files),
  EventDecoder (CVE / TID translation / FEED-GLOBAL / OSCPE-GLOBAL / CNA-MAPPING-GLOBAL; create, JSON-patch
  update, delete), StoreModel and the updaters (hotfixes, remediations, descriptions, candidates + `cve_package_*`
  reverse index, reject = remove), reloadGlobalMaps, the translation L2 cache and the readers part 3 needs.
  C quirks kept: the CVSS v2 description branch is dead in the gcc build (uninitialized `metricCVSSVersion`:
  v2-only CVEs get severity "" and score 0), LRUCache::forEach ignores the "stop" return (every matching
  translation is returned), CVE "delete" fails with "CVE5 buffer is empty".
- `fbs.rs`: flatbuffers `Parser::Parse` / `GenText` behaviour on JSON, driven by Wazuh's own `.fbs` files
  (unknown field = error, null = absent, scalar strings, enums by name, `FloatToString(6)`), including the
  `1: <column>: error:` positions on nlohmann's dump. `json_patch.rs`: nlohmann `patch_inplace` and its errors.
- `kvdb.rs`: the RocksDBWrapper calls on the bundled SQLite (bytewise keys, prefix seek, last key, columns);
  values are JSON, zlib-compressed above 64 bytes.
  shortcut: not RocksDB (no libclang for rust-rocksdb here); the full feed is 7.1 GB, the C++ RocksDB was larger
  on the same sample (80 MB vs 49 MB).
- `content_updater.rs` (content_manager): ExecutionContext (`queue/vd_updater/rocksdb/updater_vulnerability_feed_manager_metadata`,
  output folders, user agent `Wazuh VulnerabilityDetector/v4.14.7`), the chain (CtiOffset / CtiSnapshot / Offline
  downloader, zip / gzip / raw, PubSubPublisher, UpdateCtiApiOffset / UpdateOffline, CleanUpContent), CTI retry
  (500: 1 s then 2^n up to 30 s, 429: 90 s), snapshot fallback when offsets fail, and the Action scheduler thread.
  Not ported: the on-demand endpoint, the xz decompressor, the `api` / `file` sources (unused by the scanner).
- `scanner.rs` + `config.rs`: `<vulnerability-detection>` reader (cti-url from `<global>`), the updater policy
  (interval min 1 h), module start/stop; wired into `wazuh-modulesd`.
- Oracle `tests/oracle-feed`: Wazuh's EventDecoder/StoreModel on RocksDB vs the port, real snapshot sample +
  a real 1000-change page + edge cases: 16 results, 26 log lines and 275,498 stored values identical.
  The updater ran against a fake CTI (snapshot, 2 offset pages, a 500 retry, restart, offline zip + unchanged hash).
- Real CTI run 2026-10-17: snapshot 4,173,740 + 42,005 changes to offset 4,215,745 in 43 min (first try: the
  snapshot transfer stalled and dropped; retried at the next run). Feed DB 7.1 GB, temp files removed after.
- Not enabled in `data/manager/etc/ossec.conf` yet (needs ~7 GB plus ~6 GB temporary during the first load).

## Vulnerability scanner — part 3/3: scan orchestrator — 2026-10-22
- `scan/` (src/scanOrchestrator): `context.rs` (ScanContext on the JSON form of the Delta / SyncMsg /
  action messages, OsDataCache, RemediationDataCache, the CPE name), `scanners.rs` (PackageScanner with the
  CNA selection, L1/L2 translations, platform / vendor checks, version ranges, Windows hotfix filtering;
  OsScanner; HotfixInsert), `details.rs` (DescriptionsHelper, EventDetailsBuilder = the ECS state document,
  the package / OS / hotfix / clear alert builders, the report senders, the result indexers),
  `inventory.rs` (queue/vd/inventory: insert, delete, OS sync, hotfix-solved, clean-up), `orchestrator.rs`
  (the factory chains, run, agent re-scans from wazuh-db, the event and delayed queues), `sinks.rs` (the
  ReportDispatcher to queue/sockets/queue at wazuh_modules.max_eps, the indexer connector in local mode:
  queue/indexer/db/wazuh-states-vulnerabilities-<host>), `wdb.rs` (SocketDBWrapper incl. "due" packets),
  `util.rs` (string / time helpers, CPE parsing). `scanner.rs`: the facade (state_track policy changes,
  re-scan of all agents after each feed update) and the four router subscriptions (Linux).
- siem-router: `Parser::buffer_to_json` reads the binary flatbuffers the router carries.
- wazuh-modulesd: the router broker module (wm_router, Linux) and the scanner with max_eps and the host name.
- siem-api: the `siem-vuln-detector` prototype is gone (fake seeded detections, the in-process package
  matcher, the feed-upload endpoint). `vulnerability.rs` reads the scanner's documents every minute,
  serves them per tenant (`/api/v1/vulnerabilities`, `/agents/:id/vulnerabilities`) and writes a ClickHouse
  snapshot (`siem_vulnerabilities` of the agent's tenant) when an agent's CVEs change. Alerts come from the
  scanner through analysisd (rules 23502-23508). UI: the page reads the new list; no feed upload.
- Oracle `tests/oracle-scan`: Wazuh's own vd_scanner_testtool vs the port, real feed subset, 5 agents,
  36 events: 4,619 alert reports, 8,481 documents, inventory identical (see its README).
- Known limits: no OpenSearch indexer (the console reads the local document database), no cluster.

## Vulnerability scanner — follow-ups — 2026-10-22
- Router on Windows: `siem-router/src/socket_win.rs` (the socket API over loopback TCP with `<path>.port`
  files, same AppendHeaderProtocol framing; Linux keeps epoll + unix sockets). remoted publishes
  deltas-syscollector / rsync, the portable wazuh-db publishes wdb-agent-events / wdb-inventory-events
  (`wdb/router.rs`, shared with the Linux daemon), modulesd runs the broker: real-time scans on a Windows
  manager too.
- Queues on disk like the C++ RocksDB queues: `queue.rs` (DurableQueue on KvDb) behind queue/vd/event,
  queue/vd/delayed and queue/vd/reports; an event or report leaves its queue once handled. Oracle re-run:
  still identical.
- `siem-vuln-detector` prototype removed from the workspace.
- Enabled in `data/manager/etc/ossec.conf` (and in the ossec.conf siem-api writes for new installs); the
  feed loaded during the CTI test (401,677 CVEs, offset 4,215,745) was moved to data/manager/queue/vd/feed.

## wazuh-reportd — 2026-10-22
- `siem-maild/src/bin/wazuh-reportd.rs`: reportd/report.c `main` (getopt "Vdhstu:g:D:f:v:n:r:", `-f`/`-r`
  taking two arguments, privsep + chroot, PID file, the report on stderr) on the ported `report_op`
  (`siem_maild::report::os_reportd_start`, stdin as the alerts file). Installed in the manager `bin/` by
  siem-api (not supervised: a command-line tool).
- Oracle `tests/oracle-reportd`: the C reportd vs the port on the dev manager's alerts.log (1,038 alerts),
  12 option sets: report, stdout, exit code and log identical.
