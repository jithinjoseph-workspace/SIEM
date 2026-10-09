# wazuh-agentd port: progress notes (paused 2026-10-08)

This is roadmap step 6: a faithful port of Wazuh 4.14.7's `wazuh-agentd` (`src/client-agent/`).

## Done (builds, tests pass)

- **`siem-fileop/src/version_op.rs`**
  - `getuname`, `get_unix_version` and `osx_release_name`.
- **`siem-config/src/labels.rs`**
  - `labels_format`.
- **`siem-crypto/src/keystore.rs`**
  - The keystore moved here from siem-remoted, which re-exports it.
  - `msgs.rs` gained `SenderCounterFile` (the `queue/rids/sender_counter` file).
- **`siem-config/src/lib.rs`**
  - `ConfigContext` now has an ordered `log` (merror, mwarn and mdebug lines in C order).
  - Methods: `error`, `info`, `debug1`, `debug2`.
  - `ReadConfig` error paths now log as C does: the reader's own error, then `CONFIG_ERROR`.
  - For `CAGENT_CONFIG` on the agent, an XML read error is not logged.
- **`siem-config/src/client.rs`** (new; `cargo test -p siem-config` passes). It ports:
  - `Read_Client`, `Read_Client_Shared`, `Read_Client_Server`, `Read_Client_Enrollment`;
  - `Read_AntiTampering`, `Read_ClientBuffer`, `Validate_Address`;
  - the `AgentConfig` / `EnrollmentConfig` structs with the `ClientConf` and enrollment defaults.

## Written but not wired in yet

- **`siem-ipc/src/os_net.rs`**: a blocking libc port of `os_net.c`.
  - Covers connect TCP/UDP, bind, unix sockets, secure TCP framing, `OS_GetHost`, `resolve_hostname`, timeouts and keepalive.
  - It is **not** in `siem-ipc/src/lib.rs` yet. To finish it:
    1. Add `#[cfg(unix)] pub mod os_net;`.
    2. Add the dependencies `libc`, `siem-log` and `siem-regex`.
    3. Build in WSL; the module is unix-only.

## Next steps

1. Write `siem-ipc/src/mq_op.rs` as a blocking port of `shared/mq_op.c` and `shared/wait_op.c`.
   - `mq_op.c` parts: `StartMQ`, `MQReconnectPredicated`, `SendMSG` with the static `reported` flag. Reuse `mq::format_msg`.
   - `wait_op.c` parts: `os_setwait`, `os_delwait`, `os_wait`, `os_iswait`, using `queue/sockets/.wait`, a 5 s loop, and the WAITING_MSG / WAITING_FREE logs.
2. Create the crate `crates/siem-agentd`, add it to the workspace, and give it a `wazuh-agentd` binary.
   - Port these C files:
     - main.c, agentd.c, start_agent.c, sendmsg.c, event-forward.c;
     - buffer.c, notify.c, receiver.c, request.c, agcom.c;
     - state.c, config.c (`ClientConf` and the `get*Config` JSON), reload_agent.c, rotate_log.c.
   - The C source has already been read.
   - The constants are in `rc.h` and `defs.h`:
     - `CONTROL_HEADER` "#!-", HC_STARTUP / HC_ACK / HC_SHUTDOWN / HC_REQUEST;
     - the `queue/rids` paths, `NOTIFY_TIME` 20, `RECONNECT_TIME` 60.
3. Port enrollment (`shared/enrollment_op.c`). It needs TLS, probably the `openssl` crate.
4. Verify against the oracle: the real C agent is built in WSL Ubuntu-20.04 at `~/wazuh-agent-src/src/wazuh-agentd`.
   - Run the C and Rust agentd against a fake manager.
   - Decrypt both streams with siem-crypto and diff them, along with the state file and the logs.
5. After agentd: logcollector, syscheckd (FIM + realtime/whodata on siem-dbsync), modulesd/syscollector, execd, rootcheck and agent upgrade.
   - Then merge the old prototype agent crates (siem-agent, siem-agent-linux).
6. Roadmap step 7: wodles.
