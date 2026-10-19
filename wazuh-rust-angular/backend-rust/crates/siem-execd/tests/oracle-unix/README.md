# Unix wazuh-execd oracle

The real C `wazuh-execd` (`build.sh`) and the Rust one get the same exec-queue messages
(`execq_msgs.py`: repeated key -> abort, other keys, timeout 0, invalid JSON, bad command,
unknown name, missing script) with recording response scripts that use the check_keys protocol.
Run in WSL as root: `bash loop.sh <wazuh-execd>`.

2026-10-17: 6/6 script calls (stdin JSON, continue/abort, timed deletes, shutdown deletes) and
the 28-line log identical.
