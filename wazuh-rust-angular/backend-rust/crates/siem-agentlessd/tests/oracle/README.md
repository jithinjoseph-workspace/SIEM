# wazuh-agentlessd oracle

The real C daemon (`build.sh`: agentlessd.c, lessdcom.c, main.c and
agentlessd-config.c with a `ReadConfig` reduced to `<agentless>`) and the Rust one
run side by side on the same fake `agentless/` scripts (`scripts/`), each with a
fake analysisd queue (`qrecv.py`) and getconfig requests on the com socket
(`lesscom.py`). Run in WSL as root (the daemons drop to nobody), about 5 minutes
because the daemon checks once a minute:

    bash build.sh
    CARGO_TARGET_DIR=$HOME/tgt-linux cargo build -p siem-agentlessd
    bash loop.sh $HOME/tgt-linux/debug/wazuh-agentlessd

Covered: 11 configuration cases (`-t`: missing/`..` script, bad state, frequency,
port, unknown element, missing host, frequency 0); the test round (passed,
failed exit 3, a world-writable script refused with 32512); `INFO:`/`ERROR:`/
`FWD:`/`LOG:` lines, CRLF, stderr, a line over 2047 bytes, `STORE:` outside
periodic_diff; periodic_diff first run, unchanged run, small change and a diff
over the 65024-byte buffer ("More changes..."); argv and `queue/agentless` entries.

2026-10-23: config 11/11, queue messages 32/32, script argv 19/19, getconfig 4/4,
queue/agentless + queue/diff tree (12,036 lines) and the log (53 lines) identical.

Not compared: `use_sudo` / `use_su` hosts crash the C daemon (command_args puts
the literal "use_sudo" in argv and free_strarray frees it); the Rust port runs them
(`command_args_like_c` unit test). StartMQ's two debug lines are C-only.
