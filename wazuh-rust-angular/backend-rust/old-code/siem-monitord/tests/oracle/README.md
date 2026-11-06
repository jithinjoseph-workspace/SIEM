# wazuh-monitord oracle

Diffs the Rust port against the real C monitord sources (Wazuh 4.14.7), built
into `harness.c` with a reduced `ReadConfig` (only `<global>` and `<reports>`)
and a stub `generate_reports` (e-mail reports are not ported yet).

Both implementations talk to the same fake wazuh-db / analysisd queue / authd
(`fake.py`); the runner compares stdout, the log lines, every wazuh-db query,
queue message and authd request, and the resulting log file tree (names,
decompressed content, `.sum` files).

Run inside WSL (C sources at `~/wazuh-mon-src/src`, built once with
`make TARGET=server` attempted so `libwazuhext.so` exists in `~/wazuh-server-src/src`):

    bash build.sh
    CARGO_TARGET_DIR=$HOME/tgt-linux cargo build -p siem-monitord --example mon_oracle
    bash run.sh $HOME/tgt-linux/debug/examples/mon_oracle

2026-10-16: all 9 scenarios identical (config + reports parsing, getconfig,
disconnect/alert/delete with wazuh-db and authd, size/daily rotation incl. the
daily-rotation limit and old-log removal, signing/compression of
alerts/archives).
