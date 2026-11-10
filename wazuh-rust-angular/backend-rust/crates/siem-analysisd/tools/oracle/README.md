# analysisd / wazuh-logtest C oracle

`logtest_oracle` is Wazuh 4.14.7's real logtest pipeline
(`w_logtest_initialize_session` / `w_logtest_process_log`: `OS_CleanMSG`,
XML decoders and `DecodeEvent`, plugin decoders, rules, CDB lists, FTS,
accumulator, `doDiff`, `Eventinfo_to_jsonstr`) compiled from the unmodified C
sources. `tests/logtest_oracle.rs` diffs the Rust crate against it event by
event: the full output JSON (except the wall-clock `timestamp` and `id`), the
alert flag and every warning/error message.

Only daemon plumbing is stubbed (`shim/stubs.c`: logging, sockets, threads,
privilege helpers, `mitre_get_attack` → not found, alert-id counter → 0).
The Linux branches of a few small helpers (`gettime`, `IsDir`, `wfopen`,
`get_ipv4_numeric`, …) are copied verbatim.

## Build (Linux or WSL, gcc + glibc; needs `libpcre2-8.so.0` at runtime)

    tools/oracle/setup.sh <wazuh-4.14.7/src> <cJSON-1.7.18> <work>
    <work>/build.sh            # -> <work>/logtest_oracle

`pcre2.h` in the overlay only declares the handful of PCRE2 functions
`expression.c` uses, and the binary links the system `libpcre2-8.so.0`.

## Inputs

    python3 tools/make_test_home.py <wazuh-4.14.7> <home> <cases.json>

builds a Wazuh home (ruleset + test rules/decoders + lists, rule 60000 changed
the way `runtests.py` does) and the list of `ruleset/testing/tests/*.ini`
cases. Give the oracle its own copy of the home (it writes `queue/diff`,
`queue/fts`), on a native Linux filesystem: each session reads ~300 XML files.

## Run

    SIEM_LOGTEST_ORACLE="wsl -d Ubuntu-20.04 --cd /home/u/oracle -- ./logtest_oracle home" \
    SIEM_ORACLE_MANAGER=<hostname of the oracle machine> \
    SIEM_TEST_HOME=<rust home> SIEM_TEST_CASES=<cases.json> \
    SIEM_ORACLE_FUZZ=200000 \
    cargo test --release -p siem-analysisd --test logtest_oracle -- --nocapture

Sessions: one per ini case, `SIEM_ORACLE_ROUNDS` long sessions feeding the whole
event stream `SIEM_ORACLE_REPEAT` times (stateful rules), then
`SIEM_ORACLE_FUZZ` mutated events with assorted locations in sessions of 40.
The oracle loads the ruleset once and runs each session in a `fork()`ed child.

Protocol (stdin): `S` starts a session, `E <hex event> [<hex location>]`
processes an event. Output: load messages `M <level> <text>`, `READY`, then per
event `O <json>`, `A <alert flag>`, messages, `END`; `CRASH` if a session's
child died.

## analysisd event path (`ad_oracle`)

    <work>/build.sh ad         # -> <work>/ad_oracle

`ad_harness.c` loads the ruleset the way analysisd's `main()` does (rules
bound to the `<command>` / `<active-response>` blocks and `<global>` white
lists of `etc/ossec.conf`, `ar.conf` rewritten), then runs each queue message
through `OS_CleanMSG`, `DecodeEvent` and a transcription of
`w_process_event_thread` with the writer threads inlined (alert written
before the active responses run). Outputs are the real `OS_Log`,
`jsonout_output_event`, `OS_Store`, `jsonout_output_archive`, `FW_Log` and
`OS_Exec` (+ `getActiveResponseInJSON` / `InString`), with `OS_SendUnix`
writing the AR messages to `out/ar.log` and runtime errors/warnings going
to `out/messages.log`.

Fake world (mirrored by `tests/analysisd_oracle.rs`): `ORACLE_TIME` pins
`gettime`, `w_get_current_time` and `gettimeofday`; run with `TZ=UTC`;
`__shost` = "manager"; node name "node01"; active agents 1-4; agent labels
`_wazuh_version` (001 4.14.7 JSON, 002 4.1.0 legacy string, 003 4.2.3
escaped JSON, 004 none -> wazuh-db error), `env: test` and hidden
`secret`. The harness wipes `queue/fts`, `queue/diff` and `out` on start
and reports `P <n>` on stderr before each message, so the test can drop
an input that crashes the C code and retry.

Also linked for real: `state.c` (included, for its static writer: the
counters are bumped where analysisd's threads bump them, then
`asys_create_state_json`, `asys_create_agents_state_json` and the state
file), `config.c` + `config_json.c` + `logtest-config.c` (every `getconfig`
section), `mitre.c` (fed a small fixed MITRE matrix through a fake
`wdbc_query_parse_json`; its last technique has no phases so the
partial-load path runs), `asyscom.c` (included, for `asyscom_dispatch`) and
analysisd.c's hot reload code (`build.sh ad` extracts it into
`hotreload.inc`). `time()` is pinned too (`-Dtime(t)=oracle_time(t)`).

The internal decoders (rootcheck, hostinfo, ciscat, dbsync, winevt, SCA,
upgrade, syscheck, syscollector) are linked for real and talk to a fake
wazuh-db (`wdbc_query_ex`, every query logged to `out/wdb.log`).
Syscollector queries (`agent <id> netinfo|netproto|netaddr|osinfo|
hardware|port|package|hotfix|process|dbsync ...`) answer `ok done`, or
`err db` / `bad response` / `ok` / a failed query when they contain
`wdberr` / `wdbbad` / `wdbok` / `wdbfail`. `adshim/wazuh_db/wdb.h` stands in
for the real header (which needs sqlite and the router), and
`wdbi_strings_hash` + `OS_SHA1_Hexdigest` are copied verbatim (linked with
`-lcrypto`).

Input: `A <hex queue message>` and `Q <hex analysis-socket request>` lines.
Output: `=== <file>` sections (alerts, archives, firewall, AR messages,
runtime messages, ar.conf, state JSON, state file, fts-queue, getconfig,
asyscom responses).

    SIEM_AD_ORACLE="wsl -d Ubuntu-20.04 --cd /home/u/oracle_build -- env TZ=UTC ./ad_oracle home_ad" \
    SIEM_TEST_HOME=<rust home> SIEM_TEST_CASES=<cases.json> SIEM_ORACLE_MANAGER=<oracle hostname> \
    SIEM_AD_REPEAT=3 SIEM_AD_FUZZ=40000 \
    cargo test --release -p siem-analysisd --test analysisd_oracle -- --nocapture

Both homes need `ad_ossec_append.xml` appended to
`etc/ossec.conf` (local, all-agents, server and defined-agent
responses).
