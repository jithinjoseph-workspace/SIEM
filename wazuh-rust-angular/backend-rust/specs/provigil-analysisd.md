# provigil-analysisd: own code for the detection engine

Replaces `crates/siem-analysisd` (18,263 lines, ported), and with it the helper crates only it
still uses: siem-config, siem-xml, siem-ipc, siem-cjson, siem-log and siem-daemon. Owner's
requirements (2026-11-13):

- the same detection: no rule, decoder or matching feature may be missed;
- the current rules keep working unchanged until our own rules replace them;
- proven end to end, old against new.

## 0. Method and proof

1. **Feature list.** Every feature of every module, written below before any new code (section
   2). Each row says where it goes in the new code.
2. **Own code.** Written from this list, in the structure of our own crates (`provigil-daemon`,
   `provigil-ipc`, `provigil-json`, `provigil-regex`, `provigil-sqlite`).
3. **Proof, in four layers.** Nothing switches until all four agree:
   - a. **Recorded events.** Real events from ClickHouse (agent events, syslog, file integrity,
     SCA, inventory), replayed through old and new in process. Every alert and archived event
     must be identical, byte for byte.
   - b. **The ruleset's own tests** (`ruleset/testing`) and the old crate's tests (oracle,
     logtest, ruleset, overload).
   - c. **Generated inputs** per feature: decoder options, every rule option, the
     frequency/timeframe/same/different/if_matched families, lists, the accumulator,
     ignore/FTS, labels, the time and day checks.
   - d. **Live side by side.** The new engine reads the same event queue as the old one, writing
     its alerts to a comparison file, for at least a day of real traffic. Switch only when there
     is no difference.
4. **Old crate to `old-code/`** after the switch.

## 1. Module map (old crate)

| Old module | Lines | What it does |
|---|---:|---|
| `bin/provigil-analysisd.rs` | 271 | command line, start-up |
| `daemon.rs` | 1,909 | queues, the matching thread, alert/archive/firewall/FTS writers (daily files, rotation), hourly statistics, labels cache, active responses, logtest and analysis sockets, `getload` |
| `daemon_config.rs` | 320 | settings: active response, global, rules, alerts, cluster, sockets, labels, `<rule_test>`, internal options |
| `input.rs` | 196 | the decoder input queues and their occupancy |
| `event.rs` | 803 | the event and its pre-decoding (`OS_CleanMSG`): one buffer with offsets, byte for byte |
| `decoders.rs` | 980 | the XML decoder loader, decoder trees, `DecodeEvent`, field setters |
| `plugins.rs` | 534 | plugin decoders |
| `rules.rs` | 1,897 | the rule loader (attributes, AR binding, hashes, levels), rule tree, overwrite, if_matched marks |
| `engine.rs` | 1,220 | previous events, the rule matcher, context searches (last SIDs, groups, events), FTS/ignore, accumulator, `doDiff` |
| `analysis.rs` | 406 | the matching stage per event, hourly statistics |
| `output.rs` | 372 | alert, archive and firewall log formats, JSON output |
| `to_json.rs` | 619 | the alert JSON, `W_ParseJSON` |
| `syscheck_json.rs` | 354 | the syscheck part of an alert |
| `ar.rs` | 330 | active responses: which, to whom, the JSON and text messages |
| `config_json.rs` | 544 | `getconfig` answers (quirks included) |
| `logtest.rs` | 464 | the logtest service: sessions, JSON protocol |
| `logmsg.rs` | 234 | messages collected while loading a ruleset |
| `lists.rs` | 268 | CDB lists (first record wins), `.cdb` writer |
| `ruleset.rs` | 204 | which rule/decoder/list files are read |
| `state.rs` | 763 | statistics: counters, the state file, `getstats` / `getagentsstats` |
| `asyscom.rs` | 149 | the analysis socket requests |
| `mitre.rs` | 135 | MITRE technique names and tactics from provigil-db |
| `limits.rs` | 112 | EPS limits |
| `localtime.rs` | 155 | local time for formatting |
| `labels.rs` | 19 | agent labels on events |
| `timeday.rs` | 3 | time and day checks (moved to siem-config) |
| `internal/syscheck.rs` | 1,144 | file integrity events |
| `internal/syscheck_op.rs` | 548 | file integrity helpers |
| `internal/syscollector.rs` | 1,071 | inventory events |
| `internal/sca.rs` | 752 | SCA events |
| `internal/winevt.rs` | 498 | Windows event channel events |
| `internal/db_worker.rs` | 196 | the database worker |
| `internal/rootcheck.rs` | 180 | rootcheck events |
| `internal/dbsync.rs` | 171 | dbsync events |
| `internal/ciscat.rs` | 146 | CIS-CAT events |
| `internal/hostinfo.rs` | 121 | host info events |
| `internal/upgrade.rs` | 39 | upgrade results |
| `internal/mod.rs` | 96 | dispatch of the internal decoders |

## 2. Features, and where each goes

(Filled module by module while reading the old crate. A module is done when every function in
it has a row.)

### 2.1 Start-up (`bin/provigil-analysisd.rs`)

| Feature | New |
|---|---|
| Flags `-V -h -d -t -f -u -g -c -D`: `-d` counts; an option value attached or next; stops at the first non-option; a missing value prints "option requires an argument" and the help | Same; `-V` prints the ProVigil version, no licence text |
| Home folder: from the program's location, or `-D`; chdir (failure 1133 as a critical line on standard error with a time stamp) | Same |
| Debug level: `-d` count, else `analysisd.debug` (0–2, a bad value is critical) | Same |
| User/group check (Unix) and the privilege switch with chroot into the home folder | User/group `provigil`, as for agentlessd (E-3 of `provigil-execd.md`): switched only when started as root; chroot kept when root |
| Settings: active response, global, rules, alerts, cluster, sockets, labels, `<rule_test>`, internal options; warnings logged; an error is "(1202): Configuration error" and stop | Same (section 2.x, daemon_config) |
| "All alert formats are disabled ..." warning when neither `alerts_log` nor `jsonout_output` | Same |
| Sockets: "Socket '<name>' (<mode>) added" per socket; for each forwarder target, a "Socket for target ... is not defined" warning per socket before the matching one | Same (the quirk kept: the text is part of the log) |
| `rlimit_nofile` | Same (Unix) |
| Background unless `-t`/`-f`; signals flush the platform stream before exit; PID file (1212) | Same (`provigil-daemon::privs`, own signal handling as in execd) |
| Ruleset load (`Analysis::new`); `-t` stops after a successful load; a load failure is critical | Same |

### 2.2 The daemon (`daemon.rs`)

| Feature | New |
|---|---|
| **Ruleset load at start, in order:** (1) the default directories when no decoder is configured; (2) each decoder file ("Reading decoder file", failure 1202 for that file); (3) decoder options (`SetDecodeXML`: its errors make 2105 "Error loading decoder options"); (4) each list ("Reading the lists file", failure 1221); (5) "Building CDB lists"; (6) the default directories again when no rule file is configured; (7) each rule file bound to the active responses ("Reading rules file", failure 1220); (8) levels set, and one debug line per rule (`<depth> : rule:<id>, level <n>, timeout: <t>`); (9) "Total rules enabled: '<n>'"; (10) the rule hash; (11) the internal decoders; (12) the statistics rule when `<stats>` is set. Every file's warnings and errors are logged as it is read. `-t` suppresses the "Reading ..." lines and the total. | Same order, messages and failures |
| AR whitelists (IPs, host-name patterns); the forwarder (the first `<socket>` when `<forward_to>` is set); the node name ("undefined" without a cluster name) | Same |
| **Statistics files:** `stats/hourly-average/<0..24>`, `stats/weekly-average/<0..6>/<0..24>` read at start (non-numbers count 0); `stats/totals/<year>/<Mon>/ossec-totals-<dd>.log` | Same |
| **FTS:** `queue/fts/fts-queue` preloaded and appended (one line per new entry); `queue/fts/ig-queue` created and appended (ignore lines) | Same |
| **Hot reload** (`reload-ruleset`): finish the pending decodes; reload the ruleset of `etc/ossec.conf` into a new engine (decoders, lists, rules bound to the start-up active responses); internal decoders again; FTS reloaded from `fts-queue`; "Reloading ruleset" / "Ruleset reloaded successfully". The clock, alert id, hourly alerts, pending FTS writes, MITRE table and the statistics rule carry over. A failure keeps the current ruleset and returns the messages. | Same |
| **MITRE table** loaded from provigil-db at start (errors logged), shared with logtest | Same |
| **Log files** (when no platform stream): `logs/{archives,alerts,firewall}/<year>/<Mon>/ossec-<tag>-<dd>[-<nnn>].<log or json>`, with hard links `logs/archives/archives.{log,json}`, `logs/alerts/alerts.{log,json}`, `logs/firewall/firewall.log`. On opening, an existing file over `max_output_size` moves on to the next `-nnn`; an empty previous file is deleted. Daily switch at the first hour change of a new day. Rotation: every `rotate_interval`, or past `max_output_size` after `min_rotate_interval`. Flushed every second. | Same |
| **Platform stream** (siem-api): with `SIEM_STREAM_ADDR` set, alerts (`ALERT`) and archived events (`EVENT`) go to the write-ahead stream (spool `queue/stream-spool/analysisd`) instead of files. The alert id's second part is the streamed byte count. Events are always archived on the stream. Stream warnings are logged. | Same (`provigil-ipc::platform_stream`, already ours) |
| **Alert writers:** `custom_alert_output` (custom format), else `alerts_log` (text), else only JSON. The alert id's second part is the alerts file's position. `jsonout_output` writes the JSON line. The forwarder gets the JSON line without its line break; the JSON is built again for it, so its messages are logged twice. The statistics alert is written but not forwarded. | Same |
| **Firewall log** (`FW_Log`) when the event is a firewall event; archive text (`logall`) and archive JSON (`logall_json`); ignore lines; FTS lines | Same |
| **Message order** of one event: firewall, statistics alert, alert, ignore line; then for each active response, the writer messages so far, its sanity warnings, then `OS_Exec`; the remaining warnings; the archive; finally all messages are logged in that order. | Same |
| **Hourly statistics:** at each hour change, `DumpLogstats` writes the per-rule lines and `<hour>--<alerts>--<events>--<syscheck>--<firewall>`, then resets the counters. On a day change with `<stats>`, `Update_Hour` writes the totals and the averages. The hourly EPS-drop report flag is reset. | Same |
| **Input** (`queue/sockets/queue`, datagrams up to 65,536 bytes): a leading `FROM_API` byte counts platform messages; `FROM_GATEWAY` + sender counts per gateway (`getload`). The text is up to its zero byte; under 4 bytes is "(1222): Invalid msg". Messages are queued by kind; the hourly event and syscheck counters are incremented. A full queue is counted as dropped per component (CIS-CAT, syslog, localfile by its module; a localfile message without a module is 1106), and warned once per queue. | Same |
| **EPS drop reporting:** "Queues are full and no EPS credits, dropping events." once (and once per hour), `events_dropped` / `events_dropped_not_eps`; "Queues back to normal and EPS credits, no dropping events." | Same |
| **Decoding** while EPS credits last: fast queues (events, winevt, hostinfo) inline; slow ones (syscheck, syscollector, SCA, rootcheck, dbsync, upgrade, CIS-CAT) on 4 database worker threads (a window of in-flight work), results taken in arrival order. An unformatted message is 1106 + 1222. Per-component decoded counters. CIS-CAT goes through the JSON plugin first. The FIM decoder's id and name are taken over from the worker. | Same |
| **Rule matching** per decoded event (`process_event`), with labels from the cache, the hour and weekday, and `logall` forced on with the stream; the firewall-event counter | Same |
| **Labels cache:** agent 000 uses the configured labels. Others come from provigil-db (`global get-labels <id>`), cached for `label_cache_maxage`; a stale entry is served while a background read refreshes it; the first time is read inline. | Same |
| **AR delivery:** `queue/alerts/execq` (local), `queue/alerts/ar` (remote), `queue/alerts/provigil-ar` (ProVigil agents), each kept connected. A failure is "(1321): Error communicating with queue", and the next message reconnects; a connect failure is 1210. The agent version comes from the agent-version label, else provigil-db (`global get-agent-info`). The active agents list comes from provigil-db in pages. | Same |
| **Once a second:** EPS bookkeeping (`seconds_over_limit`, available credits, limit update); the state file every `state_interval` (agents no longer active on this node are removed first); decoding resumes | Same |
| **Start-up messages:** the deprecated `<queue_size>`; with AR, the IP and host-name whitelists (or "No IP/Hostname in the white list ..."); "Started (pid: N)." | Same |
| **Run order:** MITRE, logs, internal decoders, limits message, state file (or "State file is disabled."), logtest (socket `queue/sockets/logtest`, "(7200): Logtest started" / "(7201): Logtest disabled" / 7300 bind error, the session expiry timer, oversized requests answered with the oversize error), workers, input queue (1210 critical when the queue cannot be bound) | Same |
| **Analysis socket** (`queue/sockets/analysis`): an empty request is ignored; `{"command":"getload"}` is answered from the published counters without the analysis thread (`queue_usage`, `received`, `senders`); others are dispatched on the analysis thread (asyscom); oversize and receive errors are logged | Same |
| **Main loop:** input taken while the queues have room (else what arrives waits in the socket buffer: siem-api's backpressure), the queue usage published, analysis requests answered, up to 256 decodes per turn, the once-a-second work | Same |
| Forwarder (`SendJSONtoSCK`, Unix): datagram or stream to the socket location; one connection attempt per second; errors "Unable to connect to socket ..."; a busy socket (ENOBUFS) drops the message; the name `agent` is never forwarded to | Same |
| Database errors in the decoders: "Unable to connect to socket 'queue/db/wdb'." and "Bad response from provigil-db: ..." | Same (`provigil-ipc::agentdb`) |

### 2.3 Settings (`daemon_config.rs`)

| Feature | New |
|---|---|
| **Internal options** (`analysisd.*`, each a whole number in a range; a value outside it stops the start): `debug` 0–2, `decoder_order_size` 32–1024, `log_fw` 0–1, `label_cache_maxage` 0–60, `show_hidden_labels` 0–1, `min_rotate_interval` 10–86400, `default_timeframe` 60–3600, `fts_list_size` 12–512, `fts_min_size_for_str` 6–128, `rule_matching_threads` 0–32, `stats_maxdiff` 10–999999, `stats_mindiff` 10–999999, `stats_percent_diff` 5–9999, `rlimit_nofile` 1024–1048576, `state_interval` 0–86400, `event_threads`, `syscheck_threads`, `syscollector_threads`, `rootcheck_threads`, `sca_threads`, `hostinfo_threads`, `winevt_threads`, `dbsync_threads` 0–32, `geoip_jsonout` 0–1; queue sizes 128–2000000: `archives_queue_size`, `alerts_queue_size`, `statistical_queue_size`, `firewall_queue_size`, `fts_queue_size`, `decode_{syscheck,syscollector,rootcheck,sca,hostinfo,winevt,event,output}_queue_size`, `dbsync_queue_size`, `upgrade_queue_size` | Same keys, ranges and failure (the old reader fails on a missing key: E-11 of `provigil-execd.md` applies, defaults from the shipped file) |
| **Global defaults:** stats 4, integrity 8, rootcheck 8, hostinfo 8, `jsonout_output` 1, `alerts_log` 1, `memory_size` 8192, mail notify -1, `syscheck_alert_new` 1, `syscheck_ignore_frequency` 10, `syscheck_ignore_time` 3600, mail level 7, log level 1, `label_cache_maxage` 10, `hide_cluster_info` 1 | Same |
| **Reading order:** active response (commands and responses), then `etc/shared/ar.conf` is written (header + one line per command; failure 1103 stops the start); then global, ruleset, alerts, cluster, sockets; then labels; then `<rule_test>` | Same |
| **After reading:** `<alerts>` levels override the global mail/log levels; `min_rotate_interval` from the internal option; `memory_size` at least 2048; `rotate_interval` 0 or between `min_rotate_interval` and 86400 (else "Rotate interval setting must be between N seconds and one day."); `max_output_size` 0 or 1 MiB–1 TiB (else "Maximum output size must be between 1 MiB and 1 TiB."); a missing decoder or rule list takes the defaults; cluster name, node name, node type and `hide_cluster_info` copied into the global settings; `label_cache_maxage` and `show_hidden_labels` from the internal options; AR on unless disabled (-1 counts as off) | Same |
| Warnings of all readers collected and logged at start | Same |
| The siem-config readers used: `<global>` (and its syscheck options), `<cluster>`, `<socket>`, `<labels>`, `<command>`, `<active-response>`, `<rule_test>`, the time and day checks | Own readers on `provigil-daemon::xml` (section 2.4, filled when read) |

### 2.2b Input queues (`input.rs`)

| Feature | New |
|---|---|
| Queue by the message's first character: syscheck `8`, rootcheck `9`, SCA `p`, syscollector `d`, hostinfo `3`, Windows event channel `f`, dbsync `5`, upgrade `u`; everything else (CIS-CAT `e` included) is the event queue | Same |
| A queue of size N holds N-1 messages; full means count + 1 >= size | Same |
| Full-queue warnings (once each): "Syscheck decoder queue is full.", "Rootcheck decoder queue is full.", "Security Configuration Assessment decoder queue is full.", "Syscollector decoder queue is full.", "Hostinfo decoder queue is full.", "Windows eventchannel decoder queue is full.", "Database synchronization decoder queue is full.", "Upgrade module decoder queue is full.", "Input queue is full." | Same |
| Dropped counters per queue (hostinfo counts as "others", winevt as "eventchannel") | Same |
| Messages that wait on provigil-db (CIS-CAT, syscheck, rootcheck, SCA, syscollector, dbsync, upgrade) go to the worker queue; the others are decoded inline, in arrival order | Same |
| Queue usage (count / (size - 1)), the fullest queue's usage for `getload`, per-queue figures for the state file | Same |

### 2.5 The event and its pre-decoding (`event.rs`)

| Feature | New |
|---|---|
| **Event fields:** the static fields in this order (also the bit order of the rule field flags): srcip, id, dstip, srcport, dstport, srcuser, dstuser, protocol, action, url, data, extra_data, status, system_name, srcgeoip, dstgeoip, location; dynamic fields (key, value or none) looked up case-insensitively; agent id, hostname, program name, comment, decoder time stamp, decoder, generated rule, the FTS and group bookkeeping, sizes, the time (seconds and nanoseconds) and its local day, year, `HH:MM:SS` and month, previous event, labels, syscheck decoder id, rootcheck FTS, copy flag, last events, fired times, thread id, previous rule. Event types: unknown 0, syslog 1, IDS 2, firewall 3, web log 7, squid 8, Windows 9, host info 10, OSSEC rule list 11, OSSEC alert 12. FTS flags: name, srcuser, dstuser, srcip, dstip, location, id, data, system_name, done, dynamic. | Same values |
| **One buffer:** the full log and a working copy of the log in one buffer; decoders keep offsets into it and the C pointer arithmetic (including `end - 1` and the zero terminators) must behave byte for byte the same | Same model: the buffer with offsets is kept as the reference behaviour; proven by the comparison tests |
| **Message form** `<q>:<location>:<log>`: the first 2 bytes are skipped; the location ends at the first `:` not escaped by `\|`, and is unescaped (`\|\|` to `\|`, `\|:` to `:`; at most 8,451 bytes); no `:` is the format error | Same |
| **Month with an umlaut** (`Mär`): repaired to `Ma` for the header checks only | Same |
| **Syslog-style time stamps** (the log after them, then the host name and program checks): `Mmm dd hh:mm:ss ` (16); `yyyy-mm-dd hh:mm:ss,` (24); ISO 8601 `yyyy-mm-ddThh:mm:ss` with an offset (26), with fractions and an offset (30, 33, 32); `yyyy Mmm dd hh:mm:ss ` (21); `yyyy-mm-dd hh:mm:ss.ffffff+zzzz ` (32) | Same, each length and position |
| **Host name and program** after a syslog time stamp: a host name of host-name characters, then: `host: ` (Solaris: no host name, the word is the program); `host program:`; `host program[pid]:` or `program[pid] ` (other `[`: the weird-format fix that restores `[` and drops the program); AIX `\|x...:... program[: ]` forms; anything else: no host name / no program. Then `[ID n facility.severity]` is removed. The program name's length is kept. | Same |
| **Other time stamp formats** (no host name parsing): xferlog (25), snort (23), suricata (28), apache `[...]` (27, time stamp from the next byte), macOS ASL `[T...]` (the `[Sender ...]` program, `[Message ...]` log, `[Host ...]` host name), squid epoch (14, then spaces) | Same |
| **Location:** `[<id>] (<name>) <ip>-><location>`: agent id, the location after `] `, the host name inside `(...)` (empty when there is no `)`); a `[` without `]` is the format error. Otherwise agent `000`, the host name from the header or the manager's short host name. | Same |
| **Time:** the event time (seconds, nanoseconds), local day, year, month name and `HH:MM:SS` | Same (`localtime` with a fixed offset for tests) |
| **Rule description fields** (`$(field)`): dstuser, srcuser, srcip, dstip, srcgeoip / dstgeoip (only with GeoIP, which is off), srcport, dstport, protocol, action, id, url, data, status, extra_data, system_name, program_name, hostname, else a dynamic field; unknown fields expand to nothing; an unterminated `$(` keeps the rest as written; at most 1,023 bytes, else the description unchanged | Same |
| Escape helpers (`wstr_chr_escape`, `wstr_unescape`, `wstr_escape`) with their size limits | Same (`provigil-ipc::queue::escape` already matches `wstr_escape`) |

## 3. Decisions

(None yet.)

## 4. The ruleset (GPL-free plan, after the engine)

The rule and decoder **format** is free to use; the **content** of the 168 rule and 120
decoder files and 7 lists is GPL. After the engine is ours and proven:

1. List what fires: the rule ids, decoders and lists that matched real traffic (ClickHouse).
2. Write our own decoders for the formats we receive (Windows event channel, Sysmon, file
   integrity, SCA, inventory, syslog families), and our own rules for every detection that
   fired. Add SigmaHQ rules (their licence allows commercial use with credit) for breadth.
3. Run old and own rules side by side on the same events (layer d): every event the old rules
   alert on must produce an alert from ours, same level or higher. Gaps are filled before
   removal.
4. Ship ProVigil's own `internal_options.conf`, `local_decoder.xml` and agentless scripts, and
   stop siem-api reading the upstream source folder at start.
5. Remove the old ruleset files.

Not part of this work: `ruleset/sca` (used by the Linux agent, another developer's work).

## 5. Progress

- 2026-11-13: module map, method, plan; features of start-up, daemon, settings, input queues and the event written.
