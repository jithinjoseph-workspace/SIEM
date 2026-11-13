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
| Home folder: from the program's location, or `-D`; chdir (failure 1133 as a critical line on standard error with a time stamp) | `-D`, else the current folder (siem-api always passes `-D`), as execd; the same 1133 line |
| The log writer reads `<logging><log_format>` from the settings file at start (plain and/or JSON lines); an unreadable file stops with only the XML error; debug lines carry the source location; "Logging module auto-initialized", "Found user/group ..." and "Chrooted to directory ..." debug lines | Plain lines only (A-6); an unreadable file gives the XML error and "(1202): Configuration error"; no source location; those three debug lines dropped |
| Debug level: `-d` count, else `analysisd.debug` (0–2, a bad value is critical) | Same |
| User/group check (Unix) and the privilege switch with chroot into the home folder | User/group `provigil`, as for agentlessd (E-3 of `provigil-execd.md`): switched only when started as root; no chroot (A-5) |
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

### 2.6 Decoders (`decoders.rs`)

| Feature | New |
|---|---|
| **XML variables** in decoder and rule files: `<var name="X">value</var>` and `$X` replaced in contents and attributes before reading (old `siem-xml` `apply_variables`); its errors are "(1226)..."-style variable errors | **To add to `provigil-daemon::xml`**, compared with the old one like the reader |
| **File handling:** a missing file is a warning (fopen error 2) and counts as success; an XML error fails; an empty file fails, except `etc/decoders/local_decoder.xml`; no root element fails (`XML_ELEMNULL`), except the local file (-2) | Same |
| **Root elements:** only `<decoder name="...">`, optionally followed by a second attribute `status`; anything else is "Invalid element"; a decoder without child elements is `XML_ELEMNULL` | Same |
| **Decoder name store:** every decoder name and the 16 internal ones (rootcheck, syscheck_integrity_changed, syscheck_new_entry, syscheck_deleted, the six syscheck_registry_* ones, hostinfo_new, hostinfo_modified, syscollector, ciscat, windows_eventchannel, sca), sorted by bytes; a decoder's id is its 1-based position | Same |
| **Elements** (names compared ignoring case, except `type`): `parent`, `regex`, `prematch`, `program_name`, `ftscomment` (appended, at most 1,023 bytes in total, else a size error); `use_own_name` (`true`); `plugin_decoder` (a known plugin, with an offset attribute; unknown is an error); `json_null_field` (discard / string; `empty` is deprecated and means the default; other values warn and mean the default); `json_array_structure` (csv / array; other values warn); `type` (firewall, ids, web-log, syslog, squid, windows, host-information, ossec; other values: "Invalid decoder type"); `order` (fields separated by commas, more than `decoder_order_size` fields is "Order has too many fields."; each word up to its first space; the named fields, `user` meaning dstuser, any other word a dynamic field; an empty word is an error); `accumulate`; `fts` (the named FTS fields, `user`, `data`/`extra_data`, `location`, `name`, or a dynamic field already in `order`, else an error); any other element: "Invalid element ... for decoder" | Same values, messages and order of checks |
| **Attributes:** `offset` = after_parent / after_prematch / after_regex (other values: a warning for `regex`, an error for `prematch`, an error for `plugin_decoder`); `type` = osregex / osmatch / pcre2 (regex and prematch accept osregex and pcre2; program_name also osmatch; other values warn and use the default: osregex, osregex, osmatch). A second `regex` or `prematch` with an offset is a duplicate error. | Same |
| **Checks after reading** (each also logs the decoder's regex error): a decoder needs a prematch, a parent or a program name; `regex` and `order`/`fts` go together; `after_parent` needs a parent; `after_prematch` without a parent becomes after_parent, with a parent needs a prematch; `after_regex` needs a parent and a regex; a prematch offset may only be after_parent and needs a parent; the plugin offsets likewise; regex syntax errors; an OS regex without sub-strings is an error; a plugin with a regex or order is an error | Same |
| **Decoder trees:** decoders without a parent go to the program-name list or the other list; children are added under every decoder with the parent's name in both lists (error when none: the plugin/parent error). Adding to a list with a decoder of the same name: a child with a prematch or with FTS is an error; when both have a regex or plugin, the earlier gets "get next" (several children decode in turn), otherwise a duplicate error; `after_regex` needs such an earlier sibling | Same |
| **Decoder ids** (`SetDecodeXML`): each top decoder's id from the store; children take the parent's id and name unless `use_own_name`; an id of 0 is a decoder error | Same |
| **Decoding** (`DecodeEvent`), on the program-name list when the event has a program name, else the other list. For each top decoder: the program name must match (the prematch position starts at the log); the prematch must match (the position moves past the match, plus one when not at the end). Then the first child whose prematch matches (at the log, or after the parent's match), or the first child without a prematch; children marked "get next" are skipped as a group when they do not match. Then the regex: at the log, after the parent, after the prematch, or after the previous regex (or the prematch when there was none); no match ends decoding (or tries the next "get next" child); the order fields are set from the sub-strings; more dynamic fields than `decoder_order_size` stops; "get next" continues with the next child. Plugins run instead of a regex. | Same, step by step; proven with generated events per path |
| Order field setters: the static fields, or a dynamic field with the order's name | Same |

### 2.7 The rule loader (`rules.rs`)

| Feature | New |
|---|---|
| **Files:** a name without `/` is under `ruleset/rules`; relative paths under the home folder; a missing file is a warning and success; XML and variable errors fail; an empty file is success; no root element is a configuration error | Same |
| **Roots:** only `<group name="...">` (exactly one attribute `name`), else "Invalid root element"; a group without rules: "Group ... without any rule."; each child must be `<rule>`, with at least one attribute | Same |
| **Rule attributes:** `id` (digits, at most 6), `level` (digits, 0–16), `maxsize` (digits, first 4), `timeframe` (digits, first 5), `frequency` (digits, 2–9999, stored minus 2), `accuracy` (digits, first 4), `ignore` (digits, first 6), `noalert` (0/1, other values warn), `overwrite` (yes/no, else error); any other attribute: the "Only id, level, ..." error. Then "Invalid attribute for rule." A missing id or level: "No rule id or level specified for rule 'j'." Defaults: timeframe = `default_timeframe`, accuracy 1. | Same, including the C `atoi` / width-limited `sscanf` readings |
| **Duplicates:** an existing id without `overwrite` is a duplicate warning and the rule is skipped; `overwrite` for a missing rule warns and loads it as new | Same |
| **Rule start:** level 0 is stored as 99; with accuracy the level is ×100; maxsize sets extra info; mail and log flags from the levels; `noalert`; the highest frequency is kept; group = the file's group name; the rule's file | Same |
| **Elements** (most compared ignoring case; the exact-case ones are marked): `regex` (osregex), `match` (osmatch), and the field options `user`, `srcgeoip`, `dstgeoip`, `id`, `srcport`, `dstport`, `status`, `hostname`, `data`, `extra_data`, `program_name`, `action` (string type), `system_name`, `protocol`, `location`, `url`: each appended (at most 2,047 bytes), with `negate` (yes/no, others warn) and `type` (osregex/osmatch/pcre2, others warn); some set packet or extra info | Same, the same defaults and info flags |
| `decoded_as` (an unknown decoder is an error); `cve` and `info` (with `type` = text/link/cve/osvdb, invalid ones are errors; at most 32 details); `time` and `weekday` (the time and day checks; errors); `group` (appended, line breaks removed); `description` (the first line break becomes a space, appended); `srcip` / `dstip` (IP lists with `negate`; invalid IPs are errors) | Same |
| `field name="..."`: at most `decoder_order_size` fields; no `name` attribute is an error; static field names are refused ("Field ... is static."); osregex by default, `negate`, `type`; syntax errors | Same |
| `list` with `field` (the static names or a dynamic field), `lookup` (match_key, not_match_key, match_key_value, address_match_key, not_address_match_key, address_match_key_value), `check_value` (osmatch); errors for missing/invalid attributes; a list that is not loaded warns and skips the rule | Same |
| `compiled_rule` (check_id_size, comp_srcuser_dstuser, comp_mswin_targetuser_calleruser_diff, is_simple_http_request, is_valid_crawler; unknown is an error) | Same, each function's exact test (section 2.8) |
| `category` (firewall, ids, syslog, web-log, squid, windows, ossec; others are errors) | Same |
| `if_sid` (appended), `if_level` (digits, else warn and skip), `if_group`, `if_matched_regex`, `if_matched_group`, `if_matched_sid` (digits, else warn and skip) | Same |
| `same_*` / `different_*` options: srcip (also `same_source_ip`, `not_same_source_ip`, exact case for the different one), dstip, srcport (`same_src_port`), dstport, protocol, action, id (`not_same_id`), url, data, extra_data, status, system_name, srcgeoip, dstgeoip, location, srcuser, user (`not_same_user`); `same_field` / `not_same_field` / `different_field` (dynamic fields, a list each); `same_agent` / `not_same_agent` only warn as deprecated; `check_diff`; `global_frequency`; `if_fts`. Exact-case names: `same_id`, `same_url`, `same_data`, `same_extra_data`, `same_status`, `same_system_name`, `same_srcgeoip`, `same_dstgeoip`, `different_srcip`, `not_same_source_ip`, `different_protocol`, `different_action`, `different_id`, `not_same_id`, `different_url`, `different_data`, `different_extra_data`, `different_status`, `different_system_name`, `different_srcgeoip`, `different_dstgeoip` | Same names, the same case rules |
| `options`: alert_by_email, no_email_alert, log_alert, no_log, no_ar, no_full_log, no_counter (others are errors) | Same |
| `ignore` / `check_if_ignored`: user, srcip, dstip, id, location, data, name, or dynamic fields (at most `decoder_order_size`); an empty word is an error | Same |
| `mitre`: the old form (`id`) and the new form (`tacticID` + `techniqueID`, one each per block); every warning for empty values, mixing forms (old discarded when the new appears), missing halves; duplicates not repeated | Same |
| Any other element: "Invalid option ... for rule ..." | Same |
| **Checks after reading:** `if_sid` must be digits, commas and spaces (else warn and skip the rule); a description is required; context options (frequency, same/different, check_diff, global_frequency) need an `if_matched_*`; `if_matched_group` becomes `if_group` and `if_matched_sid` becomes `if_sid` when the rule has neither (and is not an overwrite); then every expression is compiled (errors name the option) | Same |
| **Active responses bound to the rule:** a rule with a real level and without `no_ar` gets each response whose level is reached and group matches (or level, or group, when only one is set), or whose rule id list names it | Same |
| **Rule tree:** rules with id < 10 are top rules, sorted by level (higher first, insertion before the first lower level). `if_sid`: a child of each listed rule (a missing one warns; with `if_matched_sid` it drops the rule); `if_level`: a child of every rule at that level or above; `if_group`: of every rule whose group matches (word match); otherwise by category (the first rule of the same category). Errors drop the rule with the matching warning. `overwrite` replaces the first rule with that id (depth-first) in place, field by field, warning about changed `if_*` options | Same, including the overwrite field list and warnings |
| **Context marks:** `if_matched_sid` searches the last events of the named rule (its event list is created); `if_matched_group` searches a group list filled by every rule whose group matches; other context rules search the last events; `check_diff` alone is not a context rule | Same |
| **Levels:** 9900 becomes 0, other levels of 100 or more divided by 100 (`_setlevels`); the rule hash: id to the first rule found depth-first | Same |

### 2.8 The matcher (`engine.rs`)

| Feature | New |
|---|---|
| **Engine settings:** rule settings, `memory_size` (event list size), `fts_list_size`, `fts_min_size_for_str`, the manager's short and full host names, `queue/diff`, `queue/fts/ig-queue`, cluster name/node and `hide_cluster_info`, `show_hidden_labels`, the MITRE table | Same |
| **Ruleset load** (also for logtest sessions): decoders, decoder ids, lists, rules (bound to the active responses), levels, the rule hash; a fork of a loaded ruleset with empty state | Same |
| **Rule statistics** (`DumpLogstats`): `<hour>-<id>-<level>-<fired>` for every rule that fired (depth-first), counters reset | Same |
| **FTS preload:** lines of `fts-queue` (at most 256 bytes each, without the line break, up to a zero byte) | Same |
| **Accumulator** (decoders with `accumulate`): needs an id and a decoder name; key `<hostname or (null)> <decoder> <id>` (shorter than 256 bytes); a stored entry younger than 120 s fills the event's empty dstuser, srcuser, dstip, srcip, dstport, srcport, data (values of 1–80 bytes); the entry is then updated the same way; old entries purged every 200 lookups or 300 s | Same |
| **FTS** (`if_fts` rules on decoders with `fts`): the line `<decoder> <id> <dstuser> <srcuser> <srcip> <dstip> <data> <system_name> <location>` (only the decoder's FTS fields; the decoder name or location `(null)` when absent), at most 255 bytes, then the FTS dynamic fields (` value` each, up to 256 bytes). Seen before: no match. IDS decoders keep a recent list: a line matching more than 2 recent lines in more than `fts_min_size_for_str` bytes is cut to that size. A new line is stored and written to `fts-queue`. An `FTS_DONE` mark (decoder or rootcheck) skips the check. | Same |
| **Ignore check** (`check_if_ignored`): the same kind of line built from the rule's `ckignore` fields (data and system name taken from `ignore`, as in the original), compared with each line of `ig-queue` including its line break (255-byte chunks) | Same |
| **Ignore line** (`ignore`): `\n<fields>[ <dynamic fields>]\n` appended to `ig-queue` | Same |
| **check_diff:** host name `(x)` reduced to `x`; file `queue/diff/<host>/<rule id>/last-entry`; events of 65,536 bytes or more never match; first time: stored, no match; same log: no match; different: stored, the event gets `previous` and last events "Previous output:" + the old log; an empty stored file is removed | Same |
| **Context searches** (frequency rules): over the rule's sid list, group list, or the whole event list (newest first). Stop at the first event older than the timeframe. Same agent unless `global_frequency`. Same id and same srcip when asked. Dynamic same/different fields (both events must have fields). With `SAME_EXTRAINFO` (or always, for the event list): the static same/different fields (same starts at dstip). The event list also needs the same decoder type and the `if_matched_regex` (its sub-strings kept). An event already matched at this level or higher stops. The first `frequency` events are counted (and kept as the last events, at most 10 shown), the next one fires: both the event and the first matched get the level. A failed search empties the last events. | Same; the one known C endless loop (`continue` without advancing, different agent) stays a skip, as now (decision A-1) |
| **Rule match order** (`OS_CheckIfRuleMatch`): decoded_as (the syscheck decoder id when set); program name, id, system name, protocol, match (log), regex (log), action, url, location; dynamic `field`s; with packet info: srcip, dstip, srcport, dstport; with extra info: compiled rule, user (dstuser, else srcuser, else no match), srcgeoip, dstgeoip, maxsize, time, weekday, data, extra_data, hostname, status, check_diff; FTS; lists (user = srcuser else dstuser; a missing field: no match); the context search. A missing field for an option: no match; `negate` inverts. | Same order (the order matters: sub-strings and side effects) |
| **Compiled rules:** comp_srcuser_dstuser (both present and equal, or either missing), check_id_size (id of 10 bytes or more), comp_mswin_targetuser_calleruser_diff (the values after "Target Account Name" and "Caller User Name" differ before a tab or two spaces), is_simple_http_request (url `/` or without `?`), is_valid_crawler (log starts with one of 8 crawler networks) | Same |
| **Children:** after a match, children are tried in order; the first child that matches wins and the parent becomes the previous rule. `noalert` rules never alert. A fired rule counts `firedtimes` and the hourly alerts. | Same |
| Logtest debug lines: "Trying rule: <id> - <description>" (1,055 bytes), "*Rule <id> matched" (31), "*Trying child rules" | Same |
| **Event store:** a fired rule with a sid list or group lists gets the event added (node ids kept to remove it later); the event list keeps the newest first; over `memory_size`, the oldest are dropped (at least 10, and while older than the highest frequency) and removed from the rule lists | Same |
| **Logtest pipeline:** location escaped, `1:<location>:<event>`, pre-decoding, size, decoding, accumulator, rules (top rules of the event's category; an OSSEC alert without a rule stops; level 0 stops; ignore time; ignore check; stored), description fields expanded, alert when `logbylevel` is reached, the alert JSON with `rule.level` added when missing | Same (section logtest) |

### 2.9 One event through the rules (`analysis.rs`)

| Feature | New |
|---|---|
| Size = the log's length; the accumulator when the decoder asks | Same |
| **Firewall events** (decoder type firewall): counted; with `log_fw`, an event missing any of action, srcip, dstip, srcport, dstport, protocol goes no further (not even to the archive); otherwise a copy goes to the firewall log | Same |
| **Statistics alert** (with `<stats>`): the hour's and the weekday's counts; when above normal, a copy of the event with the statistics rule (id 11, group `stats,`, description "Excessive number of events (above normal).") and the log replaced by the message ("The average number of logs between H:00 and H+1:00 [on <weekday>] is N. We reached M.", at most 190 bytes) | Same |
| **Statistics rules** (`stats.c`): no check until 3 days of averages; at most 3 alerts a day, once per hour; the threshold `n + max(mindiff, min(maxdiff, n × percent / 100 + 1))`; the daily update of the hourly and weekly averages (new: count + 20; else weighted with up to 7 days, +5, or +25 after 3 alerts) and the "Hour totals - h:n" / "Total events for day:n" lines | Same arithmetic |
| Labels added to the event (and the processed counter) | Same |
| **Rule walk:** top rules of the event's decoder type, in order; an OSSEC alert event uses the rule its plugin set (none: no archive at all); the first match wins | Same |
| Level 0: stop (archived only) | Same |
| **Ignore time:** first fire stores the time; within `ignore`, the previous rule (the matched child's parent) is used instead with its last events cleared, or nothing when there is none; after it, the time is reset | Same |
| Ignore check (stop, no rule); ignore line; the description's `$(field)`s; the alert copy when the rule logs | Same |
| **Active responses:** for each bound response, the dstuser must match `^[a-zA-Z._0-9@?-]*$` and the srcip `^[a-zA-Z.:_0-9-]*$` (else warnings 1272 / 1271 "Possible logging attack." and no response); a copy of the event per response | Same |
| The event joins the rule lists and the event list (its last events dropped); the archive copy when archiving | Same |
| No rule: the archive copy when archiving | Same |

### 2.10 Text formats (`output.rs`)

| Feature | New |
|---|---|
| **alerts.log** (`OS_Log`): `** Alert <sec>.<id>: [ mail ]- <groups>` / `<year> <Mon> <dd> <hh:mm:ss> [<host>->]<location>` (the host only when the location does not start with `(`) / the labels (`key: value`, not system ones, hidden only when shown; over 65,536 bytes none) / `Rule: <id> (level <n>) -> '<description>'` / `Src IP`, `Src Port`, `Dst IP`, `Dst Port`, `User` lines when present / the full log / for syscheck decoders an `Attributes:` block (size, permissions, date via ctime, inode, user (uid), group (gid), MD5/SHA1/SHA256 unless `xxx`, file attributes, the audit names, ids and folders, "What changed:", "Tags:" one per line), otherwise the decoder's dynamic fields / the last events / a blank line. Missing values print `(null)`. | Same bytes |
| **Custom format** (`custom_alert_output`): `$TIMESTAMP`, `$FTELL`, `$RULEALERT` (`mail `), `$HOSTNAME`, `$LOCATION`, `$RULEID`, `$RULELEVEL`, `$SRCIP`, `$DSTUSER`, `$FULLLOG` (line breaks as `\n`), `$RULECOMMENT`, `$RULEGROUP`; missing values `None`; values cut to 1,023 bytes; every occurrence replaced, in that order | Same |
| **archives.log** (`OS_Store`): `<year> <Mon> <dd> <time> [<host>->]<location> <full log>`; keep-alive locations (`ossec-keepalive`, `...->ossec-keepalive`) skipped | Same |
| **firewall.log** (`FW_Log`): the action normalised on the event (d/r/b → DROP, c/t → CLOSED, a/p/o → ALLOW, otherwise "drop" → DROP then "accept" tested on that → ALLOW or UNKNOWN), then `<date> [<host>->]<location> <ACTION> <protocol> <srcip>:<srcport>-><dstip>:<dstport>` | Same, the quirk kept |
| JSON lines for alerts and archives (keep-alives skipped in the archive) | Same |

### 2.11 The alert JSON (`to_json.rs`)

| Feature | New |
|---|---|
| **Member order:** `timestamp` (local `YYYY-MM-DDThh:mm:ss.mmm+zzzz`), `rule`, `agent`, `manager`, then `id` (`<sec>.<id>`), `cluster` (unless hidden: name, default the product name, see A-2; node), `previous_output`, `full_log`, `syscheck`, `predecoder`, `decoder`, `previous_log`, then `data` (when not empty); then the post-processing below | Same order (the console and ClickHouse read these documents) |
| **rule:** `level` (unless 0), `description`, `id` (text), `mitre`, `cve`, `info`, `frequency` (context rules: frequency + 2), `firedtimes` (unless `no_counter`), `mail` (bool) | Same |
| **mitre:** new form: per technique id, its name and the named tactic (warnings "Mitre Technique ID ... not found in database." and "Mitre Tactic ID ... is not a tactic of ..."), no repeats; old form: the ids, all tactics of each technique, the technique names | Same |
| `previous_output`: the last events joined by line breaks, when there are at least 2 and the second is not empty | Same |
| **data:** protocol, action, srcip, srcport, srcuser, dstip, dstport, dstuser, then id, status, url, data, extra_data, system_name, then the decoder's dynamic fields (dotted keys become nested objects; a value that is a whole JSON array is kept as an array; the first value of a key wins); GeoIP fields only with GeoIP (off) | Same |
| `full_log` unless the rule has `no_full_log` (archives always); `agent.id`; the syscheck section and its audit part for syscheck decoders; `predecoder` (program_name, timestamp); `decoder` (accumulate, parent, name, ftscomment) | Same |
| **Post-processing** (`W_ParseJSON`): `agent.name` (the location's agent name, or the manager's name for agent 000); `predecoder.hostname` from a syslog header in the full log; `agent.ip` (the agent-IP label, else from the location, not `any`); `location` (after `->` for agent locations); `agentless` {script, user, host} for agentless locations of agent 000 (then `agent` is removed); `rule.groups` and the compliance arrays (`pci_dss_`, `cis_`, `gdpr_`, `gpg13_`, `hipaa_`, `nist_800_53_`, `tsc_`), plus the SCA check's compliance values; for rootcheck alerts, `{name: a, b}` pairs from the full log (at most 10, 29 bytes each) as arrays; `agent.labels` (not system ones, hidden only when shown) | Same |

### 2.12 Active responses (`ar.rs`)

| Feature | New |
|---|---|
| **Source IP:** `::ffff:` removed; an IP in the whitelist, or matching a host-name whitelist pattern, means no response; no srcip is `-` | Same |
| User = dstuser or `-`; for syscheck decoders the file name, shell-escaped (`\\"'\t;\`><\|#*[]{}&$!:()`, an already escaped character kept); the command's extra arguments shell-escaped; the rule id | Same |
| **Local** (`location` AS_ONLY, or remote for agent 000): only when local AR is on; the JSON message to `queue/alerts/execq` | Same |
| **Remote** (when remote AR is on): to all active agents (provigil-db, "Unable to get agent's ID array."), a specific agent (its id), or the event's agent ("Unable to get agent ID."). Per agent: its version ("Failed to get agent 'N' information from provigil-db.", no version: nothing). A `ProVigil ...` version: the JSON message to `queue/alerts/provigil-ar`. Other versions (`<product> v<major>.<minor>.<patch>`, else "Unable to read agent version."): below 4.2 the text message, otherwise JSON (4.2.0–4.2.4 with `!$'\`` written as `\\xNN`), to `queue/alerts/ar`. | Same, all paths (the old-version paths serve agents other than ProVigil's, e.g. the Linux agent) |
| **JSON message:** `{"version":1,"origin":{"name":<node>,"module":"provigil-analysisd"},"command":<name>,"parameters":{"extra_args":[words of up to 2,047 bytes],"alert":<the alert JSON>}}`, at most 65,536 bytes | Same |
| **Text message:** `<name> <user> <ip> <sec>.<id> <rule> <location> <file or -> <extra args or ->`, at most 1,023 bytes | Same |
| **Envelope:** `(local_source) [] N<R or N><S or N> <agent id> <message>` (R remote, S specific or all), the head at most 1,023 bytes, all at most 65,536 | Same |

### 2.13 The syscheck part of an alert (`syscheck_json.rs`)

| Feature | New |
|---|---|
| The 51 syscheck field positions (file, hard_links, mode, size and size_before, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, diff, attrs, changed fields, the audit user/group/process/login/effective fields, tag, symbolic path, registry arch, value name, value type, registry hash, entry type, event type) | Same positions |
| `syscheck`: path, hard_links (parsed JSON), mode, symbolic_path, arch, value_name, value_type; `*_before` only when set and different from the after value; size_after; permissions (`perm_*`, or `win_perm_*` arrays of `{name, <type>: [PERMS]}` for Windows lists, with their warning/error when they cannot be read); uid, gid, md5, sha1, sha256; attrs as arrays; uname, gname; mtime as local `YYYY-MM-DDThh:mm:ss` (the old 20-byte buffer cuts the zone; an invalid value is `Invalid: '<v>'` cut to 23 bytes, and the two mtimes share that buffer); inode as a 32-bit number (after only when not 0); diff (unless `0`, only when the order size reaches it); tags and changed_attributes as arrays; event | Same, the buffer quirks kept |
| `syscheck.audit`: user, process (id, name, cwd, parent_name, parent_cwd, ppid), group, login_user, effective_user, each only when set | Same |

### 2.14 Plugin decoders (`plugins.rs`)

| Feature | New |
|---|---|
| Names (exact): `PF_Decoder`, `SymantecWS_Decoder`, `SonicWall_Decoder`, `OSSECAlert_Decoder`, `JSON_Decoder` | Same |
| **JSON_Decoder:** reads from the log, after the parent or after the prematch (the plugin offset); the JSON's members flattened with dotted keys; strings up to a zero byte; numbers as integers or `%f`; booleans `true`/`false`; null as `null` (default) or dropped (`json_null_field discard`); arrays as JSON text (default) or a CSV string (`json_array_structure csv`: strings, numbers, null, true, false; other items skipped; over 65,535 bytes empty, and an empty value is not set). Keys srcip, dstip, dstport, srcport, protocol, action, srcuser, dstuser, id, status, url, data, extra_data, `systemname` set the static fields (`user` sets dstuser only when it is empty); other keys are dynamic fields, at most `decoder_order_size` | Same |
| **PF_Decoder:** after `) `: `p` pass / `b` block; after `: `: `srcip[.port] > dstip[.port]:` (the port after the 4th dot); protocol from the next word: `u` UDP, `i` ICMP, else TCP | Same |
| **SymantecWS_Decoder:** comma-separated `10=` dstuser (128), `11=` srcip (128), `60=` url (1,024), `3=`/`2=` id (9 bytes, not stopping at commas); first value wins | Same |
| **SonicWall_Decoder:** sets its decoder's type to syslog, then `pri=(\d) c=(\d+) m=(\d+) ` (status, category (7 bytes), id), `src=ip:port:x dst=ip:port:`, `proto=` (up to 6 host-name characters before `/`); category 32 makes the type IDS; ids 98/597/598 firewall `pass`; 38/36/173/174/37 firewall `drop`; 537 firewall `close`; 97 squid with `result= dstname= arg=` (id = result, url = dstname + arg). The type change is on the decoder itself, so it lasts for later events (original behaviour, kept) | Same |
| **OSSECAlert_Decoder:** sets its decoder's type to OSSEC alert; `Alert Level: ...; Rule: <id> ...; Location: <loc>; [srcip: x;] [user: y;] <log>`: the rule must exist (by id); location becomes `<location>\|<loc>` (254 bytes) and also the host name; srcip and dstuser; the log becomes the rest (4,094 bytes); the event carries that rule | Same |

### 2.15 CDB lists (`lists.rs`)

| Feature | New |
|---|---|
| **Files:** a name without `/` is under `ruleset/rules`; a `.cdb` suffix is removed; the text file is read (a missing one is a warning, not an error); the list is known by its text name and its `.cdb` name | Same |
| **Text format** (per line of at most 65,534 bytes, cut at a zero byte, `\r` and `\n`): `key:value`; a key in quotes when a `"` comes before the `:` (`"k:1":v`; an unterminated quote skips the line); a value in quotes (`x:"v"`; unterminated: skipped); a line without `:` is skipped; `key:` gives an empty value | Same |
| **Lookups:** the first record of a key wins (`cdb_find`). match_key; not_match_key; match_key_value (the value must match the `check_value` pattern; no pattern never matches); address_match_key (the key, then shorter prefixes ending in `.`, e.g. `10.1.2.` then `10.1.` then `10.`); not_address_match_key; address_match_key_value (true when the address lookup with the value check FAILS: the original's inverted result, kept) | Same, the inversion kept: rules depend on it |
| A `.cdb` writer (D. J. Bernstein format) for other tools | Same |

### 2.16 Ruleset file selection (`ruleset.rs`)

| Feature | New |
|---|---|
| `<ruleset>`: `rule_include` / `decoder_include` (a name without `/` under `ruleset/rules` or `ruleset/decoders`), `list`, `rule_exclude`, `decoder_exclude`, `rule_dir` / `decoder_dir` (with `pattern`, default `.xml$`; an attribute other than `pattern` leaves no pattern, which is a "does not compile" error); other elements are "Invalid element" | Same |
| Default directories when none is given; every file of each directory whose path matches the pattern, unless excluded or already listed (by path or file name) | Same |
| **Order:** decoders and rules sorted by file name (bytes), a stable sort keeping directory order for equal names | Same (the order decides which of two same-level rules is tried first) |
| `<alerts>`: `email_alert_level`, `log_alert_level` (digits, else an error) | Same |
| Reading the ruleset from `ossec.conf` (logtest: also `<alerts>`; hot reload: only `<ruleset>`): XML errors; "There are no configuration blocks inside of ..."; only `<ossec_config>` roots; a section without options is `XML_ELEMNULL` + configuration error | Same |

### 2.17 Logtest (`logtest.rs`)

| Feature | New |
|---|---|
| **Sessions:** an 8-hex-digit token (random, unique); each session loads the ruleset of `etc/ossec.conf` (`<ruleset>` and `<alerts>`) into its own engine, without active responses, with the global rule hash; `logbylevel` from `<alerts>` (default 0); more than `max_sessions`: the least recently used goes; sessions idle for `session_timeout` are removed (checked every timeout) | Same |
| **Request checks:** JSON parse error: code 1, "(7307): Error parsing JSON in position N, ... <20 bytes around> ..."; missing/invalid `parameters` or `command` (7313/7317, code 2); commands `log_processing` and `remove_session`, others "(7306): Unable to process command" (code 3); `remove_session` needs an 8-character token (7309 / 7316, code 4); `log_processing` needs non-empty `location` and `log_format` (7308) and `event` (non-empty string or non-empty object; 7313/7317); an invalid token warns (7309) and is dropped; non-object `options` warns (7005) and is dropped | Same codes and texts |
| **log_processing:** a known token renews the session, an unknown one warns "(7003): '<t>' token expires"; a new session: "(7202): Session initialized with token '<t>'" or "(7311): Failure to initializing session"; `options.rules_debug` (boolean, else 7006) adds the rule trace; an object event is printed compact; the event goes through the logtest pipeline (2.8); "(7312): Failed to process the event"; `output`, `rules_debug`, `alert` | Same |
| **remove_session:** "(7206): The session '<t>' was closed successfully" or "(7004): No session found for token '<t>'" | Same |
| **Response:** `{"message":..,"error":<code>,"data":{"messages":["ERROR: ...","WARNING: ...","INFO: ..."],"token":..,"output":..,"rules_debug":[..],"alert":<bool>,"codemsg":<-1 error, 1 warning, 0>}}`; an oversized request: `{"message":"(7315): Failure to receive message: size is bigger than expected","error":5}` | Same |

### 2.18 Load messages (`logmsg.rs`)

| Feature | New |
|---|---|
| Message lists with info / warning / error, each text cut to 2,047 bytes; analysisd's lists keep the last 50 (the oldest dropped) but remember that an error was seen | Same |
| **The message texts** (every code and wording kept, they are shown in logs and logtest): 1103 file open, 1226 XML read, 1227 XML variables, 1231 NULL element, 1230 invalid element, 1234 NULL content, 7601 / 7602 / 7603 decoder option values, 2109 duplicated offsets, 2107 decoder configuration, 2110 decoder argument, 2108 no prematch, 2120 offset, 1452 / 1451 / 1450 regex syntax and sub-strings, 2111 plugin data, 2106 / 2105 decoder plugin, 1104 string size, 2102 / 2103 / 2104 duplicated decoders, 2101 parent name, 1202 configuration error, 1232, 1279, 7612 duplicated rule id, 7613 overwrite of a missing rule, 1274 invalid configuration, 1241 day format, 1237 IP, 5107 rule tag syntax, 7616 list not loaded, 1273 category, 7609 if_level, 7615 if_matched_sid, 1235 value, 7618 if_sid, 7600 rule attribute value, 7614, 7620 / 7617 signature not found, 7607 invalid signature, 7619 empty if_sid, 7608 level, 7610 group, 7611 category, 7605 overwrite, 1106 format | Same texts (a table in the new code, checked against the old one by a test) |
| System error texts in the glibc wording (No such file or directory, Permission denied, ...) | Same |

### 2.19 MITRE table (`mitre.rs`)

| Feature | New |
|---|---|
| Loaded from provigil-db's `mitre` database in pages of 100 techniques (not revoked, not deprecated, the `mitre-attack` external id); per technique its phases' tactics (name and external id); first entry per id wins | Same queries |
| Errors: "Response from the Mitre database cannot be parsed.", "... has 0 elements.", the missing technique/tactic id/name/external id texts, then "Mitre matrix information could not be loaded." | Same |

### 2.20 EPS limits (`limits.rs`)

| Feature | New |
|---|---|
| With `maximum` and `timeframe`: credits = eps × timeframe, one per decoded message; a credit spent comes back `timeframe` seconds later; "EPS limit enabled, EPS: 'N', timeframe: 'T'"; without the maximum but with a timeframe: the warning "EPS limit disabled. The maximum value is missing in the configuration block."; otherwise "EPS limit disabled" | Same |
| Limit reached and the available credits for the state report | Same |

### 2.21 Labels, local time, time and day checks (`labels.rs`, `localtime.rs`, `timeday.rs`)

| Feature | New |
|---|---|
| Labels: key, value, hidden and system flags; lookup by exact key | Same |
| Local time: the system zone, or a fixed offset for tests; broken-down time, `ctime` text, the `%FT%T%z` text into a 20-byte buffer | Same |
| Time and day checks used by rules (`<time>`, `<weekday>`; from siem-config): the accepted formats and the "on time" / "on day" tests | Own code in the new crate (section 2.x when read) |

### 2.22 Statistics, the analysis socket and getconfig (`state.rs`, `asyscom.rs`, `config_json.rs`)

| Feature | New |
|---|---|
| **Counters:** bytes and events received; decoded and dropped per component (agent, agentless, dbsync, monitor, remote, syslog, virustotal, and the modules aws, azure, ciscat, command, docker, gcp, github, office365, ms-graph, oscap, osquery, rootcheck, sca, syscheck, syscollector, upgrade, vulnerability, and logcollector eventchannel / eventlog / macos / others); processed; written alerts, archives, firewall, FTS, stats; EPS (available credits now and before, dropped, dropped not by EPS, seconds over the limit); per agent (not agentless or syslog, not agent 000): uptime, decoded per component, processed, written alerts/archives/firewall; agents no longer active are removed | Same |
| **Component of a log event:** the module after `->` in the location (or in the message for drops), mapped by name: the agent, agentless, monitor and remote program names (old and ProVigil spellings), cloud and tool module names, `command`/`command_*`, `macos`, `WinEvtLog`, otherwise logcollector "others" | Same mapping table, both spellings |
| **State file** `var/run/provigil-analysisd.state` (written to `.temp` then renamed; errors 1103 and the rename/delete texts): the totals, per-queue usage (two decimals) and sizes | Same text |
| **getstats** JSON: uptime, timestamp, name, `metrics.bytes.received`, `metrics.eps` (when EPS is on), `metrics.events` (processed, received, `received_breakdown` with `decoded_breakdown` / `dropped_breakdown` (module breakdowns), `written_breakdown`), `metrics.queues` (size, usage per queue) | Same keys and order |
| **getagentsstats:** the listed agents (fewer than 75), or `"all"` with `last_id` (pages of 75 from provigil-db, `due` when full); per agent its metrics | Same |
| **Socket requests:** `getstats`, `getagentsstats`, `getconfig` (sections global, active_response, alerts, decoders, rules, internal, command, labels, rule_test), `reload-ruleset` (the load messages; `due` when it failed); answers `{"error":N,"message":..,"data":..}` with the codes ok, due, Invalid JSON input, Empty command, Unrecognized command, Empty parameters, Empty section, Unrecognized or not configured section, Invalid agents parameter, Error getting agents from DB, Empty last id, Too many agents | Same |
| **getconfig sections:** each section's JSON as the old one builds it (global options, active responses and commands, alert levels, internal options, labels, rule_test, the full decoder list with their options, the full rule list with their options), quirks included (the FTS list holds only the first flag; the dynamic FTS fields printed as a 0/1 string; a rule with `if_level` gets an extra `if_group`) | Same JSON, compared key by key with the old code |

### 2.23 Internal decoders: the set (`internal/mod.rs`) and Windows events (`internal/winevt.rs`)

| Feature | New |
|---|---|
| **Built-in decoders** (not in the decoder trees), created at start and again on hot reload, each with its id from the name store: rootcheck (fields title, file), hostinfo (with the ids of `hostinfo_new` / `hostinfo_modified`), ciscat, windows_eventchannel, sca, syscollector, the FIM decoder (the 51 syscheck field names) and the FIM decoder ids; all of type OSSEC rule list | Same |
| **Windows event channel** (`f` queue): the decoder is set, program name and time stamp cleared; the log must be JSON ("Malformed EventChannel JSON event." error, else no `Event`: debug and stop) | Same |
| The `Event` value is printed as compact JSON and read as XML (string mode: up to a zero byte; raw bytes); an unreadable one warns once "Could not read XML string: '...'" (later ones at debug 2) and the event goes on with what it has | Same; **the XML reader gets a raw-bytes, string-mode reading**, compared like the rest |
| **System:** Provider (Name → providerName, Guid → providerGuid, EventSourceName → eventSourceName), TimeCreated SystemTime → systemTime, Execution ProcessID / ThreadID → processID / threadID, Channel → channel (and userID when the first attribute value is literally `UserID`), Security → securityUserID (same rule), Level and Keywords (kept for the severity), Correlation skipped, any other element with content → its name with the first letter lower-cased | Same, the quirks kept |
| **EventData:** `<Data Name="x">v</Data>` → `x` (first letter lower-cased); `categoryId`, `subcategoryId` and `auditPolicyChanges` remembered (the last stored as `auditPolicyChangesId`); `(NULL)` and `-` skipped; other attributes logged at debug 2 and stored under their value; unnamed `<Data>` values joined with `, ` into `data` (at most 65,535 bytes); other elements stored by name. Values: trailing white space removed | Same |
| **Other sections** (e.g. UserData): "Unexpected element (...). Decoding it." at debug; their child elements stored under the section's name | Same |
| **Severity:** Level 1 CRITICAL, 2 ERROR, 3 WARNING, 4 INFORMATION, 5 VERBOSE, 0 with keyword bit audit failure / audit success, else UNKNOWN (only when both Level and Keywords exist) → severityValue; then category and subcategory names from `%%` ids (the 9 audit categories and their 56 subcategories) | Same table |
| **Audit policy changes:** up to 4 `%%` ids → "Success removed" / "Success added" / "Failure removed" / "Failure added", joined with `, ` → auditPolicyChanges | Same |
| `Message` (JSON-unescaped, trailing white space removed) → system.message; the result `{"win":{"system":{..},"eventdata":{..},<other>:{..}}}` replaces the log and goes through the JSON decoder | Same |

### 2.24 File integrity events (`internal/syscheck.rs`)

| Feature | New |
|---|---|
| The FIM decoder (its name and id change per event: integrity_changed / new_entry / deleted, and the registry key / value variants); the 51 field names; the global options `syscheck_alert_new`, `syscheck_auto_ignore`, `syscheck_ignore_time`, `syscheck_ignore_frequency`; the end-of-first-scan time per agent (read once from provigil-db) | Same |
| **Control messages** (no space in the log): `fim-db-start-first-scan`, `fim-db-end-first-scan`, `fim-db-start-scan`, `fim-db-end-scan`, `syscheck-db-completed` → `syscheck scan_info_update first_start/first_end/start_scan/end_scan <time>` (the end ones need a start time; the first start also sends `syscheck control <time>`, the first end `syscheck cleandb`); the end time is remembered (+2 the first time); anything else "(1277): Invalid syscheck message received." | Same queries and texts |
| **Legacy checksum messages** (`<sum>[!<extra>] <file>[\n<diff>]`): the path normalised; `syscheck load <file>`; the saved and new sums decoded and compared (the attributes and Windows permissions adjust the new sum); equal → `syscheck updatedate`; deleted → `syscheck delete` (nothing saved before: no alert); new/modified → `syscheck save <file or registry> <sum escaped>!<changes>:<time>:<symbolic path> <file>`; auto-ignore after `ignore_frequency` changes within `ignore_time`; an added file alerts only after the first scan ended and with `alert_new`; a silent sum: no alert; an undecodable sum warns "at fim_db_search: Agent ... Couldn't decode fim sum ..." | Same |
| **The legacy alert text:** `File '<file>' was deleted./was added./checksum changed.` + symbolic path + one line per change: size, permissions (Unix mode text, or "Permissions changed." for Windows lists), ownership (with names), group ownership, md5, sha1, sha256 (or only the new one), attributes, modification time (ctime, or Unknown), inode; each line at most 255 bytes, attributes 1,023; the changed-fields list (comma-joined, a trailing comma); no change: no alert | Same texts and limits |
| **JSON events** (3.11 and later; log starting with `{`): `type` and `data` required ("Malformed FIM JSON event" / "Invalid FIM event"); `scan_start` / `scan_end` → `scan_info_update start_scan/end_scan <timestamp>` (query too long: an error) | Same |
| `event` data: path, mode, type, tags, content_changes, arch, value_name, index, changed_attributes, hard_links, attributes, old_attributes, audit, version; the entry type from `attributes.type` (file, registry, registry_key, registry_value; a registry entry of version 3+ needs `index`); event type added / modified / deleted chooses the decoder | Same |
| Attributes → fields (size, inode, mtime as numbers; perm, user_name, group_name, uid, gid, hash_md5/sha1/sha256, attributes, symlink_path, value_type, inode as text; a `perm` object converted to the old `<name> (allowed): PERMS, <name> (denied): ...` text) for the new and the old state; audit fields | Same |
| **The JSON alert text:** `File/Registry Key/Registry Value '<path>' <event type>`, hard links, `Mode:`, changed attributes, then the change lines; long paths shortened to 756 bytes with ` [...] ` and the last 30 bytes; registry paths with the architecture and value name (`Unknown key:Unknown Value` when missing) | Same |
| After the alert: added / modified events are saved (`syscheck save2 <event without mode, type, tags, content_changes, changed_attributes, hard_links, old_attributes, audit>`), deleted ones removed (`syscheck delete <path or index>`); database errors "FIM decoder: Cannot communicate with database." / "Cannot get response from database." / "Bad response from database: ..." ("Agent not found" ignored); "Can't generate fim alert for event: ..." | Same |

### 2.25 File integrity helpers (`internal/syscheck_op.rs`)

| Feature | New |
|---|---|
| **Checksum decoding** `size:perm:uid:gid:md5:sha1[:uname:gname:mtime:inode[:sha256[:attrs]]]`: `-1` = deleted; a perm starting with `\|` is a Windows permission list; numeric attributes turned into the Windows attribute names; a leading `+` = silent; the whodata part (14 fields), tag and symbolic path | Same |
| **Extra data** `!changes:date[:symbolic path]` | Same |
| Filling the event from a decoded sum (perm printed `%06o`) | Same |
| **Windows attributes:** the 19 names joined with ", " | Same names and order |
| **Windows permissions:** `\|account,type,mask` → "account (allowed\|denied): PERM\|PERM..." (20,480-byte buffer) | Same text and limit |
| Unix permission text (rwx with the s/t bits); field escape/unescape; path normalising; the C `strtol`-style number reading | Same |

### 2.26 Smaller internal decoders and the database workers (`internal/upgrade.rs`, `hostinfo.rs`, `ciscat.rs`, `rootcheck.rs`, `dbsync.rs`, `db_worker.rs`)

| Feature | New |
|---|---|
| **Upgrade** (`u` queue): the JSON gets `"agents":[<agent id as a number>]` added to `parameters` (an object gets the key; an array gets the list appended; a scalar: nothing), sent compact (up to a zero byte) to `queue/tasks/upgrade`; errors "Could not parse upgrade message: ...", "Could not get parameters from upgrade message: ...", "Could not connect to upgrade module socket at '...'. Error: ..."; never alerts | Same |
| **Host information:** `Host: <ip>[ ...],<ports>` compared with the lines of `queue/fts/hostinfo` (read in 65,534-byte pieces, `#` and empty lines skipped; a line starting with the IP whose rest equals the ports: drop); otherwise `<ip><ports>` appended and the event decoded as hostinfo with the id of `hostinfo_modified` (the IP was seen) or `hostinfo_new`; a bad log or file: "Error handling host information database." (counted; more than 30: "Too many errors handling host information db. Ignoring it." and no more); the file created at start (1103 on failure) | Same file and format |
| **CIS-CAT:** the location must be `wodle_cis-cat` (or `(...)...->wodle_cis-cat`; else the three "Invalid received event" debug texts); JSON (else "Error parsing JSON event." + "Input JSON: '...'"); `type` a string (else debug); `scan_info` → `agent <id> ciscat save <scan_id>\|timestamp\|benchmark\|profile\|pass\|fail\|error\|notchecked\|unknown\|<score as strtoul→int>` (missing → `NULL`; numbers by their int value), the event goes on only when the answer starts with `ok`; other types go on | Same query text |
| **Rootcheck:** `agent <id> rootcheck save <event seconds> <log>` (cut to 6,143 bytes); errors "Bad load query: '...'." (code -2) and "Rootcheck decoder unexpected result: ''"; debug "Rootcheck decoder response: '...'"; an answer whose number after the first unescaped space is 2 (new entry) marks the FTS check done; fields `title` (rk_get_title: up to ` {`, after `System Audit: ` when before ` - `, up to the first `. `, the quoted file name removed) and `file` (after `File: ` up to `. ` or a final `.`, or the quoted name after `File '` / `file '`) | Same, the title/file rules kept with their tests |
| **Database sync** (`5` queue): JSON with `component` (one of 18 valid: the 13 syscollector tables, syscheck, fim_file, fim_registry, fim_registry_key, fim_registry_value) and `type` (`integrity_check_*`, `state`, `integrity_clear`) and `data`; queries `agent <id> <component> <type> <data>`, `... save2 <data>`, `... integrity_clear <data>`; a non-empty `ok` answer to a check goes back as `<component> dbsync <answer> <data without tail and checksum>`: to the agent through the active response queue (`(msg_to_agent) [] N!S <agent> ...`), or for agent 000 to the local syscheck socket (syscheck, fim_file) or provigil-modules socket (syscollector); every error text kept ("dbsync: Cannot parse JSON", "Corrupt message: cannot get component/type/data member.", "Invalid component specified.", "Wrong message type ...", "query is too long", "Cannot communicate with database.", "Cannot get response from database.", "Bad response from database: ..." except "Agent not found", "unknown location", "cannot connect to ...") ; never alerts | Same |
| **Database workers** (own ProVigil design, kept): FIM, syscollector, SCA, rootcheck, CIS-CAT, dbsync and upgrade messages are decoded on worker threads (each with its own provigil-db connection; at most 256 in flight); an agent always goes to the same worker (hash of its id) so its messages keep their order; the analysis thread matches the rules on the decoded event; inline when no worker runs (tools, tests) | Same, with its order test |

### 2.27 Inventory events (`internal/syscollector.rs`)

| Feature | New |
|---|---|
| Location must be `syscollector` (or `(...)...->syscollector`; three "Invalid received event" debug texts); JSON (else "Error parsing JSON event." + "Input JSON: '..."); `type` string (else "Invalid message. Type not found."); `type` field filled; unknown type: "Invalid message type: X." and stop; a failed decode: the debug text per type ("Unable to send ports / packages / hotfixes / hardware information to provigil-db.", "Unable to send osinfo message ...", netinfo as error, "(9201): Unable to send dbsync information ...") and stop | Same |
| **Query building:** `agent <id> <table> save <scan id>` then `\|`-joined values (`NULL` when missing; strings as is; numbers as `%d`, hardware MHz/RAM total/free as `%f`), cut to 6,143 bytes; answers OK when the first word is `ok`; each value also filled as a dynamic field | Same |
| **port / port_end:** ID must be a number; fields protocol, local_ip, local_port (any member, its int value), remote_ip, remote_port, tx_queue, rx_queue, inode, state, PID, process → `port.*`; `port_end` → `port del <id>`; a failed scan's later messages with the same ID are skipped (per table: ports, packages, processes) | Same |
| **program / program_end:** format, name, priority, group→section, size, vendor, install_time, version, architecture, multi-arch→multiarch, source, description, location → `program.*`, then the SHA-1 hex of name+version+architecture; `package del <id>` | Same |
| **process / process_end:** pid, name, state, ppid, utime, stime, cmd, argvs (comma-joined in the query; the JSON array printed formatted as `process.args`), euser, ruser, suser, egroup, rgroup, sgroup, fgroup, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp, tgid, tty, processor; `process del <id>` | Same |
| **hotfix / hotfix_end:** `hotfix save <id>\|<time>\|<hotfix>\|` (1,023 bytes) and field `hotfix`; `hotfix del <id>` | Same |
| **hardware / OS** (`inventory` object, else nothing): hardware board_serial→serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage; `osinfo set` with hostname, architecture, os_name→name, os_version→version, codename, major, minor, build, platform, sysname, release, version→release_version, os_release, os_patch→patch, os_display_version→display_version | Same order (it is the query order) |
| **network / network_end:** `netinfo save` (name, adapter, type, state, MTU, MAC, tx/rx packets, bytes, errors, dropped → `netinfo.iface.*`); per IPv4 / IPv6: `netproto save` (iface name, 0/1, gateway, dhcp, metric → `netinfo.iface.ipv4/ipv6.*`); per address `netaddr save` (netmask / broadcast by index; IPv4 needs strings, IPv6 any member); the joined address / netmask / broadcast lists filled as JSON arrays; `network_end` needs the ID ("at decode_netinfo(): unknown type found." / "missing scan ID.") → `netinfo del` | Same |
| **dbsync_<table>** (needs an agent id): the 13 tables (hotfixes, packages, processes, ports, network_iface, network_protocol, network_address, hwinfo, osinfo, users, groups, browser_extensions, services) with their field maps to `hotfix`, `program.*`, `process.*`, `port.*`, `netinfo.iface/proto/addr.*`, `hardware.*`, `os.*`, `user.*`, `group.*`, `browser_extension.*`, `service.*` (the field lists kept entry by entry); errors 1283 (no table), 1287 (unknown table), 1284 (operation / data); network_address `proto` number → `ipv4`/`ipv6`; query `agent <id> dbsync <table> <operation> <data>`; the fields (strings, whole numbers as `%d`, others `%f`, missing as empty) and `operation_type`; answers 1286 (err, debug), 1285 (not `ok `), 1288 (no answer) | Same tables and texts |

### 2.28 Configuration assessment events (`internal/sca.rs`)

| Feature | New |
|---|---|
| JSON (else "Malformed configuration assessment JSON event." and the event still goes on); `type` string (else stop): `check`, `summary`, `policies`, `dump_end`, others ignored; all go on to the rules | Same |
| Queries `agent <id> sca <what> <arg>` (cut to 65,534 bytes); find answers `ok found <payload>` / `ok not found` / other = error ("Error querying policy monitoring database for agent '...'") | Same |
| **check:** required id (number), policy, policy_id, check.id (number), check.title (strings); optional strings description, rationale, remediation, references, file, condition, directory, process, registry, command, reason (each "Malformed JSON: field 'x' must be a string." — `references` says 'reference', `condition` has no final dot); a missing result becomes "not applicable"; `query <check id>`: found → `update <id>\|<result>\|<reason>\|<scan id>`, not found → `insert <whole event>` then `insert_compliance <id>\|<key>\|<value>` per compliance entry (numbers `%d` or `%lf`) and `insert_rules <id>\|<type>\|<rule>` per rule (first letter f/d/r/c/p/n → file/directory/registry/command/process/numeric, else "Invalid type: x"); fields filled only when the result changed | Same |
| **check fields:** sca.type=check, sca.scan_id, sca.policy, sca.check.id, title, description, rationale, remediation, sca.check.compliance.<key> (non string/number: warning), references, file / directory / registry / process / command (comma lists as JSON arrays), result, reason, previous_result (on update) | Same |
| **summary:** policy_id (string), scan_id (number, not negative), start_time, end_time, passed, failed, invalid, total_checks, score, hash, hash_file, file, name ('policy' in the texts) required; `query_scan`: not found → `insert_scan_info`, found → `update_scan_info_start` (their own argument orders); hash differs from the stored first word → fields filled (not on first scan; on a new first scan a dump request instead); `force_alert` fills anyway; `query_policy`: not found → `insert_policy` (description / references or NULL); found → `query_policy_sha256`, a changed file hash deletes the policy and checks, requests a dump and logs "Policy '...' information for agent '...' is outdated. Requested latest scan results."; `query_results` differs from hash or not found → dump request (first_scan flag) | Same |
| **summary fields:** sca.type=summary, scan_id, policy, description, policy_id, passed, failed, invalid, total_checks, score (a negative one stops the rest), file | Same |
| **policies:** `query_policies` comma list; each stored policy not in the event: `delete_policy` + `delete_check` ("Unable to purge DB content for policy '...'") | Same |
| **dump_end:** elements_sent, policy_id (string), scan_id required; `delete_check_distinct <policy>\|<scan>`; results hash differs from the scan hash → dump request | Same |
| **Dump requests:** queue of 1,023 ("SCA request queue is full."); `<agent>:sca-dump:<policy>:<first scan>` sent after each message: agent 000 → `queue/alerts/cfgaq` (without the agent part), others → `queue/alerts/cfgarq` | Same |

### 2.29 Reading the main configuration (`daemon_config.rs`, and the readers it uses from siem-config)

| Feature | New |
|---|---|
| **Internal options** (`etc/local_internal_options.conf` first, then `etc/internal_options.conf`; lines read in 1,023-byte pieces; `#`, space and empty lines skipped; `group.name = value`, spaces around trimmed, CR/LF removed; not found "(2301): Definition not found for: 'g.n'.", not all digits or out of range "(2302): Invalid definition for g.n: 'v'."; "(1119): Invalid line on file ..." for lines without `.` or `=`): analysisd's 24 options with their ranges (debug 0–2, decoder_order_size 32–1024, log_fw, label_cache_maxage 0–60, show_hidden_labels, min_rotate_interval 10–86400, default_timeframe 60–3600, fts_list_size 12–512, fts_min_size_for_str 6–128, rule_matching_threads 0–32, stats_maxdiff / mindiff 10–999999, stats_percent_diff 5–9999, rlimit_nofile 1024–1048576, state_interval 0–86400, event_threads, geoip_jsonout, the 8 decoder thread counts 0–32) and the 15 queue sizes 128–2,000,000 | Same names, ranges and texts |
| **Section dispatch** of `<ossec_config>` blocks (several blocks allowed; any other root element: "(1230): Invalid element in the configuration: 'x'." and "(1202): Configuration error at '<file>'."): every known section name is accepted (also the ones other services read) so that the file never fails because of them; `database_output` warns as deprecated; `logging` ignored; some names count only with child elements (as before); a reader error logs its text then 1202 | Same list of names and the same "needs children" rule |
| **Reading order:** active responses and commands first (writing `etc/shared/ar.conf`: the six legacy restart lines kept for older agents, then one line per response `<name><timeout> - <executable> - <timeout>`; 1103 when it can't be written), then global + ruleset + alerts + cluster + socket, then labels, then rule_test | Same order and file |
| **Defaults:** stats 4, integrity 8, rootcheck 8, hostinfo 8, jsonout yes, alerts_log yes, memory 8192 (at least 2048), email off (-1), alert new files yes, ignore frequency 10, ignore time 3600, mail level 7, log level 1, label cache 10, cluster hidden; the alert levels from `<alerts>` replace mail/log level; checks "Rotate interval setting must be between N seconds and one day." and "Maximum output size must be between 1 MiB and 1 TiB."; no `<ruleset>` decoders or rules → the default lists | Same |
| **`<global>`** (any unknown child: 1230; empty content: "(1234): Invalid NULL content for element: x."; bad value: "(1235): Invalid value for element 'x': v."): custom_alert_output, forward_to (comma list trimmed), email_notification, prelude_output / profile / log_level, geoipdb, zeromq_output / uri / server_cert / client_cert, jsonout_output, alerts_log, logall, logall_json, update_check, compress_alerts (ignored), integrity_checking, rootkit_detection, host_information, stats, memory_size, limits/eps (maximum ≤ 100,000, timeframe 1–3600, default 10), white_list (IPv4 form → IP list with "(1237): Invalid ip address", else a host pattern; "(1450)" on a bad pattern), email_to (address check), email_from / reply_to / idsname / smtp_server / helo_server / maxperhour (1–1,000,000) / log_source, geoip_db_path, geoip6_db_path, rotate_interval (number with d/h/m/s), max_output_size (G/M/K/B), queue_size ("Invalid value for option '<queue_size>'"), agents_disconnection_time (≥1, w/d/h/m/s), agents_disconnection_alert_time (≥0), cti-url (manager only, the default kept as the vulnerability feed address) | Same elements, units and texts |
| **`<syscheck>` options read by analysisd:** auto_ignore yes/no with `frequency` (1–99) and `timeframe` (0–43,200) (the values read from attribute positions 0 and 1, as before), alert_new_files, ignore (list); unknown attribute "(1233): Invalid attribute 'a' in the configuration: 'auto_ignore'." | Same, the position quirk kept |
| **`<cluster>`:** name / node_name (not empty; only the allowed characters, the list shown in the text), node_type (master, worker, client), disabled yes/no (yes hides the cluster information), hidden yes/no, interval (deprecated warning), key, socket_timeout, connection_timeout, nodes, port, bind_addr accepted; `haproxy_helper` children checked (the "missing" checks look at the parent's content, as before); unknown: 1230 | Same texts |
| **`<socket>`** (forwarding targets): name (not `agent`), location, mode udp/tcp ("Socket type 'x' is not valid at <mode>. Should be 'udp' or 'tcp'."), prefix (backslash escapes removed); "(1954): Missing field 'name' for socket.", "(1955): Missing field 'location' for socket." | Same |
| **`<labels>`:** `<label key=".." hidden="yes/no">value</label>`; keys starting with `_` warn and are skipped; empty key / no key / bad hidden texts; empty value warns; a later label with the same key replaces it; any error clears the list. Agent labels from provigil-db: `"key"`, `!"key"` (hidden), `#"key"` (system) | Same |
| **`<command>`:** name (not starting with `!`), executable, timeout_allowed yes/no, extra_args, expect (deprecated note); "(1280): Missing command options. ..." | Same |
| **`<active-response>`:** command, location, agent_id, rules_id, rules_group, level 0–20, timeout, disabled (turns all responses off), repeated_offenders, ca_store; missing command/location "(1281)" (not with repeated_offenders); location words AS/analysisd/analysis-server/server → manager, local → the agent, defined-agent → a given agent ("(1304)", id 0 skipped with "(1306)"), all/any → all agents; "(1302): Invalid active response location", "(1303): Invalid command"; timeout dropped with "(1305)" when the command does not allow it; remote / local flags | Same, the same pattern matching on location |
| **`<rule_test>`:** enabled yes/no, threads (number 0–65,534 or `auto` = CPU count; above 128: "(7000)" and 128), max_sessions (above 500: "(7001)" and 500), session_timeout (time units; above one year: "(7002)"); defaults 1 thread, 64 sessions, 900 s | Same |
| **Time and day checks** for rules: `<time>` (`[!]h[:mm][am\|pm] - h[:mm][am\|pm]`, reversed ranges become negated, stored as `.HH:MMHH:MM` / `!...`), compared on the first 5 characters; `<weekday>` (sunday…saturday, 3-letter forms, weekdays, weekends; comma or space separated; a leading `!` makes it fail, as before) | Same, the quirk kept |
| Number and time reading as before: `atoi`/`strtol` (clamped), time units w/d/h/m/s | Same |

### 2.30 XML variables and raw reading

| Feature | New |
|---|---|
| **Variables** in decoder and rule files: `<var name="X">value</var>` defines `$X` (name compared without case, under 256 bytes); later element and attribute contents of more than 2 bytes get `$X` replaced (a name ends at `$`, `.`, `\|`, `,`, space or the end; `$(` left alone); errors "XMLERR: Invalid variable content.", "Invalid variable name size.", "Only \"name\" is allowed as an attribute for a variable.", "No value set for variable.", "Unknown variable: '<first 95>'.", "Invalid variable name size: 'N'." with the line | Added to the ProVigil XML reader, compared with the old one on generated files |
| **Raw bytes:** reading a string up to its first zero byte, and child lists with their bytes as stored (no text conversion), used by the Windows event decoder | Added to the ProVigil XML reader, compared the same way |

## 3. Decisions

- **A-8 Console line ends.** On Windows the old service ended each console line with `

` (its own CR plus the text-mode conversion). The new one ends them with `
`, as the log file always did; siem-api's rule check reads them line by line either way.
- **A-7 Order of database-decoded events.** Messages that wait on provigil-db are decoded on 4 worker threads, each agent always on the same one, and the rules take each result when it is ready. Both programs work this way, so the order between agents, and against the other events, depends on provigil-db's answer times in both. What is fixed, and compared, is each agent's own order and every event's content.
- **A-6 Log format.** The service log is plain lines only, as for execd (E-6 of `provigil-execd.md`): the shipped settings use plain, and siem-api reads plain lines. The log writer no longer reads the settings file itself, so an unreadable settings file now also logs "(1202): Configuration error" (siem-api's rule check treats both as a failure).
- **A-5 No chroot.** The new service keeps absolute paths under the home folder, so it switches user and group (when started as root) without changing its root folder. siem-api runs it as its own user, where the old chroot was never possible anyway.
- **A-4 What moves where.** The old crate used two shared helper crates for its configuration and XML. The new crate reads its own configuration (section 2.29, only the sections it uses, but it accepts every section name) and uses the ProVigil XML reader (provigil-daemon), which gets variables and raw reading (2.30). Reason: siem-api no longer uses the old helpers, so analysisd was their last user on the manager.
- **A-3 Names kept for compatibility.** The six legacy restart lines in `ar.conf`, the agent-facing module names and the default vulnerability feed address stay as they are: agents and feeds use them as protocol values. They are values, not copied code.
- **A-2 Default cluster name.** When cluster information is shown and no cluster name is set, the alert's `cluster.name` is `provigil` (the old code used the upstream product name). The default setting hides cluster information.
- **A-1 Context search, different agent.** The original loops for ever on an event of another agent in the event-list search; the port skips that event, and the new code keeps the skip.

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

- 2026-11-13: module map, method, plan; features of start-up, daemon, settings, input queues, the event, the decoders, the rule loader, the matcher, the event stage, the text formats, the alert JSON, active responses, the syscheck JSON, the plugin decoders, lists, file selection, logtest, messages, MITRE, limits, labels, time, statistics, the analysis socket, getconfig, the Windows decoder, file integrity and its helpers, upgrade, host information, CIS-CAT, rootcheck, database sync, the database workers, inventory, configuration assessment, the configuration readers and XML variables written. Feature list complete.
- 2026-11-13: the ProVigil XML reader got variables, raw text reading and the `var` attribute rule (compared with the old reader). New crate `crates/provigil-analysisd` started: the settings reader (2.29) is written and compared on 6,000 generated files plus the shipped settings (values, warnings, notes, errors and `ar.conf` identical).
- Build order from here, each step compared with the old crate before the next: the event and message cleaning; decoders, plugin decoders and lists; the rule loader and matcher; the alert JSON, text formats, active responses and the syscheck JSON; the internal decoders; statistics, socket, getconfig, logtest, MITRE, limits, labels, time; the daemon and input queues. Then the end-to-end proofs (section 0) and the switch.
- 2026-11-13: written and compared with the old crate: the event and message cleaning (300,000 generated messages), decoders and plugin decoders (shipped decoders, 2,055 ruleset test logs in 4 locations and changed forms, 4,000 generated decoder sets), lists (generated lists, every lookup, `.cdb` bytes), the rule loader (shipped rules with active responses, 3,000 generated rule sets), the matcher and rule stage (61,650 events through the shipped ruleset: 35,944 alerts, 211 with context logs, every outcome and the engine state identical). Then the alert JSON (35,944 alerts byte-identical, with MITRE, labels, groups and compliance), the file integrity JSON (200,000 generated field sets), the text outputs (alerts.log, custom format, archives, firewall), and active responses (over 10,000 messages for every location and agent version kind). Then all built-in decoders: inventory, configuration assessment, rootcheck, CIS-CAT, host information, database sync and upgrade (60,000 generated messages), file integrity (checksum and JSON events) and Windows events (60,000 generated events, 200,000 checksum helper inputs), the built-in decoder entries, and the file integrity parts of alerts.log and the alert JSON. Then logtest (1,500 generated requests identical), EPS limits, statistics (state file, getstats, getagentsstats on random counter sequences), getconfig (every section on 6,000 generated settings and the shipped ruleset) and the analysis socket. Next: the daemon (input queues, writers, file rotation, labels cache, timers, hot reload) and the program.
- 2026-11-13: the daemon and the program written (`src/daemon.rs`, `src/bin/provigil-analysisd.rs`). Compared end to end with the old program: `-t` on the shipped home at every debug level (8,450 rule lines identical), 15 broken rule files, 6 broken decoder files and 5 settings cases (identical output and exit codes, except A-6). A live side-by-side run with provigil-db in each home: 21,155 messages (the ruleset test logs from the manager, agents and syslog, plus file integrity, Windows, rootcheck, host information, inventory, assessment, sync, upgrade and CIS-CAT messages, and malformed ones) gave identical alerts.json (12,070 event alerts), alerts.log, archives.json, firewall.log, state file, file tree and log lines; database-decoded events identical per agent (A-7). The analysis socket (21 requests: statistics, agent statistics, every getconfig section, errors, reload) and logtest (with the MITRE table) answered identically. siem-api's engine test now runs the new crate; the old crate no longer builds the program, so siem-api installs the new one at its next start.
- 2026-11-13: after the switch, verified live: 19,788 real events of agent 8084 (exported from ClickHouse, Windows events rebuilt to the agent's XML and checked to decode to the stored JSON byte for byte) through the old and new engines: identical output, and the same 493 alerts per rule as the live system raised in that window. Then the daemon was read line by line against the old one; four differences fixed: a duplicated agent label key is kept twice and label text that is not UTF-8 is replaced (as the old reader did), the active-agents list keeps the last id across pages, and logtest no longer gets the service's rule-id table (the old one never did).
- 2026-11-13: line-by-line reading continued: the event stage, the matcher, the rule loader and the decoder loader and decoding read against the old code with no difference in behaviour (overwrite fields, if_sid parsing quirks, decoder group skipping, carried match positions all kept). Elements without text (nested or empty) were tried in both programs for rules and decoders: same results. Console line ends: A-8.
