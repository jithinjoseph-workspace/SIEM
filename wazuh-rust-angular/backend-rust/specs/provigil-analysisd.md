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

## 3. Decisions

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

- 2026-11-13: module map, method, plan; features of start-up, daemon, settings, input queues, the event, the decoders, the rule loader, the matcher, the event stage, the text formats and the alert JSON written.
