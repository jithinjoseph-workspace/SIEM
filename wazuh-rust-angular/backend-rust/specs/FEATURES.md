# Features to keep

Every feature of a replaced crate is written here before the crate is deleted, with where it
lives now. The new code gives the same features with ProVigil's own design and code. A
feature is only dropped on purpose, with the reason written down.

Status: **kept** (works in the new code), **moved** (lives in another part, named), **to build**
(missing now, must be built), **dropped** (on purpose, reason given).

## siem-cdb: threat indicator lists (replaced 2026-11-03)

| Feature | Status |
|---|---|
| IP lists with exact addresses and ranges (CIDR) | kept: new siem-cdb |
| File hash lists (MD5, SHA-1, SHA-256), any letter case | kept |
| Domain lists, subdomains match their parent | kept; also takes a URL and checks its host |
| Add an entry with a description; count a list's entries | kept |
| Built-in starter indicators | dropped: they were demo values (e.g. the MD5 of "123456"), not real threats; the live feeds (botnet C2, malicious URLs) fill the lists hourly |
| Load a list from a text file (`value:description` per line) | kept: `load_from_text`; API `POST /api/v1/threat-intel/lists/:name/import` (platform admin) |
| List every entry of a list | kept: `entries`; API `GET /api/v1/threat-intel/lists/:name/entries` |

## siem-reportd: alert reports (deleted 2026-11-03)

| Feature | Status |
|---|---|
| Report of alert totals and the top rules | moved: PDF reports (`tenant_reports.rs`), `/api/v1/reports/summary` |
| Filter a report by rule group, rule, level, location, source IP, user, file name | kept: PDF report filters (`/api/v1/reports/pdf`, Settings → PDF Reports), plus agent |
| "Related" breakdown of one field against another (e.g. source IP by user) | kept: breakdown table in the PDF report (`by=srcip,user`) |
| Report title | kept: `title` |
| Up to 100 sample alerts in the report | kept: `samples=1` |
| The command-line report tool | for now in siem-maild (`provigil-reportd`); goes in step 3 |

## siem-rootcheck: rootkit checks (deleted 2026-11-03)

The scan itself runs on the agent; the server copy only served the old prototype agents.
All of these must be in the new agent (step 4).

| Feature | Status |
|---|---|
| Known rootkit files and folders, by path | moved: agent (step 4); our own signature list |
| Trojaned system programs (suspicious strings in binaries) | moved: agent (step 4) |
| Odd files in `/dev` (hidden or plain files) | moved: agent (step 4, Linux) |
| Hidden listening ports (bound but not shown by the system) | moved: agent (step 4) |
| Hidden processes | moved: agent (step 4) |
| Network cards in sniffing (promiscuous) mode | moved: agent (step 4) |
| Turn each check on or off | moved: agent settings (step 4) |
| Start a scan from the console | kept: `/api/v1/agents/:id/rootcheck/scan` starts the agent's own scan |
| See an agent's findings | kept: `/api/v1/agents/:id/rootcheck` |
| List the signature database over the API | dropped: no page used it |

## siem-active-response: response programs on the agent (replaced 2026-11-03)

Our own EDR programs in this crate stay (they are ProVigil's work from October): isolate
host / release, kill process, quarantine file, YARA scan, live response, tamper protection
and the `edr`, `live`, `tamper`, `yara` modules. Replaced: the shared message handling and
the four programs that came from upstream.

| Feature | Status |
|---|---|
| Read the response request from the agent (one JSON line: version, origin, command `add` / `delete`, parameters with the alert and extra arguments) | kept: new code (`siem-active-response.md`) |
| Stateful responses: ask the agent whether this key is already active (continue / abort) before adding | kept: new code |
| Log every step to the agent's response log (`active-responses.log`, time and program name per line) | kept: new code |
| Find the attacker IP in the alert (Windows event IP fields first, then the source IP), IPv4 and IPv6 | kept: new code |
| Extra arguments from the request | kept: new code |
| Find a system program (absolute path, else on `PATH`) and run it, with or without its output | kept: new code |
| One run of the same response at a time (lock), taking over from a stuck holder | kept: new code |
| Block an IP in the Linux firewall (iptables / ip6tables, incoming and forwarded), and unblock it | kept: new code (`firewall-drop`) |
| Retry the firewall command up to 5 times with growing pauses when it fails | kept: added after the old-vs-new review (test: 5 tries, growing pauses) |
| Block an IP in the Windows firewall (in and out), unblock it, warn when a firewall profile is off | kept: new code (`netsh`); unblock also removes blocks made under the old rule name |
| Block an IP with a null route to the default gateway (Windows), and remove it | kept: new code (`route-null`) |
| Restart the agent (Windows service stop / start, Linux control script) | kept: new code (`restart-wazuh`; program name kept until the agent's own config replaces `ar.conf`, step 4) |
| Windows: every DLL loaded into a response program must be validly signed (Authenticode or a Windows catalog), both those loaded at start and any loaded later; warn by default, or stop the program in strict mode, or off | kept: our own `dll_guard` module, used first thing by all ten programs (they no longer include the agent's upstream file) |
| Windows: the log of a failed DLL check gives Windows' reason (error code and text) per method | kept: added after the old-vs-new review |
| Windows: skip the DLL checks when the machine cannot verify signatures at all (its trust store is missing the roots) | kept: new code (our own test: whether a Windows system DLL verifies) |
| Windows: programs started by a response run without a console window, and their arguments are passed as written | kept: new code |
| A bad request ends the program with an error exit code | kept: new code |
| Firewall blocking on FreeBSD / Solaris / AIX | dropped: no agent runs there; logged as not supported |

## siem-core: shared types (replaced 2026-11-03)

| Feature | Status |
|---|---|
| Alert, event, agent, rule and statistics types (the stored and displayed shapes) | kept: new siem-core, same JSON |
| Reading the old manager config file and the agent key file | moved: the two prototype agents (deleted later); the new agent (step 4) has its own config and enrollment |

## siem-engine: siem-api's own detection (replaced 2026-11-03)

siem-api checks the events that do not go through the manager (syslog devices, the old
prototype agents, cluster/forwarded events) with this engine; the console's Logtest page and
the rules list use it, and Red Swarm tests the rules it writes with it.

| Feature | Status |
|---|---|
| Built-in decoders: SSH logins (user, IP, port), file changes (path, action), registry changes, Windows events (channel, event id, user), configuration-check results, sudo commands, process starts (path, user); otherwise the first IPv4 in the line, decoder "generic-syslog" | kept: new code |
| Built-in detections (18: invalid SSH user, Windows failed logon, audit log cleared, service installed, shadow-copy deletion / certutil / bitsadmin download, autostart registry keys, failed config check, critical file changes, file changes, FIM scan start / end, permission / ownership changes, rootkit found, alternate data stream, encoded PowerShell / Mimikatz, sudo to a shell, ransomware extensions), each with id, level, groups and MITRE technique | kept: same ids, levels, groups and techniques |
| SSH brute force: 4 failed logins from one IP give a level-10 alert (rule 5712, T1110), then the count starts again | kept |
| Rules and decoders in the XML rule format (the same format the manager's rules use): parent rule, parent group, matched-before rule / group with frequency and timeframe, same source IP / same user, decoded-as, text match with `|` alternatives, regex, field conditions, no-alert rules, level, groups, MITRE ids, rule group names added to each rule; decoders with parent, program name, prematch, regex and field order | kept: our own reader |
| Load every XML rule and decoder file of a ruleset folder at start | kept |
| Rules deployed at run time (Red Swarm), seen at once by every copy of the engine | kept |
| The highest-level matching rule makes the alert; a level-0 match is not an alert | kept |
| List every active rule (built-in and XML) | kept |
| Logtest: split a syslog header (time, host, program), decode, match; result with fields and the matching rule, as data and as text | kept |
| Logtest on the command line | dropped: the console's Logtest page does it (`/api/v1/logtest`) |
| Red Swarm: read a rule written in XML and test it on a sample log | kept |
| The manager's built-in XML rules and decoders embedded in the engine (agent connect / disconnect, SSH groups…) | dropped: copied from upstream; the same detections come from the built-in list above and the ruleset folder |
| Response command building, output diffs, event header cleaning (unused library parts) | dropped from this crate: nothing used them; the manager's detection engine has them (step 5) |
| Add XML decoders at run time (`add_provigil_decoders_xml`) and XML rules on top of the folder (`add_provigil_rules_xml`) | dropped: nothing called them; run-time rules go through `set_custom_rules_xml` |

## siem-task-manager: agent upgrade tasks (moved to old-code/ 2026-11-03, step 3)

siem-api listed it as a dependency but never called it. The upgrade flow the console uses
(`/api/v1/agents/:id/upgrade`) goes through siem-modulesd's own task manager.

| Feature | Status |
|---|---|
| Upgrade task for agents (standard or custom package / URL) | moved: siem-modulesd (step 5) |
| Status of an agent's latest upgrade task; update its status from the agent | moved: siem-modulesd (step 5) |
| Result of an upgrade; cancel pending tasks of a node or agent | moved: siem-modulesd (step 5) |
| Tasks stuck too long marked timed out; old tasks cleaned up | moved: siem-modulesd (step 5) |

## Mail sender (step 3, item 2): what siem-api used from siem-maild (`smtp_ext.rs`, `smtp.rs`)

Used by alert e-mails (`alert_mail.rs`), report e-mails (`tenant_reports.rs`) and the SMTP
test (`mail_settings.rs`). The rest of siem-maild (its own alert e-mails, recipient rules,
local sendmail program, SMS format, daily reports) is item 5.

| Feature | Status |
|---|---|
| Account: server, port, security (`tls` = implicit TLS, `starttls`, `none` = plain relay), user, password; port 465 means TLS, 25 plain, others STARTTLS (chosen in `mail_settings.rs`) | done (`mail_send.rs`, `lettre` v0.11) |
| TLS: the server certificate is checked against trusted roots; a TLS or certificate failure is reported with the server's name | done (`mail_send.rs`, `native-tls`) |
| Login (AUTH) only when a user is set; a refused login reported with the server's reply | done (`mail_send.rs`, `lettre` Credentials) |
| Up to 300 seconds waiting for each server reply | done (`mail_send.rs`, timeout: 300s) |
| Server replies of several lines (EHLO capabilities) read in full | done (`lettre`) |
| Several recipients in one session; every recipient must be accepted, else an error naming the refused address | done (`mail_send.rs`) |
| Each failure names the step (connect, greeting, hello, login, sender, recipient, data, end of data) and includes the server's reply text | done (`lettre` error forwarding) |
| Message text with CRLF line ends and dot-stuffing (strict servers such as Gmail) | done (`lettre`) |
| Headers: `From: ProVigil <account>`, `To:` every recipient, `Date:` (local time), `Subject:`, `MIME-Version` | done (`mail_send.rs`, `build_message`) |
| Subject: line breaks and control characters removed (no header injection); non-ASCII encoded (RFC 2047) | done (`mail_send.rs`) |
| Body: UTF-8 text | done (`mail_send.rs`, MIME quoted-printable/utf-8) |
| One attachment (name, type, bytes) as a MIME part; quotes and line breaks in its name made safe | done (`mail_send.rs`, ContentDisposition) |
| "Send test e-mail": subject "ProVigil notification - test e-mail", fixed text | done (`mail_send::send_test`) |
| QUIT at the end | done (`lettre`) |
| EHLO name `notify.ossec.net` (or the configured hello name) | changed on purpose: the machine's own name (library default); the old name belonged to upstream |
| `etc/smtp_auth.conf` written for maild / monitord (host, port, security, user, password; mode 600) | kept for now in `provigil_manager.rs` (maild still reads it until item 5) |

## Syslog sender (step 3, item 3): what siem-api uses from siem-csyslogd

Used by SOAR syslog integration (`soar.rs`: `send_syslog`) and remote syslog forwarders.

| Feature / Public Function | Status |
|---|---|
| Syslog format Default: `<pri>timestamp host provigil: Alert Level: ...; Rule: ... - ...; Location: ...;` | done (`syslog_send.rs`, pure clean-room Rust) |
| Syslog format CEF: `<pri>timestamp CEF:0\|ProVigil\|ProVigil\|v1.0\|id\|comment\|level\|dvc=host cs1=...` | done (`syslog_send.rs`, ProVigil branding) |
| Syslog format JSON: `<pri>timestamp host provigil: {json}` | done (`syslog_send.rs`, serde_json) |
| Syslog format Splunk: `<pri>timestamp host provigil: crit=... id=... description="..." component="..."` | done (`syslog_send.rs`) |
| Alert filters: min level, rule_id list, group/category pattern, location pattern | done (`syslog_send.rs`) |
| DNS resolution with retries (`get_host`, `resolve_hostname`, `ip_of`) | done (`syslog_send.rs`, `ToSocketAddrs`) |
| UDP socket connection and sender with retry (`connect_udp`, `send_udp`) | done (`syslog_send.rs`, standard UdpSocket) |
| Hostname detection (short hostname vs FQDN for `use_fqdn`) | done (`syslog_send.rs`, `sysinfo`) |
| RFC 3164 / BSD syslog timestamp formatting (`Mmm dd hh:mm:ss`) | done (`syslog_send.rs`, chrono) |
| Direct JSON alert ingestion (`serde_json::Value` without `AlertData` or `siem_cjson`) | done (`syslog_send.rs`) |
| Legacy XML `<syslog_output>` config reader (`read_csyslog`, `read_syslog_conf`) | kept for legacy manager binary until step 5 |
| IPC control `csyscom_dispatch` (`getconfig csyslog`) | kept for legacy manager binary until step 5 |

## SOAR HTTP Integrations (step 3, item 4): what siem-api uses from siem-integratord

Used by SOAR actions (`soar.rs`: Slack, PagerDuty, Shuffle, VirusTotal, Maltiverse).

| Feature / Public Function | Status |
|---|---|
| Slack webhook formatting (color good/warning/danger by level, agent/location/rule fields, attachments) & HTTP POST | done (`soar_integrations.rs`, clean-room pure Rust reqwest) |
| PagerDuty Events v2 payload (`routing_key`, `event_action: trigger`, severity warning/info by level >= 7, source, custom_details) & HTTP POST to `https://events.pagerduty.com/v2/enqueue` | done (`soar_integrations.rs`) |
| Shuffle webhook payload (rule skip list check, severity 1/2/3 by level, pretext, title, all_fields) & HTTP POST | done (`soar_integrations.rs`) |
| VirusTotal hash lookup (syscheck MD5 validation, API query to `https://www.virustotal.com/vtapi/v2/file/report`, rate-limit 204 handling, positives/malicious analysis) | done (`soar_integrations.rs`) |
| Maltiverse threat intelligence lookup (private IP filter, URL validation, API query with Bearer token, ECS types mapping, confidence calculation) | done (`soar_integrations.rs`) |
| Elimination of temporary alert file writing and subprocess `.exe` execution | done (`soar_integrations.rs`, direct async in-process HTTP) |
| Legacy XML `<integration>` config reader (`read_integrator_conf`) | kept for legacy manager binary until step 5 |
| IPC control `intgcom_dispatch` (`getconfig integration`) | kept for legacy manager binary until step 5 |

## siem-monitord: manager housekeeping & agent monitoring (step 3, item 5)

Used for agent connectivity monitoring, disconnected alerts, and log rotation/retention.

| Feature / Public Function | Status |
|---|---|
| Agent disconnection check (`agents_disconnection`): marks agent disconnected after keepalive timeout `agents_disconnection_time` (default 600s) | done (`agent_monitor.rs` in `siem-api`) |
| Agent disconnected alert (`send_disconnection_msg`, rule 504): `1:provigil-monitord:ossec: Agent disconnected: '{name}-{ip}'.` | done (`agent_monitor.rs` in `siem-api`) |
| Disconnection alert delay (`agents_disconnection_alert_time`): delay before alerting to avoid flap | done (`agent_monitor.rs` in `siem-api`) |
| Old agent auto-deletion (`agents_deletion` / `delete_old_agents`): removes agents inactive beyond limit | done (`agent_monitor.rs` in `siem-api`) |
| Removed agent alert (`send_deletion_msg`, rule 505): `ossec: Agent removed: '{name}-{ip}'.` | done (`agent_monitor.rs` in `siem-api`) |
| Daily log rotation (`w_rotate_log`): archive log files into `logs/YYYY/Mon/ossec-DD.log` | done (`log_rotator.rs` in `siem-api`) |
| Size-based log rotation (`size_rotate`): rotate when log file exceeds size limit | done (`log_rotator.rs` in `siem-api`) |
| Gzip compression of rotated logs (`os_compress_log`): gzip `.gz` and remove uncompressed | done (`log_rotator.rs` in `siem-api`, flate2) |
| Log retention cleanup (`remove_old_logs`): purge archives older than `keep_log_days` | done (`log_rotator.rs` in `siem-api`) |
| Cryptographic log integrity signing (`os_sign_log`): MD5 / SHA-1 / SHA-256 chained checksum files | done (`log_rotator.rs` in `siem-api`) |
| Daily email reports (`Read_CReports`, `manage_files`): midnight summary report generation | moved: PDF report generator & scheduler (`tenant_reports.rs`) |
| Monitord IPC control `moncom_dispatch` (`getconfig monitord`) | dropped: legacy socket IPC replaced by `siem-api` REST endpoints |

## siem-maild: alert e-mails & notifications (step 3, item 5)

Used for platform-wide alert mailing and digest batching.

| Feature / Public Function | Status |
|---|---|
| SMTP connection with TLS / STARTTLS / Plain and credentials | done (`mail_send.rs` via `lettre`) |
| Test email delivery (`send_test`) | done (`mail_send.rs`) |
| Per-tenant email alert routing and configuration | done (`alert_mail.rs`, `mail_settings.rs`) |
| Alert formatting (Full format: header, rule, level, fields, raw alert) | done (`alert_mail.rs`, `mail_send.rs`) |
| Alert formatting (SMS format: short subject and description) | done (`mail_send.rs`) |
| Hourly rate limit (`maxperhour`, default 12): suppress floods with logged warning | done (`alert_mail.rs` in `siem-api`) |
| Alert grouping & batching (`MailList`, `NEXTMAIL_TIMEOUT`, `DEFAULT_TIMEOUT`) | done (`alert_mail.rs` in `siem-api`) |
| Alert data transformation (`AlertData` extraction from JSON alert) | done (`soar.rs` internal struct, no upstream dependency) |
| Daily midnight reports e-mail | moved: PDF reports (`tenant_reports.rs`) |
| Legacy CLI tool `provigil-reportd` | dropped: web console PDF reports provide full filtering and export |
| Maild IPC control `mailcom_dispatch` (`getconfig mail`) | dropped: replaced by `siem-api` REST API (`/api/v1/mail/settings`) |

## The ProVigil Windows Agent (step 4): Replacing 9 upstream agent crates

Replaces:
1. `siem-winagent` (3,814 lines) — Windows Service management & component supervisor
2. `siem-agentd` (5,294 lines) — Network transport, encryption, heartbeat, offline buffer
3. `siem-logcollector` (10,312 lines) — Windows Event Channel & text log reader
4. `siem-syscheckd` (11,772 lines) — File Integrity Monitoring (FIM) & registry monitoring
5. `siem-syscollector` (4,579 lines) — Hardware, OS, network, port, process inventory
6. `siem-sysinfo` (4,998 lines) — Windows system metrics & bindings
7. `siem-sca` (3,210 lines) — Security Configuration Assessment (CIS benchmarks)
8. `siem-authd` (1,954 lines) — Agent registration & enrollment server
9. `siem-remoted` (6,554 lines) — Manager encrypted message receiver

| Feature / Capability | Old Ported Implementation | New ProVigil Agent (`provigil-agent`) | Status |
|---|---|---|---|
| **Windows Service** | `siem-winagent`: `service.rs`, `components.rs` | Native Windows Service using `windows-service` crate; start, stop, pause, restart | to build (`provigil-agent`) |
| **CLI Service Controls** | `/?`, `-h`, `install-service`, `uninstall-service`, `start` | `provigil-agent --service`, `--install`, `--uninstall`, `--run`, `--status` | to build (`provigil-agent`) |
| **Dynamic Configuration** | Static `ossec.conf` XML | Dynamic JSON/YAML config with ENV overrides; no hardcoding | to build (`provigil-agent`) |
| **Agent Enrollment** | `siem-authd` + `siem-agentd`: custom socket on 1515, `client.keys` | Secure HTTPS/TLS enrollment via `/api/v1/agents/enroll` with tenant key | to build (`provigil-agent`) |
| **Secure Transport** | `siem-remoted` + `siem-agentd`: Blowfish on raw UDP 1514 | Modern HTTPS / TLS streaming protocol; multiplexed bidirectional stream | to build (`provigil-agent`) |
| **Heartbeat & Keepalive** | `agentd` notify ping every 10s | Async keepalive ping with OS/resource telemetry every N seconds | to build (`provigil-agent`) |
| **Offline Leaky Buffer** | `agentd` in-memory leaky bucket | Resilient disk/memory ring buffer; zero drops during network outages | to build (`provigil-agent`) |
| **Windows Event Logs** | `siem-logcollector`: `eventchannel.rs` (`EvtSubscribe`) | Native Windows Event Log reader: Security, System, App, Sysmon, PowerShell | to build (`provigil-agent`) |
| **Bookmark Tracking** | `logcollector` bookmarks file | Event record ID & timestamp bookmark persistence across restarts | to build (`provigil-agent`) |
| **File Log Tailing** | `siem-logcollector`: `cfile.rs` | Asynchronous file watcher & log tailer for `.log` / `.txt` files | to build (`provigil-agent`) |
| **File Integrity (FIM)** | `siem-syscheckd`: periodic crawl + realtime | Realtime filesystem watcher + SHA-256 / MD5 stream hashing | to build (`provigil-agent`) |
| **Registry Monitoring** | `siem-syscheckd`: `registry.rs` | Windows Registry Run keys, Services & persistence monitoring | to build (`provigil-agent`) |
| **Hardware & OS Inventory** | `siem-syscollector`: CPU, RAM, disks, OS | Clean-room `sysinfo` collector: CPU, RAM, OS, disks, uptime | to build (`provigil-agent`) |
| **Network & Port Inventory** | `siem-syscollector`: interfaces, IPs, ports | System network interfaces, IPv4, IPv6, MAC, listening TCP/UDP sockets | to build (`provigil-agent`) |
| **Process & App Inventory** | `siem-syscollector`: processes, packages | Running process trees + installed software & hotfix registry scan | to build (`provigil-agent`) |
| **CIS Benchmark (SCA)** | `siem-sca`: YAML evaluation | Dynamic CIS Benchmark YAML rule scanner with pass/fail telemetry | to build (`provigil-agent`) |
| **EDR Host Isolation** | `siem-active-response/src/bin/isolate_host.rs` | ProVigil proprietary EDR isolation (Windows Filtering Platform) | kept (proprietary) |
| **EDR Process Killer** | `siem-active-response/src/bin/kill_process.rs` | ProVigil proprietary EDR process killer | kept (proprietary) |
| **EDR File Quarantine** | `siem-active-response/src/bin/quarantine_file.rs` | ProVigil proprietary encrypted file quarantine | kept (proprietary) |
| **EDR YARA Scanner** | `siem-active-response/src/bin/yara_scan.rs` | ProVigil proprietary in-memory and disk YARA scanner | kept (proprietary) |
| **EDR Live Shell** | `siem-active-response/src/bin/live_response.rs` | ProVigil proprietary authenticated live response command stream | kept (proprietary) |
| **Anti-Tamper & DLL Check** | `tamper_protect.rs`, `dll_guard.rs` | ProVigil proprietary anti-tamper service guard & signed DLL verify | kept (proprietary) |
| **Remote Upgrade** | `upgrade.rs` | Staging binary verification (SHA-256) & self-upgrade supervisor | to build (`provigil-agent`) |





## siem-agentd and siem-winagent: old-vs-new review (moved to old-code/ 2026-11-12)

Both were ports of the upstream agent (each file mirrors a C file). `siem-agentd` (5,294 lines)
was used only by `siem-winagent` (3,814 lines), which is not shipped: every PC runs
`provigil-agent`. `siem-winagent` also built a program named `provigil-agent`, so a full
workspace build could have replaced the shipped agent with the old one; moving it out ends that.
Each feature below was checked against `provigil-agent`; none is missing.

| Feature (old file) | Where it is now |
|---|---|
| Connect, start-up handshake, start / stop messages (`start_agent.rs`) | `lib.rs` sends "ProVigil agent started"; `transport.rs` `send_stopping` sends the last keepalive with status `stopping` |
| Several managers and failover (`start_agent.rs`, `config.rs`) | `transport.rs` `Failover` (max retries, retry interval, wraps to the first) and gRPC-to-HTTPS fallback |
| Enrollment and agent-name rules (`enrollment.rs`) | `identity.rs` (`clean_name`, HTTPS enrollment with the tenant or deployment key) |
| Keys, counters, message encryption (`keys.rs`, `sendmsg.rs`) | replaced by TLS with the private CA and the per-agent key (`transport.rs`) |
| Keepalive with the agent IP and the shared-configuration version (`notify.rs`) | `transport.rs` `keepalive_body` (agent IP, labels, group configuration version) |
| Anti-flooding buffer: normal / 90 % / full / flooded, events-per-second pacing (`buffer.rs`) | `buffer.rs` (same states, sent once per change, paced to `events_per_second`) |
| Labels (`config.rs`) | `config.rs` `labels`, sent with every keepalive and per log entry |
| `getconfig` / `getstate` requests (`agcom.rs`, `state.rs`) | `transport.rs` `query` (settings without keys; version, manager, transport, buffer, last keepalive, last scans, sent, dropped) |
| Requests from the manager with acknowledgement (`request.rs`, `receiver.rs`) | `commands.rs`; results kept and sent again until the manager has them |
| Shared files and remote configuration checked before use (`receiver.rs`, `reload.rs`) | group configuration as JSON; `config.rs` `overlay` refuses a bad one and keeps the running settings |
| Restart on new configuration (`reload.rs`) | `lib.rs`: new group settings restart the collection loops |
| Own log rotation (`rotate_log.rs`) | `main.rs`: size-based rotation keeping five files |
| Uninstall needs the manager's permission (`uninstall.rs`) | tamper protection (`tamper-protect.exe`, `siem-api/src/tamper.rs`): a locked agent cannot be stopped or removed |
| Signature check of loaded DLLs (`siem-winagent/dll_verify.rs`) | `siem_active_response::dll_guard::enable()` at agent start |
| Windows service, install / uninstall (`siem-winagent/service.rs`) | `service.rs`, `main.rs` (`--install`, `--uninstall`, `--service`, `--status`) |
| Agent upgrade (`siem-winagent/upgrade.rs`) | `upgrade.rs` (SHA-256 and signer checks, rollback) |
| Scheduled commands, osquery (`wm_command.rs`, `wm_osquery.rs`) | `config.rs` group scheduled commands (need `allow_remote_commands`), `osquery.rs` |
| Restart the connection on a timer (`force_reconnect_interval`) | not needed: the cluster plan moves agents by changing their home worker (`specs/provigil-cluster.md`, step C5) |
| IPv6 link-local interface check | not needed: managers are URLs |

## siem-authd and siem-shared (step 4, replaced 2026-11-12)

siem-api used three pieces; they are now its own code (`specs/siem-authd.md`). Old against new:

| Old (`siem-authd`) | New | Result |
|---|---|---|
| `groups::MAX_GROUPS_PER_MULTIGROUP` = 256 and its message | `groups.rs` `MAX_GROUPS` = 256, `group_count_ok` | same value and message (test `at_most_256_groups`) |
| `enrollment::add_agent_to_keystore` (ID given or next free; key given or random) | `agent_keys_store.rs` `new_agent_key` (ID always given, key always random) | same for siem-api's only call, which always gave the ID and never a key (test `new_agent_keys_are_random_and_stored`) |
| `enrollment::format_success_response` (`authd_response` in the enrollment answer) | dropped | no agent, script or gateway read it; the same values are in `agent_id`, `agent_name`, `agent_ip`, `raw_key` |

The rest of `siem-authd` served the old enrollment socket and is replaced by HTTPS enrollment:

| Old feature | Where it is now |
|---|---|
| Enrollment server on port 1515 with password (`server.rs`, `config.rs`) | provigil-gateway `POST /api/v1/agents/enroll` → siem-api, with the tenant key or a deployment token |
| Agent name rules (`is_valid_name`) | siem-api `valid_agent_name` (2–128 characters: letters, digits, `.`, `_`, `-`); provigil-agent `identity.rs` `clean_name` |
| Duplicate name and replacement rules (`can_replace_agent`, force options) | siem-api enrollment: the same name in a tenant keeps its ID; `force` re-enrolls; a removed agent cannot enroll itself again |
| Group checks: forbidden characters, `.`/`..`, repeats, limit (`groups.rs`) | siem-api `groups.rs` (`valid_group`, `resolve`, `MAX_GROUPS`); tokens refuse groups that do not exist |
| `client.keys` on disk (`server.rs`) | ClickHouse `ndr.agent_keys` (encrypted), `agent_keys_store.rs` |
| Agent certificate checks (`cert.rs`) | TLS with the private CA plus the per-agent key (provigil-gateway) |
| Local add / remove / get commands (`local_server.rs`) | console API (agents list, remove, enrollment) |
| `getconfig` request (`authcom.rs`) | not needed: no authd settings remain |
| Agent-side enrollment program (`bin/agent_auth.rs`) | provigil-agent `identity.rs` |
| Refusing agents newer than the manager (`compare_provigil_versions`) | not carried: ProVigil agents are upgraded from the console; versions are not compared with an upstream manager version |

`siem-shared` (3,214 lines) was used only by `siem-authd` and `siem-util`; moved with them.

## Unused agent crates (step 4, moved to old-code/ 2026-11-12)

Nothing in the workspace, the manager's daemon list or any script used these; their features are
in `provigil-agent` (table "The ProVigil Windows Agent" above): siem-syscheckd, siem-logcollector,
siem-remoted, siem-sysinfo, siem-dbsync, siem-syscollector, siem-agent, siem-sca, siem-util,
siem-shared-modules, siem-harvester (54,421 lines).

## siem-vulnerability-scanner (own rewrite: provigil-vulnscan)

Specification: `specs/vulnerability-scanner.md` (section numbers in brackets). Each line is one
feature the line-by-line review ticks off; the rewrite must keep the on-disk formats so existing
databases and queues are reused.

1. Started by provigil-modulesd only when a `<vulnerability-detection>` or `<vulnerability-detector>` section exists (2.1)
2. Host log lines: wdb socket init failure, "Created new thread" (2.1, 14.1)
3. Entry points: start, push event, stop, change feed interval (2.2)
4. Stop: stop flag for feed processing, event and delayed threads, scheduler join and its log line (2.2)
5. Module configuration fields from the host (2.3) and start options (2.4)
6. Start sequence order, including the defaults for enabled / index-status / feed-update-interval (2.5)
7. Start debug line with the configuration JSON in its fixed key order (2.5)
8. Start failure line with the trailing period (and double period quirk) (2.5, Q33)
9. Config reader: valid element names, invalid-element warning, nested objects, duplicate rules (3.1)
10. Deprecated section: only `enabled`, first value kept, deprecation warning (3.1)
11. Missing `cti-url` filled from the global section or the default URL (3.1)
12. Empty section leads to `Missing URL setting.` (3.1, Q1)
13. Internal options, ranges and silent defaults (3.2)
14. Time texts with s/m/h/d/w suffixes and invalid cases (3.3)
15. Validation checks in order with their exact texts (3.4)
16. Feed interval minimum 1 hour with the warning (3.4)
17. Updater parameters for online and offline modes (3.4)
18. Policy-change tracking in `queue/vd/state_track`: module, manager scan, cluster name/state/node (3.5)
19. Policy actions pushed: reboot, scanAgent 000, deleteAgent 000, with their log lines (3.5)
20. Prebuilt feed check (debug line only) (3.6, Q3)
21. Feed maps load failure at start deletes `queue/vd_updater` and logs the error (2.5)
22. All on-disk paths of 4.1
23. Key-value store layout: directory + `data.sqlite`, pragmas, `cf` and `kv` tables, text binding (4.2)
24. Key-value store operations and error texts, 20 000-write batches (4.2)
25. Durable queue format: 20-digit keys, prefix + zero byte + item, reload on open (4.3, Q4)
26. Feed value encoding: JSON, zlib above 64 bytes, read rule on byte 0x78 (4.4.1)
27. Feed columns and key formats (4.4.2)
28. CVE record schema, defaults and fields read (4.4.3)
29. Translation record schema and action names (4.4.4)
30. Candidate list format (4.4.5)
31. Description record format (4.4.6)
32. Global maps fields read (4.4.7)
33. Updater metadata store: timestamp keys, greatest key wins, one row per run (4.5, Q6)
34. Inventory database columns and key formats, node prefix (4.6)
35. Updater creation: metadata store, configured offset, output folders, user agent, chain (5.3)
36. Step chain building, invalid-value errors, offline compression from extension (5.4, Q7)
37. Run state and `stageStatus` entries (5.4)
38. Scheduled run: offset failure leads to snapshot retry; other failures; hash cleared (5.5)
39. Full download on offset 0 (online) or reset, state restored afterwards (5.5)
40. Any regular-chain failure counts as offset failure (5.5, Q8, Q9)
41. Content server metadata parsing, warnings and errors (5.6)
42. Offsets download in pages of 1000 into `<to>-api_file.json`, interruption warning (5.7)
43. Snapshot download into `downloads/` (5.8)
44. Offline download: file:// copy, http(s) single GET, unknown prefix, SHA-1 change check (5.9)
45. User agent header on every request (5.10)
46. Retry rules: 429 90 s; 5xx 1,1,2,4,8,16,30 s; endless; stop flag (5.10)
47. HTTP error texts and transport messages (5.10)
48. gzip and zip decompression, insecure-path check, directory entries (5.11)
49. Publishing to the callback and its log lines; offsets vs snapshot failure (5.12)
50. Version recording: offset row; offline hash + offset rows (5.13)
51. Clean-up of downloads/contents, stop at first missing folder (5.14, Q24)
52. Scheduler: immediate first run, interval, in-progress guard, log lines (5.15)
53. Changing the interval starts a run at once (2.2, Q34)
54. Feed message checks and unknown type (6.1)
55. Whole message under the exclusive feed lock, batch committed even on error (6.1, Q10)
56. Change pages: per-item apply, last offset, stop handling (6.2, Q23)
57. Raw file: database emptied, line-by-line, progress lines every 1000, invalid line error (6.3)
58. Stop during raw load returns offset 0 as success (6.3, Q35)
59. Resource kinds by name prefix, unknown kinds ignored with a debug line (6.4)
60. create / update / delete per kind, error texts (6.4)
61. CVE state handling: PUBLISHED stores derived records, REJECTED removes them, other errors (6.4)
62. Schema normalising rules, defaults, token names, `1: <col>: error:` positions (6.5)
63. Text form for patching with 6-decimal float printing (6.5.3)
64. JSON patch operations and every error text (6.6)
65. Hotfix index store/remove (6.7.1)
66. Remediations store/remove and its two error lines (6.7.2)
67. Descriptions per container: source name, English text, references, CVSS 3.1/3.0 choice, CVSS 2 ignored (6.7.3, Q11)
68. Candidates per container: grouping by lower-case product, vendor only for nvd/cisa, reverse index, stale product removal, write only when changed (6.7.4)
69. Candidate removal for rejected CVEs across all CNA columns (6.7.4)
70. Feed callback: log lines, reload maps, reboot event after every update (6.8, Q32)
71. Global maps loading and its errors (6.9)
72. Translation cache fill up to its size, additive, regex compile (6.9, Q12)
73. Lookups: candidates (stop ends current list only), description, remediation, hotfix prefix, CNA by format/source/prefix/contains (6.10)
74. Translation lookup: target platform, unanchored product/vendor patterns, version capture from the name (6.10, Q13)
75. Four router subscriptions with ids and filters, subscription failure line (7.1)
76. rsync attributes_type null error line (7.1)
77. Event classification table, including MODIFIED and DELETED OS deltas (7.2, Q14, Q15)
78. Hotfix insert events add the hotfix to the agent's hotfix cache (7.2)
79. JSON actions: reboot, cleanup, scanAgent, upgradeAgentDB(15), deletePackage, deleteHotfix, deleteAgent, unknown (7.2)
80. `no-index` and `full` flags (7.2)
81. Agent id padding and manager name for `000` (7.2)
82. Persistent event queue with type byte encoding, at-least-once, 1 s idle wait (7.3)
83. Delayed queue per agent, 60 s in-memory postponement, result handling (7.4)
84. Postponing an agent's events while it has delayed ones (7.5)
85. Concurrency: one feed lock for events and feed updates; single agent-database connection (7.6)
86. Event processing log lines and chains per type; delayed queue emptied after re-scans/clean-ups (7.7)
87. Error handling of normal events: not-ready, agents incomplete, json, other (7.7, Q40)
88. "Agent data not ready" sources: NOT_SYNCED answers and empty OS data (7.8)
89. Agent database transport: length-prefixed frames, `due` parts, 64 MiB limit, one reconnect (8.1)
90. Agent database answer parsing and error texts (8.2)
91. Exact query texts with trailing space and agent id check (8.3)
92. OS data loading, OS cache, CPE name building from the OS CPE rules (9.1)
93. Package insert chain stops when nothing was found (9.2)
94. CNA choice: format, source, prefix, contains, default; CNA mapping expansion (9.3)
95. Default CNA list `adp_default_array` or `nvd` (9.3)
96. Translation L1 (3 separate caches) / L2 / lower-cased fallback (9.4)
97. Package scan log lines and failure warning (9.4)
98. Candidate: already-found skip, platform check (CPE part o or code name), vendor check (9.5, Q25)
99. Version kind per package format (9.5)
100. Version ranges: equal, lower/upper bounds, `0` and `*`, unaffected stop, default status (9.5.1)
101. Match log lines and no-match lines (9.5.1)
102. Match conditions and detection source recorded (9.5.1)
103. Windows package hotfix remediation with the hotfix cache (9.6, Q16, Q17)
104. Package delete chain (9.7)
105. OS scan: Windows hotfix query first, windows/darwin only, CPE product, CNA list, Debian kind (9.8)
106. OS scan Windows remediation filter and discard of CVEs without remediation data (9.8)
107. OS scan error warning and completion line (9.8)
108. Hotfix insert lookup with prefix search (9.9, Q18)
109. Integrity clear chain (9.10, Q19)
110. Global sync does nothing but log (9.11)
111. Re-scan all: clean all, agent list (skip 000 when disabled), scan list (9.12)
112. Re-scan one: clean agent, agent-info checks with cluster rule, scan list (9.12, Q41)
113. Scan list: OS rows and package rows turned into state messages; incomplete agents (9.12, Q27)
114. Re-scans never alert (9.12)
115. Clean-up all / clean-up one (9.13)
116. Version kinds and strategies with the try-all order (10.1)
117. Calendar versions (10.2)
118. Python versions incl. normalised pre names and dev ordering (10.3, Q20)
119. Major-minor versions (10.4)
120. Semantic versions with byte-wise pre-release order (10.5)
121. Debian versions: parsing rules and ordering, invalid-character debug lines (10.6)
122. RPM versions: epoch, first hyphen split, `~` and `^`, run comparison (10.7)
123. All worked examples of 10.8
124. Version parser debug lines (10.9)
125. CPE parsing, 2.3 shift, field count, comparison with `*` (11)
126. Inventory insert: prepend new CVEs, never remove (12.1, Q22)
127. Inventory delete (12.2)
128. Inventory OS sync: old OS keys deleted with deletions published, insert/delete/unchanged elements, first-scan marker, "No changes" stop (12.3)
129. Inventory update for hotfix-solved CVEs (package column only) (12.4, Q36)
130. Clean-up of all agents: deletions published per CVE, os_initial_scan cleared (12.5)
131. Clean-up of one agent: keys removed, one DELETED_BY_QUERY, os_initial_scan (12.6)
132. Prefix-search collisions kept as they are (Q21, Q38)
133. Document fields and "if set" rule (13.1)
134. Document id with the description offset appended (13.1)
135. Detection source and `scanner.source` from `adp_descriptions` (13.1)
136. Per-CVE document errors still publish the element (13.1, Q39)
137. Install time conversion (13.1.1, Q29) and OS version formatting (Q28)
138. Score rounding and -1 fill, sentence-case severity, under_evaluation (13.1.2)
139. Description merge with fallbacks to `nvd` and its log lines (13.2)
140. Package / OS alerts: when built, INSERTED and DELETED fields, cvssN key, vector fields (13.3.1, Q31, Q42)
141. Hotfix alerts (13.3.3)
142. Clear alert builder kept but never sent (13.3.4)
143. Report line format and per-line send logs (13.3.5)
144. Report queue size limit with silent drop (13.4, Q37)
145. Report sender: datagram to `queue/sockets/queue`, retry every 1 s, rate limit, "Report sent" line, survives restarts (13.4)
146. Sink mode by `SIEM_STREAM_ADDR` / `SIEM_STREAM_TOKEN` (13.5.1)
147. Element publisher and array publisher with their log/error lines; `no-index` ignored (13.5.2, Q2)
148. Local sink: prefix deletes, upserts, missing-data warning (13.5.2)
149. Stream sink: kind V, remembered hashes without detected_at, replaced-offset deletes, unchanged skip (13.5.2)
150. Re-scan mode: deferred deletions, unseen documents deleted at the end, `full` bypass (13.5.3)
151. Every log line of section 14 with its tag and level
152. Every error text of section 15
153. Limits and sizes of section 16
154. Outputs read by siem-api, the analysis rules and the console stay compatible (17)
155. Load-bearing literals with old names kept until the owner renames them (20)
156. Tests of section 19 pass, including the differential checks against the old scanner
