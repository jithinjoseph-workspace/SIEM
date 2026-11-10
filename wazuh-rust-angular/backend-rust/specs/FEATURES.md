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




