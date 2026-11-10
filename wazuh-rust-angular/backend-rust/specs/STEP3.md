# Step 3: the five manager programs siem-api takes over

Inventory made 2026-11-03. Every file of the five crates, what it does, who uses it, and
what replaces it. Before any of them is deleted, its features go into `FEATURES.md`
(method in `HANDOFF.md`).

## Summary

| Crate | Live code | Old `legacy/` folder | C-comparison tests | Who uses it | Replaced by |
|---|---|---|---|---|---|
| siem-task-manager | 5 files, 768 lines | — | — | listed in siem-api's `Cargo.toml`, **never called** | delete (agent upgrades live in siem-modulesd today) |
| siem-csyslogd | 4 files, 954 | 8 files, 1,581 | 6 files, 201 | siem-api `soar.rs` (the SOAR "syslog" integration calls its formatter and UDP sender) | our own syslog sender in siem-api |
| siem-integratord | 12 files, 2,531 | 7 files, 949 | 8 files, 375 | not linked by any crate; **but** SOAR runs its scripts (`data/manager/integrations/*.exe`) for Slack, PagerDuty, Shuffle, VirusTotal, Maltiverse | our own HTTP integrations in siem-api |
| siem-monitord | 12 files, 1,744 | 13 files, 1,850 | 34 files, 531 | siem-agentlessd (step 1) | siem-api tasks: agent-disconnected alerts, log rotation |
| siem-maild | 11 files, 3,287 | 8 files, 1,128 | 52 files, 1,760 | siem-api (`alert_mail.rs`, `mail_settings.rs`, `provigil_manager.rs`, `soar.rs`), siem-csyslogd, siem-integratord, siem-monitord, siem-agentlessd | per-tenant alert e-mails and PDF reports (built), a platform alert e-mail, our own mail sender |
| **Total** | **44 files, 9,284** | **36 files, 5,508** | **100 files, 2,867** | | |

The `legacy/` folders are older ports no build uses; they are deleted with their crate.
The `tests/oracle*` folders compare against the original C programs; deleted too.

Also part of this step:
- `data/manager/bin/provigil-maild.exe`, `provigil-monitord.exe`, `provigil-integratord.exe`,
  `provigil-csyslogd.exe`, `provigil-reportd.exe`, and
  `data/manager/integrations/{slack,pagerduty,shuffle,virustotal,maltiverse}.exe`.
- siem-api `provigil_manager.rs`: the daemon list (`DAEMONS`: monitord, maild, integratord,
  csyslogd), `MANAGER_TOOLS` (reportd), the restart rules for those daemons, the mail part
  of `ossec.conf` (`ossec_conf_with_mail`, `apply_mail_settings`), `SMTP_AUTH_FILE`.
- siem-api `soar.rs`: `run_provigil_script` / `run_script_in` (runs the integration
  scripts), `send_syslog` and `alert_data` (use csyslogd and maild code).
- siem-api `mail_settings.rs` and `alert_mail.rs`: use `siem_maild::smtp_ext` (`SmtpAuth`,
  `send_mail`, `send_test`, `Attachment`). `smtp_ext.rs` is ProVigil's own extension, but it
  is built on the ported SMTP session code (`smtp.rs`), so the sender is rewritten.

## siem-task-manager (768 lines, unused)

| File | Lines | What it does |
|---|---|---|
| `lib.rs` | 173 | the task manager: commands in, answers out |
| `commands.rs` | 193 | upgrade task commands: create, get status, update, cancel, results |
| `task_model.rs` | 133 | a task: agent, node, module, command, status, timestamps |
| `task_store.rs` | 194 | tasks kept in memory, looked up by agent / id |
| `reaper.rs` | 75 | tasks stuck too long are marked timed out |

Replacement: none needed in this step. The live upgrade flow is siem-modulesd's own task
manager (step 5) behind `/api/v1/agents/:id/upgrade`. Delete the crate and the dependency.

## siem-csyslogd (forward alerts to remote syslog servers)

| File | Lines | What it does |
|---|---|---|
| `src/lib.rs` | 166 | the daemon: watch the alerts file, send each alert to every configured server; hostname / IP helpers (`resolve_hostname`, `ip_of`, `Hostnames`), `connect_udp`, `strerror` |
| `src/alert.rs` | 410 | one alert to one server: filters (level, rule groups, rule ids, location), formats: default syslog line, CEF, JSON, Splunk key=value; `send_log`, `send_json` |
| `src/config.rs` | 195 | `<syslog_output>` blocks: server, port, format, level, group, rule_id, location, use_fqdn |
| `src/bin/provigil-csyslogd.rs` | 183 | program entry: options, config, run |
| `legacy/…` (8) | 1,581 | older port, unused |
| `tests/oracle/…` (6) | 201 | comparison with the C program |

Features to keep: send alerts over UDP syslog to a server and port; formats default / CEF /
JSON / Splunk; filters by lowest level, rule groups, rule ids, location; host name or FQDN in
the header; resolve the server name. Today the per-tenant SOAR "syslog" integration uses
this code; the manager-wide daemon reads `alerts.json`, which no longer gets alerts (they go
to ClickHouse), so it forwards nothing now.

Replacement: a small syslog sender in siem-api (or provigil-common) with the four formats
and the filters, used by the SOAR syslog integration. Also TCP and TLS as options (new).

## siem-integratord (alerts to Slack, PagerDuty, Shuffle, VirusTotal, Maltiverse)

| File | Lines | What it does |
|---|---|---|
| `src/integrator.rs` | 405 | the daemon: each new alert is matched against each `<integration>` (level, group, rule id, location) and handed to its script with the alert file, API key and hook URL |
| `src/config.rs` | 201 | `<integration>` blocks: name, hook_url, api_key, level, group, rule_id, event_location, alert_format, max_log, options, timeout, retries |
| `src/scripts/mod.rs` | 390 | the script runner: reads the alert file and options, calls the right script, retries, logs |
| `src/scripts/slack.rs` | 76 | Slack message: colour by level, rule, agent, full log |
| `src/scripts/pagerduty.rs` | 66 | PagerDuty event: summary, severity, source, details |
| `src/scripts/shuffle.rs` | 70 | Shuffle webhook: the alert, skipping some rules |
| `src/scripts/virustotal.rs` | 163 | look up a file's MD5 from a file-change alert; report positives back as a new event |
| `src/scripts/maltiverse.rs` | 427 | look up hashes, IPs, domains, URLs of an alert at Maltiverse; report back |
| `src/pyjson.rs` | 522 | JSON reading and writing the way the original Python scripts behave |
| `src/lib.rs` | 14 | module list |
| `src/bin/provigil-integratord.rs` | 188 | program entry |
| `src/bin/integrations.rs` | 9 | the scripts as one program (`integrations/<name>.exe`) |
| `legacy/…` (7) | 949 | older port, unused |
| `tests/oracle/…` (8) | 375 | comparison with the C program and Python scripts |

Features to keep: the five integrations with their message contents, their filters (level,
groups, rule ids, location), retries and timeouts, VirusTotal / Maltiverse results returned
as new events. SOAR already offers Slack, PagerDuty, Shuffle, VirusTotal, Maltiverse,
syslog, Teams, webhook and e-mail per tenant, but five of them run these scripts.

Replacement: each integration as an HTTP call in siem-api (`reqwest`), with its own
message format; enrichment results become alerts / events through siem-api.

## siem-monitord (manager housekeeping)

| File | Lines | What it does |
|---|---|---|
| `src/monitord.rs` | 314 | main loop and timing: daily jobs at midnight, checks every few minutes |
| `src/actions.rs` | 224 | agents not seen for `agents_disconnection_time` are marked disconnected; an alert after `agents_disconnection_alert_time`; agents disconnected too long can be removed (`delete_old_agents`) through authd |
| `src/rotate_log.rs` | 224 | rotate `logs/ossec.log` / `ossec.json` by day or size, keep N days, compress old ones |
| `src/manage_files.rs` | 43 | each day: sign and compress the previous day's alerts / archives files |
| `src/sign_log.rs` | 69 | MD5 / SHA-1 / SHA-256 of a day's log written next to it |
| `src/compress_log.rs` | 39 | gzip a log file and remove the original |
| `src/config.rs` | 230 | monitord options, `<reports>` blocks (daily reports), global options |
| `src/wdb.rs` | 127 | the agent-database calls it needs (agents and their last keep-alive) |
| `src/mq.rs` | 68 | sends its alerts into the analysis queue |
| `src/moncom.rs` | 90 | `getconfig` answers on its socket |
| `src/lib.rs` | 62 | module list |
| `src/bin/provigil-monitord.rs` | 254 | program entry |
| `examples/mon_oracle.rs` + `tests/oracle/…` (34) | 531 | comparison with the C program |
| `legacy/…` (13) | 1,850 | older port, unused |

Features to keep: agent-disconnected status and alert (rule 504 today), optional removal of
long-disconnected agents, rotation / retention / compression of the manager's own logs while
the manager programs still write them, signing of daily files (only while alerts / archives
files are still written), the daily reports (moved: PDF reports + schedule, which also need
the report filters on the schedule to cover `<reports>`).

Replacement: siem-api background tasks (disconnect check from the agent registry and
provigil-db, an alert per tenant; log rotation of `data/manager/logs`); daily reports already
moved.

## siem-maild (alert e-mails)

| File | Lines | What it does |
|---|---|---|
| `src/maild.rs` | 282 | the daemon: queue alerts, group them, send at most N an hour, digests |
| `src/client.rs` | 455 | one alert to the e-mail text (full and SMS formats), subject |
| `src/smtp.rs` | 453 | SMTP session: connect, HELO, MAIL FROM, RCPT TO, DATA; also sendmail program mode |
| `src/smtp_ext.rs` | 279 | ProVigil's own extension: TLS / STARTTLS and login, MIME message with attachment (built on `smtp.rs`) |
| `src/config.rs` | 336 | global e-mail options, `<email_alerts>` blocks (per recipient: level, group, location, rule id, format, do_not_delay, do_not_group) |
| `src/alert.rs` | 427 | reading alerts from the alerts file / queue (`AlertData`) |
| `src/report.rs` | 518 | the daily report: filters, related fields, top lists (used by monitord and reportd) |
| `src/cfile.rs` | 106 | C-style file reading the alert reader needs |
| `src/lib.rs` | 49 | module list |
| `src/bin/provigil-maild.rs` | 184 | program entry |
| `src/bin/provigil-reportd.rs` | 198 | the report command-line tool |
| `examples/` (2) + `tests/oracle*/…` (52) | 1,760 | comparison with the C program |
| `legacy/…` (8) | 1,128 | older port, unused |

Features to keep: platform-wide alert e-mails (super admin: recipients, lowest level, per
hour), granular rules per recipient (level, groups, location, rule ids, full / SMS format, no
delay, no grouping), grouping and hourly limits, the daily report e-mail, the report tool,
SMTP with TLS / STARTTLS / login, test e-mail, attachments.

Already built (ProVigil's own): per-tenant alert e-mails (`alert_mail.rs`), PDF reports with
filters and schedule (`tenant_reports.rs`).

Replacement: our own mail sender (the `lettre` crate, MIT licence: TLS, STARTTLS, login,
attachments) used by `alert_mail.rs`, `mail_settings.rs` and the reports; the platform-wide
alert e-mail and the granular rules moved into siem-api; `AlertData` in `soar.rs` replaced
by reading the alert JSON directly; the report tool dropped (the console's PDF report does
it) or rewritten small if the owner wants it.

## Order inside step 3

1. siem-task-manager: delete (unused).
2. Mail sender: our own (lettre) for `alert_mail.rs`, `mail_settings.rs`, reports.
3. siem-csyslogd: our own syslog sender for SOAR.
4. siem-integratord: our own five HTTP integrations for SOAR.
5. siem-maild: platform alert e-mail and granular rules in siem-api; then delete.
6. siem-monitord: disconnect alerts and log rotation in siem-api; then delete.
7. siem-api `provigil_manager.rs`: drop the four daemons and reportd from the lists; the
   `ossec.conf` mail part; remove the files in `data/manager/bin` and
   `data/manager/integrations`.

siem-agentlessd (step 1) depends on siem-maild and siem-monitord: it must be deleted first or
together (the owner deferred step 1; ask before deleting it).
