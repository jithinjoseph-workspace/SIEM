# Next work (planned, not started)

Agreed on 2026-10-22 to do these later. Sections A-C are the remaining
Wazuh migration; sections 1-7 are console features and the deferred manager
daemons. Each item lists what
exists today, what is missing and how to verify it, following the rest of the
port: a faithful port of Wazuh 4.14.7, checked against the C/C++/Python
original (see `AGENTD_PORT_PROGRESS.md`).

## 0. Open from the vulnerability scanner

- **Real-time scan test on a live agent.** The scanner runs on the dev manager
  and found 139 real CVEs on agent 043 (this PC). Still to watch: a package
  change on an agent producing a scan within the next syscollector run.
  Needs a package installed or removed on the agent PC (e.g. an old Python
  library with known CVEs), then check the Vulnerabilities page and the
  manager log for the new detection.
- **Rotate the agent keys.** The keys were in git history until 2026-10-22
  (`data/manager/etc/client.keys` is no longer tracked; the keys live
  encrypted in ClickHouse `ndr.agent_keys`). New keys mean every agent
  re-enrolls once. Needs the owner's go-ahead.

## A. Manager self-monitoring (agent 000)

A Wazuh manager monitors its own machine as agent 000: it runs the agent
components locally and they send to analysisd's queue (`queue/sockets/queue`)
instead of remoted. Ours runs none of them, so agent 000 has no inventory,
no FIM and no logs of its own. The ported components already send through
`siem_ipc::mq_op`, which goes to that queue on a manager.

| Component | Windows | Linux |
|---|---|---|
| Log collection (`siem-logcollector`) | ported | ported |
| File integrity (`siem-syscheckd`) | ported | does not compile on Linux; no inotify / auditd (whodata) |
| Rootcheck | ported | Linux checks missing |
| Inventory (syscollector + `siem-sysinfo`) | ported | no Linux data provider (`/proc`, dpkg, rpm, ...) |
| SCA (`siem-sca`) | ported | Unix command runner / process list simplified |

Plan:
1. Linux manager: run `wazuh-logcollector` (add to the supervised daemons in
   `siem-api/src/wazuh_manager.rs`) with Wazuh's default manager `<localfile>`
   entries (journald / syslog, auth log, `logs/active-responses.log`, ...).
2. Wire FIM, rootcheck, syscollector and SCA for agent 000 so each starts as
   soon as its build exists on that platform (all four run on a Windows
   manager right away; there the dev PC is also agent 043, so it shows twice).
3. The Linux versions of FIM, rootcheck, syscollector and SCA: the same code
   the Linux agent needs (section C), done once for both. Decide who does it
   (the Linux-agent owner or us).
- **Check:** agent 000 shows inventory, FIM events and its own log alerts,
  compared with a C manager on the same host.

## B. What is left of the Wazuh migration (overall)

Already replaced or ported: analysisd, remoted, wazuh-db, modulesd (upgrade,
task manager, database, download, vulnerability scanner + CVE feed, router),
monitord, maild, integratord + 5 integrations, csyslogd, execd (Linux);
authd -> siem-api; Wazuh API / indexer / dashboard -> siem-api, ClickHouse,
Angular console (not ported on purpose).

| Area | What is left | Size |
|---|---|---|
| Manager | self-monitoring (section A) | medium |
| Manager | `wazuh-reportd` CLI | DONE 2026-10-22 |
| Manager | cloud modules: AWS, Azure, GCP, Office 365, GitHub, MS Graph, Docker | medium each |
| Manager | fluent forwarder (`wm_fluent`) | small |
| Manager | `wazuh-agentlessd` | DONE 2026-10-23 |
| Manager | `wazuh-clusterd` | large |
| Windows agent | github / office365 / ms-graph / cis-cat modules (rarely used on agents) | small-medium |
| Windows agent | MSI installer, code signing, "update all agents" (packaging) | medium |
| Linux agent | see section C | large |
| macOS agent | not started | large |

Suggested order: A, C, reportd, cloud modules (by customer need), agentlessd,
clusterd (when one server is not enough), macOS (if customers need it).

## C. Linux agent completion (owner: the Linux-agent developer)

Faithful ports exist for agentd, logcollector and execd. Missing: real-time
FIM (inotify) and whodata (auditd), Linux rootcheck checks, Linux inventory
sources, the SCA command runner, a modules host, upgrades, packaging; fix
`siem-syscheckd` on Linux. The console's Linux download still ships the old
`siem-agent-linux` prototype. Details: `wazuh-rust-angular/docs/LINUX_AGENT_COMPLETION_PLAN.md`.

## 1. Integrations and syslog forwarding — DONE 2026-10-23, per tenant

The shared manager's `<integration>` / `<syslog_output>` would send every
tenant's alerts to one place, so in the cloud forwarding is per tenant through
the shared SOAR instead (crates/siem-api/src/soar.rs):
- The analyst SOAR page (ndr-ui `analyst/soar`) works for SIEM tenants: siem-api
  serves `/api/soar/*` (integrations, playbooks, runs, cases) on each tenant's own
  `soar_*` tables, the same API and tables as ndr-engine.
- Each tenant's playbooks run on its Wazuh alerts (`wazuh_manager::on_alerts`).
  SIEM conditions: rule level / id / group, agent name, location.
- Actions on a SIEM alert use the ported Wazuh code: the integration scripts
  (Slack, PagerDuty, VirusTotal, Shuffle, Maltiverse, run as integratord runs
  them), csyslogd's default/CEF/JSON/Splunk syslog, the raw alert for webhooks,
  active response for `block_ip`. Teams, Discord, e-mail, cases: provigil-common.
- provigil-common SOAR (both copies, kept identical with ndr/rust): the alert in
  `SoarContext`, `SoarStore::soar_product_action`, the SIEM conditions, generic
  syslog / PagerDuty / Shuffle for NDR, and the private-target guard (siem-api
  turns it on; `SIEM_SOAR_ALLOW_PRIVATE_TARGETS=1` allows internal targets).
- 30 runs per playbook per minute; secrets are never returned to the browser.
- **Checked:** unit tests, the real Slack script against a local hook, all four
  syslog formats over UDP, and `soar::tests::live_clickhouse` (run with
  `--ignored`) on a scratch tenant database.
- **Open:** a run through the console with auth-service up; the Teams/Discord/
  e-mail texts and the case title are NDR-worded; ndr-engine still updates
  `run_count` with one ClickHouse mutation per run.

The Wazuh daemons stay ported and verified for single-customer installs.

## 1b. Analyst AI on the SIEM side — DONE 2026-10-23

The triage, AI activity and retrospective pages and the threat predictions
were NDR only (ndr-engine, network data, shown only to NDR tenants). The SIEM
has its own: one crate per feature (logic only, unit-tested), a thin siem-api
module each on the tenant's Wazuh alerts, its own API (`/api/v1/siem/*`) and its
own pages (ndr-ui `pages/siem-ai`, sidebar "SIEM AI & RESPONSE"):

| Crate | siem-api module | API | Page (permission) |
|---|---|---|---|
| siem-ai (providers from Settings > AI, `GROQ_API_KEY` fallback, budget, untrusted-data fencing) | ai_assist.rs | `/api/v1/ai/chat`, `/api/v1/ai/analyze` | SIEM AI Copilot |
| siem-triage (group by rule+agent+source, rules first, AI for the rest) | triage.rs (every 30 min) | `/api/v1/siem/triage*` | /analyst/siem-triage (siem-alerts) |
| siem-suppression (expiring; never hides level >= 12) | suppressions.rs (checked in `on_alerts`) | `/api/v1/siem/suppressions*`, `/ai-activity` | /analyst/siem-suppressions (siem-alerts) |
| siem-retro (past events through the live analysisd logtest, or keyword) | retro.rs | `/api/v1/siem/retrospective/*` | /analyst/siem-retrospective (siem-rules) |
| siem-predict (next MITRE stage per agent, explainable; AI briefing only) | predictions.rs (every 15 min) | `/api/v1/siem/predictions*` | /analyst/siem-predictions (siem-mitre) |

SIEM-only tenants also get the shared SOAR page in that menu.

**Analyst workload & AI-trust calibration** (crate siem-analyst-insight, insights.rs):
triage and suppression actions are logged per tenant (`siem_analyst_actions`, 30 days);
per analyst it estimates workload (decisions/h, hours without a break, queue) and use of
AI suggestions (acceptance, accepting within 10 s without looking, hidden hosts that later
went critical). Over-reliance makes triage require "View alerts" before hiding and show the
AI verdict after looking; explanations are detailed for new analysts, brief for experienced
ones under load; the largest groups come first under load. It only adds checks.
Visibility: the analyst (My Workload & AI Use, `/api/v1/siem/insights/me`), the tenant admin
(tenant-admin "Analyst Insights", `/team`, on/off `/settings`); never the super admin.
Checked by `analyst_insights_end_to_end` (`--ignored`).

AI is recommend-only, off when the tenant's AI is off, and within hourly budgets
(`SIEM_TRIAGE_AI_PER_HOUR`, `SIEM_PREDICT_AI_PER_HOUR`). Tables per tenant:
`siem_suppressions`, `siem_analyst_state`, `siem_retro_scans`, `siem_threat_predictions`.
- **Checked:** crate unit tests, and `analyst_tests` (`--ignored`) on ClickHouse and
  the running analysisd in a scratch tenant.
- **Open:** a real AI provider was not called in the tests (tenant AI off); the
  pages were built and type-checked but not clicked through with auth-service up.

## 1c. ClickHouse is where the pages read history — DONE 2026-10-23

The dashboard, MITRE, compliance, FIM summary, reports, rule hit counts, health,
ARIA and the AI chat read the tenant's last 7 days from ClickHouse (history.rs),
not siem-api's in-memory window (latest 50,000 of all tenants, empty after a
restart). `siem_alerts.alert_json` keeps the whole alert (groups, decoded fields,
FIM data); rows from before it have the old columns only. Agent inventory (OS,
hardware, packages, ports, interfaces, processes) is copied to
`siem_agent_inventory` every 10 min from wazuh-db / siem-agents and the inventory
endpoints read it (inventory_store.rs; wazuh-db is paged, a reply is at most 64 KB).
Memory now only feeds the live view and background jobs; the manager's files
(alerts.json, archives.json, wazuh-db) stay as the backup copy.
- **Checked:** `history_and_inventory_from_clickhouse` (`--ignored`).
- **Open:** counts are done in Rust over at most 50,000 rows per window (move to
  SQL GROUP BY for very busy tenants); no ClickHouse TTL / file retention yet.

## 2. Per-tenant alert e-mails

- **Have:** `wazuh-maild` sends alert e-mails platform-wide (super-admin SMTP
  settings).
- **Missing:** each tenant admin sets recipients and minimum level for its own
  agents only. maild knows nothing about tenants, so this belongs in siem-api
  (it maps agents to tenants), sending through the same SMTP settings.
- **Check:** an alert of tenant A's agent reaches A's recipients and not B's.
- **Partly covered since 2026-10-23:** a tenant can add an Email integration
  (its own SMTP) and an `email` playbook in SOAR; not yet through the platform SMTP.

## 3. PDF reports with charts

- **Have:** maild / monitord daily reports as plain text e-mails.
- **Missing:** a PDF (summary, charts of alerts by level / rule / agent,
  top vulnerabilities, explanations), per tenant, scheduled and on demand,
  e-mailed and downloadable.
- **Check:** generate for one tenant and compare the numbers with the console.

## 4. wazuh-reportd — DONE 2026-10-22 (see AGENTD_PORT_PROGRESS.md)

- **Have:** `report_op` (the reporting engine) is ported inside siem-maild.
- **Missing:** the `wazuh-reportd` command-line tool (reads alerts, filters by
  group / rule / level / location / user / source, prints the report).
- **Check:** same output as the C binary on the same alerts file.

## 5. Cloud modules (one at a time)

AWS (S3 logs, CloudTrail, GuardDuty, ...), Azure (Log Analytics, Graph,
Storage), GCP (Pub/Sub, buckets), Office 365, GitHub audit log, Docker
listener. In Wazuh these are wodles (mostly Python) run by modulesd.
- **Check:** each against the Python original with recorded API responses.

## 6. wazuh-agentlessd

Monitoring devices without an agent (routers, firewalls, old servers) over
SSH: integrity of files and command output, with Wazuh's expect scripts.
- **Check:** against the C daemon with a local SSH server.
- **DONE 2026-10-23** (crates/siem-agentlessd, tests/oracle: config, queue messages, argv,
  getconfig, diff tree and log identical to the C daemon on fake scripts; supervised on Linux,
  scripts installed to `agentless/`). Still open: a run of the real expect scripts
  against an SSH server (needs `expect` in WSL), a UI for `<agentless>`.

## 7. wazuh-clusterd (biggest)

Several managers working as one: a master and workers sharing agent keys,
groups, rules and agent status, and agents spread across workers. Plan in
`wazuh-rust-angular/docs/MANAGER_SCALING_PLAN.md`. Wazuh's clusterd is Python; needs its own
design for our multi-tenant setup (ClickHouse already shares the data).
- Also unlocks the cluster parts left out of the vulnerability scanner
  (cluster name, node name, `no-index` re-scans).
