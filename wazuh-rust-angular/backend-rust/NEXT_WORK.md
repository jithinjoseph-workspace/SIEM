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
| Manager | `wazuh-agentlessd` | medium |
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

## 1. UI for integrations and syslog forwarding (small)

- **Have:** `wazuh-integratord` and the five integration scripts (Slack,
  PagerDuty, VirusTotal, Shuffle, Maltiverse) and `wazuh-csyslogd`, ported and
  supervised by siem-api. They start when `ossec.conf` has `<integration>` /
  `<syslog_output>` blocks.
- **Missing:** console screens to add, edit and test those blocks (as the SMTP
  settings page does for `<global>` e-mail); siem-api endpoints that write
  `ossec.conf` and restart the daemon.
- **Check:** a test message reaches a Slack webhook / a local syslog listener.

## 2. Per-tenant alert e-mails

- **Have:** `wazuh-maild` sends alert e-mails platform-wide (super-admin SMTP
  settings).
- **Missing:** each tenant admin sets recipients and minimum level for its own
  agents only. maild knows nothing about tenants, so this belongs in siem-api
  (it maps agents to tenants), sending through the same SMTP settings.
- **Check:** an alert of tenant A's agent reaches A's recipients and not B's.

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

## 7. wazuh-clusterd (biggest)

Several managers working as one: a master and workers sharing agent keys,
groups, rules and agent status, and agents spread across workers. Plan in
`wazuh-rust-angular/docs/MANAGER_SCALING_PLAN.md`. Wazuh's clusterd is Python; needs its own
design for our multi-tenant setup (ClickHouse already shares the data).
- Also unlocks the cluster parts left out of the vulnerability scanner
  (cluster name, node name, `no-index` re-scans).
