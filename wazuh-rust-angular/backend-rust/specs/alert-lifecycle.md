# Alert lifecycle: from detection to closed

Status: phases 1 to 6 done (2026-11-16); not yet tested live (services stopped). L-8 resolved.

## 1. Goal

One flow for every alert: detect → enrich → group into an incident → prioritise → auto-triage →
analyst queue (owner, state, SLA) → respond → close with a verdict → feedback into tuning →
metrics. The analyst works on incidents (dozens a day), not alerts (tens of thousands).

## 2. Today (2026-11-16)

| Stage | What exists | Code |
|---|---|---|
| Detect | shipped ruleset, Sigma, YARA, file reputation, vulnerability alerts | `provigil-analysisd`, `siem-api/src/sigma.rs`, `yara_edr.rs`, `file_reputation.rs` |
| Store | `siem_alerts` per tenant | `siem-api/src/db.rs` |
| Filter | suppressions; triage recommends them | `suppressions.rs`, `triage.rs` |
| Notify | live feed, alert e-mails | `alert_mail.rs` |
| Respond | playbooks, decision gate, console buttons | `soar.rs`, `decisions.rs` |
| Investigate | inspect, process tree, timeline, copilot, memory | `investigate.rs`, `process_tree.rs` |
| Case | status, owner, SLA, disposition, history | `soar.rs`, `case_detail.rs` |
| Learn | a closed case becomes a memory lesson | `org_memory.rs` |

Problems, from the live data of tenant acm:

1. 38,000 to 180,000 alerts a day on 2 PCs, 85% below level 7.
2. An alert has no state (no status, owner or verdict column).
3. No grouping into incidents; cases match by IP, which endpoint alerts usually lack.
4. Three side paths store alerts without suppression, playbooks or e-mail: the agent HTTP
   ingest (`ingest_batch`), the FIM handler and syslog (`syslog.rs`).
5. 0 playbooks, 0 suppressions, 8 hand-made cases.
6. Suppressions name only a rule, agent or IP: no "this rule, but only for docker.exe".
7. Priority is the rule level only.
8. Test and simulation alerts sit in the real queue.
9. A "false positive" verdict never becomes an exception.

## 3. Phases

| Phase | Work | Fixes |
|---|---|---|
| 1. One path | every alert source goes through `deliver` (store, suppression, live feed, playbooks, e-mail) | 4 |
| 2. Cut noise | field exceptions in suppressions (process image, user, path); the shipped and Sigma alert of one event marked as one; test and simulation alerts tagged and left out of the queue | 1, 6, 8 |
| 3. Incidents | alerts grouped by tenant + host + (user or process) + rule family within a window into a case (`soar_cases`); an alert's state is its case's | 2, 3 |
| 4. Priority | score = level × PC importance (risk fabric) × confidence; sets the case priority and SLA | 7 |
| 5. Default playbooks | a starter set per tenant: incident at level 12+, notify, enrich; blocking and isolation behind the decision gate | 5 |
| 6. Learn | a "false positive" verdict proposes an exception a person approves; false-positive rate per rule; time to acknowledge and to resolve | 9 |

## 4. Decisions

- **L-1 One path through `deliver`.** The side paths call `deliver` in a background task, so a
  request never waits on ClickHouse retries; the alert is returned to the caller at once.
- **L-2 Risk score before storing.** `deliver` scores every alert (risk fabric) before it is stored,
  so analysis-service alerts are stored with their business risk too (until now only the side
  paths stored it; the main path scored only the in-memory copy). Red Swarm simulations are not
  scored, as before.
- **L-3 Deception on every alert.** The tripwire check ran only for side-path alerts; it now runs in
  `deliver` for every shown alert (never for deception's own alerts, so no loop).
- **L-4 Exceptions may be permanent.** A suppression may add a field condition: a dot path into the
  alert (`data.win.eventdata.image`) that must contain a text, without case. Only a suppression
  with both a rule and a field condition may be permanent: that narrow it cannot hide anything
  broad. Every other one still expires (1 hour to 7 days); level 12+ is never hidden; a field the
  alert does not have never hides it.
- **L-5 Shipped and Sigma alerts of one event** are joined by phase 3's incident grouping (same
  host, process and time), not by a second mechanism. Red Swarm alerts are already tagged and never
  stored, so they are out of the queue.
- **L-6 Incidents are cases.** Key = tenant + agent + rule (changed 2026-11-16 after the live test:
  keyed by process, one rule on four processes made four incidents; now one, listing the processes
  or users involved, 20 at most). The entity of each alert is the process image when it names one,
  else the user, else the host. Level 7+ opens an incident when none is open for its
  key; any alert of the key joins while the last one is at most 1 hour old. The case (`INC-<year>-<n>`,
  tag `auto-incident`, the key as tag `key:<tenant>|<agent>|<entity>`) gets the alert ids in
  `hit_ids` (500 at most), severity and priority from its highest level (12+ CRITICAL/P1, 10-11
  HIGH/P2, 7-9 MEDIUM/P3). Writes every 15 s keep what people set (status, owner, ...); a case
  people closed takes no more alerts, the next alert opens a new incident. Open incidents of the last
  hour are reloaded after a restart. Code: `siem-api/src/incidents.rs`.
- **L-7 Case updates keep their alerts.** A case update re-inserts the row from a column list that
  left out `hit_ids`, so any update (status, owner, disposition) would have emptied it; `hit_ids`
  is now in that list (`CASE_COLUMNS` in `soar.rs`). Until now nothing wrote `hit_ids`, so no case
  page showed alerts.
- **L-8 The case table is keyed by case id.** `soar_cases` replaced rows by (tenant, `created_at` in
  seconds), not by case id, so two cases created in the same second became one (checked in a scratch
  table). On 2026-11-16, with the owner's approval, both existing tables (`ndr.soar_cases`, 0 cases,
  and `ndr_acm.soar_cases`, 8 cases) were rebuilt keyed by `(tenant_id, id)`: a new replicated table
  (Keeper path `.../soar_cases_by_id`), every stored row copied (not only the deduplicated view, so
  a case hidden by a collision but not yet merged away would come back), the counts compared, the
  tables exchanged; the old ones stay as `soar_cases_bak_20261116`. No case was lost (8 before, 8
  after; the one extra old row was an earlier version of INC-2026-0008). New tenants get the new key
  from `ndr/config/clickhouse/init.sql`, SIEM-only installs from `SOAR_DDL` in `siem-api/src/db.rs`.
  Incidents still take a second after the newest case (`unique_second`), which costs one query and
  protects an install whose table is not migrated yet.
- **L-9 Priority from level and business risk.** An incident's severity is the higher of its
  highest level's (12+ critical, 10-11 high, 7-9 medium) and its highest business risk's (risk
  fabric score 70+ critical, 45-69 high, 25-44 medium, by the risk fabric's own tiers). The
  priority (P1 to P4, which sets the SLA) is set when the incident opens; later alerts raise the
  severity, while the priority stays as opened or as people changed it. Alerts carry no
  confidence value, so the planned "× confidence" part is left out until a detection gives one.
- **L-10 Starter playbooks, not default ones.** Incidents (phase 3) already open a case for level 7+
  and tenants already have alert e-mails; every other action needs the tenant's own credentials
  (Slack, PagerDuty, VirusTotal). Playbooks created by default would run as silent no-ops, so the
  SOAR page (`/soar`) offers five starters that fill the form instead: critical alert to the team
  chat, critical alert pages on-call, known-bad source blocked, brute-force source blocked, changed
  file checked on VirusTotal. Blocking still passes the decision policy.
- **L-11 Learning stays with people.** An automatically opened incident closed as "False Positive"
  shows a "Create exception" button on its case page: its most frequent rule and agent, and its
  process or user on the field the incident recorded (tag `field:<path>`); permanent when it has a
  field, else 7 days. Nothing is created until a person clicks it.
- **L-12 Metrics from what is stored.** `GET /api/v1/siem/incidents/metrics?days=30` (1 to 90):
  cases, open, opened automatically, mean time to the first action (the first status change, edit,
  note, disposition or resolution in the case history) and to closing, and per rule how many
  incidents ended as false positives. Shown at the top of the SOAR page.
- **L-13 The work queue is level 7+.** The SIEM console's alert list asks the server for level 7
  and up (the level that opens an incident) and filters live alerts the same way; "All levels"
  shows the rest, which stay stored and searchable (issue 1).
- **L-14 Simulations never count.** One check, `is_simulation` (the attack simulator's `simulation`
  and Red Swarm's `redswarm_simulation` groups), keeps simulated alerts out of everything with a
  real effect: `deliver` only shows them live (never stored, scored, grouped, acted on or mailed),
  and the in-memory window no longer scores them or feeds them to the intent engine. Until now the
  attack simulator raised the real PC's risk and fed its intent dossier (issue 8). Alerts caused by
  people testing on real PCs (a rescan, a test file) are real events and stay real alerts.
- **L-15 Queue order with the triage verdict.** The case list carries `sla_due`, the triage verdict
  and its confidence, and `queue_rank` (`soar.rs`): open first, then priority, then the verdict
  (compromised and malicious first; likely benign last only at 70% confidence or more), then the
  least SLA time left. The SOAR page lists cases in that order by default ("Newest first" on
  request) with Triage and SLA-left columns. This is the "confidence" of the plan (issue 7): a
  confident benign verdict moves a case down, never out of the queue.
- **L-16 Automation without setup.** Incidents, their triage and alert e-mails run with no setup;
  playbooks act through the tenant's own integrations and start when one is saved. The SOAR page
  says so above the starters (issue 5).
- **L-17 One incident per computer, opened when it matters** (2026-11-17, replaces the
  per-agent-and-rule grouping of L-6). One busy PC opened 41 cases in two hours, one per rule. Now
  a computer's alerts form one incident while its last alert is at most 24 h old; the case lists
  every rule with its count (case page "By rule", with an exception per rule). Level 7 alerts are
  gathered; they become a case at level 10+, or when they span 2 different ATT&CK tactics (several
  stages of an attack); until then they stay in the alert queue. Reason: an attack sets off many
  rules on one computer, so one case tells the whole story, and a lone medium alert is not a case.
  Earlier per-rule incidents are not continued (their key differs).
- **L-18 ProVigil's own activity raises no alert** (2026-11-17): programs the agent starts from its
  install path and what those start (by process id), the install command's verified files, and
  configuration check results seen for the first time (`siem-api/src/own_activity.rs`). Changed
  configuration checks still alert, but open no incident (Compliance page).

## 5. Progress

- 2026-11-16: plan written. Phase 1 done: `record_alert` (agent HTTP ingest, FIM handler, simulations) and the syslog engine hand their alerts to `deliver` (`siem-api/src/provigil_manager.rs`); decisions L-1 to L-3. siem-api tests: 153 passed.
- 2026-11-16: phase 2 done: field exceptions (`siem-suppression/src/lib.rs`, `siem-api/src/suppressions.rs`, the Suppressions page `/siem-suppressions`), decisions L-4 and L-5. Example: rule 960270 when `data.win.eventdata.image` contains `docker.exe`, permanent.
- 2026-11-16: phase 3 done (backend): incidents (L-6), case updates keep `hit_ids` (L-7), same-second case collapse found (L-8, open). SQL checked in a scratch database (create, analyst update, incident update, reload, a burst of 3 incidents and a manual case in one second: 4 cases). siem-api tests: 156 passed. Then: the alert list (`/api/v1/alerts`) gives each alert its case as `data.incident` (id, number, status; `incidents::attach`), and the console's alert list and alert detail link to it.
- 2026-11-16: phase 4 done: severity from level and business risk (L-9, `severity_of` in `incidents.rs`). siem-api tests: 157 passed.
- 2026-11-16: phase 5 done: starter playbooks on the SOAR page (L-10); their conditions are all evaluated by `provigil-common/src/soar/conditions.rs` (its tests cover each).
- 2026-11-16: phase 6 done: exception from a false-positive incident (L-11), metrics (L-12). The metrics SQL was run read-only on tenant acm (8 cases, 6 open, 8 min to close, 21 h to first action). siem-api tests: 157 passed.
- 2026-11-16: case tables rebuilt keyed by case id (L-8); definitions changed for new tenants.
- 2026-11-16: issues 1, 5, 7 and 8 completed (L-13 to L-16); incidents are triaged when they open; cases opened from an alert list it. siem-api tests: 158 passed.
- 2026-11-16 live test (services restarted 17:01): 445 alerts in 18 min, all stored with their risk score; 20 level 7+ alerts became 7 incidents; shipped and Sigma alerts of one process joined; incidents got their history entry. Found: no triage verdict (the investigation looked only at community_id; fixed, falls back to hit_ids) and too many incidents (one per process; now one per rule, L-6). The owner approved two permanent exceptions for build output on the development PC (rules 92213 and 962881 on agent 8084 when the path contains the repository folder).
- 2026-11-17: after an agent reinstall on win-node-e296 (26, then 41 cases, none an attack): L-17 and L-18, inventory events no longer checked by log rules, the agent keeps events on disk while the manager is unreachable (165,214 had been dropped overnight). siem-api tests: 168 passed.
