# Alert lifecycle: from detection to closed

Status: phases 1 to 3 done (2026-11-16, phase 3 without the console view of an alert's incident), phase 4 next.

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
- **L-6 Incidents are cases.** Key = tenant + agent + entity (the process image when the alert
  names one, else the user, else the host). Level 7+ opens an incident when none is open for its
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
- **L-8 Open: the case table key.** `soar_cases` replaces rows by (tenant, `created_at` in seconds),
  not by case id: two cases created in the same second become one (checked in a scratch table). New
  incidents therefore take a second after the newest case (`unique_second`). The real fix is a table
  keyed by (tenant, id); it needs a migration of every tenant's replicated table, so it waits for
  the owner's approval.

## 5. Progress

- 2026-11-16: plan written. Phase 1 done: `record_alert` (agent HTTP ingest, FIM handler, simulations) and the syslog engine hand their alerts to `deliver` (`siem-api/src/provigil_manager.rs`); decisions L-1 to L-3. siem-api tests: 153 passed.
- 2026-11-16: phase 2 done: field exceptions (`siem-suppression/src/lib.rs`, `siem-api/src/suppressions.rs`, the Suppressions page `/siem-suppressions`), decisions L-4 and L-5. Example: rule 960270 when `data.win.eventdata.image` contains `docker.exe`, permanent.
- 2026-11-16: phase 3 done (backend): incidents (L-6), case updates keep `hit_ids` (L-7), same-second case collapse found (L-8, open). SQL checked in a scratch database (create, analyst update, incident update, reload, a burst of 3 incidents and a manual case in one second: 4 cases). siem-api tests: 156 passed. Next in phase 3: the alert list shows each alert's incident.
