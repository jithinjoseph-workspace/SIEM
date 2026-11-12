# Console roadmap: one command center, coverage, data engineering

Status: plan (2026-11-11). From the owner's review of an "AI-native predictive SecOps" product's
screens. We take ideas, never their design, wording or names; every page is our own.

The comparison in one line: ProVigil does more (own EDR agent with live-tested response actions,
vulnerabilities, 3,205 SCA checks, 6 compliance frameworks, FIM with who-data, SOAR, gateway for
10,000 agents), but looks more complicated: 45 sidebar entries, each feature on its own page,
no single screen that tells the story.

## 1. Threat Center (new home page) — highest value

One screen built from data we already have, linking into the detailed pages:

| Block | Source we already have |
|---|---|
| Posture strip: yesterday / today / tomorrow | `/api/v1/posture` (built 2026-11-11) |
| Live risk line (last hours) | alerts per minute by severity (ClickHouse `siem_alerts`) |
| Live counters: events/s, detections/min, predictions/min | gateway metrics, engine counters, `siem_threat_predictions` |
| Detections by engine: rules, Sigma, AI triage, intent, deception, Red Swarm | the tables behind each page |
| Data readiness score (section 3) | parsers, agents, event sources |
| Detection ticker (newest high/critical) | `siem_alerts` over the WebSocket bus |
| Attack-chain ticker (intent dossiers moving through the kill chain) | `siem_intent_dossiers` |
| Threat map for the SIEM (alert source IPs) | GeoIP (`geomap.rs`); today's Attack Map is NDR-only |

## 2. Sidebar regrouped

45 entries into about six sections, nothing removed: Command (Threat Center, Posture, Cases),
Detect (Alerts, Triage, Sigma, Rules, MITRE coverage, Predictions, Intent, Deception, Red Swarm),
Investigate (Investigation, Copilot, Telemetry, Threat Intel), Respond (Active Response, SOAR),
Assets (Agents, Vulnerabilities, Compliance, FIM), Configure (Parsers, Logtest, Suppressions, AI
Oversight). Search box over all pages stays.

## 3. Data readiness score

"Is my data good enough to detect attacks?" per tenant, 0–100:
- agents enrolled vs active, and last event age per agent;
- the event sources expected for the fleet (Windows Security, Sysmon, PowerShell, Linux auth,
  syslog devices) present or missing;
- share of events decoded (known decoders + learned parsers) vs unmatched;
- clock skew and duplicate rates.
Each missing item says what to fix (install Sysmon, enable audit policy, add a parser).

## 4. ATT&CK coverage (extends the existing MITRE page, `/analyst/mitre`)

Today the page shows the Enterprise matrix with alerts per technique ("firing"). Add:
- **Detection content**: rules and Sigma rules mapped to each technique (counts, list on click).
- **Runnable**: the rule's data source is present (from section 3), e.g. Sysmon-based rules only
  count where Sysmon events arrive.
- **States**: firing (alerts in the period), runnable but quiet, has rules but no data
  ("blind: no data"), no rules ("blind: no content").
- **Summary**: techniques, % runnable, firing now, events detected, blind spots; filter by tactic.
- **Fix-it links**: a blind technique links to the data source to enable or to Red Swarm to test it.

## 5. Data engineering view ("router" idea, our own name later)

Event filters done 2026-11-11 (agent): Sysmon event 5 not collected; Security 4688 not collected
where Sysmon is installed (Sysmon 1 has it); a group configuration's own filter is kept. On the dev
PC that is about half the Windows events (17,676 of 36,027 an hour).

Data Flow view (one picture, counts per stage): sources (agents by OS, syslog devices) ->
filter/dedup -> decode (decoders + AI learned parsers) -> enrich (GeoIP, threat intel, Risk
Fabric) -> classify (rules, Sigma, AI triage) -> destinations (ClickHouse, plus forwarding to
Splunk, QRadar, Elasticsearch, syslog; per-tenant syslog forwarding exists, the others are new).
Sub-views in one section: Data Flow, Data Readiness (section 3), ATT&CK Coverage (section 4),
value per event type, storage and cost, forwarding settings. The raw log search ("Telemetry")
stays as an investigation tool, renamed Log Search.

Then:
- a pipeline view: received → decoded → matched rules → stored, with volumes per stage;
- a value score per event type (how often it leads to an alert), with suggested filters the
  tenant admin approves; storage and cost saved shown.

## 6. UEBA (user and entity behaviour) — new capability

Baselines per user and host (logon hours, hosts used, privilege use, data volume) and alerts on
deviations; feeds the posture score and Risk Fabric. Larger piece of work.

## 7. Small extras

Security news feed (from the threat-intel feeds), starred items, incident board (cases by
status), reference knowledge base.

## 8. Predictive Posture: parts still to build

Daily AI summary per report (tenant AI switch respected), "Create case" pre-filled from a report,
per-tenant component weights.

## Order

1. Threat Center home (1) with the sidebar regrouped (2).
2. Data readiness score (3), then ATT&CK coverage (4), which uses it.
3. Posture remaining parts (8).
4. Data engineering view (5), after the event filters are approved.
5. UEBA (6), then the extras (7).
