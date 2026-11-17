# UEBA: user and entity behaviour analytics — plan

Written 2026-11-17. A plan to agree before building. Nothing here is built yet.

## 1. What it is, and why ProVigil needs it

Rules and Sigma catch known attacks. UEBA catches what rules cannot: a real account doing
something it never does (stolen password, insider, compromised PC). It learns what is normal
for each user and each computer, then raises the unusual, scored and explained.

Example: user `ravi` normally logs on 09:00–18:00 to `pc-17` and `fs-01`, runs Office and
Chrome, sends ~200 MB a day. At 02:10 he logs on to 14 servers, runs `procdump.exe`, and
uploads 6 GB to a site no one in the company has used. No single rule fires; UEBA sees five
anomalies on one user within an hour and raises one high-risk finding.

## 2. How the leading platforms do it (research, Nov 2026)

| Platform | What they do | What we take |
|---|---|---|
| Microsoft Sentinel UEBA | Per-event "investigation priority" 0–10 from entity rarity (user, device, country) plus a time-series part (spikes such as failed sign-ins); user pages show the top anomalies of 30 days and a timeline | Rarity + time-series scoring; entity page with top anomalies; first-time events matter even when common |
| Exabeam | Baselines per user and device, compared with the user's **peer group** and the whole company; risk accumulates and escalates past a threshold; **Smart Timelines** stitch normal and abnormal events, mapped to MITRE | Peer groups; accumulating entity risk; the timeline as the main investigation view |
| Splunk UBA | Models → **anomalies**; anomalies tied to a use case → **threats** (e.g. data exfiltration); rare-event and time-series models; baseline from own history, peer groups (AD groups, OUs, behaviour clusters, device groups) and company-wide; outliers vs. a trimmed moving average | Two levels (anomaly, threat); peer group types; robust baselines that ignore extremes |
| Elastic entity analytics | Host, user and service **risk score 0–100** as a weighted sum of alerts and asset criticality, recalculated on a schedule; anomalies from ML jobs listed per entity | One 0–100 risk score per user and host that also counts normal alerts; asset criticality as a multiplier |

Common to all: (1) baselines per entity, (2) comparison with peers and the organisation,
(3) "first time / rare" plus "spike" models, (4) a risk score per entity that accumulates and
decays, (5) anomalies grouped into threats, (6) an entity page with a timeline.

Where ProVigil can be better than them:
- **Explainable**, not a black box: every anomaly says in one sentence what was unusual and
  compared with what ("first logon to `fs-02` in 30 days; none of his peers use it").
- **One platform**: endpoint (EDR), logs (SIEM) and network (NDR) feed the same profile —
  most UEBA products see only logs.
- **Works from day one**: peer and company baselines cover a new user while their own is
  learning; a visible "learning 12/30 days" status instead of silent false positives.
- **Connected to what exists**: Risk Fabric criticality, posture score, triage, SOAR, cases,
  AI guardrails, security memory.
- **Per tenant and cheap**: computed in ClickHouse with aggregates (no extra ML servers).

## 3. What ProVigil already collects (checked in tenant `acm`, 1.77 M events)

| Behaviour | Source (already arriving) |
|---|---|
| Logons, failures, logon type, source IP | Security 4624, 4625, 4634, 4648, 4672 (special privileges), 4740 (lockout); Linux auth.log, sudo |
| Account and group changes | Security 4720, 4722, 4724, 4728, 4732, 4756; look-ups 4798 / 4799 |
| Programs run (who, parent, command line, hash) | Sysmon 1, Security 4688 |
| Network connections, DNS | Sysmon 3, 22; NDR flows (bytes, destinations, countries) |
| Files created, deleted, changed (who) | Sysmon 11, 23, 26; FIM who-data |
| PowerShell | 4103, 4104, 400/600/800 |
| Registry and persistence | Sysmon 12/13/14; registry monitoring |
| Web and app policy attempts | endpoint control policies |
| Users and groups of each PC, software | inventory (agent database) |
| VPN, firewall, cloud sign-ins | syslog devices |

Events are stored as full Windows JSON (`win.eventdata.*`), so ClickHouse can extract user,
host, process and destination without changing the agents.

## 4. Design

### 4.1 Entities
User (domain\name, normalised; service and system accounts tagged), host (agent), source IP,
application (process image / hash), destination (domain, IP, country). Later: NDR devices.

### 4.2 Activity table (per tenant, ClickHouse)
`ueba_activity`: time, user, host, action (logon, logon_fail, process, net_out, dns, file_write,
file_delete, priv_use, group_change, policy_attempt, …), object (process, domain, file
extension, target host), value (bytes, count), src_ip, country, extra. Filled from events as
they are stored (a ClickHouse materialized view or siem-api's ingest path), so nothing is
re-read later. Retention 90 days (configurable).

### 4.3 Baselines (daily, in ClickHouse)
Per user and per host, rolling 30 days, robust statistics (median and spread, extremes
ignored):
- logon hours and weekdays; hosts used; source IPs and countries; logon types
- programs run; admin / special-privilege use
- data out (bytes), files written / deleted, DNS volume and distinct domains
- failed logons; accounts and groups looked up
- per host: users seen, listening/outbound destinations, programs
Peer groups: agent group, network segment (VLAN), the local/AD groups from inventory,
and (phase 3) behaviour clusters. Company-wide baseline for everything.

### 4.4 Models (explainable, each its own switch and sensitivity)
| # | Model | Kind | Example |
|---|---|---|---|
| M1 | First logon to a host / from a country / with an unusual logon type | first-time | RDP to a server never used |
| M2 | Logon at unusual hours | time profile | 02:10 when normal is 09–18 |
| M3 | Failed-logon spike, password spray (one source, many users), lockouts | spike | 40 failures in 5 min |
| M4 | Lateral movement: one account on many hosts in a short time | spike + first-time | 14 hosts in 20 min |
| M5 | Rare program for this user / host / peer group (by name and hash) | rarity | `procdump.exe`, `rclone.exe` |
| M6 | Privilege: special logon, added to an admin group, new local admin | first-time | 4728 into Domain Admins |
| M7 | Data out spike and first-time destination | spike + first-time | 6 GB to a new site |
| M8 | Mass file activity: many writes/deletes/renames, new extensions | spike | ransomware-like |
| M9 | Reconnaissance: many account/group look-ups, discovery commands | spike | 4798 × 300 |
| M10 | Service account used interactively; dormant account active again | rule + history | |
| M11 | Impossible travel (VPN / cloud sign-ins with location) | geo | Kochi then Frankfurt in 30 min |
| M12 | Unusual DNS: many new domains, long random names, new TLDs | rarity + spike | possible C2 / tunnelling |
| M13 | Repeated blocked web / app attempts | spike | from endpoint control |

### 4.5 Scores
- **Anomaly score 0–100**: how far from normal × how rare among peers and company ×
  confidence (days learned).
- **Entity risk score 0–100** per user and host: anomalies plus the entity's normal alerts,
  weighted by Risk Fabric criticality, decaying over days (an old anomaly fades).
- Above the tenant's threshold → a **UEBA alert** (own rule number range, e.g. 930000–939999,
  MITRE-tagged) that goes through suppressions, triage, SOAR, cases and alert e-mails like any
  alert.

### 4.6 Threats (anomalies grouped into a story)
Anomalies of one entity grouped by use case within a window: **account compromise**
(M1+M2+M11), **lateral movement** (M4+M6), **insider data theft** (M5+M7+M13),
**ransomware precursor** (M8+M9+M5), **privilege abuse** (M6+M10). One threat = one case
candidate with its timeline.

### 4.7 AI (recommends only, tenant AI switch respected)
Plain-language explanation of an entity's anomalies and threats; suggested peer groups;
"is this normal for a developer?" context from security memory. Never changes scores alone.

### 4.8 Console
- **UEBA page**: riskiest users and hosts (score, trend, top reasons), threats, learning status.
- **Entity page** (user / host): risk over time; today vs. normal (hours, hosts, data,
  programs); anomalies with their one-line reasons; **timeline** of normal and abnormal
  events; peer comparison; inventory and vulnerabilities (host).
- **Tuning** (tenant admin): watchlist (VIPs, privileged, leavers), exclusions (service
  accounts, scanners), sensitivity per model, learning period.
- Links from alerts, investigation timeline, cases and Copilot ("show me risky users").

### 4.9 Privacy and control
Per tenant only; models and fields can be turned off; who viewed an entity page is logged;
retention configurable.

## 5. Phases

| Phase | What | Check |
|---|---|---|
| U1 | Activity table and extraction (Windows, Linux, syslog); entity list | counts match the raw events |
| U2 | Baselines (self, peer, company) + learning status | baselines for every active user and host |
| U3 | Models M1–M8 + anomaly score + entity risk score + UEBA alerts | test events per model raise exactly one anomaly; no alert storm on normal days |
| U4 | Console: UEBA page, entity page with timeline, tuning | |
| U5 | Threats (grouping), models M9–M13, AI explanations, NDR data in profiles | |

## 6. Questions for the owner

1. Active Directory: connect to AD for real departments and managers (better peer groups), or
   use agent groups, network segments and local groups only for now?
2. Default learning period: 14 or 30 days?
3. Rule number range for UEBA alerts: 930000–939999?
4. Is UEBA part of every tenant, or a licence feature?

## Sources

- Microsoft Sentinel UEBA: https://learn.microsoft.com/azure/sentinel/identify-threats-with-entity-behavior-analytics ,
  https://learn.microsoft.com/azure/sentinel/ueba-reference
- Exabeam: https://www.exabeam.com/explainers/ueba/what-is-ueba-and-why-it-should-be-an-essential-part-of-your-incident-response/ ,
  https://www.exabeam.com/ueba/behavioral-profiling/
- Splunk UBA: https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.3/splunk-uba-models
- Elastic entity analytics: https://www.elastic.co/docs/solutions/security/advanced-entity-analytics/overview
