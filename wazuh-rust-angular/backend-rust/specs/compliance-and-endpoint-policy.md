# Compliance frameworks and endpoint control policies (per tenant)

Status: plan (2026-11-16, revised the same day). Asked by the owner after the scrum master and
the client (Oman) asked for:

1. compliance frameworks a tenant admin adds and chooses (any framework, e.g. the one the client is audited against),
   pushed to that tenant's agents so they run only those checks, with the full life cycle;
2. the tenant's own endpoint rules: block websites, block applications (e.g. ChatGPT not
   allowed), and alert when someone tries.

Revisions (owner, 2026-11-16): **both agents, Windows and Linux, cover everything**; and
**nothing framework-specific is built in for any one country or client**. Any framework (Oman
ITA or any other) is added by the tenant admin by **uploading its document**; ProVigil turns
it into controls, maps them to checks (creating new checks where none exist), and applies them
on the agents (section 3.4).

Design choices were made here (owner delegates them); each has its reason in section 14.

## 1. What exists today, and what is missing

| Area | Today | Missing |
|---|---|---|
| Frameworks | Six, fixed in code (`compliance.rs` `FRAMEWORKS`): PCI DSS, HIPAA, NIST 800-53, GDPR, SOC 2, ISO 27001 | Adding any other framework needs a code change and a release |
| Tenant choice | Profile (`siem_compliance_profile`): frameworks reported on, groups in scope, checks not needed | It only filters the **report**. Every agent still runs **every** check |
| Windows checks | ProVigil's own YAML policies compiled into `provigil-agent` (`src/sca/policies`), checks tagged with frameworks | No tenant checks, no "run only these" |
| Linux checks | `siem-agent-linux` `sca.rs`: a few fixed checks plus CIS YAML files read from disk, own simpler rule reader | Different dialect from Windows, no framework tags, no tenant checks |
| Settings push | Windows: group settings with each connection, last copy kept (`data/group_config.json`, `GROUP_FIELDS` in `provigil-agent/src/config.rs`). Linux: local `agent.conf` / `agent-config.json` only | Linux has no central push |
| Life cycle | Score, failing checks, alerts per requirement, printable report | No exceptions with approver and expiry, no history, no evidence pack, no tasks, no rollout status, no reporting deadlines |
| Endpoint rules | Response actions after an alert: Windows `siem-active-response` (block IP, kill, quarantine, isolate), Linux `execd.rs` (nft/iptables block, kill, quarantine, disable account) | No standing "never allowed" site or app rule, no attempt alert |

## 2. Words used

- **Framework pack**: a standard as data. A tree (function → category → control, any depth), and
  for each control the evidence that proves it (section 3). Built-in or imported by the tenant.
- **Control**: one requirement (e.g. "remote access requires multi-factor authentication").
- **Evidence source**: what proves a control (seven kinds, section 3.2).
- **Crosswalk**: "control X of framework A = control Y of framework B". A control mapped to a
  NIST CSF or ISO 27001 control inherits all evidence already mapped to it.
- **Obligation**: a duty with a deadline triggered by an event (e.g. report an incident to the
  national CERT within N hours). Part of a pack.
- **Endpoint policy**: a site rule or an application rule, in **monitor** (alert only) or
  **enforce** (block and alert) mode.
- **Policy bundle**: everything one agent group must run: the checks, the tenant's own checks,
  the endpoint rules. Versioned by hash, signed, pushed. The same format for both agents.

## 3. The framework engine (what makes any framework possible)

### 3.1 Is it possible? Yes, with one honest limit

Any framework can be added as data: its structure, its controls, and how each is proven. The
limit is that **no tool makes an organisation compliant or certifies it**. ProVigil proves the
**technical** controls automatically (configuration, detection, blocking, logging, response
times) and collects **evidence** for the rest (policies, training, governance: manual controls
with uploads and sign-off). The result is audit readiness: a live status per control and an
evidence pack the auditor accepts or questions. The page says this plainly.

### 3.2 Seven kinds of evidence per control

| Kind | Proves | Example | Checked by |
|---|---|---|---|
| Configuration check | a setting on each PC or server | password length ≥ 14, firewall on, disk encrypted | agents (both) |
| Detection | that the attack or misuse is watched for | "brute force on logins" rule enabled and alerts handled | the rules, `siem_alerts`, case times |
| Endpoint policy | that a forbidden use is blocked | unapproved software blocked | Part B |
| Platform fact | something ProVigil measures about itself | logs kept ≥ 180 days, ≥ 95 % of PCs reporting, critical alerts answered within 4 h, critical CVEs patched within 30 days, data stored in-country | computed by siem-api from its own data |
| Manual attestation | a person confirms, repeating | "incident response plan reviewed this year" | sign-off with name, date, next due |
| Document | a file shows it | the signed security policy PDF | upload, hash kept |
| Crosswalk | another framework's control already proves it | an uploaded framework's control → NIST CSF PR.AC-7 | resolved by the engine, transitively, no loops |

A control's status is one of: **met**, **partly met** (some evidence met), **not met**,
**accepted risk** (exception), **evidence due** (manual, overdue), **not assessed** (no
evidence mapped yet). Each status also shows how it is known: **direct**, **via crosswalk**, or
**manual**. Someone reading it then knows how strong the claim is.

### 3.3 Built-in reference packs

- **NIST CSF 1.1 and 2.0**: functions, categories, sub-categories, with NIST's own published
  mapping (informative references) to NIST SP 800-53, which our checks already carry. This is
  the reference most national and sector frameworks align to (used for mapping, step 4 of 3.4).
- **NIST SP 800-53, PCI DSS, HIPAA, GDPR, SOC 2, ISO 27001**: today's six, moved from code
  into packs with the same scores (checked before and after, nothing lost).
- **CIS Controls v8**: control ids, which our policies' checks are organised around.
- **Copyright**: ISO 27001 and PCI DSS texts belong to their publishers. Packs carry the control
  **ids and our own short titles**. A tenant who holds the standard may paste the official text
  into its own copy. NIST texts are public and are included.

### 3.4 Adding any framework: upload its document, its rules get applied

Nothing country- or client-specific is built in. The same seven steps serve Oman ITA, a
central bank's rules, a company's internal security standard, or anything else.

**Step 1: Upload.** Tenant admin → Compliance frameworks → **Add framework**. Accepted: PDF,
DOCX, XLSX, CSV, or pasted text; up to 50 MB, 1,000 pages. The file is kept as the source
(hash, uploader, date), so every control can point back to its page.

**Step 2: Read the controls out of it.**

- **Spreadsheet / CSV**: the admin picks which columns are the id, title, text and parent
  (remembered per file layout). Exact, no guessing.
- **PDF / DOCX**: the text is extracted with page numbers. Controls are found by their
  numbering (`1.2.3`, `PR.AC-1`, `A.5.1`, `OM-IAM-04`...) and headings, which gives the tree
  (function → category → control). If the tenant's AI is on, it also reads each section and
  proposes the controls with their page. Both are only proposals.
- **Review screen**: the document page on one side, the controls found on the other. The admin
  fixes, merges, splits, adds or deletes controls before going on. Each control keeps its
  **source page and paragraph**.

**Step 3: Sort each control.** Proposed, the admin confirms:

- **technical**: can be checked on machines or measured by ProVigil;
- **procedural**: policy, training, governance, so it needs a manual attestation or a document;
- **obligation**: a duty with a deadline ("report incidents within N hours").

**Values** in the text are picked out and become the control's parameters: "at least 12
characters", "locked after 10 minutes", "kept 12 months", "within 72 hours". Changing the
number later changes the check, not the mapping.

**Step 4: Find what proves each control.** For each technical control, the **mapping screen**
shows the control text and its page, then the suggested evidence, each with a confidence and
the reason:

- **existing checks** from the full check library (every check of every ProVigil policy, with
  its title, description and tags, Windows and Linux), found by text similarity and the AI;
- **reference controls** (NIST CSF, NIST 800-53, CIS, ISO 27001 ids). Kept built in only as
  **reference libraries for mapping**, never as a client's framework. Mapping to one brings
  every check already linked to it;
- **detection rules** already in ProVigil (e.g. a "monitor privileged logins" control → the
  rules that watch them);
- **platform facts** (log retention, agent coverage, response times, patch times);
- **endpoint policies** (a "no unapproved software" control → an application rule).

**Step 5: Create the checks that don't exist yet.** When nothing covers a technical control, a
**new check** is drafted in our check language: by the AI from the control text and its
parameters, or written by the admin with a form (setting, file, registry value, service,
package, permission). There is one per OS where it applies, e.g. "screen lock ≤ 10 minutes":
a Windows registry check and a Linux desktop setting check. Before it can be approved:

- it is **dry-run** on a pilot machine of each OS, showing pass / fail / not applicable and what
  it read;
- it is checked by the safety rules (section 7): read only, no commands unless that agent opted
  in.

Missing detections are listed as gaps (and can be drafted the same way as a rule, reviewed in
the Rules page).

**Step 6: Approve.** Nothing is used until a person approves each mapping and each new check
(optionally a second person: tenant setting). The screen shows the **coverage**: "52 controls:
31 checked automatically, 6 measured by ProVigil, 12 need evidence, 3 obligations, 0 not
covered". The coverage is computed from the approvals, never estimated.

**Step 7: Apply.** Publishing makes it a framework **version**. The admin adopts it and picks
the groups in scope (section 4). ProVigil builds each group's bundle with exactly the checks
this framework (and the others adopted) need, including the new ones, and pushes it to the
Windows and Linux agents. Results come back per control: the live status and the evidence pack
from then on.

**A new edition of the document**: uploaded as a new version of the same framework. Unchanged
controls (same text) keep their approved mappings. Changed and new ones go through steps 3–6
alone. A diff shows what changed, both versions are scored side by side, then the admin
switches.

**Without AI** every step still works: spreadsheets map columns exactly, PDF numbering
detection still finds the controls, similarity still suggests checks, and the admin writes
missing checks with the form. The AI only saves time. Its use follows the tenant's AI switch
and hourly budget, and documents go only to the provider the tenant configured.

**Honest limit, shown on the page**: technical controls are proven automatically; procedural
ones are evidenced. The result is audit readiness, not a certificate.

### 3.5 Obligations (regulatory deadlines)

A pack can carry obligations: `{trigger, deadline_hours, recipient, template}`. Examples:
"confirmed incident of severity high or above → report to the national CERT within N hours", or
"personal data breach → notify the authority within N hours". The tenant sets N from the
official text. When a case meets the trigger (case resolved as true positive at that severity,
or tagged `personal-data`), the case gets a **reporting timer**. The report is pre-filled from
the case (what, when, hosts, actions taken) and appears in the case page. Sending it is marked
with time and person. Overdue reports raise an alert, and the evidence pack lists every
obligation met or missed.

## 4. Part A: compliance life cycle

| # | Stage | What happens | Page (tenant admin unless noted) | API | Stored in |
|---|---|---|---|---|---|
| A1 | Catalog | Built-in and uploaded frameworks, version, controls, coverage | Compliance frameworks → Catalog | `GET /api/v1/compliance/catalog` | `ndr.compliance_packs` (shared, read only) / tenant `compliance_packs` |
| A2 | Upload | The framework's document (PDF / DOCX / XLSX / CSV / text); controls read out and reviewed with their source page (3.4 steps 1–3) | Catalog → Add framework | `POST /api/v1/compliance/documents`, `GET/PUT /api/v1/compliance/documents/:id/controls` | tenant `compliance_documents`, `compliance_packs` |
| A3 | Map and create checks | Mapping screen, new checks with dry run, approval, coverage (3.4 steps 4–6) | Catalog → Map | `GET/PUT /api/v1/compliance/packs/:id/mappings`, `POST /api/v1/compliance/checks/dry-run` | tenant `compliance_mappings`, `compliance_custom_checks` |
| A4 | Adopt | Choose the frameworks the organisation must meet | Frameworks → Adopt | `PUT /api/v1/compliance/profile` (extended) | `siem_compliance_profile` |
| A5 | Scope | Per framework, the agent groups it covers (Windows and Linux groups alike) | Frameworks → Scope | same | same |
| A6 | Tailor | Controls not applicable (with reason), parameters (password length 12 or 14), obligation deadlines | Frameworks → Tailor | same | same |
| A7 | Deploy | Per group, the union of checks the frameworks in scope need, pushed to both agents; status per agent: pending / applied / failed + reason | Frameworks → Deployment | `GET /api/v1/policy/rollout` | `policy_bundles`, `policy_rollout` |
| A8 | Assess | Agents run their checks on schedule and "scan now", send changes only; platform facts computed hourly | Compliance (analyst) | `GET /api/v1/compliance` | `siem_sca_checks` (exists), `compliance_facts` |
| A9 | Score | Per framework, control, host: status (3.2) with how it is known | Compliance (analyst) | same | ClickHouse aggregates |
| A10 | Remediate | A failed control opens a task with the fix text on the failing hosts; closed by the next passing scan | Compliance → Fix queue | `POST /api/v1/compliance/tasks` | `soar_cases` tag `compliance` |
| A11 | Exceptions | Accepted risk with reason, approver, expiry; expired ones fail again. Replaces "checks not needed" (migrated, nothing lost) | Compliance → Exceptions | `POST/DELETE /api/v1/compliance/exceptions` | `compliance_exceptions` |
| A12 | Manual evidence | Attestations and documents with due dates and reminders | Compliance → Evidence | `POST /api/v1/compliance/evidence` | `compliance_evidence` + attachments |
| A13 | Obligations | Reporting timers on cases (3.5) | Case page | `GET /api/v1/compliance/obligations` | `compliance_obligation_runs` |
| A14 | Drift | Met → not met raises a "compliance drift" alert, grouped like all alerts | Alerts / cases | — | `siem_alerts` |
| A15 | History | Daily snapshot per framework (version, score, statuses) | Compliance → Trend | `GET /api/v1/compliance/history` | `compliance_snapshots` |
| A16 | Evidence pack | Per framework for the auditor: scope, version and source document, statuses and how known, hosts, exceptions with approvers, obligations, attestations, documents, related alerts, SHA-256 of the pack | Compliance → Export | `GET /api/v1/compliance/evidence-pack?framework=` | generated |
| A17 | Review / retire | Quarterly attestation reminder; new pack version side by side then switch; dropped framework stops being pushed | Frameworks | profile | same |

## 5. Part B: endpoint control policies

### 5.1 What the tenant admin writes

| Rule type | Matches on | Example |
|---|---|---|
| Site rule | domain (and sub-domains), URL pattern, preset | `chatgpt.com`, `*.openai.com` |
| Application rule | name, path, SHA-256, signer / package, product name | `ChatGPT.exe`, signer "OpenAI", a snap or flatpak id |
| Preset | a named list we maintain | "Generative AI": ChatGPT, Claude, Gemini, Copilot web and desktop apps |

Each rule has: mode **monitor** / **enforce**; scope (groups, or all, Windows and Linux
alike); allowed users or groups; the message shown when blocked; and the compliance controls it
satisfies (it then counts as evidence in Part A).

### 5.2 Enforcement on each agent

| Layer | Windows (`provigil-agent`) | Linux (`siem-agent-linux`) |
|---|---|---|
| Sites 1: browser policy (main) | Edge, Chrome, Firefox enterprise policy in the registry: URL block list, private DNS (DoH) off | the same browsers' managed policy files (`/etc/opt/chrome/policies/managed/`, `/etc/opt/edge/policies/managed/`, `/etc/chromium/policies/managed/`, Firefox `policies.json`) |
| Sites 2: name resolution | an agent-owned section of the hosts file, between markers | the same in `/etc/hosts` |
| Sites 3: strict (off by default) | Windows firewall rules on addresses resolved every 10 min | an nftables set refreshed every 10 min (the agent already uses nft / iptables) |
| Site attempt detection | DNS lookups: Sysmon event 22 (process, user) or the Windows DNS client log, switched on by the agent where Sysmon is absent | DNS lookups read by the agent from the network (port 53, root), the process found from its socket where possible |
| Apps 1: prevent | the program name redirected to ProVigil's blocker (message, event, exit). Every edition including Home | exec permission check (fanotify `FAN_OPEN_EXEC_PERM`, kernel 5.0+): refused before it runs, by path or hash |
| Apps 2: stop by identity | process starts watched, matching hash / signer / product stopped at once | process starts watched (process events from the kernel; audit as fallback), matching ones stopped at once; snap / flatpak by package id |
| Apps 3 (later, P6) | Windows App Control deny policy on Pro / Enterprise / Education | — (layer 1 already prevents) |
| Tamper | tamper protection (exists) watches the hosts section, registry policies, the blocker | file watch on `/etc/hosts`, the policy files and the agent's files |

**Monitor mode** runs only the detection. Same events, no block, so the impact is visible
before switching to enforce.

**Limits** (shown in the UI): local administrators (root) and personal VPNs can work around web
blocking. Tamper alerts then show it. Portable browsers are covered by application rules.

### 5.3 The alert

Policy events become alerts of our own rule group `endpoint_policy`, ids from our own range
(chosen free in P3):

- "Blocked site attempt: chatgpt.com by ACME\\jdoe in msedge.exe on PC-17 (12 times)", level 5;
- "Blocked application attempt", level 6;
- "Policy removed or changed on the endpoint" (tamper), level 12;
- "Policy could not be applied", level 7.

Monitor mode uses level 3. They follow the alert life cycle (incidents per PC and rule,
exceptions, metrics). The policy page shows top blocked sites and apps, by user and group, with
the trend.

### 5.4 Endpoint policy life cycle

Draft → **monitor** on a pilot group → review impact → **enforce** on the pilot → widen
(staged) → watch attempts and tamper → edit or retire. Every change goes in the decision log
(who, when, before / after). A tenant-wide **"stop enforcing"** switch puts every rule in
monitor within one keepalive.

### 5.5 Built (2026-11-17): custom site and application rules, Windows

| Part | Where | What |
|---|---|---|
| Rule format, checks, matching | `provigil-agent-server/src/endpoint_policy.rs` | site (domain, sub-domains included), app (file name or `sha256:`), safe search; monitor / enforce; groups and OS scope; refused: system and ProVigil programs, whole country domains (`co.uk`...), addresses, local names, more than 200 rules or 5,000 entries a rule |
| Storage, API, attempt alerts | `siem-api/src/endpoint_policy.rs` | `endpoint_policies` (main database, key tenant + id) and `endpoint_policy_changes` (who, when, before, after); `GET /api/v1/endpoint-policies` (rules, presets, agents' state), `PUT` / `DELETE /api/v1/endpoint-policies/:id` (tenant admin); alerts 940300 site, 940301 application, 940303 could not apply, 940304 changed on the computer, from Sysmon 22, Sysmon 1 / 4688 and the agent's `provigil_policy:` lines, once an hour per agent, rule, target and person |
| Delivery | `provigil-gateway/src/cache.rs`, `core.rs` | rules read with the other cached tables; each agent's added to its group settings (`endpoint_policies`), in the settings version |
| Enforcement | `provigil-agent/src/endpoint_policy.rs` | hosts file section (domain and `www.`), browser DNS settings so the hosts file is used, strict: browser block lists; programs: Windows starts `provigil-agent.exe --blocked <rule>` in their place (message box), renamed ones stopped by SHA-256 within 2 s; safe search; every value restored when the rule goes; re-applied every 10 minutes, changes reported as tamper |
| Page | console: tenant admin → Endpoint Policies | rules list, editor (paste or upload a list, also hosts-format lists), presets, computers' state |

Decisions made while building:

- **Site enforcement default is the hosts file, not the browsers' block lists**: a browser that blocks
  by its own list never looks the name up, so the attempt would never be seen. The hosts file
  keeps the lookup (Sysmon 22 sees it) and makes it lead nowhere. Wildcards and paths need the
  browsers' lists: the rule's **strict** option, with that trade-off said on the page.
- **The blocker is the agent itself** (`--blocked`), so nothing new has to be installed.
- **Rules stored in the main database** (key tenant + id), like the deployment tokens, because
  the gateway reads it there; every API call filters by the caller's tenant.

**Whole categories (e.g. adult sites)**: browsers accept at most 1,000 block-list entries, and a
hosts file with hundreds of thousands of names slows Windows name lookups. So a category is not a
list pushed to every PC. Built now: the tenant pastes or uploads any list it holds (hosts-format
lists work), plus forced safe search. ProVigil ships no such list. Next (planned): a **filtering
DNS** option per rule: the agent points the computer's DNS at a filtering service the tenant
picks (e.g. a family-safe resolver, or their own), keeps the organisation's internal domains
going to their own DNS servers, and the attempt is seen as a lookup answered "blocked". To be
built and tried on a test VM, not the development PC.

**Linux agent** (built 2026-11-17, owner's approval; `siem-agent-linux/src/endpoint_policy.rs`):
fetches the group settings (`GET /api/v1/agents/:id/config`) every 5 minutes and keeps the last
rules for starts without the manager. Sites: its `/etc/hosts` section points blocked names (and
`www.`, IPv4 and IPv6 forms) at `127.65.43.21`, where the agent listens on ports 80 and 443: it
reads the site from the Host header or the TLS server name and the person from `/proc/net/tcp`,
answers http with a "blocked" page, and reports `site_attempt`; managed policy files for Chrome,
Chromium and Edge (private DNS off, strict block lists, safe search); Firefox's only when the
computer has none of its own. Programs: new processes checked every second by file name or
SHA-256, stopped in enforce mode, reported (`app_attempt`) in both modes. Files re-checked every
10 minutes, tamper reported. The server reads these reports in its event ingest (Linux events do
not go through the archive). Limits: no monitor-mode site detection on Linux yet (no DNS log
like Sysmon's); programs are stopped just after starting, not refused before (the kernel's exec
permission check waits for a test machine, because a mistake there can stop every program start).

Not yet: the filtering DNS option, Windows App Control policies (P7).

## 6. One policy core for both agents

A new shared crate **`provigil-policy`**, used by both agents, so both behave the same:

- the bundle format, its schema and size checks, the signature check;
- the check rule dialect (`r:`, `f:`, `d:`, `p:`, `c:`, content patterns, conditions), moved
  from `provigil-agent/src/sca/mod.rs` with its tests. Each OS supplies only the probes
  (registry on Windows; files, `/proc`, `sysctl`, commands on Linux);
- site and application matching (domain suffix sets, hash sets, name sets) and the safety rules
  (section 7);
- the policy event builder and its counting (one event per user, rule, process per 10 minutes).

Linux agent work (in `siem-agent-linux`, done with its developer, each change agreed with the
owner):

- receive group settings like Windows does (the manager already serves them), keep the last
  good copy;
- use `provigil-policy` for checks instead of its own reader. Its current fixed checks become a
  ProVigil Linux policy file, so nothing is lost;
- enforcement layers of 5.2 and the policy event.

ProVigil's own Linux policies (Ubuntu, Debian, RHEL family) replace the CIS files the agents
read today, as part of the own-ruleset work (`provigil-analysisd.md` section 4).

## 7. Safety rules (a policy can never break a PC or blind ProVigil)

Refused when saved, and again on the agent:

- matching the ProVigil manager addresses, update servers, or ProVigil's own programs;
- matching core system programs (Windows: `explorer.exe`, `svchost.exe`, `lsass.exe`,
  `winlogon.exe`, anything under `C:\Windows\System32`; Linux: `/sbin/init`, `systemd`,
  `sshd`, anything under `/usr/lib/systemd`, the package manager), a whole drive or folder;
- wildcards too wide (`*`, `*.com`), regexes that can run too long, more than 5,000 rules per
  tenant;
- tenant-written checks that run commands, unless that agent opted in with
  `allow_remote_commands` (existing Windows safeguard; the same flag on Linux).

## 8. Delivery: the policy bundle

- Built **per (tenant, group)** when anything it depends on changes. Cached by version
  (SHA-256 of the content).
- Pushed with the group settings. New Windows group fields `sca_only_checks`,
  `sca_custom_policies`, `endpoint_policies`, `policy_bundle_version`, `policy_signature`; the
  same names on Linux.
- **Signed** (Ed25519, control plane key, public key pinned by the agent at enrollment). A bad
  signature is refused.
- **Atomic apply** with rollback to the last good bundle, reported as `apply_failed` with the
  reason. The last good bundle is kept on disk and enforced offline and after restarts.
- **Reconciled** every 10 minutes: re-applies, reports drift (the tamper alert).
- **Staged**: pilot group first, then the rest after a hold time or on a click. A bundle failing
  on more than 20 % of the pilot stops by itself.
- **Only the checks needed**: frameworks in scope → controls → crosswalks → check ids, united per
  group.

## 9. Data (tenant database unless marked)

| Table | Content | Key |
|---|---|---|
| `ndr.compliance_packs` (shared) | built-in packs, versions | (pack_id, version) |
| `compliance_packs` | imported packs | (pack_id, version) |
| `compliance_documents` | uploaded source: file hash, name, pages, extracted text per page, uploader | id |
| `compliance_mappings` | control → evidence, approved by, at | (pack_id, version, control) |
| `compliance_custom_checks` | checks created for controls: per OS, rule text, parameters, dry-run results, approved by | (check_id, version) |
| `siem_compliance_profile` (exists) | adopted, scope, tailoring, deadlines | id |
| `compliance_exceptions` | target, scope, reason, approver, expires_at | id |
| `compliance_evidence` | attestations and documents, due dates | id |
| `compliance_facts` | platform facts per hour | (fact, hour) |
| `compliance_obligation_runs` | case, obligation, due, done_at, by | (case, obligation) |
| `compliance_snapshots` | day, framework, version, score, statuses | (framework, day) |
| `endpoint_policies` | rules | id |
| `policy_bundles` | group, version, JSON, signature | (group, version) |
| `policy_rollout` | agent, version, state, reason | agent |

ReplacingMergeTree with a version column, replicated like the other tenant tables. Everything
in ClickHouse, no files (storage rule). Agent check results stay in provigil-db and are copied
for compliance as today.

Policy event (both agents send the same):

```json
{"type":"policy","rule_id":"pol-7","kind":"site|app|tamper|apply_failed","mode":"enforce",
 "target":"chatgpt.com","user":"ACME\\jdoe","process":"/usr/bin/firefox","parent":"...",
 "hash":"sha256","count":12,"first":1794829411,"last":1794830011,"bundle":"<version>","os":"linux"}
```

## 10. Scalability

Sized for 50 tenants × 2,000 agents = 100,000 agents (today 500 per tenant):

- bundles built per group on change, cached by version. Agents download only when the version
  differs, spread by the existing splay;
- agents send only changed check results. "Only checks needed" cuts checks per agent to the
  frameworks in scope;
- policy events counted on the agent, so 10,000 retries are one event with `count: 10000`;
- scores, facts and trends are ClickHouse aggregates per tenant database, never held in memory.
  Daily snapshots keep history queries small;
- crosswalks resolved once per pack version and cached;
- matching on the agent is O(1) per DNS lookup or process start (hash sets, suffix walk), so
  5,000 rules cost nothing.

## 11. Reliability

- Enforcement runs on the endpoint. It does not depend on the manager.
- Atomic apply, rollback, last good bundle, reconcile loop, idempotent steps (the agent touches
  only its own marked hosts section, its policy files and the registry values it lists).
- Rollout state per agent with the reason. Auto-stop on a failing pilot.
- The same `provigil-policy` tests run for both agents. Windows and Linux test VMs (not the dev
  PC) for each layer in monitor and enforce. A load test of bundle pushes to 2,000 simulated
  agents (`provigil-loadtest`). Pack migration test: today's six frameworks give the same
  scores from packs.

## 12. Security

- Only the tenant admin edits packs, mappings, exceptions, deadlines and policies. Analysts
  read. Every change goes in the decision log.
- Optional second approver for enforce on more than 50 agents, for "stop enforcing", and for
  approving mappings (tenant setting).
- Tenant isolation: packs, mappings, rules, bundles in the tenant's database. Agents get only
  their own tenant's group bundle.
- Signed bundles, pinned key, schema and size checks on the agent.
- Imports: 2 MB limit, strict YAML / CSV without aliases, every field length-checked, never
  executed. AI suggestions are only suggestions; the AI never maps or approves.
- The blocker, the policy files and the agent are covered by tamper protection.
- User-facing messages: plain text, no markup or links, at most 300 characters.

## 13. Availability

- Agents keep enforcing, and keep events in their buffer, while the manager is down.
- In the cluster design (`provigil-cluster.md`) the control plane builds bundles and every
  worker serves them. With the control plane down, workers serve the last bundles; only
  editing waits.
- Replicated tables. Built-in packs are also compiled into the server as a fallback.

## 14. Decisions

| # | Decision | Reason |
|---|---|---|
| D-1 | Frameworks are data (packs), not code | Any standard added by its document, without a release |
| D-2 | NIST CSF as the backbone, with NIST's published mapping to 800-53 | Most frameworks align to CSF; our checks already carry 800-53; it speeds up mapping uploaded ones |
| D-3 | Seven evidence kinds, status shows how it is known | Honest audit readiness: technical controls automatic, the rest evidenced |
| D-4 | No client- or country-specific framework built in; every framework comes from an uploaded document, versioned | Owner's direction; one path for every standard; each control traceable to its page |
| D-5 | Mappings and new checks only by human approval (new checks after a dry run); AI and text similarity only suggest; everything works without AI | An auditor needs a person accountable; AI may be off or out of budget |
| D-6 | Obligations with tenant-set deadlines | We don't know the official hours; the tenant takes them from the text |
| D-7 | Pack texts: ids and own titles for copyrighted standards | ISO and PCI texts belong to their publishers |
| D-8 | Agents run only the checks their groups need | What the client asked; less scan time and data |
| D-9 | One shared `provigil-policy` crate for both agents | Same behaviour, one test suite, one bundle format |
| D-10 | Reuse the group settings path (Windows), add it to Linux | Already pushes, keeps a last copy, works offline |
| D-11 | Signed bundles (Ed25519, pinned) | A bad node or anything in between can't push blocking rules |
| D-12 | Sites: browser policy first, hosts second, firewall strict optional and off | HTTPS and paths handled; address blocking hits shared cloud addresses |
| D-13 | Apps: Windows name redirect + stop by identity (App Control later); Linux exec permission check + stop by identity | Prevention on every Windows edition and Linux kernel 5.0+ |
| D-14 | Monitor mode first, always available | Impact visible before blocking |
| D-15 | Exceptions with approver and expiry replace "checks not needed" (migrated) | Auditors want accepted risk visible and time-limited |
| D-16 | Remediation as tasks, no automatic fixing in this plan | Automatic changes on customer machines are risky |

## 15. Phases (2-week sprints)

| Phase | Content | Done when |
|---|---|---|
| P1 | Framework engine: packs, versions, the seven evidence kinds, crosswalk resolution, platform facts; reference libraries (NIST CSF, 800-53, CIS, ISO ids) for mapping; today's six frameworks moved into packs (kept: no feature lost); Catalog / Adopt / Scope / Tailor pages | Same scores as today from packs |
| P2 | Document upload and control reading (spreadsheet columns, PDF / DOCX numbering, AI proposals), review screen with source pages; mapping screen; check library search | A framework uploaded as PDF and one as XLSX each produce their control tree, mapped and approved |
| P3 | `provigil-policy` crate (check dialect moved with its tests); new checks (AI draft or form) with dry run on Windows and Linux; bundle build / sign / push with custom checks, rollout status; Linux receives group settings and runs checks through `provigil-policy` | An uploaded framework's new check runs only on its in-scope groups on both OSes; a bad signature is refused |
| P3b | Exceptions with expiry (migration); manual evidence; obligations with case timers; snapshots; evidence pack with source pages; drift alert; new document version with diff | A true-positive case gets its reporting timer; the evidence pack opens and its hash checks; re-uploading a changed edition keeps unchanged mappings |
| P4 | Site rules on both agents: browser policy, hosts section, DNS attempt detection, monitor / enforce, alerts, policy page, presets | chatgpt.com blocked in Edge / Chrome / Firefox on Windows and Linux test VMs; attempt alert with user and process |
| P5 | Application rules on both: Windows blocker + stop by identity, Linux exec permission + stop by identity; Generative AI preset; tamper reconcile; dashboard | ChatGPT blocked by name and when renamed on both; tamper alert when the hosts section is edited |
| P6 | Staged rollout, "stop enforcing", second approver, load test 2,000 agents, feature guide | Load test within limits; guide updated |
| P7 (later) | Windows App Control policies | — |

About 7 sprints for P1–P6 (document upload and check creation add one). Against v1.0 (27 Jan
2027) this needs the scrum master's call: e.g. P1–P3 in v1.0, so an uploaded framework runs on
both agents, and P3b–P6 right after.

## 16. Open questions for the client

1. Any framework document they want to try first (any format), to test the upload with a real
   one; its deadlines (for obligations) come from that document.
2. The message users see when blocked, and whether users may ask for an exception from it.
3. Windows editions and Linux distributions / kernel versions on their machines (decides P7 and
   the Linux kernel 5.0 requirement).
