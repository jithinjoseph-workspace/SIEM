# Compliance frameworks and endpoint control policies (per tenant)

Status: plan (2026-11-16). Asked by the owner after the scrum master and the client (Oman)
asked for: (1) compliance frameworks a tenant admin chooses (including Oman's own standards),
pushed to that tenant's agents so they run only those checks, with the full life cycle;
(2) the tenant's own endpoint rules: block websites, block applications (e.g. ChatGPT not
allowed), and alert when someone tries. Designed for scale, reliability, security and
availability. Design choices were made here (owner delegates them); each has its reason in
section 12.

## 1. What exists today, and what is missing

| Area | Today | Missing |
|---|---|---|
| Frameworks | Six, fixed in code (`compliance.rs` `FRAMEWORKS`): PCI DSS, HIPAA, NIST 800-53, GDPR, SOC 2, ISO 27001 | Adding one (e.g. Oman's) needs a code change and a release |
| Tenant choice | A profile (`siem_compliance_profile`): frameworks reported on, agent groups in scope, checks not needed | It only filters the **report**. Every agent still runs **every** built-in check |
| Checks | ProVigil configuration policies compiled into the agent (`provigil-agent/src/sca/policies`), each check tagged with the frameworks it serves | A tenant can't add its own checks, or map a new framework onto existing checks |
| Life cycle | Score, failing checks, alerts per requirement, a printable report | No exceptions with an approver and an expiry, no history (trend), no evidence pack, no remediation tasks, no rollout status per agent |
| Endpoint rules | Response actions after an alert (`siem-active-response`: block IP, kill process, quarantine file, isolate host) | No standing policy: "this site is never allowed", "this app never runs", and no "attempt" alert |
| Delivery to agents | Group settings pushed with the agent's connection, last copy kept on the agent (`data/group_config.json`, `GROUP_FIELDS` in `provigil-agent/src/config.rs`) | Reused as is. Only new fields are added (section 6) |

## 2. Words used

- **Framework pack**: a standard as data: its controls, and for each control how it is checked.
  Built-in packs ship with ProVigil; a tenant can import its own (e.g. an Oman standard).
- **Control**: one requirement of a framework (e.g. "passwords at least 14 characters").
- **Check**: one test an agent runs (registry value, file, service, audit policy...). A control
  is met when its checks pass, its alert rules stay quiet, and any manual evidence is attached.
- **Crosswalk**: "control X of this framework = control Y of ISO 27001 / NIST". An imported
  framework then inherits the checks already mapped to ISO 27001 or NIST without listing them.
- **Endpoint policy**: a tenant rule enforced on the PC: a site rule or an application rule,
  in **monitor** (alert only) or **enforce** (block and alert) mode.
- **Policy bundle**: everything one agent group must run: the checks to run, the tenant's
  own checks, and the endpoint policies. Versioned by hash, signed, pushed with the group
  settings.

## 3. Part A: compliance frameworks, the full life cycle

Each stage: what the user does, the page, the API, where it is stored.

| # | Stage | What happens | Page (tenant admin) | API | Stored in |
|---|---|---|---|---|---|
| A1 | Catalog | Browse the available frameworks: built-in packs, and the tenant's imported ones, with version and number of controls | Compliance frameworks → Catalog | `GET /api/v1/compliance/catalog` | built-in: `ndr.compliance_packs` (shared, read only for tenants); imported: tenant DB `compliance_packs` |
| A2 | Import | Upload a framework as YAML or CSV (control id, title, text, crosswalk, explicit checks). Checked strictly, previewed with its coverage ("41 of 58 controls have automatic checks, 17 need manual evidence") before saving | Catalog → Import | `POST /api/v1/compliance/packs` (preview with `?dry_run=1`) | tenant `compliance_packs` |
| A3 | Adopt | Choose the frameworks the organisation must meet | Frameworks → Adopt | `PUT /api/v1/compliance/profile` (exists, extended) | `siem_compliance_profile` |
| A4 | Scope | Per framework, the agent groups it covers (e.g. PCI only on the payment servers) | Frameworks → Scope | same | same |
| A5 | Tailor | Turn off controls that don't apply, set parameters where the standard allows a choice (e.g. minimum password length 12 or 14), map a manual control to evidence | Frameworks → Tailor | same | same |
| A6 | Deploy | ProVigil works out, per agent group, the **union of checks needed** by the frameworks in scope, and pushes only those. Rollout per agent: pending / applied / failed, with the reason | Frameworks → Deployment | `GET /api/v1/policy/rollout` | tenant `policy_bundles`, `policy_rollout` |
| A7 | Assess | Agents run the checks on their schedule (and "scan now"), sending only changes (exists) | Compliance (analyst) | `GET /api/v1/compliance` (exists) | `siem_sca_checks` (exists) |
| A8 | Score | Per framework, control and host: passed / failed / not applicable / manual, with the score as the passed share | Compliance (analyst) | same | computed in ClickHouse |
| A9 | Remediate | A failed control opens a **task** with the fix text (from the check) on the failing hosts, assigned and tracked like a case; closed by the next passing scan | Compliance → Fix queue | `POST /api/v1/compliance/tasks` | `soar_cases` with tag `compliance` |
| A10 | Exceptions | Accept a failing control for a reason, with an approver and an **expiry**; it then counts as "accepted risk", not "passed". Expired exceptions fail again. Replaces today's "checks not needed" (migrated as exceptions without expiry, so nothing is lost) | Compliance → Exceptions | `POST/DELETE /api/v1/compliance/exceptions` | tenant `compliance_exceptions` |
| A11 | Monitor drift | A control that passed and now fails raises an alert ("compliance drift") with the host and the change; it is grouped like other alerts (alert life cycle) | Alerts / cases | — | `siem_alerts` |
| A12 | History | A snapshot per framework per day (score, controls, exceptions), so trend charts and "what was our state on 1 March" work | Compliance → Trend | `GET /api/v1/compliance/history` | tenant `compliance_snapshots` |
| A13 | Evidence pack | One export per framework for an auditor: scope, score, each control's status with its checks and hosts, exceptions with approvers, related alerts, manual evidence files, timestamps, and a SHA-256 of the pack | Compliance → Export | `GET /api/v1/compliance/evidence?framework=` | generated on request |
| A14 | Review / retire | Periodic review reminder (e.g. quarterly attestation by the tenant admin); a new version of a pack is adopted side by side, compared, then switched; a dropped framework stops being pushed | Frameworks | `PUT /api/v1/compliance/profile` | same |

### How an Oman standard gets in

ProVigil does not invent control texts. The client gives the official document of the standard
(e.g. the national basic security controls, the central bank's cyber security framework for
banks, or the Personal Data Protection Law (Royal Decree 6/2022)). We build the pack once from
it, or the tenant admin imports it (A2). Most controls are then mapped by **crosswalk** to ISO
27001 / NIST controls we already check, plus explicit checks for the rest. Controls nothing can
check automatically (policies, training) become **manual** controls with evidence upload.

## 4. Part B: endpoint control policies

### 4.1 What the tenant admin writes

One page, Endpoint policies, with ready presets and custom rules:

| Rule type | Matches on | Example |
|---|---|---|
| Site rule | domain (and sub-domains), URL pattern, category preset | `chatgpt.com`, `*.openai.com`, preset "Generative AI" |
| Application rule | file name, path, SHA-256, signer (publisher), product name | `ChatGPT.exe`, signer "OpenAI", hash of a tool |
| Preset (bundle of both) | a named list we maintain | "Generative AI: ChatGPT site and desktop app, Claude, Gemini, Copilot web..." |

Each rule has: mode **monitor** or **enforce**, scope (agent groups, or all), allowed users or
groups (exceptions, e.g. the IT team), a message shown to the user when blocked, and the
compliance controls it satisfies (e.g. ISO 27001 "installation of software"), so endpoint
rules count as evidence in Part A.

### 4.2 How the Windows agent enforces it (layered, honest about limits)

**Sites**, three layers, each closing a gap of the one before:

1. **Browser policy** (main layer): the agent writes the browsers' own managed block lists
   (Edge, Chrome, Firefox enterprise policy). Blocks HTTPS addresses including paths, shows
   the browser's block page, and can't be undone by the user. It also turns off the browsers'
   private DNS ("DNS over HTTPS"), which would otherwise skip layer 2.
2. **Name resolution**: blocked domains go to a section of the hosts file that the agent owns,
   between its own markers, so other apps (desktop clients) can't reach them by name either.
3. **Strict mode** (off by default): the agent resolves the blocked domains every 10 minutes
   and blocks those addresses in the Windows firewall. Off by default because cloud providers
   share addresses, which would block unrelated sites.

**Detection of attempts**: every lookup of a blocked domain is seen in the DNS events: Sysmon
event 22 (process, user), or the Windows DNS client log, which the agent turns on where Sysmon
is absent. The agent matches lookups against the bundle on the PC and sends one **policy
event** per user, rule and process every 10 minutes, with the count.

**Applications**, two layers:

1. **Prevent by name**: the agent registers the blocked program names so that Windows starts
   ProVigil's small blocker program instead. The blocker shows the tenant's message ("ChatGPT
   is not allowed by <organisation> policy"), sends the policy event, and exits. This works on
   every Windows edition, including Home.
2. **Stop by identity**: the agent watches process starts and stops at once any process
   matching a blocked hash, signer or product name, even if renamed. It then sends the policy
   event with the parent, user and command line.

Later (P6) on Pro, Enterprise and Education editions: also generate a Windows App Control deny
policy (by signer and hash), which blocks before the program runs at all.

**Monitor mode** does the detection only: no block, the same events, so the tenant sees the
impact ("37 people opened chatgpt.com this week") before switching to enforce.

**Limits** (shown in the UI): a person with local admin rights or a personal VPN can work around
web blocking. Tamper protection (exists) re-applies the agent's hosts section and registry
policies and alerts when they are changed. Portable browsers are covered by the application
rules (block unapproved browsers). Store apps are stopped by the identity layer.

**Linux agent**: belongs to the other developer. This spec gives the bundle format and the
policy event format (sections 6 and 7) as the contract; he implements it in his agent (hosts
file, browser policy folders, process blocking). We change nothing in `siem-agent-linux`.

### 4.3 The alert

The manager turns each policy event into an alert from our own rule group `endpoint_policy`,
with rule ids from our own range (chosen free in P3):

- "Blocked site attempt: chatgpt.com by ACME\\jdoe in msedge.exe on PC-17 (12 times)", level 5;
- "Blocked application attempt", level 6;
- "Policy removed or changed on the PC" (tamper), level 12;
- "Policy could not be applied", level 7.

Monitor mode uses the same rules at level 3. They go through the alert life cycle like every
alert (incidents grouped by PC and rule, exceptions, metrics). A dashboard on the policy page:
top blocked sites and apps, by user and department, trend.

### 4.4 Endpoint policy life cycle

Draft → test on a pilot group in **monitor** → review impact → **enforce** on the pilot → widen
to all groups (staged) → watch attempts and tamper alerts → edit or retire. Every change is
recorded in the decision log with who, when, before and after. A tenant-wide **"stop
enforcing"** switch moves every rule to monitor within one keepalive, for emergencies.

## 5. Safety rules (so a policy can never break a PC or blind ProVigil)

Rejected when saved, and again on the agent:

- a rule matching the ProVigil manager addresses, update servers, or ProVigil's own programs;
- a rule matching Windows core programs (e.g. `explorer.exe`, `svchost.exe`, `lsass.exe`,
  `winlogon.exe`, anything under `C:\Windows\System32` by path) or a whole drive or folder;
- wildcards that are too wide (`*`, `*.com`), regexes that can run too long, more than 5,000
  rules per tenant;
- tenant-written checks that run commands, unless that agent has opted in with
  `allow_remote_commands` (the existing safeguard for commands from the group settings).

## 6. Delivery to agents: the policy bundle

- **Built per (tenant, group)** whenever something it depends on changes: profile, pack,
  exception, endpoint rule. One JSON document with the checks to run per policy (ids), the
  tenant's own checks (YAML, same dialect as the built-in policies), the endpoint rules, the
  safety allowlist, the version (SHA-256 of the content) and a signature.
- **Pushed with the group settings** (existing path). New agent group fields:
  `sca_only_checks`, `sca_custom_policies`, `endpoint_policies`, `policy_bundle_version`,
  `policy_signature`.
- **Signed** with an Ed25519 key held by the control plane. The agent pins the public key at
  enrollment and refuses a bundle with a bad signature. So a worker node or anything else in
  the path cannot add a rule.
- **Applied atomically**: the agent applies the new bundle as a whole; if any step fails it
  restores the previous one and reports `apply_failed` with the reason. It keeps the last good
  bundle on disk and enforces it while offline and after restarts.
- **Reconciled** every 10 minutes: the agent checks its hosts section, registry policies and
  name registrations against the bundle, re-applies them, and reports the drift (that is the
  tamper alert).
- **Staged rollout**: a bundle change goes first to the pilot group (if the tenant set one),
  then to the rest after a hold time or on the admin's click. Rollout status per agent is
  shown on the page.
- **Only checks needed**: frameworks in scope → their controls → crosswalks → the check ids,
  united per group. An agent in no framework's scope runs only the checks the tenant asked
  for directly (or none). This cuts scan time and the data stored.

## 7. Data (tenant database unless marked)

| Table | Content | Key |
|---|---|---|
| `ndr.compliance_packs` (shared) | built-in packs: id, version, controls JSON | (pack_id, version) |
| `compliance_packs` | the tenant's imported packs | (pack_id, version) |
| `siem_compliance_profile` (exists) | adopted, scope, tailoring | id |
| `compliance_exceptions` | control or check, scope, reason, approver, expires_at | id |
| `compliance_snapshots` | day, framework, score, control states | (framework, day) |
| `endpoint_policies` | rules, mode, scope, message, controls | id |
| `policy_bundles` | group, version, JSON, signature, created_at | (group, version) |
| `policy_rollout` | agent, version, state, reason, at | agent |
| `siem_alerts` (exists) | policy events as alerts | — |

All ReplacingMergeTree with a version column, replicated like the other tenant tables, keys
leading with the tenant where shared. Following the storage rule: everything in ClickHouse, no
files; agent check results stay where they are (provigil-db, copied for compliance as today).

Policy event from the agent (also the contract for the Linux agent):

```json
{"type":"policy","rule_id":"pol-7","kind":"site|app|tamper|apply_failed","mode":"enforce",
 "target":"chatgpt.com","user":"ACME\\jdoe","process":"C:\\...\\msedge.exe","parent":"...",
 "hash":"sha256","count":12,"first":1794829411,"last":1794830011,"bundle":"<version>"}
```

## 8. Scalability

Sized for 50 tenants × 2,000 agents = 100,000 agents (today 500 per tenant):

- Bundles are built per group on change, not per agent, and cached by version. An agent
  downloads only when the version in its keepalive answer differs. Spreading uses the
  existing splay (`full_send_splay_secs`), so a change to 2,000 agents doesn't come as one
  burst.
- Agents send only check results that changed (exists). With "only checks needed", the
  checks per agent drop from all built-in ones to the frameworks in scope.
- Policy events are counted on the agent (one per user, rule and process every 10 minutes), so
  a script retrying a blocked site 10,000 times is one event with `count: 10000`.
- Scores and trends are ClickHouse aggregates per tenant database, never held in memory;
  daily snapshots keep trend queries small.
- Matching on the agent: domains in a hash set (suffix walk), hashes in a hash set, names in a
  set. O(1) per lookup, so 5,000 rules cost nothing per process start or DNS query.

## 9. Reliability

- Enforcement runs on the PC and doesn't depend on the manager being reachable.
- Atomic apply with rollback, last good bundle kept, reconcile loop (section 6).
- Every apply step is idempotent: the agent owns only its marked hosts section and the
  registry values it lists, and never touches the user's own entries.
- Rollout state per agent with the failure reason. A bundle that fails on more than 20 % of
  the pilot stops the rollout by itself.
- Tests: unit tests for matching, the safety rules and bundle building. A Windows test (on a
  test VM, not the dev PC) for each layer in monitor and enforce. A load test of bundle
  pushes to 2,000 simulated agents (`provigil-loadtest`).

## 10. Security

- Only the tenant admin role edits frameworks, exceptions and endpoint policies. Analysts see
  them. Each change goes in the decision log (who, when, before and after).
- Enforce mode on more than 50 agents, or any "stop enforcing", can require a second
  approver (tenant setting, off by default).
- Tenant isolation: packs, rules and bundles live in the tenant's database. An agent gets only
  its own tenant's group bundle. Imported packs never leave the tenant.
- Signed bundles, pinned key, schema and size checks on the agent (section 6).
- Uploaded framework files: size limit (2 MB), strict YAML/CSV parsing without aliases, every
  field length-checked. Never executed.
- The blocker program and the agent's policy files are covered by tamper protection.
- Messages shown to users are plain text only (no markup, no links), limited to 300
  characters.

## 11. Availability

- Agents keep enforcing and keep events in their buffer while the manager is down (exists:
  `buffer.rs`).
- In the cluster design (`provigil-cluster.md`) bundles are built by the control plane and
  served by every worker. If the control plane is down, workers keep serving the last bundles
  and agents keep their last good one. Only editing waits.
- ClickHouse tables are replicated. Built-in packs are also compiled into the server as a
  fallback, so the catalog never shows empty.

## 12. Decisions

| # | Decision | Reason |
|---|---|---|
| D-1 | Frameworks become data (packs), not code | Oman and future standards without a release |
| D-2 | Crosswalk to ISO 27001 / NIST instead of re-mapping every check | National standards derive from them; one mapping serves many frameworks |
| D-3 | Agents run only the checks their groups' frameworks need | What the client asked; less scan time and data |
| D-4 | Reuse the group settings path, add fields | It already pushes, keeps a last copy and works offline |
| D-5 | Sign bundles (Ed25519, pinned at enrollment) | Defense in depth beyond TLS: a bad node can't push blocking rules |
| D-6 | Web blocking primarily through browser policy, hosts file second, firewall strict mode optional and off | Browser policy handles HTTPS and paths; firewall by address causes collateral blocks |
| D-7 | App blocking by name redirect plus stop-by-identity; App Control policies later | Works on every edition now (customer PCs include Home); the stronger layer where supported later |
| D-8 | Monitor mode first, always available | Impact visible before blocking; safe rollout |
| D-9 | Exceptions with approver and expiry replace "checks not needed" (migrated) | Auditors want accepted risk visible and time-limited |
| D-10 | Remediation as tasks, no automatic fixing in this plan | Automatic fixes on customer PCs are risky; tasks are tracked and safe |
| D-11 | Linux agent: contract only | It belongs to the other developer |

## 13. Phases (2-week sprints)

| Phase | Content | Done when |
|---|---|---|
| P1 | Packs as data (the six current ones moved into packs, no loss), import with preview, crosswalk, tenant admin Frameworks page (catalog, adopt, scope, tailor). `compliance.rs` reads packs | The same scores as today from packs; an imported test pack shows coverage |
| P2 | Bundle per group with only the needed checks, new agent fields, signing, rollout status, exceptions with expiry (migration), daily snapshots, evidence export, drift alert | An agent in a PCI-only group runs only PCI checks; the evidence pack opens and its hash checks |
| P3 | Endpoint site rules: browser policy, hosts section, DNS attempt detection, monitor/enforce, alerts, policy page with presets | chatgpt.com blocked in Edge/Chrome/Firefox on the test VM; attempt alert with user and process |
| P4 | Application rules: blocker program, stop by identity, Generative AI preset, tamper reconcile, dashboard | ChatGPT.exe blocked by name and when renamed; tamper alert when the hosts section is edited |
| P5 | Staged rollout, "stop enforcing" switch, second approver, load test 2,000 agents, guide | Load test within limits; feature guide updated |
| P6 (later) | Windows App Control policies on Pro/Enterprise; Oman pack(s) once the documents arrive (can start in P1 as soon as they do) | — |

That is 5 sprints for P1–P5. Against the plan to v1.0 (27 Jan 2027) this has to be agreed with
the scrum master: either P1–P3 in v1.0 and P4–P5 after, or a later v1.0.

## 14. Open questions for the client

1. Which Oman standard(s) exactly, and the official document of each (control list). We need
   it to build the pack; we don't write control texts ourselves.
2. The message the user sees when a site or app is blocked, and whether users may ask for an
   exception from that message.
3. Which Windows editions the customer PCs run (Home / Pro / Enterprise). It decides when the
   strongest app blocking layer (P6) is worth doing.
