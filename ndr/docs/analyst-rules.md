# Analyst — Rules

**Scope:** SIGMA detection rule management — create, edit, enable/disable, delete, and sync community rules.  
**Route:** `/analyst/rules`  
**Angular component:** `ndr-ui/src/pages/analyst/rules/rules.ts`  
**Template:** `ndr-ui/src/pages/analyst/rules/rules.html`  
**Styles:** `ndr-ui/src/pages/analyst/rules/rules.css`  
**Services:** `Api`, `AuthService`

---

## Purpose

The Rules page lets analysts and admins manage SIGMA-style detection rules that the NDR engine applies to all incoming Agent-Z and Agent-S events in real time. Rules define a single field/matcher/value condition and fire immediately after save — no engine restart required. Admins additionally see a "Sync Rules" button to pull the latest SigmaHQ community network detection rules from the upstream repository in the background.

---

## Component State

The component uses `OnInit` and plain class properties (not signals). `ChangeDetectorRef` is injected and called explicitly throughout because the component mixes imperative subscription callbacks with the default change detection strategy.

| Property | Type | Default | Description |
|---|---|---|---|
| `rules` | `any[]` | `[]` | Normalized rule objects loaded from API |
| `loading` | `boolean` | `true` | True while `loadRules()` is in flight |
| `saving` | `boolean` | `false` | True while `saveRule()` is in flight |
| `showForm` | `boolean` | `false` | Rule form panel visible |
| `isEditing` | `boolean` | `false` | Edit mode (true) vs create mode (false) |
| `editingId` | `string` | `''` | ID of the rule being edited |
| `totalHits` | `number` | `0` | Sum of all rule hit counts (loaded separately) |
| `message` | `string` | `''` | Current toast message |
| `messageType` | `string` | `''` | `'success'` or `'error'` |
| `showConnHelp` | `boolean` | `false` | Connection state reference guide visible |
| `showFieldInfo` | `boolean` | `false` | Field reference popup visible |
| `syncing` | `boolean` | `false` | Community rule sync in progress |
| `categoryFilter` | `string` | `''` | Selected attack category tag (empty = no filter) |
| `severityFilter` | `string` | `''` | Selected severity (empty = no filter) |

### `ruleForm` Object

Bound two-way to the form panel:

| Field | Default | Description |
|---|---|---|
| `title` | `''` | Rule name (required) |
| `severity` | `'medium'` | One of `critical / high / medium / low` |
| `description` | `''` | Human description of what the rule detects |
| `field` | `'event_type'` | Target field from the normalizer (see field table below) |
| `value` | `''` | Value to match against (required) |
| `matcher` | `'equals'` | Match strategy (see matcher table below) |
| `tags` | `[]` | Attack category tags (populated from loaded rule on edit; not editable in the form UI itself) |

---

## Getters

| Getter | Returns | Description |
|---|---|---|
| `isAdmin` | `boolean` | `auth.isAdmin()` — controls visibility of Sync Rules button |
| `activeRulesCount` | `number` | Count of rules where `status === 'ACTIVE'` |
| `selectedField` | `fieldOptions entry \| undefined` | `fieldOptions` entry matching `ruleForm.field` — used for hint, examples, and placeholder |
| `selectedSeverity` | `severityOptions entry \| undefined` | `severityOptions` entry matching `ruleForm.severity` |
| `topCategories` | `{ tag, label, count }[]` | Counts `attack.*` tags across all rules; excludes `attack.tNNNN` MITRE technique ID tags; returns top 9 by count, each with human `label` (prefix stripped, capitalised) |
| `severityCounts` | `{ [key: string]: number }` | Rule count per uppercase severity key (e.g. `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `displayRules` | `any[]` | Subset of `rules` matching both `categoryFilter` and `severityFilter`; passes all rules when both are empty |

---

## Field Options (18 fields)

Fields are split into two groups: network fields sourced from Agent-Z and Agent-S events, and Linux endpoint fields sourced from auditd via the Sigma endpoint agent.

### Network / Agent fields

| Field value | Label | Description | Example values |
|---|---|---|---|
| `event_type` | Event Type | Type of event from Agent-S | `alert`, `flow`, `dns`, `http`, `tls`, `quic` |
| `proto` | Protocol | Network protocol (lowercase) | `tcp`, `udp`, `icmp`, `ipv6-icmp` |
| `source_ip` | Source IP | IP address of the sender | `10.0.2.15`, `192.168.1.1` |
| `dest_ip` | Destination IP | IP address of the receiver | `93.184.216.34`, `8.8.8.8` |
| `conn_state` | Connection State | Agent-Z connection state code | `S0`, `REJ`, `SF`, `OTH`, `RSTO` |
| `network_protocol` | Application Protocol | Layer 7 protocol detected by Agent-Z | `dns`, `http`, `ssl`, `ssh`, `ftp`, `smtp` |
| `alert.severity` | Alert Severity | Agent-S numeric severity (1=high, 2=med, 3=low) | `1`, `2`, `3` |
| `alert.signature` | Alert Signature | Agent-S rule signature name | `ET MALWARE`, `ET SCAN`, `ET POLICY` |
| `alert.category` | Alert Category | Agent-S alert category string | `Malware`, `Exploit`, `Policy Violation` |
| `log_source` | Log Source (Agent-Z) | Agent-Z log type | `conn`, `dns`, `http`, `ssl`, `ssh` |

### Linux endpoint / auditd fields

| Field value | Label | Description | Example values |
|---|---|---|---|
| `Image` | Process Image | Full path of the executed binary | `/bin/bash`, `/usr/bin/curl`, `/tmp/malware` |
| `CommandLine` | Command Line | Full command including arguments | `curl http://`, `chmod +x`, `nc -e /bin/sh` |
| `ParentImage` | Parent Process | Path of the parent process that spawned this one | `/bin/bash`, `/usr/sbin/sshd` |
| `TargetFilename` | Target Filename | File path written or modified | `/etc/crontab`, `/root/.ssh/`, `/tmp/` |
| `DestinationIp` | Destination IP (Endpoint) | Outbound connection destination from a Linux process | `10.0.0.1`, `192.168.` |
| `DestinationPort` | Destination Port (Endpoint) | Outbound connection port from a Linux process | `4444`, `1337`, `443` |
| `User` | User | Linux user account running the process | `root`, `www-data`, `nobody` |
| `type` | Auditd Record Type | Type of auditd event record | `EXECVE`, `SYSCALL`, `PATH`, `SOCKADDR` |

---

## Matcher Options

| Value | Label | Behaviour |
|---|---|---|
| `equals` | Equals | Exact match |
| `contains` | Contains | Partial / substring match |
| `startswith` | Starts With | Prefix match |
| `endswith` | Ends With | Suffix match |
| `re` | Regex | Regular expression pattern match |

---

## Connection State Reference

Shown inline in the form when `ruleForm.field === 'conn_state'` (toggled by "Show connection state guide" button). Clicking any row fills `ruleForm.value` with that state code.

| State | Meaning |
|---|---|
| `S0` | No reply — possible scan |
| `REJ` | Connection rejected |
| `SF` | Normal connection |
| `OTH` | Mid-stream, no SYN |
| `RSTO` | Originator sent RST |
| `RSTR` | Responder sent RST |

---

## Methods

### Data Loading

**`ngOnInit()`** — calls `loadRules()`.

**`loadRules()`** — two-step:
1. `GET /api/rules` → normalises each rule into the local shape: `{ name: r.title, type: 'SIGMA', severity: uppercase, status: r.enabled ? 'ACTIVE' : 'INACTIVE', id, description, tags, conditions: r.conditions || 0, hits: 0 }`. Sets `loading = false` and triggers change detection.
2. Sequentially (not in parallel) calls `GET /api/rules/hit-counts` → fills `r.hits` per rule by matching on `rule.name`; sums all values into `totalHits`. Errors are silently swallowed.

### Form

**`openAddForm()`** — resets form to defaults, sets `showForm = true`, `isEditing = false`.

**`openEditForm(rule)`** — sets `showForm = true`, `isEditing = true`, `editingId = rule.id`, then calls `GET /api/rules/:id` to populate `ruleForm` with the full rule data. Falls back to basic info from the local `rule` object if the API call fails.

**`saveRule()`** — validates that both `title` and `value` are non-empty (shows error toast otherwise). In edit mode: calls `DELETE /api/rules/:editingId` first, then calls `createNewRule()` regardless of delete success/failure. In create mode: calls `createNewRule()` directly.

**`createNewRule()`** — `POST /api/rules` with `ruleForm` payload. The backend generates the rule ID as `ndr-{unix_timestamp}` (e.g. `ndr-1735123456`), builds a full SIGMA YAML (including `id`, `logsource: product: ndr`, `condition: keywords`), stores it in ClickHouse, and publishes `system:reload_rules` to Redis so all engine instances reload automatically. On `status === 'created'`: the component then also calls `POST /api/rules/reload` explicitly → displays success message `"Rule '{title}' {created|updated}. {N} rules active."`, closes form, resets form, calls `loadRules()`. This means a create triggers two reloads (one from the create handler via Redis, one from the explicit reload call).

**`resetForm()`** — resets `ruleForm` to all defaults; clears `showConnHelp`, `isEditing`, `editingId`.

**`getPlaceholder()`** — returns `selectedField.examples[0]` or `'Enter value'` if no field selected.

> **Edit rule implementation note:** There is no PUT/PATCH endpoint. Every edit deletes the old rule and creates a new one — meaning the rule ID changes on every edit. The new rule gets a fresh `ndr-{timestamp}` ID.

> **Redis cross-instance propagation:** Every mutating operation (create, delete, toggle, explicit reload) publishes `system:reload_rules` to the Redis pub/sub channel. All running engine instances subscribe to this channel and reload their in-memory rule set when a message arrives — ensuring cluster-wide consistency without a restart.

### Rule Actions

**`deleteRule(rule)`** — shows `window.confirm`. On confirm: `DELETE /api/rules/:id` — the backend handler deletes from ClickHouse, removes the `rules_state` record, attempts to delete the disk file at `{RULES_DIR}/{id}.yml`, then reloads rules and publishes `system:reload_rules` to Redis. The backend returns `{ status: 'deleted', active_rules: N }`. The component then calls `POST /api/rules/reload` explicitly before removing the rule from local `rules[]` in-place (no re-fetch). Like create, this triggers two reloads — one from the delete handler via Redis, one from the explicit reload call.

**`toggleRule(rule)`** — `POST /api/rules/:id/toggle` with `{ enabled: !current }`. On success: flips `rule.status` in-place between `'ACTIVE'` and `'INACTIVE'`; shows message with new active rule count. The backend handler distinguishes community rules from custom rules: community rules use a `rules_state` override table (preserving the original YAML); custom rules update `sigma_rules.enabled` directly. Both paths hot-reload and publish to Redis.

**`syncCommunityRules()`** — `POST /api/rules/sync-community`. Sets `syncing = true` while in flight.
- If `res.status === 'already_running'`: shows the server's message (e.g. "Sync already in progress — check back in a minute").
- Otherwise: shows "Sync started in background — refresh rules in a minute" and schedules `setTimeout(loadRules, 60_000)` to auto-reload after 60 seconds.
- On error: shows error message from `err.error.error` or `err.error.message`, falling back to "Sync failed — check engine connectivity".

### Filtering

**`setCategory(tag)`** — toggles `categoryFilter`; clicking the already-active chip clears the filter.

**`setSeverity(sev)`** — toggles `severityFilter` (uppercase severity string).

**`clearFilters()`** — clears both `categoryFilter` and `severityFilter`.

### Display Helpers

**`getSeverityClass(sev)`** — returns `'yaml-sev yaml-sev-{critical|high|medium|low}'` — used in the live YAML preview to color the `level:` line. Falls through to `yaml-sev yaml-sev-low` for unrecognised input.

**`getSeverityBadgeClass(sev)`** — returns `'sev-badge sev-{severity}'` — used on rule cards.

**`showMessage(msg, type)`** — sets `message` and `messageType`; auto-clears both after **6 seconds** via `setTimeout`.

---

## HTML Template

### Header

- Eyebrow: "Detection Engine" + h2 "Rules" + subtitle "SIGMA detection rules applied to Agent-Z and Agent-S events."
- Right actions:
  - **Refresh** button (always shown) — calls `loadRules()`
  - **Sync Rules** button (`*ngIf="isAdmin"`) — calls `syncCommunityRules()`; disabled while `syncing`; label switches to "Syncing…" while in flight; tooltip: "Fetch latest SigmaHQ community network rules". Note: `isAdmin()` returns `true` for roles `'admin'` or `'super_admin'`, but the backend endpoint enforces `super_admin` only — any other role sees the button but receives a 403.
  - **New Rule** primary button — calls `openAddForm()`

### Toast

`*ngIf="message"` — styled `.toast-success` (green) or `.toast-error` (red). Auto-dismisses after 6 seconds.

### Metric Cards

Three cards in `.rules-metrics`:

| Card | Value |
|---|---|
| Total Rules | `rules.length` |
| Active | `activeRulesCount` |
| Total Hits | `totalHits` |

### Category Strip

Shown only when `topCategories.length > 0`. Contains:
- "Top Attack Categories" label
- "Clear filters" button — shown only when `categoryFilter || severityFilter`; calls `clearFilters()`
- Up to 9 category chips — each shows the human label + count badge; clicking calls `setCategory(cat.tag)`; active chip gets `.active` class

### Rule Form Panel

Shown when `showForm`. The panel has HUD-corner decorators (`.hud-tl/tr/bl/br`). Form header shows "New Rule" or "Edit Rule" depending on `isEditing`. Close button (✕) sets `showForm = false` and calls `resetForm()`.

**Form body sections (in order):**

1. **Title + Severity row** (2:1 grid) — text input for title; `<select>` for severity (each option shows label + dash + description)

2. **Detection Condition section**
   - "Field Reference" toggle button — shows/hides `field-info-panel`: a grid of all 18 field buttons; clicking any field sets `ruleForm.field`
   - Three-column row: **Field Name** `<select>` (with `field: {field.value}` hint below) | **Matcher** `<select>` | **Value** text input (placeholder from `getPlaceholder()`) with example chips below — clicking an example chip sets `ruleForm.value`
   - **Connection State guide** — shown only when `ruleForm.field === 'conn_state'`; "Show/Hide connection state guide" toggle; grid of 6 state buttons; clicking any fills `ruleForm.value` with that code

3. **Description** — single-line text input

4. **Quick Templates** — 8 pre-built templates that fill the form on click:

   | Template | field | value | matcher | severity |
   |---|---|---|---|---|
   | Agent-S Alert | `event_type` | `alert` | `equals` | high |
   | Port Scan | `conn_state` | `S0` | `equals` | medium |
   | HTTP Monitor | `event_type` | `http` | `equals` | low |
   | Critical Alert | `alert.severity` | `1` | `equals` | critical |
   | Exec /tmp | `Image` | `/tmp/` | `startswith` | high |
   | Reverse Shell | `CommandLine` | `nc -e` | `contains` | critical |
   | Cron Persist | `TargetFilename` | `/etc/cron` | `startswith` | high |
   | Root Exec | `User` | `root` | `equals` | medium |

5. **SIGMA YAML Preview** — live-rendered preview block showing a simplified representation:
   ```yaml
   title: {ruleForm.title}
   level: {ruleForm.severity}        ← colored by getSeverityClass()
   detection:
     keywords:
       {ruleForm.field}|{ruleForm.matcher}: '{ruleForm.value}'
   ```
   The actual YAML stored in ClickHouse by the backend is more complete — it also includes `id: ndr-{timestamp}`, `description`, `tags`, `logsource: product: ndr`, and `condition: keywords`. The preview omits these for brevity.

6. **Form footer** — "Save Rule" / "Update Rule" primary button (disabled while `saving`; shows "Saving…"); Cancel ghost button

### Rules List Panel

Shown when `!loading`. Has HUD corners and a `.panel-scan` animated scan line.

**List topbar:**
- Left: Gavel icon + "DETECTION RULES" title
- Right: Severity filter buttons (CRITICAL / HIGH / MEDIUM / LOW) each showing `severityCounts[sev] || 0`; active filter gets `.active` class. Count pill: `{displayRules.length}[ / {rules.length}] rules` — the total is shown only when a filter is active.

**Rule cards** (per entry in `displayRules`):
- Left column: Gavel icon
- Body:
  - `rule.name` (bold)
  - Meta row: `SIGMA` type badge + severity badge (`getSeverityBadgeClass()`) + `{rule.conditions} condition(s)` + `{rule.hits || 0} hits` + first 2 tags from `rule.tags`
  - `rule.description` (shown when non-empty)
- Right column:
  - Status block: "Status" label + `ACTIVE` (green `.status-active`) or `INACTIVE` (grey `.status-inactive`)
  - 3 icon buttons: Edit (calls `openEditForm(rule)`) | Power toggle (calls `toggleRule(rule)`; icon-btn-on class when active) | Delete (calls `deleteRule(rule)`; icon-btn-del class)

**Empty state** (when `displayRules.length === 0`):
- If `rules.length === 0`: "No SIGMA rules loaded" + "Click 'New Rule' to create one, or sync community rules."
- If `rules.length > 0` (filters active): "No rules match filters" + "Try adjusting the category or severity filter."

### Info Callout

Bottom of page: Info icon + "Rules activate immediately after saving. No engine restart is needed."

---

## API Methods

| Method | HTTP | Endpoint | Description |
|---|---|---|---|
| `getRules()` | GET | `/api/rules` | List all rules for tenant |
| `getRuleById(id)` | GET | `/api/rules/:id` | Full rule detail — backend parses stored SIGMA YAML to extract `field`, `matcher`, `value` from the detection block; returns `{ id, title, severity, description, field, matcher, value, tags[] }` |
| `createRule(form)` | POST | `/api/rules` | Create new rule; returns `{ status: 'created', ... }` |
| `deleteRule(id)` | DELETE | `/api/rules/:id` | Delete rule permanently |
| `toggleRule(id, enabled)` | POST | `/api/rules/:id/toggle` | Enable or disable rule; body `{ enabled: boolean }`; returns `{ active_rules: N }` |
| `reloadRules()` | POST | `/api/rules/reload` | Hot-reload rules into the engine; publishes `system:reload_rules` to Redis for all instances; returns `{ status: 'reloaded', count: N, message: '...' }` |
| `getRuleHitCounts()` | GET | `/api/rules/hit-counts` | Map of `{ [ruleName: string]: number }` — rule name to total alert hit count; **sensor-scoped** using `sensor_ids` from JWT |
| `syncCommunityRules()` | POST | `/api/rules/sync-community` | Trigger background SigmaHQ community sync; returns `{ status: 'started'\|'already_running', message? }` |
| `searchRules(q)` | GET | `/api/rules?q={q}` | Search rules by query string — defined in `api.ts` but not currently used by the Rules component |

---

## Data Flow

```
ngOnInit
  └─ GET /api/rules → normalize → rules[]
       └─ GET /api/rules/hit-counts → fill hits per rule + sum totalHits

openAddForm / openEditForm(rule)
  └─ (edit) GET /api/rules/:id → populate ruleForm

saveRule()
  └─ (edit) DELETE /api/rules/:editingId
       └─ POST /api/rules → POST /api/rules/reload → loadRules()
  └─ (create) POST /api/rules → POST /api/rules/reload → loadRules()

deleteRule(rule)
  └─ DELETE /api/rules/:id → POST /api/rules/reload → splice from rules[]

toggleRule(rule)
  └─ POST /api/rules/:id/toggle { enabled } → update rule.status in-place

syncCommunityRules()
  └─ POST /api/rules/sync-community
       └─ setTimeout(loadRules, 60s) on success
```
