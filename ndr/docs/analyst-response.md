# Analyst — Response Module

**Scope:** Analyst portal response section, accessible at `/analyst/response/*`.  
**Angular pages:** `pages/analyst/evidence/` and `pages/analyst/soar/`  
**Sub-pages:** Evidence & Forensics (`/analyst/evidence`) and SOAR (`/analyst/soar`)  
**Roles:** `analyst`, `viewer` (read-only restrictions apply to destructive actions at Rust level)

---

## Page 1 — Evidence & Forensics

**Route:** `/analyst/evidence`  
**Angular component:** `ndr-ui/src/pages/analyst/evidence/evidence.ts`  
**Template:** `ndr-ui/src/pages/analyst/evidence/evidence.html`  
**Styles:** `ndr-ui/src/pages/analyst/evidence/evidence.css`  
**Service:** `ndr-ui/src/services/evidence/evidence.ts` (`EvidenceService`)

### 1.1 Purpose

Displays all captured evidence bundles for the analyst's tenant. Each bundle packages the complete forensic record for one network incident: connection records, DNS queries, HTTP transactions, TLS sessions, file transfers, protocol anomalies, threat intel results, and raw PCAP — sourced from both Agent-Z and Agent-S and correlated by `community_id`. The analyst can drill into any bundle through a 12-section investigation panel, run an AI-powered verdict via ARIA, and manage chain-of-custody with legal hold support.

### 1.2 Severity Ordering

A module-level constant defines sort priority for the bundle list:

```typescript
const SEV_ORDER: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
```

Used throughout `groupedBundles`, `ipGroupedBundles`, and sort comparators.

### 1.3 Signals (State)

| Signal | Type | Description |
|--------|------|-------------|
| `bundles` | `any[]` | Raw list of evidence bundles returned by `listBundles()` |
| `selectedBundle` | `any` | Currently selected bundle object |
| `timeline` | `any` | Attack timeline for selected bundle (from `/timeline`) |
| `annotations` | `any[]` | Analyst notes for selected bundle |
| `log` | `any[]` | Chain-of-custody entries for selected bundle |
| `loading` | `boolean` | True while `listBundles()` is in flight |
| `bundleContents` | `any` | Deep investigation payload from `/contents` (live ClickHouse + ZIP) |
| `contentsLoading` | `boolean` | True while `getBundleContents()` is in flight |
| `contentsError` | `string` | Error message if contents load fails |
| `verifyResult` | `any` | Result from `verifyBundle()`: `{ status, stored_sha256, computed_sha256, verified_at, verified_by }` |
| `ariaVerdict` | `any` | AI verdict from ARIA: `{ verdict, confidence, reasoning, recommended_action, mitre_techniques, generated_at }` |
| `ariaInvestigating` | `boolean` | True while `runInvestigation()` API call is pending |
| `ariaError` | `string` | Error message if AI investigation fails |
| `activeTab` | `string` | Active right-panel tab: `'bundles'` \| `'investigation'` \| `'timeline'` \| `'log'` \| `'notes'` \| `'verify'` |
| `activeContentSection` | `string` | Active sub-section within Investigation tab: `'attack_summary'` \| `'connection'` \| `'dns'` \| `'http'` \| `'ssl'` \| `'files'` \| `'weird'` \| `'alerts'` \| `'intel'` \| `'related'` \| `'pcap'` \| `'aria_verdict'` |
| `expandedCids` | `Set<string>` | Community IDs whose bundle groups are expanded in the left list |
| `corrFilterActive` | `string` | Corroboration filter: `''` (all) \| `'corroborated'` \| `'agent_z_only'` \| `'agent_s_only'` |
| `expandedIpKeys` | `Set<string>` | IP-pair group keys (`src_ip→dst_ip`) currently expanded |

### 1.4 Form Fields (Plain Properties)

| Property | Purpose |
|----------|---------|
| `holdReason` | Text input bound to the legal hold reason form |
| `newNote` | Textarea bound to the analyst note input |
| `newTag` | Tag input bound to the annotation form |
| `sensorIds` | Array of sensor IDs scoped to this JWT (from `auth.getSensorIds()`) |

### 1.5 Computed Signals

**`corroboratedCount`** — count of bundles where `correlation_status === 'corroborated'`. Displayed in the filter bar.

**`groupedBundles`** — groups bundles by `community_id`. Within each group, bundle records are sorted highest severity first; the highest-severity item becomes `primary`. Groups themselves are sorted highest-primary-severity first. Applies `corrFilterActive` filter before grouping. Produces: `{ community_id, primary, alerts[] }` (note: the `alerts` array name is from the code variable — these are bundle records, not individual IDS alerts).

**`ipGroupedBundles`** — outer grouping by `src_ip→dst_ip` string key. Within each IP-pair group, bundles are unsorted. The group carries `{ key, src_ip, dst_ip, bundles[], count, maxSev }` where `maxSev` is the highest severity in that group. Groups are sorted highest-maxSev first. Used for the left-panel IP-pair accordion. Applies `corrFilterActive` before grouping.

### 1.6 Helper Methods

| Method | Description |
|--------|-------------|
| `corrLabel(status)` | Returns `{ label, cls }` for displaying corroboration badges. `'corroborated'` → `Z+S / corr-both`, `'agent_s_only'` → `S / corr-s`, `'multiflow'` → `Z+S+ / corr-both`, default → `Z / corr-z`. Note: `'multiflow'` is a `correlation_status` value that renders as a badge only — there is no dedicated filter button for it in the UI. |
| `toggleCorrFilter(val)` | Toggles `corrFilterActive` — sets to `val` or clears to `''` if already active |
| `toggleIpGroup(key)` | Adds/removes key from `expandedIpKeys` set |
| `toggleGroup(group, event)` | Adds/removes `community_id` from `expandedCids`; stops event propagation |
| `connStateDesc(state)` | Translates Agent-Z connection state codes to human-readable descriptions. Full table: `S0`=Connection attempt, no reply; `S1`=Established, not terminated; `S2`=Closed by originator; `S3`=Closed by responder; `SF`=Normal close; `REJ`=Connection rejected; `RSTO`=Reset by originator; `RSTR`=Reset by responder; `RSTOS0`=Originator reset, no reply; `RSTRH`=Reset by responder, no SYN; `SH`=SYN then half close; `SHR`=Responder SYN, half close; `OTH`=No SYN, mid-stream. Returns `''` for unknown states. |
| `filterRules(rules)` | Filters rules list to only include rules with a space in the name or at least 8 characters (removes short/internal IDs) |
| `verdictClass(verdict)` | Maps `TRUE_POSITIVE` → `'verdict-true'`, `FALSE_POSITIVE` → `'verdict-false'`, other → `'verdict-suspicious'` |
| `verdictLabel(verdict)` | Maps verdict enum to display label: `'TRUE POSITIVE'`, `'FALSE POSITIVE'`, `'SUSPICIOUS'` |
| `hasAgentSLogs()` | Returns true if any `uid_logs` entry in the timeline has `source === 'agent-s'` |

### 1.7 Data Loading Methods

**`ngOnInit()`**  
- Reads `sensorIds` from auth JWT.  
- Subscribes to `ActivatedRoute.queryParams` to capture `cid`, `src_ip`, and `dst_ip` into `pendingCid`, `pendingSrcIp`, `pendingDstIp` — used for deep-linking from SOAR overlay.  
- Calls `loadBundles()`.

**`loadBundles()`**  
- Sets `loading = true`, calls `evidenceService.listBundles()`.  
- On success: populates `bundles`, clears `loading`.  
- If `pendingCid` is set, finds the matching bundle and calls `selectBundle(match)` — auto-navigates to a specific incident from a URL deep link.  
- If `pendingSrcIp + pendingDstIp` are set, auto-expands that IP-pair group and selects the first bundle in it.  
- Otherwise, auto-expands the first IP-pair group and selects its first bundle.

**`selectBundle(b)`**  
Selects a bundle, resets tabs to `investigation/attack_summary`, and fires five parallel loads: `loadTimeline`, `loadLog`, `loadAnnotations`, `loadBundleContents`, `loadVerdict`.

**`loadVerdict(communityId)`**  
Calls `evidenceService.getVerdict(communityId)`. On `status === 'ok' && verdict`, populates `ariaVerdict`.

**`runInvestigation(b)`**  
Sets `ariaInvestigating = true`, switches to `aria_verdict` section, calls `evidenceService.runInvestigation(b.community_id)`. On success sets `ariaVerdict`; on error sets `ariaError`.

**`loadBundleContents(bundleId)`**  
Calls `evidenceService.getBundleContents(bundleId)`. Sets `contentsLoading/contentsError/bundleContents`.

**`loadTimeline(cid)`, `loadLog(cid)`, `loadAnnotations(bundleId)`**  
Each calls its corresponding `EvidenceService` method and writes the response data directly to its respective signal (`timeline`, `log`, `annotations`).

**`download(b)`**  
Delegates to `evidenceService.downloadBundle(b.community_id)` — triggers browser file download of the ZIP.

**`verify(b)`**  
Switches tab to `'verify'`, clears `verifyResult`, calls `evidenceService.verifyBundle(b.id)`. On error, synthesizes an `ERROR` result with placeholder hashes.

**`setHold(b, hold)`**  
Calls `evidenceService.setLegalHold(b.id, hold, reason)`. When placing hold (`hold=true`), uses `holdReason` input value. When releasing (`hold=false`), hardcodes reason as `'Hold cleared'`. Reloads bundle list on success and clears `holdReason`.

**`addNote(b)`**  
Guards on `newNote` being non-empty. Calls `evidenceService.annotate(b.id, b.community_id, note, tag)`. Reloads annotations and clears form fields.

### 1.8 HTML Template Behaviour

**Left panel — bundle list:**
- Header: "Incidents" label + badge with total `bundles().length` count.
- **Corroboration filter bar** — 4 buttons: `Z+S` (filters `corroborated`, uses `corroboratedCount()` computed) | `S` (filters `agent_s_only`, inline count) | `Z` (filters `agent_z_only`, inline count) | `ALL` (clears filter). Active button gets `.active` class. Count badges update reactively from live signal.
- **IP-pair accordion** — each group row: chevron (`▼` expanded / `▶` collapsed), `maxSev` badge (colored), `src_ip → dst_ip` flow, count badge. Clicking toggles `expandedIpKeys`.
- **Bundle cards** (within expanded IP-pair): severity badge + HOLD badge (if `legal_hold`) + AUTO badge (if `auto_captured`) + corroboration badge (`corrLabel()`). Date: `captured_at | date:'M/d/yy, h:mm a'`. Size: `(size_bytes/1024).toFixed(1) KB`. CID truncated to 18 chars + `…`. Selected card gets `.selected` class.

**Right panel — bundle detail:**

**Header:** severity badge + "Evidence Bundle" h3 + corroboration label — text: `CORROBORATED` (if `b.corroborated`), `AGENT-S ONLY` (if `agent_s_only`), or `AGENT-Z ONLY` (default). `⚠ LEGAL HOLD` badge if `legal_hold`. Flow row: src_ip → dst_ip + CID truncated to 22 chars + `…`.

**Actions row:** "↓ Download ZIP" button | "Verify Integrity" button | "Legal Hold" button (`*ngIf="!legal_hold"`) / "Release Hold" button (`*ngIf="legal_hold"`).

**Tab bar:** Investigation | Overview | Attack Timeline | Chain of Custody | Analyst Notes | **Integrity** — Note: clicking the "Integrity" tab button calls `verify(selectedBundle())` directly (not `activeTab.set('verify')`), so every tab click re-runs the SHA-256 check.

**Overview tab:**
- Incident card (severity-colored): severity, src→dst IPs, captured_at. "Auto-captured" label if `auto_captured`.
- Bundle Integrity card: table — Bundle ID | Community ID (monospace) | SHA-256 (monospace, break-all) | Size (KB) | Expires | Legal Hold (Yes/No).
- Summary section (shown only when `bundleContents()?.attack_summary` loaded): narrative text, 4 stat chips (rules_fired count, threat_intel_hits, files_transferred, UA if `http_user_agent` set), recommended action text.
- Legal hold form (shown when NOT on hold): text input (`holdReason`, placeholder "Reason for legal hold (required)") + "Place Legal Hold" button — **disabled** when `holdReason` is empty.

**Attack Timeline tab:**
- Narrative h4 + narrative text.
- Event list: each row has time badge (`date:'h:mm:ss a'`), type badge (colored by event type class), description text.
- Related sessions: `timeline()?.related_sessions_count` related sessions in **±5 min** window.
- **Connection Story** section (shown when `zeek_uid` or any `uid_logs` present): Agent-Z/Agent-S source badges + UID chip. DNS queries chips row (if any). TLS SNIs chips row (if any). Per-log entry list: time | log_type (uppercase) | description (Agent-S entries prepend a small "S" badge). Empty state: "No log entries linked to this connection." If no `zeek_uid` at all: "No Agent-Z UID found for this connection — UID linking not available."

**Chain of Custody tab:** table — Time | Action (action-badge) | By | Notes | IP. Empty: "No custody log entries yet."

**Analyst Notes tab:** textarea (3 rows, `newNote`) + tag input (`newTag`, placeholder "Tag (e.g. confirmed_malicious)") + "Add Note" button (disabled when `newNote` empty). Notes list: each note card shows author, created_at, tag chip (if set), note text. Empty: "No notes yet."

**Investigation tab** — sub-nav with 12 buttons. "AI Verdict" button has a colored dot indicator when verdict exists: green for TRUE_POSITIVE, red for FALSE_POSITIVE, amber/other for SUSPICIOUS. Loading: "Loading bundle contents..." spinner. Error: error message string.

Sections render from `bundleContents()`:

- *Attack Summary*: severity h3 ("SEVERITY — title"), narrative paragraph. Summary grid (6 cards): Victim IP | Attacker/Dest IP | Rules Fired | Threat Intel Hits (red if > 0) | Related Alerts | PCAP (Captured/Not available). Recommended Action block (conditional). Rules Fired list (from `filterRules()`): each row severity badge + rule name.
- *Connection*: "Connection Record" h4 with source badge (Agent-Z/Agent-S styled). Table: Source (ip:port) | Destination (ip:port) | Protocol | **Event Type** | Timestamp | Community ID. "Alert Connection Info" h4: table — Src IP | Dst IP | Src Port | Dst Port | Protocol | **App Protocol** | **User Agent** | Total Bytes | To Server | To Client | Total Packets | Flow Start | Flow End | **Flow State** | Severity. "PCAP Engine Session Metadata" h4: table — Session ID (`arkime_session_id`) | Index | Source (`query_source`).
- *DNS*: Agent-Z header + count. "DNS query resolved to target IP — consistent with C2 domain lookup." warning (if `resolves_to_target_ip`). Each query: timestamp, query name, rcode badge (green when NOERROR), answers (IP chips), `src_ip → dns_server | Proto: {proto}`, **REJECTED badge** if `d.rejected`. Agent-S DNS: same layout but also shows `d.type` (DNS query type field).
- *HTTP*: Agent-Z: method badge (green GET / orange POST), full_url, status_code (green if < 400), UA tag, `{bytes_up}B up / {bytes_down}B down`, timestamp. Agent-S HTTP: same method/url/status + UA + **content_type** + bytes_downloaded + `src_ip → dest_ip` + timestamp | protocol.
- *TLS/SSL*: Agent-Z: global "Self-signed certificate detected..." warning (if `any_self_signed`). Per-connection: SNI (or "(no SNI)"), TLS version, SELF-SIGNED badge, "Valid" badge (if `is_valid`), Subject, Issuer, Cipher, JA3, JA3S, timestamp. Agent-S TLS: same structure + **Fingerprint** (SHA-1 hex, monospace) + **valid dates** (`not_before → not_after`) + `src_ip → dest_ip`.
- *Anomalies*: Agent-Z: weird_type, timestamp, detail (conditional), src → dst. Agent-S: type, timestamp, **layer badge** (if `w.layer` set), event text, src → dest | proto.
- *All Alerts*: Agent-S/NDR alerts — severity badge, `rule_name || tags`, timestamp, `src_ip → dst_ip | Score: {score} | {src_country} → {dst_country}`. SIGMA matches — severity badge, `sigma_hits` text, timestamp, tags.
- *Threat Intel*: "IPs checked:" row with IP tags (or "none (src/dst IP unknown at capture time)" if empty). Clean message: "Not found in any known malicious IP feed (Feodo Tracker, URLhaus, MalwareBazaar)." + note: "Alert severity is from IDS behavioral rules, not IP reputation — this IP may be legitimate." Match rows: ioc_type, ioc_value (IP), confidence % + bar (`.high` class when `confidence >= 70`), description, tags, first/last seen dates.
- *Related Activity*: h4 "Related Alerts from Same Source (±30 min window)". Each row: severity badge, timestamp, src → dst IPs, tags, CID (monospace). Empty: "No related alerts in ±30 minute window. (Isolated incident)".
- *PCAP*: If available: "PCAP Captured" h4, size in KB, "Download Full ZIP (includes session.pcap)" button, note "PCAP is inside the ZIP as `session.pcap`. Open with Wireshark." If not available: "PCAP Not Available" + 3 reasons: (1) Session rotated out of PCAP Engine storage before capture; (2) PCAP Engine not running at capture time; (3) OpenSearch session not indexed yet.
- *AI Verdict*: Always shows "Run Investigation" button (disabled while `ariaInvestigating()`). Description paragraph about ARIA. While investigating: spinner + "ARIA is analyzing the evidence. This may take 10–30 seconds...". Error state (when `ariaError && !ariaInvestigating`). Verdict card: large verdict badge, confidence %, confidence bar fill, Analysis h5 + reasoning paragraph, Recommended Action h5 + paragraph, MITRE ATT&CK techniques (chip list, conditional), "Analysis generated: {generated_at}". No-verdict state: "No AI investigation has been run for this event yet." + "Click 'Run Investigation' to have ARIA analyze the evidence."

**Integrity tab:** "Verifying bundle integrity..." shown while `!verifyResult()`. Result container has `.verified` or `.tampered` class. Status line: "VERIFIED" or "TAMPERED OR CORRUPTED". Table: Status | Stored Hash (SHA-256, monospace) | Computed Hash (SHA-256, monospace) | Verified At | **Verified By**.

**No bundle selected (empty state):** "Select an evidence bundle to view details, timeline, and chain of custody." + "HIGH and CRITICAL alerts are automatically captured. Manual download available for all alerts via the Alerts page."

### 1.9 EvidenceService API Methods

| Method | HTTP | Endpoint | Description |
|--------|------|----------|-------------|
| `listBundles(limit)` | GET | `/api/evidence/bundles?limit=N` | Lists all bundles for tenant; default limit 50 |
| `getBundle(bundleId)` | GET | `/api/evidence/bundle/:id` | Gets single bundle metadata |
| `getBundleContents(bundleId)` | GET | `/api/evidence/bundle/:id/contents` | Live investigation data — ClickHouse queries + ZIP metadata |
| `verifyBundle(bundleId)` | GET | `/api/evidence/bundle/:id/verify` | SHA-256 integrity check against stored hash |
| `setLegalHold(bundleId, hold, reason)` | POST | `/api/evidence/bundle/:id/hold` | Places or releases legal hold; body `{ hold, reason }` |
| `annotate(bundleId, communityId, note, tag)` | POST | `/api/evidence/bundle/:id/annotate` | Adds analyst annotation |
| `getAnnotations(bundleId)` | GET | `/api/evidence/bundle/:id/annotations` | Returns all annotations for a bundle |
| `getTimeline(communityId)` | GET | `/api/evidence/:cid/timeline` | Attack timeline with narrative, events, uid_logs |
| `getLog(communityId)` | GET | `/api/evidence/:cid/log` | Chain-of-custody audit log |
| `downloadBundle(communityId)` | GET | `/api/evidence/:cid` (blob) | Downloads ZIP; creates object URL and triggers `<a>` click |
| `runInvestigation(communityId)` | POST | `/api/aria/investigate` | Triggers ARIA AI investigation for a community_id |
| `getVerdict(communityId)` | GET | `/api/aria/verdict?cid=...` | Fetches cached AI verdict for a community_id |
| `checkIoc(value)` | GET | `/api/evidence/iocs/check?value=...` | (Unused by UI currently) Checks a single IOC |

### 1.10 Rust Handlers

| Handler | Route | Notes |
|---------|-------|-------|
| `list_evidence_bundles` | `GET /api/evidence/bundles` | Reads `evidence_bundles` ClickHouse table; scoped by `tenant_id` and `sensor_ids` from JWT |
| `get_evidence_bundle` | `GET /api/evidence/bundle/:id` | Single bundle lookup by ID |
| `get_bundle_contents` | `GET /api/evidence/bundle/:id/contents` | Opens ZIP to extract `session_metadata.json`, `alert.json`, PCAP size; calls `evidence::fetch_live_investigation()` for all ClickHouse data; checks OpenSearch for live PCAP session; overrides `threat_intel` from in-memory Feodo Tracker feed |
| `download_evidence_bundle` | `GET /api/evidence/:cid` | Builds ZIP on-demand via `evidence::build_evidence_bundle()`, persists bundle record to ClickHouse, logs evidence action, streams ZIP as attachment |
| `trigger_evidence_capture` | `POST /api/evidence/trigger` | Acquires evidence semaphore (max 4 concurrent), calls `build_evidence_bundle()` in background task, saves result to ClickHouse |
| `verify_evidence_bundle` | `GET /api/evidence/bundle/:id/verify` | Reads ZIP from disk, computes SHA-256, compares against `sha256` column in `evidence_bundles` table |
| `set_evidence_legal_hold` | `POST /api/evidence/bundle/:id/hold` | Updates `legal_hold` and `hold_reason` columns; logs `HOLD_PLACED` or `HOLD_RELEASED` event |
| `annotate_evidence_bundle` | `POST /api/evidence/bundle/:id/annotate` | Inserts row into `evidence_annotations` table |
| `get_evidence_annotations` | `GET /api/evidence/bundle/:id/annotations` | Returns all annotations for a bundle ordered by `created_at` |
| `get_evidence_timeline` | `GET /api/evidence/:cid/timeline` | Builds merged timeline from Agent-Z conn/uid logs and Agent-S events; includes narrative, UID-linked DNS, TLS SNIs, uid_logs |
| `get_evidence_log` | `GET /api/evidence/:cid/log` | Returns `evidence_log` rows for chain-of-custody |
| `aria_investigate` | `POST /api/aria/investigate` | Runs ARIA AI investigation — see detail below |
| `aria_get_verdict` | `GET /api/aria/verdict?cid=...` | Returns stored verdict for a community_id; returns `{ status: "not_found", verdict: null }` if no verdict exists |

#### `aria_investigate` Detail

**Source:** `rust/ndr-engine/src/ai/investigator.rs`

1. Validates JWT; checks `get_tenant_ai_enabled` — returns error if AI is disabled for tenant (`super_admin` bypasses this check).
2. Requires `community_id` in the POST body; returns `{ error: "community_id required" }` if missing.
3. Calls `auto_investigate(ch, tenant_id, community_id)` — assembles evidence context from 4 ClickHouse sources:
   - **Alerts** (`ndr_hits`): up to 10 most recent hits for this `community_id` — rule name, severity, score, tags, src/dst IPs, timestamp.
   - **Threat Intel** (`ndr.threat_intel`): IOC table lookup for every unique IP seen in the alerts (type `ip`/`ip4`/`ip6`), up to 10 matches — shows attack type, severity, description.
   - **Network Events** (`ndr_events`): up to 20 most recent raw events for this `community_id` — source, event type, src/dst IPs and ports, protocol.
   - **Evidence Bundle** (`evidence_bundles`): bundle metadata for this `community_id` — `captured_at`, severity, src/dst IPs (limit 1).
4. Builds a "senior SOC analyst with 15 years of experience" system prompt and submits to the AI via `generate(UseCase::ThreatPrediction)` — uses **"threat" providers** from `ndr.ai_providers` (not the "chat" providers used by ARIA chat).
5. Parses the AI's JSON response into an `AriaVerdict`:

| Field | Type | Description |
|---|---|---|
| `verdict` | `TRUE_POSITIVE \| FALSE_POSITIVE \| SUSPICIOUS` | Validated to exactly these 3 values; any other value maps to `SUSPICIOUS` |
| `confidence` | `u8` (0–100) | Clamped to 100; defaults to 50 if not present |
| `reasoning` | `String` | 2–3 sentence explanation; defaults to "No reasoning provided." |
| `recommended_action` | `String` | One specific next step; defaults to "Review manually." |
| `mitre_techniques` | `Vec<String>` | MITRE technique IDs (e.g. `"T1234"`); empty array if not found |
| `generated_at` | `String` | ISO 8601 UTC timestamp of verdict generation |

6. On JSON parse failure (AI returns unparseable response): **silently degrades** to a safe fallback verdict — `SUSPICIOUS`, confidence `30`, reasoning `"AI investigation inconclusive — response could not be parsed. Manual review required."`, empty `mitre_techniques`.
7. Stores verdict via `save_aria_verdict(tenant_id, community_id, verdict_json)` in the `aria_verdicts` ClickHouse table. If storage fails, logs a warning but **still returns the verdict** to the caller.
8. Returns all 6 AriaVerdict fields in JSON with `"status": "ok"` and the original `"community_id"`.

### 1.11 Data Flow

```
ngOnInit
  └─ loadBundles()
       └─ GET /api/evidence/bundles
            └─ bundles signal → ipGroupedBundles computed → left panel renders
                  └─ auto-select first bundle → selectBundle()
                        ├─ loadTimeline(cid)   → GET /api/evidence/:cid/timeline
                        ├─ loadLog(cid)        → GET /api/evidence/:cid/log
                        ├─ loadAnnotations(id) → GET /api/evidence/bundle/:id/annotations
                        ├─ loadBundleContents(id) → GET /api/evidence/bundle/:id/contents
                        │      └─ Rust: reads ZIP + queries ClickHouse live + OpenSearch check
                        └─ loadVerdict(cid)    → GET /api/aria/verdict?cid=...

runInvestigation(b)
  └─ POST /api/aria/investigate { community_id }
       └─ Rust: ARIA LLM call → stores verdict → returns verdict
            └─ ariaVerdict signal → AI Verdict section renders
```

---

## Page 2 — SOAR

**Route:** `/analyst/soar`  
**Angular component:** `ndr-ui/src/pages/analyst/soar/soar.ts`  
**Template:** `ndr-ui/src/pages/analyst/soar/soar.html`  
**Styles:** `ndr-ui/src/pages/analyst/soar/soar.css`  
**Services:** `ndr-ui/src/services/api/api.ts` (`Api`), `ndr-ui/src/services/arkime/arkime.ts` (`ArkimeService`)

### 2.1 Purpose

Security Orchestration, Automation, and Response hub. Six tabs: **Cases**, **Playbooks**, **Integrations**, **Activity Log**, **Active Blocks**, **Isolated Devices**. A case is a high-fidelity incident record linked to network evidence. Analysts can open PCAP sessions inline, run playbooks, configure integrations (Slack, Teams, firewall, cloud), block IPs, and isolate devices via multiple enforcement mechanisms.

**Page header** (rendered above the tab bar):  
- Eyebrow: "Security Orchestration" (primary color, small caps)  
- H1: "SOAR — Native Automation"  
- Sub-line: "Automated threat response engine — native to NDR"  
- Live status chip (top-right): green dot + "ENGINE RUNNING" in monospaced font

### 2.2 Signals — Cases

| Signal | Type | Description |
|--------|------|-------------|
| `activeTab` | `'cases' \| 'playbooks' \| 'integrations' \| 'activity' \| 'blocks' \| 'isolations'` | Active main tab |
| `loading` | `boolean` | General loading flag |
| `cases` | `any[]` | All SOAR cases for tenant |
| `selectedCase` | `any` | Currently open case object |
| `caseComments` | `any[]` | Comments for selected case |
| `loadingCase` | `boolean` | True while loading case comments |
| `showNewCase` | `boolean` | Show/hide new case creation modal |
| `savingNewCase` | `boolean` | True while create-case API call is in flight |
| `newCaseError` | `string` | Validation/API error for new case form |
| `editingAssignee` | `boolean` | Inline assignee edit mode |
| `showCloseForm` | `boolean` | Show close/resolve confirmation form |
| `pendingStatus` | `string` | Status to apply when close form is confirmed |
| `incidentReport` | `any` | Built incident report object for modal preview |
| `showReportModal` | `boolean` | Show/hide the incident report modal |

### 2.3 Signals — Evidence / Live Data

| Signal | Type | Description |
|--------|------|-------------|
| `evidenceLoading` | `boolean` | True while fetching PCAP sessions and NDR events |
| `liveEvidence` | `any` | `{ pcap_sessions[], pcap_total, ndr_events[] }` — loaded from Arkime + ClickHouse when a case is opened |
| `dismissedSessionIds` | `Set<string>` | Session IDs hidden from live evidence view by analyst |
| `collectingPcap` | `boolean` | True while `triggerEvidenceCapture` is in flight |
| `collectPcapDone` | `boolean` | True after PCAP collection completes (shown for 4 seconds) |
| `showEvidenceOverlay` | `boolean` | Shows Evidence page in an `<iframe>` overlay |
| `evidenceOverlaySrc` | `SafeResourceUrl` | Sanitized URL for the Evidence overlay iframe |
| `selectedSession` | `any` | Session selected for detail view |

### 2.4 Signals — PCAP Viewer

| Signal | Type | Description |
|--------|------|-------------|
| `pcapViewSession` | `any` | Session being viewed in inline PCAP viewer |
| `pcapPackets` | `any[]` | Parsed packet list from binary PCAP parser |
| `pcapLoading` | `boolean` | True while fetching raw PCAP from Arkime |
| `pcapError` | `string` | Error/status message for PCAP viewer |
| `showPcapAnalysis` | `boolean` | Show PCAP analysis panel |
| `pcapAnalysis` | `any` | Computed traffic analysis: `{ totalPackets, totalBytes, protocols, connections, http, dns, tls, icmp }` |
| `paActiveTab` | `string` | Active tab in PCAP analysis panel |
| `expandedPktIdx` | `Set<number>` | Set of packet indices expanded in hex/decode view |

### 2.5 Signals — Playbooks

| Signal | Type | Description |
|--------|------|-------------|
| `playbooks` | `any[]` | All native playbooks for tenant |
| `showNewPlaybook` | `boolean` | Show/hide playbook create/edit modal |
| `savingPb` | `boolean` | True while save is in flight |
| `pbError` | `string` | Validation/API error for playbook form |

### 2.6 Signals — Integrations

| Signal | Type | Description |
|--------|------|-------------|
| `integrations` | `any[]` | All saved integrations |
| `showNewIntegration` | `boolean` | Show/hide integration form |
| `testingInt` | `boolean` | True while test-connection API call is in flight |
| `testResult` | `string` | Test connection result message |
| `savingInt` | `boolean` | True while save is in flight |
| `testingAll` | `boolean` | (Reserved for bulk test) |
| `testAllResults` | `any[]` | (Reserved for bulk test results) |
| `runs` | `any[]` | Playbook execution history |

### 2.7 Signals — Blocks

| Signal | Type | Description |
|--------|------|-------------|
| `activeBlocks` | `any[]` | Currently active IP blocks |
| `loadingBlocks` | `boolean` | True while loading blocks |
| `showBlockModal` | `boolean` | Show/hide manual block form |
| `blockSaving` | `boolean` | True while block API call is in flight |
| `blockError` | `string` | Validation/API error for block form |

### 2.8 Signals — Isolations

| Signal | Type | Description |
|--------|------|-------------|
| `isolations` | `any[]` | All active device isolations |
| `loadingIsolations` | `boolean` | True while loading |
| `showIsolateModal` | `boolean` | Show/hide isolation form |
| `isolateSaving` | `boolean` | True while isolate API call is in flight |
| `isolateError` | `string` | Validation/API error |
| `showIsolationProgress` | `boolean` | Shows animated isolation progress panel |
| `isolationProgressTitle` | `string` | Progress panel title ("Isolating Device" / "Restoring Device") |
| `isolationProgressTarget` | `string` | Target IP being isolated |
| `isolationProgressSteps` | `{ label, status: 'pending' \| 'running' \| 'done' \| 'error' }[]` | Step list with animated status icons |
| `isolationProgressComplete` | `boolean` | True when all steps done |
| `isolationProgressSuccess` | `boolean` | True if isolation succeeded |
| `isolationProgressError` | `string` | Error message if a step failed |

### 2.9 Form Fields (Plain Properties)

| Property | Purpose |
|----------|---------|
| `newComment` | Case comment textarea |
| `sessionNote` | Note for a selected PCAP session |
| `pcapNote` | Note added from within PCAP viewer |
| `closeNotes` | Resolution notes when closing/resolving a case |
| `addToIntel` | Checkbox — add src_ip to threat intel watchlist on close |
| `intelGroup` | Attacker group label for threat intel entry |
| `assigneeInput` | Inline assignee edit input |
| `blockIp` | IP address for manual block |
| `blockPort` | Optional port for manual block |
| `blockDuration` | Duration in hours (default 24) |
| `blockEnforcement` | `'rst' \| 'firewall' \| 'both'` |
| `blockReason` | Optional reason text |
| `isolateIp` | Target IP for isolation |
| `isolateGateway` | Gateway IP (auto-populated from agent status) |
| `isolateEnforcement` | One of 8 enforcement types (see 2.12) |
| `isolateVlan` | Quarantine VLAN (default 999) |
| `isolateReason` | Optional reason |
| `pbName`, `pbDesc` | Playbook name and description |
| `pbCondField` | Condition field: `'score' \| 'severity' \| 'src_country' \| 'sigma_tag' \| 'threat_intel'` |
| `pbCondOp` | Condition operator (context-sensitive via `condOps` getter) |
| `pbCondValue` | Condition value |
| `pbActionType` | Action type: `'slack'` \| `'teams'` \| `'discord'` \| `'webhook'` \| `'email'` \| `'create_case'` \| `'block_ip'` |
| `pbActionConfig` | JSON config object for the action |
| `editingPbId` | `string \| null` — null = create, string = edit |
| `intType` | Integration type |
| `intName` | Integration display name |
| `intConfig` | Integration config object |
| `editingIntId` | `string \| null` |
| `newCaseTitle`, `newCaseDescription` | New case form fields |
| `newCaseSeverity` | `'HIGH'` default |
| `newCasePriority` | `'P2'` default |
| `newCaseAssignedTo` | Pre-filled with `currentUsername` |
| `newCaseSrcIp`, `newCaseDstIp` | Optional IPs for new case |
| `newCaseTags` | Comma-separated tags string |

### 2.10 Computed Signals

**`caseStats`**  
Computes from `cases()` signal:  
- `active`: cases not in `['Closed', 'False Positive']`  
- `inProgress`: cases with `status === 'In Progress'`  
- `resolvedToday`: cases resolved today (compares `closed_at` epoch to today midnight)  
- `avgHrs`: average resolution time in hours across all closed cases with both `created_at` and `closed_at`

**`visibleSessions`**  
Filters `liveEvidence().pcap_sessions` to exclude session IDs in `dismissedSessionIds`.

### 2.11 Constants

**`isolationEnforcementTypes`** — 8 enforcement methods:
- `arp` — ARP Spoofing (instant, agent-side)
- `unifi` — UniFi Block Station (REST)
- `cisco` — Cisco IOS VLAN quarantine (SNMP)
- `aruba` — Aruba CX Access VLAN (REST)
- `snmp` — Generic Switch VLAN quarantine (SNMP)
- `aws_sg` — AWS Security Group revoke ingress
- `azure_nsg` — Azure NSG Deny inbound rule
- `gcp_vpc` — GCP VPC Firewall Deny ingress rule

**`integrationTypes`** — 19 integration definitions with per-type connection fields:

**Notification group (`notify`)**

| Type | Abbr | Connection Fields |
|------|------|-------------------|
| `slack` | SLK | `webhook_url` — Webhook URL (text) |
| `teams` | TMS | `webhook_url` — Webhook URL (text) |
| `discord` | DSC | `webhook_url` — Webhook URL (text) |
| `webhook` | WHK | `webhook_url` — Endpoint URL (text) |
| `pagerduty` | PDY | `routing_key` — Routing Key (password) |
| `telegram` | TGM | `bot_token` — Bot Token (password); `chat_id` — Chat ID (text) |
| `smtp` | EML | `smtp_host` — SMTP Host; `smtp_port` — SMTP Port; `smtp_user` — Username; `smtp_pass` — Password; `from_addr` — From Address; `to_addr` — Recipient (text) |

**Firewall / Block group (`firewall`)**

| Type | Abbr | Connection Fields |
|------|------|-------------------|
| `pfsense` | PFS | `host` — Host (text); `api_key` — API Key (password) |
| `fortinet` | FGT | `host` — Host (text); `api_key` — API Key (password); `vdom` — VDOM (default: `root`) |
| `panos` | PAN | `host` — Host (text); `api_key` — API Key (password) |
| `opnsense` | OPN | `host` — Host (text); `api_key` — Key:Secret (`key:secret` format, password) |

**Switch Isolation group (`switch`)**

| Type | Abbr | Connection Fields |
|------|------|-------------------|
| `unifi` | UFI | `host` — Controller URL; `username`; `password`; `site` (default: `default`) |
| `cisco` | CSC | `host` — Switch IP; `community` — Write Community (password); `port_ifindex` — Port ifIndex |
| `aruba` | ARB | `host` — Switch URL; `username`; `password`; `port` — Port (e.g. `1/1/5`) |
| `snmp` | SNM | `host` — Switch IP; `community` — Write Community (password); `port_ifindex` — Port ifIndex |

**Cloud Firewall group (`cloud`)**

| Type | Abbr | Connection Fields |
|------|------|-------------------|
| `aws_sg` | AWS | `sg_id` — Security Group ID; `region` — Region; `aws_access_key_id` — Access Key ID; `aws_secret_access_key` — Secret Access Key (password) |
| `azure_nsg` | AZR | `resource_group` — Resource Group; `nsg_name` — NSG Name; `subscription_id` — Subscription ID (optional) |
| `gcp_vpc` | GCP | `project` — Project ID; `network` — Network name |

Password-type fields render as `<input type="password">` in the modal. Selecting a type resets `intConfig = {}`.

**`WORKFLOW_STATES`** — ordered list (7 steps shown in the visual stepper): `New → Assigned → In Progress → Pending → Under Review → Resolved → Closed`

**`WORKFLOW_NEXT`** — valid transitions from each state (guards what status buttons are shown):

| From | Allowed Next States |
|------|---------------------|
| `New` | Assigned, In Progress, False Positive |
| `Assigned` | In Progress, Pending, False Positive |
| `In Progress` | Pending, Under Review, Resolved, False Positive |
| `Pending` | In Progress, Resolved, Closed, False Positive |
| `Under Review` | In Progress, Resolved, Closed, False Positive |
| `Resolved` | Closed, In Progress |
| `Closed` | New |
| `False Positive` | New |
| `Evidence Collected` | In Progress, Resolved, Closed, False Positive |

Note: `False Positive` and `Evidence Collected` appear in `WORKFLOW_NEXT` as source keys but are **not in `WORKFLOW_STATES`** — they do not appear as dots in the visual stepper.

### 2.12 Lifecycle / Data Loaders

**`ngOnInit()`**  
Reads `sensorIds` and `currentUsername` from JWT. Calls `loadCases()`, `loadPlaybooks()`, `loadIntegrations()`, `loadRuns()`.

**`switchTab(tab)`**  
Sets `activeTab`, then calls the appropriate loader for the new tab (`loadCases`, `loadPlaybooks`, `loadIntegrations`, `loadRuns`, `loadBlocks`, `loadIsolations`).

**`loadCases()`** — `GET /api/soar/cases`  
**`loadPlaybooks()`** — `GET /api/soar/native/playbooks`  
**`loadIntegrations()`** — `GET /api/soar/integrations`  
**`loadRuns()`** — `GET /api/soar/runs`  
**`loadBlocks()`** — `GET /api/blocks`  
**`loadIsolations()`** — `GET /api/isolations`

### 2.13 Case Operations

**`openCase(c)`**  
1. Sets `selectedCase`, resets all PCAP/session state.  
2. Calls `getSoarCaseComments(c.id)`.  
3. If case has `src_ip + dst_ip` **or** `community_id`, fires parallel loads:  
   - PCAP sessions: if `src_ip + dst_ip` → `arkime.getSessions({ src_ip, dst_ip, limit: 50 })`; if only `community_id` → `arkime.getSessions({ cid, limit: 50 })`. Fills `liveEvidence.pcap_sessions`.  
   - `getEventsByCid(c.community_id)` — fills `liveEvidence.ndr_events` (only when `community_id` is present)

**`closeCaseModal()`** — Clears all case-related state.

**`updateCaseStatus(status)`**  
- For `Resolved` / `Closed`: shows close form (sets `pendingStatus`, pre-fills `addToIntel`, `intelGroup`).  
- For `Assigned`: auto-sets assignee to `currentUsername` if unset.  
- Otherwise calls `_doUpdateStatus(status)` directly.

**`_doUpdateStatus(status)`**  
Calls `updateSoarCaseStatus(id, status)`. On success optimistically updates `selectedCase`: sets `status` and sets `closed_at` to current epoch if status is `Resolved`, `Closed`, or `False Positive` (sets `closed_at = null` for all other statuses). Then reloads cases. Note: `False Positive` bypasses the close form — it goes directly through `_doUpdateStatus` (only `Resolved` and `Closed` show the close form).

**`confirmClose()`**  
Calls `_doUpdateStatus(pendingStatus())`. If `addToIntel` and `src_ip` present, calls `addManualIoc('ip', src_ip, intelGroup)`. Builds and sets `incidentReport` (sets `intel_added` string only when `addToIntel && src_ip`), adds closing comment with notes, shows report modal. `addToIntel` is pre-filled as `!!c.src_ip` (only true when the case has a source IP). `intelGroup` is pre-filled from the case's tags joined with `, `.

**`openCaseReport()`**  
Rebuilds `incidentReport` from current case + `_resolutionFromComments()`. Shows report modal.

**`_resolutionFromComments(c)`**  
Searches `caseComments` in reverse order: first prefers a comment matching `[Closed|Resolved|False Positive]` prefix pattern, then falls back to last non-system comment, then `c.resolution`.

**`addComment()`**  
Guards on `newComment` being non-empty. Calls `addSoarCaseComment(c.id, text)`. On success clears input and reopens case.

**`collectPcap()`**  
Calls `triggerEvidenceCapture(c.community_id)`. On success sets `collectPcapDone = true`, then reopens case after 4 seconds.

**`openNewCaseModal()` / `submitNewCase()`**  
`openNewCaseModal()` resets all form fields and pre-fills `newCaseAssignedTo` with `currentUsername`. Defaults: severity=`HIGH`, priority=`P2`. `submitNewCase()` validates title (required), parses `newCaseTags` by splitting on `,`, trimming and filtering empty entries, then calls `createSoarCase()`. Reloads cases on success.

**`startEditAssignee()` / `saveAssignee()`**  
Inline edit: sets `assigneeInput` from current case, enables edit mode, then calls `updateSoarCase()` with `assigned_to`. Updates `selectedCase` optimistically.

**`viewEvidence(cid)`**  
Builds URL `/analyst/evidence?cid=...&src_ip=...&dst_ip=...`, sanitizes it, and sets `evidenceOverlaySrc` + `showEvidenceOverlay`. Opens Evidence page in an iframe overlay.

**`dismissSession(sessionId)`**  
Adds session ID to `dismissedSessionIds` — hides it from `visibleSessions` computed.

### 2.14 Session Detail / PCAP Viewer

**`analyzeSession(session)`** — Sets `selectedSession`, clears `sessionNote`.  
**`closeSessionDetail()`** — Clears `selectedSession` and `sessionNote`.  
**`addSessionNote(session)`** — Formats comment as `[SESSION NOTE — src:port → dst:port PROTO] text`. Calls `addSoarCaseComment`, reopens case.

**`openPcapViewer(session)`**  
- Resets state (`pcapViewSession`, `pcapPackets`, `pcapError`, `pcapNote`, `expandedPktIdx`), calls `arkime.fetchPcapRaw(id, node, session)`.  
- Handles magic-byte checks: first byte `0x7b` (JSON `{`), `0x3c` (`<`), or `0x50` → JSON parse for error message; PCAP-NG magic (`0x0a0d0d0a`) → download prompt; else attempts parse with `parsePcap()`.  
- 502 error → "Arkime is not running" message; 404 → "No packet capture stored" message.

**`closePcapViewer()`** — Clears `pcapViewSession`, `pcapPackets`, and `pcapNote`.

**`togglePktExpand(idx)`** — Adds or removes `idx` from `expandedPktIdx` set; controls expanded packet detail row in packet table.

**`parsePcap(buf)`** — Pure binary parser. Reads global PCAP header (magic bytes determine endianness; magic `0x0a0d0d0a` → PCAP-NG rejected with error). Link type from header byte 20: `1` = Ethernet → `parseEthernet`; `101` = Raw IPv4 → dispatches directly to `parseIPv4` at offset 0. Each packet record: `{ idx, ts (ms relative to first packet), len, orig_len, hexLines }` plus protocol-specific fields.

**`parseEthernet(data, pkt)`** — Extracts `dst_mac`, `src_mac`. EtherType dispatch: `0x0800` → IPv4 (`parseIPv4`); `0x0806` → `proto='ARP'`, `info='ARP request/reply'`; `0x86DD` → `proto='IPv6'`, `info='IPv6'`; unknown → `proto='0x{hex}'`, `info='EtherType 0x{hex}'`.

**`parseIPv4(data, off, pkt)`** — Extracts `src_ip`, `dst_ip`, `ttl`, `ipId`. Protocol dispatch: `6` → `parseTCP`; `17` → `parseUDP`; `1` → `parseICMP`; other → `proto='IP/{num}'`.

**`parseTCP(data, off, pkt)`** — Extracts ports, TCP flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH` combined as `+`-joined string). Payload classification:
- HTTP: detected by first-line regex (`GET /`, `POST /`, `HTTP/`, etc.) → `proto='HTTP'`. Parses `httpFirstLine`, `httpHeaders` (array of `{k,v}`). Body: if `Content-Encoding` is `gzip`/`deflate`/`br` → sets `httpBodyNote` ("Body is gzip-compressed — download PCAP..."), no body shown. Otherwise sets `httpBody` (up to 1024 chars from body start). 
- TLS: detected by `0x16 0x03` prefix → `proto='TLS'`. Extracts version: `pl[2]=1`→TLS 1.0, `pl[2]=2`→TLS 1.1, `pl[2]=3`→TLS 1.2. Handshake type (`pl[5]`): `1`=ClientHello, `2`=ServerHello, `11`=Certificate, `12`=ServerKeyExchange, `14`=ServerHelloDone, `16`=ClientKeyExchange, `20`=ChangeCipherSpec. For ClientHello: walks TLS extensions to find SNI (extension type `0`), extracts server name and appends to `tlsDecoded`.
- Otherwise: `info = 'src:port → dst:port [flags]'`.

**`parseUDP(data, off, pkt)`** — Port 53 → `proto='DNS'`, calls `parseDNS`. Port 67 → `proto='DHCP'`, `info='DHCP'`. Others → `info='src:port → dst:port'`.

**`parseDNS(data, pkt)`** — Reads DNS header flags (QR bit, RCODE). Parses question section: `qname` via pointer-following name reader, `qtype` from QTYPE lookup table: `1`=A, `2`=NS, `5`=CNAME, `6`=SOA, `12`=PTR, `15`=MX, `16`=TXT, `28`=AAAA, `33`=SRV, `255`=ANY. `pkt.dnsDecoded` array: Direction, Name, Type, Questions, Answers, and Status (for responses). RCODE names: 0=No Error, 1=Format Error, 2=Server Failure, 3=NXDOMAIN, 5=Refused.

**`parseICMP(data, off, pkt)`** — Reads type/code bytes. ICMP type names: `0`=Echo Reply, `3`=Dest Unreachable, `4`=Source Quench, `5`=Redirect, `8`=Echo Request, `9`=Router Advertisement, `10`=Router Solicitation, `11`=Time Exceeded, `12`=Parameter Problem, `13`=Timestamp, `14`=Timestamp Reply, `30`=Traceroute. For type 3 (Dest Unreachable): code names: `0`=Net Unreachable, `1`=Host Unreachable, `2`=Protocol Unreachable, `3`=Port Unreachable, `4`=Fragmentation Needed, `9`=Net Admin Prohibited, `10`=Host Admin Prohibited, `13`=Communication Prohibited. For types 8/0 (Echo Request/Reply): reads `identifier` and `sequence` fields. `pkt.icmpDecoded` carries the decoded fields array.

**`addPcapNote()`** — Formats comment as `[PCAP ANALYSIS — flow] text`. Calls `addSoarCaseComment`.

**`downloadPcap(session)`** — Calls `arkime.downloadPcap(id, node, session)`.

**`toHexLines(data)` (private)**  
Formats up to first 512 bytes of raw packet data as hex dump strings. Each line: 16-byte offset (4-digit hex) + hex column (space-separated, padded to 47 chars) + ASCII column (dots for non-printable). If packet exceeds 512 bytes, appends `"... N more bytes"` as final line. These lines are stored in `pkt.hexLines` and rendered in the raw hex dump block.

**`openPcapAnalysis()`**  
Aggregates packet data into: total bytes/packets, protocol distribution map, connection map (bidirectional keyed by sorted endpoint pair), HTTP transaction list (first line + host + content-type + UA), DNS lookup map (deduped by name+type, prefers response status over query), TLS SNI map (deduped by SNI key, counts packets), ICMP list. Sets `pcapAnalysis` and shows analysis panel. Resets `paActiveTab` to `'overview'`. Calls `drawPcapChart()` after 60ms delay.

**`setpaTab(tab)`** — Sets `paActiveTab`. If switching to `'overview'`, calls `drawPcapChart()` after 60ms (re-renders the canvas chart because the canvas may have been hidden).

**`drawPcapChart()`**  
Renders a stacked area chart on `#pa-chart-canvas` (Canvas API). Buckets packets by relative timestamp into 60 time slots. Draws per-protocol stacked areas using `quadraticCurveTo` for smooth curves. Labels: protocol colors (HTTP=green, TLS=blue, DNS=yellow, TCP=sky, UDP=purple, ICMP=orange, ARP=pink). Y-axis: byte volume in human-readable format.

**`protoColor(proto)`** — Returns Tailwind text color class per protocol.

**`isKeyHeader(key)`** — Returns true for security-relevant HTTP headers: Host, Content-Type, User-Agent, Authorization, Cookie, Set-Cookie, Location, Server, X-Forwarded-For.

### 2.15 Block Operations

**`openBlockModal()`** — Resets form, shows modal.  
**`submitManualBlock()`** — Validates IP, calls `manualBlock()`. Reloads blocks on success.  
**`revokeBlock(b)`** — Confirms with `window.confirm`, calls `revokeBlock(b.id, b.sensor_id)`. Reloads blocks.

### 2.16 Isolation Operations

**`openIsolateModal()`**  
Resets form, shows modal. Also calls `getAgentStatus()` to auto-populate `isolateGateway` from the sensor's detected gateway.

**`startIsolationProgress(title, target, steps)`**  
Initializes progress panel with all steps in `'pending'` state. Shows panel.

**`runIsolationSteps(apiCall, stepDelays)`** (async)  
Animates step-by-step progress:  
1. Immediately advances step 0 to `running`.  
2. Schedules intermediate step advances via `setTimeout` at given delays.  
3. Awaits the API promise.  
4. On success: marks all steps `done`, sets `isolationProgressSuccess = true`.  
5. On failure: marks the running step as `error`, sets error message.  
6. Always calls `loadIsolations()` afterwards.

**`submitIsolation()`**  
Validates IP, closes modal, determines step labels based on enforcement type (ARP vs cloud/switch), calls `startIsolationProgress()`, wraps `isolateDevice()` in a Promise, calls `runIsolationSteps()` with delays `[800, 1800, 2800]`.

**`restoreIsolation(iso)`**  
Same progress animation pattern, calls `unisolateDevice(iso.id)`.

**`closeIsolationProgress()`** — Hides progress panel.  
**`isolationMethodLabel(enforcement)`** — Returns the short name (before " — ") from `isolationEnforcementTypes`.

### 2.17 Playbook Operations

**`togglePlaybook(pb)`** — Flips `pb.enabled` (0/1), calls `updateNativePlaybook()`.  
**`deletePlaybook(pb)`** — Confirms, calls `deleteNativePlaybook()`.  
**`savePlaybook()`** — Validates name (required). Serializes `pbActionConfig` with `JSON.stringify` before sending. Calls create or update API based on `editingPbId`. On failure (no status === 'success'): sets `pbError` from `res.message`.  
**`initPlaybookModal()`** — Resets form to defaults: `pbCondField='score'`, `pbCondOp='>'`, `pbCondValue='75'`, `pbActionType='slack'`, `pbActionConfig={}`. Shows modal.  
**`openEditPlaybook(pb)`** — Populates form from existing playbook. Parses `pb.action_config` with `JSON.parse` if it is a string; on JSON parse error falls back to `{}`. Shows modal.

**`condOps` getter** — Returns valid operators based on `pbCondField`:  
- `score` → `>, >=, <, <=, ==`  
- `severity` / `src_country` / `sigma_tag` → `==, contains`  
- `threat_intel` / default → `==`

Note: The HTML `<select>` for condition field only exposes **3 options**: `score` (Risk Score), `severity` (Severity), `threat_intel` (Threat Intel). The `src_country` and `sigma_tag` cases exist in `condOps` but have no corresponding `<option>` in the template.

**`condValueType` getter** — `'severity'` for severity field → renders severity `<select>` (LOW/MEDIUM/HIGH/CRITICAL); `'bool'` for threat_intel → renders bool `<select>` (true/false); `'text'` otherwise → renders text `<input>` (placeholder: `75` for score, `CN` for others).  
**`onCondFieldChange()`** — Resets `pbCondOp` to first allowed operator and sets `pbCondValue` default: `'true'` for threat_intel, `'HIGH'` for severity, `'75'` otherwise.

### 2.18 Integration Operations

**`integrationsByGroup(group)`** — Filters `integrationTypes` by group string.  
**`getIntAbbr(type)`** — Returns 3-letter abbreviation for display (e.g. `'SLK'` for Slack). Falls back to `type.slice(0,3).toUpperCase()` for unknown types.  
**`getIntIcon(type)`** — Alias for `getIntAbbr(type)`.  
**`selectedIntType` getter** — Returns full integration definition for current `intType` (used for dynamic form `fields` list in integration modal).  
**`testIntegration()`** — Calls `testIntegration({ type, config })`, shows result message. Success responses contain `✅`; failure responses contain `❌` — used for green/red styling in the modal.  
**`openEditIntegration(int)`** — Populates form from existing integration (`editingIntId`, `intType`, `intName`, `intConfig`), clears `testResult`, shows modal.  
**`saveIntegration()`** — Calls create or update based on `editingIntId`. If `intName` is empty, falls back to `selectedIntType.name`. Reloads list on success.  
**`toggleIntegration(int)`** — Flips `int.enabled` (boolean), calls `toggleIntegration({ id, enabled })`.  
**`deleteIntegration(int)`** — Confirms with `window.confirm("Delete {name}?")`, calls `deleteIntegration({ id })`.

### 2.19 Workflow Helpers

**`nextStates(status)`** — Returns allowed next states from `WORKFLOW_NEXT` map.  
**`statusClass(status)`** — Maps status to CSS class (e.g. `status-new`, `status-inprogress`, `status-resolved`).  
**`priorityClass(p)`** — Maps P1/P2/P3/P4 to CSS classes.  
**`severityClass(sev)`** — Maps CRITICAL/HIGH/MEDIUM/LOW to CSS classes.  
**`getCaseColor(severity)`** — Returns Tailwind text+bg class pair for severity chips.

### 2.20 Incident Report Generation

**`downloadReport(format)`** — Builds HTML report string via `_buildReportHtml(r)`. For `'html'`: creates object URL, triggers download. For `'pdf'`: opens blob URL in new window, calls `window.print()` after 400ms.

**`_buildReportHtml(r)`** — Generates a self-contained A4-format HTML page. Structure (in order):

1. **Page header**: PromaSecure NDR logo + "Security Operations — Incident Response" sub-brand. Right side: case number (large), "Generated: {closed_at}", "Analyst: {analyst}", "Classification: CONFIDENTIAL".
2. **CONFIDENTIAL badge**: red bordered badge "⚠ Confidential — Internal Use Only".
3. **Title block**: `<h1>` with case title, then badges (severity in severity color, priority blue, status green, tags grey).
4. **Executive Summary**: auto-generated paragraph — describes severity, tag, case number, attacker→victim IPs, session count, total bytes, packet count, NDR event count, analyst name, closed date.
5. **Incident Details grid** (3-column): Case Number, Lead Analyst, Closed/Resolved, Attacker IP (red), Victim IP (blue), Severity/Priority, Attack Tags (full row), Description (full row, conditional).
6. **Network Traffic Summary** — 6 stat tiles: PCAP Sessions, Total Traffic, Total Packets, Source IPs, Dest IPs, NDR Events.
7. **PCAP Traffic Analysis** (conditional, only if sessions exist): 4 SVG charts in sequence:
   - Session Timeline (18-bucket bar chart with time axis labels and session count labels above bars)
   - Protocol Distribution (Sessions) — horizontal bar chart
   - Protocol Distribution (Bytes) — horizontal bar chart
   - Top Connections by Traffic Volume — horizontal bar chart (top 8 sessions by bytes)
8. **PCAP Session Log table**: ALL sessions (no limit) — columns: Timestamp, Source ip:port, Destination ip:port, Protocol, Bytes, Packets.
9. **Correlated NDR Events table** (conditional): ALL events — columns: Timestamp, Event Type, Source, Destination, Details.
10. **Resolution**: green left-border box with resolution notes.
11. **Intel confirm** (conditional): green badge "✓ {ip} added to threat intel watchlist".
12. **Analyst Declaration**: formal paragraph — analyst name, case number, session count, packet count, NDR event count, attacker/victim IPs, certification statement.
13. **3-column Signature block**: Analyst Signature line, Date line, Case Ref line (print signature areas).
14. **Fixed page footer** (position:fixed on print): "PromaSecure NDR Platform · {case_number}" | "CONFIDENTIAL — Internal Use Only" | "{closed_at}".

All SVG charts use inline hex colors; the page is print-ready with `@page { size: A4 portrait; margin:0 }` and `-webkit-print-color-adjust: exact`.

### 2.21 Formatting Helpers

| Method | Description |
|--------|-------------|
| `formatTs(ts)` | Unix epoch (seconds) → `hh:mm:ss` local time string |
| `formatPcapTime(ms)` | Millisecond timestamp → `hh:mm:ss` |
| `formatDateShort(ts)` | Epoch (sec or Date) → `Mon D, hh:mm` |
| `formatDate(ts)` | Epoch (sec or Date) → full locale string |
| `sessionDuration(s)` | `end_time - start_time` ms → human string (`Xms` or `X.XXs`) |
| `formatBytes(b)` | Number → `B / KB / MB` with appropriate precision |
| `protocolList()` | Extracts sorted `[{ proto, count }]` from `pcapAnalysis.protocols` |

### 2.22 HTML Template Behaviour

**Main tab bar** — 6 tabs. Clicking calls `switchTab()`. Active border color and text differ per tab:
- **Cases** — active: primary-colored border; badge shows `cases().length` if > 0
- **Playbooks** — active: primary-colored border
- **Integrations** — active: primary-colored border
- **Activity Log** — active: primary-colored border
- **Active Blocks** — active: **red border** (`border-red-400`); badge shows `activeBlocks().length` if > 0
- **Isolated Devices** — active: **amber border** (`border-amber-400`); badge shows `isolations().length` if > 0

---

#### Cases Tab

**Stats bar** (hidden when a case is selected — `*ngIf="!selectedCase()"`)  
Four stat tiles rendered from `caseStats()`:
- Active Cases
- In Progress
- Resolved Today
- Avg Resolution (hours)

**Split pane layout**: left column (case list) + right column (case detail). The left column renders in two modes:

**Full table view** (no case selected — `*ngIf="!selectedCase()"`):  
Columns: Ticket ID | Priority | Title + src/dst flow | Severity | Status | Assigned To | Created

**Compact rail view** (case selected — `*ngIf="selectedCase()"`):  
Small cards per case showing: `case_number` + status badge / title / severity + priority badges + date. Selected card gets `.active` class.

**Toolbar**: "{N} case(s)" count label + "New Case" button (always visible).

**Empty state** (when `cases().length === 0`): centered icon + "No cases found" + "Create a case manually or let playbooks generate them automatically." + "New Case" button.

**"New Case" button** — always visible in the toolbar, opens `showNewCase` modal.

---

#### Case Detail — Right Column

**Header row:**
- Left: Ticket ID block (large), title
- Middle: Severity badge, Priority badge, Status badge, created date
- Right: "Report" download button — **only rendered when status is `Closed`, `Resolved`, or `False Positive`** (`*ngIf` guard on status); ✕ close button

**Metadata grid:**
| Field | Notes |
|-------|-------|
| Source IP | From `selectedCase().src_ip` |
| Destination IP | From `selectedCase().dst_ip` |
| Community ID | From `selectedCase().community_id` |
| Full Bundle ↗ | Link button — **only shown when `community_id` is present** — calls `viewEvidence(community_id)` to open Evidence overlay |
| Assigned To | Shows current assignee with "Change" button (if set) or "Assign" button (if empty). Clicking switches to inline edit: text input pre-filled with current value + "Save" button (calls `saveAssignee()`) + "✕" Cancel button (calls `editingAssignee.set(false)` inline — no separate method) |

**Workflow section:**
- Visual horizontal stepper: all `WORKFLOW_STATES` rendered as dots in sequence. Each dot gets `.active` CSS class if it matches the current status, and `.past` class for all states before the current one.
- Below the stepper: one button per valid next state from `nextStates(status)`. Button CSS classes differ per type:
  - `btn-fp` for False Positive
  - `btn-resolve` for Resolved
  - `btn-close` for Closed
  - `btn-next` for all others (Next, Assign, etc.)
- Clicking a button calls `updateCaseStatus(state)`.

**Description section** — `*ngIf="selectedCase().description"` — renders case description text.

**Inline Incident Report preview card** — `*ngIf="incidentReport()"` — renders a condensed summary card inside the case body (not the full modal). Shows: case_number, severity, status, title, Attacker IP (red), Victim IP (blue), Analyst, Closed At, PCAP Sessions count, Tags, Resolution Notes, Intel badge (if threat intel was added). This card is set when `confirmClose()` runs.

**Close/Resolve inline form** — `*ngIf="showCloseForm()"`:
- Header: "Closing as: {pendingStatus}" 
- Checkbox "Add attacker IP to Threat Intel watchlist" — **only rendered when `src_ip` is present**
- Attacker Group/Campaign text input — **only rendered when `addToIntel && src_ip`**
- Resolution Notes textarea (bound to `closeNotes`)
- "Cancel" button (clears form), "{pendingStatus()} & Generate Report" button (calls `confirmClose()`)

**Evidence panel** (inside case detail, below metadata):
- Loading spinner state when `evidenceLoading()`
- Live data state: renders PCAP Sessions section + NDR Events section + Case Notes

---

#### PCAP Sessions Section

**Header:** "PCAP SESSIONS (N · M removed)" — N = `visibleSessions().length`, M = dismissed count. "⬡ Collect PCAP" button (calls `collectPcap()`) — **only rendered when `community_id` is present**. While collecting: button text changes to "⟳ Collecting..." and is disabled.

**No-sessions fallback** (`#noPcap` template): "No PCAP sessions captured for this flow." If `collectPcapDone()`, also shows "Collection triggered — sessions will appear shortly." in emerald text.

**Session table columns:** Time | Source (ip:port) | Destination (ip:port) | Proto | Bytes | Pkts | Actions

**Per-row action buttons** — hidden by default, appear on row hover via Tailwind `group/pcap-row` + `opacity-0 group-hover:opacity-100`:
- **"Metadata"** → `analyzeSession(s)` — opens Session Detail panel
- **"⬡ Raw PCAP"** → `openPcapViewer(s)` — opens inline PCAP viewer with binary decode
- **"↓"** → `downloadPcap(s)` — downloads raw PCAP file via Arkime
- **"✕"** → `dismissSession(s.id)` — hides session from `visibleSessions` computed

---

#### Session Detail Panel — `*ngIf="selectedSession()"`

Renders to the right of the session table when a session is selected via "Metadata" button.

**Flow section:** src IP, dst IP, protocol, duration, bytes + packets, data_bytes, sensor_host, community_id

**TCP Flags section:** SYN×n, SYN-ACK×n, RST×n, FIN×n — each shown as a count badge

**HTTP section** (each field conditional — only rendered if value is non-empty):
- Method, Host, URI, Status code, User-Agent, Content-Type

**DNS section** (conditional): query host, type, status

**TLS section** (conditional): SNI, JA3, JA3S

**"↓ Download Raw PCAP" button** — calls `downloadPcap(selectedSession())`

**Analyst Notes textarea** (bound to `sessionNote`) + "Add Note to Case" button (calls `addSessionNote(selectedSession())`) + Close button

---

#### Raw PCAP Viewer — `*ngIf="pcapViewSession()"`

Opens in the right column when "⬡ Raw PCAP" is clicked.

**Header row:** flow info (src:port → dst:port PROTO), packet count badge, "⬡ Analyze" button (calls `openPcapAnalysis()`), "↓ Download" button, "✕ Close" button

**States:** Loading spinner (`pcapLoading()`), Error card (`pcapError()`), Packet table

**Packet table columns:** # | Time (shown as offset from first packet — ms or µs) | Source → Destination | Protocol badge | Length | Info | Expand icon

**Expanded packet detail** (clicking a row toggles `expandedPktIdx`):
- **TCP flags pills** — SYN, ACK, PSH, RST, FIN, URG badges
- **HTTP decoded block** — first request/response line in a code block, then headers table (key → value, security-relevant headers highlighted via `isKeyHeader()`), then body content or "(binary body not shown)" note
- **DNS decoded table** — Name, Type, Class, TTL, Data columns
- **TLS decoded table** — Record type, Version, Handshake type, SNI
- **ICMP decoded table** — Type, Code, Description
- **Raw hex dump** (fallback when no decoded layer) — 16-byte rows with hex + ASCII columns

**Analyst notes textarea** (bound to `pcapNote`) + "Add to Case Timeline" button (calls `addPcapNote()`)

---

#### PCAP Analysis Modal — `*ngIf="showPcapAnalysis()"`

Full-screen overlay (`z-50`). Overlay click calls `openPcapAnalysis()` toggle-off; inner modal has `(click).stopPropagation()`.

**Top bar:** NDR logo chip + flow breadcrumb (src:port → dst:port) + "✕ Close" button

**Left sidebar nav — 6 items**, each with a badge count; disabled (greyed) if the data array is empty:
| Nav Item | Tab Key | Badge Source |
|----------|---------|--------------|
| ◈ Data Overview | `overview` | always enabled |
| ⇌ Connections | `connections` | `connections.length` |
| ⇄ HTTP | `http` | `http.length` |
| ◉ DNS | `dns` | `dns.length` |
| ⬡ SSL / TLS | `tls` | `tls.length` |
| ◎ ICMP | `icmp` | `icmp.length` |

**Overview pane** (`paActiveTab === 'overview'`):
- Stacked area canvas chart on `#pa-chart-canvas` (rendered by `drawPcapChart()`)
- Protocol legend: colored dot + protocol name + packet count per protocol
- **6 summary cards**: Total Packets | Captured Data | Network Flows | HTTP Transactions | DNS Queries | TLS Hosts
- Protocol breakdown section: per-protocol horizontal bars with %-width fill proportional to byte share

**Connections pane:** Table of bidirectional flows — Source IP:port | Destination IP:port | Proto badge | Packets | Bytes

**HTTP pane:** Table of transactions — Request/Response first line | Host | Content-Type

**DNS pane:** Table — Domain Name | Type chip | Status chip (ok=green / err=red / query=grey)

**TLS pane:** Table — SNI | Destination IP | Handshake Type | Packets count

**ICMP pane:** Table — Description | Source IP | Destination IP

---

#### NDR Events Section

Table columns: Time | Source (AGENT-Z blue badge or AGENT-S orange badge) | Type | Flow (src:port → dst:port) | Proto

---

#### Case Notes / Timeline Section

Timeline rendered chronologically:
- **First entry always present — system-generated:** "Case {case_number} created — Status: {initial_status}" — displayed with "SYSTEM" author badge
- Then each `caseComments()` entry as a timeline row: dot indicator + author name + relative time + comment text

**Add comment:** text input (bound to `newComment`, Enter key submits) + "Add Note" button → `addComment()`

---

#### Playbooks Tab

**Toolbar:** "{N} playbook(s) defined" count + "New Playbook" button  
**Empty state:** centered icon + "No playbooks configured" + "Create a playbook to automate response actions." + "New Playbook" button

**Playbook table columns:**

| Column | Renders |
|--------|---------|
| Enabled | Toggle switch — calls `togglePlaybook(pb)` |
| Playbook | Left color bar (severity of trigger) + playbook name (bold) + description (smaller text) |
| Trigger Condition | `cond_field op cond_value` rendered in a `<code>` block |
| Action | Abbr chip (3-letter) + action type name |
| Runs | `run_count` numeric value |
| (Edit/Delete) | Edit icon + Delete icon — appear on row hover |

**New/Edit Playbook modal fields:**
- Name* (text)
- Description (text)
- **Trigger Condition** (grouped border box, 3-column grid): Condition Field `<select>` (3 options: Risk Score / Severity / Threat Intel) | Operator `<select>` (context-sensitive) | Value (severity-select / bool-select / text-input depending on field)
- **Response Action** (grouped border box): Action Type `<select>` with **7 options**; follow-up fields appear based on selection:
- Error message (`pbError()`) in red box
- Footer: "Cancel" + **"Create Playbook"** / **"Save Changes"** button (shows "Saving…" while `savingPb()`)

**Action Type — 7 options** with different follow-up fields:

| Action Type Value | Label | Extra Fields Shown |
|-------------------|-------|--------------------|
| `create_case` | Create Security Case | Informational note only ("A new security case will be created…") |
| `slack` | Send Slack Notification | Webhook URL field |
| `teams` | Send Microsoft Teams Notification | Webhook URL field |
| `discord` | Send Discord Notification | Webhook URL field |
| `email` | Send Email Alert | `to_addr` (recipient email) field |
| `webhook` | Call Custom Webhook | Webhook URL field |
| `block_ip` | Block Source IP (RST + Firewall) | Enforcement dropdown (both/rst/firewall) + Duration hours input |

---

#### Integrations Tab

**Toolbar:** "{N} channel(s) configured" count + **"Add Integration"** button (not "New Integration").  
**Empty state:** centered icon + "No integrations configured" + "Add a notification channel for playbook actions." + "Add Integration" button.

**Integration table columns:** Status (dot + toggle) | Type (3-letter abbr badge) | Name + type subtext | Endpoint / Host (webhook_url truncated to 48 chars + "…", or smtp_host:port, or "—") | Edit button | Remove button

**Summary row** (below table when integrations exist): "{N} channel(s) configured" text.

**Add/Edit Integration modal** (scrollable — `max-h-[90vh]`, body is `overflow-y-auto`):
- **Grouped type selector** — 4 labeled sections; selecting a type resets `intConfig = {}`:
  1. **Notification** — Slack, MS Teams, Discord, Webhook, PagerDuty, Telegram, Email (SMTP)
  2. **Firewall / Block** — pfSense, FortiGate, PAN-OS, OPNsense
  3. **Switch Isolation** — UniFi, Cisco SNMP, Aruba CX, Generic SNMP
  4. **Cloud Firewall** — AWS SG, Azure NSG, GCP VPC
- Connection Name input (placeholder: "e.g. Production {intType.name}")
- Dynamic fields from `selectedIntType.fields` (type-specific — see integration types table in 2.11)
- **Test result** (between fields and footer): green box if result contains `✅`, red box if contains `❌`
- **Footer** (space-between layout): "Test Connection" button (left, with spinner, calls `testIntegration()`) | "Cancel" + "Save Integration" / "Save Changes" buttons (right)

---

#### Activity Log Tab

**Toolbar:** "{N} execution(s) recorded" count + **Refresh** button (top-right, calls `loadRuns()`)  
**Empty state:** "No executions recorded" + "Playbook runs will appear here."

**Activity table columns:** Timestamp | Playbook (name) | Result (colored dot + text: green `text-primary` = success / red = other) | Details (`run.detail` field)

---

#### Active Blocks Tab

**Header:** "Active Blocks" h3 + "TCP RST injection and firewall rules enforced by NDR sensors" sub-line.  
**Toolbar:** Refresh button (with spinner while `loadingBlocks()`) + **"Block IP"** button (red).  
**Empty state:** "No active blocks" + "Use the Block IP button or configure a playbook with block_ip action."

**Active blocks table columns:** Source IP + optional `:port` | Triggered By (yellow text = manual / primary text = other) | Enforcement (RST badge `bg-red-500/15 text-red-400` when `rst_injected`; firewall_type badge `bg-orange-500/15 text-orange-400` when firewall_type not "none"; "—" if neither) | Expires | Status badge (active=green / revoked=red / other=grey) | Reason (truncated) | Revoke button — **only rendered when `status === 'active'`**

**Block IP modal fields:**
- Source IP* (required, monospace input)
- **Port + Duration row** (2-column grid): Port (optional, 0–65535) | Duration hours (number, 1–720, default 24)
- Enforcement — `<select>` with 3 options:
  1. "RST Injection + Firewall API" (value: `both`)
  2. "RST Injection Only" (value: `rst`)
  3. "Firewall API Only" (value: `firewall`)
- Reason (optional text input)
- Error display (`blockError()`) in red box
- Footer: "Cancel" + **"Block Now"** button (red, shows "Blocking…" spinner while `blockSaving()`)

---

#### Isolated Devices Tab

**Header:** "Isolated Devices" h3 + "ARP spoofing, switch VLAN quarantine, and cloud firewall deny rules" sub-line.  
**Toolbar:** Refresh button (with spinner while `loadingIsolations()`) + **"Isolate Device"** button (amber).  
**Empty state:** "No isolated devices" + "Isolate a device to cut it off from the network immediately."

**Isolations table columns:** Target IP | Method badge (amber `bg-amber-500/15 text-amber-400`, shows `iso.method` field) | Enforcement (calls `isolationMethodLabel(enforcement)` — returns short-name before " — ") | Triggered By (yellow = manual / primary = other) | Isolated At | Status badge (active=amber / restored=green) | Reason (truncated) | Restore button — **only rendered when `status === 'active'`**

**Isolate Device modal fields:**
- Target IP* (required, monospace input)
- Enforcement Method — `<select>` with all 8 types from `isolationEnforcementTypes`
- Gateway IP — **only rendered when enforcement is `arp`** (auto-populated by `getAgentStatus()`). Help text: "The ARP agent will poison both the target and gateway ARP caches to intercept traffic."
- Quarantine VLAN — **only rendered when enforcement is `cisco`, `aruba`, or `snmp`** (number input, 1–4094, default: 999). Help text: "Port will be moved to this VLAN. Configure this VLAN with no uplink or a sinkhole."
- Reason (optional text input)
- Error display (`isolateError()`) in red box
- Footer: "Cancel" + **"Isolate Now"** button (amber, shows "Isolating…" while `isolateSaving()`)

**Isolation progress modal** — `*ngIf="showIsolationProgress()"`:
- Full-screen overlay (`z-50`, black/70 backdrop) with centered card (max-w-sm)
- **Header icon** changes by state: amber WifiOff (pulsing, while not complete) → green CheckCircle (success) → red AlertCircle (failure). Background circle also changes color.
- Header also shows `isolationProgressTitle()` ("Isolating Device" or "Restoring Device") and `isolationProgressTarget()` (IP) in monospace
- **Step list**: each step shows one of: empty circle (pending), amber spinning border circle (running), green circle with checkmark (done), red circle with X (error). Step label text color: white (done), amber (running), red (error), dim (pending). Right side of each row: green "done" / amber "running…" / red "failed" label
- **Success message** (when complete and success): green box — "Device successfully isolated from the network." or "Device network access restored successfully." (based on `isolationProgressTitle` containing "Restor")
- **Error message** (when complete and failed): red box with `isolationProgressError()` text
- **Footer button**: "Please wait…" (disabled, while running) or **"Done"** button (amber, calls `closeIsolationProgress()`)

**ARP isolation steps** (4 steps): "Connecting to sensor agent" / "Starting ARP poisoning" / "Applying iptables firewall rules" / "Confirming device isolation"  
**Non-ARP isolation steps** (4 steps): "Connecting to sensor agent" / "Sending {ENFORCEMENT} quarantine command" / "Waiting for enforcement confirmation" / "Confirming device isolation"  
**ARP restore steps** (4 steps): "Connecting to sensor agent" / "Stopping ARP poisoning" / "Removing iptables firewall rules" / "Network access restored"  
**Non-ARP restore steps** (4 steps): "Connecting to sensor agent" / "Reverting {ENFORCEMENT} quarantine" / "Waiting for enforcement rollback" / "Network access restored"

---

#### New Case Modal — `*ngIf="showNewCase()"`

Eyebrow: "SOAR / NEW CASE". Title: "Create Incident Ticket".

- **Title*** (required text input, placeholder: "e.g. Lateral movement detected from 10.0.0.5")
- **Severity + Priority** (2-column grid): both are `<select>` dropdowns:
  - Severity: CRITICAL / HIGH / MEDIUM / LOW (default: HIGH)
  - Priority: P1 — Critical (<4h SLA) / P2 — High (8h SLA) / P3 — Medium (24h SLA) / P4 — Low (72h SLA) (default: P2)
- **Assign To** (optional text input, pre-filled with `currentUsername`)
- **Source IP / Dest IP** (2-column grid, monospace inputs)
- **Description** (textarea, 3 rows)
- **Tags** (comma-separated text input, e.g. "port-scan, lateral-movement, exfiltration")
- Error message (`newCaseError()`) in red box if validation fails
- Footer: "Cancel" + **"Create Case"** button (shows "Creating..." while `savingNewCase()`)

---

#### Incident Report Modal — `*ngIf="showReportModal()"`

Separate full-screen modal (`z-100`), opened from header "Report" button or automatically after `confirmClose()`.

**Header row:**
- "Incident Report" eyebrow label + case title
- Severity badge | Priority badge | Status badge | Case number badge
- "Download HTML" button (calls `downloadReport('html')`)
- "Print / PDF" button (calls `downloadReport('pdf')`)
- "✕ Close" button

**Body — key fields grid:** Attacker IP (red text) | Victim IP (blue text) | Analyst | Closed At | PCAP Sessions count | Tags

**Description block** — `*ngIf="selectedCase().description"`

**Resolution Notes block**

**Intel badge** — `*ngIf="addToIntel"` — "Attacker IP Added to Threat Intel"

**PCAP Sessions table** — sliced to **first 20 rows** (`liveEvidence().pcap_sessions.slice(0,20)`) — Time | Source ip:port | Destination ip:port | Proto | Bytes | Pkts. Note: the **downloadable HTML report** includes **all** sessions (no slice).

**NDR Events table** — sliced to **first 20 rows** (`liveEvidence().ndr_events.slice(0,20)`) — Time | Type | Source | Destination | Note. Note: the **downloadable HTML report** includes **all** events (no slice).

**Footer:** Case number + report generation date

---

#### Evidence Overlay — `*ngIf="showEvidenceOverlay()"`

Full-screen overlay (`z-200`). Top bar: "Evidence Analysis" label + "✕ Close" button (calls `closeEvidenceOverlay()`). Body: `<iframe [src]="evidenceOverlaySrc()">` — loads the Evidence page with deep-link query params (`?cid=...&src_ip=...&dst_ip=...`) to auto-select the relevant bundle.

### 2.23 API Service Methods (SOAR)

| Method | HTTP | Endpoint | Description |
|--------|------|----------|-------------|
| `getSoarCases()` | GET | `/api/soar/cases` | All cases for tenant, scoped by sensor_ids |
| `createSoarCase(payload)` | POST | `/api/soar/cases` | Creates new case; payload: title, description, severity, priority, assigned_to, src_ip, dst_ip, tags |
| `updateSoarCase(id, payload)` | PUT | `/api/soar/cases/:id` | Updates case metadata (title, description, assigned_to, priority, severity) |
| `updateSoarCaseStatus(id, status)` | PUT | `/api/soar/cases/:id/status` | Updates case status only |
| `getSoarCaseComments(id)` | GET | `/api/soar/cases/:id/comments` | Returns all comments for a case |
| `addSoarCaseComment(id, comment)` | POST | `/api/soar/cases/:id/comments` | Adds comment (used for analyst notes, session notes, PCAP notes, closing notes) |
| `getSoarRuns()` | GET | `/api/soar/runs` | Playbook execution history |
| `getNativePlaybooks()` | GET | `/api/soar/native/playbooks` | All native playbooks |
| `createNativePlaybook(data)` | POST | `/api/soar/native/playbooks` | Creates playbook |
| `updateNativePlaybook(id, data)` | PUT | `/api/soar/native/playbooks/:id` | Updates playbook |
| `deleteNativePlaybook(id)` | DELETE | `/api/soar/native/playbooks/:id` | Deletes playbook |
| `getIntegrations()` | GET | `/api/soar/integrations` | All saved integrations |
| `saveIntegration(data)` | POST | `/api/soar/integrations` | Creates integration |
| `updateIntegration(id, data)` | PUT | `/api/soar/integrations/:id` | Updates integration |
| `testIntegration(data)` | POST | `/api/soar/integrations/test` | Tests integration connection |
| `toggleIntegration(data)` | POST | `/api/soar/integrations/toggle` | Enables/disables integration |
| `deleteIntegration(data)` | POST | `/api/soar/integrations/delete` | Deletes integration |
| `getEventsByCid(cid)` | GET | `/api/events/by-cid?cid=...` | NDR events for a community_id |
| `triggerEvidenceCapture(communityId)` | POST | `/api/evidence/trigger` | Triggers background evidence bundle capture |
| `listActiveBlocks()` | GET | `/api/blocks` | Active IP blocks list |
| `manualBlock(data)` | POST | `/api/blocks/manual` | Creates manual IP block |
| `revokeBlock(id, sensor_id?)` | POST | `/api/blocks/revoke` | Revokes a block |
| `listIsolations()` | GET | `/api/isolations` | Active device isolations |
| `isolateDevice(data)` | POST | `/api/isolate` | Triggers device isolation |
| `unisolateDevice(id)` | POST | `/api/unisolate` | Restores isolated device |
| `addManualIoc(type, value, group?)` | POST | `/api/threat-intel/add` | Adds IP to threat intel watchlist |
| `getAgentStatus()` | GET | `/api/agent-status` | Sensor agent status (used to pre-fill gateway IP) |

### 2.24 Rust Handlers (SOAR)

| Handler | Route | Notes |
|---------|-------|-------|
| `get_soar_cases` | `GET /api/soar/cases` | Reads `soar_cases` ClickHouse table; scoped by `tenant_id` and `sensor_ids` |
| `create_soar_case` | `POST /api/soar/cases` | Inserts into `soar_cases`; auto-generates `case_number` (e.g. `NDR-2024-00042`) and UUID |
| `update_soar_case` | `PUT /api/soar/cases/:id` | Updates metadata fields |
| `update_soar_case_status` | `PUT /api/soar/cases/:id/status` | Updates `status` and `closed_at`; validates tenant ownership |
| `get_soar_case_comments` | `GET /api/soar/cases/:id/comments` | Returns from `soar_case_comments`; scoped by tenant |
| `add_soar_case_comment` | `POST /api/soar/cases/:id/comments` | Inserts comment; `author` from JWT `sub` |
| `get_soar_runs` | `GET /api/soar/runs` | Returns `soar_playbook_runs` for tenant |
| Playbook CRUD | `/api/soar/native/playbooks/*` | Standard CRUD on `soar_native_playbooks` table; tenant-scoped |
| Integration CRUD | `/api/soar/integrations/*` | CRUD on `soar_integrations`; configs stored as JSON; test endpoint makes live HTTP call to integration target |
| `trigger_evidence_capture` | `POST /api/evidence/trigger` | Background task: acquires semaphore, builds ZIP bundle, saves to `/opt/ndr/evidence/{tenant}/{date}/`, persists record |
| `list_active_blocks` | `GET /api/blocks` | Reads `active_blocks` table, filtered by tenant and not-expired |
| `manual_block` | `POST /api/blocks/manual` | Inserts block record; dispatches block command to sensor agent via agent message queue |
| `revoke_active_block` | `POST /api/blocks/revoke` | Marks block as revoked; dispatches revoke command to sensor agent |
| `list_isolations` | `GET /api/isolations` | Active device isolation records for tenant |
| `isolate_device_handler` | `POST /api/isolate` | Dispatches isolation command to sensor agent based on enforcement type; records in `device_isolations` table |
| `unisolate_device_handler` | `POST /api/unisolate` | Dispatches restore command; updates isolation record status |

### 2.25 Auto-Trigger Behaviour (Rust Engine)

SOAR is not only triggered manually. In the alert processing pipeline (`api/mod.rs` lines ~1454, ~1571):

- After scoring an alert, if `risk.score >= soar_threshold` (default 75), `crate::soar::execute_native_playbooks()` is called automatically.
- Active playbooks matching the condition (`cond_field op cond_value`) are evaluated; matching playbooks dispatch their action (Slack webhook, etc.) immediately.
- Evidence bundles are also auto-captured for HIGH and CRITICAL alerts (lines ~846–927) via the evidence semaphore — this is the source of AUTO-captured bundles shown in the Evidence page.

### 2.26 Data Flow

```
ngOnInit
  ├─ loadCases()          → GET /api/soar/cases
  ├─ loadPlaybooks()      → GET /api/soar/native/playbooks
  ├─ loadIntegrations()   → GET /api/soar/integrations
  └─ loadRuns()           → GET /api/soar/runs

openCase(c)
  ├─ getSoarCaseComments(id)          → GET /api/soar/cases/:id/comments
  ├─ arkime.getSessions({ src_ip, dst_ip }) → Arkime session query → liveEvidence.pcap_sessions
  └─ getEventsByCid(cid)              → GET /api/events/by-cid → liveEvidence.ndr_events

openPcapViewer(session)
  └─ arkime.fetchPcapRaw(id, node)    → raw ArrayBuffer → parsePcap() → pcapPackets signal

updateCaseStatus(status)
  ├─ if Resolved/Closed → showCloseForm
  │     └─ confirmClose()
  │           ├─ updateSoarCaseStatus(id, status)
  │           ├─ addSoarCaseComment(id, notes)   [if notes]
  │           └─ addManualIoc('ip', src_ip)       [if addToIntel]
  └─ else → _doUpdateStatus(status) → PUT /api/soar/cases/:id/status

submitIsolation()
  └─ startIsolationProgress() → showIsolationProgress panel
       └─ isolateDevice({ target_ip, enforcement, ... }) → POST /api/isolate
             └─ Rust: dispatches to sensor agent → records in device_isolations

Rust alert pipeline (background, no UI trigger)
  └─ if score >= soar_threshold → execute_native_playbooks()
       └─ matching playbooks → dispatch action (Slack/webhook/etc.)
  └─ if severity >= HIGH     → build_evidence_bundle() (auto-capture)
```
