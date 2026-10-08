# Analyst — AI Module

**Scope:** AI Activity feed, AI-generated threat intelligence reports, and the ARIA service layer.  
**Angular pages:** `pages/analyst/ai-activity/` and `pages/analyst/ai-report/`  
**Shared service:** `services/aria/aria.service.ts` (`AriaService`)

---

## Page 3 — AI Activity

**Route:** `/analyst/ai-activity`  
**Angular component:** `ndr-ui/src/pages/analyst/ai-activity/ai-activity.ts`  
**Template:** `ndr-ui/src/pages/analyst/ai-activity/ai-activity.html`  
**Styles:** `ndr-ui/src/pages/analyst/ai-activity/ai-activity.css`  
**Service:** `ndr-ui/src/services/api/api.ts` (`Api`)

### 3.1 Purpose

Live feed of ARIA's autonomous activity across three categories:

- **Threat Analyses** — ARIA-generated deep-dive assessments for individual evidence bundles (automatically triggered for HIGH, CRITICAL, and MEDIUM bundles at capture time).
- **Threat Predictions** — Forward-looking attack forecasts generated every 6 hours by the AI engine from observed behavioral patterns.
- **Suppression Decisions** — AI-driven false-positive suppression rules that ARIA applies autonomously to reduce alert noise.

The page auto-refreshes every 15 seconds (analyses/suppressions) and every 60 seconds (predictions). A "AI Report" shortcut button in the tab bar navigates to `/analyst/ai-report`.

**Page header:**  
- Bot icon + "AI Agent Activity" h2 + "ARIA threat analyses and suppression decisions" subtitle  
- Top-right: green pulsing dot + "Live · updates every 15s" indicator

### 3.2 Data Loading — Reactive Streams

The component uses two `toSignal` wrappers over RxJS pipelines (no manual `ngOnInit` imperative load):

**Primary stream** (`data` signal) — sources analyses and suppressions:
- `merge(interval(15_000), refresh$)` — fires immediately (`startWith(0)`), then every 15s, and on any `refresh$.next()` call.
- Calls `api.getAiActivity()` on each tick via `switchMap`.
- Maps to `{ analyses, suppressions, error }`. On error: sets `error = 'Failed to load AI activity.'`.
- `initialValue: { analyses: [], suppressions: [], error: '' }`.

**Prediction stream** (`predData` signal) — sources predictions separately:
- `interval(60_000)` with `startWith(0)` — fires immediately, then every 60s.
- Calls `api.getThreatPredictions()`.
- `initialValue: []`.

### 3.3 Signals

| Signal / Property | Type | Description |
|---|---|---|
| `analyses` | `computed(any[])` | ARIA threat analyses from `data().analyses` |
| `suppressions` | `computed(any[])` | Suppression decisions from `data().suppressions` |
| `error` | `computed(string)` | Error message if API call failed |
| `loading` | `computed(boolean)` | Computes `data() === null` — but because `toSignal` is given a non-null `initialValue`, this is always `false`; the loading banner in the template is effectively dead code |
| `predictions` | `computed(any[])` | Threat predictions from `predData()` |
| `expandedAnalyses` | `Set<string>` | Plain Set of analysis IDs currently expanded in the list |
| `expandedPrediction` | `signal<string\|null>` | Attack type currently expanded in predictions |
| `historicalPredictions` | `signal<any[]>` | Historical prediction entries for the expanded attack type |
| `activeTab` | `'analyses'\|'suppressions'\|'predictions'` | Active tab (plain property, not a signal) |

### 3.4 Methods

| Method | Description |
|---|---|
| `toggleAnalysis(id)` | Adds or removes `id` from `expandedAnalyses` set |
| `isExpanded(id)` | Returns true if `id` is in `expandedAnalyses` |
| `togglePrediction(type)` | If `type` is already expanded, collapses it and clears `historicalPredictions`. Otherwise sets `expandedPrediction` to `type` and calls `api.getThreatPredictionsHistory()`, filtering the result to entries matching `attack_type === type`, stored in `historicalPredictions` (up to 5 shown). |
| `isPredExpanded(type)` | Returns true if `expandedPrediction() === type` |
| `deactivateSuppression(id)` | Calls `api.deactivateAiSuppression(id)` (PATCH), then fires `refresh$.next()` to reload |
| `deleteSuppression(id)` | Confirms with `window.confirm`, calls `api.deleteAiSuppression(id)` (DELETE), then fires `refresh$.next()` |
| `openAiReport()` | `router.navigate(['/analyst/ai-report'])` |
| `sevClass(s)` | Returns `'sev-' + (s \|\| 'info').toLowerCase()` — fallback CSS class is `sev-info` when severity is falsy |
| `alertLevelClass(level)` | Returns `'alert-' + (level \|\| 'info').toLowerCase()` for prediction alert level CSS |
| `probBar(p)` | Returns `Math.round((p \|\| 0) * 100)` — probability as integer percent; `|| 0` guards against falsy input |
| `probColor(p)` | Returns hex color: ≥75% → `#ff2a5f` (red), ≥50% → `#ff9900` (orange), ≥25% → `#ffea00` (yellow), else → `#69f6b8` (green) |
| `trendIcon(trend)` | Returns Lucide icon: `'rising'` → TrendingUp, `'falling'` → TrendingDown, else → Minus |
| `trendClass(trend)` | Returns `'trend-up'`, `'trend-down'`, or `'trend-stable'` |
| `suppressTypeLabel(t)` | Maps `by_dst` → "By Destination IP", `by_src` → "By Source IP", `by_sid` → "By Signature ID"; returns raw `t` value for unknown types |
| `formatTime(ts)` | Parses ISO or space-separated timestamp string; returns `d.toLocaleString()`. Appends `Z` suffix if no `T` present (treats as UTC). Returns `''` (empty string) when `ts` is falsy. |

### 3.5 HTML Template Behaviour

**Tab bar — 4 buttons:**
- **Threat Analyses** — FileText icon + badge showing `analyses().length`
- **Threat Predictions** — Activity icon + badge showing `predictions().length`
- **Suppression Decisions** — ShieldOff icon + badge showing `suppressions().length`
- **AI Report** (styled differently: `.ai-report-btn`) — Bot icon, no badge; calls `openAiReport()`, not a tab switch

**Loading state:** "Loading AI activity..." (shown while `loading()`)  
**Error banner:** rendered above tabs when `error()` is non-empty

---

#### Threat Analyses Tab

**Empty state:** "No AI threat analyses yet. Analyses are generated automatically when HIGH, CRITICAL, or MEDIUM evidence bundles are captured."

**Analysis card** (per entry in `analyses()`):

Collapsible — clicking the header calls `toggleAnalysis(a.id)`:

**Collapsed header row:**
- Severity badge (`sevClass(a.severity)`)
- Flow: `src_asset.hostname || src_ip` → `dst_asset.hostname || dst_ip`. If hostname is available for either endpoint, the raw IP is shown below in a smaller `.flow-raw` span. **Source endpoint** shows: `✓` (if `src_asset.trusted`) or `!` (if `src_asset.threat_flagged && !src_asset.trusted`). **Destination endpoint** shows: `✓` (if `dst_asset.trusted`) only — no threat-flagged badge on dst.
- CID: truncated to 24 chars + `…` (full value in `title` attribute)
- Right side: `formatTime(a.created_at)` + chevron (up/down)

**Expanded body (when `isExpanded(a.id)`):**
- "ARIA Analysis" label
- `<pre>` block with `a.analysis` text (preserves whitespace/line breaks)
- Footer: "Bundle: {a.bundle_id}"

---

#### Threat Predictions Tab

**Empty state:** "No threat predictions yet. Predictions are generated automatically every 6 hours using DeepSeek-R1."

**Prediction card** (per entry in `predictions()`):

Clicking any card calls `togglePrediction(p.attack_type)`. Cards are in a grid layout.

**Card header:**
- AlertTriangle icon + `p.attack_type` name (bold)
- Alert level badge: `alertLevelClass(p.alert_level)` — e.g. `alert-high`, `alert-critical`; text: `(p.alert_level || 'info').toUpperCase()`
- Right: `formatTime(p.predicted_at)` + expand/collapse chevron

**Probability bar row:**
- "Probability" label
- Track bar with fill: `width = probBar(p.probability) + '%'`, fill color from `probColor(p.probability)`
- Percentage label in matching color
- Trend chip: `trendClass(p.trend)` + `trendIcon(p.trend)` icon + trend text (`rising`/`falling`/`stable`)

**Expanded detail (when `isPredExpanded(p.attack_type)`):**
- **ARIA Briefing** section (if `p.aria_briefing`): paragraph of AI-generated briefing text
- **Recommendations** section (if `p.recommendations?.length`): bulleted list, each with ShieldIcon
- **Meta row:** "Confidence: {n}%" — rendered as `(p.confidence * 100 || 0).toFixed(0)%` (uses `p.confidence`, a separate field from the probability bar's `p.probability`) + "Model: {p.ai_model}" (conditional)
- **Historical Trend** section (shown only when `historicalPredictions().length > 0`): up to 5 past predictions for this attack type, each showing: time marker dot (`.active` when `hist.id === p.id`) + predicted_at timestamp + Probability + delta (`+X.X%` or `-X.X%` delta, colored `.trend-up`/`.trend-down`)

---

#### Suppression Decisions Tab

**Empty state:** "No suppression decisions yet. ARIA automatically suppresses high-confidence false positives."

**Suppression table columns:** Signature | Suppress Type | Target IP | Flow | Confidence | Status | Reason | Time | Actions

**Per-row:**
- **Signature** cell: `a.signature_name` (bold, with `title`) + "SID {a.signature_id}" below (smaller)
- **Suppress Type:** `suppressTypeLabel(s.suppress_type)` — one of three labels
- **Target IP:** `s.suppress_ip` or `—` (monospace)
- **Flow:** `s.src_ip → s.dst_ip` (monospace, small)
- **Confidence:** inline bar (`width = s.ai_confidence + '%'`) + numeric `%`
- **Status:** badge — `.active` class (green) if `s.active`, `.inactive` (grey) otherwise
- **Reason:** `s.ai_reason` text; full value in `title` attribute (truncated visually)
- **Time:** `formatTime(s.created_at)`
- **Actions:**
  - "Deactivate" button — `*ngIf="s.active"` only; calls `deactivateSuppression(s.id)`; tooltip: "Deactivate — keeps history but stops suppressing"
  - "Delete" button — always shown; calls `deleteSuppression(s.id)` with confirm dialog; tooltip: "Delete permanently"

### 3.6 API Methods

| Method | HTTP | Endpoint | Description |
|---|---|---|---|
| `getAiActivity()` | GET | `/api/ai-activity` | Returns `{ analyses[], suppressions[] }` for tenant |
| `getThreatPredictions()` | GET | `/api/threat/predictions` | Current threat predictions |
| `getThreatPredictionsHistory()` | GET | `/api/threat/predictions/history` | All historical predictions (used for expanded trend timeline) |
| `deactivateAiSuppression(id)` | PATCH | `/api/ai-suppressions/:id/deactivate` | Marks suppression inactive; keeps record |
| `deleteAiSuppression(id)` | DELETE | `/api/ai-suppressions/:id` | Permanently removes suppression rule |

---

## Page 4 — AI Report

**Route:** `/analyst/ai-report`  
**Angular component:** `ndr-ui/src/pages/analyst/ai-report/ai-report.ts`  
**Template:** `ndr-ui/src/pages/analyst/ai-report/ai-report.html`  
**Styles:** `ndr-ui/src/pages/analyst/ai-report/ai-report.css`  
**Services:** `Api`, `AriaService`, `Router`

### 4.1 Purpose

Generates a structured, print-ready intelligence report combining live NDR telemetry with ARIA-authored narratives and MITRE ATT&CK mapping. The analyst selects a time period (24h / 7d / 30d), clicks "Generate Report", and the page:

1. Fetches 7 data sources in parallel via `forkJoin`.
2. Filters data to the selected period.
3. Renders a document with up to 8 ordered sections (cover + TOC + 6 content sections + appendix).
4. Fires 3 parallel ARIA chat calls to generate: Executive Summary, Threat Landscape narrative, and 6 prioritised Recommendations.
5. Fires 1 ARIA chat call to generate MITRE ATT&CK tactic/technique mappings for up to 15 analyses.
6. Allows "Customize" mode: drag-and-drop section reorder and per-section include/exclude toggle.
7. Supports `window.print()` for PDF export — print CSS hides the top bar, includes a `CONFIDENTIAL` watermark, and formats the page as A4.

**Report ID format:** `NDR-{YYYYMMDD}-{HHMM}-{random 4-digit}` — e.g. `NDR-20260813-1430-4721`

### 4.2 Signals — Report State

| Signal | Type | Description |
|---|---|---|
| `reportPeriod` | `signal<'24h'\|'7d'\|'30d'>` | Selected time window; default `'24h'` |
| `reportId` | `signal<string>` | Auto-generated report identifier |
| `reportDate` | `signal<string>` | Formatted generation timestamp (en-GB locale: "13 Aug 2026, 14:30 BST") |
| `generating` | `signal<boolean>` | True while `forkJoin` is in flight |
| `generated` | `signal<boolean>` | True after first successful generation |
| `globalError` | `signal<string>` | Top-level error message if `forkJoin` errors |
| `stats` | `signal<any>` | Raw stats from `getStats()` |
| `severity` | `signal<any>` | Alert severity counts from `getSeverity()` |
| `analyses` | `signal<any[]>` | AI analyses filtered to selected period |
| `suppressions` | `signal<any[]>` | Suppression rules filtered to selected period |
| `predictions` | `signal<any[]>` | Threat predictions filtered to selected period |
| `topIps` | `signal<any>` | Top source/destination IPs from `getTopIps()` |
| `protocols` | `signal<any[]>` | Protocol distribution from `getProtocols()` |
| `health` | `signal<any>` | System health snapshot from `getDashboardStats()` |
| `execSummary` | `signal<string>` | ARIA-authored executive summary paragraph |
| `threatNarrative` | `signal<string>` | ARIA-authored threat landscape narrative (2 paragraphs) |
| `recommendations` | `signal<string>` | ARIA-authored 6-item recommendation list |
| `execLoading` | `signal<boolean>` | True while executive summary ARIA call is in flight |
| `threatLoading` | `signal<boolean>` | True while threat narrative ARIA call is in flight |
| `recoLoading` | `signal<boolean>` | True while recommendations ARIA call is in flight |
| `mitreMap` | `signal<Record<string,MitreEntry>>` | Map of `analysis_id → { analysis_id, tactics[], techniques[] }` |
| `mitreLoading` | `signal<boolean>` | True while MITRE mapping ARIA call is in flight |
| `customMode` | `signal<boolean>` | True when the Report Builder panel is open |
| `sectionOrder` | `signal<string[]>` | Current section render order (IDs) |
| `enabledSections` | `signal<Set<string>>` | IDs of sections included in the report |
| `dragSrcIdx` | `signal<number\|null>` | Source index during drag-and-drop |
| `dragOverIdx` | `signal<number\|null>` | Target index during drag-and-drop hover |

### 4.3 Computed Signals — KPIs

All KPIs return `null` when the denominator is zero (rendered as "N/A" in the report).

| Computed | Formula | Purpose |
|---|---|---|
| `totalAlerts` | `critical + high + medium + low` | Total alert count for the period |
| `riskLevel` | Critical > 0 → CRITICAL; High > 5 → HIGH; Medium > 10 → MEDIUM; else LOW | Overall risk classification |
| `riskClass` | `'risk-' + riskLevel().toLowerCase()` | CSS class for risk badge |
| `kpiAiCoverage` | `min(100, analyses.length / hits_total × 100)` | % of correlation hits receiving AI deep-dive |
| `kpiFpRate` | `activeSups / hits_total × 100` | False-positive suppression rate |
| `kpiAvgConfidence` | `mean(s.ai_confidence)` across all suppressions | Mean AI confidence across suppression decisions |
| `kpiActiveSuppressionRate` | `active.length / total.length × 100` | Fraction of suppression rules still enforced |
| `kpiCriticalRate` | `critical / totalAlerts × 100` | Critical alert concentration |
| `kpiAgentZRatio` | `'{z%} / {s%}'` string | Event volume split between Agent-Z and Agent-S |
| `periodLabel` | Map: `24h→'Last 24 Hours'`, `7d→'Last 7 Days'`, `30d→'Last 30 Days'` | Display label for the selected period |
| `enabledCount` | `enabledSections().size` | Count of sections included |
| `sectionNumbers` | Iterates `sectionOrder()`; assigns sequential `01`–`0N` to enabled sections; `A` to appendix; `--` to disabled | Dynamic section numbering |
| `activeTocSections` | Filters `sectionOrder()` to enabled sections; maps to `TocSection` objects with current `num` | Drives both screen TOC and print TOC |

### 4.4 Section Registry

8 sections defined in `sectionDefs` (ordered array — this defines the default order and metadata):

| ID | Default Num | Title | Required |
|---|---|---|---|
| `section-exec` | 01 | Executive Summary | Yes (cannot be excluded) |
| `section-kpis` | 02 | Key Performance Indicators | No |
| `section-threat` | 03 | Threat Landscape Overview | No |
| `section-analyses` | 04 | AI Threat Analyses & MITRE | No |
| `section-predictions` | 05 | Predictive Threat Intelligence | No |
| `section-suppressions` | 06 | Autonomous Suppression | No |
| `section-recommendations` | 07 | Recommendations & Remediation | No |
| `section-appendix` | A | Appendix — System Health | No |

The appendix always gets number `A` regardless of position; all other enabled sections are numbered sequentially from `01`. `toggleSection()` is a no-op for `required: true` sections.

### 4.5 Report Generation Flow

**`setPeriod(p)`** — sets `reportPeriod`. If `generated()`, auto-calls `generateReport()` to refresh.

**`generateReport()`**:
1. Sets `generating = true`, resets `generated`, clears all narrative signals and `mitreMap`.
2. Calls `forkJoin` over 7 API endpoints (all wrapped in `catchError(() => of(null/default))`):
   - `getStats()` → `stats`
   - `getSeverity()` → `severity`
   - `getAiActivity()` → analyses + suppressions
   - `getThreatPredictions()` → predictions
   - `getTopIps()` → `topIps`
   - `getProtocols()` → `protocols`
   - `getDashboardStats()` → `health`
3. On success: generates `reportId` and `reportDate`, stores raw data. **Period filter applies only to `analyses`, `suppressions`, and `predictions`** — `stats`, `severity`, `topIps`, `protocols`, and `health` are stored as-is (not filtered by period, since these are aggregate snapshots, not time-series records). Sets `generated = true`, then fires `generateNarratives()` and `generateMitreMapping()` in parallel (not awaited).
4. On error: sets `globalError`.
5. `finalize()` always clears `generating`.

**`filterByPeriod(items)`** — filters items to those with `created_at` or `predicted_at` within the `cutoffDate()` window. Items with no timestamp are kept (pass-through). Invalid timestamps also pass through.

### 4.6 ARIA Narrative Generation

`generateNarratives(data)` fires 3 independent ARIA chat calls. Each is a non-blocking `subscribe()` called one after the other synchronously, so all 3 HTTP requests are in-flight concurrently — they do not wait on each other:

**Executive Summary** (`execLoading`)  
Prompt: instructs ARIA to write 3–4 formal sentences for a CISO briefing. Passes: period label, total events/hits, Agent-Z/S event counts, severity breakdown, analysis count, prediction count, active suppressions, overall risk level. Format requirement: no bullet points, no first-person "I" or "ARIA". Response stored in `execSummary`. Fallback: "Executive summary unavailable — AI provider not configured."

**Threat Landscape Narrative** (`threatLoading`)  
Prompt: instructs ARIA to write 2 formal paragraphs (max 120 words). Context includes top 4 analyses (first 150 chars each) and top 3 predictions with probability/trend. Response stored in `threatNarrative`.

**Recommendations** (`recoLoading`)  
Prompt: instructs ARIA to generate exactly 6 prioritized recommendations, each formatted as `"N. [Immediate Action] — [Technical rationale]"`. Context includes risk level, top 3 critical/high analyses (first 100 chars each), and high-probability predictions (> 50%). Response stored in `recommendations` and rendered in a `<pre>` block to preserve numbering and line breaks.

All three calls use `aria.chat(prompt, [])` — empty history (stateless calls). All degrade gracefully on error (`catchError(() => of({ reply: '' }))`).

### 4.7 MITRE ATT&CK Mapping

**`generateMitreMapping(analyses)`** — fires a single ARIA chat call with up to 15 analyses. If `analyses.length === 0`, returns immediately without calling ARIA and without setting `mitreLoading` to true.

Prompt format: instructs ARIA to return raw JSON only (no markdown, no surrounding text) — a JSON array of `{ analysis_id, tactics[], techniques[{ id, name }] }`. Rules: real MITRE ATT&CK v14 tactic names and technique IDs only; empty arrays if no clear mapping; no invented technique IDs.

Response parsing:
1. Extracts JSON array via regex `\[[\s\S]*\]` from the response (handles cases where ARIA wraps JSON in prose).
2. Parses the array; builds `Record<string, MitreEntry>` keyed by `analysis_id`.
3. Stores in `mitreMap`. On any parse error: silently degrades to `{}` — the template shows "MITRE mapping pending or unavailable for this analysis."

**`getMitreForAnalysis(id)`** — returns `mitreMap()[id] ?? null`.

### 4.8 Report Builder (Customize Mode)

Opened by the "Customize" button (only shown when `generated() && !generating()`).

**`ar-customizer` panel** (screen-only, `.no-print`):
- Header: "Report Builder" + description "Drag to reorder · click Included / Excluded to toggle sections"
- "Reset to default" button — calls `resetToDefault()` which restores `sectionOrder` and `enabledSections` to their initial defaults
- Builder list: one tile per section in `sectionOrder()` order

**Each tile** is a native HTML5 drag-and-drop target:
- `draggable="true"`, events: `dragstart` → `onDragStart(i, e)`, `dragover` → `onDragOver(i, e)`, `drop` → `onDrop(i, e)`, `dragend` → `onDragEnd()`
- Shows: GripVertical icon + section number (`sectionNumbers()[id]`) + section title
- CSS classes: `.tile-disabled` when excluded, `.tile-dragging` when being dragged, `.tile-dragover` when a dragged item is hovering over it
- Toggle button: "Included" (green) / "Excluded" (grey) — calls `toggleSection(id)`; disabled for `required: true` sections (shows "Required" label instead)

**Drag-and-drop logic (`onDrop(targetIdx)`):**
Splices `srcIdx` out of `sectionOrder` array, inserts at `targetIdx`, updates `sectionOrder` signal. The report sections render in CSS `order` matching `sectionCssOrder(id) = indexOf(id) + 10`, so they reflow instantly without page reload.

**Footer:** "{N} of {total} sections included in report" + "Changes apply instantly" hint.

### 4.9 Report Document Structure

The report document (`div.ar-report-doc`, `*ngIf="generated()"`) renders a cover page, TOC, and content sections. On print: skeleton and top bar are hidden (`.no-print`), sections render as paginated A4.

**Cover page** (`#cover-page`, `.page-break-after`):
- Classification line: "CONFIDENTIAL — RESTRICTED DISTRIBUTION"
- Logo: shield icon in a ring
- Title block: eyebrow "ARIA Intelligence Engine · NDR Platform" + h1 "Threat Intelligence" / "Security Report" (two lines via `<br>`) + subtitle "AI-Generated Network Detection & Response Assessment"
- 9-field metadata grid: Report ID (monospace) | Generated | Report Period | Overall Risk (colored) | Total Alerts | AI Analyses count | Predictions count | Suppressions count | MITRE ATT&CK (static "v14.1 Framework")
- Footer line: "Report ID: {id} · Generated by ARIA — Autonomous Response & Intelligence Agent"

**Table of Contents (screen)** (`#toc`, `.no-print`): clickable list of `activeTocSections()` — each item shows section number + title; clicking calls `scrollToSection(s.id)`.

**Table of Contents (print)** (`.ar-toc-print.print-only`): same data, rendered as a simple ordered list without click handlers.

**Section 01 — Executive Summary** (`section-exec`, required):
- ARIA narrative block: "ARIA Executive Analysis" label + `execSummary()` paragraph. Loading state: "ARIA is composing executive summary…". Empty fallback: "configure an AI provider in Settings."
- Severity snapshot (6 cards): Critical | High | Medium | Low | Total Events (`stats.events_total`) | Corr. Hits (`stats.hits_total`)

**Section 02 — Key Performance Indicators** (`section-kpis`):
- KPI strip of 6 cards; each shows: label + `ⓘ` info tooltip + value (or "N/A") + formula label + raw data line
- KPIs (in order): AI Detection Coverage | FP Suppression Rate | Avg AI Confidence | Active Suppression Rate | Critical Alert Rate | Agent-Z / Agent-S Split
- Critical Alert Rate card gets `.kpi-danger` class when value > 10%
- Note below strip: explains that MTTD/MTTR require lifecycle timestamps not yet available

**Section 03 — Threat Landscape Overview** (`section-threat`):
- ARIA threat assessment narrative block + loading state
- **Top Source IPs** subsection (`*ngIf="topIps()?.top_src_ips?.length"`): table — Rank | Source IP | Event Count | Relative Volume (horizontal bar, width proportional to top IP count). Top 5 shown.
- **Top Destination IPs** subsection: same layout for `top_dst_ips`. Top 5 shown.
- **Traffic Protocol Distribution** subsection (`*ngIf="protocols().length"`): grid of chips — proto name (uppercase) + event count. Top 10 protocols shown.

**Section 04 — AI Threat Analyses & MITRE ATT&CK** (`section-analyses`):
- MITRE loading indicator: "Mapping analyses to MITRE ATT&CK v14…" (while `mitreLoading()`)
- Empty state: "No AI threat analyses recorded in the selected period. Analyses are generated automatically for HIGH, CRITICAL and MEDIUM evidence bundles."
- Per-analysis card:
  - Header: severity badge + `src_ip → dst_ip` flow + `formatTime(created_at)`
  - MITRE row (if `getMitreForAnalysis(a.id)` returns data): tactics (chip list) + techniques (each chip shows `id` + `name`, full name in `title`)
  - MITRE unavailable row (if not loading and no mapping): "MITRE mapping pending or unavailable for this analysis"
  - Analysis body: "ARIA Analysis" label + `a.analysis` paragraph + footer "Bundle ID: {id} · Community ID: {cid first 28 chars}"

**Section 05 — Predictive Threat Intelligence** (`section-predictions`):
- Empty state: "No threat predictions recorded in the selected period. Predictions are generated every 6 hours from behavioral pattern analysis."
- Per-prediction card:
  - Header: AlertTriangle icon + `p.attack_type` + `formatTime(p.predicted_at)` + trend icon
  - Probability bar row: label + track + fill (colored by `probColor`) + `%` label + trend chip
  - Detail: `p.aria_briefing` paragraph + `p.recommendations` bulleted list (each with Shield icon) + meta: "Confidence: N%" + model (conditional) + alert_level (conditional)

**Section 06 — Autonomous Suppression Decisions** (`section-suppressions`):
- Empty state if none in period
- Full suppression table (same data as AI Activity page): Signature/SID | Suppress Type | Target IP | Flow | AI Confidence (bar + %) | Status badge | AI Reason | Timestamp

**Section 07 — Recommendations & Remediation** (`section-recommendations`):
- Loading state: "ARIA is generating recommendations from observed threat data…"
- Narrative block: "ARIA Prioritised Recommendations" label + `<pre>` with `recommendations()` text
- Empty state (`*ngIf="!recoLoading() && !recommendations()"`): "Recommendations unavailable — AI provider may not be configured or returned no response."

**Appendix A — System Health** (`section-appendix`):
- Health grid (`*ngIf="health()"`): up to 16 scalar fields from `health()` (excludes object/null values); each shows key + value
- Empty state (`*ngIf="!health()"`): "System health data unavailable."
- Document footer (within appendix): left side — "NDR — ARIA Threat Intelligence Report" + Report ID + Generated date + Period; right side — "CONFIDENTIAL — For authorized personnel only / ARIA v14 · MITRE ATT&CK v14.1"

**Print watermark** (`div.ar-watermark`): "CONFIDENTIAL" — hidden on screen, fixed on every printed page.

### 4.10 Helper Methods

| Method | Description |
|---|---|
| `generateReport()` | Main generation — see 4.5 |
| `setPeriod(p)` | Sets period; auto-regenerates if already generated |
| `downloadPdf()` | `window.print()` — opens browser print dialog; CSS handles A4 formatting |
| `goBack()` | `router.navigate(['/analyst/dashboard'])` |
| `scrollToSection(id)` | `document.getElementById(id).scrollIntoView({ behavior: 'smooth', block: 'start' })` |
| `probBar(p)` | `Math.round((p \|\| 0) * 100)` |
| `probColor(p)` | Same 4-tier color as AI Activity page |
| `sevClass(s)` | `'sev-' + (s \|\| 'unknown').toLowerCase()` — fallback is `sev-unknown` (differs from AI Activity which uses `'info'`) |
| `trendIcon(t)` | TrendingUp / TrendingDown / Minus |
| `trendClass(t)` | `'trend-up'` / `'trend-down'` / `'trend-stable'` |
| `suppressTypeLabel(t)` | Same 3-key map as AI Activity page; falls back to raw `t` for unknown types |
| `formatTime(ts)` | Same ISO/space-separated parsing as AI Activity. **Differs in falsy return**: returns `'—'` (em dash) when `ts` is falsy (AI Activity returns `''`) |
| `getMitreForAnalysis(id)` | Returns `mitreMap()[id] ?? null` |
| `getHealthKeys()` | Returns up to 16 scalar keys from `health()` (filters out object values and nulls) |
| `getSectionDef(id)` | Returns the `sectionDefs` entry for a given section ID |
| `isSectionEnabled(id)` | Returns `enabledSections().has(id)` |
| `sectionCssOrder(id)` | Returns `indexOf(id) + 10` for CSS `order` property |
| `toggleSection(id)` | Adds/removes `id` from `enabledSections`; no-op for `required: true` sections |
| `onDragStart/Over/Drop/End` | HTML5 native drag-and-drop for section reorder |
| `resetToDefault()` | Restores `sectionOrder` and `enabledSections` to their initial defaults |
| `buildReportId(now)` | Formats `NDR-{YYYYMMDD}-{HHMM}-{rand 4-digit}` from a Date object |
| `cutoffDate()` | Returns cutoff Date based on period: 24h → 24h ago, 7d → 168h ago, 30d → 720h ago |
| `filterByPeriod(items)` | Filters array by `created_at` or `predicted_at` vs cutoff; items with no timestamp pass through |

### 4.11 HTML Template Behaviour

**Error banner** (`.ar-error-banner.no-print`, `*ngIf="globalError()"`): Alert icon + `globalError()` text — shown at any page state, not mutually exclusive with the sections below.

**Top bar** (`.ar-topbar`, `.no-print`):
- Back button → `goBack()`
- Center: Bot icon + "ARIA Threat Intelligence Report"
- Right actions (in order):
  1. Period selector (24h / 7d / 30d) — `*ngIf="!generating()"`; buttons call `setPeriod()` — which auto-regenerates if report is already generated; active period gets `.active` class
  2. "Customize" / "Close Builder" button — `*ngIf="generated() && !generating()"`; toggles `customMode()`; active state gets `.active` class
  3. "Generate Report" / "Generating…" / "Regenerate" button — calls `generateReport()`; disabled while `generating()`; shows spinning `LoaderCircle` icon while generating
  4. "Download PDF" button — calls `downloadPdf()`; disabled when `!generated()`

**Page states (mutually exclusive sections):**
- **Idle/landing** (`*ngIf="!generating() && !generated()"`): centered card with Bot icon, title, description paragraph, large period selector (buttons call `reportPeriod.set()` directly — **not** `setPeriod()`, so no auto-regenerate; auto-regenerate only applies after a report has been generated), feature chips (ToC / KPI / MITRE / AI Analyses / Predictions / Recommendations), "Generate Report Now" button
- **Skeleton loading** (`*ngIf="generating()"`): animated placeholder blocks (title + sub + 8 section skeletons with 3 line bars each)
- **Report Builder panel** (`*ngIf="customMode() && generated()"`): section reorder/toggle UI (see 4.8)
- **Report document** (`*ngIf="generated()"`): full structured report (see 4.9)

### 4.12 API Methods Used by AI Report

| Method | HTTP | Endpoint | Description |
|---|---|---|---|
| `getStats()` | GET | `/api/stats` | Total events, hits, agent event counts |
| `getSeverity()` | GET | `/api/severity` | Alert severity distribution (critical/high/medium/low counts) |
| `getAiActivity()` | GET | `/api/ai-activity` | All analyses and suppressions |
| `getThreatPredictions()` | GET | `/api/threat/predictions` | All threat predictions |
| `getTopIps()` | GET | `/api/top-ips` | Top source and destination IPs by event volume |
| `getProtocols()` | GET | `/api/protocols` | Protocol distribution (name + count) |
| `getDashboardStats()` | GET | `/api/health` | System health/status snapshot |

Plus ARIA calls (via `AriaService`):
- `aria.chat(prompt, [])` — `POST /api/aria/chat` — 4 calls per report generation (exec summary, threat narrative, recommendations, MITRE mapping)

---

## ARIA Bot Widget

**Component:** `ndr-ui/src/components/aria-bot/aria-bot.ts`  
**Selector:** `<app-aria-bot>`  
**Mounted:** `app.html` inside `*ngIf="showShell"` — global overlay, present on all shell pages

### Visibility

- Rendered whenever the app shell is shown (user is logged in).
- **Hidden on `/admin` routes** — `isVisible = !url.includes('/admin')`; toggled by subscribing to `Router.events`.

### Status Polling

The bot polls `GET /api/aria/status` **immediately on init** and then **every 30 seconds** via `interval(30000)` + `switchMap`. It does NOT use `AriaService` — it calls the endpoint directly via `HttpClient`.

`handleStatus(s)` processes each response:

| Condition | Behaviour |
|---|---|
| New `latest_community_id` (not previously seen) **AND** `latest_severity === 'CRITICAL'` | Sets emotion `alert`, increments `unreadCount`, shows alert banner, shows speech bubble `"{severity} alert! {src_ip} is doing something suspicious!"`, adds bot message with 4 action buttons (Investigate / Evidence bundle / Attack timeline / Block IP) |
| New `prediction_id` (not previously seen) **AND** `prediction_alert === true` | Sets emotion `alert`, increments `unreadCount`, shows alert banner, shows speech bubble with prediction summary, adds bot message with 3 action buttons (Show details / View pattern match / Escalate now) |

Deduplication uses `lastSeenCid` and `lastSeenPredId` — compares against previous poll.

**`statusColor` computed:**
- `criticalCount > 0` → `#ef4444` (red)
- `highCount > 0` → `#f59e0b` (amber)
- else → `#22c55e` (green)

### Chat

**`sendMessage(text?)`** — adds user message to `messages[]`, pushes to `history[]`, sets emotion `think`, then:
- `POST /api/aria/chat` with `{ message, history }` — direct `HttpClient` call (not via `AriaService`)
- On success: adds bot reply to `messages[]`, pushes assistant message to `history[]`
- **Client-side history trim**: after each response, if `history.length > 20` → `history = history.slice(-20)` (server also independently trims to last 6 messages for prompt construction)
- On error: adds fallback message "I'm having trouble connecting. Check if the NDR engine is running." with emotion `sad`

**Quick replies** (6 preset messages) — shown only when `messages.length <= 1` (welcome message only; hidden once any conversation has started):

| Text | Icon |
|---|---|
| Check alerts | shield-alert |
| System status | activity |
| Lateral movement? | network |
| Any critical alerts? | triangle-alert |
| Show latest evidence | file-text |
| Top talkers | users |

### Animation (DotLottie)

The bot avatar is a Lottie animation at `/assets/lottie/robot.json` rendered on a `<canvas>` via `@lottiefiles/dotlottie-web`. Playback is controlled per named segment — frame boundaries enforced by a `frame` event listener that either loops the segment or returns to idle on completion.

**Segments:**

| Key | Frames | Loop |
|---|---|---|
| `idle` | 0 – 29 | Yes |
| `yes` | 31 – 104 | No |
| `no` | 106 – 179 | No |
| `alert` | 181 – 269 | No (plays at 1.3× speed) |
| `thinking` | 271 – 389 | No |
| `jump` | 391 – 478 | No |

**Emotion → segment mapping:**

| ARIA emotion | Segment |
|---|---|
| `idle` | idle |
| `think` | thinking |
| `alert` | alert |
| `cheer` | jump |
| `wave` | yes |
| `sad` | no |

**`moodLabel` computed** (shown as status line below avatar):

| Emotion | Label |
|---|---|
| `idle` | All systems nominal |
| `wave` | Saying hello |
| `alert` | Alert detected! |
| `think` | Analyzing... |
| `cheer` | Threat resolved! |
| `sad` | Worried |

**Talking animation:** when a bot message is added, `isTalking = true` for `max(1200, textLength × 35)` ms.

### Action Handlers

`handleAction(action: ChatAction)` dispatches on `action.action`:

| Action | Behaviour |
|---|---|
| `investigate` | Navigates to `/alerts?cid={community_id}` after 1.2s delay |
| `evidence` | Opens `/api/evidence/{cid}` in a new tab; navigates to `/evidence` if no CID |
| `timeline` | Navigates to `/evidence?cid={community_id}` |
| `block` | Calls `sendMessage("Block IP {dst_ip}")` |
| `navigate` | Calls `router.navigate([action.data])` |
| `chat` | Calls `sendMessage(action.data)` |
| Any other | Falls through to `sendMessage(action.label)` |

### Template Structure

**Alert banner** (`*ngIf="showAlertBanner && latestAlert"`):
- Shows `latestAlert.severity` + `latestAlert.src_ip → latestAlert.dst_ip`
- "Investigate" button → calls `handleAlertCardClick(latestAlert)` (adds a new bot message with "Take me there" and "Get evidence" action options)
- "✕" button → `dismissAlertBanner()` (hides banner, does not navigate)

**Chat panel** (`.aria-panel`, open when `isOpen`):
- Header: draggable (cursor: grab); "AR" initials + "ARIA ✨" title + "NDR Security Assistant" subtitle + "● Online" status; theme toggle pill (sun/moon SVG); close (✕) button
- Messages list: `*ngFor` over `messages[]`; user messages right-aligned (`.user-row`), bot messages left-aligned (`.bot-row`) with inline SVG avatar; bot messages with `msg.content` rendered `white-space: pre-wrap`; embedded `alertCard` renders a clickable card showing severity, src→dst, community_id — clicking calls `handleAlertCardClick(msg.alertCard)`
- Typing indicator: shown when `isTyping`; 3 animated dots in a `.typing` bubble
- Quick replies grid: shown only when `messages.length <= 1`
- Input row: text input `placeholder="Ask ARIA anything..."` disabled when `isTyping`; send button disabled when `!inputText.trim() || isTyping`; `Enter` key also sends
- Footer: "ARIA uses real-time data • All systems nominal"

**Closed-state widget** (`.bot-wrap`, shown when `!isOpen`):
- `.pulsing` class applied when `unreadCount > 0` (pulse animation)
- Unread badge (`*ngIf="unreadCount > 0"`): shows `unreadCount`
- Alert ring (`*ngIf="unreadCount > 0"`): animated ring around avatar
- Canvas: `#lottieCanvas` for DotLottie playback
- Talk overlay (`*ngIf="isTalking"`): animated mouth while ARIA is "speaking"
- Click → `toggleChat()` (blocked if `hasMoved`)

**Speech bubble** (`*ngIf="!isOpen && showSpeech"`): floating text above the avatar; clicking it also calls `toggleChat()`.

### UI Behaviour

- **Drag**: pointer capture on the avatar/panel. `hasMoved` flag (set when pointer moves > 3px) prevents the next click from toggling open/close.
- **Position**: fixed bottom-right (default 24px from each edge); drag updates `currentRight`/`currentBottom` CSS values.
- **Theme**: `light` / `dark` toggle; persisted in `localStorage['aria_bot_theme']`.
- **Proactive speech bubbles**: every 18 seconds while chat is closed, cycles through 6 preset messages; each bubble auto-dismisses after 7 seconds.
- **Boot greeting**: on Lottie load, plays `wave` animation, shows speech bubble "Hi! I'm ARIA. I'm watching your network right now!", and adds the welcome message to chat (so `messages[]` is never empty on first open).
- **Unread count badge**: increments on each new alert/prediction bot message; cleared to 0 when chat is opened.
- **User initials**: read from `localStorage['username']`, first 2 chars uppercased.

---

## ARIA Service

**Angular service:** `ndr-ui/src/services/aria/aria.service.ts`  
**Provider:** root-level singleton

| Method | HTTP | Endpoint | Parameters | Returns |
|---|---|---|---|---|
| `chat(message, history)` | POST | `/api/aria/chat` | `{ message: string, history: any[] }` | `Observable<{ reply: string, emotion: string }>` |
| `getStatus()` | GET | `/api/aria/status` | — | `Observable<any>` |
| `pollStatus(intervalMs?)` | — | — | Defaults to 30 000 ms | `Observable<any>` — wraps `getStatus()` in `interval` + `switchMap`, cancelled by `destroy$` |
| `destroy()` | — | — | — | Completes `destroy$` to cancel `pollStatus` subscriptions |

**Current usage across the platform:**
- **AI Report page** — the only consumer of `AriaService`; uses `aria.chat(prompt, [])` with empty history for all 4 narrative/MITRE calls (stateless)
- **Evidence page** — `runInvestigation()` calls `POST /api/aria/investigate` directly via `EvidenceService`, not via `AriaService`
- **ARIA Bot widget** — calls `/api/aria/chat` and `/api/aria/status` directly via `HttpClient`; does NOT inject or use `AriaService`
- **`pollStatus()`, `getStatus()`, `destroy()`** — defined in the service but not currently called by any component; reserved for future consumers
- The `AriaMessage` interface defines the expected chat message shape: `{ role, content, timestamp, emotion?, alertCard?, actions? }`

---

## AI Provider System (Rust Backend)

**Source files:** `rust/ndr-engine/src/ai/mod.rs`, `rust/ndr-engine/src/ai/provider.rs`

### Multi-Provider Architecture

Providers are stored in the `ndr.ai_providers` ClickHouse table. Each row defines one provider:

| Field | Description |
|---|---|
| `name` | Display name |
| `provider_type` | `"openai"` (or compatible) / `"anthropic"` |
| `api_key` | API key — **no env var fallback; must be set in DB** |
| `model` | Model override; empty → provider default |
| `base_url` | Base URL; empty → provider default (`https://api.openai.com` or `https://api.anthropic.com`) |
| `endpoint_path` | Path after base URL; empty → provider default (`/v1/chat/completions` or `/v1/messages`) |
| `msg_format` | (Legacy field — not used in provider.rs routing) |
| `priority` | `u8` — providers tried in ascending priority order |

**Use-case tags** separate providers by purpose:
- `"chat"` — used by `aria_chat` handler (ARIA conversational assistant) and all report narrative/MITRE calls
- `"threat"` — used by correlator, chain_matcher, threat predictor, and `aria_investigate` (AI auto-investigation)

### Provider Cache

Providers are cached **per use-case tag** in a process-level `HashMap` (behind `Mutex`). Cache TTL: **5 minutes**. On a cache miss, one ClickHouse query fires and the result is stored. Concurrent requests wait on the `Mutex` and immediately read the freshly cached result — no thundering herd.

### Provider Dispatch — Two Entry Points

**`generate_chat(storage, system, history, user_msg)`** — entry point for all ARIA conversational calls (`aria_chat` handler and all `aria.chat()` report narrative calls):
1. Loads `"chat"` providers from cache (refreshes from `ndr.ai_providers` if stale).
2. Tries providers in priority order — skips any with empty `api_key`.
3. If `provider_type == "anthropic"` → calls `call_claude_chat()` (Anthropic Messages API format).
4. Otherwise → calls `call_openai_chat()` (OpenAI-compatible chat completions format).
5. If a provider returns a non-empty response, returns immediately.
6. If all providers fail or return empty → **`env_fallback_chat()`**: returns `("AI not configured — add a provider in Settings > AI Configuration.", "sad")` — a user-visible error message with the `"sad"` emotion.

**`generate(storage, use_case, system, prompt)`** — entry point for autonomous/batch AI calls (correlator, chain_matcher, predictor, `aria_investigate`):
1. Loads providers for the use-case tag (`"threat"`) from cache.
2. Tries providers in priority order via `call_provider_simple()` — returns plain text (no conversation history, no emotion).
3. If all providers fail or return empty → **`env_fallback_simple()`**: returns an **empty string** and logs a warning. The calling module receives silence — no user-visible message.

**There is NO environment variable fallback in either path** — providers must be configured in the `ndr.ai_providers` table via Settings > AI Configuration.

### HTTP Call Parameters

| Format | max_tokens | temperature | timeout |
|---|---|---|---|
| OpenAI-compat chat (provider.rs) | 1024 | 0.7 | 60s |
| Anthropic chat (provider.rs) | 1024 | — | 60s |
| OpenAI-compat simple/threat | 1024 | 0.1 | 60s |
| Anthropic simple/threat | 1024 | — | 60s |
| Test connection (any provider) | 64 | 0.1 | 30s |

Default model fallbacks: OpenAI-compatible → `gpt-4o-mini`; Anthropic → `claude-sonnet-4-6`.

### Emotion System

ARIA includes a self-reported emotion in every response using bracketed tags at the **end** of the response text. The `extract_emotion(text)` function scans for these tags, strips the matched tag, and returns `(cleaned_reply, emotion_string)`. If no tag is found, emotion defaults to `"idle"`.

| Tag | Emotion | Meaning |
|---|---|---|
| `[EMO:alert]` | alert | New threats found |
| `[EMO:cheer]` | cheer | All clear |
| `[EMO:think]` | think | Analyzing |
| `[EMO:sad]` | sad | Concerning pattern or AI not configured |
| `[EMO:wave]` | wave | Greeting |
| `[EMO:idle]` | idle | Default / no significant event |

The Angular `AriaMessage` interface captures the emotion: `{ role, content, timestamp, emotion?, alertCard?, actions? }`.

### System Prompt (`build_system_prompt`)

Called by `aria_chat` handler — injected before each conversation. Contents (in order):
1. **Identity**: "You are ARIA (Autonomous Response & Intelligence Assistant), a SOC assistant built into the NDR platform."
2. **Context**: analyst username + tenant_id from JWT.
3. **Live system status**: critical alerts (last 24h), high alerts (last 24h), evidence bundles captured — from parallel ClickHouse queries.
4. **Strict data rule**: must only answer from the DATA section; never invent IPs, hostnames, community IDs, rule names, or events; if data doesn't contain what's asked, say "I don't see any [X] in your current data."
5. **Personality**: professional but friendly, direct, proactive, shows genuine concern.
6. **Capabilities**: alert details, community_id/IP explanation, attack narratives from Agent-Z/Agent-S, conn_state code explanation.
7. **NDR platform context**: alerts via Kafka, community_id linkage, HIGH/CRITICAL auto-capture bundles.
8. **Response format**: under 150 words unless explaining an attack; plain text; reference specific IPs/timestamps from DATA; suggest next action.
9. **Emotion hint format**: `[EMO:tag]` must appear at very end of response.
10. **DATA section**: real_context from `fetch_aria_context()`, truncated to **3000 chars** — this is the live ClickHouse-sourced tenant data injected per request.

Note: The report-generation calls (`aria.chat(prompt, [])` from AI Report page) also go through this same system prompt, so ARIA's report narratives include the same live NDR context and data constraints.

#### `fetch_aria_context()` — Keyword-Driven DATA Assembly

`fetch_aria_context(ch, tenant_id, user_message, sensor_ids)` builds the DATA block dynamically from up to 6 ClickHouse sections. Sections are included **conditionally based on keywords detected in the lowercase user message**. All queries are sensor-scoped when `sensor_ids` is non-empty.

| Section | Trigger | Query | Limit |
|---|---|---|---|
| RECENT ALERTS | Always included | `ndr_hits` ordered by `timestamp` DESC — `community_id`, `src_ip`, `dst_ip`, `severity`, `score`, `tags`, `rule_name`, `timestamp` | 15 rows |
| ALERTS INVOLVING IP {x} | Message contains an IPv4 address (regex match) | `ndr_hits` WHERE `src_ip = '{ip}'` OR `dst_ip = '{ip}'` | 20 rows |
| LATERAL MOVEMENT ALERTS | "lateral", "spread", or "movement" in message | `ndr_hits` WHERE tags or sigma_hits contain "lateral" | 10 rows |
| EVIDENCE BUNDLES | "evidence", "bundle", or "pcap" in message | `evidence_bundles` FINAL — `id`, `community_id`, `src_ip`, `dst_ip`, `severity`, `captured_at`; additionally sensor-scoped via community_id sub-select | 10 rows |
| SUPPRESSION DECISIONS | "suppress", "false positive", or "whitelist" in message | `ai_suppressions` FINAL — `signature_name`, `suppress_type`, `suppress_ip`, `src_ip`, `dst_ip`, `ai_confidence`, `created_at` | 10 rows |
| CRITICAL/HIGH ALERTS (last 24h) | "critical", "high", or "severe" in message | `ndr_hits` WHERE `severity = '{CRITICAL\|HIGH}'` AND `timestamp >= now() - INTERVAL 24 HOUR` | 10 rows |

The assembled string is truncated to **3000 chars** before being embedded in the system prompt. If all queries return empty, each section explicitly states "No [X] found." so ARIA knows the data absence is real, not a missing section.

---

## Rust Handlers (AI Module)

| Handler | Route | Notes |
|---|---|---|
| `aria_chat` | `POST /api/aria/chat` | See detail below |
| `aria_status` | `GET /api/aria/status` | See detail below |
| `aria_investigate` | `POST /api/aria/investigate` | Evidence bundle AI investigation — documented in analyst-response.md §1.9 |
| `aria_get_verdict` | `GET /api/aria/verdict?cid=...` | Cached verdict retrieval — documented in analyst-response.md §1.9 |
| `get_ai_activity` | `GET /api/ai-activity` | Returns `{ suppressions, analyses }` — suppressions from `list_ai_suppressions` (tenant-scoped only); analyses from `get_all_ai_annotations` (scoped by both tenant and sensor_ids from JWT) |
| `deactivate_ai_suppression_handler` | `PATCH /api/ai-suppressions/:id/deactivate` | Marks suppression inactive; keeps record; tenant-scoped |
| `delete_ai_suppression_handler` | `DELETE /api/ai-suppressions/:id` | Permanently removes suppression rule; tenant-scoped |
| `get_threat_predictions` | `GET /api/threat/predictions` | Calls `crate::threat::get_predictions()` with **limit 20**; returns `{ predictions: rows }` |
| `get_threat_predictions_history` | `GET /api/threat/predictions/history` | Same function but **limit 100** — returns full historical data for trend timeline |

**`aria_chat` detail:**
1. Validates JWT; checks `get_tenant_ai_enabled(&tenant_id)` — returns `{ reply: "AI features are not enabled...", emotion: "neutral" }` if disabled for tenant (super_admin bypasses this check).
2. Truncates `history` to **last 6 messages** to limit input size (comment: "prevents prompt bloat on long conversations; Groq 6k TPM").
3. Fetches live tenant context in parallel (via `tokio::join!`): critical hit count, high hit count, evidence bundle count.
4. Calls `ch_storage.fetch_aria_context()` for real-time NDR data; truncates result to **3000 chars**.
5. Calls `crate::ai::build_system_prompt()` to assemble the full system prompt with analyst identity, live counts, and DATA section.
6. Calls `crate::ai::provider::generate_chat()` — resolves active `"chat"` providers from `ndr.ai_providers` (5-min cached), tries in priority order (see AI Provider System section). max_tokens: **1024**, timeout: **60s**.
7. Returns `{ reply, emotion }`. Emotion values: `"neutral"` (AI disabled), `"sad"` (all providers failed or unconfigured), or any `[EMO:tag]` value extracted from the response text.

**`aria_status` detail:**
Runs 4 ClickHouse queries: critical hit count and high hit count are fetched sequentially; then `tokio::join!` fetches the latest critical hit and the rising critical prediction in parallel. Returns:
```json
{
  "critical_count": N,
  "high_count": N,
  "latest_severity": "CRITICAL",
  "latest_src_ip": "...",
  "latest_dst_ip": "...",
  "latest_community_id": "...",
  "prediction_alert": true/false,
  "prediction_id": "...",
  "prediction_attack": "...",
  "prediction_prob": 0.0–1.0,
  "prediction_level": "...",
  "prediction_expl": "...",
  "emotion": "alert" | "idle"
}
```
`emotion` is `"alert"` if `critical_count > 0` or a rising critical prediction exists; otherwise `"idle"`.

---

## Data Flow

```
AI Activity page (live feed)
  merge(interval(15s), refresh$)
    └─ GET /api/ai-activity → analyses + suppressions signals
  interval(60s)
    └─ GET /api/threat/predictions → predictions signal

  deactivateSuppression(id)
    └─ PATCH /api/ai-suppressions/:id/deactivate → refresh$.next()

  togglePrediction(type)
    └─ GET /api/threat/predictions/history → historicalPredictions (filtered by attack_type)

AI Report page (on-demand generation)
  generateReport()
    └─ forkJoin(7 API calls) → raw data signals → filterByPeriod()
         └─ generateNarratives()
               ├─ POST /api/aria/chat (exec summary prompt)   → execSummary
               ├─ POST /api/aria/chat (threat narrative prompt) → threatNarrative
               └─ POST /api/aria/chat (recommendations prompt)  → recommendations
         └─ generateMitreMapping()
               └─ POST /api/aria/chat (MITRE JSON prompt) → mitreMap
                    └─ regex-extract JSON array → parse → Record<analysis_id, MitreEntry>

  downloadPdf() → window.print() (CSS: @page A4, watermark, hide .no-print)

ARIA Bot Widget (global overlay, mounted in app shell)
  ngOnInit
    └─ GET /api/aria/status → handleStatus() (initial)
  interval(30s)
    └─ GET /api/aria/status → handleStatus()
         ├─ new CRITICAL community_id → alert emotion + speech bubble + bot message (4 actions)
         └─ new prediction_id with alert → alert emotion + speech bubble + bot message (3 actions)

  sendMessage(text)
    └─ POST /api/aria/chat { message, history }
         └─ reply + emotion → addBotMessage() → setEmotion() → Lottie segment playback
              └─ history trimmed to last 20 client-side

  setInterval(18s) — proactive speech bubbles (while chat closed)
```
