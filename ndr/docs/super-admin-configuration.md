# NDR Developer Reference — Super Admin: Configuration

**Section path:** `/admin` → Configuration  
**Roles allowed:** `super_admin` only (all four pages enforce this in Rust handlers)  
**Sub-pages:** AI Providers · Trusted Cloud · Trusted Domains · SMTP Config · Support

---

## Routing Architecture

All four pages are **lazy-loaded child routes** of `AdminLayout` (`ndr-ui/src/layout/admin-layout/admin-layout.ts`). The layout is a two-panel shell: a fixed left sidebar + a `<router-outlet>` that renders the active child.

| URL | Component loaded |
|-----|-----------------|
| `/admin/ai-providers` | `AiProviders` |
| `/admin/trusted-cloud` | `TrustedCloud` |
| `/admin/trusted-domains` | `TrustedDomains` |
| `/admin/smtp-config` | `SmtpConfig` |
| `/admin/support` | `Support` (`ndr-ui/src/pages/admin/support/support.ts`) — role-aware via `isSuperAdmin` getter, shows "Forwarded Support" title and description for super_admin |

**Sidebar group:** "Configuration" with amber accent (`sa-group--amber`). The group auto-expands on load when any of the four URLs is active (checked in `AdminLayout.ngOnInit()` via `router.url.includes(...)`). Clicking the group header toggles collapse. All four pages use `routerLink` + `routerLinkActive="active"` — no query-param navigation.

**Full Super Admin sidebar structure for context:**

| Type | Color | Pages |
|------|-------|-------|
| Standalone | — | Overview |
| Standalone | — | **Support** (`/admin/support`) |
| Group: Access Control | Blue | Tenants, Users |
| Group: Infrastructure | Violet | Engines, Sensor Keys |
| Group: Monitoring | Emerald | Rules, Telemetry, Announcements |
| Group: **Configuration** | **Amber** | **AI Providers, Trusted Cloud, Trusted Domains, SMTP Config** |

The brand block in the sidebar shows "Super Admin" role label, "ProVigilAI" logo, and "powered by PromaSecure" badge.

---

## Page 1 — AI Providers

### 1.1 Angular Component

| Item | Detail |
|------|--------|
| Component class | `AiProviders` |
| File | `ndr-ui/src/pages/admin/ai-providers/ai-providers.ts:25` |
| Template | `ndr-ui/src/pages/admin/ai-providers/ai-providers.html` |
| Stylesheet | `ndr-ui/src/pages/admin/ai-providers/ai-providers.css` |
| Change detection | `OnPush` |

**`AiProvider` interface (line 10):**

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Unique provider name used as the DB primary key |
| `provider_type` | `string` | `custom` / `openai` / `anthropic` |
| `model` | `string` | Model identifier (e.g. `gpt-4o-mini`, `claude-sonnet-4-6`) |
| `base_url` | `string` | Root URL of the AI API (e.g. `https://api.openai.com`) |
| `endpoint_path` | `string` | Path appended to base_url — default `/v1/chat/completions` |
| `msg_format` | `string` | Request envelope format: `openai` or `anthropic` |
| `use_case` | `string` | `all` / `chat` / `threat` — controls which AI calls use this provider |
| `priority` | `number` | Lower number = higher priority when multiple providers match a use-case |
| `enabled` | `boolean` | Whether this provider is active |
| `key_set` | `boolean` | `true` if an API key exists in the DB — key itself is never returned |

**State fields:**

| Field | Purpose |
|-------|---------|
| `providers` | Loaded list of all configured providers |
| `loadingProviders` | Spinner during list load |
| `savingProvider` | Disables Save button during POST |
| `providerMessage` | Success toast text (e.g. `Provider "X" saved`) — auto-clears after 3 s |
| `providerError` | Error toast text — shown on save or delete failure |
| `testingProvider` | Name of provider currently being tested — drives per-row spinner; `'__new__'` while testing the unsaved form |
| `testProviderResult` | One-line test result: `"✓ name — OK"` (saved provider, 5 s) or `"✓ Connection OK — <response>"` (new, 6 s) |
| `showAddProviderForm` | Shows/hides the add/edit form panel |
| `isEditingProvider` | When `true`, Save updates instead of creating |
| `showProviderKey` | Toggles API key field between `type="password"` and plain text |

**Dropdown option arrays:**

| Array | Values |
|-------|--------|
| `providerTypeOptions` (line 53) | `{value:'custom', label:'Custom / OpenAI-compatible'}`, `{value:'openai', …}`, `{value:'anthropic', …}` |
| `useCaseOptions` (line 58) | `{value:'all', label:'All (chat + threat analysis)'}`, `{value:'chat', label:'ARIA chat only'}`, `{value:'threat', label:'Threat analysis only'}` |

**Form defaults (line 47):**

```typescript
newProvider = {
  name: '', provider_type: 'custom', api_key: '',
  model: '', base_url: '', endpoint_path: '/v1/chat/completions',
  msg_format: 'openai', use_case: 'all', priority: 10, enabled: true,
}
```

---

### 1.2 Lifecycle

```
ngOnInit() → loadProviders()    (GET /api/settings/ai/providers)
```

No polling — the provider list is static until an admin makes a change.

---

### 1.3 Angular Functions

#### `loadProviders()` — line 68
Calls `api.listAiProviders()` → `GET /api/settings/ai/providers`. Sets `providers[]`.

#### `saveProvider()` — line 76
Calls `api.saveAiProvider(this.newProvider)` → `POST /api/settings/ai/providers`.  
Works for both create and update — the backend upserts by `name`. After success: hides the form, resets it, and reloads the list. Toast auto-clears after 3 seconds.

#### `deleteProvider(name)` — line 93
Shows a browser `confirm()` dialog first. Calls `api.deleteAiProvider(name)` → `DELETE /api/settings/ai/providers/:name`.

#### `testProvider(p)` — line 105
Tests an **already-saved** provider. Sets `testingProvider = p.name` to show a per-row spinner. Sends `api_key: ''` (and the endpoint path defaults to `/v1/chat/completions` if not set, msg_format to `openai`). The backend fetches the real key from the DB by name. Result displayed for **5 seconds**, then cleared.

#### `testNewProvider()` — line 126
Tests the provider **currently in the add/edit form** (before saving). Sets `testingProvider = '__new__'`. Sends the full form object including any `api_key` the user typed. On success, shows first 60 chars of the AI response (`"✓ Connection OK — <text>"`). Result displayed for **6 seconds** (longer than the saved-provider test, since the full response text may need more reading time).

#### `editProvider(p)` — line 153
Copies a saved provider into the form (`{ ...p, api_key: '' }` — key is deliberately blanked). Sets `isEditingProvider = true` and `showAddProviderForm = true`.

#### `resetNewProvider()` — line 144
Resets `newProvider` to defaults and clears `isEditingProvider`.

#### `defaultBaseUrl` getter — line 159
Returns pre-filled base URL based on `provider_type`:
- `openai` → `https://api.openai.com`
- `anthropic` → `https://api.anthropic.com`
- `custom` → `''` (user must fill in; the form shows a Groq-specific hint: `For Groq: https://api.groq.com/openai`)

#### `defaultModelPlaceholder` getter — line 167
Returns placeholder text: `gpt-4o-mini` / `claude-sonnet-4-6` / `e.g. llama-3.3-70b-versatile`.

#### `useCaseLabel(uc)` — line 175
Converts `all`/`chat`/`threat` to `All`/`Chat`/`Threat` for display.

---

### 1.3a Form UI Constraints (from template)

These behaviors are enforced in the HTML template, not in the TypeScript class:

| Constraint | Detail |
|------------|--------|
| `name` field disabled when editing | Cannot rename an existing provider — the name is the DB primary key. To rename, delete and recreate. |
| API key required for new providers | Save button disabled (`!newProvider.api_key && !isEditingProvider`) — key is optional only when editing |
| Test Connection disabled without API key | Button disabled if `!newProvider.api_key` — even when editing, need to paste a key to test |
| `msg_format` not in form | Defaults to `'openai'` and cannot be changed from the UI. Only changeable via direct API call. |
| `enabled` not in form | Defaults to `true` — new providers are always created as enabled. No toggle in the UI. |
| Env var fallback order | Panel description: "Falls back to env vars (GROQ_API_KEY → OPENAI_API_KEY) if all fail" — Groq is tried before OpenAI |

---

### 1.4 API Service Methods

File: `ndr-ui/src/services/api/api.ts`

| Method | Line | HTTP Call |
|--------|------|-----------|
| `listAiProviders()` | 313 | `GET /api/settings/ai/providers` |
| `saveAiProvider(data)` | 317 | `POST /api/settings/ai/providers` |
| `deleteAiProvider(name)` | 321 | `DELETE /api/settings/ai/providers/:name` |
| `testAiProvider(data)` | 325 | `POST /api/settings/ai/providers/test` |

**Legacy single-config methods (api.ts lines 305–311, unused by any Angular component):**

| Method | HTTP Call | Notes |
|--------|-----------|-------|
| `getAiConfig()` | `GET /api/settings/ai` | Returns single-provider config: `ai_provider`, `ai_model`, `ai_api_key` (masked), `ai_key_set`, `ai_base_url`, `ai_endpoint_path`, `ai_msg_format` |
| `updateAiConfig(data)` | `POST /api/settings/ai` | Saves to the `"default"` tenant settings KV store |

These service methods exist in api.ts and their Rust handlers (`get_ai_config` at mod.rs:3301, `update_ai_config` at mod.rs:3323) are fully implemented, but no Angular component currently calls them. They predate the multi-provider system and are kept for backward compatibility.

---

### 1.5 Rust Routes

File: `rust/ndr-engine/src/main.rs:763–765`

| Method | URL | Handler |
|--------|-----|---------|
| `GET` | `/api/settings/ai/providers` | `api::list_ai_providers` |
| `POST` | `/api/settings/ai/providers` | `api::save_ai_provider` |
| `DELETE` | `/api/settings/ai/providers/:name` | `api::delete_ai_provider` |
| `POST` | `/api/settings/ai/providers/test` | `api::test_ai_provider` |

---

### 1.6 ClickHouse Table: `ndr.ai_providers`

Table engine: `ReplacingMergeTree` — deduplicates by `name`. Every save is an `INSERT`; reads use `FINAL` to collapse duplicates to the latest version.

| Column | ClickHouse Type | Description |
|--------|----------------|-------------|
| `name` | `String` | Primary key (unique provider name) |
| `provider_type` | `String` | `custom` / `openai` / `anthropic` |
| `api_key` | `String` | Raw API key — never returned by list/get admin APIs |
| `model` | `String` | Model identifier |
| `base_url` | `String` | Root URL |
| `endpoint_path` | `String` | API path suffix |
| `msg_format` | `String` | `openai` or `anthropic` |
| `use_case` | `String` | `all` / `chat` / `threat` |
| `priority` | `UInt8` | Lower = higher priority |
| `enabled` | `UInt8` | `1` = active, `0` = disabled (ClickHouse has no native bool) |

**`enabled` storage note:** Stored as `UInt8` (0/1), not a boolean. The storage layer converts: `if enabled { 1 } else { 0 }` on write, `r.enabled == 1` on read back to Rust bool.

**Internal `get_ai_providers(use_case)` method (storage/clickhouse.rs:2350):** A separate storage method used by the AI subsystem (not the admin API). It returns full `AiProvider` structs **including the real api_key** and filters by `use_case`. This is what threat scoring, AI suppression, and ARIA chat call to pick a provider.

---

### 1.7 Rust Handler: `list_ai_providers()` — line 3357

File: `rust/ndr-engine/src/api/mod.rs`

Requires `super_admin`. Calls `ch_storage.list_ai_providers()`. Returns `{ status:"ok", providers:[...] }` ordered by `priority ASC`.

**Key masking happens at the SQL level** (storage/clickhouse.rs:2382–2383):
```sql
SELECT name, provider_type, model, ...,
       if(length(api_key) > 0, 1, 0) as key_set
FROM ndr.ai_providers FINAL ORDER BY priority ASC
```
The `api_key` column is never selected — a computed `key_set` integer (0 or 1) is returned instead and converted to a boolean. This means even a compromised Rust handler cannot leak the key from a list call.

---

### 1.8 Rust Handler: `save_ai_provider()` — line 3369

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Requires `super_admin`.
2. Extracts all provider fields from the JSON body.
3. Validates that `name` is not empty — returns error if missing.
4. **Masked key handling — two-stage flow** (line 3392):
   - Stage 1 (line 3392): if `api_key` contains `"****"` or is empty, the code sets `effective_key = ""`. The intermediate `list_ai_providers()` call at this point is a no-op — its `Ok(_)` result is immediately discarded with `String::new()`.
   - Stage 2 (line 3406): if `effective_key` is now empty, calls `ch_storage.get_ai_provider_key(&name)` to fetch the real key from the DB and assigns it to `final_key`. If the provider does not yet exist, `final_key` will also be empty (a new provider with no key set).
5. Calls `ch_storage.save_ai_provider(name, provider_type, key, model, base_url, endpoint_path, msg_format, use_case, priority, enabled)` — upsert by `name`.
6. Returns `{ status:"ok", message:"Provider saved" }`.

**Why is the API key never returned to the UI?**  
API keys for OpenAI, Anthropic, and other providers are credentials. Listing them would expose them to anyone who can view network traffic or browser DevTools. The `key_set` boolean tells the UI whether a key exists without revealing it.

---

### 1.9 Rust Handler: `delete_ai_provider()` — line 3423

Requires `super_admin`. Deletes the provider row from the DB by name. Returns `{ status:"ok" }`.

---

### 1.10 Rust Handler: `test_ai_provider()` — line 3436

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Requires `super_admin`.
2. Reads `api_key` from request. If empty or contains `"****"` (masked from UI), fetches the real key from the DB using `ch_storage.get_ai_provider_key(&name)`. If still empty after lookup, returns error.
3. Builds a `crate::ai::provider::AiProvider` struct with the provider's config.
4. Calls `crate::ai::provider::call_provider_test(&provider, "You are a test assistant.", "Reply with exactly: OK")`.
5. Returns `{ status:"ok", response:"OK" }` on success or `{ status:"error", error:"..." }` on failure.

The test prompt is intentionally trivial — it only verifies the endpoint is reachable and the key is valid, not that the model produces quality output.

---

### 1.11 Use-Case Routing

When the AI subsystem calls `generate()` or `generate_chat()`, it selects a provider based on `use_case` and `priority`:
- `use_case = "all"` → provider is eligible for any AI call
- `use_case = "chat"` → only ARIA chatbot requests
- `use_case = "threat"` → only threat analysis and AI suppression calls
- `priority` — if multiple providers match, the lowest `priority` number wins

This allows the admin to route heavy threat-analysis workloads to a high-quota provider while using a cheaper model for ARIA chat.

---

## Page 2 — Trusted Cloud

### 2.1 Angular Component

| Item | Detail |
|------|--------|
| Component class | `TrustedCloud` |
| File | `ndr-ui/src/pages/admin/trusted-cloud/trusted-cloud.ts:19` |
| Template | `ndr-ui/src/pages/admin/trusted-cloud/trusted-cloud.html` |
| Stylesheet | `ndr-ui/src/pages/admin/trusted-cloud/trusted-cloud.css` |

**State fields:**

| Field | Type | Purpose |
|-------|------|---------|
| `trustedCloud.keywords` | `string[]` | ASN org name keywords that mark cloud traffic as trusted |
| `trustedCloud.domains` | `string[]` | Exact domain suffixes that mark traffic as trusted |
| `trustedCloud.suggestions` | `{org,hits}[]` | AI/heuristic suggestions for orgs seen frequently in traffic |
| `newKeyword` | `string` | Input field bound to keyword text box |
| `newDomain` | `string` | Input field bound to domain text box |
| `loadingTrustedCloud` | `boolean` | Spinner during initial load |
| `trustedCloudSaving` | `boolean` | Save button spinner |
| `trustedCloudSaved` | `boolean` | Shows green checkmark for 3 seconds after save |

---

### 2.2 Lifecycle

```
ngOnInit() → loadTrustedCloud()    (GET /api/settings/trusted-cloud)
```

---

### 2.3 Angular Functions

#### `loadTrustedCloud()` — line 36
Calls `api.getTrustedCloudSettings()` → `GET /api/settings/trusted-cloud`.  
Populates `trustedCloud` with `{ keywords, domains, suggestions }`.

#### `addKeyword()` — line 44
Trims the input and converts to **uppercase**. Adds to `trustedCloud.keywords[]` only if not already present. Clears the input field. Changes are local until `saveTrustedCloud()` is called. Triggered by both the Add Keyword button and the **Enter key** (`keydown.enter` binding on the input).

#### `removeKeyword(kw)` — line 50
Removes entry from local `trustedCloud.keywords[]`. Not persisted until `saveTrustedCloud()`.

#### `addDomain()` — line 52
Trims and converts to **lowercase**. Adds to `trustedCloud.domains[]` if not duplicate. Local-only until saved. Also triggered by the **Enter key**.

#### `removeDomain(d)` — line 58
Removes entry from local `trustedCloud.domains[]`. Local-only until saved.

#### `saveTrustedCloud()` — line 60
Calls `api.updateTrustedCloudSettings({ keywords, domains })` → `PUT /api/settings/trusted-cloud`.  
Sets `trustedCloudSaved = true` for 3 seconds (green checkmark feedback).

#### `approveSuggestion(org)` — line 74
Calls `api.approveTrustedCloudSuggestion(org)` → `POST /api/settings/trusted-cloud/suggestions/approve` with `{ org }`.  
On success in Angular: removes the suggestion from the local list and adds `org.split(' ')[0]` (first space-delimited word) to `trustedCloud.keywords` locally for immediate display.

**The Rust backend does full persistence** — `approve_suggestion()` in `cloud_suggestions.rs:154`:
1. Calls `extract_keyword(org)` (see below) to derive the canonical keyword
2. Appends the keyword to `trusted_cloud_asn_keywords` global setting in the DB (skips if already present)
3. Removes the org from the `trusted_cloud_suggestions` JSON setting
4. Calls `guard.add_asn_keyword(&keyword)` on `state.trusted` — keyword is hot-applied immediately

**`extract_keyword(org)` function (`cloud_suggestions.rs:206`)** — more than just `first word`:
- Known multi-word brands are preserved as one token: `DIGITAL OCEAN` → `DIGITALOCEAN`, `HETZNER`, `LINODE`, `VULTR`, `OVH`, `LEASEWEB`
- Otherwise takes the first meaningful word, skipping bare AS numbers (e.g. `AS12345`)
- Example: `"ORACLE CLOUD INFRASTRUCTURE"` → `"ORACLE"`

**Angular vs Rust extraction differ:** Angular adds `org.split(' ')[0]` to the local keyword chip display; Rust persists `extract_keyword(org)` to the DB. These may differ for multi-word brands (e.g. `"DIGITAL OCEAN"` — Angular would add `"DIGITAL"`, Rust would add `"DIGITALOCEAN"`). The DB wins; the local chip is display-only and refreshes on next `loadTrustedCloud()`.

#### `rejectSuggestion(org)` — line 85
Calls `api.rejectTrustedCloudSuggestion(org)` → `POST /api/settings/trusted-cloud/suggestions/reject` with `{ org }`.  
Removes from local suggestions list. The Rust `reject_suggestion()` (`cloud_suggestions.rs:188`):
1. Removes the org from the `trusted_cloud_suggestions` JSON setting
2. Appends `extract_keyword(org)` to `trusted_cloud_rejected` global setting — this ensures the scanner's `run_scan()` will skip this org on every future cycle

---

### 2.4 API Service Methods

File: `ndr-ui/src/services/api/api.ts`

| Method | Line | HTTP Call | Body |
|--------|------|-----------|------|
| `getTrustedCloudSettings()` | 329 | `GET /api/settings/trusted-cloud` | — |
| `updateTrustedCloudSettings(data)` | 333 | `PUT /api/settings/trusted-cloud` | `{ keywords?, domains? }` |
| `approveTrustedCloudSuggestion(org)` | 337 | `POST /api/settings/trusted-cloud/suggestions/approve` | `{ org }` |
| `rejectTrustedCloudSuggestion(org)` | 341 | `POST /api/settings/trusted-cloud/suggestions/reject` | `{ org }` |

---

### 2.5 Rust Routes

File: `rust/ndr-engine/src/main.rs:766–768`

| Method | URL | Handler |
|--------|-----|---------|
| `GET` | `/api/settings/trusted-cloud` | `api::get_trusted_cloud_settings` |
| `PUT` | `/api/settings/trusted-cloud` | `api::update_trusted_cloud_settings` |
| `POST` | `/api/settings/trusted-cloud/suggestions/approve` | `api::approve_trusted_cloud_suggestion` |
| `POST` | `/api/settings/trusted-cloud/suggestions/reject` | `api::reject_trusted_cloud_suggestion` |

---

### 2.6 Rust Handler: `get_trusted_cloud_settings()` — line 10413

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Requires `super_admin`.
2. Reads `trusted_cloud_asn_keywords` global setting — a comma-separated string.
3. Reads `trusted_cloud_domains` global setting — a comma-separated string.
4. Splits both into `Vec<&str>`, filtering empty entries.
5. Calls `crate::threat::cloud_suggestions::load_suggestions(ch)` to get AI/heuristic suggestions sorted by hit count (descending).
6. Returns `{ keywords:[...], domains:[...], suggestions:[{org,hits},...] }`.

---

### 2.7 Rust Handler: `update_trusted_cloud_settings()` — line 10447

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Requires `super_admin`.
2. If `keywords` is provided:
   - Uppercases each keyword, filters empty entries, joins with commas, saves to global setting `trusted_cloud_asn_keywords` via `ch.set_global_setting()`.
   - Also iterates the keyword list and calls `guard.add_asn_keyword(kw.trim())` on the `state.trusted` write lock — **keywords take effect immediately for the live engine instance without a restart**.
3. If `domains` is provided:
   - Lowercases each domain, joins with commas, saves to global setting `trusted_cloud_domains`.
   - **The in-memory `state.trusted` RwLock is NOT updated for domains.** Domain changes are persisted to the DB only. They take effect on the next engine restart or reload cycle — not immediately.
4. Returns `{ ok: true }`.

> **Behavioral asymmetry:** ASN keyword changes are hot-applied (instant); domain changes require an engine restart to propagate to the live processing cache. This is a current implementation limitation — keywords have `add_asn_keyword()` on the `TrustedCloud` struct; no equivalent `add_domain()` is called here.

**Why update `state.trusted` for keywords at all?**  
The trusted cloud list is checked on every event in the hot processing path. Reading from the DB on every event would be too slow. The `Arc<RwLock<TrustedCloud>>` is the live cache; ClickHouse settings are the persistent source loaded on startup.

---

### 2.8 What "Trusted Cloud" Controls

The trusted cloud list tells the AI suppression system and the threat scoring engine which ASN organizations and domains are pre-approved infrastructure.

- **Keywords** match against the ASN org name from GeoIP enrichment. Example: `AMAZON`, `GOOGLE`, `MICROSOFT`. Traffic whose destination IP resolves to an ASN containing one of these keywords is considered trusted cloud traffic and will not trigger false-positive suppression suggestions.
- **Domains** match against DNS query or TLS SNI. Example: `amazonaws.com`, `azure.com`.
- **Suggestions** are org names that the `cloud_suggestions` background scanner has identified as high-volume destinations with zero threat hits, then confirmed as legitimate cloud/CDN via AI. The admin can approve (keyword added to DB + in-memory immediately) or reject (org suppressed from future suggestions).

**Background scanner (`cloud_suggestions::spawn_suggestion_scanner` — runs every 15 minutes):**
1. Reads current `trusted_cloud_asn_keywords` and `trusted_cloud_rejected` global settings
2. Queries `get_high_volume_clean_dst_ips(tenant, 24h, threshold=30)` for all tenants that have AI enabled
3. Looks up ASN org name via `GeoLite2-ASN.mmdb` for each IP
4. Filters orgs already trusted, rejected, or already pending as suggestions
5. Calls AI (`UseCase::ThreatPrediction`) for up to 10 new candidates per cycle: "Is this org a legitimate cloud/CDN provider?"
6. Saves approved suggestions as JSON to global setting `trusted_cloud_suggestions` (`{org: hits_count}`)
7. Sleeps 3 seconds between AI calls to avoid rate limiting

**UI scan frequency note:** Panel header says "AI scans every 15 minutes" — this is correct (`tokio::time::sleep(900s)`). The empty-state text "Next scan runs automatically every 6 hours" is incorrect UI copy.

**Suggestion storage:** Stored as JSON in the `trusted_cloud_suggestions` global settings key — not a separate table. Rejected orgs are stored in `trusted_cloud_rejected`.

**"Saved and applied immediately" text on Save:** Shown after `saveTrustedCloud()`. This is accurate for **keywords** (which update `state.trusted` in-memory instantly) but **not for domains** (which only persist to the DB and require an engine restart). The save feedback copy does not distinguish between the two.

---

## Page 3 — Trusted Domains

### 3.1 Angular Component

| Item | Detail |
|------|--------|
| Component class | `TrustedDomains` |
| File | `ndr-ui/src/pages/admin/trusted-domains/trusted-domains.ts:19` |
| Template | `ndr-ui/src/pages/admin/trusted-domains/trusted-domains.html` |
| Stylesheet | `ndr-ui/src/pages/admin/trusted-domains/trusted-domains.css` |

**State fields:**

| Field | Type | Purpose |
|-------|------|---------|
| `tenants` | `any[]` | All tenants — populates the scope dropdown |
| `trustedDomains` | `any[]` | Full list returned by the API |
| `tdNewDomain` | `string` | Domain input field |
| `tdNewCategory` | `string` | Category dropdown — default `dns_beacon`; options: `dns_beacon`, `threat_intel`, `both` |
| `tdNewScope` | `string` | `''` = global, or a tenant UUID for tenant-scoped |
| `tdNewNote` | `string` | Optional human note |
| `tdSaving` | `boolean` | Spinner during add |
| `tdAiLoading` | `boolean` | Spinner while AI suggestion is running |
| `tdAiAvailable` | `boolean \| null` | Whether AI is configured — hides button if `false` |
| `tdAiSuggestions` | `any[]` | AI-suggested domains pending review |

**Computed getters:**
- `globalDomains` (line 98) — filters `trustedDomains` where `scope === 'global'` (tenant_id is empty)
- `tenantDomains` (line 99) — filters where `scope === 'tenant'`

---

### 3.2 Lifecycle

```
ngOnInit()
  → loadTrustedDomains()     (GET /api/trusted-domains)
  → api.getTenants()         (GET /api/auth/tenants — populates scope dropdown)
```

---

### 3.3 Angular Functions

#### `loadTrustedDomains()` — line 48
Calls `api.listTrustedDomains()` → `GET /api/trusted-domains`. Sets `trustedDomains[]`.

#### `addTrustedDomain()` — line 56
1. Trims and lowercases `tdNewDomain`. Returns if empty.
2. Calls `api.addTrustedDomain(domain, category, scope, note)` → `POST /api/trusted-domains`.
3. On success: clears `tdNewDomain` and `tdNewNote` (category and scope are kept for the next entry), reloads list.
4. Add button is disabled until `tdNewDomain.trim()` is non-empty. Domain input also supports **Enter key** (`keydown.enter`).

#### `deleteTrustedDomain(domain, tenantId)` — line 66
Calls `api.deleteTrustedDomain(domain, tenantId)` → `POST /api/trusted-domains/delete` with `{ domain, tenant_id }`.  
On success: removes the entry from `trustedDomains[]` locally without a full reload.

#### `runAiSuggest()` — line 76
Calls `api.aiSuggestTrustedDomains()` → `POST /api/trusted-domains/ai-suggest {}`.  
Sets `tdAiAvailable` from `data.ai_available`. Populates `tdAiSuggestions` with the returned list.

#### `approveTdSuggestion(s)` — line 89
Only callable for suggestions where `s.verdict === 'TRUSTED'` — the "Add Global" button is hidden (`*ngIf="s.verdict === 'TRUSTED'"`) for SUSPICIOUS-classified domains. Calls `api.addTrustedDomain(s.domain, 'dns_beacon', '', s.reason)` — creates the domain as a **global** entry (empty tenant_id) with the AI's reason as the note. Removes the suggestion from `tdAiSuggestions[]` locally and reloads the full domain list.

#### `dismissTdSuggestion(domain)` — line 96
Removes the suggestion from local `tdAiSuggestions[]` only — no API call. The suggestion may reappear on the next AI run. This is the **only action available for SUSPICIOUS-verdict suggestions** — they cannot be approved, only dismissed.

**Suggestion card UI details:**
- SUSPICIOUS suggestions are visually dimmed (`opacity: 0.6`; TRUSTED are at full opacity)
- Each card shows: domain, query count with `number` pipe, and AI reason text
- TRUSTED: shows "Add Global" + "Dismiss" buttons
- SUSPICIOUS: shows "Dismiss" only
- When `tdAiAvailable === false`, displays: "AI not configured — Add an AI provider in the AI Providers tab to enable domain classification suggestions."

---

### 3.4 API Service Methods

File: `ndr-ui/src/services/api/api.ts`

| Method | Line | HTTP Call | Body |
|--------|------|-----------|------|
| `listTrustedDomains()` | 355 | `GET /api/trusted-domains` | — |
| `addTrustedDomain(domain, category, tenantId, note)` | 359 | `POST /api/trusted-domains` | `{ domain, category, tenant_id, note }` |
| `deleteTrustedDomain(domain, tenantId)` | 365 | `POST /api/trusted-domains/delete` | `{ domain, tenant_id }` |
| `aiSuggestTrustedDomains()` | 371 | `POST /api/trusted-domains/ai-suggest` | `{}` |

**Why `POST /trusted-domains/delete` instead of `DELETE /trusted-domains/:domain`?**  
The delete operation requires both a `domain` and a `tenant_id` to uniquely identify the row (the same domain can exist for multiple tenants). Encoding two parameters in a DELETE URL is awkward — a POST body is cleaner.

---

### 3.5 Rust Routes

File: `rust/ndr-engine/src/main.rs:769–771`

| Method | URL | Handler |
|--------|-----|---------|
| `GET` | `/api/trusted-domains` | `api::list_trusted_domains` |
| `POST` | `/api/trusted-domains` | `api::add_trusted_domain` |
| `POST` | `/api/trusted-domains/delete` | `api::delete_trusted_domain` |
| `POST` | `/api/trusted-domains/ai-suggest` | `api::ai_suggest_trusted_domains` |

---

### 3.6 Rust Handler: `list_trusted_domains()` — line 10525

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Extracts JWT claims — returns 401 if missing.
2. Role-based query scope:
   - `super_admin` → `SELECT ... FROM ndr.trusted_domains FINAL ORDER BY tenant_id, category, domain` (returns all rows for all tenants)
   - Any other role → `WHERE tenant_id = '' OR tenant_id = '{claims.tenant_id}'` (global entries + their tenant's entries only)
3. For each row, adds a computed `scope` field: `"global"` when `tenant_id` is empty, `"tenant"` otherwise.
4. Returns `{ domains: [...] }`.

---

### 3.7 Rust Handler: `add_trusted_domain()` — line 10577

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Extracts JWT claims — returns 401 if missing.
2. Role check: only `super_admin` and `tenant_admin` may add domains — returns 403 for analysts.
3. Lowercases the domain. Defaults category to `dns_beacon` if omitted.
4. **Tenant scope logic** (line 10597):
   - `super_admin`: uses `body.tenant_id` as-is. If empty string → global entry (visible to all tenants).
   - `tenant_admin`: ignores `body.tenant_id` and forces `claims.tenant_id` — cannot create global entries.
5. Inserts into `ndr.trusted_domains` with `added_by = claims.sub` and `added_at = now()`.
6. Returns `{ ok:true, domain, scope:"global"|"tenant" }`.

---

### 3.8 Rust Handler: `delete_trusted_domain()` — line 10621

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Extracts JWT claims — returns 401 if missing.
2. Role check: only `super_admin` and `tenant_admin`.
3. Same tenant scope logic as `add_trusted_domain` — tenant_admin is forced to their own `tenant_id`.
4. Runs `ALTER TABLE ndr.trusted_domains ON CLUSTER ndr_cluster DELETE WHERE domain = '...' AND tenant_id = '...' SETTINGS mutations_sync=1`.

**Why `ALTER TABLE DELETE` instead of `ReplacingMergeTree` pattern?**  
ClickHouse `trusted_domains` uses a deletion-based approach here (`mutations_sync=1` blocks until the mutation completes). This is appropriate because trusted domain entries are rare and writes are infrequent — the mutation overhead is acceptable. Other tables like `ndr.sensor_keys` use the INSERT/FINAL pattern because they are updated frequently.

---

### 3.9 Rust Handler: `ai_suggest_trusted_domains()` — line 10654

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Extracts JWT claims — returns 401 if missing. Only `super_admin` and `tenant_admin`.
2. **AI availability check** (line 10669):
   - Checks if any enabled provider exists in `ch_storage.list_ai_providers()`.
   - Also checks env vars: `GROQ_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`.
   - If neither, returns `{ ai_available: false }` — UI hides the AI Suggest button.
3. Queries `ndr.ndr_events` for high-frequency DNS query domains from the last 24 hours (line 10686):
   - `event_type = 'dns'`, `JSONExtractString(raw, 'query')` as the domain field
   - Excludes internal suffixes: domains ending in `.local`, `.internal`, `.lan`, `.corp`, `.home`
   - `HAVING cnt > 30` — only domains queried more than 30 times qualify
   - `ORDER BY cnt DESC LIMIT 40` — returns up to 40 candidates (not 50)
   - Query is tenant-scoped: `super_admin` sees `1=1`; others see `tenant_id = '{claims.tenant_id}'`
   - Returns empty suggestions (not an error) if no candidates meet the threshold
4. Fetches already-trusted domains from `ndr.trusted_domains` and removes them from the candidate list using both exact match and subdomain match (`c.domain.ends_with(&format!(".{}", e))`) — e.g. if `amazonaws.com` is trusted, `s3.amazonaws.com` is also filtered out.
5. Formats the remaining candidates as a bullet list (`- domain (N queries/24h)`) and sends to AI using `UseCase::ThreatPrediction` (so threat-analysis-configured providers are preferred) with this system prompt:
   > "You are a network security analyst. Classify domains as TRUSTED (legitimate CDN, cloud, SaaS, update server) or SUSPICIOUS (potential C2, malware, or out-of-place traffic). Reply ONLY with valid JSON."
6. Parses the AI JSON response (with fallback bracket-search for messy responses).
7. Returns `{ ai_available: true, suggestions: [{domain, verdict, reason, cnt}] }`.

---

### 3.10 ClickHouse Table: `ndr.trusted_domains`

| Column | Type | Description |
|--------|------|-------------|
| `domain` | `String` | The trusted domain or suffix (lowercased) |
| `category` | `String` | Classification: `dns_beacon`, `update_server`, `cdn`, etc. |
| `tenant_id` | `String` | Empty string = global; tenant UUID = tenant-scoped |
| `note` | `String` | Human note or AI reason |
| `added_by` | `String` | `claims.sub` (username) of whoever added this entry |
| `added_at` | `DateTime` | When the entry was created |

**Category semantics:**

| Category value | What it suppresses |
|---------------|-------------------|
| `dns_beacon` | DNS beaconing alerts — domain excluded from beacon detection |
| `threat_intel` | Threat intel alerts — domain excluded from threat intel matching |
| `both` | Both DNS beaconing and threat intel alerts |

The panel description reads: "Domains in this list are excluded from DNS beaconing and threat intel alerts." — but which exclusions apply depends on the category stored for each entry.

**Scope semantics:** `tenant_id = ''` means the entry is visible to all tenants. `tenant_id = 'abc-123'` means it is visible only to that tenant and to super_admins.

**UI rendering details:**
- **Global entries** — rendered as chips. Each chip shows: domain, category badge, remove button. Hovering shows `title="note || added_by"` — the note if set, otherwise the username who added it.
- **Tenant entries** — rendered as a table with columns: Domain, Category, Tenant (tenant_id), Added By. Has a dedicated red trash-icon delete button per row.
- **Category field stored values:** `dns_beacon`, `threat_intel`, `both` (displayed as-is from the DB).
- **Scope dropdown** — populated from `api.getTenants()` response: first option is `value=""` (Global, all tenants); then one option per tenant using `t.id` as value and `t.name` as label.

---

## Page 4 — SMTP Config

### 4.1 Angular Component

| Item | Detail |
|------|--------|
| Component class | `SmtpConfig` |
| File | `ndr-ui/src/pages/admin/smtp-config/smtp-config.ts:19` |
| Template | `ndr-ui/src/pages/admin/smtp-config/smtp-config.html` |
| Stylesheet | `ndr-ui/src/pages/admin/smtp-config/smtp-config.css` |
| Panel title | "Sender Gmail Configuration" — the UI is specifically worded for Gmail |

**State fields:**

| Field | Default | Purpose |
|-------|---------|---------|
| `smtpConfig.host` | `smtp.gmail.com` | SMTP relay host — rendered as `type="text"` |
| `smtpConfig.port` | `587` | SMTP port (587 = STARTTLS) — rendered as `type="number"` |
| `smtpConfig.user` | `''` | Gmail address — rendered as `type="email"` with placeholder `security@yourdomain.com` |
| `smtpConfig.password` | `''` | Gmail App Password — rendered as `type="password"` (always; no show/hide toggle) with placeholder "Leave empty to keep existing password" |
| `savingSmtp` | `false` | Disables Save button during POST |
| `smtpMessage` | `''` | Success toast text |
| `smtpError` | `''` | Error toast text |

---

### 4.2 Lifecycle

```
ngOnInit() → loadSmtpConfig()    (GET /api/settings/smtp)
```

---

### 4.3 Angular Functions

#### `loadSmtpConfig()` — line 34
Calls `api.getGlobalSmtp()` → `GET /api/settings/smtp`.  
If `data.status === 'ok' && data.config` exists, sets `smtpConfig`. The returned `password` field is always `"****"` if a password is stored — never the real value.

#### `saveSmtpConfig()` — line 44
Calls `api.updateGlobalSmtp(this.smtpConfig)` → `POST /api/settings/smtp`.  
On success: clears the password field (`this.smtpConfig.password = ''`) and reloads from the API. This prevents the user from accidentally resubmitting the password. Toast clears after 3 seconds.

**Why clear the password field after save?**  
The GET endpoint returns `"****"` for any stored password. If the user saves, then the form shows their real typed password. Clearing it and reloading puts it back to `"****"`, which is the correct masked state. It also prevents the form from resubmitting a real password on a second accidental save.

**Note:** The Save button has no required-field validation — it only disables during `savingSmtp`. Saving with empty host/user/password fields is allowed; the backend will save whatever is provided (empty strings become empty settings, except password which is guarded against overwriting with blank).

---

### 4.4 API Service Methods

File: `ndr-ui/src/services/api/api.ts`

| Method | Line | HTTP Call | Body |
|--------|------|-----------|------|
| `getGlobalSmtp()` | 297 | `GET /api/settings/smtp` | — |
| `updateGlobalSmtp(data)` | 301 | `POST /api/settings/smtp` | `{ host, port, user, password }` |

---

### 4.5 Rust Routes

File: `rust/ndr-engine/src/main.rs:761`

| Method | URL | Handler |
|--------|-----|---------|
| `GET` | `/api/settings/smtp` | `api::get_global_smtp` |
| `POST` | `/api/settings/smtp` | `api::update_global_smtp` |

---

### 4.6 Rust Handler: `get_global_smtp()` — line 3248

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Requires `super_admin`.
2. Calls `ch_storage.get_global_smtp_settings()` — reads four setting keys: `global_smtp_host`, `global_smtp_port`, `global_smtp_user`, `global_smtp_password`. Defaults to `smtp.gmail.com:587` if not set.
3. Parses port string to `u16`, defaulting to `587` on parse failure.
4. Masks the password: if not empty returns `"****"`, otherwise `""`.
5. Returns `{ status:"ok", config:{ host, port, user, password:"****" } }`.

---

### 4.7 Rust Handler: `update_global_smtp()` — line 3272

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Requires `super_admin`.
2. Reads `host`, `port`, `user`, `password` from the JSON body.
3. Saves `global_smtp_host`, `global_smtp_port`, `global_smtp_user` via `ch_storage.save_setting(key, value)` — always overwrites.
4. **Password guard** (line 3290): only saves `global_smtp_password` if the value is non-empty AND does not contain `'*'`. This prevents a masked `"****"` from overwriting the real stored password when the form is submitted without changing the password field.
5. Returns `{ status:"ok", message:"SMTP configuration saved successfully" }`.

---

### 4.8 Settings Storage Pattern

All four config pages ultimately store data via the global settings key-value mechanism:

| Setting key | Page | Value type |
|-------------|------|------------|
| `global_smtp_host` | SMTP Config | String |
| `global_smtp_port` | SMTP Config | String (parsed to u16 on read) |
| `global_smtp_user` | SMTP Config | String |
| `global_smtp_password` | SMTP Config | String (plain — protect at rest via disk encryption) |
| `trusted_cloud_asn_keywords` | Trusted Cloud | Comma-separated string, uppercase |
| `trusted_cloud_domains` | Trusted Cloud | Comma-separated string, lowercase |

AI Providers use a dedicated `ndr.ai_providers` table (not the settings KV store) because they have multiple rows with structured fields including per-provider priority and use_case routing.

Trusted Domains use a dedicated `ndr.trusted_domains` table because entries are per-tenant with category and audit fields.

---

## Full Data Flow Diagrams

### Save AI Provider

```
Admin fills provider form → Save
  → saveProvider()                              ai-providers.ts:76
  → api.saveAiProvider(newProvider)             api.ts:317
  → POST /api/settings/ai/providers  (cookie)
  → save_ai_provider()                          api/mod.rs:3369
      → require_super_admin()
      → if api_key contains "****" or empty:
          → ch_storage.get_ai_provider_key(name)   ← fetch existing key
      → ch_storage.save_ai_provider(all fields)
          → upsert into ndr.ai_providers
  → HTTP 200: { status:"ok" }
  → loadProviders()                             (refresh list)
```

### Test Existing Provider

```
Admin clicks ⚡ on a saved provider
  → testProvider(p)                             ai-providers.ts:105
  → api.testAiProvider({ name, provider_type, api_key:'', model, ... })  api.ts:325
  → POST /api/settings/ai/providers/test
  → test_ai_provider()                          api/mod.rs:3436
      → raw_api_key is empty → ch_storage.get_ai_provider_key(name)
      → builds AiProvider struct
      → call_provider_test(provider, system, "Reply with exactly: OK")
          → HTTP POST to provider's base_url + endpoint_path
  → HTTP 200: { status:"ok", response:"OK" }
  → testProviderResult = "✓ ProviderName — OK"  (shown 5 seconds)
```

### AI Suggest Trusted Domains

```
Admin clicks "AI Suggest"
  → runAiSuggest()                              trusted-domains.ts:76
  → api.aiSuggestTrustedDomains()               api.ts:371
  → POST /api/trusted-domains/ai-suggest  {}
  → ai_suggest_trusted_domains()                api/mod.rs:10654
      → check ai_available (DB providers OR env vars)
      → SELECT DNS query domains: last 24h, cnt>30, LIMIT 40, tenant-scoped
            (excludes .local/.internal/.lan/.corp/.home)
      → SELECT existing trusted domains → remove already-trusted (exact + subdomain match)
      → AI classify remaining: TRUSTED / SUSPICIOUS  (UseCase::ThreatPrediction)
  → HTTP 200: { ai_available:true, suggestions:[{domain,verdict,reason,cnt}] }
  → tdAiSuggestions = data.suggestions
  → admin approves → approveTdSuggestion(s)     trusted-domains.ts:89
      → api.addTrustedDomain(s.domain,'dns_beacon','',s.reason)
      → POST /api/trusted-domains  { domain, category, tenant_id:'', note }
      → add_trusted_domain()                    api/mod.rs:10577
          → INSERT INTO ndr.trusted_domains
```

---

## Role-Based Differences

| Operation | super_admin | tenant_admin | analyst/viewer |
|-----------|-------------|--------------|----------------|
| Manage AI Providers | Full access | 403 | 403 |
| Configure Trusted Cloud | Full access | 403 | 403 |
| Configure SMTP | Full access | 403 | 403 |
| List Trusted Domains | All tenants | Own tenant + global | 403 |
| Add Trusted Domain | Global or any tenant | Own tenant only | 403 |
| Delete Trusted Domain | Any entry | Own tenant entries only | 403 |
| Run AI Suggest (Domains) | All DNS events | Own tenant DNS events | 403 |

---

## Page 5 — Support

### 5.1 Angular Component

| Item | Detail |
|------|--------|
| Component class | `Support` |
| File | `ndr-ui/src/pages/admin/support/support.ts` |
| Template | `ndr-ui/src/pages/admin/support/support.html` |
| Stylesheet | `ndr-ui/src/pages/admin/support/support.css` |
| Selector | `app-support` |
| Route | `/admin/support` (standalone link in AdminLayout sidebar) |

**Role behaviour:** The component is role-aware via computed getters. When loaded by a super_admin it shows the "Forwarded Support" inbox — escalated messages from tenant admins and messages from the default tenant. The "Send a Support Request" panel is hidden and only Review, Reply, and Delete actions are available. The Forward button shown to tenant admins is hidden for super_admin.

---

### 5.2 Interfaces

```typescript
// From ndr-ui/src/services/api/api.ts:51
export interface SupportMessage {
  id:              string;
  tenant_id:       string;
  sender_username: string;
  sender_role:     string;
  subject:         string;
  category:        string;
  message:         string;
  status:          string;   // 'open' | 'reviewed' | 'replied' | 'forwarded' | 'deleted' | 'sending' | 'syncing'
  admin_reply:     string;
  replied_by:      string;
  forwarded:       number;   // 0 or 1
  forwarded_by:    string;
  deleted:         number;
  created_at:      string;
  updated_at:      string;
  replied_at:      string;
  forwarded_at:    string;
}

// Local view model — extends SupportMessage with pre-formatted fields
export interface SupportMessageView extends SupportMessage {
  statusLabelText:    string;  // human label from statusLabel()
  formattedCreatedAt: string;
  formattedRepliedAt: string;
  formattedUpdatedAt: string;
}
```

---

### 5.3 Component State

| Property | Type | Initial | Purpose |
|----------|------|---------|---------|
| `messages` | `SupportMessageView[]` | `[]` | Full list of messages shown in the inbox, merged with any local optimistic entries |
| `loading` | `boolean` | `false` | Controls spinner during initial load |
| `error` | `string` | `''` | Inline error banner text |
| `actionMessage` | `string` | `''` | Inline success banner text after an action |
| `subject` | `string` | `''` | New request subject (unused by super_admin — panel hidden) |
| `category` | `string` | `'General'` | New request category (unused by super_admin) |
| `message` | `string` | `''` | New request body (unused by super_admin) |
| `activeReplyId` | `string` | `''` | `id` of the message whose reply composer is currently open; `''` means none |
| `replyDrafts` | `Record<string, string>` | `{}` | Keyed by message `id` — stores draft reply text per message |
| `busyAction` | `{ id: string; action: string } \| null` | `null` | Tracks the in-flight action so buttons show spinner/disabled state |
| `categories` | `string[]` | `['General','Access','Alert Review','Sensor','Incident','Other']` | Dropdown options for new-request category |
| `refreshSub` | `Subscription \| undefined` | — | Timer subscription for 5-second auto-refresh |
| `locallyTrackedUntil` | `Record<string, number>` | `{}` | Maps message `id` to expiry timestamp (ms) for optimistic messages |

---

### 5.4 Computed Getters

| Getter | Returns | Logic |
|--------|---------|-------|
| `user` | `any` | `auth.getUser()` |
| `isTenantAdmin` | `boolean` | `user?.role === 'tenant_admin'` |
| `isSuperAdmin` | `boolean` | `user?.role === 'super_admin' \|\| user?.role === 'admin'` |
| `isManager` | `boolean` | `isTenantAdmin \|\| isSuperAdmin` — true for both admin roles |
| `canSubmitRequest` | `boolean` | `!isManager` — always `false` for super_admin; hides the "Send a Support Request" panel |
| `pageTitle` | `string` | `'Forwarded Support'` for super_admin · `'Tenant Support'` for tenant_admin · `'Support'` for analyst |
| `pageDescription` | `string` | `'Review escalated tenant requests and default-user support messages.'` for super_admin |
| `openCount` | `number` | `messages.filter(m => m.status === 'open').length` |
| `forwardedCount` | `number` | `messages.filter(m => m.forwarded).length` — shown as "Escalated" in the stats strip for super_admin |

---

### 5.5 Angular Functions

#### `ngOnInit()`
Calls `loadSupportMessages()` immediately, then starts a `timer(5000, 5000)` to silently refresh every 5 seconds. Stored in `refreshSub`.

#### `ngOnDestroy()`
Unsubscribes `refreshSub` to stop the auto-refresh timer.

#### `loadSupportMessages(silent = false)`
- If `silent = false`, sets `loading = true` (shows spinner).
- Calls `api.getSupportMessages()` with a 12-second `timeout`.
- On success: calls `mergePendingMessages(messages)` to merge backend response with any locally tracked optimistic entries, assigns to `this.messages`, clears `loading`.
- On error: sets `this.error`, clears `loading`.

#### `reviewMessage(item)`
Delegates to `runMessageAction(item, 'review', () => api.reviewSupportMessage(item.id))`.  
Locally sets `item.status = 'reviewed'` on success via `applyActionLocally`.

#### `deleteMessage(item)`
Delegates to `runMessageAction(item, 'delete', () => api.deleteSupportMessage(item.id))`.  
Locally removes the message from `this.messages` on success via `removeLocalMessage`.

#### `toggleReply(item)`
Toggles `activeReplyId` between `item.id` and `''`. Pre-fills `replyDrafts[item.id]` with `item.admin_reply` if a previous reply exists.

#### `sendReply(item)`
Reads `replyDrafts[item.id]`, validates non-empty, then delegates to `runMessageAction(item, 'reply', () => api.replySupportMessage(item.id, reply))`.  
On success: locally sets `item.status = 'replied'`, `item.admin_reply`, `item.replied_by`, `item.replied_at`, and closes the composer (`activeReplyId = ''`).

#### `isBusy(item, action?)`
Returns `true` if `busyAction.id === item.id` and (if `action` supplied) `busyAction.action === action`. Used to disable buttons and show loading labels.

#### `statusLabel(item)`
Returns a human-readable string from `item.status`:

| Status value | Label |
|---|---|
| `forwarded` (and `item.forwarded == 1`) | `Forwarded` |
| `sending` | `Sending` |
| `syncing` | `Syncing` |
| `reviewed` | `Reviewed` |
| `replied` | `Replied` |
| `deleted` | `Deleted` |
| anything else | `Open` |

#### `formatDate(value)`
Normalises date strings from ClickHouse (space-separated `YYYY-MM-DD HH:MM:SS`) or ISO format to a JavaScript `Date` and calls `.toLocaleString()`. Returns the original string if parsing fails, `'Not yet'` if empty.

#### `trackMessage(index, item)`
Returns `item.id` — used by `*ngFor` `trackBy` to avoid full list re-renders on each refresh.

#### Private helpers

| Method | Purpose |
|--------|---------|
| `runMessageAction(item, action, request, afterSuccess?)` | Sets `busyAction`, clears banners, calls `request()`, handles success/error. On success: calls `applyActionLocally`, sets `actionMessage`, triggers silent reload. |
| `buildLocalMessage(id, subject, category, message, status)` | Builds a `SupportMessage` from local state — used for optimistic inserts in `submitSupportRequest`. Not called by super_admin. |
| `replaceLocalMessage(id, next)` | Swaps a message in `this.messages` by id. |
| `removeLocalMessage(id)` | Removes a message from `this.messages` and deletes its `locallyTrackedUntil` entry. |
| `mergePendingMessages(messages)` | Merges backend response with locally tracked pending/syncing messages. Expires entries older than their `locallyTrackedUntil` timestamp. |
| `applyActionLocally(item, action)` | Immediately reflects the result of an action in `this.messages` before the silent reload arrives, keeping the UI responsive. |
| `enrichMessage(item)` | Wraps a `SupportMessage` into a `SupportMessageView` by pre-computing `statusLabelText` and the three formatted date fields. |

---

### 5.6 HTML Template Behaviour

**Stats strip** — three stat cards always visible:
- Total Messages — `messages.length`
- Open — `openCount`
- Escalated / Forwarded — `forwardedCount` (label is `'Escalated'` for `isSuperAdmin`, `'Forwarded'` otherwise)

**Send a Support Request panel** — `*ngIf="canSubmitRequest"` — hidden for super_admin.

**Support Inbox panel** — always visible. Panel icon shows `ShieldIcon` for managers, `InboxIcon` for analysts.

**Message card actions** — `*ngIf="isManager"` guards the entire action row. For super_admin:
- **Reviewed** button — enabled if message is not already `reviewed`. Calls `reviewMessage(item)`.
- **Reply** button — opens/closes the reply composer. Calls `toggleReply(item)`.
- **Forward** button — `*ngIf="isTenantAdmin"` — **not shown** for super_admin.
- **Delete** button — calls `deleteMessage(item)`. Always available to super_admin for any visible message.

**Reply composer** — shown when `activeReplyId === item.id`. Contains a textarea bound to `replyDrafts[item.id]`, a "Send Reply" button (calls `sendReply(item)`), and a Cancel button.

**Status badge classes:**
| Class | Applied when |
|-------|-------------|
| `badge-replied` | `item.status === 'replied'` |
| `badge-forwarded` | `item.forwarded` is truthy |
| `badge-pending` | status is `'sending'` or `'syncing'` |
| `badge-reviewed` | `item.status === 'reviewed'` |

---

### 5.7 Rust Access Control

#### `can_manage_support_message(claims, tenant_id, forwarded)` — line 6440

The shared authorisation check used by review, reply, and delete handlers:

```rust
fn can_manage_support_message(claims: &AuthClaims, tenant_id: &str, forwarded: u8) -> bool {
    if claims.role == "super_admin" || claims.role == "admin" {
        return forwarded == 1 || tenant_id == "default";
    }
    if claims.role == "tenant_admin" {
        return claims.tenant_id == tenant_id;
    }
    false
}
```

**Super_admin can manage a message only if** it was forwarded by a tenant admin (`forwarded == 1`) **or** it originated from the `default` tenant. This matches exactly what `get_support_messages_for_super_admin()` returns — super_admin never sees messages they cannot act on.

---

### 5.8 Rust API Handlers

#### `get_support_messages` — line 6450
`GET /api/support/messages`

Routes to one of three ClickHouse queries based on role:

| Role | Query called | Scope |
|------|-------------|-------|
| `super_admin` / `admin` | `get_support_messages_for_super_admin()` | All forwarded messages + all messages from `default` tenant |
| `tenant_admin` | `get_support_messages_for_tenant(tenant_id)` | All messages belonging to their tenant |
| analyst / viewer | `get_support_messages_for_user(tenant_id, sub)` | Only messages sent by that specific user |

Timeout: 8 seconds. Returns `{ status, messages: [...] }`.

#### `review_support_message` — line 6545
`POST /api/support/messages/:id/review`

1. Extracts JWT claims.
2. Fetches `scope = get_support_message_scope(id)` → `(tenant_id, sender, forwarded)`.
3. Calls `can_manage_support_message` — returns 403 if not authorised.
4. Calls `ch_storage.update_support_status(id, "reviewed")`.
5. Returns `{ status:"ok", message:"Support request marked reviewed" }`.

#### `reply_support_message` — line 6584
`POST /api/support/messages/:id/reply`  
Body: `{ "reply": "..." }`

1. Validates `reply` field is non-empty.
2. Fetches scope, checks `can_manage_support_message`.
3. Calls `ch_storage.reply_support_message(id, reply, claims.sub, "replied")` — stores reply text, replied_by, replied_at, sets status to `replied`.
4. Returns `{ status:"ok", message:"Reply sent" }`.

#### `forward_support_message` — line 6629
`POST /api/support/messages/:id/forward`

**Blocked for super_admin** — line 6639 explicitly checks `claims.role != "tenant_admin"` and returns 403 with `"Only tenant admins can forward support requests"`. The Forward button is also hidden in the HTML via `*ngIf="isTenantAdmin"`.

#### `delete_support_message_api` — line 6672
`DELETE /api/support/messages/:id`

1. Fetches scope, checks `can_manage_support_message`.
2. Calls `ch_storage.delete_support_message(id)` — hard delete from ClickHouse.
3. Returns `{ status:"ok", message:"Support request deleted" }`.

---

### 5.9 Angular API Service Methods

| Method | Angular call | URL | Notes |
|--------|-------------|-----|-------|
| `getSupportMessages()` | `GET` | `/api/support/messages` | Returns `SupportMessage[]` unwrapped from `messages` field; throws if `status != 'ok'` |
| `reviewSupportMessage(id)` | `POST` | `/api/support/messages/:id/review` | Empty body `{}` |
| `replySupportMessage(id, reply)` | `POST` | `/api/support/messages/:id/reply` | Body `{ reply }` |
| `deleteSupportMessage(id)` | `DELETE` | `/api/support/messages/:id` | No body |
| `forwardSupportMessage(id)` | `POST` | `/api/support/messages/:id/forward` | Not called by super_admin |

All calls use a 12-second `timeout` applied at the component level via RxJS `timeout` operator.

---

### 5.10 Super Admin Specific Behaviour Summary

| Aspect | Behaviour |
|--------|-----------|
| Page title | "Forwarded Support" |
| Page description | "Review escalated tenant requests and default-user support messages." |
| Messages visible | Forwarded messages from all tenants + all messages from `default` tenant |
| Can submit new request | No — `canSubmitRequest = false`, panel hidden |
| Can review | Yes |
| Can reply | Yes |
| Can forward | No — button hidden + Rust 403 |
| Can delete | Yes — any visible message |
| Stats strip third card label | "Escalated" (not "Forwarded") |
| Auto-refresh | Every 5 seconds (silent) |
| Timeout per API call | 12 seconds |

---

## Error Handling

| Scenario | HTTP | Backend message | Angular reaction |
|----------|------|-----------------|-----------------|
| Non-super_admin calls AI Providers endpoints | 403 | `require_super_admin` | — (page never loads for non-admins) |
| Save provider with empty name | 200 | `{ status:"error", error:"name is required" }` | `providerError` shown |
| Test provider with no API key in DB | 200 | `{ status:"error", error:"No API key found..." }` | `testProviderResult = "✗ ..."` |
| Trusted domain add: analyst role | 200 | `{ error:"Forbidden" }` | — |
| AI Suggest: no AI configured | 200 | `{ ai_available:false }` | Hides AI Suggest button |
| SMTP save: masked password submitted | 200 | `{ status:"ok" }` (password not overwritten) | Silent — correct behavior |

---

*Powered by PromaSecure*
