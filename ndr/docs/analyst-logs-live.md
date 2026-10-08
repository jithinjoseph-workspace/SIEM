# Analyst — Logs & Live Stream

Route: `/analyst/logs`

The Logs page hosts two tabs in a single route: **Network Logs** (historical + real-time buffer) and **Live Stream** (raw real-time feed). The Live Stream tab embeds `<app-live>` as a standalone child component.

---

## 1. Network Logs Tab

**Component:** `ndr-ui/src/pages/analyst/logs/logs.ts`  
**Template:** `ndr-ui/src/pages/analyst/logs/logs.html`

### Layout

```
┌─────────────────────────────────────────────────────────────────┐
│ Eyebrow: "Network Telemetry"  h2: "Network Logs"                │
│ Subtitle: "Deep packet inspection — Agent-Z & Agent-S"          │
│ Status strip: Visible {n} | Buffer {n} | Sensor pill(s)*        │
│ Actions: [Search] [Refresh] [Time Range ▾] [Format ▾] [Export] │
├─────────────────────────────────────────────────────────────────┤
│ While loading:  Terminal icon pulse + "Loading network events"  │
│                 + "Fetching latest captured traffic…"           │
├─────────────────────────────────────────────────────────────────┤
│ Terminal panel  (HUD corner brackets + scan sweep)              │
│  topbar: "NDR_EVENTS / LIVE STREAM"        "LIVE" pill          │
│  Table: Time | Source | Proto | Source IP | Dest IP | Event     │
│  Empty state: "No matching logs"                                │
│               "Try a different IP, protocol, or source filter." │
│  Footer: {n}/{n} entries            ● WebSocket connected       │
└─────────────────────────────────────────────────────────────────┘
* Sensor pills only rendered when sensorIds.length > 0

[Live Stream tab]  →  embeds <app-live>
```

### State

| Property | Type | Default | Purpose |
|---|---|---|---|
| `logs` | `any[]` | `[]` | Combined buffer — historical + real-time (max 200) |
| `filteredLogs` | `any[]` | `[]` | Display slice after filter (max 100) |
| `searchText` | `string` | `''` | Text filter applied across src/dst/proto/source |
| `timeRange` | `number` | `24` | Hours for historical load (24 = 1 day, 168 = 7 days) |
| `exportFormat` | `string` | `'csv'` | `'csv'` / `'json'` / `'pdf'` |
| `activeTab` | `string` | `'logs'` | `'logs'` or `'live'` |
| `loading` | `boolean` | `true` | Drives loading state panel; set false after `loadLogs()` resolves |
| `totalCount` | `number` | `0` | Raw count of historical results (`data.length`); not displayed in template |
| `sensorIds` | `string[]` | `[]` | Sensor IDs from JWT via `auth.getSensorIds()`; drives sensor pills |

### `ngOnInit` Order

```
1. sensorIds = auth.getSensorIds()
2. route.queryParams.subscribe → set searchText + onSearch() if ?search= present
3. loadLogs()                  ← historical load fires BEFORE WebSocket subscription
4. ws.events$.subscribe(...)   ← real-time subscription
```

### Dual Data Source

The Logs page pulls data from two sources simultaneously.

#### WebSocket (real-time)

Subscribes to `ws.events$`. `events$` is a filtered pipe of the shared `messages$` Subject — it only passes messages whose `type` is `'agent-z'` or `'agent-s'`, so rule hits and alerts never appear in the Logs buffer.

Each incoming message is normalized to:

```ts
{
  ts:         evtTime,                        // toLocaleTimeString('en-US', h12, with seconds)
  proto:      event.proto?.toUpperCase() || '',
  src:        event.src || '',                // field is 'src', not 'src_ip'
  dst:        event.dst || '',                // field is 'dst', not 'dst_ip'
  source:     event.type || '',              // 'agent-z' | 'agent-s'
  action:     'ALLOW',                       // same literal as historical events
  event_type: normalizeEventType(event.event_type)
}
```

`evtTime` derivation: if `event.ts` is truthy (Unix seconds), `new Date(event.ts * 1000).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })`; otherwise `new Date().toLocaleTimeString(...)` (current time).

Prepended to `logs[]` with `unshift`; buffer capped at 200 (oldest popped). After each push, `scheduleUpdate()` is called to trigger a deferred `applyFilter()`.

#### Historical API

`loadLogs()` fires on `ngOnInit` and on Refresh button click and on time-range change. Calls `api.getRecentEvents(timeRange)` → `GET /api/events?hours={N}`. Each result is mapped to:

```ts
{
  ts:         new Date(e.timestamp * 1000).toLocaleTimeString('en-US', {
                hour: '2-digit', minute: '2-digit', second: '2-digit'
              }),                             // Unix seconds × 1000
  proto:      e.proto?.toUpperCase() || '',
  src:        e.src_ip || '',
  dst:        e.dst_ip || '',
  source:     e.source || '',
  action:     'ALLOW',
  event_type: normalizeEventType(e.event_type)
}
```

Historical results **replace** `logs[]` (not merged). Sets `totalCount = data.length`. Calls `applyFilter()` then sets `loading = false`.

### Filtering Pipeline (`applyFilter`)

`MAX_DISPLAY = 100` — display always capped at 100 entries regardless of buffer size.

```
logs[]  (up to 200)
  │
  ├─ hasEndpoint filter
  │    src = l.src?.trim()
  │    dst = l.dst?.trim()
  │    keep only: (src && src !== '-') || (dst && dst !== '-')
  │
  ├─ text search (if searchText non-empty)
  │    lowercased match across: src, dst, proto, source
  │
  └─ .slice(0, 100)
       → filteredLogs[]
```

`applyFilter()` is called by:
- WebSocket incoming event (via `scheduleUpdate()`)
- `loadLogs()` completion (direct call)
- `onSearch()` (search input change, direct call)
- Refresh button (calls `loadLogs()` which calls `applyFilter()`)
- Time range change (calls `onTimeRangeChange()` → `loadLogs()`)

### `scheduleUpdate()` — Dedup Pattern

Prevents multiple rapid DOM updates when WebSocket events arrive in bursts:

```ts
private updateScheduled = false;

private scheduleUpdate() {
  if (this.updateScheduled) return;
  this.updateScheduled = true;
  setTimeout(() => {
    this.applyFilter();
    this.cdr.detectChanges();
    this.updateScheduled = false;
  }, 0);
}
```

A single `setTimeout(0)` merges all synchronous pushes within the same tick into one filter+render pass. Flag name is `updateScheduled` (not `updatePending`).

### `normalizeEventType(t)`

Private method:

```ts
private normalizeEventType(t: string | null | undefined): string {
  return (t && t !== '-') ? t : 'conn';
}
```

Returns `t` if truthy and not a dash, otherwise falls back to `'conn'`.

### `evtSlug(t)`

Private method, used to generate CSS class names for event-type badges:

```ts
private evtSlug(t: string): string {
  return (t || 'conn').toLowerCase().replace(/[^a-z0-9]/g, '') || 'conn';
}
```

Produces e.g. `'dns'`, `'http'`, `'conn'`, `'ssh'`.

### Template Helper Methods

| Method | Returns |
|---|---|
| `getRowClass(log)` | `'log-grid log-row evt-{evtSlug(log.event_type)}'` |
| `getEventBadgeClass(eventType)` | `'event-badge evt-{evtSlug(eventType)}'` |
| `getSourceClass(source)` | see table below |
| `getProtoClass(proto)` | `'proto-badge proto-{proto.toLowerCase()}'` |

`getSourceClass(source)` — full class strings returned:

| source (lowercased) | Returned class string |
|---|---|
| `'agent-s'` | `'source-badge src-s'` |
| `'agent-z'` | `'source-badge src-z'` |
| anything else | `'source-badge'` |

### Source Badge Label

Template inline logic for the label text:

| `log.source` | Label displayed |
|---|---|
| `'agent-z'` | `AGENT-Z` |
| `'agent-s'` | `AGENT-S` |
| anything else | `(log.source \|\| '-').toUpperCase()` |

### Time Range Selector

`<select>` maps UI label to numeric hours stored in `timeRange`. Changing calls `onTimeRangeChange()` → `loadLogs()`.

| UI label (actual template text) | `timeRange` value |
|---|---|
| `1 Day` | `24` |
| `7 Days` | `168` |

### Export

```
[Export] → api.exportNetworkLogs(exportFormat, timeRange)
         → GET /api/export-logs?format={format}&hours={hours}
         → response blob + Content-Disposition: attachment; filename="..."
             filename extracted via /filename="(.+)"/ regex; falls back to ndr-logs.{format}
         → browser download via synthetic <a> click + URL.createObjectURL
```

The API method is `void` — it subscribes internally and handles the download. Supported formats: `csv`, `json`, `pdf`.

### Query Parameter Support

The route accepts a `search` query parameter via `ActivatedRoute.queryParams`. On `ngOnInit`, if `?search=...` is present, `searchText` is set and `onSearch()` is called immediately — enabling deep-link navigation from other pages (e.g. clicking an IP on the Network Map navigates to `/analyst/logs?search={ip}`).

### `trackByLog`

Composite key for `ngFor` performance:

```ts
trackByLog(_: number, log: any): string {
  return `${log.ts}|${log.src}|${log.dst}|${log.proto}`;
}
```

---

## 2. Live Stream Component

**Component:** `ndr-ui/src/pages/analyst/live/live.ts`  
**Template:** `ndr-ui/src/pages/analyst/live/live.html`  
**Selector:** `<app-live>`

Standalone component — no HTTP calls, no routing, WebSocket only. Embedded inside the Logs page's Live Stream tab.

### Layout

```
┌─────────────────────────────────────────────────────────────────┐
│ Radio● "Real-Time Monitoring"   h2 "Live Event Stream"          │
│ Subtitle: "Agent-Z and Agent-S telemetry over active WebSocket."│
│ [Events {n}] [Hits {n}]  [Clear]                                │
│ Status: ● Stream active | Buffer 100 msg limit | Displayed {n}  │
├─────────────────────────────────────────────────────────────────┤
│ Stream panel (HUD corners + scan line)                          │
│  topbar: Wifi icon + "INCOMING EVENTS"              "LIVE" pill │
│  Column header (when messages.length > 0):                      │
│    Time | Source | Direction | Proto | Event | Detail           │
│  Empty state: Activity icon + "Awaiting events"                 │
│               "WebSocket connected — events appear here…"       │
│  Stream rows (newest first)                                     │
│  Footer: Activity icon + "{n} messages in buffer"               │
│          [Auto-scroll: ON/OFF]                                  │
└─────────────────────────────────────────────────────────────────┘
```

### State

| Property | Type | Default |
|---|---|---|
| `messages` | `any[]` | `[]` |
| `eventCount` | `number` | `0` |
| `hitCount` | `number` | `0` |
| `autoScroll` | `boolean` | `true` |
| `updateScheduled` | `boolean` | `false` | (private, dedup flag) |

`@ViewChild('streamContainer')` → `ElementRef`; `#streamContainer` is on the `div.stream-list` container. Used for `scrollTop = 0` auto-scroll.

### WebSocket Subscription

Subscribes to `ws.messages$` on `ngOnInit` — the unfiltered main Subject, so all message types arrive.

Ignored types: `agent_status` and `interfaces` are caught at the top of the handler. All other unrecognized types (beyond the four handled types below) also hit `else { return; }` and are silently discarded.

### Message Type Handlers

| `msg.type` | `kind` | `label` | `event_type` | `extra` | Counter |
|---|---|---|---|---|---|
| `'agent-z'` | `'zeek'` | `'AGENT-Z'` | `(msg.service \|\| msg.conn_state \|\| 'conn').toUpperCase()` | `msg.conn_state \|\| ''` | `eventCount++` |
| `'agent-s'` | `'suricata'` | `'AGENT-S'` | `(msg.event_type \|\| 'flow').toUpperCase()` | `''` | `eventCount++` |
| `'hit'` | `'hit'` | `'HIT'` | `(msg.severity \|\| 'medium').toUpperCase()` | `msg.tags?.join(' · ') \|\| ''` | `hitCount++` |
| `'alert'` | `'alert'` | `'ALERT'` | `'ALERT'` | `msg.description \|\| msg.rule \|\| 'Rule triggered'` | `hitCount++` |

All four types also get these base fields built first:

```ts
{
  timestamp: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
  src:   msg.src || '',
  dst:   msg.dst || '',
  proto: (msg.proto || '').toUpperCase(),
  raw:   msg,
}
```

Note the field is `timestamp` (not `ts`).

`hit` entries additionally carry:

```ts
entry.score = msg.score != null ? Math.round(msg.score) : null;
entry.cid   = msg.cid || '';
```

### Buffer Management and `scheduleUpdate()`

```ts
this.messages.unshift(entry);
if (this.messages.length > 100) this.messages.pop();
this.scheduleUpdate();   // deferred cdr.detectChanges() only (no applyFilter)

if (this.autoScroll && this.streamContainer) {
  this.streamContainer.nativeElement.scrollTop = 0;
}
```

`scheduleUpdate()` in Live defers only `cdr.detectChanges()` (no filter step). The auto-scroll happens synchronously in the same subscription tick, before change detection.

```ts
private scheduleUpdate() {
  if (this.updateScheduled) return;
  this.updateScheduled = true;
  setTimeout(() => {
    this.cdr.detectChanges();
    this.updateScheduled = false;
  }, 0);
}
```

### `getEventBadgeClass(entry)`

Takes the full entry object (not a string):

```ts
getEventBadgeClass(entry: any): string {
  const t = (entry.event_type || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  return `evt-badge evt-${t}`;
}
```

### Stream Row Structure

Each row has CSS class `'stream-row kind-{msg.kind}'` (e.g. `kind-hit`, `kind-alert`, `kind-zeek`).

| Column | Template |
|---|---|
| Time | `msg.timestamp` |
| Source | Badge with class `'source-badge src-{msg.kind}'`, text = `msg.label` |
| Direction | `{msg.src \|\| '–'} → {msg.dst \|\| '–'}` |
| Proto | Proto badge if `msg.proto` truthy, else `–` |
| Event | `getEventBadgeClass(msg)` badge, text = `msg.event_type \|\| '–'` |
| Detail | If `score != null`: score chip + extra text. Else: extra text only. |

### `clearMessages()`

```ts
clearMessages() {
  this.messages = [];
  this.eventCount = 0;
  this.hitCount = 0;
  this.cdr.detectChanges();   // immediate sync update
}
```

### Auto-scroll Toggle

Footer button: `(click)="autoScroll = !autoScroll"` with class `.on` when active. Label: `ON` / `OFF`. Auto-scroll acts on the next incoming message — toggling on does not jump the scroll position immediately.

---

## 3. WebSocket Service

**Service:** `ndr-ui/src/services/websocket/websocket.ts`

Singleton (`providedIn: 'root'`). Maintains a single native `WebSocket` to `ws[s]://{host}/ws`.

### Connection

```
connect()
  ├─ Guard: if socket OPEN or CONNECTING → return (no double-connect)
  ├─ Cancel any pending reconnect timer
  ├─ Close stale socket (null out onclose/onerror first to suppress spurious reconnect)
  ├─ Start batch flush interval (300ms) outside NgZone — only if not already running
  └─ new WebSocket(`ws[s]://{host}/ws`)
       onopen   → zone.run (no-op; cookie sent in HTTP upgrade, no auth message needed)
       onmessage → see below
       onerror  → console.error
       onclose  → set socket=null, reconnect after 3 000ms via reconnectTimer
```

If `new WebSocket(...)` throws, the same 3-second reconnect fires.

Authentication is handled via the session cookie (same-origin, `SameSite=Strict`) sent automatically in the WebSocket upgrade HTTP request. No application-level auth handshake.

### Message Routing

High-volume types (`hit`, `agent-s`, `agent-z`) are queued outside NgZone in `pendingBatch[]` and flushed in batches every **300ms** via `flushBatch()`. This prevents Angular's change-detection cycle from firing for every individual network packet.

All other types (`agent_status`, `interfaces`, `telemetry`, `alert`, `force_logout`, etc.) enter NgZone immediately and are passed to `messages$` synchronously.

`flushBatch()`: splices the entire pending batch at once, then inside `zone.run()` calls `messages$.next(data)` for each. For `hit` entries, also `unshift`s into `hitsHistory[]` (max 100). After the batch, if any `hit` was present, updates `continuousHits$` and debounces a `sessionStorage` write by 250ms (via `updateTimeout`).

### Observables

| Observable | Type | Description |
|---|---|---|
| `messages$` | `Subject<any>` | All messages — both immediate and batch-flushed |
| `events$` | filtered pipe of `messages$` | Only `agent-z` and `agent-s` types — used by Logs |
| `agentStatus$` | filtered pipe of `messages$` | Only `agent_status` type |
| `interfaces$` | filtered pipe of `messages$` | Only `interfaces` type |
| `hits$` | filtered pipe of `messages$` | Only `hit` type |
| `telemetry$` | filtered pipe of `messages$` | Only `telemetry` type |
| `lastAgentStatus$` | `BehaviorSubject<any>` | Latest `agent_status` payload |
| `lastInterfaces$` | `BehaviorSubject<any>` | Latest `interfaces` payload |
| `lastTelemetry$` | `BehaviorSubject<any>` | Latest `telemetry` payload |
| `continuousHits$` | `BehaviorSubject<any[]>` | Rolling last-100 hit history (persisted to sessionStorage) |

**Key distinction:** The Logs page subscribes to `events$` (only Agent-Z/Agent-S telemetry). The Live component subscribes to `messages$` (every type).

### `continuousHits$` — Hit History

`hit` events in the batch are `unshift`ed into `hitsHistory[]` (max 100, oldest popped). After each batch containing hits:
1. `continuousHits$.next([...hitsHistory])` — emitted as a new reference
2. `sessionStorage.setItem('ndr_live_hits', JSON.stringify(hitsHistory))` — debounced 250ms via `updateTimeout`

On service construction, `sessionStorage` is read to restore history across Angular page navigation (SPA route changes).

### `force_logout` Handler

Runs inside the immediate (`zone.run`) path — not batched. When received:
1. Checks `data.target_username` — only kicks the current user if it matches, or if no target specified
2. Calls `disconnect()` (clears timers, batch, socket)
3. `localStorage.removeItem('ndr_user')` + `localStorage.removeItem('ndr_token')`
4. `sessionStorage.clear()`
5. `fetch('/api/auth/logout', { method: 'POST', credentials: 'include' })` — expires httpOnly session cookie server-side
6. `.finally(() => { window.location.href = '/login'; })` — redirect after cookie expiry

### `disconnect()`

Full teardown — clears all timers and state:

```ts
disconnect() {
  clearTimeout(reconnectTimer)   → reconnectTimer = null
  clearTimeout(updateTimeout)    → updateTimeout = null     // sessionStorage debounce
  clearInterval(flushTimer)      → flushTimer = null        // stops 300ms batch flush
  pendingBatch = []                                         // drop queued high-volume events
  socket.onclose = null
  socket.onerror = null
  socket.close()
  socket = null
}
```

### `send(data)`

Sends a JSON-serialized message to the server when the socket is `OPEN`:

```ts
send(data: any) {
  if (this.socket && this.socket.readyState === WebSocket.OPEN) {
    this.socket.send(JSON.stringify(data));
  }
}
```

Currently not called by any component (available for future use).

---

## API Reference

| Method | HTTP | Endpoint | Notes |
|---|---|---|---|
| `getRecentEvents(hours?)` | GET | `/api/events?hours={N}` | `hours` omitted → no `?hours=` param (backend default applies) |
| `exportNetworkLogs(format, hours)` | GET | `/api/export-logs?format={format}&hours={hours}` | Returns blob; filename from `Content-Disposition`; falls back to `ndr-logs.{format}` |

---

## Data Flow Summary

```
WebSocket /ws
  │
  ├── HIGH VOLUME (agent-z, agent-s, hit)
  │       queued outside NgZone → pendingBatch[]
  │       flushed every 300ms via flushBatch()
  │       └─► messages$.next() for each item in batch
  │
  └── ALL OTHERS (alert, telemetry, force_logout, etc.)
          zone.run() immediately → messages$.next()


                    messages$  (Subject<any>)
                         │
              ┌──────────┤
              │          │
          events$     (all types)
    (agent-z/agent-s
      only; filtered)
              │          │
        Logs           Live
       component      component
     ws.events$      ws.messages$
     normalize →     build entry →
     logs[]          messages[]
     max buf: 200    max buf: 100
     display: 100

     + scheduleUpdate()      + scheduleUpdate()
       (applyFilter +          (detectChanges only)
        detectChanges)        + autoScroll to top
                                (sync, same tick)


GET /api/events?hours={N}
  └──► loadLogs() → replaces logs[] → applyFilter() → loading=false


GET /api/export-logs?format={f}&hours={h}
  └──► blob → createObjectURL → synthetic <a> click → browser download
```
