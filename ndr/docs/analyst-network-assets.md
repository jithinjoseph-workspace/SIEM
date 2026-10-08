# Analyst — Network Map & Assets

---

## Network Map

**Route:** `/analyst/network-map`  
**Angular component:** `ndr-ui/src/pages/analyst/network-map/network-map.ts`  
**Template:** `ndr-ui/src/pages/analyst/network-map/network-map.html`  
**Styles:** `ndr-ui/src/pages/analyst/network-map/network-map.css`  
**Sub-services:** `network-map/services/network-data.service.ts`, `network-map/services/network-physics.service.ts`  
**Services:** `Api`, `ArkimeService`, `AuthService`, `ChangeDetectorRef`  
**Shared component:** `<app-device-drawer>`

### Purpose

Interactive D3.js force-directed graph of host communication observed in the **last 1 hour** of traffic. Nodes are network hosts (internal and external); edges are observed connections. Supports cluster expansion, device focus mode, search, and node filtering.

---

### Component State

| Property | Type | Description |
|---|---|---|
| `nodeCount` | `number` | Total nodes in the current graph (from API `total_nodes`) |
| `edgeCount` | `number` | Total edges in the current graph (from API `total_edges`) |
| `viewState` | `'loading' \| 'loaded' \| 'error' \| 'empty'` | Controls which state overlay is shown |
| `errorMessage` | `string` | Error text shown in the error overlay |
| `selectedNode` | `any` | Node currently selected in the D3 graph — passed to `<app-device-drawer>` |
| `lastUpdated` | `string` | Time of last successful load (locale time: HH:MM:SS AM/PM) |
| `nodesData` | `any[]` | Live D3 node array (mutated in-place to preserve x/y positions) |
| `edgesData` | `any[]` | Live D3 edge array |
| `searchQuery` | `string` | Current search input value |
| `searchDebounce` | `any` | `setTimeout` handle for 300ms search debounce |
| `isSearchActive` | `boolean` | True when a non-empty search is applied |
| `searchMatches` | `Set<string>` | Node IDs that match the current search |
| `focusMode` | `boolean` | True when device focus mode is active |
| `activeFilter` | `string` | Active node type filter: `'all' \| 'internal' \| 'external' \| 'threat' \| 'traffic'` |
| `selectedPathNode` | `any` | Node selected via the Device Selector Bar chip — triggers focus mode |
| `sensorIds` | `string[]` | Sensor IDs from JWT (read on init; backend scopes API responses) |
| `zoomBehavior` | `any` | D3 zoom behaviour instance |

---

### Getters

| Getter | Returns | Description |
|---|---|---|
| `internalNodes` | `any[]` | Internal non-cluster nodes; sorted: router/gateway/firewall/switch first, then by `connections` desc |
| `gatewayNode` | `any` | First explicit router/gateway/firewall node; fallback: most-connected internal node |
| `selectedPathExternals` | `any[]` | Up to 10 external nodes connected to `selectedPathNode` (via `edgesData`), sorted by connections desc |
| `internalCount` | `number` | Count of `is_internal && !threat` nodes |
| `externalCount` | `number` | Count of `!is_internal && !threat` nodes |
| `threatCount` | `number` | Count of nodes where `n.threat === true` |
| `trafficCount` | `number` | Count of nodes where `connections > 5` |

---

### Methods

**`ngOnInit()`** — reads `sensorIds` from JWT, calls `loadMap()`.

**`ngOnDestroy()`** — calls `physics.destroy()` (stops D3 simulation), clears `searchDebounce` timeout.

**`loadMap(resetCamera?)`** — calls `dataService.loadMap()` → `GET /api/network-map?mode=top&limit=25`. Preserves D3 x/y/vx/vy for any node already in `nodesData` (prevents graph from reshuffling on refresh). Updates `nodesData`, `edgesData`, `nodeCount`, `edgeCount`, `viewState`, `lastUpdated`. Restores `selectedNode` to the newly loaded version of the same node (by ID). Calls `renderGraph()` after a 100ms delay; if `resetCamera=true`, calls `resetCamera()` another 50ms later.

**`loadFocusMode(ip)`** — calls `dataService.loadFocusMode(ip)` → `GET /api/network-map/node/{ip}`. Same position-preservation pattern as `loadMap`. After 100ms delay: calls `renderGraph(nodes, edges, isClusterExpand=true)` (hot update — existing nodes keep positions); then zooms to the focused node at 1.2× scale, or resets camera if the node has no coordinates yet.

**`expandCluster(clusterNode)`** — calls `dataService.expandCluster()` → `GET /api/network-map` (no params). Freezes the cluster's current `x/y` as `anchorX/anchorY` before any data change. Replaces the cluster node with its `member_ips` as individual nodes (all seeded at `anchorX/anchorY`). Existing nodes keep their positions. Calls `renderGraph(nodes, edges, isClusterExpand=true)` for a hot update. Zooms to anchor at 0.75× scale after 80ms.

**`selectPathNode(node)`** — sets `selectedPathNode`, `selectedNode`, `focusMode=true`, calls `loadFocusMode(node.id)`.

**`exitDeviceFocus()`** — clears `selectedPathNode`, sets `focusMode=false`, calls `loadMap(true)` (loads full map and resets camera).

**`clearSelection()`** — clears `selectedNode`, sets `focusMode=false`, removes `is-selected` D3 CSS class from all nodes, calls `applyFocus()` (no-op).

**`applyFocus()`** — legacy method, now a complete no-op. Comment: "Legacy local focus behavior can be skipped since we now fetch the sub-graph". Called by `clearSelection()`.

**`toggleFocus()`** — if entering focus and `selectedNode` exists: calls `loadFocusMode(selectedNode.id)`; if leaving: calls `loadMap(true)`.

**`setFilter(filter)`** — sets `activeFilter`; transitions all `g.topology-node` elements to full opacity (1) or near-invisible (0.08) based on match. Edge opacity by filter:

| Filter | Matching edges | Non-matching edges |
|---|---|---|
| `all` | 1 | 1 |
| `internal` | 0.5 | 0.04 |
| `external` | 0.5 | 0.04 |
| `threat` | **0.8** | 0.04 |
| `traffic` | **1** | 0.04 |

Transition duration: 220ms. Edge labels (`labelsLayer`) are not affected by `setFilter` (only by search).

**`onSearchChange(event)`** — debounced 300ms. Two-phase:
1. **Client-side instant match** — searches `id`, `label`, `active_ip`, `mac`, `ip_history` (JSON-parsed array of `{ip}`), `primary_domain`, `all_domains[]`, `member_ips[]`; updates `searchMatches`; calls `renderGraph()` immediately for visual feedback.
2. **Server-side deep search** — `GET /api/network-map/search?q={query}` → returns node ID array; merges new IDs into `searchMatches`; if a matched ID is inside a cluster's `member_ips`, also marks the cluster as a match; auto-expands clusters containing a match; zooms to the first result at 2× scale.

When `searchQuery` is cleared: resets `isSearchActive`, clears `searchMatches`, re-renders graph at full opacity.

**`getDrawerIcon(node)`** (NetworkMap version — uses `node?.is_internal`, not RFC-1918) — resolution order: cluster→`Users`, laptop→`Laptop`, desktop→`Monitor`, phone/mobile→`Smartphone`, tablet→`Tablet`, iot→`Cpu`, printer→`Printer`, tv/media→`Tv`, server→`Server`, router/gateway/firewall/switch→`Router`; then `is_internal` checked → `Router`; then `threat` checked → `TriangleAlert`; else `Globe`. **`is_internal` check precedes `threat`**: internal threat nodes return `Router`, not `TriangleAlert`. (`HelpCircle` is imported but unreachable.)

**`getNodeKindLabel(node)`** — human-readable node kind string: threat→`'Threat Indicator'`, domain type→`'External Domain'`, known type (not unknown/external)→type capitalized, internal→`'Internal Host'`, else→`'External Server'`.

**`getNodeTypeClass(node)`** — CSS class: threat→`'threat'`, internal→`'internal'`, else→`'external'`. Applied as part of each `g.topology-node`'s class string.

**`isIPAddress(val)`** — returns true if val matches IPv4 pattern `/^\d{1,3}(\.\d{1,3}){3}$/` or contains `':'` (IPv6). Used in the Network Path Strip to decide favicon vs globe SVG for external destinations.

**`zoomToNode(node, scale=2)`** — D3 zoom transition (800ms) centering on node.x/y at the given scale, relative to SVG viewport center.

**`resetCamera()`** — auto-scales based on `nodeCount`: >50 → 0.3×, >20 → 0.5×, else → 0.8×; 750ms transition.

**`renderGraph(nodes, edges, isClusterExpand?)`** — D3 data join on three layers. On first call: creates `<defs>` (glow filter, arrow marker), creates `g.main-container`, sets up D3 zoom (scale extent 0.1–8; adds `zoomed-out` class when scale < 0.6). On subsequent calls: updates existing DOM via D3 join (enter/update/exit). Two simulation paths:
- `isClusterExpand=false` → `physics.initSimulation()` — full simulation restart (cold path)
- `isClusterExpand=true` → `physics.updateSimulation()` — hot update; existing nodes barely move, new nodes settle from seeded position (alpha 0.25)

---

### D3 Node Visual

Each node is a `g.topology-node` group:

| Element | Details |
|---|---|
| `<circle>` | Radius: base (cluster 24, internal 20, external 16) + `min(log(connections+1)×3, 15)`. Fill: threat→`#2b1214`, internal→`#0c2a2c`, external→`#101c35`. Stroke: threat→`#ff716a`, internal→`#69f6b8`, external→`#7ca3ff`. Glow filter on internal nodes. |
| `<path>` (icon) | SVG path from `DEVICE_PATHS` (15 keys); hidden when `hasFavicon()` returns true |
| `<image>` (favicon) | `/favicon-proxy?...&url=http://{domain}&size=64`; falls back to `<path>` on `error` event |
| Label (primary) | `label \|\| id`; truncated to 18 chars + `...` if over 20 chars |
| Label (secondary) | `type` or `is_internal ? 'internal' : 'external'` |
| Connection badge | Top-right; shows `connections` count; only when `connections > 0` |

**`getDomain(node)`** — extracts and validates a domain string from `node.label`. Returns `''` (falsy) on any rejection:
1. Takes `String(node.label).split(' ')[0]` — first word of the label
2. Rejects if contains `/` or `:`
3. Rejects plain IPv4 addresses (`/^\d{1,3}(\.\d{1,3}){3}$/`)
4. Validates against strict hostname regex: `(?=.{1,253}$)([a-zA-Z0-9][...]{0,61}[a-zA-Z0-9]?\.)+[A-Za-z]{2,63}`
5. Rejects consecutive dots (`..`)
6. Returns lowercased domain

**`hasFavicon(node)`** — calls `getDomain(node)` first; returns false if that returns falsy. Then additionally rejects:
- `_` prefix (mDNS service names)
- `.arpa` or `.local` suffix (reverse DNS / link-local)
- `._tcp`, `._udp`, or `._sub` substrings
- No `.` in result, or contains spaces

Returns true only if: `node.type === 'domain'` OR (`!node.is_internal && node.type !== 'cluster' && node.label && node.label !== node.id`).

**`getNodeIconPath(node)`** — device type → `DEVICE_PATHS` key: cluster→`cluster`, threat→`DEVICE_PATHS['unknown']` (**key does not exist** → returns `undefined`; D3 path element renders nothing visible), `phone`/`mobile`→`phone`, `tv`/`media`→`tv`, `router`/`gateway`/`firewall`/`switch`→`router`. Then checks `node.type` directly in `DEVICE_PATHS` (covers `laptop`, `desktop`, `server`, `printer`, `iot`). Internal nodes without a matching type default to `router` path. Label-based fallbacks: `github`, `youtube`/`googlevideo`→`youtube`, `apple`/`icloud`/`mzstatic`→`apple`, `aws`/`amazonaws`/`cloudfront`→`cloud`, `google`→`cloud`. Final fallback: `globe`.

---

### D3 Edge Visual

| Property | Value |
|---|---|
| Stroke color | `log(connections+1) > 3` → `#f8a01080` (amber); else → `#7ca3ff46` (blue) |
| Stroke width | `min(log(connections+1), 4)` |
| Arrow | `url(#arrow)` marker at line end (directed edges) |
| `.traffic-flow` class | Applied when `connections > 10` |
| Edge label | Connection count text shown midpoint; only for edges where `connections > 5` |

**Search mode:** non-matching nodes fade to 0.15 opacity; non-matching edges fade to 0.15; non-matching edge labels hide completely (opacity 0).

---

### Node Click Behaviour

- **Cluster node** (not in focusMode): calls `expandCluster(d)` — replaces cluster with its member nodes
- **Any other node**: sets `selectedNode` → opens `<app-device-drawer>`; applies `is-selected` CSS class

---

### `NetworkDataService`

Injectable singleton at `ndr-ui/src/pages/analyst/network-map/services/network-data.service.ts`.

| Method | API call | Description |
|---|---|---|
| `loadMap(limit=25)` | `GET /api/network-map?mode=top&limit=25` | Loads top-N hosts by traffic; calculates `connections` per node (sum of `edge.connections` for all edges touching that node) |
| `loadFocusMode(ip)` | `GET /api/network-map/node/{ip}` | Loads the sub-graph centred on one IP; same connection calculation |
| `expandCluster(clusterNode, currentNodes, currentEdges)` | `GET /api/network-map` (no params) | Fetches full unclustered graph; extracts `clusterNode.member_ips` as individual nodes; removes the cluster node; filters edges to only those valid within the updated node set. `nodeCount` returned is `updatedNodes.length` (local approximation, not from `total_nodes`) |

All three return `Observable<GraphData>` where `GraphData = { nodes, edges, nodeCount, edgeCount }`.

---

### `NetworkPhysicsService`

Injectable singleton at `ndr-ui/src/pages/analyst/network-map/services/network-physics.service.ts`.

| Method | Description |
|---|---|
| `initSimulation(nodes, edges, w, h, onTick)` | Full D3 force simulation restart. Forces: `link` (distance 120–240 based on connections), `charge` (-1200 internal, -600 external), `center`, `collision` (radius 65, 2 iterations). `alphaDecay` 0.04. |
| `updateSimulation(nodes, edges, onTick)` | Hot update — stops simulation, swaps nodes/edges, restarts at alpha 0.25. Existing nodes barely move; only new nodes (seeded at a fixed position) settle outward. |
| `dragBehavior` | D3 drag: pins node (`fx/fy`) on start/drag; releases on end. Reheats simulation to `alphaTarget 0.3` on drag start. |
| `destroy()` | Stops the simulation and nulls the reference (called on component destroy). |

---

### Template Structure

1. **Ambient orbs** — 3 decorative background glow divs (`.orb-1/2/3`)
2. **Header** — eyebrow "Live Topology" + h2 "Network Map" + subtitle "Real-time host communication graph · Last hour of traffic"; right: Nodes metric pill + Connections metric pill + Refresh button (icon spins while `viewState === 'loading'`)
3. **Status bar** — "Topology renderer active" live dot + "Window: last 1 hour" + "Updated {lastUpdated}"
4. **Device Selector Bar** (`*ngIf="viewState === 'loaded' || focusMode"`) — "LOCAL DEVICES" label + `internalCount`; scrollable row of chips for each `internalNodes` entry. Each chip shows:
   - Top: `dsb-chip__dot` + role label (`'GATEWAY'` for router/gateway type, `'INTERNAL HOST'` otherwise)
   - Middle: `n.label` (when label ≠ id), else `n.id`
   - Bottom: `n.type || 'host'` and `n.connections`
   - CSS class `dsb-chip--gw` and dot class `dsb-chip__dot--gw` applied when `n.type === 'router' || n.type === 'gateway' || n.type === 'firewall'` (switch does NOT get `dsb-chip--gw`)
   - Role label text "GATEWAY" only when `n.type === 'router' || n.type === 'gateway'` — firewall gets the `--gw` CSS class but shows "INTERNAL HOST" as the label
   - "Show All" button (`*ngIf="selectedPathNode"`) → `exitDeviceFocus()`
5. **Network Path Strip** (`*ngIf="selectedPathNode"`) — horizontal path: **Internet** → **Gateway** (shown only if different from selected node; includes an "Unmanaged L2 Switch / Transparent" node between gateway and device) → **Selected Device** → up to 10 external destinations as clickable `<a>` chips with favicons (domains) or globe SVG (raw IPs)
6. **Map Workspace** (`.has-selection` when `selectedNode`):
   - **Type filter bar**: All | Internal | External | Threats | High Traffic — each shows count; clicking calls `setFilter()`
   - **Hint badge**: "Drag · Scroll to zoom"
   - **Search input** (hidden when `focusMode`) — live `(input)` handler → `onSearchChange()`
   - **"Back to full map" button** (shown when `focusMode && !selectedPathNode`) → `clearSelection()`
   - **State overlays** (mutually exclusive based on `viewState`): loading spinner card | error card ("Connection Lost" + Retry button) | empty card ("No network data yet")
   - **HUD corners** + scan line overlay
   - **`<svg #mapSvg>`** — D3 canvas
7. **`<app-device-drawer>`** (`*ngIf="selectedNode"`) — inputs: `[node]="selectedNode"`, `[focusModeActive]="focusMode"`; outputs: `(closeDrawer)="clearSelection()"`, `(focusRequested)="toggleFocus()"`

---

### API Methods

| Method | HTTP | Endpoint | Description |
|---|---|---|---|
| `getNetworkMap(mode?, limit?)` | GET | `/api/network-map[?mode=top&limit=25]` | Full graph; `mode=top` returns highest-traffic nodes first |
| `getNetworkMapNode(ip)` | GET | `/api/network-map/node/{ip}` | Sub-graph centred on one host |
| `searchNetworkMap(query)` | GET | `/api/network-map/search?q={query}` | Returns `string[]` of matching node IDs |

---

## Assets

**Route:** `/analyst/assets`  
**Angular component:** `ndr-ui/src/pages/analyst/assets/assets.ts`  
**Template:** `ndr-ui/src/pages/analyst/assets/assets.html`  
**Styles:** `ndr-ui/src/pages/analyst/assets/assets.css`  
**Services:** `Api`, `AuthService`, `ChangeDetectorRef`  
**Shared component:** `<app-device-drawer>`

### Purpose

Tabular inventory of all discovered internal hosts with enrichment (vendor, OS guess, role, criticality, trust status). Supports filtering by device type, subnet, and last-seen window, plus full-text search. Analysts can rename assets and toggle trust status inline. Clicking any row opens the `DeviceDrawer` panel for detailed connection and alert history.

---

### Component State

| Property | Type | Description |
|---|---|---|
| `assets` | `any[]` | Raw asset array from `GET /api/assets` |
| `filteredAssets` | `any[]` | Subset of `assets` after all filters applied |
| `loading` | `boolean` | True while API call is in flight |
| `searchTerm` | `string` | Current search input text |
| `filterDeviceType` | `string` | Selected device type; default `'all'` |
| `filterSubnet` | `string` | Selected subnet CIDR; default `'all'` |
| `filterLast24h` | `boolean` | Filter to assets seen within 24h |
| `editingIp` | `string \| null` | IP of asset currently in inline edit mode |
| `editNameValue` | `string` | Current value in the name edit input |
| `subnets` | `any[]` | IPAM subnets from `GET /api/ipam/subnets` |
| `isSubnetDropdownOpen` | `boolean` | Subnet dropdown open |
| `selectedAsset` | `any \| null` | Asset selected for DeviceDrawer display |
| `isDropdownOpen` | `boolean` | Device type dropdown open |
| `totalAssets` | `number` | `assets.length` — set in `calculateStats()` |
| `stats` | `object` | `{ workstations, servers, iot, networking }` — each `{ count, percent }` |
| `sensorIds` | `string[]` | Read from JWT; not passed to API (backend scopes responses) |

---

### `ngOnInit()`

Reads `sensorIds`, then calls `loadAssets()` and `loadSubnets()` — both fire immediately (concurrent HTTP requests). Neither waits for the other to complete.

---

### Data Loading

**`loadAssets()`** — `GET /api/assets` → stores in `assets[]`; calls `calculateStats()` then `filterAssets()`. Handles three response shapes: `Array` (normal), `{ error }` (backend error), unexpected format — all silently degrade to empty array.

**`loadSubnets()`** — `GET /api/ipam/subnets` → stores in `subnets[]`. Errors silently degrade to `[]`.

---

### `calculateStats()`

Groups assets into 4 buckets by `device_type`:

| Bucket | Device types included |
|---|---|
| Servers | `server` |
| IoT | `iot`, `printer`, `tv` |
| Networking | `router`, `network`, `gateway`, `switch`, `firewall` |
| Workstations | Everything else (including `unknown`) |

Percentages are rounded to integers. A rounding correction is applied to the largest bucket to ensure `workstations + servers + iot + networking === 100%` exactly.

---

### `filterAssets()`

Filters `assets[]` into `filteredAssets[]` in four ordered steps:

1. **Subnet filter** — `isIpInCidr(a.ip, filterSubnet)`: pure bitmask comparison; skips assets with no IP when a subnet is selected.
2. **Device type filter** — exact match with synonyms: `phone` matches `mobile`; `tv` matches `media`; `router` matches `gateway`, `firewall`, `switch`.
3. **24h filter** — `last_seen` is Unix **seconds**; passes when `(Date.now()/1000 - last_seen) <= 86400`. Assets with no `last_seen` are excluded.
4. **Search term** — case-insensitive match against: `ip`, `mac`, `hostname`, `custom_name`, `vendor`, `device_type`, and `ip_history` (JSON-parsed array of `{ip: string}` — searches historical IPs for the Hybrid Asset Model).

---

### Methods

| Method | Description |
|---|---|
| `filterAssets()` | Re-evaluates all 4 filter steps and updates `filteredAssets` |
| `setFilter(value)` | Sets `filterDeviceType`, closes dropdown, calls `filterAssets()` |
| `setSubnetFilter(cidr)` | Sets `filterSubnet`, closes dropdown, calls `filterAssets()` |
| `getFilterLabel()` | Human label for current device type filter |
| `getSubnetLabel()` | Returns CIDR string or `'All Subnets'` |
| `isIpInCidr(ip, cidr)` | Pure bitmask CIDR check; handles `/0` edge case |
| `startEdit(asset)` | Sets `editingIp = asset.ip`, `editNameValue = asset.custom_name \|\| asset.hostname` |
| `cancelEdit()` | Clears `editingIp` |
| `saveEdit(asset)` | `PUT /api/assets/{ip}` with `{ custom_name }`; updates `asset.custom_name` in-place on success; shows `alert()` on error |
| `toggleTrusted(asset)` | `PATCH /api/assets/{ip}/trusted` with `{ trusted: !current }`; on success: flips `asset.trusted`; if now trusted, also clears `asset.threat_flagged` |
| `selectAsset(asset)` | Sets `selectedAsset` → opens DeviceDrawer |
| `closeDrawer()` | Clears `selectedAsset` |
| `handleFocus(ip)` | **No-op** — comment indicates future router navigation to network map focus mode is planned but not implemented |
| `formatLastSeen(ts)` | Unix seconds → `new Date(ts × 1000).toLocaleString()`; returns `'Never'` when falsy |
| `getDeviceIcon(type)` | Returns Lucide icon: laptop/desktop→Monitor, mobile/phone/tablet→Smartphone, printer→Printer, router→Router, server→Server, iot→Lightbulb, default→Server |
| `getRoleClass(role)` | CSS class from role keyword: if role is falsy → `''` (empty string, no class); uses `.includes()` matching: server→`role-server`, gateway/router→`role-network`, workstation→`role-workstation`, iot→`role-iot`, database→`role-database`, else→`role-default` |
| `getCriticalityClass(score)` | ≥70→`crit-high`, ≥40→`crit-medium`, else→`crit-low` |
| `calculateStats()` | Recomputes `stats` and `totalAssets` from full `assets[]` |

---

### Template Structure

**Header:**
- h2 "Asset Inventory" + "Discovered devices, identities, and hostnames."
- Right side (filter group):
  - **Device type dropdown** (custom, not `<select>`) — 10 options + "All Devices"; backdrop div closes dropdown on outside click
  - **"Seen in last 24h" checkbox** — `[(ngModel)]="filterLast24h"` with `(ngModelChange)="filterAssets()"`
  - **Search input** — `[(ngModel)]="searchTerm"` with `(ngModelChange)="filterAssets()"`, placeholder "Search IPs, names, vendors..."
  - **Subnet dropdown** (`*ngIf="subnets.length > 0"`) — "All Subnets" + one item per subnet showing CIDR + usage ratio

**Subnet stats row** (`*ngIf="subnets.length > 0 && !loading"`):
- Clickable cards per subnet, each showing: CIDR (bold), interface + sensor_id (if set), usage bar (`used_ips / total_ips × 100%`), used count + free count; clicking filters the grid to that subnet

**Dashboard** (`*ngIf="!loading && totalAssets > 0"`):
- **Donut chart**: CSS `conic-gradient` with 4 segments (workstations blue, IoT rose, servers green, networking purple). Center: total asset count. SVG `<circle>` serves as donut ring background.
- **Stats grid**: 4 cards — Workstations (Monitor icon, blue) | IoT Devices (Lightbulb, orange) | Servers (Server, green) | Networking (Router, purple) — each shows count and percentage

**Asset workspace** (`.has-selection` class when `selectedAsset`):
- **Grid header** row: Type | IP Address | Name | Vendor | OS | Role | Risk | MAC Address | Conns (24h) | Alerts (24h) | Last Seen | Status | (actions)
- **Loading state**: "Loading assets..."
- **Empty state**: Search icon + "No assets found" + "Try adjusting your search criteria or filters to see more devices."
- **Grid rows** (per `filteredAssets`): click → `selectAsset(asset)`; `.selected` class when `selectedAsset?.ip === asset.ip`
  - **Type**: device icon badge (`getDeviceIcon(asset.device_type)`) with `title` tooltip
  - **IP**: `<code>` monospace
  - **Name**: displays `custom_name || hostname || vendor || 'Unknown'` + pencil Edit button → inline edit; double-click on cell also opens edit. Edit mode: text input (Enter→save, Escape→cancel) + check and × buttons
  - **Vendor**: text or `--`
  - **OS**: `ja3_os || os_guess || '--'` — JA3 fingerprint OS takes precedence
  - **Role**: role badge with `getRoleClass()`; `title` attribute shows `"Subnet: {subnet_role}"` when `subnet_role` is set; shows `--` when `asset.role` is falsy
  - **Risk**: criticality bar + numeric score (bar width = `criticality%`, colored by `getCriticalityClass()`); shows `--` (not hidden) when `!criticality || criticality === 0`
  - **MAC**: `<code>` or `--`
  - **Conns (24h)**: `connections_24h || 0`
  - **Alerts (24h)**: `alerts_24h` shown in orange `.alert-badge` when > 0; plain `0` otherwise
  - **Last Seen**: `formatLastSeen(asset.last_seen)`
  - **Status**: "Threat" badge (AlertTriangle icon) when `threat_flagged && !trusted`; "Trusted" badge (ShieldCheck icon) when `trusted`; both hidden otherwise
  - **Actions** (click stops propagation): ShieldCheck/ShieldOff toggle button → `toggleTrusted(asset)`
- **`<app-device-drawer>`** (`*ngIf="selectedAsset"`) — `[node]="selectedAsset"`; `(closeDrawer)="closeDrawer()"`, `(focusRequested)="handleFocus($event)"` (no-op). Note: `[focusModeActive]` input is **not passed** here (that input is only wired by Network Map)

---

### API Methods

| Method | HTTP | Endpoint | Description |
|---|---|---|---|
| `getAssets()` | GET | `/api/assets` | All internal assets for the tenant |
| `getIpamSubnets()` | GET | `/api/ipam/subnets` | IPAM subnet list with `cidr`, `interface`, `sensor_id`, `used_ips`, `free_ips`, `total_ips` |
| `updateAsset(ip, payload)` | PUT | `/api/assets/{ip}` | Update asset fields — used for `{ custom_name }` |
| `setAssetTrusted(ip, trusted)` | PATCH | `/api/assets/{ip}/trusted` | Set `{ trusted: boolean }` — trusted assets also clear `threat_flagged` client-side |

---

## Shared: `DeviceDrawer` Component

**Source:** `ndr-ui/src/components/device-drawer/device-drawer.ts`  
**Selector:** `<app-device-drawer>`  
**Used by:** Network Map page and Assets page

### Inputs / Outputs

| Input / Output | Type | Description |
|---|---|---|
| `@Input() node` | `any` | The node/asset to display — triggers `ngOnChanges` |
| `@Input() focusModeActive` | `boolean` | Focus mode state — passed by Network Map only; Assets does not pass this input (defaults to `false`) |
| `@Output() closeDrawer` | `EventEmitter<void>` | Emitted when user closes the drawer |
| `@Output() focusRequested` | `EventEmitter<string>` | Emits `node.id || node.ip` — Network Map wires to `toggleFocus()`; Assets wires to `handleFocus()` (no-op) |

### State

| Property | Type | Description |
|---|---|---|
| `drawerTab` | `string` | Active tab: `'overview'` \| `'connections'` \| `'alerts'`; default `'overview'` |
| `selectedNodeConnections` | `any[]` | Connection peer list loaded via `GET /api/network-map/node/{ip}` |
| `loadingConnections` | `boolean` | Loading flag for connections tab |
| `selectedNodeAlerts` | `any[]` | Alerts filtered for this node, loaded via `GET /api/alerts` |
| `loadingAlerts` | `boolean` | Loading flag for alerts tab |
| `pcapSessions` | `any[]` | PCAP sessions from Arkime, limit 10 (TypeScript state exists; no tab UI in current template) |
| `pcapLoading` | `boolean` | Loading flag — no UI in current template |
| `pcapError` | `string` | Error string — no UI in current template |
| `isEditingName` | `boolean` | Whether inline name edit is active |
| `editNameValue` | `string` | Current value in the name edit input |

### `ngOnChanges`

Fires when `node` input changes:
1. Calls `setDrawerTab(this.drawerTab)` — re-triggers the loader for whichever tab is currently active
2. If the active tab is NOT `'connections'`: additionally pre-loads connections for the overview chart (connections are used by both overview and connections tabs)

IP resolution order used throughout: `node.active_ip || node.id || node.ip`.

### Tabs and Data Loading

`setDrawerTab(tab)` sets `drawerTab` and calls the appropriate loader:

| Tab | Loader | API |
|---|---|---|
| `'overview'` | (no load — uses pre-loaded `selectedNodeConnections`) | — |
| `'connections'` | `loadNodeConnections(ip)` | `GET /api/network-map/node/{ip}` |
| `'alerts'` | `loadNodeAlerts(ip)` | `GET /api/alerts` (filtered client-side by `src_ip === ip \|\| dst_ip === ip`) |
| `'pcaps'` | `loadPcapSessions(ip)` | Arkime `getSessions({ ip, limit: 10 })` — **method exists in TS, no tab button in current HTML template** |

`loadNodeConnections(ip)` — maps each edge from the response to `{ peer, connections, protocols[] }` where `peer` is whichever end of the edge is not the current node.

### `isInternalNode(node)`

Private helper — determines internal status by RFC-1918 IP range first, then falls back to the API field:

```
10.x.x.x         → internal
192.168.x.x      → internal
127.x.x.x        → internal (loopback)
169.254.x.x      → internal (link-local)
172.16–31.x.x    → internal
everything else  → node.is_internal ?? false
```

IP is taken from `node.active_ip || node.ip || node.id`. Used by `riskScore`, `getDrawerIcon()`, `getNodeTypeClass()`.

### `riskScore` Getter

```ts
get riskScore(): number {
  if (!this.node) return 0;
  if (this.node.criticality != null) return Math.min(100, this.node.criticality);
  if (this.node.threat) return 88;
  const conns = this.node.connections || 0;
  if (!this.isInternalNode(this.node)) return Math.min(60, 18 + Math.floor(conns / 100));
  return Math.min(35, 4 + Math.floor(conns / 150));
}
```

Priority order:
1. `node.criticality != null` → `min(100, criticality)` (uses loose null check — catches both null and undefined)
2. Threat node → **88**
3. External (non-internal by RFC-1918) → `min(60, 18 + floor(conns/100))` (max 60)
4. Internal without score → `min(35, 4 + floor(conns/150))` (max 35 — not the same formula as external)

### `getDrawerIcon(node)` in DeviceDrawer

Note: DeviceDrawer has its own `getDrawerIcon()`, distinct from NetworkMap's version. It uses `node?.type || node?.device_type` so it handles Assets' `device_type` field as well as NetworkMap's `type` field. Also uses `isInternalNode()` (RFC-1918) rather than `node.is_internal` for the internal fallback.

Resolution order (first match wins):

```
cluster                         → Users
laptop                          → Laptop
desktop                         → Monitor
phone / mobile                  → Smartphone
tablet                          → Tablet
iot                             → Cpu
printer                         → Printer
tv / media                      → Tv
server                          → Server
router/gateway/firewall/switch  → Router
ANY internal (by RFC-1918)      → Router   ← checked BEFORE threat; internal threats get Router
external threat node            → TriangleAlert
external unknown                → Globe
```

**Note:** `HelpCircle` is imported but unreachable — the final `return isInternal ? HelpCircle : Globe` always evaluates to `Globe` because the `isInternal` branch already returned earlier.

### `getNodeTypeClass(node)` in DeviceDrawer

Uses `isInternalNode()`: threat→`'threat'`, internal→`'internal'`, else→`'external'`. (NetworkMap's version uses `node.is_internal` directly.)

### Drawer Template Structure

**Header:**
- Title: `node.label || node.custom_name || node.hostname || node.id || node.ip`
- Subtitle: `"Root Domain • External"` when `node.type === 'domain'`; else `"{ node.id || node.ip } • { node.type || node.device_type }"`
- Pencil edit button: **hidden when `node.type === 'domain'`**
- Edit mode: text input (Enter→save, Escape→cancel) + confirm and cancel buttons

**Focus button:** "Focus on this Device" / "Exit Focus Mode" toggled by `focusModeActive`; always visible.

**Tabs (3):** Overview | Connections | Alerts

**Overview tab content:**

1. *IP Hero* — shows `node.active_ip || node.id || node.ip` in `<code>`; copy button → `copyToClipboard()`; eyebrow: `'INTERNAL HOST'` / `'THREAT INDICATOR'` / `'EXTERNAL NODE'` (uses `node.is_internal` and `node.threat`); badges for type, trusted (✓ Trusted), threat (⚠ Threat), mac
2. *Stats triptych* — connections: `node.connections_24h` if defined, else `node.connections || 0`; vendor (shown `*ngIf="node.vendor"`); OS (`*ngIf="node.os_guess"`); fallback: device type when no vendor/os_guess
3. *Traffic Activity sparkline* — 14 `activityBars` heights; bars get class `activity-bar--high` (h > 65) or `activity-bar--mid` (h > 35); animation delay `i × 30ms`; labeled "1h window"
4. *Risk gauge + Protocols row* — SVG arc ring: green ≤40, amber 40–70, red >70; `topProtocols` chips alongside; "No data" / "Loading…" shown while loading
5. *Top Connections* — `topPeers` (top 4), shows `selectedNodeConnections.length` total count; peer IP + bar (relative to max) + connection count
6. *Connected Websites* — shown when `(node.is_internal || node.type === 'domain') && node.all_domains?.length > 0`; title is "Connected Websites" for internal nodes, "Observed Domains" for `node.type === 'domain'`; each entry is a clickable `<a href="http://{d}" target="_blank">` card with favicon
7. *Resolved IPs* — shown only when `node.type === 'domain' && node.member_ips?.length > 0`; displays IP chips
8. *Primary Domain* — shown when `node.type !== 'domain' && !node.is_internal && node.primary_domain`; shown as `<code>`

**Connections tab:** Full list of `selectedNodeConnections` (not just top 4). Each row: peer IP + protocol tags + connection count. Shows loading spinner and empty state.

**Alerts tab:** Shows `selectedNodeAlerts`. Each row: `alert.rule_name || alert.event_type` + `alert.timestamp | date:'short'`. Shows loading spinner and empty state.

### Computed Getters

| Getter | Description |
|---|---|
| `activityBars` | Array of 14 pseudo-random bar heights (14–95) for the overview mini-chart; seed string is `node?.id || node?.ip || ''`; hash: `((a * 31) + charCode) & 0xFFFF` with initial accumulator `7`; base height scales with `connections` |
| `topPeers` | Top 4 peers from `selectedNodeConnections`, sorted by `connections` desc |
| `topProtocols` | Up to 6 unique protocols collected from all `selectedNodeConnections[].protocols[]`, in order of first appearance |

### Methods

| Method | Description |
|---|---|
| `setDrawerTab(tab)` | Sets active tab and triggers appropriate data load |
| `loadNodeConnections(ip)` | `GET /api/network-map/node/{ip}` → maps edges to peer list |
| `loadNodeAlerts(ip)` | `GET /api/alerts` → filters by `src_ip \|\| dst_ip` |
| `loadPcapSessions(ip)` | Arkime `getSessions({ ip, limit: 10 })` |
| `downloadPcap(sessionId)` | Calls `arkime.downloadPcap(sessionId)` |
| `toggleFocus()` | Emits `focusRequested` with `node.id \|\| node.ip` |
| `onClose()` | Emits `closeDrawer` |
| `startEditName()` | Sets `isEditingName = true`; initializes `editNameValue = node.custom_name \|\| node.hostname \|\| node.label \|\| ''` |
| `saveName()` | `PUT /api/assets/{active_ip \|\| ip \|\| id}` with `{ custom_name }`; on success: updates `node.custom_name` and `node.label` in-place, closes edit mode. On error: `console.error`, closes edit mode |
| `cancelEditName()` | Sets `isEditingName = false` |
| `copyToClipboard(text)` | `navigator.clipboard.writeText(text)` — silently catches errors |
| `onFaviconError(event)` | Hides failed `<img>`, sets `data-fallback='🌐'` on parent `.website-card__icon` |
| `getPeerBarWidth(peer)` | Returns `(peer.connections / maxPeerConnections) × 100` as percentage for bar chart |
| `isInternalNode(node)` | RFC-1918 range check with API fallback (see above) |

---

## Data Flow

```
Network Map
  ngOnInit
    └─ GET /api/network-map?mode=top&limit=25
         └─ calculateConnections() → nodesData[], edgesData[]
         └─ renderGraph() → physics.initSimulation() (cold start)

  selectPathNode(node) / toggleFocus()
    └─ GET /api/network-map/node/{ip}
         └─ renderGraph(isClusterExpand=true) → physics.updateSimulation()
         └─ zoomToNode(focusedNode, 1.2×)

  expandCluster(clusterNode)
    └─ GET /api/network-map (no params, full unclustered graph)
         └─ splice cluster → expand member_ips
         └─ renderGraph(isClusterExpand=true) → physics.updateSimulation()
         └─ zoomToNode(anchor, 0.75×)

  onSearchChange(query) [debounced 300ms]
    ├─ client-side: scan nodesData → searchMatches → renderGraph()
    └─ GET /api/network-map/search?q={query}
         └─ merge new IDs → searchMatches → renderGraph()
         └─ expandCluster() if match is inside a cluster
         └─ zoomToNode(first result, 2×)

Assets
  ngOnInit
    ├─ GET /api/assets → assets[] → calculateStats() → filterAssets()
    └─ GET /api/ipam/subnets → subnets[]

  saveEdit(asset)
    └─ PUT /api/assets/{ip} { custom_name } → update in-place

  toggleTrusted(asset)
    └─ PATCH /api/assets/{ip}/trusted { trusted } → update in-place
```
