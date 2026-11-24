# NDR Developer Reference — Super Admin: Infrastructure

**Module path:** `/admin` → Infrastructure section  
**Roles allowed:** `super_admin` only (both sub-pages enforce this in the Rust handler)  
**Angular page shell:** `ndr-ui/src/layout/admin-layout/admin-layout.ts` (`AdminLayout` — lazy-loaded parent with built-in sidebar and `<router-outlet>`)

The Infrastructure group contains two sub-pages: **Engines** and **Sensor Keys**.  
Engines manages the pool of running NDR Engine Docker containers and the Kafka message bus.  
Sensor Keys issues and manages the API credentials that allow Agent-S and Agent-Z sensors to send data to the platform.

---

## Part 1 — Engines

### 1.1 Angular Component

| Item | Detail |
|------|--------|
| Component class | `Engines` |
| File | `ndr-ui/src/pages/admin/engines/engines.ts:19` |
| Template | `ndr-ui/src/pages/admin/engines/engines.html` |
| Stylesheet | `ndr-ui/src/pages/admin/engines/engines.css` |
| Change detection | `OnPush` — `cdr.detectChanges()` called explicitly after every async result |
| View encapsulation | `None` — styles are global within the admin shell |

**Component state fields:**

| Field | Type | Purpose |
|-------|------|---------|
| `engines` | `any[]` | List of running engine containers |
| `loadingEngines` | `boolean` | Shows spinner during `GET /api/admin/engines` |
| `scaling` | `boolean` | Disabled state for scale-up button while request is in flight |
| `pendingStopEngine` | `string` | Engine name waiting for stop confirmation — empty = no modal |
| `lastEngineRefresh` | `Date \| null` | Timestamp shown in UI so the admin knows how fresh the list is |
| `kafkaData` | `any` | Full Kafka status object returned by `GET /api/monitor/kafka` |
| `kafkaLoading` | `boolean` | True only on the very first Kafka load (no previous data yet) |
| `kafkaInterval` | `any` | `setInterval` handle — must be cleared in `ngOnDestroy` to prevent memory leak |
| `syncingRules` | `boolean` | Spinner state for the Sync Community Rules button |
| `syncMessage` | `string` | Success/error text shown after sync |

---

### 1.2 Lifecycle & Polling

```
ngOnInit()  →  loadEngines()          (once, on mount)
            →  loadKafkaStatus()      (once, on mount)
            →  setInterval(loadKafkaStatus, 10 000ms)   (every 10 seconds)

ngOnDestroy()  →  clearInterval(kafkaInterval)
```

**Why poll Kafka every 10 seconds?**  
Consumer group lag changes continuously as Agent-S and Agent-Z sensors send events. The admin needs near-real-time visibility without a full page reload.

---

### 1.3 Angular Functions

#### `loadEngines()` — line 54
Calls `api.getEngines()` → `GET /api/admin/engines`.  
Sets `engines[]` and `lastEngineRefresh`. On error shows toast via `showMsg()`.

#### `scaleUp()` — line 67
Calls `api.scaleEngines('up')` → `POST /api/admin/engines/scale` with body `{ action: "up" }`.  
Sets `scaling = true` during the request. After success, waits 3 seconds then re-calls `loadEngines()` — the 3s delay gives Docker time to start the new container before the list is refreshed.

#### `requestStopEngine(engine)` — line 84
Sets `pendingStopEngine = engine`. This opens a confirmation modal in the template. Nothing is sent to the backend yet.

#### `cancelStopEngine()` — line 85
Clears `pendingStopEngine = ''`. Closes the modal without stopping anything.

#### `confirmStopEngine()` — line 87
Called when the admin confirms the stop modal. Sends `POST /api/admin/engines/scale` with body `{ action: "down", engine: "<name>" }`. Waits 2 seconds then refreshes the engine list.

#### `loadKafkaStatus()` — line 100
Calls `api.getKafkaStatus()` → `GET /api/monitor/kafka`. Sets `kafkaData`. Sets `kafkaLoading = true` only when `kafkaData` is still null (first load) so the polling refresh does not flash a spinner.

#### `getEngineForPartition(partition)` — line 108
Helper used in the template. Searches `kafkaData.consumers[]` for the entry matching the partition number and returns its `engine` (client-id) string. Returns `'-'` if not found.

#### `getLagForPartition(partition)` — line 113
Same search as above but returns the `lag` number for that partition. Returns `0` if not found.

#### `syncCommunityRules()` — line 118
Calls `api.syncCommunityRules()` → `POST /api/rules/sync-community`.  
Sets `syncingRules = true`. The backend returns immediately (it spawns a background task). On success, shows the returned message, e.g. `"47 community rules synced from SigmaHQ"`.

---

### 1.4 API Service Methods

File: `ndr-ui/src/services/api/api.ts`

| Method | Line | HTTP Call | When called |
|--------|------|-----------|-------------|
| `getEngines()` | 565 | `GET /api/admin/engines` | On init, after scale operations |
| `getKafkaStatus()` | 574 | `GET /api/monitor/kafka` | On init, every 10 seconds |
| `scaleEngines(action, engine?)` | 582 | `POST /api/admin/engines/scale` | Scale Up / Confirm Stop |
| `syncCommunityRules()` | 220 | `POST /api/rules/sync-community` | Sync Community Rules button |

---

### 1.5 Rust Routes

File: `rust/ndr-engine/src/main.rs`

| Method | URL | Handler | Line |
|--------|-----|---------|------|
| `GET` | `/api/admin/engines` | `api::get_engines` | 823 |
| `POST` | `/api/admin/engines/scale` | `api::scale_engines` | 824 |
| `GET` | `/api/monitor/kafka` | `monitor::kafka::kafka_status` | 894 |
| `POST` | `/api/rules/sync-community` | `api::sync_community_rules_api` | 741 |

---

### 1.6 Rust Handler: `get_engines()` — line 6108

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Calls `require_super_admin(&headers)` — returns HTTP 403 if role is not `super_admin`.
2. Runs shell command: `docker ps --filter name=ndr-engine --format {{.Names}},{{.Status}},{{.RunningFor}}`.
3. Splits each output line on `,` into `{ name, status, running }` JSON objects.
4. Returns `{ engines: [...], count: N }`.

**Why Docker ps directly?**  
NDR Engine instances are Docker containers, not OS services. Docker ps is the authoritative source of running container state — no external process manager is involved.

**Returns:**
```json
{
  "engines": [
    { "name": "ndr-engine-1", "status": "Up 2 hours", "running": "2 hours" }
  ],
  "count": 1
}
```

---

### 1.7 Rust Handler: `scale_engines()` — line 6145

File: `rust/ndr-engine/src/api/mod.rs`

Accepts `{ action: "up" | "down", engine?: string }`.  
Requires `super_admin`.

#### Scale Up (`action = "up"`) — line 6157

1. Counts currently running `ndr-engine` containers via `docker ps -q --filter name=ndr-engine`.
2. Derives the new instance name: `ndr-engine-{count + 1}`.
3. Runs a bash script that:
   - Finds an existing running engine container to use as a blueprint.
   - Inspects the blueprint's image, networks, volume mounts (`-v`), and environment variables.
   - Patches `INSTANCE_ID` in the env vars to the new instance number.
   - Removes any stopped container with the same name (avoids Docker name conflict).
   - Starts the new container with `docker run -d` using the cloned config.
   - Connects the new container to any additional Docker networks the blueprint was on.
4. Scales the Kafka `ndr-events` topic partition count to match the new engine count via `kafka-topics.sh --alter --partitions N`. Each engine instance consumes exactly one partition, so partition count must equal instance count.
5. Adds the new engine to both Nginx upstream blocks in `$INSTALL_DIR/config/nginx/nginx.conf` at the `# ENGINES_MARKER` and `# WS_ENGINES_MARKER` comments, then reloads nginx with `docker exec ndr-nginx nginx -s reload`.

**Returns:**
```json
{
  "status": "ok",
  "message": "Engine ndr-engine-2 started!",
  "engine": "ndr-engine-2",
  "kafka": "Kafka partitions set to 2",
  "nginx": "Added server ndr-engine-2:3000 max_fails=3 fail_timeout=30s; to ndr_engines\nNginx reloaded"
}
```

#### Scale Down (`action = "down"`) — line 6295

1. Requires `engine` name in payload — returns error if missing.
2. **Removes the container from both Nginx upstreams first** — this stops new requests being routed to it before it stops. Nginx is reloaded immediately so traffic is drained cleanly.
3. Waits 2 seconds to let any in-flight requests on that engine finish.
4. Runs `docker stop <engine_name>` to stop the container gracefully.

**Why remove from Nginx before stopping?**  
If the container is stopped first, Nginx still routes requests to it for up to `fail_timeout=30s`. Removing from the upstream config first guarantees zero dropped requests.

**Returns:**
```json
{
  "status": "ok",
  "message": "ndr-engine-2 stopped!",
  "engine": "ndr-engine-2",
  "nginx": "Nginx reloaded",
  "note": "Nginx drained before container stop — zero dropped requests"
}
```

---

### 1.8 Rust Handler: `kafka_status()` — line 5

File: `rust/ndr-engine/src/monitor/kafka.rs`

**Step by step:**

1. Runs `docker exec kafka1 kafka-topics.sh --describe --topic ndr-events` to get partition count, replication factor, and per-partition leader/ISR info.
2. Runs `docker exec kafka1 kafka-consumer-groups.sh --describe --group ndr-engine-group` to get per-partition consumer lag and which engine (client-id) owns each partition.
3. Checks each of the three brokers (`kafka1`, `kafka2`, `kafka3`) by running `kafka-broker-api-versions.sh` and reporting `"healthy"` or `"unreachable"`.
4. Returns the full status object.

**Returns:**
```json
{
  "topic": "ndr-events",
  "partition_count": 2,
  "replication_factor": 3,
  "brokers": [
    { "id": 1, "host": "kafka1", "status": "healthy" }
  ],
  "partitions": [
    { "partition": 0, "leader_broker": 1, "replicas": "1,2,3", "isr": "1,2,3", "in_sync": true }
  ],
  "consumers": [
    { "partition": 0, "current_offset": "1042", "log_end_offset": "1042", "lag": 0, "engine": "ndr-engine-1" }
  ],
  "total_lag": 0
}
```

---

### 1.9 Rust Handler: `sync_community_rules_api()` — line 2572

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Requires `super_admin`.
2. Tries to acquire a Redis distributed lock: `SET ndr:sync_rules_lock 1 NX EX 300`. `NX` means "set only if not exists" — so only one engine across the whole cluster can run the sync at a time.
3. If the lock already exists (another engine is syncing), returns `{ status: "already_running" }` immediately.
4. Spawns a background `tokio::spawn` task so the HTTP response is returned before the sync finishes — avoids nginx timeout on slow GitHub downloads.
5. Background task calls `crate::detection::sync_now()` which downloads the latest SigmaHQ community Sigma rules and inserts new ones into ClickHouse.
6. Background task releases the Redis lock via `DEL ndr:sync_rules_lock` when done, regardless of success or failure.

**Redis key used:** `ndr:sync_rules_lock` — TTL 300 seconds, single-owner distributed lock.

---

## Part 2 — Sensor Keys

### 2.1 Angular Component

| Item | Detail |
|------|--------|
| Component class | `Sensors` |
| File | `ndr-ui/src/pages/admin/sensors/sensors.ts:19` |
| Template | `ndr-ui/src/pages/admin/sensors/sensors.html` |
| Stylesheet | `ndr-ui/src/pages/admin/sensors/sensors.css` |
| Change detection | `OnPush` |

**Component state fields:**

| Field | Type | Purpose |
|-------|------|---------|
| `tenants` | `any[]` | List of all tenants — populates the tenant dropdown in the create-key form |
| `sensorKeys` | `SensorKey[]` | All sensor keys visible to the current user |
| `loadingSensorKeys` | `boolean` | Spinner while loading the key list |
| `creatingSensorKey` | `boolean` | Disables create button during the API call |
| `newSensorKey` | `{ tenant_id, name }` | Two-field form bound with `[(ngModel)]` |
| `createdSensorKey` | `SensorKey \| null` | Holds the newly created key for display in the success modal |
| `showSensorKeyModal` | `boolean` | Controls visibility of the "Key Created" modal |
| `installCommand` | `string` | Full install command shown in the modal for copy-paste |

---

### 2.2 Lifecycle

```
ngOnInit()
  → loadSensorKeys()       (GET /api/sensor-keys)
  → api.getTenants()       (GET /api/tenants — populates dropdown)
```

No polling — the sensor key list is static until an admin creates or revokes a key.

---

### 2.3 Angular Functions

#### `loadSensorKeys()` — line 47
Calls `api.getSensorKeys()` → `GET /api/sensor-keys`. Sets `sensorKeys[]`.

#### `createSensorKey()` — line 55
1. Validates that both `tenant_id` and `name` are filled — shows error toast and returns early if not.
2. Calls `api.createSensorKey(tenantId, name)` → `POST /api/sensor-keys`.
3. On success, builds the `createdSensorKey` object locally using the returned key and id.
4. Sets `installCommand` — the complete shell command the sensor operator runs on the remote machine:
   ```
   sudo bash install-sensor.sh --cloud-url https://your-ndr.com --tenant-id <id> --api-key <key>
   ```
5. Sets `showSensorKeyModal = true` to display the one-time key reveal modal.
6. Resets the form fields and calls `loadSensorKeys()` to refresh the list.

**The full key is shown exactly once.** The backend stores only a bcrypt hash; the plain key cannot be retrieved later.

#### `revokeSensorKey(key)` — line 82
Calls `api.revokeSensorKey(key.id)` → `DELETE /api/sensor-keys/:id`.  
On success, sets `key.active = false` locally (no full list reload needed).

#### `reactivateSensorKey(key)` — line 94
Calls `api.reactivateSensorKey(key.id)` → `POST /api/sensor-keys/:id/reactivate`.  
On success, sets `key.active = true` locally.

#### `copyCreatedSensorKey()` — line 107
Copies `createdSensorKey.key` (the full plain key) to the clipboard using `navigator.clipboard.writeText()`.

#### `copyInstallCommand()` — line 108
Copies `installCommand` to the clipboard.

#### `tenantName(id)` — line 110
Maps a `tenant_id` UUID to its human-readable name by searching `tenants[]`. Used in the table to show tenant name instead of UUID.

---

### 2.4 `SensorKey` Interface

File: `ndr-ui/src/services/api/api.ts:10`

```typescript
export interface SensorKey {
  id: string;
  key_prefix: string;    // first 16 chars of the plain key — used as display identifier
  key?: string;          // full plain key — only present immediately after creation
  tenant_id: string;
  name: string;
  hostname?: string;     // populated after the sensor calls /api/sensor/register
  interface?: string;    // network interface being monitored (e.g. "eth0")
  os?: string;           // operating system (e.g. "Ubuntu 22.04")
  'agent-z'?: string;    // Agent-Z service status: "running" | "stopped" | "unknown"
  'agent-s'?: string;    // Agent-S service status
  vector?: string;       // Vector log shipper status
  arkime?: string;       // Arkime PCAP viewer status
  arkime_url?: string;   // URL to the Arkime UI for this sensor
  active: boolean;
  created_at: string;
  last_seen: string;     // timestamp of last heartbeat from the sensor
}
```

---

### 2.5 API Service Methods

File: `ndr-ui/src/services/api/api.ts`

| Method | Line | HTTP Call | Body / Params |
|--------|------|-----------|---------------|
| `getSensorKeys()` | 589 | `GET /api/sensor-keys` | — |
| `createSensorKey(tenantId, name)` | 603 | `POST /api/sensor-keys` | `{ tenant_id, name }` |
| `revokeSensorKey(id)` | 610 | `DELETE /api/sensor-keys/:id` | — |
| `reactivateSensorKey(id)` | 614 | `POST /api/sensor-keys/:id/reactivate` | `{}` |

**`getSensorKeys()` handles two response shapes (line 589–600):**  
The backend may return either a bare `SensorKey[]` array or `{ status: "ok", keys: SensorKey[] }`. The `pipe(map(...))` normalizes both into a plain array before the component receives it.

---

### 2.6 Rust Routes

File: `rust/ndr-engine/src/main.rs`

| Method | URL | Handler | Line |
|--------|-----|---------|------|
| `GET` | `/api/sensor-keys` | `api::get_sensor_keys` | 829 |
| `POST` | `/api/sensor-keys` | `api::create_sensor_key_api` | 830 |
| `DELETE` | `/api/sensor-keys/:id` | `api::revoke_sensor_key_api` | 832 |
| `POST` | `/api/sensor-keys/:id/reactivate` | `api::reactivate_sensor_key_api` | 834 |

---

### 2.7 Rust Handler: `create_sensor_key_api()` — line 6831

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Extracts JWT claims via `extract_claims(&headers)` — returns 401 if missing.
2. Reads `tenant_id` and `name` from the JSON body — returns error if either is blank.
3. Role check:
   - `super_admin` or `admin` → can create a key for any tenant.
   - `tenant_admin` → can only create keys for their **own** `tenant_id`. Returns 403 if `tenant_id` in the payload differs from `claims.tenant_id`.
   - Any other role → 403.
4. Calls `generate_sensor_key(tenant_id)` at line 6701:
   - Generates 32 random alphanumeric characters using `rand::thread_rng()`.
   - Constructs the plain key: `NDR-{tenant_id}-{32_random_chars}`.
   - Extracts the prefix: first 16 characters of the plain key.
   - Hashes the plain key with `bcrypt::hash(plain, cost=10)`.
   - Returns `(plain, prefix, hash)`.
5. Calls `ch_storage.create_sensor_key(tenant_id, name, hash, prefix)` — inserts into `ndr.sensor_keys`.
6. Returns `{ status: "ok", key: <plain>, id: <uuid> }`.

**The plain key is returned here and never stored again.** Only the bcrypt hash is persisted. If the admin closes the modal without copying the key, they must revoke and create a new one.

---

### 2.8 Rust Handler: `get_sensor_keys()` — line 6870

File: `rust/ndr-engine/src/api/mod.rs`

**Step by step:**

1. Extracts JWT claims — returns 401 if missing.
2. Determines query scope:
   - `super_admin` or `admin` → `target_tenant = "all"` (fetches every key across all tenants).
   - `tenant_admin` → `target_tenant = claims.tenant_id` (only their own tenant's keys).
   - Analyst / viewer → 403.
3. Calls `ch_storage.get_sensor_keys(target_tenant)`.
4. Returns `{ status: "ok", keys: [...] }`.

---

### 2.9 Rust Handler: `revoke_sensor_key_api()` — line 6899

File: `rust/ndr-engine/src/api/mod.rs`

**Only `super_admin` can revoke.** Returns 403 for any other role.

**Step by step:**

1. Validates role.
2. Calls `ch_storage.revoke_sensor_key(id)` — sets `active = 0` in `ndr.sensor_keys` via `ALTER TABLE UPDATE`.
3. Fetches `key_prefix` by id via `ch_storage.get_sensor_key_prefix_by_id(id)`.
4. Calls `sensor_key_cache.invalidate_by_prefix(prefix)` — immediately removes all Redis cache entries matching `sensorkey:{prefix}*` using a SCAN+DEL loop.

**Why invalidate Redis immediately?**  
The Redis cache has a 90-second TTL. Without immediate invalidation, a revoked key would continue authenticating sensors for up to 90 seconds after revocation. The `invalidate_by_prefix` call makes the revocation effective on the **next request** across all engine instances.

---

### 2.10 Rust Handler: `reactivate_sensor_key_api()` — line 6929

File: `rust/ndr-engine/src/api/mod.rs`

**Only `super_admin` can reactivate.** Sets `active = 1` in `ndr.sensor_keys` via `ALTER TABLE UPDATE`. No cache action needed — the next sensor request will naturally populate the cache from the DB.

---

### 2.11 `generate_sensor_key()` — line 6701

File: `rust/ndr-engine/src/api/mod.rs`

```
plain  = "NDR-{tenant_id}-{32 random alphanumeric chars}"
prefix = plain[0..16]   ← first 16 chars, used as the lookup index
hash   = bcrypt(plain, cost=10)
```

The prefix allows a fast ClickHouse lookup (`WHERE key_prefix = '...'`) without scanning the full key column. Then bcrypt verifies the full plain key against the stored hash — the prefix alone is not enough to authenticate.

---

### 2.12 Redis Sensor Key Cache

File: `rust/ndr-engine/src/auth/sensor_cache.rs`

| Redis Key | Value | TTL | Purpose |
|-----------|-------|-----|---------|
| `sensorkey:{full_api_key}` | JSON `{ tenant_id, key_prefix, active }` | 90 seconds | Sensor auth fast path — avoids bcrypt+DB on every request |
| `sensor_hb:{sensor_id}` | status signature string | 300 seconds | Heartbeat dedup — prevents ClickHouse write on every checkin when status is unchanged |

**Resolution flow (`resolve_tenant()` — line 216):**

```
Incoming sensor request with X-Sensor-Key header
  ↓
Redis GET sensorkey:{key}
  ├── HIT  → return tenant_id immediately (no DB, no bcrypt)
  └── MISS
        ↓
        ClickHouse SELECT WHERE key_prefix = key[0..16]  (fast index lookup)
          ↓
          bcrypt.verify(plain_key, stored_hash)
            ├── FAIL → return None (sensor rejected)
            └── OK   → cache result in Redis (SET sensorkey:{key} ... EX 90)
                         return tenant_id
```

**Cache invalidation on revoke:**  
`invalidate_by_prefix(prefix)` runs `SCAN MATCH sensorkey:{prefix}* COUNT 100` in a cursor loop and `DEL` each matching key. This works even though the full plain key is not stored in the DB — the prefix (first 16 chars) is enough to find and remove the cache entry.

**Background health loop (`spawn_refresh_loop()` — line 168):**  
Runs every 60 seconds. Counts `active = 1` rows in `ndr.sensor_keys` and confirms Redis is reachable. Logs both values at `DEBUG` level. This is a health-check, not a cache preload — plain keys are never stored so bulk-preload is impossible.

---

### 2.13 ClickHouse Table: `ndr.sensor_keys`

File: `rust/ndr-engine/src/storage/clickhouse.rs`

| Column | Type | Description |
|--------|------|-------------|
| `id` | `String` (UUID) | Primary identifier |
| `key_hash` | `String` | bcrypt hash of the full plain key — never returned to any API |
| `key_prefix` | `String` | First 16 characters of the plain key — used as lookup index |
| `tenant_id` | `String` | Which tenant owns this sensor key |
| `name` | `String` | Human-readable label set by the admin (e.g. "Office-Router-1") |
| `hostname` | `String` | Filled in when the sensor calls `/api/sensor/register` |
| `interface_name` | `String` | Network interface being captured (e.g. `eth0`) |
| `os_name` | `String` | Operating system string (e.g. `Ubuntu 22.04`) |
| `agent_z_status` | `String` | Agent-Z service status: `running` / `stopped` / `unknown` |
| `agent_s_status` | `String` | Agent-S service status |
| `vector_status` | `String` | Vector log shipper status |
| `arkime_status` | `String` | Arkime PCAP viewer status |
| `arkime_url` | `String` | URL to reach the Arkime UI on this sensor |
| `arkime_pass` | `String` | Arkime viewer password (for the admin to open PCAP sessions) |
| `active` | `UInt8` | `1` = active, `0` = revoked |
| `created_at` | `DateTime` | When the key was created |
| `last_seen` | `DateTime` | Timestamp of the last successful heartbeat from the sensor |

**ClickHouse uses `ReplacingMergeTree` for this table.**  
Updates (revoke, reactivate, registration, heartbeat) are INSERT statements that duplicate the row with the new values. `SELECT ... FINAL` deduplicates on read, returning only the latest version of each row. This is why all queries use `FINAL`.

---

### 2.14 Storage Functions

File: `rust/ndr-engine/src/storage/clickhouse.rs`

| Function | Line | SQL Operation | Description |
|----------|------|---------------|-------------|
| `create_sensor_key()` | 3443 | `INSERT INTO ndr.sensor_keys (id, key_hash, key_prefix, tenant_id, name)` | Creates a new key record |
| `validate_sensor_key()` | 3461 | `SELECT key_hash, tenant_id, active FROM ndr.sensor_keys FINAL WHERE key_prefix = ?` | Bcrypt verify path on cache miss |
| `get_sensor_keys()` | 3494 | `SELECT 16 columns FROM ndr.sensor_keys FINAL WHERE tenant_id = ? ORDER BY created_at DESC` | Returns key list for the admin UI |
| `revoke_sensor_key()` | 3922 | `ALTER TABLE ndr.sensor_keys UPDATE active = 0 WHERE id = ?` | Disables a key |
| `get_sensor_key_prefix_by_id()` | 3939 | `SELECT key_prefix FROM ndr.sensor_keys FINAL WHERE id = ?` | Used to find prefix for cache invalidation after revoke |
| `reactivate_sensor_key()` | 3958 | `ALTER TABLE ndr.sensor_keys UPDATE active = 1 WHERE id = ?` | Re-enables a revoked key |

---

## Part 3 — Full Data Flow Diagrams

### Create Sensor Key

```
Admin fills form (tenant + name)
  → createSensorKey()                         engines.ts:55
  → api.createSensorKey(tenantId, name)       api.ts:603
  → POST /api/sensor-keys  (withCredentials, ndr_token cookie)
  → authInterceptor                           auth-interceptor.ts
  → Actix-Web router                          main.rs:830
  → create_sensor_key_api()                   api/mod.rs:6831
      → extract_claims() — validate JWT
      → role check (super_admin or own tenant)
      → generate_sensor_key()                 api/mod.rs:6701
          → 32-char random string
          → plain = "NDR-{tenant_id}-{random}"
          → prefix = plain[0..16]
          → hash = bcrypt(plain, cost=10)
      → ch_storage.create_sensor_key()        clickhouse.rs:3443
          → INSERT INTO ndr.sensor_keys
  → HTTP 200: { status:"ok", key: plain, id: uuid }
  → Angular: store createdSensorKey           sensors.ts:65
  → showSensorKeyModal = true                 (key shown once)
  → loadSensorKeys()                          (refresh list)
```

### Revoke Sensor Key

```
Admin clicks Revoke → confirm modal
  → revokeSensorKey(key)                      sensors.ts:82
  → api.revokeSensorKey(key.id)               api.ts:610
  → DELETE /api/sensor-keys/:id
  → revoke_sensor_key_api()                   api/mod.rs:6899
      → role check: super_admin only
      → ch_storage.revoke_sensor_key(id)      clickhouse.rs:3922
          → ALTER TABLE ndr.sensor_keys UPDATE active = 0
      → ch_storage.get_sensor_key_prefix_by_id(id)  clickhouse.rs:3939
      → sensor_key_cache.invalidate_by_prefix(prefix)
          → Redis SCAN sensorkey:{prefix}* → DEL each hit
  → HTTP 200: { status:"ok" }
  → Angular: key.active = false               (local update, no reload)
```

### Scale Up Engine

```
Admin clicks Scale Up
  → scaleUp()                                 engines.ts:67
  → api.scaleEngines('up')                    api.ts:582
  → POST /api/admin/engines/scale  { action:"up" }
  → scale_engines()                           api/mod.rs:6145
      → require_super_admin()
      → docker ps → count running engines (N)
      → new name = ndr-engine-{N+1}
      → bash script:
          docker inspect blueprint → clone image/nets/binds/envs
          docker run -d --name ndr-engine-{N+1} ...
          docker network connect (extra networks)
      → kafka-topics.sh --alter --partitions {N+1}
      → sed nginx.conf → add new upstream entries
      → docker exec ndr-nginx nginx -s reload
  → HTTP 200: { status:"ok", engine, kafka, nginx }
  → setTimeout(loadEngines, 3000)             engines.ts:73
```

---

## Part 4 — Error Handling

| Scenario | HTTP | Backend code | Angular reaction |
|----------|------|--------------|-----------------|
| Non-super_admin calls GET /api/admin/engines | 403 | `require_super_admin` | `showMsg('Failed to load engines', 'error')` — engines.ts:63 |
| Scale up with no blueprint container | 500 | `"No running engine found as blueprint"` | Toast error with message |
| Sensor key creation: blank tenant or name | 200 | `{ status:"error", message:"tenant_id and name are required" }` | `showMsg(...)` — sensors.ts:58 |
| tenant_admin creates key for different tenant | 200 | `{ status:"error", message:"Forbidden: tenant admins can only create..." }` | Toast error |
| Revoke called by non-super_admin | 200 | `{ status:"error", message:"Forbidden: Only super_admin can revoke..." }` | Toast error |
| Kafka status unreachable (docker exec fails) | 200 | Empty arrays, broker `"unreachable"` | kafkaData shows brokers as unreachable |
| Sync community rules already running | 200 | `{ status:"already_running" }` | `syncMessage` set to the returned message |

---

## Part 5 — Role-Based Differences

| Operation | super_admin | tenant_admin | analyst/viewer |
|-----------|-------------|--------------|----------------|
| GET /api/admin/engines | Allowed | 403 | 403 |
| POST /api/admin/engines/scale | Allowed | 403 | 403 |
| GET /api/monitor/kafka | Allowed | 403 | 403 |
| POST /api/rules/sync-community | Allowed | 403 | 403 |
| GET /api/sensor-keys | Returns ALL tenants' keys | Returns own tenant's keys only | 403 |
| POST /api/sensor-keys | Can create for any tenant | Can create for own tenant only | 403 |
| DELETE /api/sensor-keys/:id | Allowed | 403 | 403 |
| POST /api/sensor-keys/:id/reactivate | Allowed | 403 | 403 |

---

## Part 6 — Key Design Decisions

- **Why bcrypt the sensor key?**  
  Sensor keys are long-lived credentials that authenticate Agent-S and Agent-Z sensors. If the database were breached, bcrypt hashing means attackers cannot extract working keys from the stored hashes.

- **Why store only the prefix, not the full key?**  
  The full key is a secret. Storing only the first 16 characters (prefix) allows a fast indexed lookup without storing anything that could be used to authenticate. The bcrypt verify step uses the full plain key submitted on the request.

- **Why a shared Redis cache instead of in-memory per engine?**  
  When running multiple NDR Engine instances behind Nginx, each instance has its own in-memory state. A key revoked on one engine would still be cached in memory on the others. Redis is shared across all instances, so revocation is immediately visible to every engine on the next request.

- **Why scale Kafka partitions to match engine count?**  
  The `ndr-engine-group` consumer group assigns one partition per consumer instance. If there are 2 engines but only 1 partition, one engine is idle. Matching partition count to engine count ensures every engine processes traffic.

- **Why remove from Nginx before stopping a container?**  
  Nginx upstream health checks have a `fail_timeout=30s` window. If the container is stopped first, Nginx continues routing requests to it for up to 30 seconds, causing 502 errors. Updating the config and reloading Nginx before stopping prevents any dropped requests.

---

*Powered by PromaSecure*
