//! Shared (Redis-backed) cache for sensor API key → tenant_id lookups.
//!
//! All ndr-engine instances share ONE cache via Redis, so a key revocation
//! or new key is visible to every instance consistently — not just whichever
//! instance happens to refresh next. Engines remain stateless.
//!
//! Schema note: ndr.sensor_keys stores key_hash (bcrypt) + key_prefix, NOT
//! plain api_keys. So the cache can't be bulk-preloaded from DB. It is
//! populated on first use (bcrypt verify + DB lookup), then cached in Redis
//! with a TTL (default 900s). Revocation is immediate via invalidate().

use redis::AsyncCommands;
use std::sync::Arc;

const CACHE_PREFIX: &str = "sensorkey:";
// TTL slightly longer than the 60s refresh interval so entries don't
// expire between refresh cycles under normal operation.
//
// The TTL is long on purpose: every miss costs a ClickHouse lookup plus a bcrypt
// verify (~50 ms of CPU). At 3000 sensors a 90 s TTL meant ~33 verifies/s
// (about 2 cores) forever. Revocation does not wait for the TTL:
// invalidate_by_prefix() clears the entry immediately, so a longer TTL only
// changes how often a healthy key is re-verified. Override: SENSOR_KEY_CACHE_TTL_SECS.
const DEFAULT_CACHE_TTL_SECS: usize = 900;

fn cache_ttl_secs() -> usize {
    static TTL: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *TTL.get_or_init(|| {
        std::env::var("SENSOR_KEY_CACHE_TTL_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v >= 10)
            .unwrap_or(DEFAULT_CACHE_TTL_SECS)
    })
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SensorKeyInfo {
    pub tenant_id:  String,
    pub key_prefix: String,
    pub active:     bool,
}

pub struct SensorKeyCache {
    redis: Arc<redis::Client>,
}

impl SensorKeyCache {
    pub fn new(redis_client: Arc<redis::Client>) -> Self {
        Self { redis: redis_client }
    }

    /// Look up a sensor key in Redis. Returns None on cache miss OR on any
    /// Redis connectivity issue — caller always falls back to direct DB.
    pub async fn get(&self, api_key: &str) -> Option<SensorKeyInfo> {
        let mut conn = self.redis
            .get_multiplexed_async_connection()
            .await
            .ok()?;

        let redis_key = format!("{}{}", CACHE_PREFIX, api_key);
        let raw: Option<String> = conn.get(&redis_key).await.ok()?;
        raw.and_then(|s| serde_json::from_str(&s).ok())
    }

    /// Insert/update a single entry with TTL.
    /// Called on cache-miss fallback after successful bcrypt verify.
    pub async fn insert(&self, api_key: &str, info: &SensorKeyInfo) {
        let Ok(mut conn) = self.redis
            .get_multiplexed_async_connection()
            .await
        else {
            tracing::warn!("Redis unavailable — sensor key cache insert skipped");
            return;
        };

        let redis_key = format!("{}{}", CACHE_PREFIX, api_key);
        let Ok(json) = serde_json::to_string(info) else { return; };
        let _: Result<(), _> = conn.set_ex(&redis_key, json, cache_ttl_secs()).await;
    }

    /// Immediately remove a key from the shared Redis cache.
    /// Called when an admin revokes a sensor key so ALL engine instances
    /// reject it on their very next lookup, with no TTL wait.
    pub async fn invalidate(&self, api_key: &str) {
        let Ok(mut conn) = self.redis
            .get_multiplexed_async_connection()
            .await
        else {
            return;
        };

        let redis_key = format!("{}{}", CACHE_PREFIX, api_key);
        let _: Result<i64, _> = conn.del(&redis_key).await;

        tracing::info!(
            "Sensor key cache invalidated: {}…",
            &api_key[..api_key.len().min(16)]
        );
    }

    /// Invalidate all Redis cache entries for a given key_prefix.
    /// Called on key revocation — since plain api_keys are never stored in
    /// DB (only bcrypt hashes), we know the key_prefix (first 16 chars) and
    /// can SCAN+DEL all matching `sensorkey:{prefix}*` Redis entries.
    /// This removes the entry regardless of what the full plain key was.
    pub async fn invalidate_by_prefix(&self, key_prefix: &str) {
        let Ok(mut conn) = self.redis
            .get_multiplexed_async_connection()
            .await
        else {
            return;
        };

        let pattern = format!("{}{}*", CACHE_PREFIX, key_prefix);
        let mut cursor = 0u64;
        let mut deleted = 0u32;

        loop {
            // SCAN with MATCH — non-blocking cursor-based iteration
            let (new_cursor, keys): (u64, Vec<String>) =
                redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(100u32)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or((0, vec![]));

            for k in &keys {
                let _: Result<i64, _> = conn.del(k).await;
                deleted += 1;
            }

            cursor = new_cursor;
            if cursor == 0 { break; }
        }

        tracing::info!(
            "Sensor key cache: invalidated {} entr{} for prefix {}…",
            deleted,
            if deleted == 1 { "y" } else { "ies" },
            key_prefix
        );
    }

    /// Returns `true` if a heartbeat DB write (`last_seen` and the service statuses) is needed.
    ///
    /// A write happens when the status changed, on a sensor's first check-in, and again once
    /// the last write is SENSOR_HEARTBEAT_WRITE_SECS old (default 120 s), so `last_seen` stays
    /// fresh without a ClickHouse write on every 30 s check-in.
    ///
    /// The window is NOT extended by unchanged check-ins. It used to be: every check-in reset
    /// the 5-minute expiry, so a healthy sensor with a stable status was never written again
    /// and the UI (online = seen in the last few minutes) showed it as offline.
    pub async fn needs_heartbeat_write(&self, sensor_id: &str, status_sig: &str) -> bool {
        let mut conn = match self.redis
            .get_multiplexed_async_connection()
            .await
        {
            Ok(c) => c,
            Err(_) => return true, // Redis unavailable → always write
        };

        let key = format!("sensor_hb:{}", sensor_id);
        let cached = conn
            .get::<_, Option<String>>(&key)
            .await
            .unwrap_or(None);

        if cached.as_deref() == Some(status_sig) {
            return false; // same status, written less than one window ago
        }

        // Status changed, first check-in, or the window ran out: write now, start a new window.
        let _: Result<(), _> = conn.set_ex(&key, status_sig, heartbeat_write_secs()).await;
        true
    }
}

fn heartbeat_write_secs() -> usize {
    static SECS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SECS.get_or_init(|| {
        std::env::var("SENSOR_HEARTBEAT_WRITE_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v >= 30)
            .unwrap_or(120)
    })
}

/// Spawn a background health-check loop that logs DB active key count
/// every 60s and confirms Redis connectivity. Call once at startup.
///
/// Note: we cannot bulk-preload the cache because plain API keys are never
/// stored (only bcrypt hashes). Cache entries are populated on first use
/// and expire after 90s TTL. Revocation is handled immediately by
/// invalidate() called from the revoke-key handler.
pub fn spawn_refresh_loop(
    cache: Arc<SensorKeyCache>,
    ch_storage: Arc<crate::storage::ClickhouseStorage>,
) {
    tokio::spawn(async move {
        loop {
            // Count active keys in DB for health logging
            match count_active_keys(&ch_storage).await {
                Ok(n) => {
                    // Also confirm Redis is reachable
                    let redis_ok = cache.redis
                        .get_multiplexed_async_connection()
                        .await
                        .is_ok();
                    tracing::debug!(
                        "Sensor key cache health: {} active keys, redis_ok={}",
                        n, redis_ok
                    );
                }
                Err(e) => {
                    tracing::error!("Sensor key DB health check failed: {}", e);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
}

async fn count_active_keys(
    ch: &crate::storage::ClickhouseStorage,
) -> anyhow::Result<u64> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row { count: u64 }

    let rows = ch.client
        .query("SELECT count() as count FROM ndr.sensor_keys FINAL WHERE active = 1")
        .fetch_all::<Row>()
        .await?;

    Ok(rows.first().map(|r| r.count).unwrap_or(0))
}

/// Resolve a sensor API key to its tenant_id.
///
/// Fast path  (Redis hit)  : O(1), no DB, no bcrypt.
/// Slow path  (Redis miss) : full bcrypt+DB lookup (same cost as before),
///                           then the result is stored in SHARED Redis so
///                           every other engine instance benefits too.
pub async fn resolve_tenant(
    cache: &SensorKeyCache,
    ch: &crate::storage::ClickhouseStorage,
    api_key: &str,
) -> Option<String> {
    if api_key.is_empty() {
        return None;
    }

    // Fast path — shared Redis cache hit
    if let Some(info) = cache.get(api_key).await {
        if info.active {
            return Some(info.tenant_id);
        }
        return None;
    }

    // Slow path — cache miss: existing validate_sensor_key does prefix
    // lookup + bcrypt verify. Result is then cached in shared Redis so
    // every other engine instance benefits on subsequent requests.
    let tenant_id = ch.validate_sensor_key(api_key).await.ok()??;

    let info = SensorKeyInfo {
        tenant_id: tenant_id.clone(),
        key_prefix: api_key.chars().take(16).collect(),
        active: true,
    };
    cache.insert(api_key, &info).await;

    tracing::debug!(
        "Sensor key cache populated: prefix={}…",
        &api_key[..api_key.len().min(16)]
    );
    Some(tenant_id)
}

/// True when `api_key` is a real key that an admin has revoked (the bcrypt hash
/// matches an inactive row). An unknown or malformed key is NOT "revoked".
/// The verdict is cached (as an inactive entry) so a sensor that keeps
/// retrying costs one Redis read, not a DB query plus bcrypt, per request.
pub async fn is_revoked(
    cache: &SensorKeyCache,
    ch: &crate::storage::ClickhouseStorage,
    api_key: &str,
) -> bool {
    if api_key.len() < 16 {
        return false;
    }
    if let Some(info) = cache.get(api_key).await {
        return !info.active;
    }
    if !ch.is_revoked_sensor_key(api_key).await.unwrap_or(false) {
        return false;
    }
    let info = SensorKeyInfo {
        tenant_id: String::new(),
        key_prefix: api_key.chars().take(16).collect(),
        active: false,
    };
    cache.insert(api_key, &info).await;
    true
}

#[cfg(test)]
mod heartbeat_tests {
    use super::*;

    // Needs a real Redis: TEST_REDIS_URL (default: a throwaway DB 5 on localhost).
    // Run with: cargo test -p ndr-engine heartbeat -- --ignored
    #[tokio::test]
    #[ignore]
    async fn last_seen_is_written_on_a_schedule_not_only_when_status_changes() {
        let url = std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/5".into());
        let client = std::sync::Arc::new(redis::Client::open(url).unwrap());
        let cache = SensorKeyCache::new(client.clone());
        let id = format!("hbtest-{}", std::process::id());
        let key = format!("sensor_hb:{}", id);
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let _: Result<i64, _> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;

        assert!(cache.needs_heartbeat_write(&id, "up|up|up|up").await, "first check-in writes");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let before: i64 = redis::cmd("TTL").arg(&key).query_async(&mut conn).await.unwrap();
        assert!(!cache.needs_heartbeat_write(&id, "up|up|up|up").await, "same status right after: no write");
        let after: i64 = redis::cmd("TTL").arg(&key).query_async(&mut conn).await.unwrap();
        // The throttle window must keep counting down. When every check-in reset it, a sensor
        // whose status never changes (check-in every 30 s) was never written again and the UI
        // showed a healthy sensor as offline.
        assert!(after <= before, "a check-in reset the throttle window: {before}s -> {after}s");
        assert!(cache.needs_heartbeat_write(&id, "up|down|up|up").await, "a status change writes at once");
        let _: Result<i64, _> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;
    }
}
