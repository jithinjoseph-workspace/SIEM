// Dedup check — SET NX log_id in Valkey before inserting to ClickHouse
// Prevents double-insert on Kafka redelivery after replica crash (T-IDEM-02)

use tracing::{debug, warn};

const DEDUP_TTL_SECS: u64 = 86_400; // 24h — covers any realistic Kafka redelivery window

/// Returns true if this log_id is new (safe to insert).
/// Returns false if already seen (skip — duplicate).
pub async fn is_new(log_id: &str, valkey_url: &str) -> bool {
    let client = match redis::Client::open(valkey_url) {
        Ok(c) => c,
        Err(e) => {
            warn!("Dedup Valkey connect error: {e} — allowing insert");
            return true; // fail-open: inserting a duplicate is safer than data loss
        }
    };
    let mut conn = match client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Dedup Valkey conn error: {e} — allowing insert");
            return true;
        }
    };

    let key = format!("siem:dedup:{log_id}");
    // SET NX returns "OK" (Some) if key was newly set, nil (None) if key already existed.
    // Must use Option<String> — bool would fail on the Status("OK") response at runtime.
    let set: redis::RedisResult<Option<String>> = redis::cmd("SET")
        .arg(&key)
        .arg(1u8)
        .arg("NX")
        .arg("EX")
        .arg(DEDUP_TTL_SECS)
        .query_async(&mut conn)
        .await;

    match set {
        Ok(Some(_)) => {
            debug!("Dedup: new log_id {log_id}");
            true
        }
        Ok(None) => {
            debug!("Dedup: duplicate log_id {log_id} — skipping");
            false
        }
        Err(e) => {
            warn!("Dedup SET NX error: {e} — allowing insert");
            true // fail-open
        }
    }
}

/// Call when a ClickHouse insert fails — removes the dedup key so Kafka redelivery can retry.
pub async fn unmark(log_id: &str, valkey_url: &str) {
    let Ok(client) = redis::Client::open(valkey_url) else { return };
    let Ok(mut conn) = client.get_multiplexed_async_connection().await else { return };
    let key = format!("siem:dedup:{log_id}");
    let _: redis::RedisResult<()> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;
    debug!("Dedup: unmarked {log_id} after failed insert — will retry on Kafka redelivery");
}
