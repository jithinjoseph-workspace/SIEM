// SIEM Correlation Engine — Alert Deduplication (Valkey)
// Key: siem:alert:dedup:{rule_id}:{tenant_id}:{hostname_or_src}
// TTL: 5 minutes (300 seconds)
// If key exists  → update existing alert's updated_at in ClickHouse
// If key missing → create a new alert
// License: Apache-2.0

use anyhow::Result;
use redis::AsyncCommands;

pub const DEDUP_TTL_SECS: u64 = 300; // 5 minutes

pub enum DedupResult {
    /// New alert — caller should INSERT into ClickHouse
    New,
    /// Duplicate — caller should UPDATE existing alert
    Duplicate { alert_id: String },
}

/// Check Valkey dedup key. Returns `New` or `Duplicate { alert_id }`.
///
/// On `New`: atomically SET the key with the new `alert_id` value and 5-min TTL.
/// On `Duplicate`: the existing `alert_id` is returned for the UPDATE call.
pub async fn check_or_insert<C>(
    conn:     &mut C,
    rule_id:  &str,
    tenant_id: &str,
    entity:   &str,       // hostname, src_ip_token, or username — the "about" entity
    alert_id: &str,       // the NEW alert_id to store if this is the first occurrence
) -> Result<DedupResult>
where
    C: AsyncCommands,
{
    let key = dedup_key(rule_id, tenant_id, entity);

    // SET key alert_id NX EX 300  (only sets if not already present)
    let set_result: Option<String> = redis::cmd("SET")
        .arg(&key)
        .arg(alert_id)
        .arg("NX")
        .arg("EX")
        .arg(DEDUP_TTL_SECS)
        .query_async(conn)
        .await?;

    if set_result.is_some() {
        // Key was newly set — this is a fresh alert
        Ok(DedupResult::New)
    } else {
        // Key already existed — fetch the stored alert_id
        let existing: String = conn.get(&key).await?;
        // Refresh TTL so the 5-min window stays alive
        let _: () = conn.expire(&key, DEDUP_TTL_SECS as usize).await?;
        Ok(DedupResult::Duplicate { alert_id: existing })
    }
}

/// Build the canonical Valkey dedup key.
pub fn dedup_key(rule_id: &str, tenant_id: &str, entity: &str) -> String {
    format!("siem:alert:dedup:{}:{}:{}", rule_id, tenant_id, entity)
}

/// Build a consistent "entity" string from an event's primary identifier.
/// Prefers hostname, falls back to src_ip_token, falls back to username.
pub fn entity_from_event(event: &crate::correlation::types::SiemEvent) -> String {
    event.hostname.clone()
        .or_else(|| event.src_ip_token.clone())
        .or_else(|| event.username.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Mark an alert's Valkey key as processed (idempotent offset tracking).
/// Used by the Kafka consumer for at-least-once → effectively-once semantics.
pub async fn mark_offset_processed<C>(
    conn:   &mut C,
    topic:  &str,
    partition: i32,
    offset: i64,
) -> Result<()>
where
    C: AsyncCommands,
{
    let key = format!("siem:processed:{}:{}:{}", topic, partition, offset);
    // Keep for 7 days — longer than any replay window we'd ever use
    let _: () = conn.set_ex(&key, 1u8, 604_800).await?;
    Ok(())
}

/// Returns true if this Kafka offset has already been processed.
pub async fn is_offset_processed<C>(
    conn:   &mut C,
    topic:  &str,
    partition: i32,
    offset: i64,
) -> bool
where
    C: AsyncCommands,
{
    let key = format!("siem:processed:{}:{}:{}", topic, partition, offset);
    let result: redis::RedisResult<Option<u8>> = conn.get(&key).await;
    result.ok().flatten().is_some()
}
