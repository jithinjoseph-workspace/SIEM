// SIEM Correlation Engine — UEBA (User and Entity Behaviour Analytics)
// 7-day rolling baseline stored as Valkey sorted sets.
// Metrics: login_count, bytes_out, dst_ip_count per tenant+entity+hour-bucket.
// Peer groups: same department field or same /24 subnet.
// Anomaly threshold: Z-score > 3.0 triggers Rule 10 (C2 beacon) supplement.
// License: Apache-2.0

use anyhow::Result;
use redis::AsyncCommands;
use chrono::{Timelike, Utc};

use crate::correlation::types::SiemEvent;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// 7 days × 24 hours = 168 hourly buckets retained
const BASELINE_WINDOW_HOURS: i64 = 168;
const BASELINE_TTL_SECS: usize   = 8 * 24 * 3600; // 8 days (slight buffer over window)

/// Business hours (UTC): 08:00–18:00
pub const BUSINESS_HOUR_START: u32 = 8;
pub const BUSINESS_HOUR_END:   u32 = 18;

/// Anomaly Z-score threshold: observations this many std-devs above mean are flagged
const ANOMALY_THRESHOLD: f64 = 3.0;

// ─────────────────────────────────────────────────────────────────────────────
// Metric types tracked
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UebaMetric {
    LoginCountPerHour,
    BytesOutPerHour,
    DstIpCountPerHour,
}

impl UebaMetric {
    pub fn as_str(self) -> &'static str {
        match self {
            UebaMetric::LoginCountPerHour  => "login_count",
            UebaMetric::BytesOutPerHour    => "bytes_out",
            UebaMetric::DstIpCountPerHour  => "dst_ip_count",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Update the rolling UEBA baseline for a single event.
/// Returns `Some(description)` if the observed value is anomalous (Z > 3.0).
pub async fn update_and_check<C>(
    conn:  &mut C,
    event: &SiemEvent,
) -> Result<Vec<String>>
where
    C: AsyncCommands,
{
    let mut anomalies = Vec::new();
    let now = Utc::now();
    let hour_bucket = now.timestamp() / 3600; // Unix hour number

    let entity = entity_key(event);
    if entity.is_empty() { return Ok(anomalies); }

    // ── Metric 1: Login count ────────────────────────────────────────────────
    if event.event_type == "authentication" {
        let obs = increment_metric(
            conn, &event.tenant_id, &entity,
            UebaMetric::LoginCountPerHour, hour_bucket, 1.0,
        ).await?;

        let baseline = get_baseline(
            conn, &event.tenant_id, &entity,
            UebaMetric::LoginCountPerHour, hour_bucket,
        ).await?;

        if let Some(desc) = check_anomaly(UebaMetric::LoginCountPerHour, obs, &baseline) {
            anomalies.push(desc);
        }
    }

    // ── Metric 2: Bytes out ──────────────────────────────────────────────────
    if let Some(bytes) = event.bytes_out {
        let obs = increment_metric(
            conn, &event.tenant_id, &entity,
            UebaMetric::BytesOutPerHour, hour_bucket, bytes as f64,
        ).await?;

        let baseline = get_baseline(
            conn, &event.tenant_id, &entity,
            UebaMetric::BytesOutPerHour, hour_bucket,
        ).await?;

        if let Some(desc) = check_anomaly(UebaMetric::BytesOutPerHour, obs, &baseline) {
            anomalies.push(desc);
        }
    }

    // ── Metric 3: Distinct destination IPs ──────────────────────────────────
    if let (Some(dst), Some(src)) = (&event.dst_ip_token, &event.src_ip_token) {
        // We use a HyperLogLog (PFADD) for cardinality counting
        let hll_key = format!(
            "siem:ueba:{}:{}:dst_hll:{}",
            event.tenant_id, src, hour_bucket
        );
        let _: () = conn.pfadd(&hll_key, dst).await?;
        let _: () = conn.expire(&hll_key, BASELINE_TTL_SECS).await?;
        let count: u64 = conn.pfcount(&hll_key).await?;

        let baseline = get_baseline(
            conn, &event.tenant_id, entity_key(event).as_str(),
            UebaMetric::DstIpCountPerHour, hour_bucket,
        ).await?;

        // Store current count for baseline
        let metric_key = sorted_set_key(
            &event.tenant_id, &entity, UebaMetric::DstIpCountPerHour
        );
        let _: () = conn.zadd(&metric_key, count as f64, hour_bucket).await?;
        let _: () = conn.expire(&metric_key, BASELINE_TTL_SECS).await?;

        if let Some(desc) = check_anomaly(UebaMetric::DstIpCountPerHour, count as f64, &baseline) {
            anomalies.push(desc);
        }
    }

    Ok(anomalies)
}

/// Check if the current hour is within business hours (UTC).
pub fn is_business_hours() -> bool {
    let hour = Utc::now().hour();
    hour >= BUSINESS_HOUR_START && hour < BUSINESS_HOUR_END
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Increment an hourly metric bucket in a sorted set (score = cumulative value).
/// Returns the new bucket total.
async fn increment_metric<C>(
    conn:        &mut C,
    tenant_id:   &str,
    entity:      &str,
    metric:      UebaMetric,
    hour_bucket: i64,
    delta:       f64,
) -> Result<f64>
where
    C: AsyncCommands,
{
    let key = sorted_set_key(tenant_id, entity, metric);
    // ZINCRBY key delta member — atomically adds delta to the score of member
    let new_score: f64 = conn.zincr(&key, hour_bucket, delta).await?;
    // Refresh TTL on each write
    let _: () = conn.expire(&key, BASELINE_TTL_SECS).await?;
    // Prune buckets older than 7 days
    let cutoff = Utc::now().timestamp() / 3600 - BASELINE_WINDOW_HOURS;
    let _: () = conn.zrembyscore(&key, i64::MIN as f64, cutoff as f64).await?;
    Ok(new_score)
}

/// Baseline statistics (mean + std_dev) over all historical hour buckets
/// within the 7-day window, excluding the current hour.
struct Baseline {
    mean:    f64,
    std_dev: f64,
    count:   usize,
}

async fn get_baseline<C>(
    conn:        &mut C,
    tenant_id:   &str,
    entity:      &str,
    metric:      UebaMetric,
    current_hour: i64,
) -> Result<Baseline>
where
    C: AsyncCommands,
{
    let key = sorted_set_key(tenant_id, entity, metric);
    let cutoff = current_hour - BASELINE_WINDOW_HOURS;

    // Get all members (hour buckets) + scores (cumulative metric values) in the window
    // redis 0.23 ZRANGEBYSCORE WITHSCORES returns Vec<(member, score)>
    let raw: Vec<(f64, f64)> = conn.zrangebyscore_withscores(
        &key,
        cutoff as f64,
        (current_hour - 1) as f64,
    ).await.unwrap_or_default();

    let values: Vec<f64> = raw.into_iter().map(|(_member, score)| score).collect();
    let count = values.len();

    if count == 0 {
        return Ok(Baseline { mean: 0.0, std_dev: 0.0, count: 0 });
    }

    let mean = values.iter().sum::<f64>() / count as f64;
    let variance = values.iter()
        .map(|v| (v - mean).powi(2))
        .sum::<f64>() / count as f64;
    let std_dev = variance.sqrt();

    Ok(Baseline { mean, std_dev, count })
}

/// Check if the observed value is anomalous (Z-score > ANOMALY_THRESHOLD).
fn check_anomaly(metric: UebaMetric, observed: f64, baseline: &Baseline) -> Option<String> {
    // Need at least 24 data points (1 day) before flagging
    if baseline.count < 24 { return None; }
    if baseline.std_dev < 1e-6 { return None; } // no variance = no anomaly scoring

    let z_score = (observed - baseline.mean) / baseline.std_dev;
    if z_score > ANOMALY_THRESHOLD {
        Some(format!(
            "UEBA anomaly — {}: observed={:.1}, baseline mean={:.1} ±{:.1}, Z-score={:.2}",
            metric.as_str(), observed, baseline.mean, baseline.std_dev, z_score
        ))
    } else {
        None
    }
}

/// Build the sorted-set key for a UEBA metric.
fn sorted_set_key(tenant_id: &str, entity: &str, metric: UebaMetric) -> String {
    format!("siem:ueba:{}:{}:{}", tenant_id, entity, metric.as_str())
}

/// Derive the entity string from an event (username > hostname > src_ip_token).
fn entity_key(event: &SiemEvent) -> String {
    event.username.clone()
        .or_else(|| event.hostname.clone())
        .or_else(|| event.src_ip_token.clone())
        .unwrap_or_default()
}

/// Extract the /24 subnet from a src_ip_token string (best-effort peer group).
/// The token is an HMAC so we can't recover the real IP; instead we use the
/// department field or the subnet field enriched at ingest time.
pub fn peer_group(event: &SiemEvent) -> String {
    if let Some(ref dept) = event.department {
        return format!("dept:{}", dept);
    }
    if let Some(ref subnet) = event.subnet {
        return format!("subnet:{}", subnet);
    }
    "global".to_string()
}
