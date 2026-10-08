// SIEM Correlation Engine — Living Genome Fitness Scorer
// Runs at 02:00 UTC daily under a Valkey distributed lock (one leader only).
// Scores each rule 0.0–1.0 based on true-positive rate, suppression rate, and
// average time-to-resolve. Writes scores to ndr.siem_rule_fitness.
// Low-fitness rules (score < 0.2) are flagged with a WARN log for admin review.
// License: Apache-2.0

use anyhow::Result;
use clickhouse::Client;
use chrono::{Utc, Timelike};
use serde::Deserialize;

use crate::correlation::types::GenomeFitness;

// ─────────────────────────────────────────────────────────────────────────────
// Distributed lock
// ─────────────────────────────────────────────────────────────────────────────

const GENOME_LOCK_KEY: &str  = "siem:genome:lock";
const GENOME_LOCK_TTL: usize = 3600; // 1 hour — enough to complete scoring

// ─────────────────────────────────────────────────────────────────────────────
// ClickHouse query rows
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, clickhouse::Row)]
struct RuleStat {
    rule_id:              String,
    tenant_id:            String,
    total_alerts:         u64,
    resolved_count:       u64,
    suppressed_count:     u64,
    avg_resolve_minutes:  f64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Background scorer task
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn the Living Genome scorer.
/// Wakes at 02:00 UTC every day. Only the instance that wins the Valkey lock runs.
pub fn spawn_genome_scorer(ch: Client, redis_url: String) {
    tokio::spawn(async move {
        let redis_client = match redis::Client::open(redis_url) {
            Ok(c)  => c,
            Err(e) => {
                tracing::error!("Genome scorer: Redis connect failed: {}", e);
                return;
            }
        };
        let mut conn = match redis_client.get_multiplexed_async_connection().await {
            Ok(c)  => c,
            Err(e) => {
                tracing::error!("Genome scorer: Redis connection failed: {}", e);
                return;
            }
        };

        loop {
            // Sleep until the next 02:00 UTC
            let sleep_secs = secs_until_02_utc();
            tracing::debug!("Genome scorer: sleeping {}s until 02:00 UTC", sleep_secs);
            tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;

            // Try to acquire the distributed lock (SET NX EX 3600)
            let acquired: Option<String> = match redis::cmd("SET")
                .arg(GENOME_LOCK_KEY)
                .arg("1")
                .arg("NX")
                .arg("EX")
                .arg(GENOME_LOCK_TTL)
                .query_async(&mut conn)
                .await
            {
                Ok(v)  => v,
                Err(e) => {
                    tracing::warn!("Genome scorer: lock acquire failed: {}", e);
                    None
                }
            };

            if acquired.is_none() {
                tracing::info!("Genome scorer: lock held by another instance — skipping");
                // Sleep an extra hour to avoid busy-looping at 02:00
                tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
                continue;
            }

            tracing::info!("Genome scorer: acquired lock — starting fitness scoring");

            match run_fitness_scoring(&ch).await {
                Ok(count) => tracing::info!("Genome scorer: scored {} rule-tenant pairs", count),
                Err(e)    => tracing::error!("Genome scorer: scoring failed: {}", e),
            }

            // Release lock (best-effort — it'll expire anyway)
            let _: redis::RedisResult<()> = redis::cmd("DEL")
                .arg(GENOME_LOCK_KEY)
                .query_async(&mut conn)
                .await;

            // Sleep 1 hour to avoid re-running immediately at 02:01
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Fitness scoring logic
// ─────────────────────────────────────────────────────────────────────────────

fn tenant_db(tenant_id: &str) -> String {
    if tenant_id == "default" || tenant_id.is_empty() {
        "ndr".to_string()
    } else {
        format!("ndr_{}", tenant_id.replace('-', "_"))
    }
}

/// Score all rules across all tenants and write results to siem_rule_fitness.
/// Returns the number of rule-tenant pairs scored.
async fn run_fitness_scoring(ch: &Client) -> Result<usize> {
    // Get all tenant IDs to scan each per-tenant unified_alerts table
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct TRow { id: String }
    let tenant_ids: Vec<String> = ch
        .query("SELECT id FROM ndr.tenants FINAL")
        .fetch_all::<TRow>().await.unwrap_or_default()
        .into_iter().map(|r| r.id).collect();

    let mut dbs: Vec<String> = vec!["ndr".to_string()];
    for tid in &tenant_ids {
        let db = tenant_db(tid);
        if !dbs.contains(&db) { dbs.push(db); }
    }

    let mut stats: Vec<RuleStat> = vec![];
    for db in &dbs {
        let sql = format!(r#"
            SELECT
                rule_id,
                tenant_id,
                count()                                              AS total_alerts,
                countIf(status IN ('Resolved', 'Closed'))           AS resolved_count,
                countIf(status = 'Suppressed')                      AS suppressed_count,
                avg(
                    if(
                        status IN ('Resolved', 'Closed') AND updated_at > created_at,
                        dateDiff('minute', created_at, updated_at),
                        0
                    )
                )                                                    AS avg_resolve_minutes
            FROM {db}.unified_alerts FINAL
            WHERE source = 'corroborated'
              AND created_at >= now() - INTERVAL 30 DAY
              AND rule_id != ''
            GROUP BY rule_id, tenant_id
        "#, db = db);
        let mut db_stats: Vec<RuleStat> = ch.query(&sql).fetch_all().await.unwrap_or_default();
        stats.append(&mut db_stats);
    }
    let count = stats.len();

    let scored_at = Utc::now();
    let mut insert = ch.insert("ndr.siem_rule_fitness")?;

    for stat in &stats {
        let fitness = compute_fitness(stat);

        if fitness.fitness_score < 0.2 {
            tracing::warn!(
                rule_id = %stat.rule_id,
                tenant  = %stat.tenant_id,
                score   = %fitness.fitness_score,
                "Living Genome: LOW fitness rule flagged for admin review \
                 (score={:.3}, suppression_rate={:.1}%, true_positive_rate={:.1}%)",
                fitness.fitness_score,
                fitness.suppression_rate * 100.0,
                fitness.true_positive_rate * 100.0,
            );
        }

        // Write to siem_rule_fitness
        insert.write(&GenomeFitnessRow {
            rule_id:              fitness.rule_id.clone(),
            tenant_id:            fitness.tenant_id.clone(),
            fitness_score:        fitness.fitness_score,
            true_positive_rate:   fitness.true_positive_rate,
            suppression_rate:     fitness.suppression_rate,
            avg_resolve_minutes:  fitness.avg_resolve_minutes,
            alert_count:          fitness.alert_count,
            scored_at:            scored_at.timestamp() as u32,
        }).await?;
    }

    insert.end().await?;
    Ok(count)
}

/// Compute a 0.0–1.0 fitness score for a rule given its 30-day stats.
///
/// Formula:
///   true_positive_rate  = resolved_count / total_alerts   (want HIGH)
///   suppression_rate    = suppressed_count / total_alerts  (want LOW)
///   avg_resolve_penalty = capped at 1.0 from avg_resolve_minutes / 1440
///
///   fitness = 0.6 × true_positive_rate
///           + 0.3 × (1.0 - suppression_rate)
///           + 0.1 × (1.0 - avg_resolve_penalty)
///
fn compute_fitness(stat: &RuleStat) -> GenomeFitness {
    let total = stat.total_alerts.max(1) as f64;

    let true_positive_rate = (stat.resolved_count as f64 / total).clamp(0.0, 1.0) as f32;
    let suppression_rate   = (stat.suppressed_count as f64 / total).clamp(0.0, 1.0) as f32;

    // Penalise slow resolution: 0 = instant, 1 = 24h+ (cap at 1.0)
    let avg_resolve_penalty = (stat.avg_resolve_minutes / 1440.0).clamp(0.0, 1.0) as f32;

    let fitness_score = (0.6 * true_positive_rate as f64
        + 0.3 * (1.0 - suppression_rate as f64)
        + 0.1 * (1.0 - avg_resolve_penalty as f64))
        .clamp(0.0, 1.0) as f32;

    GenomeFitness {
        rule_id:             stat.rule_id.clone(),
        tenant_id:           stat.tenant_id.clone(),
        fitness_score,
        true_positive_rate,
        suppression_rate,
        avg_resolve_minutes: stat.avg_resolve_minutes as f32,
        alert_count:         stat.total_alerts,
        scored_at:           Utc::now(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClickHouse INSERT row for siem_rule_fitness
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, clickhouse::Row, serde::Serialize)]
struct GenomeFitnessRow {
    rule_id:             String,
    tenant_id:           String,
    fitness_score:       f32,
    true_positive_rate:  f32,
    suppression_rate:    f32,
    avg_resolve_minutes: f32,
    alert_count:         u64,
    scored_at:           u32,  // Unix timestamp
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: compute seconds until next 02:00 UTC
// ─────────────────────────────────────────────────────────────────────────────

fn secs_until_02_utc() -> u64 {
    let now      = Utc::now();
    let hour     = now.hour();
    let minute   = now.minute();
    let second   = now.second();
    let current_day_secs = (hour * 3600 + minute * 60 + second) as i64;
    let target_secs: i64 = 2 * 3600; // 02:00:00

    let secs_remaining = if current_day_secs < target_secs {
        target_secs - current_day_secs
    } else {
        // Already past 02:00 today — wait until tomorrow's 02:00
        86400 - current_day_secs + target_secs
    };

    secs_remaining.max(1) as u64
}
