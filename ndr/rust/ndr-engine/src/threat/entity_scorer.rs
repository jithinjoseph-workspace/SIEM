/// Entity Scorer — per-host accumulated risk scoring.
///
/// Every 5 minutes aggregates all ndr_hits from the last 24 hours per src_ip,
/// sums their scores, and upserts into ndr.entity_scores. The UI queries
/// GET /api/entity-scores to show a "Top Risky Hosts" panel.

use std::sync::Arc;
use tracing::{info, warn};

use crate::storage::ClickhouseStorage;

const REFRESH_SECS: u64 = 300; // 5 minutes
const WINDOW_HOURS: u32 = 24;

pub fn spawn_entity_scorer(
    ch:        Arc<ClickhouseStorage>,
    cache:     Arc<dashmap::DashMap<String, f32>>,
    is_leader: Arc<std::sync::atomic::AtomicBool>,
) {
    tokio::spawn(async move {
        // Run immediately on startup so the in-memory cache is pre-populated.
        // Previously delayed 60s, leaving entity_score=0 for all new hits in that window.
        //
        // Unlike the other 11 leader-gated tasks, this one is NOT skipped
        // wholesale on non-leader instances: `cache` also backs the
        // synchronous per-event entity_score lookup on the live Kafka
        // ingestion path (api/mod.rs), which every instance runs regardless
        // of leadership (Kafka consumer-group partitions are spread across
        // all 3, not just the leader). Gating this entire function behind
        // is_leader (an earlier fix here today) silently left followers'
        // caches permanently empty, so 2 of 3 engines quietly scored every
        // event they processed with entity_score=0 - the original bug this
        // task existed to prevent. is_leader is instead threaded down to
        // gate only the ndr.entity_scores ClickHouse upsert, which is the
        // part 3 engines genuinely shouldn't all do - the cache-refreshing
        // SELECT (a read, not a write) runs on every instance every cycle.
        run_refresh(&ch, &cache, &is_leader).await;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(REFRESH_SECS)).await;
            run_refresh(&ch, &cache, &is_leader).await;
        }
    });
}

async fn run_refresh(
    ch:        &Arc<ClickhouseStorage>,
    cache:     &Arc<dashmap::DashMap<String, f32>>,
    is_leader: &Arc<std::sync::atomic::AtomicBool>,
) {
    info!("entity_scorer: refreshing");
    let tenant_ids = ch.get_all_tenants().await
        .unwrap_or_else(|_| vec!["default".to_string()]);

    // Refresh all tenants concurrently (bounded, configurable via
    // TENANT_SCAN_CONCURRENCY) so a slow scan on one tenant doesn't push the
    // total past the 5-minute refresh window.
    let sem = Arc::new(tokio::sync::Semaphore::new(super::tenant_scan_concurrency()));
    let mut handles = Vec::with_capacity(tenant_ids.len());
    let write_scores = is_leader.load(std::sync::atomic::Ordering::Relaxed);
    for tenant_id in tenant_ids {
        let ch2    = ch.clone();
        let cache2 = cache.clone();
        let sem2   = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem2.acquire().await;
            if let Err(e) = refresh_tenant(&ch2, &tenant_id, &cache2, write_scores).await {
                warn!("entity_scorer: tenant {} failed — {}", tenant_id, e);
            }
        }));
    }
    futures_util::future::join_all(handles).await;
}

/// Alerts below this score are noise for the purpose of judging a HOST (INFO and LOW). They still
/// exist as alerts; they just do not make the host "risky".
const MIN_ENTITY_ALERT_SCORE: u32 = 40;

/// Per-host accumulated risk over the last `hours`.
///
/// It used to be `sum(score)` over every alert with score >= 20, with each alert counted once PER TAG
/// (so an alert with three tags counted three times). A host that merely made ~150 low-score DNS
/// alerts to 8.8.8.8 reached the cap (score/10, max 100), was labelled `compromised-host`, and then
/// got +20 on every later alert and was described to the AI as compromised: chatter fed itself.
/// Now each destination counts ONCE, at its worst alert score, only alerts scoring at least
/// MIN_ENTITY_ALERT_SCORE count, and trusted-cloud alerts are ignored. A host reaches "compromised"
/// (80) only by accumulating many DISTINCT serious detections.
pub(crate) fn entity_query(db: &str, tid: &str, hours: u32) -> String {
    format!(
        "SELECT
             src_ip,
             sum(g_score)                  AS accumulated_score,
             sum(g_count)                  AS alert_count,
             argMax(g_sev, g_score)        AS top_severity,
             groupUniqArrayArray(g_tags)   AS top_tags,
             max(g_last)                   AS last_seen
         FROM (
             SELECT src_ip, dst_ip,
                    max(score)                    AS g_score,
                    count()                       AS g_count,
                    argMax(severity, score)       AS g_sev,
                    groupUniqArrayArray(tags)     AS g_tags,
                    max(timestamp)                AS g_last
             FROM {db}.ndr_hits FINAL
             WHERE tenant_id = '{tid}'
               AND timestamp  > now() - INTERVAL {hours} HOUR
               AND src_ip    != ''
               AND score     >= {min}
               AND NOT has(tags, 'trusted-cloud')
             GROUP BY src_ip, dst_ip
         )
         GROUP BY src_ip
         HAVING accumulated_score > 0
         ORDER BY accumulated_score DESC
         LIMIT 100",
        db = db, tid = tid, hours = hours, min = MIN_ENTITY_ALERT_SCORE
    )
}

async fn refresh_tenant(
    ch:          &Arc<ClickhouseStorage>,
    tenant_id:   &str,
    cache:       &Arc<dashmap::DashMap<String, f32>>,
    write_scores: bool,
) -> anyhow::Result<()> {
    use crate::storage::clickhouse::{tenant_db_pub, sql_escape_pub};

    let db  = tenant_db_pub(tenant_id);
    let tid = sql_escape_pub(tenant_id);

    let select_q = entity_query(&db, &tid, WINDOW_HOURS);

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        src_ip:            String,
        accumulated_score: f64,
        alert_count:       u64,
        top_severity:      String,
        top_tags:          Vec<String>,
        last_seen:         u32, // ClickHouse DateTime as unix timestamp
    }

    let rows = ch.client.query(&select_q).fetch_all::<Row>().await?;

    if rows.is_empty() {
        return Ok(());
    }

    info!("entity_scorer: {} hosts for tenant {}", rows.len(), tenant_id);

    // Cache refresh runs on every instance regardless of leadership - see the
    // comment on spawn_entity_scorer. Only the ClickHouse upsert below is
    // leader-gated.
    for row in &rows {
        let normalized: f32 = (row.accumulated_score as f32 / 10.0).min(100.0);
        cache.insert(format!("{}:{}", tenant_id, row.src_ip), normalized);
    }

    if !write_scores {
        return Ok(());
    }

    // Collect rows for a single batch INSERT. Previously issued one INSERT
    // per host (up to 100 round-trips per tenant).
    #[derive(clickhouse::Row, serde::Serialize)]
    struct EntityScoreRow {
        src_ip:            String,
        tenant_id:         String,
        accumulated_score: f64,
        alert_count:       u64,
        top_severity:      String,
        top_tags:          Vec<String>,
        last_seen:         u32,
        updated_at:        u32,
    }

    let now_ts = chrono::Utc::now().timestamp() as u32;
    let table  = format!("{}.entity_scores", db);
    match ch.client.insert(&table) {
        Err(e) => {
            warn!("entity_scorer: failed to open insert for tenant {}: {}", tenant_id, e);
        }
        Ok(mut inserter) => {
            for row in &rows {
                let r = EntityScoreRow {
                    src_ip:            row.src_ip.clone(),
                    tenant_id:         tenant_id.to_string(),
                    accumulated_score: row.accumulated_score,
                    alert_count:       row.alert_count,
                    top_severity:      row.top_severity.clone(),
                    top_tags:          row.top_tags.clone(),
                    last_seen:         row.last_seen,
                    updated_at:        now_ts,
                };
                if let Err(e) = inserter.write(&r).await {
                    warn!("entity_scorer: write failed for {}: {}", row.src_ip, e);
                }
            }
            if let Err(e) = inserter.end().await {
                warn!("entity_scorer: batch commit failed for tenant {}: {}", tenant_id, e);
            }
        }
    }

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    // Against a real ClickHouse (a throwaway database, dropped at the end):
    //   CLICKHOUSE_URL=... CLICKHOUSE_USER=... CLICKHOUSE_PASSWORD=... \
    //   cargo test -p ndr-engine entity_query -- --ignored
    #[tokio::test]
    #[ignore]
    async fn chatter_no_longer_makes_a_host_compromised_but_real_detections_still_do() {
        let ch = crate::storage::ClickhouseStorage::new();
        let db = "ndr_zz_entitytest";
        let run = |q: String| { let c = ch.client.clone(); async move { c.query(&q).execute().await.unwrap() } };
        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db}")).execute().await;
        run(format!("CREATE DATABASE {db}")).await;
        run(format!("CREATE TABLE {db}.ndr_hits (tenant_id String, src_ip String, dst_ip String, score Float32, \
             severity String, tags Array(String), timestamp DateTime) ENGINE = ReplacingMergeTree ORDER BY (src_ip, dst_ip, timestamp)")).await;

        // 10.0.2.15: 145 DNS alerts to 8.8.8.8 at score 20 (this is the real pattern from the hosted site)
        // 10.0.9.9: 12 different destinations, threat-intel score 85
        // 10.0.5.5: 3 different destinations at score 60
        for i in 0..145 {
            run(format!("INSERT INTO {db}.ndr_hits VALUES ('t','10.0.2.15','8.8.8.8',20,'INFO',['protocol:dns','trusted-cloud','compromised-host'], now() - {i})")).await;
        }
        for d in 0..12 { run(format!("INSERT INTO {db}.ndr_hits VALUES ('t','10.0.9.9','203.0.113.{d}',85,'HIGH',['threat-intel'], now())")).await; }
        for d in 0..3  { run(format!("INSERT INTO {db}.ndr_hits VALUES ('t','10.0.5.5','198.51.100.{d}',60,'MEDIUM',['ids-alert'], now())")).await; }

        // the OLD scoring, kept here to show what the bug did
        let old = format!("SELECT src_ip, sum(score) AS a FROM (SELECT src_ip, score, arrayJoin(tags) AS tag FROM {db}.ndr_hits FINAL \
             WHERE tenant_id = 't' AND timestamp > now() - INTERVAL 24 HOUR AND src_ip != '' AND score >= 20) GROUP BY src_ip");
        let old_rows: Vec<(String, f64)> = ch.client.query(&old).fetch_all().await.unwrap();
        let old_norm = |ip: &str| old_rows.iter().find(|r| r.0 == ip).map(|r| (r.1 / 10.0).min(100.0)).unwrap_or(0.0);
        assert!(old_norm("10.0.2.15") >= 80.0, "the old query called the DNS-chatter host compromised: {}", old_norm("10.0.2.15"));

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct R { src_ip: String, accumulated_score: f64, alert_count: u64, top_severity: String, top_tags: Vec<String>, last_seen: u32 }
        let rows: Vec<R> = ch.client.query(&entity_query(db, "t", 24)).fetch_all().await.unwrap();
        let norm = |ip: &str| rows.iter().find(|r| r.src_ip == ip).map(|r| (r.accumulated_score as f32 / 10.0).min(100.0)).unwrap_or(0.0);
        assert_eq!(norm("10.0.2.15"), 0.0, "145 low-score DNS alerts to one resolver must not count at all");
        assert!(norm("10.0.9.9") >= 80.0, "12 distinct threat-intel destinations must still be compromised: {}", norm("10.0.9.9"));
        assert!((norm("10.0.5.5") - 18.0).abs() < 0.01, "3 destinations at 60 = 18: {}", norm("10.0.5.5"));
        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db}")).execute().await;
    }
}
