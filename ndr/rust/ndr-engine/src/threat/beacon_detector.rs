/// Beacon Detector — detects C2 beaconing even to trusted cloud infrastructure.
///
/// C2 malware "phones home" on a regular schedule. Normal human traffic to
/// AWS/Cloudflare is random and varied; C2 beacons are mechanical and regular.
/// This runs independently of the trusted-cloud suppression system so that
/// beaconing tagged hits are NEVER suppressed by trusted-cloud scoring.

use std::sync::Arc;
use tracing::{info, warn};

use crate::storage::ClickhouseStorage;

// Beacon score thresholds (0–100)
const BEACON_SCORE_THRESHOLD: f64 = 70.0;
// Minimum connections in window to bother scoring
const MIN_CONNS: u64 = 10;

fn beacon_window_hours() -> u32 {
    std::env::var("BEACON_WINDOW_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&h: &u32| h >= 1 && h <= 168) // clamp to 1h – 7 days
        .unwrap_or(1)
}

pub fn spawn_beacon_detector(
    ch:        Arc<ClickhouseStorage>,
    redis_mux: redis::aio::MultiplexedConnection,
    ws_tx:     tokio::sync::broadcast::Sender<String>,
    is_leader: Arc<std::sync::atomic::AtomicBool>,
) {
    tokio::spawn(async move {
        // Initial delay — let traffic accumulate before first scan
        tokio::time::sleep(std::time::Duration::from_secs(180)).await;
        loop {
            if is_leader.load(std::sync::atomic::Ordering::Relaxed) {
                run_scan(&ch, &redis_mux, &ws_tx).await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1800)).await; // every 30 min
        }
    });
}

async fn run_scan(
    ch:        &Arc<ClickhouseStorage>,
    redis_mux: &redis::aio::MultiplexedConnection,
    ws_tx:     &tokio::sync::broadcast::Sender<String>,
) {
    info!("beacon_detector: starting scan");

    let tenant_ids = ch.get_all_tenants().await
        .unwrap_or_else(|_| vec!["default".to_string()]);

    let sem = Arc::new(tokio::sync::Semaphore::new(crate::threat::tenant_scan_concurrency()));
    let mut handles = Vec::with_capacity(tenant_ids.len());
    for tenant_id in tenant_ids {
        let ch2    = Arc::clone(ch);
        let redis2 = redis_mux.clone();
        let ws2    = ws_tx.clone();
        let sem2   = Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem2.acquire().await;
            if let Err(e) = scan_tenant(&ch2, &tenant_id, &redis2, &ws2).await {
                warn!("beacon_detector: tenant {} failed — {}", tenant_id, e);
            }
        }));
    }
    futures_util::future::join_all(handles).await;
}

async fn scan_tenant(
    ch:        &Arc<ClickhouseStorage>,
    tenant_id: &str,
    redis_mux: &redis::aio::MultiplexedConnection,
    ws_tx:     &tokio::sync::broadcast::Sender<String>,
) -> anyhow::Result<()> {
    let candidates = ch.get_beacon_candidates(tenant_id, beacon_window_hours(), MIN_CONNS).await?;

    if candidates.is_empty() {
        info!("beacon_detector: no candidates for tenant {}", tenant_id);
        return Ok(());
    }

    info!("beacon_detector: {} pairs to score for tenant {}", candidates.len(), tenant_id);

    // Load already-flagged pairs this hour to avoid duplicate hits
    let already_flagged = load_flagged_pairs(ch, tenant_id).await;

    for (src_ip, dst_ip, timestamps) in candidates {
        let pair_key = format!("{}→{}", src_ip, dst_ip);
        if already_flagged.contains(&pair_key) {
            continue;
        }

        let score = beacon_score(&timestamps);
        if score >= BEACON_SCORE_THRESHOLD {
            info!(
                "beacon_detector: BEACON detected tenant={} {}→{} score={:.1} conns={}",
                tenant_id, src_ip, dst_ip, score, timestamps.len()
            );
            store_beacon_hit(ch, tenant_id, &src_ip, &dst_ip, score, timestamps.len(), redis_mux, ws_tx).await;
        }
    }

    Ok(())
}

/// Calculate beacon score 0–100.
/// High score = regular intervals (low coefficient of variation of gaps).
fn beacon_score(timestamps: &[i64]) -> f64 {
    if timestamps.len() < 4 {
        return 0.0;
    }

    // Calculate inter-arrival gaps
    let gaps: Vec<f64> = timestamps.windows(2)
        .map(|w| (w[1] - w[0]) as f64)
        .filter(|&g| g > 0.0)
        .collect();

    if gaps.len() < 3 {
        return 0.0;
    }

    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    if mean < 1.0 {
        return 0.0; // sub-second gaps = noise, not beaconing
    }

    let variance = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
    let stddev = variance.sqrt();

    // Coefficient of Variation: low CV = very regular = high beacon suspicion
    let cv = stddev / mean;

    // CV=0 (perfect beacon) → score=100; CV=1 (random) → score~0
    // Score = 100 * max(0, 1 - cv)²  — penalise irregularity quadratically
    let regularity = (1.0_f64 - cv).max(0.0);
    let score = 100.0 * regularity * regularity;

    // Bonus for high connection count (more connections = more confidence)
    let count_bonus = ((timestamps.len() as f64 - MIN_CONNS as f64) / 40.0).min(0.15) * 100.0;

    (score + count_bonus).min(100.0)
}

async fn store_beacon_hit(
    ch:        &Arc<ClickhouseStorage>,
    tenant_id: &str,
    src_ip:    &str,
    dst_ip:    &str,
    score:     f64,
    conn_cnt:  usize,
    redis_mux: &redis::aio::MultiplexedConnection,
    ws_tx:     &tokio::sync::broadcast::Sender<String>,
) {
    let community_id = format!("beacon:{}:{}:{}", tenant_id, src_ip, dst_ip);
    let severity = if score >= 85.0 { "HIGH" } else { "MEDIUM" };
    let reason = format!(
        "Beaconing detected — {} connections in {}h with regular intervals (score={:.0}/100). \
         Bypasses trusted-cloud suppression. Investigate for C2 activity.",
        conn_cnt, beacon_window_hours(), score
    );

    // Write directly as a scored hit — tags include "beaconing" which the API
    // checks to skip trusted-cloud score cap (see scoring/mod.rs rule 7)
    let q = format!(
        "INSERT INTO {db}.ndr_hits \
         (community_id, tenant_id, src_ip, dst_ip, score, severity, tags, \
          threat_intel, timestamp, correlation_status, agent_z_details, agent_s_details) \
         VALUES \
         ('{cid}', '{tid}', '{src}', '{dst}', {score:.1}, '{sev}', {tags}, \
          0, now(), 'beacon', '{details}', '{{}}')",
        db      = crate::storage::clickhouse::tenant_db_pub(tenant_id),
        cid     = crate::storage::clickhouse::sql_escape_pub(&community_id),
        tid     = crate::storage::clickhouse::sql_escape_pub(tenant_id),
        src     = crate::storage::clickhouse::sql_escape_pub(src_ip),
        dst     = crate::storage::clickhouse::sql_escape_pub(dst_ip),
        score   = score,
        sev     = severity,
        tags    = "['beaconing', 'c2-suspect']",
        details = crate::storage::clickhouse::sql_escape_pub(&reason),
    );

    if let Err(e) = ch.client.query(&q).execute().await {
        warn!("beacon_detector: failed to store hit for {}→{}: {}", src_ip, dst_ip, e);
        return;
    }

    // Capture evidence bundle — no PCAP (beacon: CIDs are not network-session CIDs),
    // but threat-intel enrichment and log data are bundled for analyst review.
    {
        let cid_ev   = community_id.clone();
        let tid_ev   = tenant_id.to_string();
        let sev_ev   = severity.to_string();
        let src_ev   = src_ip.to_string();
        let dst_ev   = dst_ip.to_string();
        let ch_ev    = ch.clone();
        let now_str  = chrono::Utc::now().to_rfc3339();
        let alert_ev = serde_json::json!({
            "community_id": cid_ev,
            "tenant_id":    tid_ev,
            "severity":     sev_ev,
            "src_ip":       src_ev,
            "dst_ip":       dst_ev,
            "rule_name":    "beacon-detector",
            "timestamp":    now_str,
        });
        tokio::spawn(async move {
            let opensearch_url = std::env::var("OPENSEARCH_URL")
                .unwrap_or_else(|_| "http://localhost:9200".to_string());
            let arkime_url  = std::env::var("ARKIME_URL").unwrap_or_default();
            let arkime_pass = std::env::var("ARKIME_PASS")
                .unwrap_or_else(|_| "admin".to_string());
            match crate::evidence::build_evidence_bundle(
                &opensearch_url, &arkime_url, &arkime_pass,
                &cid_ev, alert_ev, &tid_ev, None,
            ).await {
                Ok((zip_bytes, sha256, _manifest)) => {
                    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
                    let dir  = format!("/opt/ndr/evidence/{}/{}", tid_ev, date);
                    let _ = tokio::fs::create_dir_all(&dir).await;
                    let bundle_id = uuid::Uuid::new_v4().to_string();
                    let file_path = format!("{}/{}.zip", dir, bundle_id);
                    let size = zip_bytes.len() as u64;
                    if tokio::fs::write(&file_path, &zip_bytes).await.is_ok() {
                        let _ = ch_ev.save_evidence_bundle(
                            &tid_ev, &bundle_id, &cid_ev,
                            &file_path, &sha256, size,
                            1, 90, &src_ev, &dst_ev, &sev_ev,
                            &cid_ev,
                        ).await;
                    }
                }
                Err(e) => warn!("beacon_detector: evidence bundle failed for {}: {}", cid_ev, e),
            }
        });
    }

    // Broadcast beacon hit via WebSocket so the UI shows it in real-time
    let ws_msg = serde_json::json!({
        "type":         "hit",
        "community_id": community_id,
        "src_ip":       src_ip,
        "dst_ip":       dst_ip,
        "severity":     severity,
        "score":        score,
        "tags":         ["beaconing", "c2-suspect"],
        "tenant_id":    tenant_id,
    }).to_string();

    let channel = format!("tenant:{}", tenant_id);
    let mut mux  = redis_mux.clone();
    let msg_copy = ws_msg.clone();
    let tx_copy  = ws_tx.clone();
    tokio::spawn(async move {
        if redis::cmd("PUBLISH")
            .arg(&channel).arg(&msg_copy)
            .query_async::<_, i32>(&mut mux).await
            .is_err()
        {
            let _ = tx_copy.send(msg_copy);
        }
    });
}

/// Load (src→dst) pairs already flagged as beaconing in the last hour
/// so we don't create duplicate hits every 30 min.
async fn load_flagged_pairs(ch: &Arc<ClickhouseStorage>, tenant_id: &str) -> Vec<String> {
    let db = crate::storage::clickhouse::tenant_db_pub(tenant_id);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row { src_ip: String, dst_ip: String }

    let rows = ch.client.query(&format!(
        "SELECT src_ip, dst_ip FROM {db}.ndr_hits FINAL
         WHERE tenant_id = '{tid}'
           AND has(tags, 'beaconing')
           AND timestamp > now() - INTERVAL 2 HOUR",
        db  = db,
        tid = crate::storage::clickhouse::sql_escape_pub(tenant_id),
    )).fetch_all::<Row>().await.unwrap_or_default();

    rows.into_iter().map(|r| format!("{}→{}", r.src_ip, r.dst_ip)).collect()
}
