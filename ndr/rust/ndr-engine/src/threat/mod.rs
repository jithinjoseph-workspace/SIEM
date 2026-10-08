pub mod collector;
pub mod analyzer;
pub mod predictor;
pub mod patterns;
pub mod chain_matcher;
pub mod correlator;
pub mod cloud_trust;
pub mod cloud_suggestions;
pub mod beacon_detector;
pub mod entity_scorer;
pub mod lateral_movement;
pub mod jarm;

use std::sync::Arc;

/// How many tenants a background task processes concurrently, instead of
/// one at a time. Every tenant-looping task here used a plain sequential
/// `for tenant_id in tenants { ... .await }` - fine at a handful of
/// tenants, but at real scale (hundreds-to-thousands) it means a single
/// slow tenant (or a task that calls out to an AI provider per tenant,
/// like chain_matcher/correlator) pushes the whole cycle length out
/// linearly, and multi-second-per-tenant tasks can end up taking longer
/// than their own refresh interval - permanently falling behind, never
/// completing one pass before the next is due. Configurable rather than a
/// fixed constant since the safe value depends on real hardware (Click
/// House capacity, AI provider rate limits) this code has no way to know.
pub fn tenant_scan_concurrency() -> usize {
    std::env::var("TENANT_SCAN_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(10)
}

/// Start threat background tasks with Redis leader election.
/// Only the elected leader runs tasks — automatic failover if leader dies.
/// Returns (election handle, trusted ranges Arc) — both stored in AppState.
pub fn spawn_all(
    ch:           Arc<crate::storage::ClickhouseStorage>,
    redis_url:    &str,
    asn:          Arc<Option<crate::enrichment::AsnLookup>>,
    entity_cache: Arc<dashmap::DashMap<String, f32>>,
    redis_mux:    redis::aio::MultiplexedConnection,
    ws_tx:        tokio::sync::broadcast::Sender<String>,
    // ENGINE_ROLE switches (see crate::role). Both true = behaviour before roles existed.
    run_enrichment_caches: bool,
    run_leader_jobs:       bool,
) -> (
    Arc<crate::leader::LeaderElection>,
    Arc<tokio::sync::RwLock<cloud_trust::TrustedRanges>>,
) {
    // Create trusted here so AppState can hold the same Arc that the updater writes into
    let trusted = Arc::new(tokio::sync::RwLock::new(cloud_trust::TrustedRanges::default()));

    // Small random jitter so all 3 engines don't race at the exact same ms
    let jitter_ms: u64 = rand::random::<u64>() % 2000;
    let redis_url  = redis_url.to_string();

    let redis_client = Arc::new(
        redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|_| redis::Client::open("redis://localhost:6379").unwrap())
    );

    let election = match crate::leader::LeaderElection::new(&redis_url) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            tracing::error!(
                "Leader election init failed: {} — threat tasks disabled until Redis recovers. \
                 Running without coordination risks duplicate data across engines.",
                e
            );
            let fallback = Arc::new(
                crate::leader::LeaderElection::new("redis://localhost:6379")
                    .expect("Cannot create fallback election")
            );
            return (fallback, trusted);
        }
    };

    let election_arc    = election.clone();
    let ch_for_election = ch.clone();
    let trusted_for_spawn = Arc::clone(&trusted);

    // Run on every instance unconditionally, regardless of election outcome -
    // both back synchronous per-event lookups on the live Kafka ingestion
    // path that every instance runs whether or not it's the current leader.
    // Everything inside spawn_threat_tasks() below only ever runs on
    // whichever instance holds (or once held) the leader election, so these
    // two can't live there - a follower that never wins an election would
    // never run them at all.
    let is_leader_flag = election_arc.is_leader_flag();
    if run_enrichment_caches {
        cloud_trust::spawn_trust_updater(
            Arc::clone(&trusted),
            Arc::clone(&redis_client),
            Arc::clone(&asn),
            Arc::clone(&ch),
        );
        entity_scorer::spawn_entity_scorer(Arc::clone(&ch), Arc::clone(&entity_cache), Arc::clone(&is_leader_flag));
    }

    // Without leader jobs (ingest / ui roles) this engine never joins the election, so it
    // can never become leader and none of the elected-leader tasks start on it.
    if run_leader_jobs {
    tokio::spawn(async move {
        tokio::time::sleep(
            std::time::Duration::from_millis(jitter_ms)
        ).await;

        let tasks_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag            = tasks_started.clone();
        let ch_for_elect    = ch_for_election.clone();
        let redis_for_elect = redis_client.clone();
        let asn_for_elect   = asn.clone();
        let trusted_clone   = Arc::clone(&trusted_for_spawn);

        let redis_mux_for_spawn    = redis_mux.clone();
        let ws_tx_for_spawn        = ws_tx.clone();
        // Same flag election_arc.is_leader() reads — cloned once here so every
        // spawned task can poll it every cycle instead of only checking
        // leadership at spawn time (see spawn_threat_tasks doc comment below).
        let is_leader_for_spawn    = election_arc.is_leader_flag();
        election_arc.start(
            move || {
                if !flag.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    tracing::info!("Starting all threat background tasks as elected leader");
                    spawn_threat_tasks(
                        ch_for_elect.clone(),
                        redis_for_elect.clone(),
                        asn_for_elect.clone(),
                        Arc::clone(&trusted_clone),
                        redis_mux_for_spawn.clone(),
                        ws_tx_for_spawn.clone(),
                        Arc::clone(&is_leader_for_spawn),
                    );
                } else {
                    tracing::info!("Re-elected — tasks already running, no restart needed");
                }
            },
            || {
                tracing::warn!(
                    "Leadership lost — tasks continue running until shutdown or re-election"
                );
            },
        );

        // Keep this spawn alive forever
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
        }
    });
    }

    (election, trusted)
}

/// Start all 5 threat background tasks. Called once when this engine wins election.
///
/// `is_leader` is polled by each task every cycle, not just read once here at
/// spawn time. Tasks are only ever spawned once per process (re-election just
/// logs and returns, see the caller) — they keep running for the process
/// lifetime, but skip their real work whenever this engine isn't the current
/// leader. Without this, an instance that later lost leadership (e.g. after a
/// Redis restart) kept running the full analysis suite forever in parallel
/// with the new leader — duplicate entity scoring, predictions, correlation,
/// all double-writing the same ClickHouse tables.
fn spawn_threat_tasks(
    ch:        Arc<crate::storage::ClickhouseStorage>,
    redis:     Arc<redis::Client>,
    asn:       Arc<Option<crate::enrichment::AsnLookup>>,
    trusted:   Arc<tokio::sync::RwLock<cloud_trust::TrustedRanges>>,
    redis_mux: redis::aio::MultiplexedConnection,
    ws_tx:     tokio::sync::broadcast::Sender<String>,
    is_leader: Arc<std::sync::atomic::AtomicBool>,
) {
    let chain_trigger = Arc::new(tokio::sync::Notify::new());

    // cloud_trust::spawn_trust_updater and entity_scorer::spawn_entity_scorer
    // are NOT started here - see spawn_all() below. Both back per-event
    // lookups on the live Kafka ingestion path that every instance runs
    // regardless of leadership, so they can't only run when this function
    // gets called (which only ever happens on whichever instance currently
    // holds - or once held - the leader election).

    // Only collect external feeds if any active tenant purchased threat_intel.
    // Not leader-gated below: collector.rs wraps a loop shared with siem-engine
    // in provigil-common, out of scope for this fix - flagged separately.
    {
        let ch_feat = Arc::clone(&ch);
        tokio::spawn(async move {
            let any_ti = ch_feat.client
                .query("SELECT count() FROM ndr.tenants WHERE active = 1 AND positionCaseInsensitive(features, 'threat_intel') > 0")
                .fetch_one::<u64>()
                .await
                .unwrap_or(0);
            if any_ti > 0 {
                collector::spawn_collector(ch_feat);
            } else {
                tracing::info!("No tenant has threat_intel — external feed collector skipped");
            }
        });
    }
    predictor::spawn_predictor(Arc::clone(&ch), Arc::clone(&trusted), Arc::clone(&is_leader));
    patterns::spawn_pattern_sync(Arc::clone(&ch), Arc::clone(&chain_trigger), Arc::clone(&redis), Arc::clone(&is_leader));
    chain_matcher::spawn_chain_matcher(Arc::clone(&ch), Arc::clone(&chain_trigger), Arc::clone(&trusted), Arc::clone(&asn), Arc::clone(&is_leader));
    correlator::spawn_correlator(Arc::clone(&ch), Arc::clone(&is_leader));
    cloud_suggestions::spawn_suggestion_scanner(Arc::clone(&ch), Arc::clone(&is_leader));
    beacon_detector::spawn_beacon_detector(Arc::clone(&ch), redis_mux, ws_tx, Arc::clone(&is_leader));
    crate::enrichment::asset_intel::spawn_asset_intel(Arc::clone(&ch), Arc::clone(&is_leader));
    lateral_movement::spawn_lateral_movement_detector(Arc::clone(&ch), Arc::clone(&is_leader));
    jarm::spawn_jarm_scanner(Arc::clone(&ch), Arc::clone(&is_leader));
    crate::triage::spawn_triage(Arc::clone(&ch), Arc::clone(&is_leader));

    tracing::info!("Threat background tasks started on elected leader (cloud_trust + entity_scorer run independently on every instance, see spawn_all)");
}

// ── Row structs for ClickHouse queries ───────────────────────────────────────

#[derive(clickhouse::Row, serde::Deserialize)]
struct PredictionRow {
    attack_type:        String,
    probability:        f32,
    confidence:         f32,
    trend:              String,
    trend_delta:        f32,
    intel_signal_count: u32,
    exposure_score:     f32,
    internal_hit_count: u32,
    explanation:        String,
    recommendations:    String,
    aria_briefing:      String,
    alert_level:        String,
    predicted_at:       String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct ExposureRow {
    tenant_id:            String,
    rdp_exposed:          u8,
    smb_exposed:          u8,
    ssh_exposed:          u8,
    http_exposed:         u8,
    dns_anomalies:        u64,
    port_scans:           u64,
    failed_logins:        u64,
    lateral_movement:     u64,
    c2_beacons:           u64,
    data_exfil_bytes:     u64,
    brute_force_attempts: u64,
    unique_src_ips:       u64,
    snapshot_at:          String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct IntelSummaryRow {
    source:       String,
    attack_type:  String,
    severity:     String,
    signal_count: u64,
    latest:       String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct PatternMatchRow {
    id:                  String,
    chain_id:            String,
    chain_name:          String,
    attack_type:         String,
    steps_observed:      u8,
    steps_total:         u8,
    completion_pct:      f32,
    next_step:           String,
    predicted_eta_hours: f32,
    src_ip:              String,
    severity:            String,
    confidence:          f32,
    status:              String,
    ai_assessment:       String,
    recommendations:     String,
    first_seen:          String,
    last_updated:        String,
}

// ── API query helpers ────────────────────────────────────────────────────────

pub async fn get_predictions(
    ch: &crate::storage::ClickhouseStorage,
    tenant_id: &str,
    limit: u32,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = crate::storage::clickhouse::tenant_db_pub(tenant_id);
    let q = format!(
        "SELECT attack_type, probability, confidence, trend, trend_delta, \
                intel_signal_count, exposure_score, internal_hit_count, \
                explanation, recommendations, aria_briefing, alert_level, \
                toString(predicted_at) as predicted_at
         FROM {db}.threat_predictions
         ORDER BY predicted_at DESC
         LIMIT {limit}",
        db = db,
        limit = limit,
    );

    let rows = ch.client.query(&q).fetch_all::<PredictionRow>().await?;

    Ok(rows.into_iter().map(|r| serde_json::json!({
        "attack_type":        r.attack_type,
        "probability":        r.probability,
        "confidence":         r.confidence,
        "trend":              r.trend,
        "trend_delta":        r.trend_delta,
        "intel_signal_count": r.intel_signal_count,
        "exposure_score":     r.exposure_score,
        "internal_hit_count": r.internal_hit_count,
        "explanation":        r.explanation,
        "recommendations":    serde_json::from_str::<serde_json::Value>(&r.recommendations)
                                  .unwrap_or(serde_json::json!([])),
        "aria_briefing":      r.aria_briefing,
        "alert_level":        r.alert_level,
        "predicted_at":       r.predicted_at,
    })).collect())
}

pub async fn get_exposure_history(
    ch: &crate::storage::ClickhouseStorage,
    tenant_id: &str,
    limit: u32,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = crate::storage::clickhouse::tenant_db_pub(tenant_id);
    let q = format!(
        "SELECT tenant_id, rdp_exposed, smb_exposed, ssh_exposed, http_exposed,
                dns_anomalies, port_scans, failed_logins, lateral_movement,
                c2_beacons, data_exfil_bytes, brute_force_attempts, unique_src_ips,
                toString(snapshot_at) as snapshot_at
         FROM {db}.exposure_profile
         ORDER BY snapshot_at DESC
         LIMIT {limit}",
        db = db, limit = limit
    );

    let rows = ch.client.query(&q).fetch_all::<ExposureRow>().await?;

    Ok(rows.into_iter().map(|r| serde_json::json!({
        "tenant_id":           r.tenant_id,
        "rdp_exposed":         r.rdp_exposed > 0,
        "smb_exposed":         r.smb_exposed > 0,
        "ssh_exposed":         r.ssh_exposed > 0,
        "http_exposed":        r.http_exposed > 0,
        "dns_anomalies":       r.dns_anomalies,
        "port_scans":          r.port_scans,
        "failed_logins":       r.failed_logins,
        "lateral_movement":    r.lateral_movement,
        "c2_beacons":          r.c2_beacons,
        "data_exfil_bytes":    r.data_exfil_bytes,
        "brute_force_attempts":r.brute_force_attempts,
        "unique_src_ips":      r.unique_src_ips,
        "snapshot_at":         r.snapshot_at,
    })).collect())
}

pub async fn get_threat_intel_summary(
    ch: &crate::storage::ClickhouseStorage,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let q = "SELECT source, attack_type, severity, count() as signal_count, \
              max(toString(collected_at)) as latest
              FROM ndr.threat_intel
              WHERE collected_at >= now() - INTERVAL 24 HOUR
              GROUP BY source, attack_type, severity
              ORDER BY signal_count DESC
              LIMIT 50";

    let rows = ch.client.query(q).fetch_all::<IntelSummaryRow>().await?;

    Ok(rows.into_iter().map(|r| serde_json::json!({
        "source":        r.source,
        "attack_type":   r.attack_type,
        "severity":      r.severity,
        "signal_count":  r.signal_count,
        "latest":        r.latest,
    })).collect())
}

pub async fn get_pattern_matches(
    ch: &crate::storage::ClickhouseStorage,
    tenant_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = crate::storage::clickhouse::tenant_db_pub(tenant_id);
    let q = format!(
        "SELECT id, chain_id, chain_name, attack_type, \
                steps_observed, steps_total, completion_pct, \
                next_step, predicted_eta_hours, src_ip, severity, confidence, \
                status, ai_assessment, recommendations, \
                toString(first_seen) as first_seen, \
                toString(last_updated) as last_updated
         FROM {db}.pattern_matches
         WHERE status = 'active'
         AND last_updated >= now() - INTERVAL 24 HOUR
         ORDER BY completion_pct DESC, last_updated DESC
         LIMIT 50",
        db = db
    );

    let rows = ch.client.query(&q).fetch_all::<PatternMatchRow>().await?;

    Ok(rows.into_iter().map(|r| serde_json::json!({
        "id":                  r.id,
        "chain_id":            r.chain_id,
        "chain_name":          r.chain_name,
        "attack_type":         r.attack_type,
        "steps_observed":      r.steps_observed,
        "steps_total":         r.steps_total,
        "completion_pct":      r.completion_pct,
        "next_step":           r.next_step,
        "predicted_eta_hours": r.predicted_eta_hours,
        "src_ip":              r.src_ip,
        "severity":            r.severity,
        "confidence":          r.confidence,
        "status":              r.status,
        "ai_assessment":       r.ai_assessment,
        "recommendations":     serde_json::from_str::<serde_json::Value>(&r.recommendations)
                                   .unwrap_or(serde_json::json!([])),
        "first_seen":          r.first_seen,
        "last_updated":        r.last_updated,
    })).collect())
}
