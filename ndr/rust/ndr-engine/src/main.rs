// NDR Engine — Entry Point
// Boots all subsystems, wires them into AppState, starts background tasks.
// License: Apache-2.0

mod api;
mod auth;
mod license;
mod ratelimit;
mod role;
mod siem;
mod consumer;
mod correlator;
mod detection;
mod enrichment;
mod normalizer;
mod scoring;
mod storage;
mod evidence;
mod ai;
mod homecountry;
#[cfg(feature = "soar")]
pub mod soar;
mod monitor;
mod threat;
mod triage;
mod leader;

use api::{websocket::ws_handler, AppState};
use futures_util::StreamExt;
use axum::{routing::{get, post, put, delete, patch}, Router};
use axum::extract::DefaultBodyLimit;
use tower_http::cors::{Any, CorsLayer, AllowOrigin};
use axum::http::HeaderValue;
use tower_http::decompression::RequestDecompressionLayer;
use tower_http::catch_panic::CatchPanicLayer;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, ACCEPT};


use enrichment::{AsnLookup, AssetIdentifier, EnrichmentPipeline, GeoIpLookup, ThreatIntel};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

/// Turns an unhandled handler panic into a logged, structured 500 instead of
/// tower_http's default (a raw stderr dump with no tracing correlation).
fn handle_panic(err: Box<dyn std::any::Any + Send + 'static>) -> axum::response::Response {
    let detail = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "unknown panic payload".to_string()
    };
    tracing::error!("handler panicked: {}", detail);
    axum::response::Response::builder()
        .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(r#"{"status":"error","message":"internal server error"}"#))
        .unwrap()
}

#[cfg(feature = "soar")]
fn soar_routes() -> Router<AppState> {
    Router::new()
        .route("/api/soar/status",  get(api::get_soar_status))
        .route("/api/soar/playbook/toggle",post(api::toggle_playbook))
        .route("/api/soar/playbook/create",post(api::create_playbook))
        .route("/api/soar/integrations",get(api::get_integrations).post(api::save_integration))
        .route("/api/soar/integrations/test",post(api::test_integration_endpoint))
        .route("/api/soar/integrations/toggle",post(api::toggle_integration))
        .route("/api/soar/cases", get(api::get_soar_cases).post(api::create_soar_case))
        .route("/api/soar/cases/:id", put(api::update_soar_case))
        .route("/api/soar/cases/:id/comments", get(api::get_soar_case_comments).post(api::add_soar_case_comment))
        .route("/api/soar/cases/:id/status", put(api::update_soar_case_status))
        .route("/api/soar/native/playbooks", get(api::get_native_playbooks).post(api::create_native_playbook))
        .route("/api/soar/native/playbooks/:id", put(api::update_native_playbook).delete(api::delete_native_playbook))
        .route("/api/soar/runs", get(api::get_soar_runs))
        .route("/api/soar/integrations/delete",post(api::delete_integration)) // legacy
        .route("/api/soar/integrations/:id", put(api::update_integration).delete(api::delete_integration))
        .route("/api/soar/jira/tickets", post(api::get_jira_tickets))
        .route("/api/blocks",          get(api::list_active_blocks))
        .route("/api/blocks/manual",   post(api::manual_block))
        .route("/api/blocks/revoke",   post(api::revoke_active_block))
        .route("/api/isolations",      get(api::list_isolations))
        .route("/api/isolate",         post(api::isolate_device_handler))
        .route("/api/unisolate",       post(api::unisolate_device_handler))
}

#[cfg(not(feature = "soar"))]
fn soar_routes() -> Router<AppState> {
    Router::new()
}

#[tokio::main]
async fn main() {
    // ── Logging ───────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "ndr_engine=info".to_string())
                .as_str(),
        )
        .init();

    info!("NDR Engine starting");

    // What this process is for: all (default) | ingest | process | ui - see role.rs
    let role = role::EngineRole::from_env();
    info!(
        "Engine role: {} (kafka consumer: {}, leader jobs: {}, full platform: {})",
        role.as_str(), role.consumer(), role.leader_jobs(), role.full_platform()
    );

    // ── Production credential warnings ────────────────────────────────────
    // Fail fast if JWT_SECRET is absent — every auth call would panic otherwise.
    if std::env::var("JWT_SECRET").is_err() {
        tracing::error!(
            "FATAL: JWT_SECRET env var is not set. \
             Authentication cannot work without it. Set JWT_SECRET in .env and restart."
        );
        std::process::exit(1);
    }
    let default_jwt = "1c14f97d4d12b77a471227ab268ae22b1765df18b188cdceb9c5d4668189e85c";
    if std::env::var("JWT_SECRET").as_deref() == Ok(default_jwt) {
        tracing::warn!("SECURITY: JWT_SECRET is still the default value — change it in .env before production!");
    }
    if std::env::var("NDR_AGENT_SECRET").unwrap_or_default().contains("change-this") {
        tracing::warn!("SECURITY: NDR_AGENT_SECRET is still the default placeholder — set a strong secret in .env!");
    }
    if std::env::var("CORS_ORIGIN").unwrap_or_default().is_empty() {
        tracing::warn!("SECURITY: CORS_ORIGIN not set — API accepts requests from any origin. Set CORS_ORIGIN in .env for production!");
    }

    // ── Ensure required storage directories exist ─────────────────────────
    for dir in &["/opt/ndr/pcap", "/opt/ndr/evidence"] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            tracing::warn!("Could not create storage dir {}: {}", dir, e);
        }
    }

    // ── GeoIP / ASN (optional — engine works without them) ───────────────
    let geoip = GeoIpLookup::open("data/GeoLite2-City.mmdb")
        .map_err(|e| info!("GeoIP unavailable ({}). Place GeoLite2-City.mmdb in data/", e))
        .ok();

    let asn_arc: Arc<Option<AsnLookup>> = Arc::new(
        AsnLookup::open("data/GeoLite2-ASN.mmdb")
            .map_err(|e| info!("ASN DB unavailable ({}). Place GeoLite2-ASN.mmdb in data/", e))
            .ok()
    );

    // ── Threat intel ──────────────────────────────────────────────────────
    let threat_intel = ThreatIntel::new();
    let ti_ref = Arc::new(threat_intel);

    // ── Build AppState ────────────────────────────────────────────────────
    let (tx, _) = broadcast::channel::<String>(512);

    let redis_url = std::env::var("VALKEY_URL")
        .or_else(|_| std::env::var("REDIS_URL"))
        .unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let redis_client = redis::Client::open(redis_url.clone())
        .expect("Valkey connection failed");
    // Shared multiplexed connection for publishing — avoids opening a new
    // TCP connection on every event (was causing per-event latency spikes)
    let redis_mux = {
        let mut conn = None;
        let mut last_err = String::new();
        for attempt in 1u8..=6 {
            match redis_client.get_multiplexed_async_connection().await {
                Ok(c) => { conn = Some(c); break; }
                Err(e) => {
                    last_err = e.to_string();
                    tracing::warn!("Valkey not ready (attempt {}/6): {} — retrying in 5s", attempt, e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        }
        conn.unwrap_or_else(|| {
            tracing::error!(
                "Valkey unreachable after 30 s ({}). \
                 Check VALKEY_URL={} or ensure the Valkey container is running. Exiting.",
                last_err, redis_url
            );
            std::process::exit(1);
        })
    };

    let storage = storage::SqliteStorage::new("ndr.db")
        .expect("Failed to open SQLite database");

    let kafka_cfg = provigil_common::kafka::KafkaConfig::from_env();
    let kafka_producer = kafka_cfg.build_producer();

    let kafka_producer = Arc::new(kafka_producer);

    // ── Sensor key auth cache (Redis-backed, shared across all engine instances)
    let sensor_key_cache = Arc::new(
        auth::sensor_cache::SensorKeyCache::new(Arc::new(redis_client.clone()))
    );

    // ── Async ingest channel: events wait here until the drain task hands them to Kafka ─────
    // Capacity is how many events can be waiting at once (it is NOT a per-second rate; that is
    // set by how fast the drain below can publish). When it is full /api/ingest answers 503 so
    // the sensor retries, instead of dropping events. Memory is about 1 KB per queued event.
    // Override: INGEST_QUEUE_CAPACITY (default 200,000, minimum 1,000).
    let (ingest_tx, mut ingest_rx) =
        tokio::sync::mpsc::channel::<(String, String)>(ingest_queue_capacity());
    let drain_batch = ingest_drain_batch();

    // Background drain: flushes channel to Kafka in micro-batches of ≤200
    // events every 100ms. /api/ingest returns immediately without waiting.
    //
    // The "batch" used to only describe how many events get COLLECTED before
    // flushing - the actual flush itself called producer.send(...).await
    // (the blocking variant, up to a 5s wait) sequentially, one event at a
    // time, on this single task shared by the whole engine instance across
    // every tenant. At real ingest volume this is a hard global throughput
    // ceiling regardless of tenant count or Kafka partitions. Fixed with
    // send_result() - librdkafka's actual non-blocking enqueue, returns a
    // DeliveryFuture immediately instead of awaiting the broker round-trip -
    // so all events in a batch get handed to librdkafka right away (which
    // does its own real wire-level batching), and delivery confirmation for
    // the whole batch is awaited concurrently instead of one at a time.
    {
        use rdkafka::producer::FutureRecord;
        let producer = kafka_producer.clone();

        async fn flush_batch(
            producer: &rdkafka::producer::FutureProducer,
            batch: &mut Vec<(String, String)>,
        ) {
            let futures: Vec<_> = batch.drain(..).filter_map(|(_, payload)| {
                let rec = FutureRecord::<str, str>::to(provigil_common::kafka::TOPIC_NDR_EVENTS)
                    .payload(&payload);
                match producer.send_result(rec) {
                    Ok(delivery) => Some(delivery),
                    Err((e, _)) => {
                        tracing::error!("Kafka enqueue error: {}", e);
                        None
                    }
                }
            }).collect();

            for result in futures_util::future::join_all(futures).await {
                match result {
                    Ok(Ok(_)) => {}
                    Ok(Err((e, _))) => tracing::error!("Kafka publish error: {}", e),
                    Err(_) => tracing::error!("Kafka delivery future cancelled"),
                }
            }
        }

        tokio::spawn(async move {
            let mut batch: Vec<(String, String)> = Vec::with_capacity(drain_batch);
            let mut ticker = tokio::time::interval(
                std::time::Duration::from_millis(100)
            );
            loop {
                tokio::select! {
                    maybe = ingest_rx.recv() => {
                        match maybe {
                            Some(ev) => {
                                batch.push(ev);
                                if batch.len() >= drain_batch {
                                    flush_batch(&producer, &mut batch).await;
                                }
                            }
                            None => break,
                        }
                    }
                    _ = ticker.tick() => {
                        if !batch.is_empty() {
                            flush_batch(&producer, &mut batch).await;
                        }
                    }
                }
            }
        });
    }

    // ── Redis publish drain (replaces per-event tokio::spawn in publish_event) ──
    // One task batches up to 64 PUBLISH commands into a single Redis pipeline
    // every 5 ms, eliminating unbounded task spawning under high event rates.
    let (publish_tx, mut publish_rx) =
        tokio::sync::mpsc::channel::<(String, String)>(4_096);
    {
        let mut pub_conn   = redis_mux.clone();
        let tx_ws_fallback = tx.clone();
        tokio::spawn(async move {
            let mut batch  = Vec::<(String, String)>::with_capacity(64);
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(5));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            macro_rules! flush_batch {
                () => {
                    if !batch.is_empty() {
                        let mut pipe = redis::pipe();
                        for (ch, msg) in &batch {
                            pipe.cmd("PUBLISH").arg(ch).arg(msg).ignore();
                        }
                        if pipe.query_async::<_, redis::Value>(&mut pub_conn).await.is_err() {
                            // Redis unavailable — fall back to in-process broadcast
                            for (_, msg) in batch.drain(..) {
                                let _ = tx_ws_fallback.send(msg);
                            }
                        } else {
                            batch.clear();
                        }
                    }
                };
            }

            loop {
                tokio::select! {
                    biased;
                    maybe = publish_rx.recv() => {
                        match maybe {
                            Some(m) => {
                                batch.push(m);
                                if batch.len() >= 64 { flush_batch!(); }
                            }
                            None => { flush_batch!(); break; }
                        }
                    }
                    _ = ticker.tick() => flush_batch!(),
                }
            }
        });
    }

    // ── Common shared-table migrations (provigil-common) ─────────────────
    {
        let ch = provigil_common::clickhouse::ClickHouseConfig::from_env().build_client();
        provigil_common::migrations::run_common_migrations(&ch).await;
    }

    let ch_storage_arc = {
        let ch = Arc::new(storage::ClickhouseStorage::new());
        ch.init_tables().await;
        ch.migrate_ipam_subnets().await;
        ch.seed_local_sensor().await;
        ch.seed_doh_providers().await;
        ch.ensure_licenses_table().await;
        ch.ensure_honeypots_table().await;
        ch
    };

    // ── DoH provider IP cache (DB-backed, refreshed every 24h) ──────────────
    let doh_ips = {
        let set = ch_storage_arc.load_doh_providers().await.unwrap_or_default();
        Arc::new(tokio::sync::RwLock::new(set))
    };
    {
        let ch_doh = ch_storage_arc.clone();
        let doh_ref = Arc::clone(&doh_ips);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(86_400)).await;
                if let Ok(set) = ch_doh.load_doh_providers().await {
                    *doh_ref.write().await = set;
                }
            }
        });
    }

    // ── SIEM syslog forwarder (optional, set SIEM_SYSLOG_HOST to enable) ────
    // env::var() returns Ok("") for a var that's *set but empty* - which is
    // exactly how every installer's default .env ships this (SIEM_SYSLOG_HOST=
    // with no value), not just "unset". That previously fell into the "try to
    // connect" branch and warned on every single startup with no SIEM
    // configured at all - the normal/default case, not an error.
    let siem: Option<Arc<crate::siem::SiemForwarder>> =
        match std::env::var("SIEM_SYSLOG_HOST") {
            Ok(host) if !host.trim().is_empty() => {
                let port: u16 = std::env::var("SIEM_SYSLOG_PORT")
                    .ok().and_then(|v| v.parse().ok()).unwrap_or(514);
                match crate::siem::SiemForwarder::new(&host, port).await {
                    Ok(f) => {
                        tracing::info!("SIEM syslog forwarder enabled → {}:{}", host, port);
                        Some(Arc::new(f))
                    }
                    Err(e) => {
                        tracing::warn!("SIEM forwarder init failed (disabling): {}", e);
                        None
                    }
                }
            }
            _ => None,
        };

    // ── Seed in-memory threat-intel from persisted IOC watchlist ─────────
    {
        let ch_wl = ch_storage_arc.clone();
        let ti_wl = ti_ref.clone();
        tokio::spawn(async move {
            match ch_wl.load_watchlist_iocs().await {
                Ok(iocs) if !iocs.is_empty() => {
                    let n = iocs.len();
                    for (ioc_type, value) in iocs {
                        ti_wl.add_ioc(&ioc_type, &value);
                    }
                    tracing::info!("Loaded {} manual IOCs from ioc_watchlist", n);
                }
                _ => {}
            }
        });
    }

    // ── Background: Threat tasks with Redis leader election ───────────────
    let sensor_ip: Option<std::net::IpAddr> = std::env::var("HOST_IP").ok()
        .and_then(|s| s.trim().parse().ok());
    if let Some(ip) = sensor_ip {
        tracing::info!("Sensor self-IP: {} — own trusted traffic will be filtered", ip);
    }

    let entity_cache: Arc<dashmap::DashMap<String, f32>> = Arc::new(dashmap::DashMap::new());
    let (election, trusted) = threat::spawn_all(
        ch_storage_arc.clone(), &redis_url, Arc::clone(&asn_arc),
        entity_cache.clone(),
        redis_mux.clone(),
        tx.clone(),
        role.full_platform(),
        role.leader_jobs(),
    );

    // Start sensor key cache refresh loop (after ch_storage is ready)
    auth::sensor_cache::spawn_refresh_loop(
        sensor_key_cache.clone(),
        ch_storage_arc.clone(),
    );

    // ── Kafka health: background poll every 30s (avoids blocking Tokio threads) ──
    let kafka_healthy = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let flag     = kafka_healthy.clone();
        let producer = kafka_producer.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                ticker.tick().await;
                let prod = producer.clone();
                let ok = tokio::task::spawn_blocking(move || {
                    api::kafka_health_probe(&prod)
                }).await.unwrap_or(false);
                flag.store(ok, std::sync::atomic::Ordering::Relaxed);
            }
        });
    }

    // ── License JWT startup verification (RS256) ──────────────────────────
    let license_private_key = license::load_private_key().unwrap_or_else(|_| {
        tracing::debug!("LICENSE_PRIVATE_KEY not set — license generation disabled (normal for customer installs)");
        String::new()
    });
    let license_public_key = license::load_public_key().unwrap_or_else(|e| {
        tracing::warn!("LICENSE_PUBLIC_KEY: {} — on-premise license verification disabled", e);
        String::new()
    });

    let verified_license: Option<Arc<license::LicenseClaims>> =
        if !license_public_key.is_empty() {
            std::env::var("LICENSE_TOKEN").ok()
            .filter(|t| !t.trim().is_empty())
            .and_then(|token| {
                match license::verify_license(&token, &license_public_key) {
                    Ok(claims) => {
                        info!(
                            "License verified (RS256) — tenant: '{}', features: {:?}, issued_by: {}",
                            claims.tenant_id, claims.features, claims.issued_by
                        );
                        Some(Arc::new(claims))
                    }
                    Err(e) => {
                        tracing::error!(
                            "LICENSE_TOKEN present but invalid: {} — falling back to database features",
                            e
                        );
                        None
                    }
                }
            })
        } else {
            None
        };

    // ── Honeypot CIDR cache (DB-backed, pre-parsed for O(n) membership checks) ──
    let honeypot_cidrs = {
        let pairs = ch_storage_arc.get_all_honeypot_cidrs().await.unwrap_or_default();
        let parsed: Vec<(ipnetwork::IpNetwork, String)> = pairs.into_iter()
            .filter_map(|(cidr, tid)| {
                cidr.parse::<ipnetwork::IpNetwork>().ok().map(|net| (net, tid))
            })
            .collect();
        Arc::new(tokio::sync::RwLock::new(parsed))
    };

    let state = AppState {
        correlator: Arc::new(correlator::CorrelationEngine::new()),
        enrichment: Arc::new(EnrichmentPipeline {
            geoip,
            asn: Arc::clone(&asn_arc),
            threat_intel: ti_ref.clone(),
            asset_id: Arc::new(AssetIdentifier::new()),
        }),
        scorer:     Arc::new(scoring::RiskScorer::new()),
        detection:  Arc::new(tokio::sync::RwLock::new(detection::DetectionEngine::new("rules"))),
        ch_storage: ch_storage_arc.clone(),
        storage:    Arc::new(storage),
        tx:         tx.clone(),
        redis:      Arc::new(redis_client.clone()),
        redis_mux:  redis_mux,
        kafka_producer: kafka_producer.clone(),
        correlation_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
        sensor_key_cache,
        ingest_tx,
        publish_tx,
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("NDR-Engine/1.0")
            .build()
            .unwrap_or_default(),
        trusted,
        sensor_ip,
        entity_cache,
        doh_ips,
        siem,
        trusted_asset_cache: Arc::new(dashmap::DashMap::new()),
        ws_dedup: Arc::new(dashmap::DashMap::new()),
        trusted_source_cidrs: Arc::new({
            std::env::var("TRUSTED_SOURCE_CIDRS").unwrap_or_default()
                .split(',')
                .filter_map(|s| {
                    let s = s.trim();
                    if s.is_empty() { return None; }
                    s.parse::<ipnetwork::IpNetwork>().map_err(|e| {
                        tracing::warn!("TRUSTED_SOURCE_CIDRS: invalid CIDR '{}': {}", s, e);
                    }).ok()
                })
                .collect()
        }),
        kafka_healthy,
        soar_dedupe: Arc::new(dashmap::DashMap::new()),
        update_status: Arc::new(tokio::sync::RwLock::new(api::UpdateStatus {
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            ..Default::default()
        })),
        license_private_key,
        license_public_key,
        verified_license,
        honeypot_cidrs,
        retro_scans: Arc::new(dashmap::DashMap::new()),
    };

    // ── License tenant provisioning ───────────────────────────────────────
    // If an RS256-verified license is present, ensure the tenant row exists
    // in ClickHouse so the super admin sees it in the UI immediately.
    if let Some(lic) = &state.verified_license {
        if lic.tenant_id != "default" {
            let ch  = ch_storage_arc.clone();
            let tid = lic.tenant_id.clone();
            let tname = lic.tenant_name.clone();
            let feats = lic.features.clone();
            tokio::spawn(async move {
                ch.ensure_license_tenant(&tid, &tname, &feats).await;
            });
        }
    }

    // ── Background: OUI vendor database auto-updater ─────────────────────
    if role.full_platform() {
        state.enrichment.asset_id.clone().spawn_auto_updater();
    }

    // ── Background: session reaper (every 30s) ────────────────────────────
    if role.full_platform() {
        let eng = state.correlator.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                eng.sweep_expired();
                tracing::debug!("Session sweep complete. Active: {}", eng.session_count());
            }
        });
    }

    // ── Background: threat intel refresh (every 60 min) ───────────────────
    // Fix background refresh — refresh NOW then every 60 min
if role.full_platform() {
    let ti = ti_ref.clone();
    let ch_storage = ch_storage_arc.clone();
    tokio::spawn(async move {
        loop {
            ti.refresh().await;
            let snapshot_entries = ti.snapshot_entries("runtime_refresh");
            if !snapshot_entries.is_empty() {
                match ch_storage.persist_threat_intel_entries(snapshot_entries).await {
                    Ok(inserted) => tracing::info!("Threat intel runtime snapshot persisted to ClickHouse: {} entries", inserted),
                    Err(err) => tracing::warn!("Threat intel runtime snapshot persist failed: {}", err),
                }
            }
            tokio::time::sleep(
                tokio::time::Duration::from_secs(3600)
            ).await;
        }
    });
}
    // ── Background: vendor backfill via Redis SET ─────────────────────────
    // On startup: seed Redis SET with all existing Unknown-vendor assets.
    // Worker: SPOP one item, OUI lookup, write DB. Sleeps 1s when set empty.
    // SADD in consumer ensures no duplicates; SPOP is atomic across instances.
    if role.full_platform() {
        let ch_seed = state.ch_storage.clone();
        let mut redis_seed = state.redis_mux.clone();
        tokio::spawn(async move {
            if let Ok(tenants) = ch_seed.get_all_tenants().await {
                for tenant in &tenants {
                    if let Ok(assets) = ch_seed.get_assets_by_tenant(tenant).await {
                        for asset in assets {
                            if (asset.vendor.is_empty() || asset.vendor == "Unknown") && !asset.mac.is_empty() {
                                let qi = format!("{}|{}|{}", asset.tenant_id, asset.ip, asset.mac);
                                let _: Result<i64, _> = redis::cmd("SADD")
                                    .arg("ndr:vendor_pending").arg(qi)
                                    .query_async(&mut redis_seed).await;
                            }
                        }
                    }
                }
            }
        });
    }
    if role.full_platform() {
        let ch = state.ch_storage.clone();
        let asset_id = state.enrichment.asset_id.clone();
        let redis_client_vb = redis_client.clone();
        tokio::spawn(async move {
            let mut conn = match redis_client_vb.get_async_connection().await {
                Ok(c) => c,
                Err(e) => { tracing::warn!("Vendor backfill: Redis connect failed: {}", e); return; }
            };
            loop {
                let item: Option<String> = redis::cmd("SPOP")
                    .arg("ndr:vendor_pending")
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(None);

                match item {
                    Some(entry) => {
                        let parts: Vec<&str> = entry.splitn(3, '|').collect();
                        if parts.len() == 3 {
                            let (tenant, ip, mac) = (parts[0], parts[1], parts[2]);
                            let vendor = asset_id.lookup_vendor(mac);
                            if !vendor.is_empty() && vendor != "Unknown" {
                                if let Ok(Some(mut asset)) = ch.get_asset_by_ip(tenant, ip).await {
                                    if asset.vendor.is_empty() || asset.vendor == "Unknown" {
                                        asset.vendor = vendor.clone();
                                        let _ = ch.upsert_asset(&asset).await;
                                        info!("Vendor backfill: {} → {}", ip, vendor);
                                    }
                                }
                            }
                            // Randomized MACs (no OUI) are silently dropped — correct
                        }
                    }
                    None => {
                        // Set empty — all vendors resolved, sleep until new unknown arrives
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });
    }

    // ── Kafka consumer — auto-restarts on panic or error ─────────────────
    if role.consumer() {
        let consumer_state = state.clone();
        tokio::spawn(async move {
            loop {
                let s = Arc::new(consumer_state.clone());
                let result = tokio::spawn(async move {
                    consumer::start_consumer(s).await;
                }).await;
                if let Err(e) = result {
                    tracing::error!("Kafka consumer crashed: {:?} — restarting in 5s", e);
                } else {
                    tracing::warn!("Kafka consumer exited unexpectedly — restarting in 5s");
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }


    let rules_dir = std::env::var("RULES_DIR").unwrap_or_else(|_| "rules".to_string());

    // ── Migrate rules to ClickHouse — leader only, once per startup ───────
    {
        let ch = state.ch_storage.clone();
        let rules_dir = rules_dir.clone();
        let election = election.clone();
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));

        tokio::spawn(async move {
            loop {
                if !election.is_leader() {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    continue;
                }
                if ran.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                if let Ok(entries) = std::fs::read_dir(&rules_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                        if ext != "yml" && ext != "yaml" { continue; }
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            if let Ok(doc) = serde_yaml::from_str::<std::collections::HashMap<String, serde_yaml::Value>>(&content) {
                                let id = doc.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let name = doc.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                if !id.is_empty() {
                                    let exists = ch.get_sigma_rule_by_id(&id, "default").await.map(|r| r.is_some()).unwrap_or(false);
                                    if !exists {
                                        if let Err(e) = ch.save_sigma_rule(&id, &name, &content, "default").await {
                                            tracing::warn!("Failed to migrate rule {}: {}", id, e);
                                        } else {
                                            tracing::info!("Migrated rule {} to ClickHouse", id);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                break;
            }
        });
    }

    // ── Load rules from ClickHouse (or file fallback) ───────────────────────
    {
        let ch = state.ch_storage.clone();
        let det = state.detection.clone();
        let rules_dir = rules_dir.clone();
        tokio::spawn(async move {
            // Wait briefly for migration to complete
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let (rules, overrides) = api::load_rules_from_clickhouse(&ch, &rules_dir).await;
            det.write().await.set_rules(rules, overrides);
        });
    }

    // ── Subscribe to Redis "system:reload_rules" ───────────────────────────
    {
        let ch = state.ch_storage.clone();
        let det = state.detection.clone();
        let redis_client = redis_client.clone();
        let rules_dir = rules_dir.clone();

        tokio::spawn(async move {
            if let Ok(conn) = redis_client.get_async_connection().await {
                let mut pubsub = conn.into_pubsub();
                if pubsub.subscribe("system:reload_rules").await.is_ok() {
                    let mut stream = pubsub.on_message();
                    while let Some(_) = stream.next().await {
                        tracing::info!("Reloading rules via Redis signal...");
                        let (rules, overrides) = api::load_rules_from_clickhouse(&ch, &rules_dir).await;
                        let count = rules.len();
                        det.write().await.set_rules(rules, overrides);
                        tracing::info!("Hot-reloaded {} SIGMA rules from Redis signal", count);
                    }
                }
            }
        });
    }

    // ── Periodic rule reload (safety net — bounds propagation to ≤60s) ────────
    {
        let ch = state.ch_storage.clone();
        let det = state.detection.clone();
        let rules_dir = rules_dir.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                let (rules, overrides) = api::load_rules_from_clickhouse(&ch, &rules_dir).await;
                det.write().await.set_rules(rules, overrides);
            }
        });
    }

    // ── Weekly SigmaHQ community rules auto-updater ────────────────────────
    // Remove any blocked rules that slipped into the DB (e.g. before blocklist existed)
    if role.full_platform() {
        let ch_bl = ch_storage_arc.clone();
        tokio::spawn(async move {
            for &id in detection::updater::GLOBAL_RULE_BLOCKLIST {
                let _ = ch_bl.delete_community_rule(id).await;
            }
        });
    }

    if role.full_platform() {
        detection::spawn_sigma_updater(
            rules_dir.clone(),
            redis_url.clone(),
            state.detection.clone(),
            state.ch_storage.clone(),
        );
    }

    // ── Multi-flow correlator (Tier 1/2/3 cross-flow detection) ───────────
    // Runs only on the elected leader — same election as threat tasks
    // so all singleton background work stays on one instance.
    if role.leader_jobs() {
        detection::multiflow::spawn(ch_storage_arc.clone(), election.clone());
    }



    let cors_origin: AllowOrigin = match std::env::var("CORS_ORIGIN") {
        Ok(origin) if !origin.is_empty() => {
            // Support comma-separated list of allowed origins
            let origins: Vec<HeaderValue> = origin
                .split(',')
                .filter_map(|o| o.trim().parse::<HeaderValue>().ok())
                .collect();
            if origins.is_empty() {
                AllowOrigin::any()
            } else {
                AllowOrigin::list(origins)
            }
        }
        _ => {
            tracing::warn!("CORS_ORIGIN not set — allowing all origins (POC/dev mode only)");
            AllowOrigin::any()
        }
    };

    let cors = CorsLayer::new()
        .allow_origin(cors_origin)
        .allow_methods(Any)
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            ACCEPT,
        ]);

    let app = Router::new()
        .route("/ws",              get(ws_handler))
        .route("/api/health",          get(api::health))
        .route("/api/client-errors",   post(api::report_client_error))
        .route("/api/admin/client-errors", get(api::list_client_errors))
        .route("/api/interfaces",  get(api::get_interfaces))
        .route("/api/interface",   get(api::get_interface).post(api::set_interface))
        .route("/api/start",       post(api::start_services))
        .route("/api/stop",        post(api::stop_services))
        .route("/api/agent-status",  get(api::get_agent_status))
        .route("/api/stats",         get(api::get_stats))
        .route("/api/stats/timeline", get(api::get_stats_timeline))
        .route("/api/stats/unified", get(api::get_unified_stats))
        .route("/api/events",        get(api::get_recent_events))
        .route("/api/top-ips",       get(api::get_top_ips))
        .route("/api/protocols",     get(api::get_protocols))
        .route("/api/severity",      get(api::get_severity))
        .route("/api/hits",          get(api::get_hits))
        .route("/api/entity-scores", get(api::get_entity_scores))
        .route("/api/network-map", get(api::get_network_map))
        .route("/api/network-map/node/:ip", get(api::get_network_map_node))
        .route("/api/network-map/search", get(api::search_network_map))
        .route("/api/scale-status", get(api::get_scale_status))
        .route("/api/rules",          get(api::get_rules).post(api::create_rule))
        .route("/api/rules/reload",   post(api::reload_rules_api))     // ← MUST be before /:id
        .route("/api/rules/sync-community", post(api::sync_community_rules_api))
        .route("/api/rules/hit-counts", get(api::get_rule_hit_counts))
        .route("/api/rules/:id",      get(api::get_rule_by_id).delete(api::delete_rule))
        .route("/api/threat-map",        get(api::get_threat_map))
        .route("/api/threat-intel-map",  get(api::get_threat_intel_map))
        .route("/api/threat-intel",                    get(api::get_threat_intel))
        .route("/api/threat-intel/feeds",              get(api::get_threat_intel_feed_summary))
        .route("/api/threat-intel/add",               post(api::add_manual_ioc))
        .route("/api/threat-intel/watchlist",         get(api::get_watchlist_iocs))
        .route("/api/threat-intel/watchlist/:value",  axum::routing::delete(api::delete_watchlist_ioc))
        .route("/api/threat-intel/:ip",               get(api::lookup_ioc))
        .route("/api/rules/:id/toggle", post(api::toggle_rule))
        .route("/api/export", get(api::export_report))
        .route("/api/export-logs", get(api::export_logs))
        .route("/api/license/generate",      post(api::generate_license))
        .route("/api/license/public-key",    get(api::get_license_public_key))
        .route("/api/licenses",              get(api::list_licenses))
        .route("/api/licenses/:id",          axum::routing::delete(api::delete_license))
        .route("/api/tenant/features",       get(api::get_tenant_features))
        .route("/api/tenant/features/:id",   post(api::set_tenant_features))
        .route("/api/settings", get(api::get_settings).post(api::update_settings))
        .route("/api/settings/smtp", get(api::get_global_smtp).post(api::update_global_smtp))
        .route("/api/settings/ai", get(api::get_ai_config).post(api::update_ai_config))
        .route("/api/settings/ai/providers", get(api::list_ai_providers).post(api::save_ai_provider))
        .route("/api/settings/ai/providers/test", post(api::test_ai_provider))
        .route("/api/settings/ai/providers/:name", delete(api::delete_ai_provider))
        .route("/api/settings/trusted-cloud", get(api::get_trusted_cloud_settings).put(api::update_trusted_cloud_settings))
        .route("/api/settings/trusted-cloud/suggestions/approve", post(api::approve_trusted_cloud_suggestion))
        .route("/api/settings/trusted-cloud/suggestions/reject",  post(api::reject_trusted_cloud_suggestion))
        .route("/api/triage",                     get(triage::get_triage))
        .route("/api/triage/run",                 post(triage::run_now))
        .route("/api/triage/:id/apply",           post(triage::apply))
        .route("/api/triage/:id/dismiss",         post(triage::dismiss))
        .route("/api/trusted-domains",            get(api::list_trusted_domains).post(api::add_trusted_domain))
        .route("/api/trusted-domains/delete",     post(api::delete_trusted_domain))
        .route("/api/trusted-domains/ai-suggest", post(api::ai_suggest_trusted_domains))
        .route("/api/assets",                  get(api::get_assets))
        .route("/api/assets/:ip",              get(api::get_asset_by_ip).put(api::update_asset_name))
        .route("/api/assets/:ip/trusted",      patch(api::set_asset_trusted_handler))
        .route("/api/assets/subnet-roles",     get(api::get_subnet_roles).put(api::set_subnet_roles))
        .route("/api/ipam/subnets", get(api::get_ipam_subnets))
        .merge(soar_routes())
        // Auth, users, and tenants are owned by auth-service (provigil-auth:3001) —
        // nginx proxies /api/auth/login, /api/auth/users, /api/auth/tenants,
        // /api/auth/me/, /api/auth/forgot/ there directly, so no duplicate
        // handlers live in ndr-engine for those.
        //
        // Announcements stay here: nginx has no dedicated /api/announcements
        // block on this branch, so this traffic falls through the generic
        // /api catch-all straight to ndr-engine.
        .route("/api/announcements",
            get(api::get_announcements_api)
            .post(api::create_announcement_api))
        .route("/api/announcements/active", get(api::get_active_announcements_api))
        .route("/api/announcements/:id/read", post(api::mark_announcement_read_api))
        .route("/api/announcements/:id",
            put(api::update_announcement_api)
            .delete(api::delete_announcement_api))
        .route("/api/support/messages", get(api::get_support_messages).post(api::create_support_message))
        .route("/api/support/messages/:id/review", post(api::review_support_message))
        .route("/api/support/messages/:id/reply", post(api::reply_support_message))
        .route("/api/support/messages/:id/forward", post(api::forward_support_message))
        .route("/api/support/messages/:id", delete(api::delete_support_message_api))
        .route("/api/admin/engines", get(api::get_engines))
        .route("/api/admin/engines/scale", post(api::scale_engines))
        .route("/api/admin/telemetry", get(api::get_telemetry))
        .route("/api/admin/severity-all-tenants", get(api::get_severity_all_tenants))
        .route("/api/admin/stats-all-tenants", get(api::get_stats_all_tenants))
        .route("/api/admin/top-ips-all-tenants", get(api::get_top_ips_all_tenants))
        .route("/api/admin/protocols-all-tenants", get(api::get_protocols_all_tenants))
        .route("/api/admin/threat-intel-all-tenants", get(api::get_threat_intel_all_tenants))
        .route("/api/admin/threat-map-all-tenants", get(api::get_threat_map_all_tenants))
        .route("/api/install-sensor.sh",          get(api::install_sensor_script))
.route("/api/sensor/pcap-uploader.py",   get(api::serve_pcap_uploader))
        .route("/api/uninstall-sensor.sh", get(api::uninstall_sensor_script))
        .route("/api/sensor-keys",
            get(api::get_sensor_keys)
            .post(api::create_sensor_key_api))
        .route("/api/sensor-keys/event-counts", get(api::get_sensor_event_counts))
        .route("/api/sensor-keys/recent-ips", get(api::get_sensor_recent_ips))
        .route("/api/sensor-keys/:id",
            delete(api::revoke_sensor_key_api))
        .route("/api/sensor-keys/:id/reactivate",
            post(api::reactivate_sensor_key_api))
        .route("/api/sensor/register",  post(api::sensor_register))
        .route("/api/sensor/heartbeat", post(api::sensor_heartbeat))
        .route("/api/sensor/checkin",   post(api::sensor_checkin))
        .route("/api/sensors/assign",   post(api::assign_sensor_to_user).delete(api::remove_sensor_from_user))
        .route("/api/sensors/assignments", get(api::list_sensor_assignments))
        .route("/api/ingest",           post(api::ingest_events))
        .route("/api/sensor/command",   get(api::get_sensor_command_api))
        .route("/api/sensor/control",   post(api::sensor_control_api))
        .route("/api/arkime/sessions",           get(api::arkime_sessions))
        .route("/api/arkime/pcap/:id",           get(api::arkime_pcap_download))
        .route("/api/arkime/status",             get(api::arkime_status))
        .route("/api/arkime/link/:community_id", get(api::arkime_session_link))
        .route("/api/events/by-cid",             get(api::get_events_by_cid))
        .route("/api/pcap/upload",               post(api::pcap_upload))
        .route("/api/pcap/upload-failed",        post(api::pcap_upload_failed))
        .route("/api/pcap/pending",              get(api::pcap_pending))
        .route("/api/pcap/:session_id",          get(api::pcap_download_stored))
        // Evidence routes
.route("/api/evidence/bundles", get(api::list_evidence_bundles))
.route("/api/evidence/bundle/:id", get(api::get_evidence_bundle))
.route("/api/evidence/bundle/:id/verify", get(api::verify_evidence_bundle))
.route("/api/evidence/bundle/:id/hold", post(api::set_evidence_legal_hold))
.route("/api/evidence/bundle/:id/annotate", post(api::annotate_evidence_bundle))
.route("/api/evidence/bundle/:id/annotations", get(api::get_evidence_annotations))
.route("/api/evidence/bundle/:id/contents", get(api::get_bundle_contents))
.route("/api/evidence/trigger", post(api::trigger_evidence_capture))
.route("/api/evidence/:cid", get(api::download_evidence_bundle))
.route("/api/evidence/:cid/log", get(api::get_evidence_log))
.route("/api/evidence/:cid/timeline", get(api::get_evidence_timeline))
.route("/api/evidence/iocs/check", get(api::check_shared_ioc))
 .route("/api/aria/chat",        post(api::aria_chat))
.route("/api/aria/status",      get(api::aria_status))
.route("/api/aria/investigate", post(api::aria_investigate))
.route("/api/aria/verdict",     get(api::aria_get_verdict))
.route("/api/ai-activity", get(api::get_ai_activity))
.route("/api/ai-suppressions",                get(api::list_ai_suppressions).post(api::create_manual_suppression))
.route("/api/ai-suppressions/:id/deactivate", patch(api::deactivate_ai_suppression_handler))
.route("/api/ai-suppressions/:id", delete(api::delete_ai_suppression_handler))
.route("/api/incidents",                          get(api::list_incidents))
.route("/api/incidents/:id/status/:status",       post(api::update_incident_status))
.route("/api/doh-providers",                      get(api::list_doh_providers).post(api::add_doh_provider))
.route("/api/doh-providers/:ip",                  delete(api::delete_doh_provider))
.route("/api/threat/predictions",         get(api::get_threat_predictions))
.route("/api/threat/predictions/history", get(api::get_threat_predictions_history))
.route("/api/threat/exposure",            get(api::get_threat_exposure))
.route("/api/threat/patterns",            get(api::get_threat_patterns))
.route("/api/admin/leader-status",        get(api::get_leader_status))
.route("/api/admin/version",              get(api::get_version_status))
.route("/api/admin/apply-update",         post(api::apply_update))
.route("/api/admin/active-sessions",      get(api::get_active_sessions))
.route("/api/geo-lookup",                 post(api::geo_lookup))
.route("/api/admin/sessions/:username",        delete(api::force_logout_user))
.route("/api/admin/sessions/:username/device", delete(api::force_logout_device))
.route("/api/monitor/kafka", get(monitor::kafka::kafka_status))
.route("/api/honeypots",      get(api::list_honeypots).post(api::create_honeypot))
.route("/api/honeypots/:id",  delete(api::remove_honeypot))
.route("/api/retrospective/fired-rules", get(api::list_fired_rules))
.route("/api/retrospective/scan",       post(api::start_retrospective_scan))
.route("/api/retrospective/scans",      get(api::list_retrospective_scans))
.route("/api/retrospective/scans/:id",  get(api::get_retrospective_scan))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(state.clone(), api::auth_middleware))
        .layer(axum::middleware::from_fn(ratelimit::rate_limit_middleware))

        .layer(DefaultBodyLimit::max(500 * 1024 * 1024)) // 500MB for PCAP uploads
        .layer(RequestDecompressionLayer::new())
        .layer(cors)
        // Outermost layer — a handler panic becomes a structured tracing::error!
        // + 500 response instead of an unlogged stderr dump that kills the task.
        .layer(CatchPanicLayer::custom(handle_panic));

    info!("🌐 API active");
    info!("❤  Health:    GET  http://0.0.0.0:3000/health");
    info!("📡 Kafka:     ndr-events (broker: {})",
        std::env::var(provigil_common::kafka::ENV_KAFKA_BROKERS)
            .unwrap_or_else(|_| provigil_common::kafka::DEFAULT_KAFKA_BROKERS.to_string()));

// ── Background: agent status monitor ─────────────────────────────────
    if role.full_platform() {
        let tx = tx.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let agent = std::env::var("NDR_AGENT_URL")
                .unwrap_or_else(|_| "http://host.docker.internal:3001".to_string());
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                if let Ok(resp) = client.get(format!("{}/agent/status", agent)).send().await {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        let msg = serde_json::json!({
                            "type": "agent_status",
                            "agent-z": data.get("agent-z").and_then(|v| v.as_str()).unwrap_or("stopped"),
                            "agent-s": data.get("agent-s").and_then(|v| v.as_str()).unwrap_or("stopped"),
                            "vector": data.get("vector").and_then(|v| v.as_str()).unwrap_or("stopped"),

                            "interface": data.get("interface").and_then(|v| v.as_str()).unwrap_or("eth0"),
                        });
                        let _ = tx.send(msg.to_string());
                    }
                }
            }
        });
    }

    // ── Background: Arkime → pcap_sessions sync — leader only ───────────────
    if role.leader_jobs() {
        let arkime_state = state.clone();
        let election_arkime = election.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            if election_arkime.is_leader() {
                api::sync_arkime_sessions(arkime_state).await;
            }
        });
    }

    // ── Background: daily PCAP file cleanup — leader only ────────────────────
    if role.leader_jobs() {
        let ch_cleanup = state.ch_storage.clone();
        let election_pcap = election.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            loop {
                if election_pcap.is_leader() {
                    cleanup_expired_pcaps(&ch_cleanup).await;
                }
                tokio::time::sleep(
                    std::time::Duration::from_secs(86400)
                ).await;
            }
        });
    }

    // ── Background: periodic in-memory cache eviction ────────────────────
    {
        let ws_dedup         = state.ws_dedup.clone();
        let trusted_cache    = state.trusted_asset_cache.clone();
        let entity_cache_evict = state.entity_cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                // Remove ws_dedup entries older than 30s (they've served their purpose)
                ws_dedup.retain(|_, v: &mut std::time::Instant| v.elapsed().as_secs() < 30);
                // Remove trusted_asset_cache entries older than 300s (their TTL)
                trusted_cache.retain(|_, v: &mut (bool, std::time::Instant)| v.1.elapsed().as_secs() < 300);
                // Cap entity_cache at 50k entries — drop all when over limit (rebuilt quickly)
                if entity_cache_evict.len() > 50_000 {
                    entity_cache_evict.clear();
                }
            }
        });
    }

    // ── Background: version update checker (on-prem only, every 6h) ─────
    if role.full_platform() {
        let update_status = state.update_status.clone();
        let http = state.http_client.clone();
        let current = env!("CARGO_PKG_VERSION").to_string();
        // Only check for updates when running on-prem (DEPLOY_MODE=local or unset)
        if std::env::var("DEPLOY_MODE").as_deref() != Ok("cloud") {
            tokio::spawn(async move {
                const VERSION_URL: &str =
                    "https://raw.githubusercontent.com/jithinjoseph-workspace/NDR-Demo/arkime/VERSION";
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_secs(6 * 3600)
                );
                loop {
                    interval.tick().await;
                    match http.get(VERSION_URL).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            if let Ok(body) = resp.text().await {
                                let latest = body.trim().to_string();
                                let available = latest != current && !latest.is_empty();
                                let mut s = update_status.write().await;
                                s.latest_version   = Some(latest);
                                s.update_available = available;
                                s.last_checked_secs = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default().as_secs();
                                if available {
                                    tracing::info!(
                                        "Update available: {} → {}",
                                        s.current_version,
                                        s.latest_version.as_deref().unwrap_or("")
                                    );
                                }
                            }
                        }
                        Err(e) => tracing::warn!("Version check failed: {}", e),
                        _ => {}
                    }
                }
            });
        }
    }

    // ── Start server + graceful shutdown with leader release ─────────────
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    let server   = axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>());

    tokio::select! {
        res = server => {
            if let Err(e) = res { tracing::error!("Server error: {}", e); }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutdown signal received — releasing leadership...");
            election.release().await;
            tracing::info!("Leadership released. Shutting down.");
        }
    }
}

/// Delete PCAP files older than 30 days from disk and remove their pcap_sessions rows.
/// Runs once per day. Queries every tenant DB for expired sessions.
async fn cleanup_expired_pcaps(ch: &storage::clickhouse::ClickhouseStorage) {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct ExpiredRow { file_path: String, #[allow(dead_code)] session_id: String, #[allow(dead_code)] tenant_id: String }

    // Get all tenant DBs from the tenants table
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct TenantRow { id: String }
    let tenants = ch.client
        .query("SELECT id FROM ndr.tenants WHERE active = 1")
        .fetch_all::<TenantRow>().await
        .unwrap_or_default();

    let mut total_deleted = 0usize;

    for t in &tenants {
        let db = if t.id == "default" {
            "ndr".to_string()
        } else {
            format!("ndr_{}", t.id.replace('-', "_"))
        };

        let rows = ch.client.query(&format!(
            "SELECT file_path, session_id, tenant_id \
             FROM {}.pcap_sessions \
             WHERE start_time < now() - INTERVAL 30 DAY \
             AND file_path != '' LIMIT 500",
            db
        )).fetch_all::<ExpiredRow>().await.unwrap_or_default();

        for row in &rows {
            // Delete file from disk only — pcap_sessions has TTL start_time + INTERVAL 30 DAY
            // so ClickHouse cleans up the DB rows automatically; ALTER TABLE DELETE is redundant
            // and heavyweight (async mutation, doesn't reclaim space immediately).
            if std::fs::remove_file(&row.file_path).is_ok() {
                total_deleted += 1;
            }
        }
    }

    if total_deleted > 0 {
        tracing::info!("PCAP cleanup: deleted {} expired files", total_deleted);
    }
}






/// Events the ingest queue can hold. See the comment where the channel is created.
fn ingest_queue_capacity() -> usize {
    std::env::var("INGEST_QUEUE_CAPACITY")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1_000)
        .unwrap_or(200_000)
}

/// Events handed to Kafka per flush by the drain task. Delivery of a whole flush is awaited
/// together, so larger flushes mean fewer waits per event, i.e. a higher publish rate.
/// Override: INGEST_DRAIN_BATCH (default 1000, minimum 50).
fn ingest_drain_batch() -> usize {
    std::env::var("INGEST_DRAIN_BATCH")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n >= 50)
        .unwrap_or(1000)
}
