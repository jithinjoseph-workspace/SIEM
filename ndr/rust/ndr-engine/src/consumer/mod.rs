// NDR Engine — Kafka Consumer (pure-Rust via rdkafka)
// License: Apache-2.0

use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::Message;
use redis::aio::MultiplexedConnection;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::api::AppState;
use crate::normalizer::EventSource;
use crate::storage::clickhouse::NdrEvent;

// How long (seconds) a fingerprint is remembered. 0 disables de-duplication.
// Memory: roughly events/sec x TTL x ~90 bytes in Redis (e.g. 1,000 eps x 900 s = ~80 MB).
fn dedup_ttl_secs() -> u64 {
    std::env::var("EVENT_DEDUP_TTL_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(900)
}

// Identity of an event = every stored column. Two events with the same fingerprint
// are the same log line delivered twice (e.g. a log file re-read after rotation).
fn event_fingerprint(tenant_id: &str, e: &NdrEvent) -> String {
    let mut h = Sha256::new();
    for part in [
        e.timestamp.to_string(), e.source.clone(), e.src_ip.clone(), e.dst_ip.clone(),
        e.src_port.to_string(), e.dst_port.to_string(), e.proto.clone(), e.event_type.clone(),
        e.community_id.clone(), e.sensor_id.clone(), tenant_id.to_string(), e.raw.clone(),
    ] {
        h.update(part.as_bytes());
        h.update([0x1f]);
    }
    let d = h.finalize();
    d[..16].iter().map(|b| format!("{:02x}", b)).collect()
}

// Drops events already seen within the TTL window. Atomic across all engine
// instances (Redis SET NX). Fails OPEN: on any Redis problem every event is kept,
// so this can never lose data - at worst a duplicate gets through.
async fn dedup_events(
    redis: &mut MultiplexedConnection,
    tenant_id: &str,
    events: Vec<NdrEvent>,
    ttl_secs: u64,
) -> Vec<NdrEvent> {
    if ttl_secs == 0 || events.is_empty() { return events; }
    let mut pipe = redis::pipe();
    for e in &events {
        pipe.cmd("SET")
            .arg(format!("ndr:evseen:{}", event_fingerprint(tenant_id, e)))
            .arg(1)
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs);
    }
    let res: Result<Vec<Option<String>>, _> = pipe.query_async(redis).await;
    match res {
        Ok(flags) if flags.len() == events.len() => {
            let total = events.len();
            let kept: Vec<NdrEvent> = events
                .into_iter()
                .zip(flags)
                .filter_map(|(e, first_time)| first_time.map(|_| e))
                .collect();
            let dropped = total - kept.len();
            if dropped > 0 {
                warn!("Dropped {} duplicate event(s) (tenant={})", dropped, tenant_id);
            }
            kept
        }
        Ok(_) => events,
        Err(e) => {
            warn!("Event de-dup check failed, keeping events (tenant={}): {}", tenant_id, e);
            events
        }
    }
}

// How many tenants' flushes run concurrently per 100ms tick, instead of the
// fully-sequential H-4 fix below. Separate knob from
// threat::tenant_scan_concurrency() - this runs every 100ms (not every
// several minutes to hours), so its right concurrency level is a different
// question with a different answer.
fn ingest_flush_concurrency() -> usize {
    std::env::var("INGEST_FLUSH_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(20)
}

// How often buffered events are flushed to ClickHouse (per tenant, one insert).
// It used to be a fixed 100 ms: every tenant with traffic did up to 10 inserts a
// second, each a tiny part plus Keeper writes on the Replicated tables. At
// hundreds of tenants that is thousands of inserts/s. 1 s gives ~10x fewer, larger
// inserts for at most ~1 s extra delay before an event is stored and alerted on.
// Override: INGEST_FLUSH_MS (minimum 100).
fn ingest_flush_interval_ms() -> u64 {
    std::env::var("INGEST_FLUSH_MS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|&n: &u64| n >= 100)
        .unwrap_or(1000)
}

// Drains the channel every INGEST_FLUSH_MS (default 1 s) and batch-inserts into ClickHouse.
// One HTTP round-trip per tenant per tick instead of one per event.
//
// H-3 fix: channel is bounded (50 K events). Backpressure: if CH is slow and
// the channel fills, try_send fails and the Kafka consumer slows naturally.
//
// H-4 fix (original): inserts were awaited directly instead of spawning a
// new task per tenant per tick, to eliminate *unbounded* task accumulation
// when CH is slow - explicitly scoped to "with 1-5 tenants each insert is
// sub-100ms, so sequential is fine". At real scale (hundreds-to-thousands
// of tenants, some pushing "lakhs of events") sequential no longer holds:
// if even a fraction of tenants have events in the same 100ms window, each
// one waiting on the previous tenant's ClickHouse round-trip pushes the
// flush past its own 100ms tick, backing up the whole pipeline. Fixed with
// *bounded* concurrency (a semaphore, capped by INGEST_FLUSH_CONCURRENCY)
// rather than reverting to the original unbounded tokio::spawn-per-tenant
// that H-4 was written to fix - this avoids both failure modes instead of
// trading one for the other.
async fn batch_writer(
    ch: Arc<crate::storage::clickhouse::ClickhouseStorage>,
    mut rx: mpsc::Receiver<(NdrEvent, String)>,
    redis: MultiplexedConnection,
) {
    let dedup_ttl = dedup_ttl_secs();
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(ingest_flush_interval_ms()));
    let mut buf: HashMap<String, Vec<NdrEvent>> = HashMap::new();
    let sem = Arc::new(tokio::sync::Semaphore::new(ingest_flush_concurrency()));

    loop {
        tokio::select! {
            Some((event, tenant_id)) = rx.recv() => {
                buf.entry(tenant_id).or_default().push(event);
            }
            _ = ticker.tick() => {
                if buf.is_empty() { continue; }
                let mut handles = Vec::with_capacity(buf.len());
                for (tenant_id, events) in buf.drain() {
                    let ch2        = Arc::clone(&ch);
                    let mut redis2 = redis.clone();
                    let sem2       = Arc::clone(&sem);
                    handles.push(tokio::spawn(async move {
                        let _permit = sem2.acquire().await;
                        let events = dedup_events(&mut redis2, &tenant_id, events, dedup_ttl).await;
                        if events.is_empty() { return; }
                        if let Err(e) = ch2.batch_insert_events_for_tenant(events, &tenant_id).await {
                            warn!("ClickHouse batch insert error (tenant={}): {}", tenant_id, e);
                        }
                    }));
                }
                futures_util::future::join_all(handles).await;
            }
        }
    }
}

pub async fn start_consumer(state: Arc<AppState>) {
    let kafka_cfg = provigil_common::kafka::KafkaConfig::from_env();
    let instance_id = std::env::var("INSTANCE_ID")
        .unwrap_or_else(|_| "1".to_string());
    let consumer: StreamConsumer = kafka_cfg
        .build_consumer("ndr-engine-group", &format!("ndr-engine-{}", instance_id));

    consumer
        .subscribe(&[provigil_common::kafka::TOPIC_NDR_EVENTS])
        .expect("Topic subscription failed");

    // Channel: consumer sends events here; batch_writer flushes to ClickHouse every 100 ms.
    // Bounded at 50 K entries — when CH is slow the channel fills and try_send fails, which
    // naturally slows Kafka consumption (backpressure) instead of OOM-ing the process.
    let (ch_tx, ch_rx) = mpsc::channel::<(NdrEvent, String)>(50_000);
    tokio::spawn(batch_writer(state.ch_storage.clone(), ch_rx, state.redis_mux.clone()));

    info!("Kafka consumer ready — group: ndr-engine-group instance: {}", instance_id);
    use dashmap::DashMap;
    let known_assets: Arc<DashMap<String, u32>> = Arc::new(DashMap::new());

    // Hourly eviction: remove IPs not seen in the last 24h to bound memory under DHCP churn
    {
        let assets_evict = known_assets.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                ticker.tick().await;
                let cutoff = chrono::Utc::now().timestamp() as u32;
                assets_evict.retain(|_, ts| cutoff.saturating_sub(*ts) < 86400);
            }
        });
    }

    // Background flush: dirty assets in Redis → ClickHouse every 30s
    {
        let ch_flush = state.ch_storage.clone();
        let mut redis_flush = state.redis_mux.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                ticker.tick().await;
                // SCAN instead of KEYS — non-blocking cursor scan, safe at any key count
                let mut dirty_keys: Vec<String> = Vec::new();
                let mut cursor: u64 = 0;
                loop {
                    let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                        .arg(cursor)
                        .arg("MATCH").arg("ndr:assets_dirty:*")
                        .arg("COUNT").arg(100u64)
                        .query_async(&mut redis_flush).await.unwrap_or((0, vec![]));
                    dirty_keys.extend(batch);
                    cursor = next;
                    if cursor == 0 { break; }
                }
                for dirty_key in dirty_keys {
                    let tenant_id = dirty_key.trim_start_matches("ndr:assets_dirty:").to_string();
                    let ips: Vec<String> = redis::cmd("SPOP")
                        .arg(&dirty_key).arg(200u64)
                        .query_async(&mut redis_flush).await.unwrap_or_default();
                    // Pipeline all HGETALL calls in one round-trip instead of
                    // issuing 200 sequential requests.
                    let hash_keys: Vec<String> = ips.iter()
                        .map(|ip| format!("ndr:asset:{}:{}", tenant_id, ip))
                        .collect();
                    let pipeline_results: Vec<Vec<String>> = {
                        let mut pipe = redis::pipe();
                        for key in &hash_keys {
                            pipe.cmd("HGETALL").arg(key);
                        }
                        pipe.query_async(&mut redis_flush).await.unwrap_or_default()
                    };
                    for (ip, pairs) in ips.into_iter().zip(pipeline_results.into_iter()) {
                        let mut m: std::collections::HashMap<String,String> = std::collections::HashMap::new();
                        let mut i = 0;
                        while i + 1 < pairs.len() { m.insert(pairs[i].clone(), pairs[i+1].clone()); i += 2; }
                        if m.get("mac").map(|s| s.is_empty()).unwrap_or(true) { continue; }
                        let asset = crate::storage::clickhouse::AssetRow {
                            ip:             ip.clone(),
                            mac:            m.get("mac").cloned().unwrap_or_default(),
                            hostname:       m.get("hostname").cloned().unwrap_or_default(),
                            vendor:         m.get("vendor").cloned().unwrap_or_default(),
                            os_guess:       m.get("os_guess").cloned().unwrap_or_default(),
                            device_type:    m.get("device_type").cloned().unwrap_or_default(),
                            custom_name:    m.get("custom_name").cloned().unwrap_or_default(),
                            tenant_id:      tenant_id.clone(),
                            first_seen:     m.get("first_seen").and_then(|s| s.parse().ok()).unwrap_or(0),
                            last_seen:      m.get("last_seen").and_then(|s| s.parse().ok()).unwrap_or(0),
                            ip_history:     m.get("ip_history").cloned().unwrap_or_else(|| "[]".to_string()),
                            trusted:        0,
                            threat_flagged: 0,
                            role:           String::new(),
                            criticality:    0,
                            open_ports:     "[]".to_string(),
                            subnet_role:    String::new(),
                            ja3_os:         String::new(),
                        };
                        let mut final_asset = asset;
                        if let Ok(Some(existing)) = ch_flush.get_asset_by_ip(&final_asset.tenant_id.clone(), &ip).await {
                            if existing.trusted != 0 { final_asset.trusted = existing.trusted; }
                            if existing.threat_flagged != 0 { final_asset.threat_flagged = existing.threat_flagged; }
                            if !existing.role.is_empty() { final_asset.role = existing.role; }
                            if existing.criticality != 0 { final_asset.criticality = existing.criticality; }
                            if existing.open_ports != "[]" && !existing.open_ports.is_empty() { final_asset.open_ports = existing.open_ports; }
                            if !existing.subnet_role.is_empty() { final_asset.subnet_role = existing.subnet_role; }
                            if !existing.ja3_os.is_empty() { final_asset.ja3_os = existing.ja3_os; }
                        }
                        if let Err(e) = ch_flush.upsert_asset(&final_asset).await {
                            warn!("Asset flush error {}: {}", ip, e);
                        }
                    }
                }
            }
        });
    }

    loop {
        match consumer.recv().await {
            Ok(msg) => {
                let payload = match msg.payload() {
                    Some(p) => p,
                    None => continue,
                };

                let raw: serde_json::Value = match serde_json::from_slice(payload) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let Some(mut event) = crate::normalizer::normalize(&raw) else { continue; };

                if event.should_drop() { continue; }

                let tenant_id = raw.get("tenant_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default")
                    .to_string();

                // ── Hash threat-intel: Zeek `files` log + Suricata `fileinfo` ──────
                // Extract SHA256 from the appropriate field location for each source,
                // then check against the MalwareBazaar feed DashSet.
                let is_file_event = event.log_source.as_deref() == Some("files")
                    || event.event_type.as_deref() == Some("fileinfo");
                if is_file_event {
                    let sha256_opt = raw.get("sha256")
                        .or_else(|| raw.get("fileinfo").and_then(|f| f.get("sha256")))
                        .and_then(|v| v.as_str())
                        .filter(|s| s.len() >= 32)
                        .map(|s| s.to_lowercase());

                    if let Some(sha256) = sha256_opt {
                        if state.enrichment.threat_intel.is_malicious_hash(&sha256) {
                            let now_ts  = chrono::Utc::now().timestamp() as u32;
                            let src     = event.source_ip.clone().unwrap_or_default();
                            let dst     = event.dest_ip.clone().unwrap_or_default();
                            // Use sha256 + 5-min bucket so repeated transfers of the
                            // same file within one window collapse to a single alert.
                            let bucket  = now_ts / 300 * 300;
                            let cid     = event.community_id.clone()
                                .unwrap_or_else(|| format!("hash-{}-{}", sha256, bucket));
                            let filename = raw.get("filename")
                                .or_else(|| raw.get("fileinfo").and_then(|f| f.get("filename")))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let details = serde_json::json!({
                                "sha256":   sha256,
                                "filename": filename,
                                "source":   match event.event_source {
                                    EventSource::Zeek => "zeek-files",
                                    _                 => "suricata-fileinfo",
                                },
                            });
                            let (az, as_) = if event.event_source == EventSource::Zeek {
                                (serde_json::to_string(&details).unwrap_or_else(|_| "{}".into()), "{}".to_string())
                            } else {
                                ("{}".to_string(), serde_json::to_string(&details).unwrap_or_else(|_| "{}".into()))
                            };
                            let ch_hit = crate::storage::clickhouse::NdrHit {
                                timestamp:          now_ts,
                                community_id:       cid,
                                src_ip:             src,
                                dst_ip:             dst,
                                score:              90.0,
                                severity:           "HIGH".to_string(),
                                tags:               vec!["malware-hash".to_string(), "threat-intel".to_string()],
                                sigma_hits:         vec![],
                                threat_intel:       1,
                                src_country:        String::new(),
                                dst_country:        String::new(),
                                tenant_id:          tenant_id.clone(),
                                correlation_status: "hash_match".to_string(),
                                agent_z_details:    az,
                                agent_s_details:    as_,
                                corroborated_at:    0,
                                agent_s_rule_id:    String::new(),
                                agent_s_category:   "malware".to_string(),
                                updated_at:         now_ts,
                                sensor_id:          raw.get("sensor_host")
                                    .and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            };
                            let ch_cl      = state.ch_storage.clone();
                            let tid_cl     = tenant_id.clone();
                            let sha_log    = sha256.clone();
                            let state_soar = Arc::clone(&state);
                            let cid_s      = ch_hit.community_id.clone();
                            let src_s      = ch_hit.src_ip.clone();
                            let dst_s      = ch_hit.dst_ip.clone();
                            let sev_s      = ch_hit.severity.clone();
                            let hit_soar   = crate::correlator::session::CorrelationHit {
                                community_id: cid_s.clone(),
                                agent_z:      event.clone(),
                                agent_s:      crate::normalizer::NormalizedEvent::blank(),
                                hit_time:     now_ts as u64,
                                source:       "hash".to_string(),
                            };
                            let risk_soar  = crate::scoring::RiskResult {
                                score:    90.0,
                                severity: crate::scoring::Severity::High,
                                tags:     vec!["malware-hash".to_string(), "threat-intel".to_string()],
                                reasons:  vec!["malware hash matched".to_string()],
                            };
                            let enrich_soar = crate::enrichment::EnrichmentData {
                                src_geo: None, dst_geo: None,
                                src_asn: None, dst_asn: None,
                                is_malicious: true,
                                direction: String::new(),
                                sensitive_country: false,
                            };
                            tokio::spawn(async move {
                                if let Err(e) = ch_cl.insert_hit_for_tenant(ch_hit, &tid_cl).await {
                                    tracing::warn!("hash-match hit insert error: {}", e);
                                    return;
                                }
                                tracing::info!(sha256 = %sha_log, tenant = %tid_cl, "malware hash matched — hit created");
                                let feats = crate::api::get_effective_features(&state_soar, &tid_cl).await;
#[cfg(feature = "soar")]
                                if feats.iter().any(|f| f == "soar") {
                                    crate::soar::execute_native_playbooks(
                                        &state_soar, hit_soar, risk_soar, enrich_soar, &tid_cl,
                                    ).await;
                                }
                                let ws_msg = serde_json::json!({
                                    "type": "hit", "community_id": cid_s,
                                    "src_ip": src_s, "dst_ip": dst_s,
                                    "severity": sev_s, "score": 90.0,
                                    "tenant_id": tid_cl,
                                });
                                crate::api::publish_event(&state_soar, &tid_cl, &ws_msg.to_string());
                            });
                        }
                    }
                }
                // ── JA3 threat-intel + asset OS fingerprint: Zeek ssl log ───────
                if event.log_source.as_deref() == Some("ssl") {
                    // Store SNI → dst_ip in passive_dns so alerts can show the
                    // hostname (e.g. "outlook.office365.com") instead of the raw IP.
                    if let (Some(sni), Some(dst)) = (
                        raw.get("server_name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()),
                        event.dest_ip.as_deref().filter(|s| !s.is_empty()),
                    ) {
                        let ch_cl  = state.ch_storage.clone();
                        let sni_s  = sni.to_string();
                        let dst_s  = dst.to_string();
                        tokio::spawn(async move {
                            let _ = ch_cl.insert_passive_dns(&dst_s, &sni_s).await;
                        });
                    }

                    let ja3_opt = raw.get("ja3")
                        .and_then(|v| v.as_str())
                        .filter(|s| s.len() == 32)
                        .map(|s| s.to_lowercase());
                    if let Some(ja3) = ja3_opt {
                        // Populate ja3_os on the asset for every ssl event regardless
                        // of whether the fingerprint is malicious. Only writes once
                        // (skips if ja3_os already set so we don't overwrite a manual label).
                        if let Some(os_label) = crate::enrichment::asset_intel::ja3_lookup(&ja3) {
                            if let Some(src) = event.source_ip.clone() {
                                let ch_cl  = state.ch_storage.clone();
                                let tid_cl = tenant_id.clone();
                                let os_str = os_label.to_string();
                                tokio::spawn(async move {
                                    if let Ok(Some(mut asset)) = ch_cl.get_asset_by_ip(&tid_cl, &src).await {
                                        if asset.ja3_os.is_empty() {
                                            asset.ja3_os = os_str;
                                            let _ = ch_cl.upsert_asset(&asset).await;
                                        }
                                    }
                                });
                            }
                        }

                        if state.enrichment.threat_intel.is_malicious_ja3(&ja3) {
                            let now_ts = chrono::Utc::now().timestamp() as u32;
                            let src    = event.source_ip.clone().unwrap_or_default();
                            let dst    = event.dest_ip.clone().unwrap_or_default();
                            let cid    = event.community_id.clone()
                                .unwrap_or_else(|| format!("ja3-{}-{}", ja3, now_ts / 300 * 300));
                            let sni    = raw.get("server_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let details = serde_json::json!({ "ja3": ja3, "sni": sni });
                            let ch_hit = crate::storage::clickhouse::NdrHit {
                                timestamp:          now_ts,
                                community_id:       cid,
                                src_ip:             src,
                                dst_ip:             dst,
                                score:              80.0,
                                severity:           "HIGH".to_string(),
                                tags:               vec!["malicious-ja3".to_string(), "threat-intel".to_string(), "encrypted-traffic".to_string()],
                                sigma_hits:         vec![],
                                threat_intel:       1,
                                src_country:        String::new(),
                                dst_country:        String::new(),
                                tenant_id:          tenant_id.clone(),
                                correlation_status: "ja3_match".to_string(),
                                agent_z_details:    serde_json::to_string(&details).unwrap_or_else(|_| "{}".into()),
                                agent_s_details:    "{}".to_string(),
                                corroborated_at:    0,
                                agent_s_rule_id:    String::new(),
                                agent_s_category:   "malware".to_string(),
                                updated_at:         now_ts,
                                sensor_id:          raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            };
                            let ch_cl      = state.ch_storage.clone();
                            let tid_cl     = tenant_id.clone();
                            let ja3_log    = ja3.clone();
                            let state_soar = Arc::clone(&state);
                            let cid_s      = ch_hit.community_id.clone();
                            let src_s      = ch_hit.src_ip.clone();
                            let dst_s      = ch_hit.dst_ip.clone();
                            let sev_s      = ch_hit.severity.clone();
                            let hit_soar   = crate::correlator::session::CorrelationHit {
                                community_id: cid_s.clone(),
                                agent_z:      event.clone(),
                                agent_s:      crate::normalizer::NormalizedEvent::blank(),
                                hit_time:     now_ts as u64,
                                source:       "ja3".to_string(),
                            };
                            let risk_soar  = crate::scoring::RiskResult {
                                score:    80.0,
                                severity: crate::scoring::Severity::High,
                                tags:     vec!["malicious-ja3".to_string(), "threat-intel".to_string()],
                                reasons:  vec!["malicious JA3 fingerprint matched".to_string()],
                            };
                            let enrich_soar = crate::enrichment::EnrichmentData {
                                src_geo: None, dst_geo: None,
                                src_asn: None, dst_asn: None,
                                is_malicious: true,
                                direction: String::new(),
                                sensitive_country: false,
                            };
                            tokio::spawn(async move {
                                if let Err(e) = ch_cl.insert_hit_for_tenant(ch_hit, &tid_cl).await {
                                    tracing::warn!("ja3-match hit insert error: {}", e);
                                    return;
                                }
                                tracing::info!(ja3 = %ja3_log, tenant = %tid_cl, "malicious JA3 matched — hit created");
                                let feats = crate::api::get_effective_features(&state_soar, &tid_cl).await;
#[cfg(feature = "soar")]
                                if feats.iter().any(|f| f == "soar") {
                                    crate::soar::execute_native_playbooks(
                                        &state_soar, hit_soar, risk_soar, enrich_soar, &tid_cl,
                                    ).await;
                                }
                                let ws_msg = serde_json::json!({
                                    "type": "hit", "community_id": cid_s,
                                    "src_ip": src_s, "dst_ip": dst_s,
                                    "severity": sev_s, "score": 80.0,
                                    "tenant_id": tid_cl,
                                });
                                crate::api::publish_event(&state_soar, &tid_cl, &ws_msg.to_string());
                            });
                        }
                    }
                }

                // ── DoH evasion: HTTPS traffic to known DNS-over-HTTPS providers ─
                // A host bypassing the local resolver to use DoH is a policy violation
                // and common C2 evasion technique.
                // Provider list is DB-backed (ndr.doh_providers) — add/remove via admin API.
                {
                    let dst_port = event.dest_port.unwrap_or(0);
                    let dst_ip   = event.dest_ip.as_deref().unwrap_or("");
                    let is_doh_ip = state.doh_ips.read().await.contains(dst_ip);
                    let is_conn_or_ssl = matches!(
                        event.log_source.as_deref().or(event.event_type.as_deref()),
                        Some("conn") | Some("ssl") | Some("flow")
                    );
                    if is_conn_or_ssl && dst_port == 443 && is_doh_ip {
                        if let Some(src) = event.source_ip.clone() {
                            if crate::enrichment::is_private_ip(&src) {
                                let now_ts = chrono::Utc::now().timestamp() as u32;
                                let bucket = now_ts / 300 * 300;
                                let cid    = event.community_id.clone()
                                    .unwrap_or_else(|| format!("doh-{}-{}-{}", src, dst_ip, bucket));
                                let ch_hit = crate::storage::clickhouse::NdrHit {
                                    timestamp:          now_ts,
                                    community_id:       cid,
                                    src_ip:             src.clone(),
                                    dst_ip:             dst_ip.to_string(),
                                    score:              65.0,
                                    severity:           "MEDIUM".to_string(),
                                    tags:               vec!["doh-evasion".to_string(), "t:command-and-control".to_string()],
                                    sigma_hits:         vec![],
                                    threat_intel:       0,
                                    src_country:        String::new(),
                                    dst_country:        String::new(),
                                    tenant_id:          tenant_id.clone(),
                                    correlation_status: "doh_evasion".to_string(),
                                    agent_z_details:    serde_json::json!({ "dst_ip": dst_ip, "dst_port": 443 }).to_string(),
                                    agent_s_details:    "{}".to_string(),
                                    corroborated_at:    0,
                                    agent_s_rule_id:    String::new(),
                                    agent_s_category:   "policy-violation".to_string(),
                                    updated_at:         now_ts,
                                    sensor_id:          raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                };
                                let ch_cl      = state.ch_storage.clone();
                                let tid_cl     = tenant_id.clone();
                                let src_log    = src.clone();
                                let state_soar = Arc::clone(&state);
                                let cid_s      = ch_hit.community_id.clone();
                                let src_s      = ch_hit.src_ip.clone();
                                let dst_s      = ch_hit.dst_ip.clone();
                                let sev_s      = ch_hit.severity.clone();
                                let hit_soar   = crate::correlator::session::CorrelationHit {
                                    community_id: cid_s.clone(),
                                    agent_z:      event.clone(),
                                    agent_s:      crate::normalizer::NormalizedEvent::blank(),
                                    hit_time:     now_ts as u64,
                                    source:       "doh".to_string(),
                                };
                                let risk_soar  = crate::scoring::RiskResult {
                                    score:    65.0,
                                    severity: crate::scoring::Severity::Medium,
                                    tags:     vec!["doh-evasion".to_string(), "t:command-and-control".to_string()],
                                    reasons:  vec!["DoH evasion — HTTPS to known DNS-over-HTTPS resolver".to_string()],
                                };
                                let enrich_soar = crate::enrichment::EnrichmentData {
                                    src_geo: None, dst_geo: None,
                                    src_asn: None, dst_asn: None,
                                    is_malicious: false,
                                    direction: "outbound".to_string(),
                                    sensitive_country: false,
                                };
                                tokio::spawn(async move {
                                    if let Err(e) = ch_cl.insert_hit_for_tenant(ch_hit, &tid_cl).await {
                                        tracing::warn!("doh-evasion hit insert error: {}", e);
                                        return;
                                    }
                                    tracing::info!(src = %src_log, tenant = %tid_cl, "DoH evasion detected — hit created");
#[cfg(feature = "soar")]
                                    crate::soar::execute_native_playbooks(
                                        &state_soar, hit_soar, risk_soar, enrich_soar, &tid_cl,
                                    ).await;
                                    let ws_msg = serde_json::json!({
                                        "type": "hit", "community_id": cid_s,
                                        "src_ip": src_s, "dst_ip": dst_s,
                                        "severity": sev_s, "score": 65.0,
                                        "tenant_id": tid_cl,
                                    });
                                    crate::api::publish_event(&state_soar, &tid_cl, &ws_msg.to_string());
                                });
                            }
                        }
                    }
                }
                // ────────────────────────────────────────────────────────────────

                let source_str = match event.event_source {
                    EventSource::Zeek     => "agent-z",
                    EventSource::Suricata => "agent-s",
                    _ => "unknown",
                }.to_string();

                let ch_event = NdrEvent {
                    timestamp: if event.timestamp > 0 {
                        (event.timestamp / 1000) as u32
                    } else {
                        chrono::Utc::now().timestamp() as u32
                    },
                    source: source_str,
                    src_ip: event.source_ip.clone().unwrap_or_default(),
                    dst_ip: event.dest_ip.clone().unwrap_or_default(),
                    src_port: event.source_port.unwrap_or(0),
                    dst_port: event.dest_port.unwrap_or(0),
                    proto: event.proto.clone().unwrap_or_default(),
                    event_type: event.event_type.clone()
                        .or(event.log_source.clone())
                        .unwrap_or_default(),
                    community_id: event.community_id.clone().unwrap_or_default(),
                    raw: raw.to_string(),
                    tenant_id: tenant_id.clone(),
                    sensor_id: raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                };

                // ARP events are only used for asset discovery — never store as ndr_events
                if event.log_source.as_deref() == Some("arp") {
                    // fall through to ARP asset handler below
                } else {
                    if ch_tx.try_send((ch_event, tenant_id.clone())).is_err() {
                        warn!("ClickHouse write channel full — dropping event for tenant {}", tenant_id);
                    }
                }

                // --- Asset Identification (DHCP) ---
                if event.log_source.as_deref() == Some("dhcp") {
                    let mac = raw.get("mac").and_then(|v| v.as_str()).unwrap_or("");
                    let ip = raw.get("assigned_addr")
                        .or_else(|| raw.get("requested_addr"))
                        .or_else(|| raw.get("client_addr"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let hostname = raw.get("host_name")
                        .or_else(|| raw.get("client_fqdn"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    if !mac.is_empty() && !ip.is_empty() {
                        let is_gateway = (ip.ends_with(".1") || ip.ends_with(".254"))
                            && !ip.starts_with("169.254.");
                        let vendor = state.enrichment.asset_id.lookup_vendor(mac);
                        // Queue for vendor backfill if OUI not resolved
                        if vendor == "Unknown" {
                            let mut rc = state.redis_mux.clone();
                            let qi = format!("{}|{}|{}", tenant_id, ip, mac);
                            tokio::spawn(async move {
                                let _: Result<i64, _> = redis::cmd("SADD")
                                    .arg("ndr:vendor_pending").arg(qi)
                                    .query_async(&mut rc).await;
                            });
                        }
                        let device_type = state.enrichment.asset_id.guess_device_type(hostname, &vendor, is_gateway);
                        let asset = crate::storage::clickhouse::AssetRow {
                            ip:             ip.to_string(),
                            mac:            mac.to_string(),
                            hostname:       hostname.to_string(),
                            vendor,
                            os_guess:       "".to_string(),
                            device_type,
                            custom_name:    "".to_string(),
                            tenant_id:      tenant_id.clone(),
                            first_seen:     chrono::Utc::now().timestamp() as u32,
                            last_seen:      chrono::Utc::now().timestamp() as u32,
                            ip_history:     "[]".to_string(),
                            trusted:        0,
                            threat_flagged: 0,
                            role:           String::new(),
                            criticality:    0,
                            open_ports:     "[]".to_string(),
                            subnet_role:    String::new(),
                            ja3_os:         String::new(),
                        };
                        let ch_clone = state.ch_storage.clone();
                        let mac_clone = mac.to_string();
                        let tenant_clone2 = tenant_id.clone();
                        tokio::spawn(async move {
                            let now_ts = chrono::Utc::now().timestamp() as u32;
                            let mut final_asset = asset;

                            if !mac_clone.is_empty() {
                                if let Ok(Some(existing_by_mac)) = ch_clone.get_asset_by_mac(&tenant_clone2, &mac_clone).await {
                                    if !existing_by_mac.os_guess.is_empty() {
                                        final_asset.os_guess = existing_by_mac.os_guess.clone();
                                    }
                                    if !existing_by_mac.custom_name.is_empty() {
                                        final_asset.custom_name = existing_by_mac.custom_name.clone();
                                    }
                                    if !existing_by_mac.hostname.is_empty() && final_asset.hostname.is_empty() {
                                        final_asset.hostname = existing_by_mac.hostname.clone();
                                    }
                                    if existing_by_mac.first_seen > 0 {
                                        final_asset.first_seen = existing_by_mac.first_seen;
                                    }
                                    if existing_by_mac.ip != final_asset.ip {
                                        tracing::info!(
                                            "[HybridAsset] MAC {} moved: {} → {}",
                                            mac_clone, existing_by_mac.ip, final_asset.ip
                                        );
                                        let mut history: Vec<serde_json::Value> =
                                            serde_json::from_str(&existing_by_mac.ip_history)
                                                .unwrap_or_default();
                                        history.push(serde_json::json!({
                                            "ip": existing_by_mac.ip,
                                            "start_time": existing_by_mac.first_seen,
                                            "end_time": now_ts
                                        }));
                                        if history.len() > 50 {
                                            let skip = history.len() - 50;
                                            history = history.into_iter().skip(skip).collect();
                                        }
                                        final_asset.ip_history =
                                            serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string());
                                    } else {
                                        final_asset.ip_history = existing_by_mac.ip_history.clone();
                                    }
                                    // Preserve user-set fields that the pipeline never overwrites
                                    if existing_by_mac.trusted != 0 { final_asset.trusted = existing_by_mac.trusted; }
                                    if existing_by_mac.threat_flagged != 0 { final_asset.threat_flagged = existing_by_mac.threat_flagged; }
                                    if !existing_by_mac.role.is_empty() { final_asset.role = existing_by_mac.role.clone(); }
                                    if existing_by_mac.criticality != 0 { final_asset.criticality = existing_by_mac.criticality; }
                                    if existing_by_mac.open_ports != "[]" && !existing_by_mac.open_ports.is_empty() { final_asset.open_ports = existing_by_mac.open_ports.clone(); }
                                    if !existing_by_mac.subnet_role.is_empty() { final_asset.subnet_role = existing_by_mac.subnet_role.clone(); }
                                    if !existing_by_mac.ja3_os.is_empty() { final_asset.ja3_os = existing_by_mac.ja3_os.clone(); }
                                }
                            } else {
                                if let Ok(Some(existing)) = ch_clone.get_asset_by_ip(&final_asset.tenant_id, &final_asset.ip).await {
                                    if !existing.os_guess.is_empty() { final_asset.os_guess = existing.os_guess; }
                                    if existing.first_seen > 0 { final_asset.first_seen = existing.first_seen; }
                                    final_asset.ip_history = existing.ip_history;
                                    if existing.trusted != 0 { final_asset.trusted = existing.trusted; }
                                    if existing.threat_flagged != 0 { final_asset.threat_flagged = existing.threat_flagged; }
                                    if !existing.role.is_empty() { final_asset.role = existing.role; }
                                    if existing.criticality != 0 { final_asset.criticality = existing.criticality; }
                                    if existing.open_ports != "[]" && !existing.open_ports.is_empty() { final_asset.open_ports = existing.open_ports; }
                                    if !existing.subnet_role.is_empty() { final_asset.subnet_role = existing.subnet_role; }
                                    if !existing.ja3_os.is_empty() { final_asset.ja3_os = existing.ja3_os; }
                                }
                            }

                            if let Err(e) = ch_clone.upsert_asset(&final_asset).await {
                                warn!("Asset upsert error: {}", e);
                            }
                        });
                    }
                } else if event.log_source.as_deref() == Some("software") {
                    let ip = raw.get("host")
                        .or_else(|| raw.get("id.orig_h"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let software_type = raw.get("software_type").and_then(|v| v.as_str()).unwrap_or("");
                    let name = raw.get("name").and_then(|v| v.as_str()).unwrap_or("");

                    if !ip.is_empty() && software_type == "OS" && !name.is_empty() {
                        let ch_clone = state.ch_storage.clone();
                        let ip_clone = ip.to_string();
                        let os_name = name.to_string();
                        let tenant_clone = tenant_id.clone();
                        tokio::spawn(async move {
                            if let Ok(Some(mut updated_asset)) = ch_clone.get_asset_by_ip(&tenant_clone, &ip_clone).await {
                                updated_asset.os_guess = os_name;
                                updated_asset.last_seen = chrono::Utc::now().timestamp() as u32;
                                if let Err(e) = ch_clone.upsert_asset(&updated_asset).await {
                                    warn!("Asset OS upsert error: {}", e);
                                }
                            }
                        });
                    }
                } else if event.log_source.as_deref() == Some("http") {
                    let ip = raw.get("id.orig_h")
                        .or_else(|| raw.get("src_ip"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let user_agent = raw.get("user_agent")
                        .or_else(|| raw.get("useragent"))
                        .and_then(|v| v.as_str())
                        .or_else(|| raw.get("http").and_then(|h| h.get("http_user_agent")).and_then(|v| v.as_str()))
                        .unwrap_or("");

                    if !ip.is_empty() && !user_agent.is_empty() {
                        let os_guess = guess_os_from_ua(user_agent);
                        if !os_guess.is_empty() {
                            let ch_clone = state.ch_storage.clone();
                            let ip_clone = ip.to_string();
                            let tenant_clone = tenant_id.clone();
                            tokio::spawn(async move {
                                if let Ok(Some(mut asset)) = ch_clone.get_asset_by_ip(&tenant_clone, &ip_clone).await {
                                    if asset.os_guess.is_empty() {
                                        asset.os_guess = os_guess;
                                        asset.last_seen = chrono::Utc::now().timestamp() as u32;
                                        if let Err(e) = ch_clone.upsert_asset(&asset).await {
                                            warn!("Asset OS (UA) upsert error: {}", e);
                                        }
                                    }
                                }
                            });
                        }
                    }
                } else if event.log_source.as_deref() == Some("arp") {
                    let mac = raw.get("mac").or_else(|| raw.get("SHA")).and_then(|v| v.as_str()).unwrap_or("");
                    let ip  = raw.get("SPA").or_else(|| raw.get("ip")).and_then(|v| v.as_str()).unwrap_or("");

                    if !mac.is_empty() && !ip.is_empty() {
                        let now        = chrono::Utc::now().timestamp() as u32;
                        let hash_key   = format!("ndr:asset:{}:{}", tenant_id, ip);
                        let dirty_key  = format!("ndr:assets_dirty:{}", tenant_id);
                        let mut rc     = state.redis_mux.clone();
                        let ip_s       = ip.to_string();
                        let mac_s      = mac.to_string();
                        let tid        = tenant_id.clone();
                        let is_gateway = (ip.ends_with(".1") || ip.ends_with(".254"))
                            && !ip.starts_with("169.254.");
                        let vendor     = state.enrichment.asset_id.lookup_vendor(mac);
                        let device_type = state.enrichment.asset_id.guess_device_type("", &vendor, is_gateway);
                        let conflict_ch = state.ch_storage.clone();

                        // Vendor backfill if unresolved
                        if vendor == "Unknown" {
                            let mut rc2 = state.redis_mux.clone();
                            let qi = format!("{}|{}|{}", tenant_id, ip, mac);
                            tokio::spawn(async move {
                                let _: Result<i64, _> = redis::cmd("SADD")
                                    .arg("ndr:vendor_pending").arg(qi)
                                    .query_async(&mut rc2).await;
                            });
                        }

                        tokio::spawn(async move {
                            // Read existing asset from Redis (pure in-memory, no ClickHouse)
                            let pairs: Vec<String> = redis::cmd("HGETALL")
                                .arg(&hash_key)
                                .query_async(&mut rc).await.unwrap_or_default();
                            let mut existing: std::collections::HashMap<String,String> = std::collections::HashMap::new();
                            let mut i = 0;
                            while i + 1 < pairs.len() { existing.insert(pairs[i].clone(), pairs[i+1].clone()); i += 2; }

                            let existing_mac = existing.get("mac").cloned().unwrap_or_default();

                            // IP conflict detection — purely from Redis, zero ClickHouse calls
                            if !existing_mac.is_empty() && existing_mac != mac_s && !existing_mac.contains("00:00:00") {
                                warn!("IP CONFLICT: {} claimed by {} and {} — possible ARP spoofing", ip_s, existing_mac, mac_s);
                                let hit = crate::storage::clickhouse::NdrHit {
                                    timestamp:          now,
                                    community_id:       format!("arp-conflict-{}", ip_s),
                                    src_ip:             mac_s.clone(),
                                    dst_ip:             ip_s.clone(),
                                    score:              85.0,
                                    severity:           "HIGH".to_string(),
                                    tags:               vec!["ip-conflict".to_string(), "arp-spoofing".to_string()],
                                    sigma_hits:         vec![],
                                    threat_intel:       0,
                                    src_country:        "".to_string(),
                                    dst_country:        "".to_string(),
                                    tenant_id:          tid.clone(),
                                    correlation_status: "arp_conflict".to_string(),
                                    agent_z_details:    "{}".to_string(),
                                    agent_s_details:    "{}".to_string(),
                                    corroborated_at:    0,
                                    agent_s_rule_id:    "".to_string(),
                                    agent_s_category:   "".to_string(),
                                    updated_at:         now,
                                    sensor_id:          raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                };
                                let _ = conflict_ch.insert_hit_for_tenant(hit, &tid).await;
                            }

                            // Merge: preserve existing enriched fields, update last_seen
                            let final_vendor      = if existing.get("vendor").map(|v| v != "Unknown" && !v.is_empty()).unwrap_or(false) { existing["vendor"].clone() } else { vendor };
                            let final_os          = existing.get("os_guess").cloned().unwrap_or_default();
                            let final_hostname    = existing.get("hostname").cloned().unwrap_or_default();
                            let final_device_type = if existing.get("device_type").map(|v| v != "unknown" && !v.is_empty()).unwrap_or(false) { existing["device_type"].clone() } else { device_type };
                            let final_custom      = existing.get("custom_name").cloned().unwrap_or_default();
                            let first_seen        = existing.get("first_seen").and_then(|s| s.parse::<u32>().ok()).unwrap_or(now);
                            let ip_history        = existing.get("ip_history").cloned().unwrap_or_else(|| "[]".to_string());

                            // Write back to Redis (hot store)
                            let _: Result<(), _> = redis::cmd("HSET")
                                .arg(&hash_key)
                                .arg("mac").arg(&mac_s)
                                .arg("hostname").arg(&final_hostname)
                                .arg("vendor").arg(&final_vendor)
                                .arg("os_guess").arg(&final_os)
                                .arg("device_type").arg(&final_device_type)
                                .arg("custom_name").arg(&final_custom)
                                .arg("first_seen").arg(first_seen)
                                .arg("last_seen").arg(now)
                                .arg("ip_history").arg(&ip_history)
                                .query_async(&mut rc).await;

                            // 24h TTL so stale assets auto-expire
                            let _: Result<(), _> = redis::cmd("EXPIRE")
                                .arg(&hash_key).arg(86400u64)
                                .query_async(&mut rc).await;

                            // Mark as dirty for next 30s flush to ClickHouse
                            let _: Result<i64, _> = redis::cmd("SADD")
                                .arg(&dirty_key).arg(&ip_s)
                                .query_async(&mut rc).await;
                        });
                    }
                } else if event.log_source.as_deref() == Some("ipam") {
                    let cidr      = raw.get("cidr").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let interface = raw.get("interface").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let local_ip  = raw.get("local_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let gateway   = raw.get("gateway").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let sensor_id = raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    if !cidr.is_empty() {
                        let ch_clone = state.ch_storage.clone();
                        let tid = tenant_id.clone();
                        tokio::spawn(async move {
                            if let Err(e) = ch_clone.upsert_ipam_subnet(&tid, &interface, &cidr, &local_ip, &gateway, &sensor_id).await {
                                tracing::debug!("IPAM subnet upsert: {}", e);
                            } else {
                                tracing::debug!("IPAM: {} {} → {}", sensor_id, interface, cidr);
                            }
                        });
                    }
                } else if event.log_source.as_deref() == Some("dns") {
                    let ip = raw.get("id.orig_h").or_else(|| raw.get("src_ip")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let query = raw.get("query").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let mut domain = query.clone();
                    let mut resolved_ips: Vec<String> = Vec::new();

                    if let Some(ans_val) = raw.get("answers") {
                        if let Some(ans_arr) = ans_val.as_array() {
                            for ans in ans_arr {
                                if let Some(s) = ans.as_str() { resolved_ips.push(s.to_string()); }
                            }
                        } else if let Some(ans_str) = ans_val.as_str() {
                            for s in ans_str.split(',') { resolved_ips.push(s.trim().to_string()); }
                        }
                    }
                    if let Some(dns_obj) = raw.get("dns") {
                        if domain.is_empty() {
                            domain = dns_obj.get("rrname").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        }
                        if let Some(rdata) = dns_obj.get("rdata").and_then(|v| v.as_str()) {
                            resolved_ips.push(rdata.to_string());
                        }
                        if let Some(grouped) = dns_obj.get("grouped").and_then(|v| v.get("A")).and_then(|v| v.as_array()) {
                            for ans in grouped {
                                if let Some(s) = ans.as_str() { resolved_ips.push(s.to_string()); }
                            }
                        }
                    }

                    if !domain.is_empty() && !domain.ends_with(".local") {
                        // Real-time domain IOC check against the in-memory threat intel DashSet.
                        // This fires immediately on the DNS query — no 30-min sweep delay.
                        if state.enrichment.threat_intel.is_malicious_domain(&domain) {
                            let now_ts  = chrono::Utc::now().timestamp() as u32;
                            let src     = event.source_ip.clone().unwrap_or_default();
                            let dst     = event.dest_ip.clone().unwrap_or_default();
                            let bucket  = now_ts / 300 * 300;
                            let cid     = event.community_id.clone()
                                .unwrap_or_else(|| format!("domain-{}-{}", bucket,
                                    domain.replace('.', "-")));
                            let details = serde_json::json!({ "domain": domain, "query": query });
                            let ch_hit  = crate::storage::clickhouse::NdrHit {
                                timestamp:          now_ts,
                                community_id:       cid,
                                src_ip:             src,
                                dst_ip:             dst,
                                score:              85.0,
                                severity:           "HIGH".to_string(),
                                tags:               vec!["malicious-domain".to_string(), "threat-intel".to_string()],
                                sigma_hits:         vec![],
                                threat_intel:       1,
                                src_country:        String::new(),
                                dst_country:        String::new(),
                                tenant_id:          tenant_id.clone(),
                                correlation_status: "domain_match".to_string(),
                                agent_z_details:    serde_json::to_string(&details).unwrap_or_else(|_| "{}".into()),
                                agent_s_details:    "{}".to_string(),
                                corroborated_at:    0,
                                agent_s_rule_id:    String::new(),
                                agent_s_category:   "c2".to_string(),
                                updated_at:         now_ts,
                                sensor_id:          raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            };
                            let ch_cl      = state.ch_storage.clone();
                            let tid_cl     = tenant_id.clone();
                            let dom_log    = domain.clone();
                            let state_soar = Arc::clone(&state);
                            let cid_s      = ch_hit.community_id.clone();
                            let src_s      = ch_hit.src_ip.clone();
                            let dst_s      = ch_hit.dst_ip.clone();
                            let sev_s      = ch_hit.severity.clone();
                            let hit_soar   = crate::correlator::session::CorrelationHit {
                                community_id: cid_s.clone(),
                                agent_z:      event.clone(),
                                agent_s:      crate::normalizer::NormalizedEvent::blank(),
                                hit_time:     now_ts as u64,
                                source:       "domain".to_string(),
                            };
                            let risk_soar  = crate::scoring::RiskResult {
                                score:    85.0,
                                severity: crate::scoring::Severity::High,
                                tags:     vec!["malicious-domain".to_string(), "threat-intel".to_string()],
                                reasons:  vec!["malicious domain in DNS query".to_string()],
                            };
                            let enrich_soar = crate::enrichment::EnrichmentData {
                                src_geo: None, dst_geo: None,
                                src_asn: None, dst_asn: None,
                                is_malicious: true,
                                direction: String::new(),
                                sensitive_country: false,
                            };
                            tokio::spawn(async move {
                                if let Err(e) = ch_cl.insert_hit_for_tenant(ch_hit, &tid_cl).await {
                                    tracing::warn!("domain-match hit insert error: {}", e);
                                    return;
                                }
                                tracing::info!(domain = %dom_log, tenant = %tid_cl, "malicious domain in DNS query — hit created");
                                let feats = crate::api::get_effective_features(&state_soar, &tid_cl).await;
#[cfg(feature = "soar")]
                                if feats.iter().any(|f| f == "soar") {
                                    crate::soar::execute_native_playbooks(
                                        &state_soar, hit_soar, risk_soar, enrich_soar, &tid_cl,
                                    ).await;
                                }
                                let ws_msg = serde_json::json!({
                                    "type": "hit", "community_id": cid_s,
                                    "src_ip": src_s, "dst_ip": dst_s,
                                    "severity": sev_s, "score": 85.0,
                                    "tenant_id": tid_cl,
                                });
                                crate::api::publish_event(&state_soar, &tid_cl, &ws_msg.to_string());
                            });
                        }

                        resolved_ips.retain(|ans_str| ans_str.parse::<std::net::IpAddr>().is_ok());
                        if !resolved_ips.is_empty() {
                            let ch_clone = state.ch_storage.clone();
                            tokio::spawn(async move {
                                let entries: Vec<(String, String)> = resolved_ips
                                    .into_iter()
                                    .map(|ip| (ip, domain.clone()))
                                    .collect();
                                if let Err(e) = ch_clone.batch_insert_passive_dns(&entries).await {
                                    tracing::warn!("Passive DNS batch insert error: {}", e);
                                }
                            });
                        }
                    }

                    if !ip.is_empty() && query.ends_with(".local") {
                        let raw_label = query.strip_suffix(".local").unwrap_or(&query);
                        // mDNS service labels sometimes encode JSON: '{"nm":"boult",...}._svc._udp'
                        // Extract the device name from the JSON prefix if present.
                        let hostname = if raw_label.starts_with('{') {
                            if let Some(json_end) = raw_label.find('}') {
                                let json_part = &raw_label[..=json_end];
                                serde_json::from_str::<serde_json::Value>(json_part)
                                    .ok()
                                    .and_then(|v| v["nm"].as_str().map(|s| s.to_string()))
                                    .unwrap_or_else(|| raw_label.to_string())
                            } else {
                                raw_label.to_string()
                            }
                        } else {
                            raw_label.to_string()
                        };
                        let ch_clone = state.ch_storage.clone();
                        let ip_clone = ip.clone();
                        let tenant_clone = tenant_id.clone();
                        let is_gateway = (ip.ends_with(".1") || ip.ends_with(".254"))
                            && !ip.starts_with("169.254.");
                        tokio::spawn(async move {
                            if let Ok(Some(mut updated_asset)) = ch_clone.get_asset_by_ip(&tenant_clone, &ip_clone).await {
                                if updated_asset.hostname.is_empty() {
                                    updated_asset.hostname = hostname;
                                    let h = updated_asset.hostname.to_lowercase();
                                    if is_gateway { updated_asset.device_type = "router".into(); }
                                    else if h.contains("macbook") || h.contains("imac") || h.contains("lap") { updated_asset.device_type = "laptop".into(); }
                                    else if h.contains("iphone") || h.contains("ipad") { updated_asset.device_type = "phone".into(); }
                                    else if h.contains("print") { updated_asset.device_type = "printer".into(); }
                                    else if h.contains("tv") || h.contains("cast") { updated_asset.device_type = "tv".into(); }
                                    updated_asset.last_seen = chrono::Utc::now().timestamp() as u32;
                                    if let Err(e) = ch_clone.upsert_asset(&updated_asset).await {
                                        warn!("Asset mDNS upsert error: {}", e);
                                    }
                                }
                            }
                        });
                    }
                }

                // --- Placeholder Asset Creation ---
                // Update last_seen for confirmed assets (MAC-verified) seen in traffic.
                // Never create new placeholder rows — assets only enter the table via
                // ARP/DHCP events that carry a real MAC address.
                let update_last_seen = |ip: &str, tenant: &str| {
                    if ip.is_empty() { return; }
                    if ip.ends_with(".255") || ip.ends_with(".0")
                        || ip.starts_with("224.") || ip.starts_with("239.")
                        || ip == "255.255.255.255" { return; }
                    if !crate::enrichment::is_private_ip(ip) { return; }
                    let cache_key = format!("{}:{}", tenant, ip);
                    let now = chrono::Utc::now().timestamp() as u32;
                    let mut needs_db_sync = false;
                    if let Some(mut last_sync) = known_assets.get_mut(&cache_key) {
                        if now.saturating_sub(*last_sync) > 300 {
                            *last_sync = now;
                            needs_db_sync = true;
                        }
                    } else {
                        known_assets.insert(cache_key.clone(), now);
                        needs_db_sync = true;
                    }
                    if needs_db_sync {
                        let ch_clone = state.ch_storage.clone();
                        let ip_clone = ip.to_string();
                        let tenant_clone = tenant.to_string();
                        tokio::spawn(async move {
                            let now_ts = chrono::Utc::now().timestamp() as u32;
                            match ch_clone.get_asset_by_ip(&tenant_clone, &ip_clone).await {
                                Ok(Some(mut existing)) => {
                                    existing.last_seen = now_ts;
                                    let _ = ch_clone.upsert_asset(&existing).await;
                                }
                                // Asset not yet in DB — create a minimal stub from IP alone.
                                // MAC/vendor/hostname will be filled later when ARP/DHCP arrives.
                                _ => {
                                    let is_gateway = (ip_clone.ends_with(".1") || ip_clone.ends_with(".254"))
                                        && !ip_clone.starts_with("169.254.");
                                    let asset = crate::storage::clickhouse::AssetRow {
                                        ip:             ip_clone.clone(),
                                        mac:            String::new(),
                                        hostname:       String::new(),
                                        vendor:         String::new(),
                                        os_guess:       String::new(),
                                        device_type:    if is_gateway { "router".into() } else { "unknown".into() },
                                        custom_name:    String::new(),
                                        tenant_id:      tenant_clone.clone(),
                                        first_seen:     now_ts,
                                        last_seen:      now_ts,
                                        ip_history:     "[]".to_string(),
                                        trusted:        0,
                                        threat_flagged: 0,
                                        role:           String::new(),
                                        criticality:    0,
                                        open_ports:     "[]".to_string(),
                                        subnet_role:    String::new(),
                                        ja3_os:         String::new(),
                                    };
                                    let _ = ch_clone.upsert_asset(&asset).await;
                                }
                            }
                        });
                    }
                };
                if let Some(src) = &event.source_ip {
                    update_last_seen(src, &tenant_id);
                }
                if let Some(dst) = &event.dest_ip {
                    update_last_seen(dst, &tenant_id);
                }
                // -----------------------------------

                // Broadcast immediately (non-blocking) — skip IPAM subnet discovery events
                // (already stored in ClickHouse for network map; no value in live stream)
                if event.log_source.as_deref() != Some("ipam") {
                    crate::api::broadcast_raw_event(&state, &event);
                }

                // ── Standalone Suricata alert → direct hit ───────────────────
                // Suricata severity 1 (Critical) and 2 (High) alerts are promoted
                // directly to ndr_hits without requiring a Zeek corroboration.
                // This covers cases where Zeek has no matching SIGMA rule (e.g.
                // ET MALWARE / ET TROJAN / exploit rules).
                if event.event_source == EventSource::Suricata {
                    if let Some(alert) = &event.alert {
                        if alert.severity <= 2 {
                            let src = event.source_ip.clone().unwrap_or_default();
                            let dst = event.dest_ip.clone().unwrap_or_default();
                            let mut enrich = state.enrichment.enrich(&src, &dst);
                            let now_ts = chrono::Utc::now().timestamp() as u32;
                            let cid = event.community_id.clone()
                                .unwrap_or_else(|| format!("suricata-{}-{}", alert.signature_id, now_ts));

                            // Load tenant settings for thresholds + sensitive country list
                            let settings = state.ch_storage
                                .get_settings_by_tenant(&tenant_id).await
                                .unwrap_or(serde_json::json!({}));
                            let critical_score = settings["critical_threshold"].as_f64().unwrap_or(90.0) as f32;
                            let high_score     = settings["alert_threshold"].as_f64().unwrap_or(75.0) as f32;

                            // Tenant's Sensitive Countries list, minus the countries its own sensors are in
                            crate::homecountry::apply(&state, &tenant_id, &mut enrich).await;

                            let (score, severity) = match alert.severity {
                                1 => (critical_score, "CRITICAL"),
                                _ => (high_score,     "HIGH"),
                            };

                            let tags = {
                                let mut t = vec![
                                    format!("suricata:{}", alert.signature_id),
                                    alert.category.to_lowercase().replace(' ', "-"),
                                ];
                                t.extend(alert.mitre_tactics.iter().map(|m| format!("t:{}", m)));
                                t
                            };

                            let ch_hit = crate::storage::clickhouse::NdrHit {
                                timestamp:          now_ts,
                                community_id:       cid.clone(),
                                src_ip:             src.clone(),
                                dst_ip:             dst.clone(),
                                score,
                                severity:           severity.to_string(),
                                tags:               tags.clone(),
                                sigma_hits:         vec![alert.signature.clone()],
                                threat_intel:       if enrich.is_malicious { 1 } else { 0 },
                                src_country:        enrich.src_geo.as_ref().map(|g| g.country_code.clone()).unwrap_or_default(),
                                dst_country:        enrich.dst_geo.as_ref().map(|g| g.country_code.clone()).unwrap_or_default(),
                                tenant_id:          tenant_id.clone(),
                                correlation_status: "agent_s_only".to_string(),
                                agent_z_details:    "{}".to_string(),
                                agent_s_details:    serde_json::to_string(&event.raw).unwrap_or_else(|_| "{}".to_string()),
                                corroborated_at:    0,
                                agent_s_rule_id:    alert.signature_id.to_string(),
                                agent_s_category:   alert.category.clone(),
                                updated_at:         now_ts,
                                sensor_id:          event.raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            };

                            let ch_cl      = state.ch_storage.clone();
                            let state_soar = Arc::clone(&state);
                            let tid_cl     = tenant_id.clone();
                            let hit_soar   = crate::correlator::session::CorrelationHit {
                                community_id: cid.clone(),
                                agent_z:      crate::normalizer::NormalizedEvent::blank(),
                                agent_s:      event.clone(),
                                hit_time:     now_ts as u64,
                                source:       "agent-s".to_string(),
                            };
                            let risk_soar = crate::scoring::RiskResult {
                                score,
                                severity: if alert.severity == 1 {
                                    crate::scoring::Severity::Critical
                                } else {
                                    crate::scoring::Severity::High
                                },
                                tags:    tags.clone(),
                                reasons: vec![format!("Suricata: {} ({})", alert.signature, alert.category)],
                            };
                            let enrich_soar = enrich.clone();
                            let src_ws = src.clone();
                            let dst_ws = dst.clone();
                            let sev_ws = severity.to_string();
                            tokio::spawn(async move {
                                if let Err(e) = ch_cl.insert_hit_for_tenant(ch_hit, &tid_cl).await {
                                    tracing::warn!("suricata-alert hit insert error: {}", e);
                                    return;
                                }
                                tracing::info!(
                                    src = %src_ws, dst = %dst_ws, sig = %hit_soar.agent_s.alert.as_ref().map(|a| a.signature.as_str()).unwrap_or(""),
                                    "Suricata alert promoted to hit"
                                );
                                let feats = crate::api::get_effective_features(&state_soar, &tid_cl).await;
#[cfg(feature = "soar")]
                                if feats.iter().any(|f| f == "soar") {
                                    crate::soar::execute_native_playbooks(
                                        &state_soar, hit_soar, risk_soar, enrich_soar, &tid_cl,
                                    ).await;
                                }
                                let ws_msg = serde_json::json!({
                                    "type": "hit",
                                    "community_id": cid,
                                    "src_ip": src_ws,
                                    "dst_ip": dst_ws,
                                    "severity": sev_ws,
                                    "score": score,
                                    "tenant_id": tid_cl,
                                });
                                crate::api::publish_event_deduped(&state_soar, &tid_cl, &ws_msg.to_string(), &src_ws, &sev_ws);
                            });
                        }
                    }
                }

                // Inline SIGMA for all Zeek events — Suricata can't always corroborate
                // (DNS alerts have empty IPs; SMB/Kerberos/SSL often have no ET rule).
                // Store as zeek_only; corroborated hits will overwrite via ReplacingMergeTree.
                // Skip events with no IP context — Sigma hits without src/dst are unactionable.
                let has_ip = event.source_ip.as_deref().map(|s| !s.is_empty()).unwrap_or(false)
                          || event.dest_ip.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
                if event.event_source == EventSource::Zeek && has_ip {
                    // ── GAP 1: Enrich BEFORE Sigma so rules can test geo/threat-intel ──
                    let src = event.source_ip.clone().unwrap_or_default();
                    let dst = event.dest_ip.clone().unwrap_or_default();
                    let mut enrich = state.enrichment.enrich(&src, &dst);
                    event.is_malicious     = enrich.is_malicious;
                    event.src_country_code = enrich.src_geo.as_ref().map(|g| g.country_code.clone()).unwrap_or_default();
                    event.dst_country_code = enrich.dst_geo.as_ref().map(|g| g.country_code.clone()).unwrap_or_default();
                    event.src_asn_org      = enrich.src_asn.as_ref().map(|a| a.org.clone()).unwrap_or_default();
                    event.dst_asn_org      = enrich.dst_asn.as_ref().map(|a| a.org.clone()).unwrap_or_default();
                    event.direction        = enrich.direction.clone();

                    // Tenant's Sensitive Countries list (admin-editable), minus its own sensors' countries
                    crate::homecountry::apply(&state, &tenant_id, &mut enrich).await;

                    let detections = {
                        let engine = state.detection.read().await;
                        engine.check_for_tenant(&event, &tenant_id)
                    };
                    if !detections.is_empty() {
                        let now_ts = chrono::Utc::now().timestamp() as u32;

                        let sigma_titles: Vec<String> = {
                            let mut seen = std::collections::HashSet::new();
                            detections.iter().map(|d| d.title.clone()).filter(|t| seen.insert(t.clone())).collect()
                        };
                        let cid = event.community_id.clone().unwrap_or_else(|| format!("zeek-{}-{}", now_ts, event.uid.as_deref().unwrap_or("x")));

                        // Skip sigma hits where src is absent and dst is RFC1918 —
                        // "Publicly Accessible" and exposure rules make no sense for
                        // internal-only traffic with no external source observed
                        let dst_is_private = dst.starts_with("10.") || dst.starts_with("192.168.") || {
                            let p: Vec<&str> = dst.split('.').collect();
                            dst.starts_with("172.") && p.get(1)
                                .and_then(|s| s.parse::<u8>().ok())
                                .map(|n| (16..=31).contains(&n))
                                .unwrap_or(false)
                        };
                        if src.is_empty() && dst_is_private {
                            continue;
                        }

                        // ── GAP 2: Use RiskScorer instead of inline severity map ──────
                        // Build a CorrelationHit with the enriched Zeek event + blank
                        // Suricata half so the scorer gets conn_state, port, protocol signals.
                        let corr_hit = crate::correlator::session::CorrelationHit {
                            community_id: cid.clone(),
                            agent_z:      event.clone(),
                            agent_s:      crate::normalizer::NormalizedEvent::blank(),
                            hit_time:     now_ts as u64,
                            source:       "sigma".to_string(),
                        };
                        let is_trusted_cloud = {
                            let tr = state.trusted.read().await;
                            if tr.is_trusted_ip(&dst) { true }
                            else { enrich.dst_asn.as_ref().map(|a| tr.is_trusted_asn(&a.org)).unwrap_or(false) }
                        };
                        let entity_score = state.entity_cache
                            .get(&format!("{}:{}", tenant_id, src))
                            .map(|v| *v)
                            .unwrap_or(0.0);
                        let raw_risk = state.scorer.score(
                            &corr_hit,
                            enrich.is_malicious,
                            enrich.sensitive_country,
                            is_trusted_cloud,
                            entity_score,
                        );
                        // Sigma rule severity acts as a floor — take the max of scorer and rule
                        let rule_floor: f32 = detections.iter().map(|d| match d.severity.to_lowercase().as_str() {
                            "critical" => 90.0_f32, "high" => 70.0, "medium" => 50.0, "low" => 30.0, _ => 10.0,
                        }).fold(0.0_f32, f32::max);
                        let score    = raw_risk.score.max(rule_floor).min(100.0);
                        let severity = crate::scoring::Severity::from_score(score).as_str();
                        // Clone raw_risk before partially moving its fields
                        let risk_soar       = raw_risk.clone();
                        let mut tags = raw_risk.tags;
                        if !tags.contains(&"sigma".to_string()) { tags.push("sigma".to_string()); }

                        let agent_z_details = serde_json::to_string(&event.raw).unwrap_or_else(|_| "{}".into());
                        let ch_hit = crate::storage::clickhouse::NdrHit {
                            timestamp:          now_ts,
                            community_id:       cid,
                            src_ip:             src,
                            dst_ip:             dst,
                            score,
                            severity:           severity.to_string(),
                            tags,
                            sigma_hits:         sigma_titles,
                            threat_intel:       enrich.is_malicious as u8,
                            src_country:        enrich.src_geo.as_ref().map(|g| g.country_code.clone()).unwrap_or_default(),
                            dst_country:        enrich.dst_geo.as_ref().map(|g| g.country_code.clone()).unwrap_or_default(),
                            tenant_id:          tenant_id.clone(),
                            correlation_status: "zeek_only".to_string(),
                            agent_z_details,
                            agent_s_details:    "{}".to_string(),
                            corroborated_at:    0,
                            agent_s_rule_id:    String::new(),
                            agent_s_category:   String::new(),
                            updated_at:         now_ts,
                            sensor_id:          event.raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        };
                        let ch_clone        = state.ch_storage.clone();
                        let tid_clone       = tenant_id.clone();
                        let cid_clone       = ch_hit.community_id.clone();
                        let src_clone       = ch_hit.src_ip.clone();
                        let dst_clone       = ch_hit.dst_ip.clone();
                        let sev_clone       = ch_hit.severity.clone();
                        let sigma_log       = detections.iter().map(|d| d.title.as_str()).collect::<Vec<_>>().join(",");
                        // Evidence (PCAP) only meaningful for proper network flows with a
                        // standard community_id. WS broadcast has no such restriction (Bug 6 fix).
                        let do_evidence     = matches!(severity, "HIGH" | "CRITICAL" | "MEDIUM")
                                             && cid_clone.starts_with("1:");
                        // GAP 3: SOAR + WS broadcast for Sigma hits
                        let state_soar      = Arc::clone(&state);
                        let enrich_soar     = enrich.clone();
                        let hit_soar        = corr_hit.clone();
                        let score_soar      = score;
                        tracing::info!(
                            sigma = %sigma_log,
                            src   = %event.source_ip.as_deref().unwrap_or("-"),
                            dst   = %event.dest_ip.as_deref().unwrap_or("-"),
                            "zeek_only SIGMA hit"
                        );
                        tokio::spawn(async move {
                            if let Err(e) = ch_clone.insert_hit_for_tenant(ch_hit, &tid_clone).await {
                                tracing::warn!("zeek_only hit insert error: {}", e);
                                return;
                            }
                            // GAP 3: SOAR playbooks
#[cfg(feature = "soar")]
                            crate::soar::execute_native_playbooks(
                                &state_soar, hit_soar, risk_soar, enrich_soar, &tid_clone,
                            ).await;
                            // GAP 3: WS broadcast — always send regardless of community_id format
                            // (Bug 6 fix: removed starts_with("1:") guard that silently dropped
                            // DNS/weird/software sigma hits from live alerts)
                            let ws_msg = serde_json::json!({
                                "type": "hit", "community_id": cid_clone,
                                "src_ip": src_clone, "dst_ip": dst_clone,
                                "severity": sev_clone, "score": score_soar,
                                "tenant_id": tid_clone,
                            });
                            crate::api::publish_event_deduped(&state_soar, &tid_clone, &ws_msg.to_string(), &src_clone, &sev_clone);
                            if !do_evidence { return; }

                            let opensearch_url = std::env::var("OPENSEARCH_URL")
                                .unwrap_or_else(|_| "http://localhost:9200".to_string());
                            let arkime_url  = std::env::var("ARKIME_URL").unwrap_or_default();
                            let arkime_pass = std::env::var("ARKIME_PASS")
                                .unwrap_or_else(|_| "admin".to_string());
                            let now_str  = chrono::Utc::now().to_rfc3339();
                            let alert_json = serde_json::json!({
                                "community_id":    cid_clone,
                                "tenant_id":       tid_clone,
                                "severity":        sev_clone,
                                "src_ip":          src_clone,
                                "dst_ip":          dst_clone,
                                "rule_name":       sigma_log,
                                "timestamp":       now_str,
                                "auto_captured_at": now_str,
                            });
                            let ev_sem = crate::api::evidence_semaphore();
                            let _permit = ev_sem.acquire_owned().await;
                            match crate::evidence::build_evidence_bundle(
                                &opensearch_url, &arkime_url, &arkime_pass,
                                &cid_clone, alert_json, &tid_clone, None,
                            ).await {
                                Ok((zip_bytes, sha256, _manifest)) => {
                                    let date      = chrono::Utc::now().format("%Y-%m-%d").to_string();
                                    let dir       = format!("/opt/ndr/evidence/{}/{}", tid_clone, date);
                                    let _         = tokio::fs::create_dir_all(&dir).await;
                                    let bundle_id = uuid::Uuid::new_v4().to_string();
                                    let file_path = format!("{}/{}.zip", dir, bundle_id);
                                    let size      = zip_bytes.len() as u64;
                                    if tokio::fs::write(&file_path, &zip_bytes).await.is_ok() {
                                        let _ = ch_clone.save_evidence_bundle(
                                            &tid_clone, &bundle_id, &cid_clone,
                                            &file_path, &sha256, size,
                                            1, 90,
                                            &src_clone, &dst_clone, &sev_clone, "",
                                        ).await;
                                        let _ = ch_clone.log_evidence_action(
                                            &tid_clone, &cid_clone, &bundle_id,
                                            "auto_captured", "auto",
                                            &sev_clone, "", "",
                                            "Automatically captured on SIGMA zeek_only hit",
                                            "",
                                        ).await;
                                        tracing::info!(
                                            "Evidence bundle {} captured for zeek_only cid {}",
                                            bundle_id, cid_clone
                                        );
                                        // GAP 4c: AI threat analysis for Sigma zeek_only hits.
                                        // The correlator path runs AI for corroborated hits, but
                                        // when the correlator score falls below store_threshold,
                                        // only this path runs — so AI must fire here too.
                                        if ch_clone.get_tenant_ai_enabled(&tid_clone).await {
                                            let bundles = ch_clone
                                                .get_bundles_for_cid(&tid_clone, &cid_clone)
                                                .await.unwrap_or_default();
                                            let sys = "You are a senior NDR (Network Detection & Response) \
                                                security analyst. A Sigma detection rule matched on a Zeek \
                                                network event. Analyse the alert and respond in plain text \
                                                with three short sections:\n\
                                                THREAT: what this detection indicates (2-3 sentences)\n\
                                                RISK: potential impact (1-2 sentences)\n\
                                                ACTION: recommended immediate response steps (2-3 bullet points)\n\
                                                Be concise and actionable. No markdown headers.";
                                            let q = format!(
                                                "Sigma rule(s) fired: {sigma_log}\n\
                                                 Session community_id: {cid_clone}\n\
                                                 Source: {src_clone} → Destination: {dst_clone}\n\
                                                 Severity: {sev_clone}\n\
                                                 Evidence bundles: {}\n\
                                                 Tenant: {tid_clone}\n\
                                                 Provide your threat analysis.",
                                                bundles.len()
                                            );
                                            match crate::ai::provider::generate_chat(
                                                &ch_clone, sys, &[], &q
                                            ).await {
                                                Ok((analysis, _)) => {
                                                    let safe = analysis.replace('\'', "''");
                                                    let _ = ch_clone.delete_ai_annotations_for_cid(
                                                        &tid_clone, &cid_clone,
                                                    ).await;
                                                    let _ = ch_clone.add_evidence_annotation(
                                                        &tid_clone, &bundle_id, &cid_clone,
                                                        "ARIA-AI", &safe, "ai_analysis",
                                                    ).await;
                                                    tracing::info!(
                                                        "AI analysis saved for zeek_only cid {}",
                                                        cid_clone
                                                    );
                                                }
                                                Err(e) => tracing::warn!(
                                                    "AI analysis failed for zeek_only {}: {}", cid_clone, e
                                                ),
                                            }
                                        }
                                    }
                                }
                                Err(e) => tracing::warn!("Evidence capture failed for {}: {}", cid_clone, e),
                            }
                        });
                    }
                }

                // Correlate in a bounded background task — semaphore caps concurrent
                // ClickHouse+SOAR calls at 16 so a burst of hits can't saturate the
                // connection pool or starve the tokio runtime
                if let Some(hit) = state.correlator.process(event) {
                    let state_clone = state.as_ref().clone();
                    let sem = state.correlation_semaphore.clone();
                    tokio::spawn(async move {
                        let _permit = sem.acquire_owned().await;
                        crate::api::process_correlation_hit(&state_clone, hit).await;
                    });
                }
            }
            Err(e) => {
                error!("Kafka error: {}", e);
                tokio::time::sleep(
                    tokio::time::Duration::from_secs(1)
                ).await;
            }
        }
    }
}

fn guess_os_from_ua(ua: &str) -> String {
    if ua.contains("Windows NT 10") || ua.contains("Windows NT 11") {
        return "Windows 10/11".to_string();
    }
    if ua.contains("Windows NT 6.3") { return "Windows 8.1".to_string(); }
    if ua.contains("Windows NT 6.1") { return "Windows 7".to_string(); }
    if ua.contains("Windows") { return "Windows".to_string(); }
    if ua.contains("iPhone") || ua.contains("iPad") { return "iOS".to_string(); }
    if ua.contains("Android") { return "Android".to_string(); }
    if ua.contains("Mac OS X") { return "macOS".to_string(); }
    if ua.contains("Ubuntu") { return "Ubuntu Linux".to_string(); }
    if ua.contains("Debian") { return "Debian Linux".to_string(); }
    if ua.contains("Linux") { return "Linux".to_string(); }
    String::new()
}

#[cfg(test)]
mod dedup_tests {
    use super::*;

    fn ev(ts: u32, raw: &str) -> NdrEvent {
        NdrEvent {
            timestamp: ts, source: "agent-z".into(), src_ip: "192.168.1.76".into(),
            dst_ip: "8.8.8.8".into(), src_port: 40000, dst_port: 53, proto: "udp".into(),
            event_type: "conn".into(), community_id: "1:abc=".into(), raw: raw.into(),
            tenant_id: "default".into(), sensor_id: "local-central".into(),
        }
    }

    #[test]
    fn fingerprint_is_stable_and_sensitive() {
        assert_eq!(event_fingerprint("default", &ev(1, "{\"uid\":\"A\"}")), event_fingerprint("default", &ev(1, "{\"uid\":\"A\"}")));
        assert_ne!(event_fingerprint("default", &ev(1, "{\"uid\":\"A\"}")), event_fingerprint("default", &ev(1, "{\"uid\":\"B\"}")));
        assert_ne!(event_fingerprint("default", &ev(1, "{}")), event_fingerprint("default", &ev(2, "{}")));
        assert_ne!(event_fingerprint("default", &ev(1, "{}")), event_fingerprint("other", &ev(1, "{}")));
        assert_eq!(event_fingerprint("default", &ev(1, "{}")).len(), 32);
    }

    // Needs a real Redis:  TEST_REDIS_URL=redis://127.0.0.1:6390 cargo test -p ndr-engine dedup_tests -- --ignored
    #[tokio::test]
    #[ignore]
    async fn dedup_against_real_redis() {
        let url = std::env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL");
        let client = redis::Client::open(url).unwrap();
        let mut conn = client.get_multiplexed_tokio_connection().await.unwrap();
        let salt = format!("{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let raws: Vec<String> = (0..5).map(|i| format!("{{\"uid\":\"{}-{}\"}}", salt, i)).collect();

        // first delivery: all 5 kept
        let first = dedup_events(&mut conn, "default", raws.iter().map(|r| ev(10, r)).collect(), 60).await;
        assert_eq!(first.len(), 5);
        // the same 5 again (e.g. file re-read): all dropped
        let again = dedup_events(&mut conn, "default", raws.iter().map(|r| ev(10, r)).collect(), 60).await;
        assert_eq!(again.len(), 0);
        // 3 new + 1 duplicate of a new one inside the same batch: 3 kept
        let mixed: Vec<NdrEvent> = vec![ev(11, &format!("{}-x", salt)), ev(11, &format!("{}-y", salt)),
                                        ev(11, &format!("{}-x", salt)), ev(11, &format!("{}-z", salt))];
        assert_eq!(dedup_events(&mut conn, "default", mixed, 60).await.len(), 3);
        // a same-content event for another tenant is NOT a duplicate
        assert_eq!(dedup_events(&mut conn, "tenant2", vec![ev(10, &raws[0])], 60).await.len(), 1);
        // TTL 0 disables de-dup entirely
        assert_eq!(dedup_events(&mut conn, "default", raws.iter().map(|r| ev(10, r)).collect(), 0).await.len(), 5);
    }

    // Redis dies mid-flight => every event is still kept (fail open, no data loss).
    // Uses its own throwaway server: TEST_REDIS_URL_KILL (the test shuts it down).
    #[tokio::test]
    #[ignore]
    async fn fails_open_when_redis_dies() {
        let url = std::env::var("TEST_REDIS_URL_KILL").expect("TEST_REDIS_URL_KILL");
        let client = redis::Client::open(url).unwrap();
        let mut conn = client.get_multiplexed_tokio_connection().await.unwrap();
        // sanity: works while the server is up
        assert_eq!(dedup_events(&mut conn, "default", vec![ev(1, "{\"k\":1}")], 60).await.len(), 1);
        assert_eq!(dedup_events(&mut conn, "default", vec![ev(1, "{\"k\":1}")], 60).await.len(), 0);
        let _: Result<(), _> = redis::cmd("SHUTDOWN").arg("NOSAVE").query_async(&mut conn).await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        // server is gone: the very same (already-seen) events must be KEPT, not dropped
        let kept = dedup_events(&mut conn, "default", vec![ev(1, "{\"k\":1}"), ev(2, "{\"k\":2}"), ev(3, "{\"k\":3}")], 60).await;
        assert_eq!(kept.len(), 3);
    }
}
