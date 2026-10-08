// NDR Engine — API Routes and Handlers
// License: Apache-2.0

use axum::response::IntoResponse;
pub mod websocket;
pub mod response;
#[allow(unused_imports)]
pub use response::{ApiResponse, JsonResponse, ok as api_ok, err_response as api_err};

/// Global semaphore — limits concurrent evidence bundle AI calls to 4.
/// Prevents burst of HIGH/CRITICAL alerts from exhausting AI rate limits.
static EVIDENCE_SEMAPHORE: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();

pub fn evidence_semaphore() -> Arc<tokio::sync::Semaphore> {
    EVIDENCE_SEMAPHORE
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(4)))
        .clone()
}

trait ExitStatusDefault {
    fn default() -> Self;
}
impl ExitStatusDefault for std::process::ExitStatus {
    fn default() -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(0)
        }
        #[cfg(not(unix))]
        {
            unsafe { std::mem::zeroed() }
        }
    }
}

use crate::correlator::{CorrelationEngine, CorrelationHit};
use crate::detection::DetectionEngine;
use crate::enrichment::EnrichmentPipeline;
use crate::normalizer::NormalizedEvent;
use crate::scoring::{conn_state_description, RiskScorer};
use crate::storage::SqliteStorage;
use crate::storage::ClickhouseStorage;
use crate::storage::clickhouse::sql_escape;
use axum::{extract::{State, Query}, Json, http::StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::sync::broadcast;
use tracing::{debug, info, trace, warn};
use std::env;
use std::time::Duration;
use rdkafka::producer::Producer;
use rdkafka::util::Timeout;
use crate::evidence;


use base64::Engine;
use std::sync::atomic::{AtomicBool, Ordering};

// Shared HTTP client for outbound webhook / integration calls.
// reqwest::Client is internally Arc-based — cloning is cheap.
// Standalone handlers that don't carry AppState use this module-level instance.
//
// reqwest::Client::new() has NO timeout by default, so a request to an
// unreachable host hangs for however long the OS takes to give up on the TCP
// connect (often 30s+ when the target silently drops packets instead of
// sending RST - e.g. a cloud VM's security group, or a host.docker.internal
// that doesn't resolve to anything on a remote-sensor deployment). Confirmed
// live: /api/agent-status took ~30s per call on a cloud install with no
// local capture agent, instead of failing fast. 10s covers this client's
// slowest legitimate caller (the ip-api.com external geo lookup) with room
// to spare, while turning agent-call hangs from ~30s into ~10s.
static HTTP_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default()
    });

/// Batch geo-lookup for the threat/attack map widgets.
///
/// Tries the local GeoLite2-City DB first (state.enrichment.geoip) — offline,
/// instant, and doesn't generate outbound traffic that our own Suricata rules
/// flag ("ET INFO External IP Lookup Domain" fires on ip-api.com DNS lookups
/// from the engine's own dashboard queries). Only IPs the local DB can't
/// resolve fall back to ip-api.com, so most requests never leave the box.
async fn geo_lookup_batch(state: &AppState, ips: &[String]) -> Vec<Value> {
    let mut results = Vec::with_capacity(ips.len());
    let mut unresolved: Vec<&String> = Vec::new();

    for ip in ips {
        match state.enrichment.geoip.as_ref().and_then(|g| g.lookup(ip)) {
            Some(geo) if !geo.country_code.is_empty() => {
                results.push(json!({
                    "query":       ip,
                    "status":      "success",
                    "country":     geo.country_name,
                    "countryCode": geo.country_code,
                    "city":        geo.city,
                    "lat":         geo.latitude.unwrap_or(0.0),
                    "lon":         geo.longitude.unwrap_or(0.0),
                }));
            }
            _ => unresolved.push(ip),
        }
    }

    // ip-api.com's batch endpoint hard-caps at 100 queries per request and
    // returns 422 for anything larger - which failed silently here before:
    // resp.json::<Vec<Value>>() errors on that response body (not an array),
    // the `if let Ok(...)` just dropped it, and every unresolved IP ended up
    // with no geo data and no log line explaining why. Confirmed live -
    // batching exactly 100 succeeds, 101+ returns 422.
    for chunk in unresolved.chunks(100) {
        let batch: Vec<Value> = chunk.iter().map(|ip| json!({ "query": ip })).collect();
        match HTTP_CLIENT
            .post("http://ip-api.com/batch?fields=query,country,countryCode,city,lat,lon,status")
            .json(&batch)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                match resp.json::<Vec<Value>>().await {
                    Ok(fallback) => results.extend(fallback),
                    Err(e) => tracing::warn!(
                        "geo_lookup_batch: ip-api.com returned {} for a {}-IP batch, body didn't parse: {}",
                        status, chunk.len(), e
                    ),
                }
            }
            Err(e) => tracing::warn!("geo_lookup_batch: ip-api.com request failed for a {}-IP batch: {}", chunk.len(), e),
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::is_public_ip_candidate;

    #[test]
    fn public_ip_filter_keeps_only_external_addresses() {
        assert!(is_public_ip_candidate("8.8.8.8"));
        assert!(is_public_ip_candidate("1.1.1.1"));
        assert!(!is_public_ip_candidate("192.168.1.70"));
        assert!(!is_public_ip_candidate("10.0.0.5"));
        assert!(!is_public_ip_candidate("172.16.0.1"));
        assert!(!is_public_ip_candidate("127.0.0.1"));
    }
}

fn is_public_ip_candidate(ip: &str) -> bool {
    let trimmed = ip.trim();
    if trimmed.is_empty() {
        return false;
    }

    match IpAddr::from_str(trimmed) {
        Ok(addr) => !crate::enrichment::is_private_ip(&addr.to_string()),
        Err(_) => false,
    }
}

fn agent_url() -> String {
    env::var("NDR_AGENT_URL")
        .unwrap_or_else(|_| "http://host.docker.internal:3001".to_string())
}


fn agent_secret() -> String {
    env::var("NDR_AGENT_SECRET").unwrap_or_default()
}

fn add_agent_auth(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    let secret = agent_secret();
    if secret.is_empty() {
        rb
    } else {
        rb.header("X-Agent-Secret", secret)
    }
}

fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i+1..i+3]) {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b as char);
                    i += 3;
                    continue;
                }
            }
        } else if bytes[i] == b'+' {
            out.push(' ');
            i += 1;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Poll Kafka synchronously — only called from spawn_blocking in the background task.
/// Never call this from an async context directly; it blocks for up to 2 seconds.
pub fn kafka_health_probe(producer: &rdkafka::producer::FutureProducer) -> bool {
    match producer
        .client()
        .fetch_metadata(None, Timeout::After(Duration::from_secs(2)))
    {
        Ok(metadata) => metadata.brokers().iter().any(|broker| broker.id() >= 0),
        Err(e) => {
            warn!("Kafka health check failed: {}", e);
            false
        }
    }
}

#[derive(serde::Deserialize)]
pub struct TogglePayload {
    pub enabled: bool,
}



// ── Shared application state ──────────────────────────────────────────────




#[derive(Clone)]
pub struct AppState {
    pub correlator: Arc<CorrelationEngine>,
    pub enrichment: Arc<EnrichmentPipeline>,
    pub scorer:     Arc<RiskScorer>,
    pub detection:  Arc<tokio::sync::RwLock<DetectionEngine>>,
    pub storage:    Arc<SqliteStorage>,
    pub ch_storage:  Arc<ClickhouseStorage>,
    pub tx:         broadcast::Sender<String>, // broadcasts to all WS clients
    pub redis:      Arc<redis::Client>,
    pub redis_mux:  redis::aio::MultiplexedConnection,
    pub kafka_producer: Arc<rdkafka::producer::FutureProducer>,
    pub correlation_semaphore: Arc<tokio::sync::Semaphore>,
    pub sensor_key_cache: Arc<crate::auth::sensor_cache::SensorKeyCache>,
    pub ingest_tx:   tokio::sync::mpsc::Sender<(String, String)>,
    // Single-task publish drain — eliminates per-event tokio::spawn overhead.
    // try_send is synchronous; the drain task batches PUBLISH via Redis pipeline.
    pub publish_tx:  tokio::sync::mpsc::Sender<(String, String)>,
    pub http_client: reqwest::Client,
    pub trusted: Arc<tokio::sync::RwLock<crate::threat::cloud_trust::TrustedRanges>>,
    pub sensor_ip: Option<std::net::IpAddr>,
    pub entity_cache: Arc<dashmap::DashMap<String, f32>>,
    // WS flood dedup: key = "tenant:src_ip:severity", value = last-published Instant.
    // First event in a 30-second window is pushed to the browser; duplicates are dropped.
    // ClickHouse storage is unaffected — every event is still stored.
    pub ws_dedup: Arc<dashmap::DashMap<String, std::time::Instant>>,
    pub doh_ips: Arc<tokio::sync::RwLock<std::collections::HashSet<String>>>,
    pub siem: Option<Arc<crate::siem::SiemForwarder>>,
    // (bool trusted, Instant expires) — 5-min TTL avoids a ClickHouse round-trip per hit
    pub trusted_asset_cache: Arc<dashmap::DashMap<String, (bool, std::time::Instant)>>,
    // CIDR ranges whose source IPs are always treated as trusted assets (env TRUSTED_SOURCE_CIDRS)
    pub trusted_source_cidrs: Arc<Vec<ipnetwork::IpNetwork>>,
    // Cached Kafka reachability — updated every 30s by a background spawn_blocking task.
    // The health endpoint reads this instead of blocking a Tokio thread on fetch_metadata.
    pub kafka_healthy: Arc<AtomicBool>,
    // SOAR dedupe cache: incident_key -> last trigger time (prevents repeated actions
    // for the same attacker/target pattern within the SOAR window).
    pub soar_dedupe: Arc<dashmap::DashMap<String, std::time::Instant>>,
    // Update availability, refreshed every 6h from the GitHub VERSION file.
    // None when running in cloud mode (DEPLOY_MODE=cloud) or before first check.
    pub update_status: Arc<tokio::sync::RwLock<UpdateStatus>>,
    // RSA private key PEM — signs license JWTs; never leaves this server.
    pub license_private_key: String,
    // RSA public key PEM — verifies tokens; safe to share with customers.
    pub license_public_key: String,
    // JWT verified at startup from LICENSE_TOKEN env var (on-premise installs).
    // When present, its features take precedence over the database for this tenant.
    pub verified_license: Option<std::sync::Arc<crate::license::LicenseClaims>>,
    // Pre-parsed honeypot CIDRs for O(n) IP membership checks on every event.
    // Refreshed whenever honeypots are added or removed via the API.
    pub honeypot_cidrs: Arc<tokio::sync::RwLock<Vec<(ipnetwork::IpNetwork, String)>>>,
    // In-memory retrospective scan state (ephemeral — not persisted).
    pub retro_scans: Arc<dashmap::DashMap<String, RetroScan>>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct UpdateStatus {
    pub current_version:   String,
    pub latest_version:    Option<String>,
    pub update_available:  bool,
    pub last_checked_secs: u64, // unix timestamp of last successful check
}

pub fn publish_event(state: &AppState, tenant_id: &str, msg: &str) {
    let channel = format!("tenant:{}", tenant_id);
    // Non-blocking hand-off to the single publish drain task.
    // Falls back to in-process broadcast only when the channel is full (rare).
    if state.publish_tx.try_send((channel, msg.to_string())).is_err() {
        let _ = state.tx.send(msg.to_string());
    }
}

/// Like publish_event but deduplicates WS pushes by (tenant, src_ip, severity).
/// The first event in a 30-second window is pushed; subsequent identical events
/// are silently dropped from the live feed. ClickHouse storage is never affected.
/// This prevents browser flooding during nmap scans or high-rate detection bursts.
pub fn publish_event_deduped(
    state: &AppState,
    tenant_id: &str,
    msg: &str,
    src_ip: &str,
    severity: &str,
) {
    let key = format!("{}:{}:{}", tenant_id, src_ip, severity);
    let now = std::time::Instant::now();
    let should_publish = if let Some(mut t) = state.ws_dedup.get_mut(&key) {
        if t.elapsed().as_secs() >= 30 {
            *t = now;
            true
        } else {
            false
        }
    } else {
        state.ws_dedup.insert(key, now);
        true
    };
    if should_publish {
        publish_event(state, tenant_id, msg);
    }
}



// JWT Claims extractor — the shared struct auth-service actually signs into
// every token, so ndr-engine sees the same `features`/`iat` fields it carries
// instead of silently dropping them.
pub type AuthClaims = provigil_common::Claims;

#[allow(dead_code)]
pub fn extract_claims_with_token(token: &str) -> Option<AuthClaims> {
    let secret = std::env::var("JWT_SECRET").ok()?;
    provigil_common::validate_jwt(token, &secret).ok()
}

pub fn extract_claims(
    headers: &axum::http::HeaderMap
) -> Option<AuthClaims> {
    // Try httpOnly cookie first; fall back to Authorization: Bearer header.
    // Both paths stay active so old clients (localStorage) keep working.
    let token_from_cookie = headers
        .get("Cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|c| {
            c.split(';').find_map(|p| {
                p.trim().strip_prefix("ndr_token=").map(str::to_owned)
            })
        });

    let token_from_header = || {
        headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned)
    };

    let token = token_from_cookie.or_else(token_from_header)?;

    let secret = std::env::var("JWT_SECRET").ok()?;

    provigil_common::validate_jwt(&token, &secret).ok()
}

fn require_super_admin(
    headers: &axum::http::HeaderMap,
) -> Result<AuthClaims, Json<Value>> {
    match extract_claims(headers) {
        Some(claims) if claims.role == "super_admin" => Ok(claims),
        Some(_) => Err(Json(json!({
            "status": "error",
            "message": "Forbidden: super admin required"
        }))),
        None => Err(Json(json!({
            "status": "error",
            "message": "Unauthorized"
        }))),
    }
}

// Announcements live entirely in ndr-engine on this branch — nginx has no
// specific /api/announcements block here, so the generic /api catch-all
// sends this traffic to ndr-engine, not auth-service.
fn string_list_from_payload(payload: &Value, key: &str) -> Vec<String> {
    match payload.get(key) {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        Some(Value::String(value)) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn announcement_status_from_payload(payload: &Value) -> String {
    if let Some(status) = payload["status"].as_str() {
        return status.trim().to_string();
    }
    match payload["active"].as_bool() {
        Some(true) => "active".to_string(),
        Some(false) => "inactive".to_string(),
        None => "draft".to_string(),
    }
}

fn announcement_targets_from_payload(payload: &Value) -> (String, Vec<String>, Vec<String>) {
    let audience = payload["audience"].as_str().unwrap_or("all").trim().to_string();
    let mut target_roles = string_list_from_payload(payload, "target_roles");
    let mut target_tenants = string_list_from_payload(payload, "target_tenants");

    match audience.as_str() {
        "tenant_admins" if target_roles.is_empty() => {
            target_roles.push("tenant_admin".to_string());
        }
        "tenant" => {
            if target_tenants.is_empty() {
                if let Some(tenant_id) = payload["tenant_id"].as_str() {
                    let tenant_id = tenant_id.trim();
                    if !tenant_id.is_empty() {
                        target_tenants.push(tenant_id.to_string());
                    }
                }
            }
        }
        "all" if target_roles.is_empty() && target_tenants.is_empty() => {
            target_roles.push("all".to_string());
            target_tenants.push("all".to_string());
        }
        _ => {}
    }

    (audience, target_roles, target_tenants)
}

// Auth middleware
/// The PCAP endpoints a sensor calls with its X-Sensor-Key (no user login). They were public
/// (added 2026-06-21) until 40c9175 removed them on 2026-07-23; since then the login check
/// answered every sensor pcap upload with 401 {"message":"Unauthorized"} before the handler
/// could look at the sensor key. Each of these handlers validates the key itself
/// (validate_sensor_key_cached). EXACT paths only: `/api/pcap/:session_id` (a user download)
/// must keep requiring a login, and a prefix match would let a session id that starts with
/// "upload" or "pending" past it.
pub fn is_sensor_pcap_path(path: &str) -> bool {
    matches!(path, "/api/pcap/upload" | "/api/pcap/upload-failed" | "/api/pcap/pending")
}

#[cfg(test)]
mod pcap_public_path_tests {
    use super::*;

    #[test]
    fn only_the_three_sensor_endpoints_skip_the_login_check() {
        for p in ["/api/pcap/upload", "/api/pcap/upload-failed", "/api/pcap/pending"] {
            assert!(is_sensor_pcap_path(p), "{p} must be reachable with a sensor key");
        }
        // user-facing download and look-alikes keep requiring a login
        for p in ["/api/pcap/abc123", "/api/pcap/uploadabc", "/api/pcap/pending/x", "/api/pcap/upload/x",
                  "/api/pcap/", "/api/pcap", "/api/pcap/upload-failed2", "/api/evidence/pcap/upload"] {
            assert!(!is_sensor_pcap_path(p), "{p} must stay protected");
        }
    }
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = request.uri().path().to_string();
    
    // Public routes - no auth needed. (/api/auth/* itself is not registered
    // here at all — nginx proxies it straight to auth-service.)
    // /api/client-errors is public on purpose — an error on the login page
    // or with an expired/invalid token is exactly what needs reporting,
    // and gating it behind auth would silently drop those reports.
    let public = ["/api/health", "/ws", "/api/sensor", "/api/ingest", "/api/sensor/command", "/api/sensor/checkin", "/api/install-sensor.sh", "/api/uninstall-sensor.sh", "/api/client-errors"];
    if public.iter().any(|p| path.starts_with(p)) || is_sensor_pcap_path(&path) {
        return next.run(request).await;
    }

    // Extract JWT
    match extract_claims(&headers) {
        Some(claims) => {
            if claims.role != "super_admin" {
                let mut rc = state.redis_mux.clone();

                // ── Session JTI gate — force-logout / session revocation ───────
                // Checks that the session still exists in Redis. Deleted by force-logout
                // or explicit logout. Falls back to allow if Redis is unavailable.
                if !claims.jti.is_empty() {
                    let jti = &claims.jti;
                    let session_key = format!("ndr:session:{}", jti);
                    let result: Result<bool, _> = redis::cmd("EXISTS")
                        .arg(&session_key)
                        .query_async(&mut rc)
                        .await;
                    let exists = match result {
                        Ok(v) => v,
                        Err(_) => {
                            // Redis unavailable — fail closed: reject rather than allow
                            return axum::response::Response::builder()
                                .status(503)
                                .header("Content-Type", "application/json")
                                .body(axum::body::Body::from(
                                    r#"{"status":"error","code":"SERVICE_UNAVAILABLE","message":"Session verification unavailable — please try again"}"#
                                ))
                                .unwrap();
                        }
                    };
                    if !exists {
                        return axum::response::Response::builder()
                            .status(401)
                            .header("Content-Type", "application/json")
                            .body(axum::body::Body::from(
                                r#"{"status":"error","code":"SESSION_TERMINATED","message":"Session terminated — please log in again"}"#
                            ))
                            .unwrap();
                    }
                }

                // ── Tenant-level gate (Redis-cached 60s) ──────────────────────
                let t_key = format!("ndr:active:tenant:{}", claims.tenant_id);
                let t_cached: Option<String> = redis::cmd("GET").arg(&t_key).query_async(&mut rc).await.ok().flatten();
                let tenant_active = match t_cached.as_deref() {
                    Some("1") => true,
                    Some("0") => false,
                    _ => {
                        let active = state.ch_storage.is_tenant_active(&claims.tenant_id).await.unwrap_or(true);
                        let v = if active { "1" } else { "0" };
                        let _: Result<(), _> = redis::cmd("SET").arg(&t_key).arg(v).arg("EX").arg(60u64).query_async(&mut rc).await;
                        active
                    }
                };
                if !tenant_active {
                    return axum::response::Response::builder()
                        .status(403)
                        .header("Content-Type", "application/json")
                        .body(axum::body::Body::from(
                            r#"{"status":"error","message":"Tenant has been deactivated"}"#
                        ))
                        .unwrap();
                }

                // ── Per-user active gate (Redis-cached 30s) ───────────────────
                let blockable_roles = ["analyst", "senior_analyst", "viewer", "default_user"];
                if blockable_roles.contains(&claims.role.as_str()) {
                    let u_key = format!("ndr:active:user:{}", claims.sub);
                    let u_cached: Option<String> = redis::cmd("GET").arg(&u_key).query_async(&mut rc).await.ok().flatten();
                    let user_active = match u_cached.as_deref() {
                        Some("1") => true,
                        Some("0") => false,
                        _ => {
                            let active = state.ch_storage.is_user_active(&claims.sub).await.unwrap_or(true);
                            let v = if active { "1" } else { "0" };
                            let _: Result<(), _> = redis::cmd("SET").arg(&u_key).arg(v).arg("EX").arg(30u64).query_async(&mut rc).await;
                            active
                        }
                    };
                    if !user_active {
                        tracing::info!("🚫 Blocked user '{}' attempted API access — rejecting", claims.sub);
                        return axum::response::Response::builder()
                            .status(403)
                            .header("Content-Type", "application/json")
                            .body(axum::body::Body::from(
                                r#"{"status":"error","message":"Your account has been disabled by your administrator.","code":"USER_DISABLED"}"#
                            ))
                            .unwrap();
                    }
                }
            }
            request.extensions_mut().insert(claims);
            next.run(request).await
        }
        None => {
            axum::response::Response::builder()
                .status(401)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"status":"error","message":"Unauthorized"}"#
                ))
                .unwrap()
        }
    }
}

pub fn broadcast_raw_event(state: &AppState, event: &NormalizedEvent) {
    let src = event.source_ip.as_deref().unwrap_or("-");
    let dst = event.dest_ip.as_deref().unwrap_or("-");

    // Skip events with no IP tuple — no value in live stream
    if src == "-" && dst == "-" { return; }

    let mut msg = match event.event_source {
        crate::normalizer::EventSource::Zeek => {
            let cs       = event.conn_state.as_deref().unwrap_or("-");
            let cs_desc  = conn_state_description(cs);
            let svc      = event.network_protocol.as_deref().unwrap_or("-");
            let proto    = event.proto.as_deref().unwrap_or("-");
            let ts       = event.raw.get("ts").and_then(|v| v.as_f64()).unwrap_or(0.0);
            // Skip unclassified conn.log entries with no service and no conn_state —
            // a richer dns/ssl/http log for the same UID already covers this flow
            if svc == "-" && cs == "-" { return; }
            trace!("zeek {} | {}→{} [{}] {} cid={}",
                svc, src, dst, proto, cs,
                event.community_id.as_deref().unwrap_or("?"));
            json!({
                "type": "agent-z",
                "ts":   ts,
                "event_type": if svc != "-" { svc } else { cs },
                "cid":  event.community_id,
                "src":  src, "dst": dst,
                "proto": event.proto,
                "service": event.network_protocol,
                "conn_state": event.conn_state,
                "conn_state_desc": cs_desc,
                "raw": event.raw,
            })
        }
        crate::normalizer::EventSource::Suricata => {
            let et = event.event_type.as_deref().unwrap_or("-");
            let ts = event.raw.get("timestamp")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.timestamp() as f64)
                .unwrap_or(0.0);
            trace!("suricata {} | {}→{} cid={}",
                et, src, dst, event.community_id.as_deref().unwrap_or("?"));
            json!({
                "type": "agent-s",
                "ts":   ts,
                "event_type": et,
                "cid":  event.community_id,
                "src":  src, "dst": dst,
                "proto": event.proto,
                "raw": event.raw,
            })
        }
        _ => return,
    };

    let tenant_id = event.raw.get("tenant_id")
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();
    let sensor_host = event.raw.get("sensor_host")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if let Some(obj) = msg.as_object_mut() {
        obj.insert("tenant_id".to_string(), serde_json::Value::String(tenant_id.clone()));
        obj.insert("sensor_host".to_string(), serde_json::Value::String(sensor_host));
    }

    publish_event(state, &tenant_id, &msg.to_string());
}


//network map
#[derive(serde::Deserialize)]
pub struct NetworkMapQuery {
    pub mode: Option<String>,
    pub limit: Option<usize>,
}

#[derive(serde::Deserialize)]
pub struct SearchQuery {
    pub q: String,
}

pub async fn get_network_map(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<NetworkMapQuery>
) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();
    match state.ch_storage.get_network_map_by_tenant(&tenant_id, query.mode.as_deref(), query.limit, &sensor_ids).await {
        Ok(data) => Json(data),
        Err(_) => Json(json!({"nodes": [], "edges": []}))
    }
}

pub async fn get_network_map_node(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(ip): axum::extract::Path<String>
) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();
    match state.ch_storage.get_network_map_node(&tenant_id, &ip, &sensor_ids).await {
        Ok(data) => Json(data),
        Err(_) => Json(json!({"nodes": [], "edges": []}))
    }
}

pub async fn search_network_map(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<SearchQuery>
) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();
    match state.ch_storage.search_network_map(&tenant_id, &query.q, &sensor_ids).await {
        Ok(data) => Json(json!(data)),
        Err(_) => Json(json!([]))
    }
}

pub async fn process_correlation_hit(state: &AppState, hit: CorrelationHit) {
    let tenant_id = hit.agent_z.raw.get("tenant_id")
        .or_else(|| hit.agent_s.raw.get("tenant_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();

  // ── Get thresholds from ClickHouse ────────
    let settings = state.ch_storage
        .get_settings_by_tenant(&tenant_id).await
        .unwrap_or(json!({}));
    let store_threshold    = settings["store_threshold"].as_f64().unwrap_or(10.0) as f32;
    let alert_threshold    = settings["alert_threshold"].as_f64().unwrap_or(75.0) as f32;
    let critical_threshold = settings["critical_threshold"].as_f64().unwrap_or(90.0) as u32;
    let medium_threshold   = settings["medium_threshold"].as_f64().unwrap_or(50.0) as u32;
    let low_threshold      = settings["low_threshold"].as_f64().unwrap_or(25.0) as u32;
    let soar_threshold     = settings["soar_threshold"].as_f64().unwrap_or(75.0) as f32;
        
    let (src, dst) = match hit.source.as_str() {
        "agent-z" => (
            hit.agent_z.source_ip.as_deref().unwrap_or("-"),
            hit.agent_z.dest_ip.as_deref().unwrap_or("-"),
        ),
        "agent-s" => (
            hit.agent_s.source_ip.as_deref().unwrap_or("-"),
            hit.agent_s.dest_ip.as_deref().unwrap_or("-"),
        ),
        _ => (
            // zeek+suricata — prefer Zeek for flow data
            hit.agent_z.source_ip.as_deref()
                .or(hit.agent_s.source_ip.as_deref())
                .unwrap_or("-"),
            hit.agent_z.dest_ip.as_deref()
                .or(hit.agent_s.dest_ip.as_deref())
                .unwrap_or("-"),
        ),
    };
    // Enrich. This path used the built-in sensitive-country list (which includes IN) and ignored
    // the tenant's own setting; homecountry::apply uses the tenant's list minus its home countries.
    let mut enrichment = state.enrichment.enrich(src, dst);
    crate::homecountry::apply(&state, &tenant_id, &mut enrichment).await;

    // Write permanent IOC hit records for any malicious IP match
    if enrichment.is_malicious {
        let ti = &state.enrichment.threat_intel;
        let mut ioc_matches: Vec<(String, String)> = vec![]; // (matched_ip, feed_source)
        for ip in [src, dst] {
            if !ip.is_empty() && ip != "-" && ti.is_malicious_ip(ip) {
                ioc_matches.push((ip.to_string(), "feodo".to_string()));
            }
        }
        if !ioc_matches.is_empty() {
            let ch = state.ch_storage.clone();
            let cid  = hit.community_id.clone();
            let tid  = tenant_id.clone();
            let s = src.to_string();
            let d = dst.to_string();
            tokio::spawn(async move {
                for (matched_ip, feed) in ioc_matches {
                    let _ = ch.write_ioc_hit(&tid, &cid, &s, &d, &matched_ip, &feed).await;
                }
            });
        }
    }

    // Resolve trusted-cloud flag via dynamic DB-driven TrustedRanges (no hardcoding)
    let dst_ip_str = hit.agent_z.dest_ip.as_deref().unwrap_or("").to_string();
    let sni_str    = hit.agent_z.raw.get("server_name")
        .and_then(|v| v.as_str()).unwrap_or("").to_string();
    let is_trusted_cloud = {
        let tr = state.trusted.read().await;
        if tr.is_trusted_ip(&dst_ip_str) || tr.is_trusted_domain(&sni_str) {
            true
        } else if let Some(asn) = enrichment.dst_asn.as_ref() {
            tr.is_trusted_asn(&asn.org)
        } else {
            false
        }
    };

    // TAP mode: sensor is a passive probe — ALL traffic from sensor IP is noise.
    // Agent mode: sensor IS the monitored host — don't suppress its traffic.
    let src_ip_parsed: Option<std::net::IpAddr> = hit.agent_z.source_ip
        .as_deref().and_then(|s| s.parse().ok());
    let sensor_mode_tap = std::env::var("SENSOR_MODE")
        .map(|m| m.to_lowercase() == "tap")
        .unwrap_or(false);
    if let (Some(sensor), Some(src)) = (state.sensor_ip, src_ip_parsed) {
        if src == sensor {
            if sensor_mode_tap {
                return; // TAP mode: sensor probe traffic — silently drop
            }
            // Agent mode: only drop if destination is trusted cloud (management noise)
            if is_trusted_cloud {
                return;
            }
        }
    }

    // ── Honeypot check — CRITICAL alert if src or dst touches a honeypot CIDR ──
    {
        let src_addr: Option<std::net::IpAddr> = src.parse().ok();
        let dst_addr: Option<std::net::IpAddr> = dst.parse().ok();
        let honeypot_tenant = {
            let cidrs = state.honeypot_cidrs.read().await;
            cidrs.iter().find(|(net, tid)| {
                (tid == &tenant_id || tid.is_empty()) &&
                (src_addr.map(|ip| net.contains(ip)).unwrap_or(false) ||
                 dst_addr.map(|ip| net.contains(ip)).unwrap_or(false))
            }).map(|(_, t)| t.clone())
        };
        if honeypot_tenant.is_some() {
            let now_ts = chrono::Utc::now().timestamp() as u32;
            let hp_hit = crate::storage::clickhouse::NdrHit {
                timestamp:          now_ts,
                community_id:       hit.community_id.clone(),
                src_ip:             src.to_string(),
                dst_ip:             dst.to_string(),
                score:              100.0,
                severity:           "CRITICAL".to_string(),
                tags:               vec!["honeypot-access".to_string()],
                sigma_hits:         vec!["Honeypot Access Detected".to_string()],
                threat_intel:       0,
                src_country:        enrichment.src_geo.as_ref().map(|g| g.country_code.clone()).unwrap_or_default(),
                dst_country:        enrichment.dst_geo.as_ref().map(|g| g.country_code.clone()).unwrap_or_default(),
                tenant_id:          tenant_id.clone(),
                correlation_status: hit.source.clone(),
                agent_z_details:    serde_json::to_string(&hit.agent_z.raw).unwrap_or_else(|_| "{}".into()),
                agent_s_details:    "{}".into(),
                corroborated_at:    0,
                agent_s_rule_id:    String::new(),
                agent_s_category:   "Honeypot Access".to_string(),
                updated_at:         now_ts,
                sensor_id:          hit.agent_z.raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            };
            let ch_hp = state.ch_storage.clone();
            let tid_hp = tenant_id.clone();
            let ws_msg = serde_json::json!({
                "type":      "alert",
                "severity":  "CRITICAL",
                "src_ip":    src,
                "dst_ip":    dst,
                "tags":      ["honeypot-access"],
                "message":   "Honeypot access detected",
                "tenant_id": tenant_id,
            }).to_string();
            publish_event(state, &tenant_id, &ws_msg);
            tokio::spawn(async move {
                if let Err(e) = ch_hp.insert_hit_for_tenant(hp_hit, &tid_hp).await {
                    tracing::warn!("Honeypot hit insert error: {}", e);
                }
            });
            return; // Skip normal scoring — honeypot hits are always CRITICAL
        }
    }

    // Score — use tenant-configured severity thresholds so critical_threshold
    // and alert_threshold bands from the Settings page are respected.
    let entity_score = state.entity_cache
        .get(&format!("{}:{}", tenant_id, src))
        .map(|v| *v)
        .unwrap_or(0.0);
    let raw_risk = state.scorer.score(&hit, enrichment.is_malicious, enrichment.sensitive_country, is_trusted_cloud, entity_score);

    // Trusted-asset check: src is trusted if it matches a CIDR in trusted_source_cidrs OR
    // is manually marked trusted in the assets table (5-min cache).
    let ta_key = format!("{}:{}", tenant_id, src);
    let is_trusted_asset = {
        // Fast path: check CIDR list first (no DB, no cache needed)
        let cidr_trusted = src.parse::<std::net::IpAddr>().ok()
            .map(|addr| state.trusted_source_cidrs.iter().any(|net| net.contains(addr)))
            .unwrap_or(false);

        if cidr_trusted {
            true
        } else {
            const TTL: std::time::Duration = std::time::Duration::from_secs(300);
            let cached = state.trusted_asset_cache.get(&ta_key)
                .filter(|e| e.1.elapsed() < TTL)
                .map(|e| e.0);
            if let Some(v) = cached {
                v
            } else {
                let v = state.ch_storage
                    .get_asset_by_ip(&tenant_id, src).await
                    .ok().flatten()
                    .map(|a| a.trusted == 1)
                    .unwrap_or(false);
                state.trusted_asset_cache.insert(ta_key, (v, std::time::Instant::now()));
                v
            }
        }
    };

    let adjusted_score = if is_trusted_asset { raw_risk.score * 0.5 } else { raw_risk.score };
    let mut adjusted_tags = raw_risk.tags.clone();
    if is_trusted_asset && !adjusted_tags.contains(&"trusted-asset".to_string()) {
        adjusted_tags.push("trusted-asset".to_string());
    }

    let severity = crate::scoring::Severity::from_score_with_thresholds(
        adjusted_score,
        critical_threshold,
        alert_threshold as u32,
        medium_threshold,
        low_threshold,
    );
    let mut risk = crate::scoring::RiskResult {
        score:    adjusted_score,
        severity,
        tags:     adjusted_tags,
        reasons:  raw_risk.reasons,
    };

    // Drop hits that are already AI-suppressed — check before storing so
    // suppressed alerts never appear in the UI at all
    if let Some(alert) = hit.agent_s.alert.as_ref() {
        let sig_id = alert.signature_id;
        if sig_id > 0 && state.ch_storage
            .is_ai_suppressed(&tenant_id, sig_id, src, dst).await
        {
            tracing::info!(
                tenant = %tenant_id,
                sig_id = %sig_id,
                src    = %src,
                dst    = %dst,
                "AI suppression: alert dropped before storage (sig matched active suppression rule)"
            );
            return;
        }
    }

    // Auto-capture evidence for HIGH, CRITICAL, and MEDIUM hits.
    // Non-1: CIDs (hash/JA3/domain/DoH/beacon) are included — Arkime PCAP fetch
    // is skipped internally for those, but threat-intel and log evidence still captures.
    let severity_str = risk.severity.as_str().to_string();
    let hit_is_malicious = enrichment.is_malicious;
    // A conversation is captured and analysed once per AUTOCAPTURE_REPEAT_SECS (default 1 h), not
    // for every alert it raises: the repeats were duplicate bundles and duplicate AI analyses.
    let capture_allowed = if matches!(severity_str.as_str(), "HIGH" | "CRITICAL" | "MEDIUM")
        && !hit.community_id.is_empty()
    {
        let mut rc = state.redis_mux.clone();
        crate::ai::throttle::claim_once(
            &mut rc,
            &format!("ndr:autocap:{}:{}", tenant_id, hit.community_id),
            crate::ai::throttle::capture_repeat_secs(),
        ).await
    } else {
        false
    };
    if capture_allowed
    {
        let cid = hit.community_id.clone();
        let tenant = tenant_id.clone();
        let ch = state.ch_storage.clone();
        let opensearch_url = std::env::var("OPENSEARCH_URL")
            .unwrap_or_else(|_| "http://localhost:9200".to_string());
        let arkime_url = std::env::var("ARKIME_URL").unwrap_or_default();
        let arkime_pass = std::env::var("ARKIME_PASS")
            .unwrap_or_else(|_| "admin".to_string());
        let src_ip_str = src.to_string();
        let dst_ip_str = dst.to_string();
        let rule_name_str = hit.agent_s.alert
            .as_ref().map(|a| a.signature.clone())
            .or_else(|| hit.agent_z.raw.get("rule_name").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .unwrap_or_default();
        let suricata_category_str = hit.agent_s.alert
            .as_ref().map(|a| a.category.clone()).unwrap_or_default();
        let app_proto_str = hit.agent_s.raw
            .get("app_proto").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let dns_query_str = hit.agent_s.raw
            .get("dns").and_then(|d| d.get("queries")).and_then(|q| q.as_array())
            .and_then(|arr| arr.first()).and_then(|q| q.get("rrname"))
            .and_then(|v| v.as_str()).unwrap_or("").to_string();
        let now_str = chrono::Utc::now().to_rfc3339();
        let alert_json = serde_json::json!({
            "community_id": cid,
            "tenant_id": tenant,
            "severity": severity_str,
            "src_ip": src_ip_str,
            "dst_ip": dst_ip_str,
            "rule_name": rule_name_str,
            "timestamp": now_str,
            "auto_captured_at": now_str
        });

        // Facts about the two ends, for the AI (country / operator come from the local databases).
        let dst_geo_c  = enrichment.dst_geo.clone();
        let dst_asn_c  = enrichment.dst_asn.clone();
        let src_geo_c  = enrichment.src_geo.clone();
        let src_asn_c  = enrichment.src_asn.clone();
        let dst_port_c = hit.agent_z.dest_port.or(hit.agent_s.dest_port);
        let proto_c    = hit.agent_z.proto.clone().or_else(|| hit.agent_s.proto.clone());
        let mut redis_c = state.redis_mux.clone();
        let ev_sem = evidence_semaphore();
        tokio::spawn(async move {
            // Acquire permit — at most 4 concurrent evidence+AI calls
            let _permit = ev_sem.acquire_owned().await;
            match crate::evidence::build_evidence_bundle(
                &opensearch_url,
                &arkime_url,
                &arkime_pass,
                &cid,
                alert_json,
                &tenant,
                None,
            ).await {
                Ok((zip_bytes, sha256, _manifest)) => {
                    // Save to disk
                    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
                    let dir = format!("/opt/ndr/evidence/{}/{}", tenant, date);
                    let _ = tokio::fs::create_dir_all(&dir).await;
                    let bundle_id = uuid::Uuid::new_v4().to_string();
                    let file_path = format!("{}/{}.zip", dir, bundle_id);
                    let size = zip_bytes.len() as u64;

                    if tokio::fs::write(&file_path, &zip_bytes).await.is_ok() {
                        let _ = ch.save_evidence_bundle(
                            &tenant, &bundle_id, &cid,
                            &file_path, &sha256, size,
                            1, // auto_captured
                            90, // expires in 90 days
                            &src_ip_str, &dst_ip_str, &severity_str,
                            &cid, // alert_id = community_id (natural cross-reference key)
                        ).await;
                        let _ = ch.log_evidence_action(
                            &tenant, &cid, &bundle_id,
                            "auto_captured", "auto",
                            &severity_str, "", "",
                            "Automatically captured on HIGH/CRITICAL/MEDIUM alert",
                            "",
                        ).await;
                        tracing::info!(
                            "Auto-captured evidence bundle {} for cid {}",
                            bundle_id, cid
                        );

                        // AI threat analysis — gathers ALL bundles for this CID,
                        // sends grouped prompt, deletes old analyses, saves one result.
                        // Skip entirely if destination is a trusted cloud provider with no
                        // real threat signal — prevents false-positive AI analysis.
                        {
                            if is_trusted_cloud && !hit_is_malicious {
                                tracing::info!(
                                    "AI analysis skipped — trusted cloud provider, no threat signal (cid {})",
                                    cid
                                );
                            } else {
                                // One AI analysis per source->destination pair per AI_ANALYSIS_REPEAT_SECS,
                                // and a per-host hourly cap, so one chatty host cannot flood the list.
                                let pair_key = format!("ndr:aiana:{}:{}:{}", tenant, src_ip_str, dst_ip_str);
                                if !crate::ai::throttle::claim_once(&mut redis_c, &pair_key, crate::ai::throttle::pair_repeat_secs()).await {
                                    tracing::info!("AI analysis skipped — {} -> {} was analysed recently (cid {})", src_ip_str, dst_ip_str, cid);
                                    return;
                                }
                                let host_key = format!("ndr:aiana-host:{}:{}", tenant, src_ip_str);
                                if !crate::ai::throttle::take_hourly_slot(&mut redis_c, &host_key, crate::ai::throttle::host_max_per_hour()).await {
                                    crate::ai::throttle::release(&mut redis_c, &pair_key).await;
                                    tracing::info!("AI analysis skipped — {} reached its hourly analysis limit (cid {})", src_ip_str, cid);
                                    return;
                                }

                                let bundles = ch.get_bundles_for_cid(&tenant, &cid).await
                                    .unwrap_or_default();

                                // Threat-intel history of the source host, as facts (not a verdict)
                                let (ti_matches, ti_peers) = ch.host_threat_intel_summary(&tenant, &src_ip_str).await;
                                let host_context = crate::ai::context::host_history_text(&src_ip_str, ti_matches, &ti_peers);

                                // Who and what the two ends are: country, operator, names seen in DNS, service
                                let dst_names = ch.passive_dns_names_for_ip(&dst_ip_str, 3).await;
                                let src_names = ch.passive_dns_names_for_ip(&src_ip_str, 3).await;
                                let ip_context = format!(
                                    "{}{}{}",
                                    crate::ai::context::ip_facts("SOURCE", &src_ip_str, crate::enrichment::is_private_ip(&src_ip_str),
                                        src_geo_c.as_ref(), src_asn_c.as_ref(), &src_names),
                                    crate::ai::context::ip_facts("DESTINATION", &dst_ip_str, crate::enrichment::is_private_ip(&dst_ip_str),
                                        dst_geo_c.as_ref(), dst_asn_c.as_ref(), &dst_names),
                                    crate::ai::context::connection_line(dst_port_c, proto_c.as_deref()),
                                );

                                // Look up asset info for src and dst IPs from the asset inventory
                                let asset_context = {
                                    let mut parts = Vec::new();
                                    for (label, ip) in [("src", &src_ip_str), ("dst", &dst_ip_str)] {
                                        if ip.is_empty() { continue; }
                                        let rows = ch.client
                                            .query(&format!(
                                                "SELECT hostname, mac, vendor, os_guess, device_type, custom_name, trusted \
                                                 FROM ndr.assets WHERE ip = '{}' AND tenant_id = '{}' LIMIT 1",
                                                ip.replace('\'', "''"), tenant
                                            ))
                                            .fetch_all::<(String,String,String,String,String,String,u8)>()
                                            .await
                                            .unwrap_or_default();
                                        if let Some((hostname, mac, vendor, os_guess, device_type, custom_name, trusted)) = rows.first() {
                                            let mut info = Vec::new();
                                            if *trusted == 1            { info.push("TRUSTED INTERNAL DEVICE".to_string()); }
                                            if !hostname.is_empty()    { info.push(format!("hostname={}", hostname)); }
                                            if !mac.is_empty()         { info.push(format!("mac={}", mac)); }
                                            if !vendor.is_empty()      { info.push(format!("vendor={}", vendor)); }
                                            if !os_guess.is_empty()    { info.push(format!("os={}", os_guess)); }
                                            if !device_type.is_empty() { info.push(format!("type={}", device_type)); }
                                            if !custom_name.is_empty() { info.push(format!("name={}", custom_name)); }
                                            if !info.is_empty() {
                                                parts.push(format!("  {} ({}): {}", ip, label, info.join(", ")));
                                            }
                                        }
                                    }
                                    if parts.is_empty() {
                                        String::new()
                                    } else {
                                        format!("ASSET INVENTORY:\n{}\n", parts.join("\n"))
                                    }
                                };

                                // Group alerts by severity, include full rule details
                                let sev_order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO","UNKNOWN"];
                                let mut by_sev: std::collections::HashMap<String, Vec<String>> =
                                    std::collections::HashMap::new();
                                for b in &bundles {
                                    let sev = b["severity"].as_str().unwrap_or("UNKNOWN").to_string();
                                    let src  = b["src_ip"].as_str().unwrap_or("?");
                                    let dst  = b["dst_ip"].as_str().unwrap_or("?");
                                    let entry = format!("  {}→{}", src, dst);
                                    by_sev.entry(sev).or_default().push(entry);
                                }

                                let mut grouped = String::new();
                                for sev in sev_order {
                                    if let Some(entries) = by_sev.get(sev) {
                                        grouped.push_str(&format!(
                                            "{} ({} alert{}):\n", sev, entries.len(),
                                            if entries.len() == 1 { "" } else { "s" }
                                        ));
                                        for e in entries { grouped.push_str(e); grouped.push('\n'); }
                                        grouped.push('\n');
                                    }
                                }

                                // The details of the alert that triggered this analysis, stated once (they used to be
                                // repeated on every bundle line even though they belong to this alert only).
                                let mut latest = Vec::new();
                                if !rule_name_str.is_empty()         { latest.push(format!("sig=\"{}\"", rule_name_str)); }
                                if !suricata_category_str.is_empty() { latest.push(format!("category=\"{}\"", suricata_category_str)); }
                                if !app_proto_str.is_empty()         { latest.push(format!("proto={}", app_proto_str)); }
                                if !dns_query_str.is_empty()         { latest.push(format!("dns_query={}", dns_query_str)); }
                                let latest_line = if latest.is_empty() { String::new() } else { format!("Latest alert: {}\n", latest.join("  ")) };

                                let system_prompt = "You are a senior NDR (Network Detection & Response) \
                                    security analyst. You are given ALL alerts captured for a single \
                                    network session grouped by severity. Analyse the full picture and \
                                    respond in plain text with three short sections:\n\
                                    THREAT: what this session indicates overall (2-3 sentences)\n\
                                    RISK: combined impact across all severity levels (1-2 sentences)\n\
                                    ACTION: recommended immediate response steps (2-3 bullet points)\n\
                                    Be concise and actionable. No markdown headers.\n\
                                    Base your analysis ONLY on the facts given. Use the SOURCE and DESTINATION \
                                    lines to say who the other side is (operator, country, service) and \
                                    name it in THREAT. Traffic to a DNS server (port 53/853), NTP, a package \
                                    mirror or the host's own internet provider is normally routine: say so, \
                                    and do not raise the risk because of the destination country alone.\n\
                                    A threat-intelligence match in HOST THREAT-INTEL MATCHES is a lead, not \
                                    proof: weigh it against this session and say how sure you are. DNS \
                                    queries to ngrok, pagekite or other tunneling domains are suspicious \
                                    and can indicate C2 beaconing. Traffic to well-known cloud providers \
                                    (Google, AWS, Microsoft, Cloudflare) is normal unless other evidence \
                                    says otherwise.";

                                let question = format!(
                                    "Session community_id: {cid}\n\
                                     {ip_context}\
                                     {host_context}\
                                     {asset_context}\
                                     All captured alerts grouped by severity:\n\
                                     {grouped}\
                                     {latest_line}\n\
                                     Tenant: {tenant}\n\
                                     Provide your comprehensive threat analysis.",
                                );

                                if !ch.get_tenant_ai_enabled(&tenant).await {
                                    return;
                                }

                                match crate::ai::provider::generate_chat(
                                    &ch, system_prompt, &[], &question
                                ).await {
                                    Ok((analysis, _)) => {
                                        let safe_analysis = analysis.replace('\'', "''");
                                        // Delete old individual analyses for this CID
                                        let _ = ch.delete_ai_annotations_for_cid(&tenant, &cid).await;
                                        // Save one comprehensive analysis
                                        let _ = ch.add_evidence_annotation(
                                            &tenant, &bundle_id, &cid,
                                            "ARIA-AI", &safe_analysis, "ai_analysis",
                                        ).await;
                                        tracing::info!(
                                            "AI analysis saved for cid {} ({} bundles)",
                                            cid, bundles.len()
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!("AI analysis failed for {}: {}", bundle_id, e);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Auto-capture failed for {}: {}", cid, e);
                }
            }
        });
    }

    // SIGMA detection — single lock acquisition for both events
    let detections = {
        let engine = state.detection.read().await;
        let mut d = engine.check_for_tenant(&hit.agent_z, &tenant_id);
        d.extend(engine.check_for_tenant(&hit.agent_s, &tenant_id));
        d
    };

    // GAP 5: apply Sigma rule floor so a high-severity Sigma match can't be
    // downgraded by a lower correlator score (mirrors the inline Sigma path fix).
    if !detections.is_empty() {
        let rule_floor: f32 = detections.iter().map(|d| match d.severity.to_lowercase().as_str() {
            "critical" => 90.0_f32, "high" => 70.0, "medium" => 50.0, "low" => 30.0, _ => 10.0,
        }).fold(0.0_f32, f32::max);
        if !risk.tags.contains(&"sigma".to_string()) {
            risk.tags.push("sigma".to_string());
        }
        if rule_floor > risk.score {
            let floored = rule_floor.min(100.0);
            let floored_sev = crate::scoring::Severity::from_score_with_thresholds(
                floored, critical_threshold, alert_threshold as u32, medium_threshold, low_threshold,
            );
            risk = crate::scoring::RiskResult {
                score:    floored,
                severity: floored_sev,
                tags:     std::mem::take(&mut risk.tags),
                reasons:  std::mem::take(&mut risk.reasons),
            };
        }
    }

    let cs      = hit.agent_z.conn_state.as_deref().unwrap_or("-");
    let cs_desc = conn_state_description(cs);

    debug!(
        cid = %hit.community_id,
        flow = %format!("{}→{}", src, dst),
        severity = %risk.severity.as_str(),
        score = risk.score,
        state = %format!("{} ({})", cs, cs_desc),
        tags = %risk.tags.join(","),
        reasons = %risk.reasons.join("|"),
        sigma = %detections.iter().map(|d| d.title.as_str()).collect::<Vec<_>>().join(","),
        "correlation hit"
    );

// Only store hits above threshold
    if risk.score < store_threshold {
        return;
    }

    // Persist to SQLite — run on the blocking thread pool so the Tokio worker
    // is never stalled waiting on rusqlite's synchronous Mutex.
    {
        let storage_ref = Arc::clone(&state.storage);
        let hit_c = hit.clone();
        let risk_c = risk.clone();
        let det_c = detections.clone();
        let enr_c = enrichment.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            storage_ref.store_hit(&hit_c, &risk_c, &det_c, &enr_c)
        }).await.unwrap_or(Ok(())) {
            warn!("Storage error: {}", e);
        }
    }

    // Persist to ClickHouse
    // zeek+suricata hits ENRICH the existing zeek-only row via ReplacingMergeTree
    // instead of inserting a second duplicate row.

    let ch             = state.ch_storage.clone();
    let tenant_id_clone = tenant_id.clone();
    let hit_source     = hit.source.clone();
    let now_ts         = chrono::Utc::now().timestamp() as u32;
    let sigma_deduped: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        let mut hits: Vec<String> = detections.iter().map(|d| d.title.clone())
            .filter(|t| seen.insert(t.clone())).collect();
        // Include Suricata rule name so corroborated hits expose the actual signature
        if let Some(alert) = hit.agent_s.alert.as_ref() {
            if !alert.signature.is_empty() && seen.insert(alert.signature.clone()) {
                hits.push(alert.signature.clone());
            }
        }
        hits
    };
    let src_country = enrichment.src_geo.as_ref().map(|g| g.country_code.clone()).unwrap_or_default();
    let dst_country = enrichment.dst_geo.as_ref().map(|g| g.country_code.clone()).unwrap_or_default();
    let threat_intel_flag = enrichment.is_malicious as u8;

    let agent_z_details = serde_json::to_string(&hit.agent_z.raw).unwrap_or_else(|_| "{}".into());
    let agent_s_details = if hit_source == "agent-z+agent-s" || hit_source == "agent-s" {
        serde_json::to_string(&hit.agent_s.raw).unwrap_or_else(|_| "{}".into())
    } else {
        "{}".into()
    };
    let agent_s_rule_id = hit.agent_s.alert.as_ref()
        .map(|a| a.signature_id.to_string())
        .unwrap_or_default();
    let agent_s_category = hit.agent_s.alert.as_ref()
        .map(|a| a.category.clone())
        .unwrap_or_default();

    let corr_status = match hit_source.as_str() {
        "agent-z+agent-s" => "corroborated",
        "agent-s"         => "agent_s_only",
        _                 => "agent_z_only",
    }.to_string();

    let ch_hit = crate::storage::clickhouse::NdrHit {
        timestamp:          now_ts,
        community_id:       hit.community_id.clone(),
        src_ip:             src.to_string(),
        dst_ip:             dst.to_string(),
        score:              risk.score as f32,
        severity:           risk.severity.as_str().to_string(),
        tags:               risk.tags.clone(),
        sigma_hits:         sigma_deduped,
        threat_intel:       threat_intel_flag,
        src_country:        src_country.clone(),
        dst_country:        dst_country.clone(),
        tenant_id:          tenant_id.clone(),
        correlation_status: corr_status,
        agent_z_details:    agent_z_details,
        agent_s_details:    agent_s_details,
        corroborated_at:    if hit_source == "agent-z+agent-s" { now_ts } else { 0 },
        agent_s_rule_id:    agent_s_rule_id,
        agent_s_category:   agent_s_category,
        updated_at:         now_ts,
        sensor_id:          hit.agent_z.raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
    };
    tokio::spawn(async move {
        if let Err(e) = ch.insert_hit_for_tenant(ch_hit, &tenant_id_clone).await {
            tracing::warn!("ClickHouse hit insert error: {}", e);
        }
    });

    // SIEM forwarding — HIGH/CRITICAL hits emitted as CEF over UDP syslog
    if matches!(risk.severity.as_str(), "HIGH" | "CRITICAL") {
        if let Some(siem) = &state.siem {
            let siem2      = Arc::clone(siem);
            let src_s      = src.to_string();
            let dst_s      = dst.to_string();
            let sport      = hit.agent_z.source_port.or(hit.agent_s.source_port).unwrap_or(0) as u16;
            let dport      = hit.agent_z.dest_port.or(hit.agent_s.dest_port).unwrap_or(0) as u16;
            let sev_s      = risk.severity.as_str().to_string();
            let score_f    = risk.score;
            let rule_n     = hit.agent_s.alert.as_ref()
                .map(|a| a.signature.clone())
                .unwrap_or_else(|| "NDR Detection".to_string());
            let reasons_cl = risk.reasons.clone();
            let tenant_cl  = tenant_id.clone();
            tokio::spawn(async move {
                siem2.send_hit(
                    &src_s, &dst_s, sport, dport,
                    &sev_s, score_f, &rule_n, &reasons_cl, &tenant_cl,
                ).await;
            });
        }
    }

    // Queue PCAP upload request for sensors — HIGH/CRITICAL only.
    // MEDIUM generates too many short-lived multicast sessions (SSDP etc.)
    // and evidence bundles for MEDIUM are already auto-captured above.
    // Default-tenant cloud sensors (e.g. EVOFOX) also need queuing — they
    // poll /api/pcap/pending and upload from their local Arkime raw files.
    if !hit.community_id.is_empty()
        && matches!(risk.severity.as_str(), "HIGH" | "CRITICAL")
    {
        let ch2 = state.ch_storage.clone();
        let tid2 = tenant_id.clone();
        let cid2 = hit.community_id.clone();
        tokio::spawn(async move {
            if let Err(e) = ch2.queue_pcap_request(&tid2, &cid2).await {
                tracing::warn!("pcap_pending queue failed: {}", e);
            }
        });
    }

    // AI auto-suppression: check IDS alerts for false positives
    if risk.tags.contains(&"ids-alert".to_string()) {
        if let Some(alert_info) = hit.agent_s.alert.as_ref() {
            let sig_id          = alert_info.signature_id;
            let sig_name        = alert_info.signature.clone();
            let alert_category  = alert_info.category.clone();
            let alert_sev_raw   = alert_info.severity;
            let src_ip          = src.to_string();
            let dst_ip          = dst.to_string();
            let cid             = hit.community_id.clone();
            let ch3             = state.ch_storage.clone();
            let tid3            = tenant_id.clone();

            // Extra context extracted from raw event — gives AI enough signal
            // to distinguish sensor-to-own-infrastructure FPs from real threats.
            let app_proto = hit.agent_s.raw
                .get("app_proto").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let direction = hit.agent_s.raw
                .get("direction").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let tls_sni = hit.agent_s.raw
                .get("tls").and_then(|t| t.get("sni")).and_then(|v| v.as_str())
                .unwrap_or("").to_string();
            let zeek_conn_state = hit.agent_z.conn_state.clone().unwrap_or_default();
            let tags_str        = risk.tags.join(", ");
            let threat_intel    = enrichment.is_malicious;
            let sensitive_ctry  = enrichment.sensitive_country;

            let src_scope = if crate::enrichment::is_private_ip(&src_ip) { "private/internal" } else { "public/external" };
            let dst_scope = if crate::enrichment::is_private_ip(&dst_ip) { "private/internal" } else { "public/external" };

            tokio::spawn(async move {
                // Hard-block 1: hit itself has threat intel match — AI cannot override this
                if threat_intel {
                    tracing::info!(
                        "Suppression skipped — threat_intel=true for {}→{} SID={}",
                        src_ip, dst_ip, sig_id
                    );
                    return;
                }

                // Hard-block 2: src_ip has ANY confirmed C2/threat-intel hit in last 24h
                // An already-confirmed compromised host must never have its alerts suppressed
                if ch3.host_has_threat_intel_hit(&tid3, &src_ip).await {
                    tracing::info!(
                        "Suppression skipped — {} has confirmed threat-intel history (SID={})",
                        src_ip, sig_id
                    );
                    return;
                }

                // Skip if already suppressed
                if ch3.is_ai_suppressed(&tid3, sig_id, &src_ip, &dst_ip).await {
                    return;
                }
                // Skip if we've already decided on this sig+dst recently
                let already = ch3.list_ai_suppressions(&tid3).await.unwrap_or_default();
                let already_seen = already.iter().any(|s|
                    s["signature_id"].as_u64() == Some(sig_id)
                    && s["suppress_ip"].as_str() == Some(dst_ip.as_str())
                );
                if already_seen { return; }

                let prompt = "You are an NDR (Network Detection & Response) security analyst AI. \
                    Determine if a Suricata IDS alert is a FALSE POSITIVE. \
                    Respond ONLY with valid JSON (no markdown): \
                    {\"false_positive\": true/false, \"confidence\": 0-100, \
                    \"suppress_type\": \"by_dst\"|\"by_src\"|\"by_sid\"|\"none\", \
                    \"reason\": \"short explanation\"}. \
                    suppress_type rules: \
                    by_dst = destination is known/trusted infrastructure (cloud, CDN, monitoring endpoint, tunnel server); \
                    by_src = source is a trusted internal device (sensor, scanner, management host); \
                    by_sid = the entire Suricata rule is globally broken/noisy regardless of IP; \
                    none = real threat, do not suppress. \
                    ABSOLUTE RULES — these override everything else: \
                    (A) If threat_intel=true (destination IP is in a threat feed like Feodo, abuse.ch, etc.), \
                    this is ALWAYS a real threat — set false_positive=false, suppress_type=none, confidence=0. \
                    An internal device communicating with a known C2/malicious IP means it is INFECTED. \
                    (B) If the rule name or category contains ANY of: 'CNC', 'CnC', 'C&C', 'Feodo', \
                    'Trojan', 'Malware', 'Ransomware', 'Backdoor', 'RAT', 'Botnet', 'Exploit', \
                    set false_positive=false, suppress_type=none regardless of source IP. \
                    Internal source IPs for these categories indicate a compromised host — NOT a false positive. \
                    (C) If the rule name contains 'HUNTING' and threat_intel=true, treat as real threat. \
                    General hints (only apply when ABSOLUTE RULES above do not match): \
                    (1) Rules starting with 'SURICATA STREAM' or 'SURICATA ENGINE' are Suricata internal \
                    TCP/IP stack checks — they fire on NAT, VPN, and tunnel traffic; almost always FP. \
                    (2) If direction is 'to_client', the alert fired on RESPONSE traffic from server to sensor. \
                    (3) Private/internal source IPs alone are NOT sufficient reason to suppress — internal \
                    devices can be infected and beacon to external C2 servers. \
                    (4) TLS SNI reveals the actual domain — if it matches known infrastructure or monitoring \
                    tools it is almost certainly a FP. \
                    (5) If threat_intel=false and the rule category is 'Generic Protocol Command Decode', \
                    lean toward FP with high confidence.";

                let question = format!(
                    "Suricata alert to analyse:\n\
                     SID          : {sig_id}\n\
                     Rule         : \"{sig_name}\"\n\
                     Category     : \"{alert_category}\"\n\
                     Suri severity: {alert_sev_raw} (1=high 2=medium 3=low)\n\
                     Protocol     : {app_proto}\n\
                     Direction    : {direction}\n\
                     src_ip       : {src_ip} ({src_scope})\n\
                     dst_ip       : {dst_ip} ({dst_scope})\n\
                     TLS SNI      : {tls_sni_display}\n\
                     Agent-Z state: {zeek_conn_state}\n\
                     Risk tags    : [{tags_str}]\n\
                     Threat intel : {threat_intel}\n\
                     Sensitive cty: {sensitive_ctry}\n\
                     Tenant       : {tid3}\n\
                     Is this a false positive?",
                    tls_sni_display = if tls_sni.is_empty() { "none".to_string() } else { tls_sni },
                );

                if !ch3.get_tenant_ai_enabled(&tid3).await {
                    return;
                }

                if let Ok((reply, _)) = crate::ai::provider::generate_chat(
                    &ch3, prompt, &[], &question
                ).await {
                    // Parse AI JSON response
                    let ai: serde_json::Value = serde_json::from_str(&reply)
                        .unwrap_or_else(|_| {
                            // Try to extract JSON from response text
                            if let Some(start) = reply.find('{') {
                                if let Some(end) = reply.rfind('}') {
                                    return serde_json::from_str(&reply[start..=end])
                                        .unwrap_or(json!({}));
                                }
                            }
                            json!({})
                        });

                    let is_fp         = ai["false_positive"].as_bool().unwrap_or(false);
                    let confidence    = ai["confidence"].as_u64().unwrap_or(0) as u8;
                    let suppress_type = ai["suppress_type"].as_str().unwrap_or("none");
                    let reason        = ai["reason"].as_str().unwrap_or("").to_string();

                    if is_fp && confidence >= 80 && suppress_type != "none" {
                        let suppress_ip = match suppress_type {
                            "by_dst" => dst_ip.clone(),
                            "by_src" => src_ip.clone(),
                            _        => String::new(),
                        };

                        // Store in ai_suppressions table
                        let _ = ch3.save_ai_suppression(
                            &tid3, sig_id, &sig_name,
                            suppress_type, &suppress_ip,
                            &src_ip, &dst_ip, &cid,
                            &reason, confidence, "",
                            None,           // AI suppressions use 90-day table TTL
                            "individual",   // AI always suppresses by SID/dst/src, not group
                        ).await;

                        // Queue suppress command to sensor
                        let cmd = match suppress_type {
                            "by_sid" => format!("suppress_sid:{}", sig_id),
                            _        => format!("suppress_sid:{}:{}:{}", sig_id, suppress_type, suppress_ip),
                        };
                        let _ = ch3.set_sensor_command(&tid3, "", &cmd).await;

                        tracing::info!(
                            "AI auto-suppressed SID={} {} {} confidence={}% reason={}",
                            sig_id, suppress_type, suppress_ip, confidence, reason
                        );
                    }
                }
            });
        }
    }

    // Build WebSocket hit message
    let sigma_hits: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        detections.iter()
            .map(|d| d.title.clone())
            .filter(|t| seen.insert(t.clone()))
            .collect()
    };


// ── Execute all SOAR automation under one score gate ─────────────────────
// Native playbooks were previously ungated and fired for every alert regardless
// of score, which caused duplicate notifications alongside the legacy path below.
// All three paths now share the same soar_threshold check.
#[cfg(feature = "soar")]
if risk.score >= soar_threshold {
    // 1. Native playbooks — tenant-scoped, each evaluates its own condition
    crate::soar::execute_native_playbooks(state, hit.clone(), risk.clone(), enrichment.clone(), &tenant_id).await;

// 2. Legacy playbooks — now tenant-scoped (was hardcoded to "default" tenant)
let playbooks = state.ch_storage
    .get_soar_playbooks_by_tenant(&tenant_id).await
    .unwrap_or_default();

for pb in &playbooks {
    if pb["enabled"] != true { continue; }

    let trigger = pb["trigger"]
        .as_str().unwrap_or("");

    // Check if trigger matches
    let triggered = match trigger {
        t if t.starts_with("score >") => {
            let threshold = t
                .replace("score >", "")
                .trim()
                .parse::<f32>()
                .unwrap_or(75.0);
            risk.score >= threshold
        }
        "threat_intel" => enrichment.is_malicious,
        "any"          => true,
        _              => false
    };

    if !triggered { continue; }

    let action_type = pb["action_type"]
        .as_str().unwrap_or("").to_string();
    let config: serde_json::Value =
        serde_json::from_str(
            pb["config"].as_str().unwrap_or("{}")
        ).unwrap_or(json!({}));
    let pb_name = pb["name"]
        .as_str().unwrap_or("").to_string();

    match action_type.as_str() {
        "slack" => {
            if let Some(url) = config["webhook_url"]
                .as_str() {
                let msg = json!({
                    "text": format!(
                        "🚨 *NDR Alert* | *{}*\n\
                        Source: `{}` → Dest: `{}`\n\
                        Score: *{}/100* | Threat Intel: {}\n\
                        Tags: {}",
                        risk.severity.as_str(),
                        src, dst,
                        risk.score as u32,
                        if enrichment.is_malicious 
                            { "⚠️ YES" } else { "No" },
                        risk.tags.join(", ")
                    )
                });
                let url = url.to_string();
                let http_c = state.http_client.clone();
                tokio::spawn(async move {
                    let _ = http_c
                        .post(&url)
                        .json(&msg)
                        .timeout(
                            std::time::Duration
                                ::from_secs(5)
                        )
                        .send().await;
                });
                info!("✅ Slack playbook fired: {}",
                    pb_name);
            }
        }
        "webhook" => {
            let url_val = config["url"]
                .as_str()
                .or(config["webhook_url"].as_str())
                .unwrap_or("").to_string();
            if !url_val.is_empty() {
                let url = url_val;
                let payload = json!({
                    "alert_type":   "ndr_threat",
                    "src_ip":       src,
                    "dst_ip":       dst,
                    "score":        risk.score,
                    "severity":     risk.severity.as_str(),
                    "threat_intel": enrichment.is_malicious,
                    "tags":         risk.tags,
                    "timestamp":    chrono::Utc::now()
                        .to_rfc3339()
                });
                let url = url.to_string();
                let http_c = state.http_client.clone();
                tokio::spawn(async move {
                    let _ = http_c
                        .post(&url)
                        .json(&payload)
                        .timeout(
                            std::time::Duration
                                ::from_secs(5)
                        )
                        .send().await;
                });
                info!("✅ Webhook playbook fired: {}",
                    pb_name);
            }
        }
        _ => {}
    }
}
} // end playbooks threshold check


// 3. Integrations — tenant-scoped (was hardcoded to "default" tenant)
#[cfg(feature = "soar")]
if risk.score >= soar_threshold {
let integrations = state.ch_storage
    .get_integrations_by_tenant(&tenant_id).await
    .unwrap_or_default();

for integration in &integrations {
    if integration["enabled"] != true { continue; }
    
    let int_type = integration["type"]
        .as_str().unwrap_or("").to_string();
    let config = &integration["config"];
    let int_name = integration["name"]
        .as_str().unwrap_or("").to_string();

    match int_type.as_str() {
        "slack" | "discord" => {
            if let Some(url) = config["webhook_url"]
                .as_str() {
                let msg = json!({
                    "text": format!(
                        "🚨 *{}* | Score: {}/100\n\
                        {} → {}\nTags: {}",
                        risk.severity.as_str(),
                        risk.score as u32,
                        src, dst,
                        risk.tags.join(", ")
                    )
                });
                let url = url.to_string();
                let http_c = state.http_client.clone();
                tokio::spawn(async move {
                    let _ = http_c
                        .post(&url)
                        .json(&msg)
                        .timeout(Duration::from_secs(5))
                        .send().await;
                });
                info!("✅ {} fired", int_name);
            }
        }
        "teams" => {
            if let Some(url) = config["webhook_url"]
                .as_str() {
                let msg = json!({
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "summary": "NDR Alert",
                    "themeColor": "FF0000",
                    "title": format!(
                        "🚨 NDR Alert: {}",
                        risk.severity.as_str()
                    ),
                    "sections": [{
                        "facts": [
                            {"name": "Source", "value": src},
                            {"name": "Destination", "value": dst},
                            {"name": "Score", "value": format!("{}/100", risk.score as u32)},
                            {"name": "Severity", "value": risk.severity.as_str()},
                            {"name": "Tags", "value": risk.tags.join(", ")}
                        ]
                    }]
                });
                let url = url.to_string();
                let http_c = state.http_client.clone();
                tokio::spawn(async move {
                    let _ = http_c
                        .post(&url)
                        .json(&msg)
                        .timeout(Duration::from_secs(5))
                        .send().await;
                });
                info!("✅ Teams alert sent");
            }
        }
        "telegram" => {
            if let (Some(token), Some(chat_id)) = (
                config["bot_token"].as_str(),
                config["chat_id"].as_str()
            ) {
                let url = format!(
                    "https://api.telegram.org/bot{}/sendMessage",
                    token
                );
                let msg = json!({
                    "chat_id": chat_id,
                    "text": format!(
                        "🚨 NDR Alert\nSeverity: {}\nSource: {}\nDest: {}\nScore: {}/100\nTags: {}",
                        risk.severity.as_str(),
                        src, dst,
                        risk.score as u32,
                        risk.tags.join(", ")
                    ),
                    "parse_mode": "HTML"
                });
                let http_c = state.http_client.clone();
                tokio::spawn(async move {
                    let _ = http_c
                        .post(&url)
                        .json(&msg)
                        .timeout(Duration::from_secs(5))
                        .send().await;
                });
                info!("✅ Telegram alert sent");
            }
        }
        "pagerduty" => {
            if let Some(key) = config["routing_key"]
                .as_str() {
                let payload = json!({
                    "routing_key": key,
                    "event_action": "trigger",
                    "payload": {
                        "summary": format!(
                            "NDR Alert: {} - {} → {}",
                            risk.severity.as_str(),
                            src, dst
                        ),
                        "severity": match risk.severity.as_str() {
                            "CRITICAL" => "critical",
                            "HIGH"     => "error",
                            "MEDIUM"   => "warning",
                            _          => "info"
                        },
                        "source": src,
                        "custom_details": {
                            "score":        risk.score,
                            "dst_ip":       dst,
                            "tags":         risk.tags,
                            "threat_intel": enrichment.is_malicious
                        }
                    }
                });
                let http_c = state.http_client.clone();
                tokio::spawn(async move {
                    let _ = http_c
                        .post(
                            "https://events.pagerduty.com/v2/enqueue"
                        )
                        .json(&payload)
                        .timeout(Duration::from_secs(5))
                        .send().await;
                });
                info!("✅ PagerDuty alert sent");
            }
        }
        "webhook" => {
            let url_val = config["url"]
                .as_str()
                .or(config["webhook_url"].as_str())
                .unwrap_or("").to_string();
            if !url_val.is_empty() {
                let url = url_val;
                let payload = json!({
                    "alert_type":   "ndr_threat",
                    "src_ip":       src,
                    "dst_ip":       dst,
                    "score":        risk.score,
                    "severity":     risk.severity.as_str(),
                    "threat_intel": enrichment.is_malicious,
                    "tags":         risk.tags,
                    "timestamp":    chrono::Utc::now()
                        .to_rfc3339()
                });
                let url = url.to_string();
                let _int_name_c = int_name.clone();
                let http_c = state.http_client.clone();
                tokio::spawn(async move {
                    let _ = http_c
                        .post(&url)
                        .json(&payload)
                        .timeout(Duration::from_secs(5))
                        .send().await;
                });
                info!("✅ Webhook integration fired: {}",
                    int_name);
            }
        }
        "jira" => {
    if let (Some(url), Some(email), Some(token), Some(project)) = (
        config["url"].as_str(),
        config["email"].as_str(),
        config["token"].as_str(),
        config["project_key"].as_str()
    ) {
        // Dedup via Redis SET NX EX — one ticket per IP pair per hour, cross-instance safe.
        let redis_dedup_key = format!("ndr:jira_dedup:{}:{}", src, dst);
        let should_create: bool = {
            let mut rc = state.redis_mux.clone();
            let set: Option<String> = redis::cmd("SET")
                .arg(&redis_dedup_key)
                .arg("1")
                .arg("NX")
                .arg("EX")
                .arg(3600u64)
                .query_async(&mut rc)
                .await
                .unwrap_or(None);
            set.is_some()
        };
        if !should_create {
            info!("⏭️ Jira dedup: skipping {} → {}", src, dst);
        } else {
        let issue_url = format!(
            "{}/rest/api/3/issue", url
        );
        let creds = base64::engine::general_purpose::STANDARD.encode(
            format!("{}:{}", email, token)
        );
        let priority = match risk.severity.as_str() {
            "CRITICAL" => "Highest",
            "HIGH"     => "High",
            "MEDIUM"   => "Medium",
            _          => "Low"
        };
        let description = json!({
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [{
                    "type": "text",
                    "text": format!(
                        "NDR Alert Details\n\nSeverity: {}\nScore: {}/100\nSource IP: {}\nDestination IP: {}\nThreat Intel: {}\nTags: {}\nTime: {}",
                        risk.severity.as_str(),
                        risk.score as u32,
                        src, dst,
                        if enrichment.is_malicious { "MALICIOUS" } else { "Clean" },
                        risk.tags.join(", "),
                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                    )
                }]
            }]
        });
        let payload = json!({
            "fields": {
                "project": { "key": project },
                "summary": format!(
                    "🚨 NDR Alert: {} | {} → {} | Score: {}/100",
                    risk.severity.as_str(),
                    src, dst,
                    risk.score as u32
                ),
                "description": description,
                "issuetype": { "name": "Bug" },
                "priority": { "name": priority },
                "labels": ["NDR-Alert", "security"]
            }
        });
        let issue_url = issue_url.to_string();
        let creds = creds.to_string();
        let int_name_j = int_name.clone();
        let http_c = state.http_client.clone();
        tokio::spawn(async move {
            match http_c
                .post(&issue_url)
                .header("Authorization",
                    format!("Basic {}", creds))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(&payload)
                .timeout(Duration::from_secs(10))
                .send().await {
                Ok(r) if r.status().is_success() =>
                    info!("✅ Jira ticket created: {}",
                        int_name_j),
                Ok(r) => warn!("Jira error: {}",
                    r.status()),
                Err(e) => warn!("Jira failed: {}", e),
            }
        });
        } // end should_create
    }
}
        _ => {}
    }
}
} // end alert_threshold check

    let hit_ts = hit.agent_z.timestamp as f64 / 1000.0;

    let mut hit_msg = json!({
        "type":            "hit",
        "ts":              hit_ts,
        "cid":             hit.community_id,
        "event_type":      hit.agent_s.event_type,
        "score":           risk.score,
        "severity":        risk.severity.as_str(),
        "severity_colour": risk.severity.colour(),
        "tags":            risk.tags,
        "reasons":         risk.reasons,
        "threat_intel":    enrichment.is_malicious,
        "direction":       enrichment.direction,
        "src_country":     enrichment.src_geo.as_ref().map(|g| &g.country_code),
        "dst_country":     enrichment.dst_geo.as_ref().map(|g| &g.country_code),
        "src_asn":         enrichment.src_asn.as_ref().map(|a| &a.full),
        "dst_asn":         enrichment.dst_asn.as_ref().map(|a| &a.full),
        "sigma_hits":      sigma_hits,
        "agent-s": {
            "src": hit.agent_s.source_ip, "src_port": hit.agent_s.source_port,
            "dst": hit.agent_s.dest_ip,   "dst_port": hit.agent_s.dest_port,
        },
        "agent-z": {
            "src": hit.agent_z.source_ip, "dst": hit.agent_z.dest_ip,
            "proto":            hit.agent_z.proto,
            "service":          hit.agent_z.network_protocol,
            "conn_state":       hit.agent_z.conn_state,
            "conn_state_desc":  cs_desc,
        },
    });

    let hit_sensor_host = hit.agent_z.raw.get("sensor_host")
        .or_else(|| hit.agent_s.raw.get("sensor_host"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if let Some(obj) = hit_msg.as_object_mut() {
        obj.insert("tenant_id".to_string(), serde_json::Value::String(tenant_id.clone()));
        obj.insert("sensor_host".to_string(), serde_json::Value::String(hit_sensor_host));
    }

    if hit.community_id.starts_with("1:") {
        publish_event(state, &tenant_id, &hit_msg.to_string());
    }
}









// ── GET /health ───────────────────────────────────────────────────────────

pub async fn health(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let claims = extract_claims(&headers);

    // This route is intentionally public (see the `public` allowlist in
    // auth_middleware) — Docker's own healthchecks (docker-compose.yml) curl
    // it with no Authorization header, and other services' startup depends
    // on that succeeding. But it used to return full platform-wide metrics
    // (event/hit counts, sigma rule count, per-service up/down) to that same
    // unauthenticated request. Docker only needs a 2xx; an anonymous caller
    // gets a bare status now, and the detailed metrics are reserved for
    // authenticated users (already tenant-scoped below).
    let Some(claims) = claims else {
        return Json(json!({ "status": "ok" }));
    };

    let tenant_id = claims.tenant_id.clone();
    let sensor_ids = claims.sensor_ids;
    let ch_stats = state.ch_storage.get_stats_by_tenant(&tenant_id, &sensor_ids).await.unwrap_or(json!({}));
    let clickhouse_status = if state.ch_storage.health_check().await {
        "running"
    } else {
        "stopped"
    };
    let kafka_status = if state.kafka_healthy.load(Ordering::Relaxed) { "running" } else { "stopped" };

    Json(json!({
        "status":          "ok",
        "sessions":        state.correlator.session_count(),
        "sigma_rules":     state.detection.read().await.rule_count(),
        "events_total":    ch_stats.get("events_total").and_then(|v| v.as_u64()).unwrap_or(0),
        "hits_total":      ch_stats.get("hits_total").and_then(|v| v.as_u64()).unwrap_or(0),
        "events_1h":       ch_stats.get("events_1h").and_then(|v| v.as_u64()).unwrap_or(0),
        "agent_z_events":     ch_stats.get("agent_z_events").and_then(|v| v.as_u64()).unwrap_or(0),
        "agent_s_events": ch_stats.get("agent_s_events").and_then(|v| v.as_u64()).unwrap_or(0),
        "services": {
            "agent-z":       "unknown",
            "agent-s":   "unknown",
            "vector":     "unknown",
            "kafka":      kafka_status,
            "clickhouse": clickhouse_status,
            "engine":     "running",
        }
    }))
}
// ── Interface Management ──────────────────────────────────────────────────

pub async fn get_interfaces() -> Json<Value> {
    let url = format!("{}/agent/interfaces", agent_url());
    match add_agent_auth(HTTP_CLIENT.get(&url)).send().await {
        Ok(resp) => {
            let data: Value = resp.json().await.unwrap_or(json!([]));
            Json(data)
        }
        Err(_) => Json(json!([])),
    }
}

pub async fn get_interface() -> Json<Value> {
    let url = format!("{}/agent/status", agent_url());
    match add_agent_auth(HTTP_CLIENT.get(&url)).send().await {
        Ok(resp) => {
            let data: Value = resp.json().await.unwrap_or(json!({ "interface": "eth0" }));
            Json(json!({ "interface": data.get("interface").and_then(|v| v.as_str()).unwrap_or("eth0") }))
        }
        Err(_) => Json(json!({ "interface": "eth0" })),
    }
}

pub async fn set_interface(Json(payload): Json<Value>) -> StatusCode {
    let url = format!("{}/agent/interface", agent_url());
    match add_agent_auth(HTTP_CLIENT.post(&url).json(&payload)).send().await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::BAD_GATEWAY,
    }
}

// ── Service Control ───────────────────────────────────────────────────────

pub async fn start_services() -> Json<Value> {
    let url = format!("{}/agent/start", agent_url());
    match add_agent_auth(HTTP_CLIENT.post(&url)).send().await {
        Ok(resp) => {
            let data: Value = resp.json().await
                .unwrap_or(json!({"status": "started"}));
            Json(data)
        }
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

pub async fn stop_services() -> Json<Value> {
    let url = format!("{}/agent/stop", agent_url());
    match add_agent_auth(HTTP_CLIENT.post(&url)).send().await {
        Ok(resp) => {
            let data: Value = resp.json().await
                .unwrap_or(json!({"status": "stopped"}));
            Json(data)
        }
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

pub async fn get_agent_status() -> Json<Value> {
    let url = format!("{}/agent/status", agent_url());
    match add_agent_auth(HTTP_CLIENT.get(&url)).send().await {
        Ok(resp) => {
            let data: Value = resp.json().await.unwrap_or(json!({
                "agent-z": "stopped",
                "agent-s": "stopped",
                "vector": "stopped",
                "interface": "eth0"
            }));
            Json(data)
        }
        Err(_) => Json(json!({
            "agent-z": "stopped",
            "agent-s": "stopped",
            "vector": "stopped",
            "interface": "eth0"
        }))
    }
}

// ── ClickHouse API endpoints ──────────────────────────────────────────────

pub async fn get_stats(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();
    match state.ch_storage.get_stats_by_tenant(&tenant_id, &sensor_ids).await {
        Ok(stats) => Json(stats),
        Err(e) => {
            tracing::warn!("Stats query error: {}", e);
            Json(json!({
                "events_total": 0,
                "hits_total": 0,
                "events_1h": 0,
                "hits_1h": 0,
                "agent_z_events": 0,
                "agent_s_events": 0,
            }))
        }
    }
}

// GET /api/stats/timeline — real per-minute event counts for the caller's
// own tenant (last 60 minutes), for an ingestion sparkline that isn't
// randomized/simulated.
pub async fn get_stats_timeline(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    match state.ch_storage.get_events_per_minute_by_tenant(&tenant_id, 60).await {
        Ok(points) => Json(json!({ "status": "ok", "points": points })),
        Err(e) => {
            tracing::warn!("Stats timeline query error: {}", e);
            Json(json!({ "status": "error", "message": e.to_string(), "points": [] }))
        }
    }
}

// GET /api/admin/stats-all-tenants — platform-wide event/hit totals (super admin only)
pub async fn get_stats_all_tenants(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }
    match state.ch_storage.get_stats_all_tenants().await {
        Ok(stats) => Json(stats),
        Err(e) => {
            tracing::warn!("All-tenant stats query error: {}", e);
            Json(json!({
                "events_total": 0, "hits_total": 0, "events_1h": 0,
                "hits_1h": 0, "agent_z_events": 0, "agent_s_events": 0,
            }))
        }
    }
}

pub async fn get_unified_stats(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.as_ref().map(|c| c.sensor_ids.clone()).unwrap_or_default();
    let db = format!("ndr_{}", tenant_id.replace('-', "_"));

    // NDR stats (reuse existing)
    let ndr = state.ch_storage.get_stats_by_tenant(&tenant_id, &sensor_ids).await.unwrap_or(json!({}));

    // SIEM: logs today + last hour + EPS
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct SiemRow { logs_today: u64, logs_1h: u64 }
    let siem_row = state.ch_storage.client
        .query(&format!(
            "SELECT countIf(timestamp >= toStartOfDay(now())) AS logs_today,
                    countIf(timestamp >= now() - INTERVAL 1 HOUR)  AS logs_1h
             FROM {db}.siem_logs"
        ))
        .fetch_one::<SiemRow>().await;
    let (logs_today, logs_1h) = siem_row.map(|r| (r.logs_today, r.logs_1h)).unwrap_or((0, 0));
    let eps = if logs_1h > 0 { logs_1h / 3600 } else { 0 };

    // Combined alerts: critical + high from unified_alerts (covers both NDR hits and SIEM rules)
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct AlertRow { critical: u64, high: u64, medium: u64 }
    let alert_row = state.ch_storage.client
        .query(&format!(
            "SELECT countIf(severity = 'CRITICAL') AS critical,
                    countIf(severity = 'HIGH')     AS high,
                    countIf(severity = 'MEDIUM')   AS medium
             FROM {db}.unified_alerts FINAL
             WHERE timestamp >= now() - INTERVAL 24 HOUR"
        ))
        .fetch_one::<AlertRow>().await;
    let (critical, high, medium) = alert_row.map(|r| (r.critical, r.high, r.medium)).unwrap_or((0, 0, 0));

    // Correlation hits last hour (NDR rule engine)
    let hits_1h = ndr.get("hits_1h").and_then(|v| v.as_u64()).unwrap_or(0);

    Json(json!({
        "ndr_events_today": ndr.get("events_total").and_then(|v| v.as_u64()).unwrap_or(0),
        "ndr_events_1h":    ndr.get("events_1h").and_then(|v| v.as_u64()).unwrap_or(0),
        "siem_logs_today":  logs_today,
        "siem_logs_1h":     logs_1h,
        "siem_eps":         eps,
        "correlation_hits_1h": hits_1h,
        "critical_alerts":  critical,
        "high_alerts":      high,
        "medium_alerts":    medium,
    }))
}

pub async fn get_recent_events(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();
    match state.ch_storage.get_recent_events_by_tenant(50, &tenant_id, &sensor_ids).await {
        Ok(events) => Json(json!(events)),
        Err(e) => {
            tracing::warn!("Recent events query error: {}", e);
            Json(json!([]))
        }
    }
}

pub async fn get_events_by_cid(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let cid = raw_query
        .as_deref()
        .unwrap_or("")
        .split('&')
        .find_map(|kv| {
            let mut p = kv.splitn(2, '=');
            let k = p.next()?;
            let v = p.next().unwrap_or("");
            if k == "cid" { Some(percent_decode(v)) } else { None }
        })
        .unwrap_or_default();

    if cid.is_empty() {
        return Json(json!({"status":"error","message":"cid required"}));
    }
    match state.ch_storage.get_events_by_community_id(&cid, &claims.tenant_id, &claims.sensor_ids).await {
        Ok(events) => Json(json!({"status":"ok","events":events})),
        Err(_)     => Json(json!({"status":"ok","events":[]})),
    }
}

pub async fn get_top_ips(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let tenant_id = extract_claims(&headers)
        .map(|c| c.tenant_id)
        .unwrap_or_else(|| "default".to_string());
    let sensor_ids = extract_claims(&headers).map(|c| c.sensor_ids).unwrap_or_default();
    let src = state.ch_storage.get_top_src_ips_by_tenant(10, &tenant_id, &sensor_ids).await.unwrap_or_default();
    let dst = state.ch_storage.get_top_dst_ips_by_tenant(10, &tenant_id, &sensor_ids).await.unwrap_or_default();
    Json(json!({
        "top_src_ips": src,
        "top_dst_ips": dst,
    }))
}

// GET /api/admin/top-ips-all-tenants — platform-wide, merged/summed by IP across every tenant (super admin only)
pub async fn get_top_ips_all_tenants(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }
    let src = state.ch_storage.get_top_src_ips_all_tenants(10).await.unwrap_or_default();
    let dst = state.ch_storage.get_top_dst_ips_all_tenants(10).await.unwrap_or_default();
    Json(json!({
        "top_src_ips": src,
        "top_dst_ips": dst,
    }))
}


pub async fn get_protocols(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let tenant_id = extract_claims(&headers)
        .map(|c| c.tenant_id)
        .unwrap_or_else(|| "default".to_string());
    let sensor_ids = extract_claims(&headers).map(|c| c.sensor_ids).unwrap_or_default();
    let protos = state.ch_storage.get_top_protocols_by_tenant(5, &tenant_id, &sensor_ids).await.unwrap_or_default();
    Json(json!({ "protocols": protos }))
}

// GET /api/admin/protocols-all-tenants — platform-wide protocol distribution (super admin only)
pub async fn get_protocols_all_tenants(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }
    let protos = state.ch_storage.get_top_protocols_all_tenants(5).await.unwrap_or_default();
    Json(json!({ "protocols": protos }))
}

#[derive(serde::Deserialize, Default)]
pub struct HitsQuery {
    pub src_ip: Option<String>,
}

pub async fn get_hits(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<HitsQuery>,
) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();
    let limit = if query.src_ip.is_some() { 500 } else { 200 };
    match state.ch_storage.get_recent_hits_by_tenant(limit, &tenant_id, &sensor_ids, 0, query.src_ip.as_deref()).await {
        Ok(hits) => Json(json!(hits)),
        Err(e) => {
            tracing::warn!("Hits query error: {}", e);
            Json(json!([]))
        }
    }
}

pub async fn get_entity_scores(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    match state.ch_storage.get_entity_scores(&tenant_id, 20).await {
        Ok(scores) => Json(json!(scores)),
        Err(e) => {
            tracing::warn!("entity_scores query error: {}", e);
            Json(json!([]))
        }
    }
}

pub async fn load_rules_from_clickhouse(
    ch: &crate::storage::ClickhouseStorage,
    _rules_dir: &str,
) -> (Vec<crate::detection::SigmaRule>, std::collections::HashMap<String, std::collections::HashSet<String>>) {
    // Rules are loaded exclusively from ClickHouse (disk files are download cache only)
    let mut rules: Vec<crate::detection::SigmaRule> = Vec::new();

    if let Ok(ch_rules) = ch.get_all_enabled_sigma_rules().await {
        for (id, content, tenant_id) in ch_rules {
            match crate::detection::parse_rule_content(&content) {
                Ok(mut r) => {
                    r.tenant_id = tenant_id;
                    rules.push(r);
                }
                Err(e) => tracing::warn!("Failed to parse rule {} from ClickHouse: {}", id, e),
            }
        }
    }

    let overrides = ch.get_all_disabled_overrides().await.unwrap_or_default();
    (rules, overrides)
}

pub async fn get_rule_by_id(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(rule_id): axum::extract::Path<String>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    if rule_id.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_') {
        return Json(json!({"status": "error", "message": "Invalid rule ID"}));
    }
    // Try ClickHouse first
    if let Ok(Some((id, name, content, _tenant_id, _enabled))) = state.ch_storage.get_sigma_rule_by_id(&rule_id, &tenant_id).await {
        let doc: std::collections::HashMap<String, serde_yaml::Value> =
            serde_yaml::from_str(&content).unwrap_or_default();

        let get_str = |k: &str| -> String {
            doc.get(k).and_then(|v| v.as_str())
                .unwrap_or("").to_string()
        };

        let mut field = String::new();
        let mut matcher = String::new();
        let mut value = String::new();

        if let Some(detection) = doc.get("detection")
            .and_then(|v| v.as_mapping()) {
            for (k, v) in detection {
                let key = k.as_str().unwrap_or("");
                if key == "condition" { continue; }
                if let Some(field_map) = v.as_mapping() {
                    for (fk, fv) in field_map {
                        let fk_str = fk.as_str().unwrap_or("");
                        let parts: Vec<&str> = fk_str.splitn(2, '|').collect();
                        field   = parts[0].to_string();
                        matcher = parts.get(1).unwrap_or(&"equals").to_string();
                        value   = match fv {
                            serde_yaml::Value::String(s) => s.clone(),
                            serde_yaml::Value::Sequence(s) => s.first()
                                .and_then(|v| v.as_str())
                                .unwrap_or("").to_string(),
                            _ => String::new(),
                        };
                    }
                }
            }
        }

        return Json(json!({
            "id":          id,
            "title":       name,
            "severity":    get_str("level"),
            "description": get_str("description"),
            "field":       field,
            "matcher":     matcher,
            "value":       value,
            "tags":        doc.get("tags")
                .and_then(|v| v.as_sequence())
                .map(|s| s.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>())
                .unwrap_or_default(),
        }));
    }

    // Fallback to file-based
    let rules_dir = std::env::var("RULES_DIR")
        .unwrap_or_else(|_| "rules".to_string());
    let file_path = format!("{}/{}.yml", rules_dir, rule_id);

    match tokio::fs::read_to_string(&file_path).await {
        Ok(content) => {
            let doc: std::collections::HashMap<String, serde_yaml::Value> =
                serde_yaml::from_str(&content).unwrap_or_default();

            let get_str = |k: &str| -> String {
                doc.get(k).and_then(|v| v.as_str())
                    .unwrap_or("").to_string()
            };

            let mut field = String::new();
            let mut matcher = String::new();
            let mut value = String::new();

            if let Some(detection) = doc.get("detection")
                .and_then(|v| v.as_mapping()) {
                for (k, v) in detection {
                    let key = k.as_str().unwrap_or("");
                    if key == "condition" { continue; }
                    if let Some(field_map) = v.as_mapping() {
                        for (fk, fv) in field_map {
                            let fk_str = fk.as_str().unwrap_or("");
                            let parts: Vec<&str> = fk_str.splitn(2, '|').collect();
                            field   = parts[0].to_string();
                            matcher = parts.get(1).unwrap_or(&"equals").to_string();
                            value   = match fv {
                                serde_yaml::Value::String(s) => s.clone(),
                                serde_yaml::Value::Sequence(s) => s.first()
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("").to_string(),
                                _ => String::new(),
                            };
                        }
                    }
                }
            }

            Json(json!({
                "id":          get_str("id"),
                "title":       get_str("title"),
                "severity":    get_str("level"),
                "description": get_str("description"),
                "field":       field,
                "matcher":     matcher,
                "value":       value,
                "tags":        doc.get("tags")
                    .and_then(|v| v.as_sequence())
                    .map(|s| s.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>())
                    .unwrap_or_default(),
            }))
        }
        Err(_) => Json(json!({
            "error": "Rule not found"
        }))
    }
}

pub async fn get_rules(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let search = params.get("q").map(|s| s.to_lowercase()).unwrap_or_default();

    let db_rules = state.ch_storage.get_all_sigma_rules(&tenant_id).await.unwrap_or_default();

    let mut result: Vec<serde_json::Value> = db_rules.iter()
        .filter_map(|(id, name, content, _r_tenant_id, enabled, source)| {
            let parsed = crate::detection::parse_rule_content(content).ok();
            let conditions_len = parsed.as_ref().map(|p| p.conditions.len()).unwrap_or(0);
            let tags      = parsed.as_ref().map(|p| p.tags.clone()).unwrap_or_default();
            let severity  = parsed.as_ref().map(|p| p.severity.clone()).unwrap_or_default();
            let logsource = parsed.as_ref().map(|p| p.logsource.clone());
            let is_enabled = *enabled == 1;

            // Filter by search query if provided
            if !search.is_empty() {
                let name_lc = name.to_lowercase();
                let sev_lc  = severity.to_lowercase();
                let tag_match = tags.iter().any(|t| t.to_lowercase().contains(&search));
                if !name_lc.contains(&search) && !sev_lc.contains(&search) && !tag_match {
                    return None;
                }
            }

            Some(json!({
                "id":        id,
                "name":      name,
                "title":     name,
                "type":      source,
                "severity":  severity,
                "tags":      tags,
                "conditions": conditions_len,
                "logsource": {
                    "product":  logsource.as_ref().and_then(|l| l.product.clone()),
                    "category": logsource.as_ref().and_then(|l| l.category.clone()),
                    "service":  logsource.as_ref().and_then(|l| l.service.clone()),
                },
                "enabled": is_enabled,
                "status":  if is_enabled { "ACTIVE" } else { "DISABLED" },
            }))
        })
        .collect();

    let total = result.len();
    let active_total = result.iter().filter(|r| r["enabled"] == json!(true)).count();

    // order=desc: newest first. The list is community rules followed by the
    // tenant's own custom rules, so reversing puts a just-created custom rule
    // on page 1. Applied before pagination so it holds across pages - without
    // it a new rule would sit at the very end of a 1,000+ rule list.
    if params.get("order").map(|v| v == "desc").unwrap_or(false) {
        result.reverse();
    }

    // Optional pagination — callers that don't pass limit/offset (e.g. the
    // retrospective and overview pages) get the full search-filtered set.
    if let Some(limit) = params.get("limit").and_then(|v| v.parse::<usize>().ok()) {
        let offset = params.get("offset").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
        result = result.into_iter().skip(offset).take(limit).collect();
    }

    let mut resp_headers = axum::http::HeaderMap::new();
    if let Ok(v) = total.to_string().parse() {
        resp_headers.insert("X-Total-Count", v);
    }
    if let Ok(v) = active_total.to_string().parse() {
        resp_headers.insert("X-Active-Count", v);
    }
    (resp_headers, Json(json!(result)))
}

pub async fn get_rule_hit_counts(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();
    let counts = state.ch_storage.get_rule_hit_counts(&tenant_id, &sensor_ids).await.unwrap_or_default();
    Json(serde_json::to_value(counts).unwrap_or(json!({})))
}

//threat intelegence endpoint
pub async fn get_threat_intel(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();
    let detected = state.ch_storage.get_threat_intel_hits_by_tenant(&tenant_id, &sensor_ids).await
        .unwrap_or_default();
    let summary = state.ch_storage.get_threat_intel_summary().await.unwrap_or_else(|_| json!({
        "unique_ips": 0,
        "unique_hashes": 0,
        "unique_domains": 0,
        "unique_public_ips": 0,
        "last_refresh": "never",
    }));
    let feed_sources = state.ch_storage.get_threat_intel_feed_sources().await.unwrap_or_default();

    let manual_iocs = state.ch_storage.get_watchlist_iocs_by_tenant(&tenant_id).await.unwrap_or_default();
    let mut manual_by_type: std::collections::HashMap<String, std::collections::HashSet<String>> = std::collections::HashMap::new();
    for item in &manual_iocs {
        let ioc_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let value = item.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if ioc_type.is_empty() || value.is_empty() {
            continue;
        }
        manual_by_type.entry(ioc_type.clone()).or_default().insert(value);
    }

    let manual_ip_total = manual_by_type.get("ip").map(|s| s.len() as u64).unwrap_or(0);
    let manual_hash_total = manual_by_type.get("hash").map(|s| s.len() as u64).unwrap_or(0);
    let manual_domain_total = manual_by_type.get("domain").map(|s| s.len() as u64).unwrap_or(0);

    let total_ips = summary["unique_ips"].as_u64().unwrap_or(0) + manual_ip_total;
    let total_hashes = summary["unique_hashes"].as_u64().unwrap_or(0) + manual_hash_total;
    let total_domains = summary["unique_domains"].as_u64().unwrap_or(0) + manual_domain_total;

    let mut merged_sources = feed_sources;
    for (ioc_type, values) in manual_by_type {
        merged_sources.push(json!({
            "source": "manual",
            "ioc_type": ioc_type,
            "rows": values.len(),
            "unique_values": values.len(),
        }));
    }

    Json(json!({
        "total_malicious_ips":     total_ips,
        "total_malicious_hashes":  total_hashes,
        "total_malicious_domains": total_domains,
        "detected_in_network":     detected,
        "last_refresh":            summary["last_refresh"].as_str().unwrap_or("never"),
        "refresh_interval":        "Every 60 minutes",
        "feed_summary":            summary,
        "sources":                merged_sources,
    }))
}

// GET /api/admin/threat-intel-all-tenants — platform-wide threat-intel hits
// merged across every tenant's own ndr_hits (super admin only). Feed-level
// summary/sources are already global, only "detected_in_network" and the
// manual-IOC counts were tenant-scoped before.
pub async fn get_threat_intel_all_tenants(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }
    let detected = state.ch_storage.get_threat_intel_hits_all_tenants().await.unwrap_or_default();
    let summary = state.ch_storage.get_threat_intel_summary().await.unwrap_or_else(|_| json!({
        "unique_ips": 0,
        "unique_hashes": 0,
        "unique_domains": 0,
        "unique_public_ips": 0,
        "last_refresh": "never",
    }));
    let feed_sources = state.ch_storage.get_threat_intel_feed_sources().await.unwrap_or_default();

    let tenant_ids = state.ch_storage.get_all_tenants().await.unwrap_or_default();
    let mut manual_by_type: std::collections::HashMap<String, std::collections::HashSet<String>> = std::collections::HashMap::new();
    for tid in &tenant_ids {
        let manual_iocs = state.ch_storage.get_watchlist_iocs_by_tenant(tid).await.unwrap_or_default();
        for item in &manual_iocs {
            let ioc_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let value = item.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if ioc_type.is_empty() || value.is_empty() { continue; }
            manual_by_type.entry(ioc_type).or_default().insert(value);
        }
    }

    let manual_ip_total = manual_by_type.get("ip").map(|s| s.len() as u64).unwrap_or(0);
    let manual_hash_total = manual_by_type.get("hash").map(|s| s.len() as u64).unwrap_or(0);
    let manual_domain_total = manual_by_type.get("domain").map(|s| s.len() as u64).unwrap_or(0);

    let total_ips = summary["unique_ips"].as_u64().unwrap_or(0) + manual_ip_total;
    let total_hashes = summary["unique_hashes"].as_u64().unwrap_or(0) + manual_hash_total;
    let total_domains = summary["unique_domains"].as_u64().unwrap_or(0) + manual_domain_total;

    let mut merged_sources = feed_sources;
    for (ioc_type, values) in manual_by_type {
        merged_sources.push(json!({
            "source": "manual",
            "ioc_type": ioc_type,
            "rows": values.len(),
            "unique_values": values.len(),
        }));
    }

    Json(json!({
        "total_malicious_ips":     total_ips,
        "total_malicious_hashes":  total_hashes,
        "total_malicious_domains": total_domains,
        "detected_in_network":     detected,
        "last_refresh":            summary["last_refresh"].as_str().unwrap_or("never"),
        "refresh_interval":        "Every 60 minutes",
        "feed_summary":            summary,
        "sources":                merged_sources,
    }))
}

pub async fn get_threat_intel_feed_summary(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let summary = state.ch_storage.get_threat_intel_summary().await.unwrap_or_else(|_| json!({
        "unique_ips": 0,
        "unique_hashes": 0,
        "unique_domains": 0,
        "unique_public_ips": 0,
        "last_refresh": "never",
    }));
    let feed_sources = state.ch_storage.get_threat_intel_feed_sources().await.unwrap_or_default();
    let manual_iocs = state.ch_storage.get_watchlist_iocs_by_tenant(&tenant_id).await.unwrap_or_default();

    let mut manual_by_type: std::collections::HashMap<String, std::collections::HashSet<String>> = std::collections::HashMap::new();
    for item in &manual_iocs {
        let ioc_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let value = item.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if ioc_type.is_empty() || value.is_empty() {
            continue;
        }
        manual_by_type.entry(ioc_type).or_default().insert(value);
    }

    let mut merged_sources = feed_sources;
    for (ioc_type, values) in manual_by_type {
        merged_sources.push(json!({
            "source": "manual",
            "ioc_type": ioc_type,
            "rows": values.len(),
            "unique_values": values.len(),
        }));
    }

    Json(json!({
        "summary": summary,
        "sources": merged_sources,
    }))
}


// Attack Intelligence Map — top external source IPs with geo-lookup
pub async fn get_threat_map(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();

    let (ip_rows, attack_tags) = tokio::join!(
        state.ch_storage.get_top_external_src_ips_by_tenant(50, &tenant_id, &sensor_ids),
        state.ch_storage.get_country_attack_tags(&tenant_id, &sensor_ids)
    );
    let ip_rows    = ip_rows.unwrap_or_default();
    let attack_tags = attack_tags.unwrap_or_default();

    if ip_rows.is_empty() {
        return Json(json!({ "countries": [] }));
    }

    // Geo-lookup: local GeoLite2 DB first, ip-api.com only for what it can't resolve
    let ips: Vec<String> = ip_rows.iter().take(100).map(|(ip, _)| ip.clone()).collect();
    let geo_results = geo_lookup_batch(&state, &ips).await;

    // Build a count map from the DB rows
    let count_map: std::collections::HashMap<String, u64> = ip_rows.into_iter().collect();

    // Aggregate by country
    let mut country_map: std::collections::HashMap<String, (String, f64, f64, u64)> = std::collections::HashMap::new();
    for geo in &geo_results {
        if geo.get("status").and_then(|s| s.as_str()) != Some("success") { continue; }
        let ip      = geo["query"].as_str().unwrap_or("").to_string();
        let country = geo["country"].as_str().unwrap_or("Unknown").to_string();
        let code    = geo["countryCode"].as_str().unwrap_or("XX").to_string();
        let lat     = geo["lat"].as_f64().unwrap_or(0.0);
        let lon     = geo["lon"].as_f64().unwrap_or(0.0);
        let cnt     = count_map.get(&ip).copied().unwrap_or(1);
        country_map.entry(country.clone())
            .and_modify(|e| e.3 += cnt)
            .or_insert((code, lat, lon, cnt));
    }

    let mut countries: Vec<Value> = country_map.into_iter().map(|(country, (code, lat, lon, count))| {
        // attack_tags is keyed by ISO country code (stored in ndr_hits.src_country)
        let attacks: Vec<Value> = attack_tags.get(&code)
            .map(|tags| tags.iter().map(|(t, c)| json!({ "tag": t, "count": c })).collect())
            .unwrap_or_default();
        json!({ "country": country, "code": code, "lat": lat, "lon": lon, "count": count, "attacks": attacks })
    }).collect();
    countries.sort_by(|a, b| b["count"].as_u64().unwrap_or(0).cmp(&a["count"].as_u64().unwrap_or(0)));
    countries.truncate(15);

    Json(json!({ "countries": countries }))
}

// GET /api/admin/threat-map-all-tenants — platform-wide attack map, merging
// raw IP/country counts across every tenant before the geo-lookup + country
// rollup (super admin only). Mirrors get_threat_map()'s aggregation logic.
pub async fn get_threat_map_all_tenants(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }

    let (ip_rows, attack_tags) = tokio::join!(
        state.ch_storage.get_top_external_src_ips_all_tenants(50),
        state.ch_storage.get_country_attack_tags_all_tenants()
    );
    let ip_rows    = ip_rows.unwrap_or_default();
    let attack_tags = attack_tags.unwrap_or_default();

    if ip_rows.is_empty() {
        return Json(json!({ "countries": [] }));
    }

    let ips: Vec<String> = ip_rows.iter().take(100).map(|(ip, _)| ip.clone()).collect();
    let geo_results = geo_lookup_batch(&state, &ips).await;

    let count_map: std::collections::HashMap<String, u64> = ip_rows.into_iter().collect();

    let mut country_map: std::collections::HashMap<String, (String, f64, f64, u64)> = std::collections::HashMap::new();
    for geo in &geo_results {
        if geo.get("status").and_then(|s| s.as_str()) != Some("success") { continue; }
        let ip      = geo["query"].as_str().unwrap_or("").to_string();
        let country = geo["country"].as_str().unwrap_or("Unknown").to_string();
        let code    = geo["countryCode"].as_str().unwrap_or("XX").to_string();
        let lat     = geo["lat"].as_f64().unwrap_or(0.0);
        let lon     = geo["lon"].as_f64().unwrap_or(0.0);
        let cnt     = count_map.get(&ip).copied().unwrap_or(1);
        country_map.entry(country.clone())
            .and_modify(|e| e.3 += cnt)
            .or_insert((code, lat, lon, cnt));
    }

    let mut countries: Vec<Value> = country_map.into_iter().map(|(country, (code, lat, lon, count))| {
        let attacks: Vec<Value> = attack_tags.get(&code)
            .map(|tags| tags.iter().map(|(t, c)| json!({ "tag": t, "count": c })).collect())
            .unwrap_or_default();
        json!({ "country": country, "code": code, "lat": lat, "lon": lon, "count": count, "attacks": attacks })
    }).collect();
    countries.sort_by(|a, b| b["count"].as_u64().unwrap_or(0).cmp(&a["count"].as_u64().unwrap_or(0)));
    countries.truncate(15);

    Json(json!({ "countries": countries }))
}

// Threat Intel Map — geo-locate public malicious IPs from the actual IOC feed.
pub async fn get_threat_intel_map(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let _claims = extract_claims(&headers);
    let rows = state.ch_storage.get_public_threat_intel_ip_counts().await.unwrap_or_default();
    if rows.is_empty() {
        return Json(json!({ "countries": [] }));
    }

    let mut ip_hits: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for (ip, count) in rows {
        if !is_public_ip_candidate(&ip) {
            continue;
        }
        *ip_hits.entry(ip).or_default() += count;
    }
    if ip_hits.is_empty() {
        return Json(json!({ "countries": [] }));
    }

    let ips: Vec<String> = ip_hits.keys().take(200).cloned().collect();
    let geo_results = geo_lookup_batch(&state, &ips).await;
    let geo_index: std::collections::HashMap<String, Value> = geo_results
        .into_iter()
        .filter(|g| g.get("status").and_then(|s| s.as_str()) == Some("success"))
        .filter_map(|g| {
            let query = g["query"].as_str().unwrap_or("").to_string();
            if query.is_empty() { None } else { Some((query, g)) }
        })
        .collect();

    let mut country_map: std::collections::HashMap<String, (String, f64, f64, u64, u64, Vec<String>)> =
        std::collections::HashMap::new();

    for (ip, hits) in ip_hits {
        let Some(geo) = geo_index.get(&ip) else {
            continue;
        };

        let country = geo["country"].as_str().unwrap_or("Unknown").to_string();
        let code = geo["countryCode"].as_str().unwrap_or("XX").to_string();
        let lat = geo["lat"].as_f64().unwrap_or(0.0);
        let lon = geo["lon"].as_f64().unwrap_or(0.0);

        country_map.entry(code.clone())
            .and_modify(|e| {
                e.3 += 1;
                e.4 += hits;
                e.5.push(ip.clone());
            })
            .or_insert((country, lat, lon, 1, hits, vec![ip]));
    }

    let mut countries: Vec<Value> = country_map.into_iter()
        .map(|(code, (country, lat, lon, ip_count, hit_count, ips))| json!({
            "country":   country,
            "code":      code,
            "lat":       lat,
            "lon":       lon,
            "ip_count":  ip_count,
            "hit_count": hit_count,
            "ips":       ips,
        }))
        .collect();

    countries.sort_by(|a, b| b["hit_count"].as_u64().unwrap_or(0).cmp(&a["hit_count"].as_u64().unwrap_or(0)));
    Json(json!({ "countries": countries }))
}

//lookup ioc
//lookup ioc
pub async fn lookup_ioc(
    State(state): State<AppState>,
    axum::extract::Path(ioc): axum::extract::Path<String>,
) -> Json<Value> {
    let ti = &state.enrichment.threat_intel;

    // Check if real IP — ALL 4 parts must be valid numbers 0-255
    let is_real_ip = ioc.split('.').count() == 4 &&
        ioc.split('.').all(|p| p.parse::<u8>().is_ok());

    // Check if hash — hex string of specific length
    let is_hash = (ioc.len() == 32 || ioc.len() == 40 || ioc.len() == 64) &&
        ioc.chars().all(|c| c.is_ascii_hexdigit());

    // Detect IOC type correctly
    let (ioc_type, is_malicious) = if is_real_ip {
        // Real IP address like 10.0.2.15
        ("ip", ti.is_malicious_ip(&ioc))
    } else if is_hash {
        // Hash (MD5=32, SHA1=40, SHA256=64)
        ("hash", ti.is_malicious_hash(&ioc))
    } else if ioc.contains('.') {
        // Domain/hostname — includes 1navorex.lat etc
        ("domain", ti.is_malicious_domain(&ioc))
    } else {
        ("unknown", false)
    };

    Json(json!({
        "ioc":          ioc,
        "type":         ioc_type,
        "is_malicious": is_malicious,
        "source":       "abuse.ch (Feodo + MalwareBazaar + URLhaus)"
    }))
}
pub async fn add_manual_ioc(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };
    let tenant_id = claims.tenant_id.clone();

    let ioc_type       = payload["type"].as_str().unwrap_or("ip");
    let value          = payload["value"].as_str().unwrap_or("");
    let attacker_group = payload["attacker_group"].as_str().unwrap_or("");

    if value.is_empty() {
        return Json(json!({"status": "error", "message": "value is required"}));
    }

    // Add to in-memory store for immediate effect
    state.enrichment.threat_intel.add_ioc(ioc_type, value);

    // Persist to ioc_watchlist so it survives engine restarts
    let _ = state.ch_storage.save_watchlist_ioc(&tenant_id, ioc_type, value, attacker_group).await;

    Json(json!({
        "status":  "added",
        "type":    ioc_type,
        "value":   value,
        "message": format!("IOC {} added and persisted to watchlist", ioc_type)
    }))
}

pub async fn get_watchlist_iocs(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };
    match state.ch_storage.get_watchlist_iocs_by_tenant(&claims.tenant_id).await {
        Ok(iocs) => Json(json!({"status": "ok", "data": iocs})),
        Err(e)   => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

pub async fn delete_watchlist_ioc(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(value): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };
    let decoded = urlencoding::decode(&value).unwrap_or(std::borrow::Cow::Borrowed(&value)).to_string();
    match state.ch_storage.delete_watchlist_ioc(&claims.tenant_id, &decoded).await {
        Ok(_)  => Json(json!({"status": "ok", "message": "IOC removed from watchlist"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

// auto reload rules
pub async fn reload_rules_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let rules_dir = std::env::var("RULES_DIR")
        .unwrap_or_else(|_| "rules".to_string());

    let (active, overrides) = load_rules_from_clickhouse(&state.ch_storage, &rules_dir).await;
    let count = active.len();

    state.detection.write().await.set_rules(active, overrides);
    tracing::info!("Hot-reloaded {} SIGMA rules", count);

    // Publish reload rules to Redis channel
    let redis = state.redis.clone();
    tokio::spawn(async move {
        if let Ok(mut conn) = redis.get_async_connection().await {
            let _: Result<(), _> = redis::cmd("PUBLISH")
                .arg("system:reload_rules")
                .arg(&tenant_id)
                .query_async(&mut conn)
                .await;
        }
    });

    Json(json!({
        "status":        "reloaded",
        "count":         count,
        "message":       "Rules reloaded successfully"
    }))
}

/// Admin-only: fetch latest SigmaHQ community network rules right now.
pub async fn sync_community_rules_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let claims = match require_super_admin(&headers) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let rules_dir = std::env::var("RULES_DIR").unwrap_or_else(|_| "rules".to_string());
    let redis_url = std::env::var("VALKEY_URL")
        .or_else(|_| std::env::var("REDIS_URL"))
        .unwrap_or_else(|_| "redis://localhost:6379".to_string());

    // Acquire a Valkey lock so only one engine runs the sync at a time.
    // TTL = 300s covers the worst-case GitHub download time.
    let lock_acquired = match redis::Client::open(redis_url.clone()) {
        Ok(client) => match client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                let result: redis::RedisResult<Option<String>> = redis::cmd("SET")
                    .arg("ndr:sync_rules_lock")
                    .arg("1")
                    .arg("NX")
                    .arg("EX")
                    .arg(300u64)
                    .query_async(&mut conn)
                    .await;
                matches!(result, Ok(Some(_)))
            }
            Err(_) => true, // Redis unavailable — allow sync to proceed
        },
        Err(_) => true,
    };

    if !lock_acquired {
        return Json(json!({
            "status":  "already_running",
            "message": "Sigma sync already in progress on another engine — check back in a minute",
        })).into_response();
    }

    // Spawn background — return immediately so nginx never times out
    let detection  = state.detection.clone();
    let ch_storage = state.ch_storage.clone();
    let admin_sub  = claims.sub.clone();
    tokio::spawn(async move {
        match crate::detection::sync_now(&rules_dir, &redis_url, &detection, &ch_storage).await {
            Ok(count) => tracing::info!("Admin {} SigmaHQ sync complete: {} new rules", admin_sub, count),
            Err(e)    => tracing::warn!("Admin {} SigmaHQ sync failed: {}", admin_sub, e),
        }
        // Release lock regardless of outcome
        if let Ok(client) = redis::Client::open(redis_url.clone()) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let _: redis::RedisResult<()> = redis::cmd("DEL")
                    .arg("ndr:sync_rules_lock")
                    .query_async(&mut conn)
                    .await;
            }
        }
    });

    tracing::info!("Admin {} triggered SigmaHQ sync in background", claims.sub);
    Json(json!({
        "status":  "started",
        "message": "Sigma sync started in background",
    })).into_response()
}

// ── License endpoints ────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct GenerateLicenseRequest {
    pub tenant_id:    String,
    pub tenant_name:  String,
    pub features:     Vec<String>,
    pub max_sensors:  u32,
    pub expires_days: u32,
    #[serde(default)]
    pub admin_user:   String,
}

pub async fn generate_license(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<GenerateLicenseRequest>,
) -> axum::response::Response {
    if let Err(e) = require_super_admin(&headers) { return e.into_response(); }
    if state.license_private_key.is_empty() {
        return Json(json!({ "error": "LICENSE_PRIVATE_KEY not configured on this server" })).into_response();
    }
    match crate::license::generate_license(
        &body.tenant_id,
        &body.tenant_name,
        body.features.clone(),
        body.max_sensors,
        body.expires_days,
        &state.license_private_key,
    ) {
        Ok(token) => {
            // Persist to DB so super admin can retrieve it later
            let _ = state.ch_storage.insert_license(
                &body.tenant_id,
                &body.tenant_name,
                &body.features,
                body.max_sensors,
                body.expires_days,
                &body.admin_user,
                &token,
            ).await;
            Json(json!({ "token": token, "status": "ok" })).into_response()
        }
        Err(e) => Json(json!({ "error": e.to_string() })).into_response(),
    }
}

pub async fn get_license_public_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if let Err(e) = require_super_admin(&headers) { return e.into_response(); }
    if state.license_public_key.is_empty() {
        return Json(json!({ "error": "LICENSE_PUBLIC_KEY not configured" })).into_response();
    }
    // Return the original base64-encoded value from env (single line) so the
    // customer can paste it directly into install-customer.sh without .env breakage.
    let b64 = std::env::var("LICENSE_PUBLIC_KEY").unwrap_or_default();
    Json(json!({ "public_key": b64 })).into_response()
}

pub async fn list_licenses(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    if let Err(e) = require_super_admin(&headers) { return e.into_response(); }
    let tenant_id = params.get("tenant_id").map(|s| s.as_str());
    match state.ch_storage.list_licenses(tenant_id).await {
        Ok(rows) => Json(json!({ "licenses": rows })).into_response(),
        Err(e)   => Json(json!({ "error": e.to_string() })).into_response(),
    }
}

pub async fn delete_license(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> axum::response::Response {
    if let Err(e) = require_super_admin(&headers) { return e.into_response(); }
    match state.ch_storage.delete_license(&id).await {
        Ok(_)  => Json(json!({ "status": "ok" })).into_response(),
        Err(e) => Json(json!({ "error": e.to_string() })).into_response(),
    }
}

pub async fn get_tenant_features(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let claims = extract_claims(&headers);
    let tenant_id = claims.map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let features = get_effective_features(&state, &tenant_id).await;
    let from_license = state.verified_license.as_ref().map_or(false, |l| l.tenant_id == tenant_id);
    Json(json!({ "features": features, "tenant_id": tenant_id, "from_license": from_license })).into_response()
}

pub async fn set_tenant_features(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(tenant_id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if let Err(e) = require_super_admin(&headers) { return e.into_response(); }
    let features: Vec<String> = body["features"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    match state.ch_storage.set_tenant_features(&tenant_id, &features).await {
        Ok(_)  => Json(json!({ "status": "ok", "features": features })).into_response(),
        Err(e) => Json(json!({ "error": e.to_string() })).into_response(),
    }
}

/// Returns the effective feature list for a tenant.
/// Checks the startup-verified license JWT first (on-premise installs);
/// falls back to the database for cloud deployments.
pub async fn get_effective_features(state: &AppState, tenant_id: &str) -> Vec<String> {
    if let Some(lic) = &state.verified_license {
        if lic.tenant_id == tenant_id {
            return lic.features.clone();
        }
    }
    state.ch_storage.get_tenant_features(tenant_id).await
}


#[cfg(feature = "soar")]
pub async fn get_soar_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());

    let playbooks = state.ch_storage
        .get_soar_playbooks_by_tenant(&tenant_id).await
        .unwrap_or_default();

    let active_count = playbooks.iter()
        .filter(|p| p["enabled"] == true)
        .count();

    Json(json!({
        "playbooks":    playbooks,
        "active_count": active_count,
        "ndr_playbooks_count": active_count
    }))
}






#[cfg(feature = "soar")]
pub async fn toggle_playbook(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let id = payload["id"]
        .as_str().unwrap_or("").to_string();
    let enabled = payload["enabled"]
        .as_bool().unwrap_or(false);

    match state.ch_storage
        .update_playbook_enabled(&id, enabled, &tenant_id).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": format!(
                "Playbook {} {}",
                id,
                if enabled { "enabled" } else { "disabled" }
            )
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

#[cfg(feature = "soar")]
pub async fn create_playbook(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let id = format!("pb-{}",
        chrono::Utc::now().timestamp());
    let name = payload["name"]
        .as_str().unwrap_or("New Playbook").to_string();
    let description = payload["description"]
        .as_str().unwrap_or("").to_string();
    let trigger = payload["trigger"]
        .as_str().unwrap_or("score > 75").to_string();
    let action_type = payload["action_type"]
        .as_str().unwrap_or("webhook").to_string();
    let action_config = payload["action_config"]
        .to_string()
        .replace("'", "\\'");



    match state.ch_storage.create_playbook(
        &id, &name, &description,
        &trigger, &action_type, &action_config, &tenant_id
    ).await {
        Ok(_) => Json(json!({
            "status":  "ok",
            "id":      id,
            "message": "Playbook created!"
        })),
        Err(e) => Json(json!({
            "status":  "error",
            "message": e.to_string()
        }))
    }
}





// ── SIGMA Rules CRUD ──────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct NewRule {
    pub title:       String,
    pub severity:    String,
    pub description: Option<String>,
    pub tags:        Option<Vec<String>>,
    pub field:       String,
    pub value:       String,
    pub matcher:     Option<String>,
}

pub async fn create_rule(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<NewRule>
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let id = format!("ndr-{}", chrono::Utc::now().timestamp());
    let tags = payload.tags.clone().unwrap_or_default();
    let matcher = payload.matcher.unwrap_or_else(|| "contains".to_string());
    let description = payload.description.unwrap_or_default();

    // Build SIGMA YAML
    let yaml = format!(
r#"id: {id}
title: {title}
description: {description}
level: {severity}
tags:{tags_str}
logsource:
  product: ndr
detection:
  keywords:
    {field}|{matcher}:
      - '{value}'
  condition: keywords
"#,
        id = id,
        title = payload.title,
        description = description,
        severity = payload.severity,
        tags_str = if tags.is_empty() {
            "\n  []".to_string()
        } else {
            tags.iter().map(|t| format!("\n  - {}", t)).collect::<String>()
        },
        field = payload.field,
        matcher = matcher,
        value = payload.value,
    );

    // Save to ClickHouse (single source of truth — no disk write needed)
    match state.ch_storage.save_sigma_rule(&id, &payload.title, &yaml, &tenant_id).await {
        Ok(_) => {

            let redis = state.redis.clone();
            let tid = tenant_id.clone();
            tokio::spawn(async move {
                if let Ok(mut conn) = redis.get_async_connection().await {
                    let _: Result<(), _> = redis::cmd("PUBLISH")
                        .arg("system:reload_rules")
                        .arg(&tid)
                        .query_async(&mut conn)
                        .await;
                }
            });

            tracing::info!("New SIGMA rule created in ClickHouse: {}", id);
            Json(json!({
                "status": "created",
                "id":     id,
                "rule":   yaml
            }))
        }
        Err(e) => {
            tracing::warn!("Failed to save rule in ClickHouse: {}", e);
            Json(json!({
                "status": "error",
                "message": e.to_string()
            }))
        }
    }
}

pub async fn delete_rule(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(rule_id): axum::extract::Path<String>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    if rule_id.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_') {
        return Json(json!({"status": "error", "message": "Invalid rule ID"}));
    }
    // Delete from ClickHouse
    let ch_deleted = state.ch_storage.delete_sigma_rule(&rule_id, &tenant_id).await.is_ok();
    
    // Also remove state from ClickHouse rules_state
    state.ch_storage.delete_rule_state(&rule_id, &tenant_id).await.ok();

    // Also delete from disk if present
    let rules_dir = std::env::var("RULES_DIR")
        .unwrap_or_else(|_| "rules".to_string());
    let file_path = format!("{}/{}.yml", rules_dir, rule_id);
    let disk_deleted = std::fs::remove_file(&file_path).is_ok();

    if ch_deleted || disk_deleted {
        // Reload rules
        let (active, overrides) = load_rules_from_clickhouse(&state.ch_storage, &rules_dir).await;
        let count = active.len();
        state.detection.write().await.set_rules(active, overrides);

        // Notify all other engine instances to reload
        let redis = state.redis.clone();
        let tid = tenant_id.clone();
        tokio::spawn(async move {
            if let Ok(mut conn) = redis.get_async_connection().await {
                let _: Result<(), _> = redis::cmd("PUBLISH")
                    .arg("system:reload_rules")
                    .arg(&tid)
                    .query_async(&mut conn).await;
            }
        });

        tracing::info!("Rule deleted: {}", rule_id);
        Json(json!({
            "status": "deleted",
            "id":     rule_id,
            "active_rules": count
        }))
    } else {
        Json(json!({
            "status":  "error",
            "message": "Rule not found"
        }))
    }
}



//scale status
pub async fn get_scale_status(State(state): State<AppState>) -> Json<Value> {
    let stats = state.ch_storage.get_stats().await.unwrap_or(json!({}));
    let events_1h = stats.get("events_1h")
        .and_then(|v| v.as_u64()).unwrap_or(0);
    let events_per_sec = events_1h / 3600;

    let count_out = std::process::Command::new("docker")
        .args(["ps", "-q", "--filter", "name=ndr-engine"])
        .output()
        .unwrap_or_else(|_| std::process::Output {
            status: <std::process::ExitStatus as ExitStatusDefault>::default(),
            stdout: vec![],
            stderr: vec![],
        });
    let current_engines = String::from_utf8_lossy(&count_out.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .count() as u64;

    Json(json!({
        "events_per_sec":   events_per_sec,
        "events_1h":        events_1h,
        "sessions":         state.correlator.session_count(),
        "scale_recommendation": if events_per_sec > 10000 {
            "scale_up"
        } else if events_per_sec < 1000 {
            "scale_down"
        } else {
            "optimal"
        },
        "current_engines": current_engines,
        "max_engines":     12,
    }))
}



//rules enable disable
pub async fn toggle_rule(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(rule_id): axum::extract::Path<String>,
    Json(payload): Json<TogglePayload>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());

    // Bug 5 fix: toggle_sigma_rule now returns whether the rule is a community rule.
    // Community rules can't be modified in sigma_rules directly — they use rules_state overrides.
    // Custom rules use sigma_rules.enabled directly — rules_state is redundant and skipped.
    let is_community = match state.ch_storage
        .toggle_sigma_rule(&rule_id, payload.enabled, &tenant_id).await {
        Ok(v) => v,
        Err(e) => return Json(json!({"status": "error", "message": e.to_string()})),
    };

    if is_community {
        if let Err(e) = state.ch_storage
            .set_rule_enabled(&rule_id, payload.enabled, &tenant_id).await {
            return Json(json!({"status": "error", "message": e.to_string()}));
        }
    }

    // Reload rules respecting disabled state
    let rules_dir = std::env::var("RULES_DIR")
        .unwrap_or_else(|_| "rules".to_string());
    let (active, overrides) = load_rules_from_clickhouse(&state.ch_storage, &rules_dir).await;
    let count = active.len();
    state.detection.write().await.set_rules(active, overrides);

    // Notify all other engine instances to reload
    let redis = state.redis.clone();
    let tid = tenant_id.clone();
    tokio::spawn(async move {
        if let Ok(mut conn) = redis.get_async_connection().await {
            let _: Result<(), _> = redis::cmd("PUBLISH")
                .arg("system:reload_rules")
                .arg(&tid)
                .query_async(&mut conn).await;
        }
    });

    Json(json!({
        "status":       "ok",
        "id":           rule_id,
        "enabled":      payload.enabled,
        "active_rules": count
    }))
}

// ── Sensor assignment handlers ────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct SensorAssignPayload {
    pub user_id:   String,
    pub sensor_id: String,
}

/// POST /api/sensors/assign  — tenant_admin assigns a sensor to an analyst
pub async fn assign_sensor_to_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<SensorAssignPayload>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({ "status": "error", "message": "Unauthorized" })),
    };
    if claims.role != "tenant_admin" && claims.role != "super_admin" {
        return Json(json!({ "status": "error", "message": "Forbidden: admin required" }));
    }
    // Verify the target user and sensor are real and actually belong to
    // the same tenant before writing the assignment — previously this
    // trusted user_id/sensor_id from the request body outright, so a
    // tenant_admin could reference an id from another tenant with no check.
    if let Err(resp) = verify_same_tenant_assignment(&state, &claims, &payload.user_id, &payload.sensor_id).await {
        return resp;
    }
    match state.ch_storage
        .assign_sensor_to_user(&payload.user_id, &payload.sensor_id, &claims.tenant_id).await
    {
        Ok(_) => Json(json!({ "status": "ok", "user_id": payload.user_id, "sensor_id": payload.sensor_id })),
        Err(e) => Json(json!({ "status": "error", "message": e.to_string() })),
    }
}

/// Shared ownership check for assign/remove: the user and sensor must both
/// exist, must belong to the same real tenant as each other, and — unless
/// the caller is super_admin — that tenant must be the caller's own.
async fn verify_same_tenant_assignment(
    state: &AppState,
    claims: &AuthClaims,
    user_id: &str,
    sensor_key_prefix: &str,
) -> Result<(), Json<Value>> {
    let user_tenant = match state.ch_storage.get_user_tenant(user_id).await {
        Ok(Some(t)) => t,
        Ok(None) => return Err(Json(json!({ "status": "error", "message": "User not found" }))),
        Err(e) => return Err(Json(json!({ "status": "error", "message": e.to_string() }))),
    };
    let sensor_tenant = match state.ch_storage.get_sensor_key_tenant(sensor_key_prefix).await {
        Ok(Some(t)) => t,
        Ok(None) => return Err(Json(json!({ "status": "error", "message": "Sensor not found" }))),
        Err(e) => return Err(Json(json!({ "status": "error", "message": e.to_string() }))),
    };
    if user_tenant != sensor_tenant {
        return Err(Json(json!({ "status": "error", "message": "User and sensor must belong to the same tenant" })));
    }
    if claims.role != "super_admin" && user_tenant != claims.tenant_id {
        return Err(Json(json!({ "status": "error", "message": "Forbidden: cannot manage sensors outside your tenant" })));
    }
    Ok(())
}

/// DELETE /api/sensors/assign  — remove a sensor assignment
pub async fn remove_sensor_from_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<SensorAssignPayload>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({ "status": "error", "message": "Unauthorized" })),
    };
    if claims.role != "tenant_admin" && claims.role != "super_admin" {
        return Json(json!({ "status": "error", "message": "Forbidden: admin required" }));
    }
    if let Err(resp) = verify_same_tenant_assignment(&state, &claims, &payload.user_id, &payload.sensor_id).await {
        return resp;
    }
    match state.ch_storage
        .remove_sensor_assignment(&payload.user_id, &payload.sensor_id, &claims.tenant_id).await
    {
        Ok(_) => Json(json!({ "status": "ok", "removed": true })),
        Err(e) => Json(json!({ "status": "error", "message": e.to_string() })),
    }
}

/// GET /api/sensors/assignments  — list all user→sensor assignments for this tenant
pub async fn list_sensor_assignments(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({ "status": "error", "message": "Unauthorized" })),
    };
    if claims.role != "tenant_admin" && claims.role != "super_admin" {
        return Json(json!({ "status": "error", "message": "Forbidden: admin required" }));
    }
    match state.ch_storage.get_sensor_assignments(&claims.tenant_id).await {
        Ok(rows) => {
            let list: Vec<Value> = rows.iter().map(|(uid, sid)| json!({
                "user_id":   uid,
                "sensor_id": sid,
            })).collect();
            Json(json!({ "status": "ok", "assignments": list }))
        }
        Err(e) => Json(json!({ "status": "error", "message": e.to_string() })),
    }
}

//get the executions from the workflow
// Get settings
pub async fn get_settings(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    match state.ch_storage.get_settings_by_tenant(&tenant_id).await {
        Ok(settings) => Json(json!({
            "status": "ok",
            "settings": settings
        })),
        Err(_) => Json(json!({
            "status": "ok",
            "settings": {
                "store_threshold":    10,
                "alert_threshold":    75,
                "critical_threshold": 90,
                "medium_threshold":   50,
                "low_threshold":      25,
                "soar_threshold":     75
            }
        }))
    }
}

// Update settings
pub async fn update_settings(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    // Numeric threshold keys
    let numeric_keys = vec![
        "store_threshold",
        "alert_threshold",
        "critical_threshold",
        "medium_threshold",
        "low_threshold",
        "soar_threshold",
    ];
    for key in &numeric_keys {
        if let Some(val) = payload[key].as_f64() {
            let _ = state.ch_storage
                .save_setting_by_tenant(key, &val.to_string(), &tenant_id)
                .await;
        }
    }

    // String keys — saved as-is
    let string_keys = vec!["sensitive_countries"];
    for key in &string_keys {
        if let Some(val) = payload[key].as_str() {
            let _ = state.ch_storage
                .save_setting_by_tenant(key, val, &tenant_id)
                .await;
        }
    }

    Json(json!({
        "status": "ok",
        "message": "Settings saved!"
    }))
}

// GET /api/settings/smtp — super_admin only
pub async fn get_global_smtp(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    if let Err(e) = require_super_admin(&headers) {
        return e;
    }
    let (host, port_str, user, password) = state.ch_storage.get_global_smtp_settings().await.unwrap_or_else(|_| ("smtp.gmail.com".to_string(), "587".to_string(), "".to_string(), "".to_string()));
    let port = port_str.parse::<u16>().unwrap_or(587);
    
    let masked_password = if password.is_empty() { "".to_string() } else { "****".to_string() };

    Json(json!({
        "status": "ok",
        "config": {
            "host": host,
            "port": port,
            "user": user,
            "password": masked_password
        }
    }))
}

// POST /api/settings/smtp — super_admin only
pub async fn update_global_smtp(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    if let Err(e) = require_super_admin(&headers) {
        return e;
    }
    
    let host = payload["host"].as_str().unwrap_or("smtp.gmail.com");
    let port = payload["port"].as_u64().unwrap_or(587) as u16;
    let user = payload["user"].as_str().unwrap_or("");
    let password = payload["password"].as_str().unwrap_or("");

    let _ = state.ch_storage.save_setting("global_smtp_host", host).await;
    let _ = state.ch_storage.save_setting("global_smtp_port", &port.to_string()).await;
    let _ = state.ch_storage.save_setting("global_smtp_user", user).await;
    
    if !password.is_empty() && password != "****" {
        let _ = state.ch_storage.save_setting("global_smtp_password", password).await;
    }

    Json(json!({
        "status": "ok",
        "message": "SMTP configuration saved successfully"
    }))
}

// GET /api/settings/ai — super_admin only
pub async fn get_ai_config(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    if let Err(e) = require_super_admin(&headers) {
        return e;
    }
    let cfg = state.ch_storage.get_ai_config_full("default").await;
    let masked_key = if cfg.api_key.is_empty() { "".to_string() } else { "****".to_string() };
    Json(json!({
        "status":          "ok",
        "ai_provider":     cfg.provider,
        "ai_api_key":      masked_key,
        "ai_key_set":      !cfg.api_key.is_empty(),
        "ai_model":        cfg.model,
        "ai_base_url":     cfg.base_url,
        "ai_endpoint_path": cfg.endpoint_path,
        "ai_msg_format":   cfg.msg_format
    }))
}

// POST /api/settings/ai — super_admin only
pub async fn update_ai_config(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    if let Err(e) = require_super_admin(&headers) {
        return e;
    }

    let string_fields = [
        "ai_provider", "ai_model", "ai_base_url",
        "ai_endpoint_path", "ai_msg_format",
    ];
    for key in &string_fields {
        if let Some(v) = payload[*key].as_str() {
            let _ = state.ch_storage
                .save_setting_by_tenant(key, v, "default").await;
        }
    }
    // Only overwrite the API key if a real value is provided (not masked)
    if let Some(v) = payload["ai_api_key"].as_str() {
        if !v.is_empty() && !v.contains('*') {
            let _ = state.ch_storage
                .save_setting_by_tenant("ai_api_key", v, "default").await;
        }
    }

    Json(json!({
        "status": "ok",
        "message": "AI configuration saved!"
    }))
}

// GET /api/settings/ai/providers — list all providers (super_admin)
pub async fn list_ai_providers(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    if let Err(e) = require_super_admin(&headers) { return e; }
    match state.ch_storage.list_ai_providers().await {
        Ok(providers) => Json(json!({ "status": "ok", "providers": providers })),
        Err(e)        => Json(json!({ "status": "error", "error": e.to_string() })),
    }
}

// POST /api/settings/ai/providers — add or update a provider (super_admin)
pub async fn save_ai_provider(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(p): Json<Value>,
) -> Json<Value> {
    if let Err(e) = require_super_admin(&headers) { return e; }

    let name          = p["name"].as_str().unwrap_or("").trim().to_string();
    let provider_type = p["provider_type"].as_str().unwrap_or("custom").to_string();
    let api_key       = p["api_key"].as_str().unwrap_or("").to_string();
    let model         = p["model"].as_str().unwrap_or("").to_string();
    let base_url      = p["base_url"].as_str().unwrap_or("").to_string();
    let endpoint_path = p["endpoint_path"].as_str().unwrap_or("/v1/chat/completions").to_string();
    let msg_format    = p["msg_format"].as_str().unwrap_or("openai").to_string();
    let use_case      = p["use_case"].as_str().unwrap_or("all").to_string();
    let priority      = p["priority"].as_u64().unwrap_or(10) as u8;
    let enabled       = p["enabled"].as_bool().unwrap_or(true);

    if name.is_empty() {
        return Json(json!({ "status": "error", "error": "name is required" }));
    }

    // If api_key contains '****' it's the masked value — keep existing key
    let effective_key = if api_key.contains("****") || api_key.is_empty() {
        // preserve existing key by re-inserting with existing value
        match state.ch_storage.list_ai_providers().await {
            Ok(_) => {
                // We can't get the actual key from list (it's masked), so just skip key update
                String::new()
            }
            Err(_) => String::new(),
        }
    } else {
        api_key
    };

    // If effective_key is empty and provider already exists, get the existing key
    let final_key = if effective_key.is_empty() {
        state.ch_storage.get_ai_provider_key(&name).await.unwrap_or_default()
    } else {
        effective_key
    };

    match state.ch_storage.save_ai_provider(
        &name, &provider_type, &final_key, &model,
        &base_url, &endpoint_path, &msg_format,
        &use_case, priority, enabled,
    ).await {
        Ok(_)  => Json(json!({ "status": "ok", "message": "Provider saved" })),
        Err(e) => Json(json!({ "status": "error", "error": e.to_string() })),
    }
}

// DELETE /api/settings/ai/providers/:name — remove a provider (super_admin)
pub async fn delete_ai_provider(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Json<Value> {
    if let Err(e) = require_super_admin(&headers) { return e; }
    match state.ch_storage.delete_ai_provider(&name).await {
        Ok(_)  => Json(json!({ "status": "ok", "message": "Provider deleted" })),
        Err(e) => Json(json!({ "status": "error", "error": e.to_string() })),
    }
}

// POST /api/settings/ai/providers/test — test a specific provider config (super_admin)
pub async fn test_ai_provider(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(p): Json<Value>,
) -> Json<Value> {
    if let Err(e) = require_super_admin(&headers) { return e; }

    let name          = p["name"].as_str().unwrap_or("test").to_string();
    let raw_api_key   = p["api_key"].as_str().unwrap_or("").to_string();

    // If UI sent masked key (****) or empty, look up real key from DB by name
    let api_key = if raw_api_key.is_empty() || raw_api_key.contains("****") {
        state.ch_storage.get_ai_provider_key(&name).await.unwrap_or_default()
    } else {
        raw_api_key
    };

    if api_key.is_empty() {
        return Json(json!({ "status": "error", "error": "No API key found for this provider" }));
    }

    let provider = crate::ai::provider::AiProvider {
        name,
        provider_type: p["provider_type"].as_str().unwrap_or("custom").to_string(),
        api_key,
        model:         p["model"].as_str().unwrap_or("").to_string(),
        base_url:      p["base_url"].as_str().unwrap_or("").to_string(),
        endpoint_path: p["endpoint_path"].as_str().unwrap_or("/v1/chat/completions").to_string(),
        msg_format:    p["msg_format"].as_str().unwrap_or("openai").to_string(),
        priority:      1,
    };

    match crate::ai::provider::call_provider_test(
        &provider,
        "You are a test assistant.",
        "Reply with exactly: OK",
    ).await {
        Ok(text) => Json(json!({ "status": "ok", "response": text })),
        Err(e)   => Json(json!({ "status": "error", "error": e })),
    }
}

fn build_xlsx_report(
    report: &serde_json::Value,
    assets: &[crate::storage::clickhouse::AssetRow],
) -> Result<Vec<u8>, String> {
    use rust_xlsxwriter::{Color, Format, Workbook, Worksheet};

    fn fmt_ts_xl(unix: u64) -> String {
        use chrono::{TimeZone, Utc};
        Utc.timestamp_opt(unix as i64, 0)
            .single()
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| unix.to_string())
    }

    fn sev_colors(sev: &str) -> (Color, Color) {
        match sev.to_lowercase().as_str() {
            "critical" => (Color::RGB(0xDC2626), Color::RGB(0xFFFFFF)),
            "high"     => (Color::RGB(0xEA580C), Color::RGB(0xFFFFFF)),
            "medium"   => (Color::RGB(0xCA8A04), Color::RGB(0x1F2937)),
            "low"      => (Color::RGB(0x16A34A), Color::RGB(0xFFFFFF)),
            _          => (Color::RGB(0x2563EB), Color::RGB(0xFFFFFF)),
        }
    }

    let hdr_fmt = Format::new()
        .set_bold()
        .set_background_color(Color::RGB(0x1E293B))
        .set_font_color(Color::RGB(0xFFFFFF));

    // ── Sheet 1: Summary ────────────────────────────────────────────────────
    let mut ws_summary = Worksheet::new();
    ws_summary.set_name("Summary").map_err(|e| e.to_string())?;
    ws_summary.set_column_width(0, 28.0).map_err(|e| e.to_string())?;
    ws_summary.set_column_width(1, 18.0).map_err(|e| e.to_string())?;
    ws_summary.write_with_format(0, 0, "Metric", &hdr_fmt).map_err(|e| e.to_string())?;
    ws_summary.write_with_format(0, 1, "Value",  &hdr_fmt).map_err(|e| e.to_string())?;
    // "Total Hits" = scoped count (same window + suppression as Alerts sheet)
    let scoped_hits_total: u64 = ["critical", "high", "medium", "low", "info"]
        .iter()
        .map(|s| report["severity_breakdown"][s].as_u64().unwrap_or(0))
        .sum();
    let summary_rows: &[(&str, u64)] = &[
        ("Total Events",      report["summary"]["total_events"].as_u64().unwrap_or(0)),
        ("Total Hits",        scoped_hits_total),
        ("Events Last Hour",  report["summary"]["events_1h"].as_u64().unwrap_or(0)),
        ("Agent-Z Events",    report["summary"]["agent_z_events"].as_u64().unwrap_or(0)),
        ("Agent-S Events",    report["summary"]["agent_s_events"].as_u64().unwrap_or(0)),
        ("Active Rules",      report["summary"]["active_rules"].as_u64().unwrap_or(0)),
    ];
    for (i, (metric, value)) in summary_rows.iter().enumerate() {
        let row = (i + 1) as u32;
        ws_summary.write(row, 0, *metric).map_err(|e| e.to_string())?;
        ws_summary.write(row, 1, *value as f64).map_err(|e| e.to_string())?;
    }

    // ── Sheet 2: Alerts ─────────────────────────────────────────────────────
    let mut ws_alerts = Worksheet::new();
    ws_alerts.set_name("Alerts").map_err(|e| e.to_string())?;
    let alert_col_widths: &[(u16, f64)] = &[
        (0,20.0),(1,26.0),(2,15.0),(3,20.0),(4,10.0),
        (5,15.0),(6,20.0),(7,28.0),(8,10.0),(9,12.0),
        (10,7.0),(11,10.0),(12,12.0),(13,16.0),
        (14,30.0),(15,30.0),(16,16.0),(17,14.0),
    ];
    for (col, w) in alert_col_widths {
        ws_alerts.set_column_width(*col, *w).map_err(|e| e.to_string())?;
    }
    let alert_hdrs = [
        "Timestamp","Community ID",
        "Source IP","Source Hostname","Src Country",
        "Dest IP","Dest Hostname","Dest Domain","Dst Country",
        "Severity","Score","Threat Intel","Corroborated","Corr. Status",
        "Tags","Sigma Rules","Agent-S Rule","Sensor ID",
    ];
    for (c, h) in alert_hdrs.iter().enumerate() {
        ws_alerts.write_with_format(0, c as u16, *h, &hdr_fmt).map_err(|e| e.to_string())?;
    }
    if let Some(arr) = report["recent_hits"].as_array() {
        for (i, h) in arr.iter().enumerate() {
            let row = (i + 1) as u32;
            let sev = h["severity"].as_str().unwrap_or("info");
            let (bg, fg) = sev_colors(sev);
            let row_fmt = Format::new()
                .set_background_color(bg)
                .set_font_color(fg);
            let dst_host = h["dst_asset"]["hostname"].as_str().unwrap_or("");
            let vals: &[&str] = &[
                &fmt_ts_xl(h["timestamp"].as_u64().unwrap_or(0)),
                h["community_id"].as_str().unwrap_or("-"),
                h["src_ip"].as_str().unwrap_or("-"),
                h["src_asset"]["hostname"].as_str().unwrap_or("-"),
                h["src_country"].as_str().unwrap_or("-"),
                h["dst_ip"].as_str().unwrap_or("-"),
                if dst_host.is_empty() { "-" } else { dst_host },
                h["dst_domain"].as_str().unwrap_or("-"),
                h["dst_country"].as_str().unwrap_or("-"),
                sev,
                &format!("{:.1}", h["score"].as_f64().unwrap_or(0.0)),
                if h["threat_intel"].as_bool().unwrap_or(false) { "Yes" } else { "No" },
                if h["corroborated"].as_bool().unwrap_or(false)  { "Yes" } else { "No" },
                h["correlation_status"].as_str().unwrap_or("-"),
                &h["tags"].as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join("; "))
                    .unwrap_or_default(),
                &h["sigma_hits"].as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join("; "))
                    .unwrap_or_default(),
                h["agent_s_rule_id"].as_str().unwrap_or("-"),
                h["sensor_id"].as_str().unwrap_or("-"),
            ];
            for (c, val) in vals.iter().enumerate() {
                ws_alerts.write_with_format(row, c as u16, *val, &row_fmt)
                    .map_err(|e| e.to_string())?;
            }
        }
    }

    // ── Sheet 3: Severity Breakdown ─────────────────────────────────────────
    let mut ws_sev = Worksheet::new();
    ws_sev.set_name("Severity Breakdown").map_err(|e| e.to_string())?;
    ws_sev.set_column_width(0, 16.0).map_err(|e| e.to_string())?;
    ws_sev.set_column_width(1, 12.0).map_err(|e| e.to_string())?;
    ws_sev.set_column_width(2, 14.0).map_err(|e| e.to_string())?;
    ws_sev.write_with_format(0, 0, "Severity",   &hdr_fmt).map_err(|e| e.to_string())?;
    ws_sev.write_with_format(0, 1, "Count",      &hdr_fmt).map_err(|e| e.to_string())?;
    ws_sev.write_with_format(0, 2, "% of Total", &hdr_fmt).map_err(|e| e.to_string())?;
    // Use the sum of scoped severity counts as denominator — these are filtered to the
    // same time window and suppression rules as the Alerts sheet, so percentages are accurate.
    let sev_total = ["critical", "high", "medium", "low", "info"]
        .iter()
        .map(|s| report["severity_breakdown"][s].as_u64().unwrap_or(0))
        .sum::<u64>()
        .max(1) as f64;
    let mut sev_row = 1u32;
    for sev_name in ["critical", "high", "medium", "low", "info"] {
        let cnt = report["severity_breakdown"][sev_name].as_u64().unwrap_or(0);
        if cnt == 0 { continue; }
        let pct = format!("{:.0}%", cnt as f64 / sev_total * 100.0);
        let (bg, fg) = sev_colors(sev_name);
        let sev_fmt = Format::new()
            .set_bold()
            .set_background_color(bg)
            .set_font_color(fg);
        ws_sev.write_with_format(sev_row, 0, sev_name,        &sev_fmt).map_err(|e| e.to_string())?;
        ws_sev.write_with_format(sev_row, 1, cnt as f64,      &sev_fmt).map_err(|e| e.to_string())?;
        ws_sev.write_with_format(sev_row, 2, pct.as_str(),    &sev_fmt).map_err(|e| e.to_string())?;
        sev_row += 1;
    }

    // ── Sheet 4: Assets ─────────────────────────────────────────────────────
    let mut ws_assets = Worksheet::new();
    ws_assets.set_name("Assets").map_err(|e| e.to_string())?;
    let asset_cols: &[(u16, f64)] = &[
        (0,15.0),(1,20.0),(2,18.0),(3,20.0),(4,14.0),
        (5,14.0),(6,20.0),(7,10.0),(8,14.0),(9,22.0),(10,22.0),
    ];
    for (col, w) in asset_cols {
        ws_assets.set_column_width(*col, *w).map_err(|e| e.to_string())?;
    }
    let asset_hdr = [
        "IP","Hostname","MAC","Vendor","OS Guess",
        "Device Type","Custom Name","Trusted","Threat Flagged",
        "First Seen","Last Seen",
    ];
    for (c, h) in asset_hdr.iter().enumerate() {
        ws_assets.write_with_format(0, c as u16, *h, &hdr_fmt).map_err(|e| e.to_string())?;
    }
    let threat_fmt  = Format::new().set_background_color(Color::RGB(0xFEE2E2));
    let trusted_fmt = Format::new().set_background_color(Color::RGB(0xDCFCE7));
    let plain_fmt   = Format::new();
    for (i, a) in assets.iter().enumerate() {
        let row = (i + 1) as u32;
        let row_fmt = if a.threat_flagged != 0 { &threat_fmt }
                      else if a.trusted != 0   { &trusted_fmt }
                      else                      { &plain_fmt };
        let str_cols: &[&str] = &[
            &a.ip, &a.hostname, &a.mac, &a.vendor,
            &a.os_guess, &a.device_type, &a.custom_name,
        ];
        for (c, val) in str_cols.iter().enumerate() {
            ws_assets.write_with_format(row, c as u16, *val, row_fmt)
                .map_err(|e| e.to_string())?;
        }
        ws_assets.write_with_format(row, 7,  if a.trusted != 0 { "Yes" } else { "No" },        row_fmt).map_err(|e| e.to_string())?;
        ws_assets.write_with_format(row, 8,  if a.threat_flagged != 0 { "Yes" } else { "No" }, row_fmt).map_err(|e| e.to_string())?;
        ws_assets.write_with_format(row, 9,  fmt_ts_xl(a.first_seen as u64).as_str(),           row_fmt).map_err(|e| e.to_string())?;
        ws_assets.write_with_format(row, 10, fmt_ts_xl(a.last_seen as u64).as_str(),            row_fmt).map_err(|e| e.to_string())?;
    }

    // ── Sheet 5: Threat Intel ────────────────────────────────────────────────
    let mut ws_ti = Worksheet::new();
    ws_ti.set_name("Threat Intel").map_err(|e| e.to_string())?;
    ws_ti.set_column_width(0, 15.0).map_err(|e| e.to_string())?;
    ws_ti.set_column_width(1, 15.0).map_err(|e| e.to_string())?;
    ws_ti.set_column_width(2, 12.0).map_err(|e| e.to_string())?;
    ws_ti.set_column_width(3, 22.0).map_err(|e| e.to_string())?;
    ws_ti.write_with_format(0, 0, "Source IP",  &hdr_fmt).map_err(|e| e.to_string())?;
    ws_ti.write_with_format(0, 1, "Dest IP",    &hdr_fmt).map_err(|e| e.to_string())?;
    ws_ti.write_with_format(0, 2, "Hit Count",  &hdr_fmt).map_err(|e| e.to_string())?;
    ws_ti.write_with_format(0, 3, "Last Seen",  &hdr_fmt).map_err(|e| e.to_string())?;
    let ti_fmt = Format::new().set_background_color(Color::RGB(0xFEF2F2));
    if let Some(arr) = report["threat_intel_hits"].as_array() {
        for (i, t) in arr.iter().enumerate() {
            let row = (i + 1) as u32;
            ws_ti.write_with_format(row, 0, t["src_ip"].as_str().unwrap_or("-"),                        &ti_fmt).map_err(|e| e.to_string())?;
            ws_ti.write_with_format(row, 1, t["dst_ip"].as_str().unwrap_or("-"),                        &ti_fmt).map_err(|e| e.to_string())?;
            ws_ti.write_with_format(row, 2, t["hits"].as_u64().unwrap_or(0) as f64,                     &ti_fmt).map_err(|e| e.to_string())?;
            ws_ti.write_with_format(row, 3, fmt_ts_xl(t["last_seen"].as_u64().unwrap_or(0)).as_str(),   &ti_fmt).map_err(|e| e.to_string())?;
        }
    }

    // ── Sheet 6: Top Source IPs ──────────────────────────────────────────────
    let mut ws_ips = Worksheet::new();
    ws_ips.set_name("Top Source IPs").map_err(|e| e.to_string())?;
    ws_ips.set_column_width(0, 6.0).map_err(|e| e.to_string())?;
    ws_ips.set_column_width(1, 15.0).map_err(|e| e.to_string())?;
    ws_ips.set_column_width(2, 14.0).map_err(|e| e.to_string())?;
    ws_ips.write_with_format(0, 0, "Rank",        &hdr_fmt).map_err(|e| e.to_string())?;
    ws_ips.write_with_format(0, 1, "Source IP",   &hdr_fmt).map_err(|e| e.to_string())?;
    ws_ips.write_with_format(0, 2, "Alert Count", &hdr_fmt).map_err(|e| e.to_string())?;
    // Compute from hits so this sheet is populated even when live events are idle
    let mut ip_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    if let Some(arr) = report["recent_hits"].as_array() {
        for h in arr {
            if let Some(ip) = h["src_ip"].as_str() {
                if !ip.is_empty() { *ip_counts.entry(ip.to_string()).or_insert(0) += 1; }
            }
        }
    }
    if ip_counts.is_empty() {
        if let Some(ips) = report["top_source_ips"].as_array() {
            for (i, ip) in ips.iter().enumerate() {
                let row = (i + 1) as u32;
                ws_ips.write(row, 0, (i + 1) as f64).map_err(|e| e.to_string())?;
                ws_ips.write(row, 1, ip["ip"].as_str().unwrap_or("-")).map_err(|e| e.to_string())?;
                ws_ips.write(row, 2, ip["count"].as_u64().unwrap_or(0) as f64).map_err(|e| e.to_string())?;
            }
        }
    } else {
        let mut sorted: Vec<(&String, &u64)> = ip_counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (i, (ip, cnt)) in sorted.iter().take(10).enumerate() {
            let row = (i + 1) as u32;
            ws_ips.write(row, 0, (i + 1) as f64).map_err(|e| e.to_string())?;
            ws_ips.write(row, 1, ip.as_str()).map_err(|e| e.to_string())?;
            ws_ips.write(row, 2, **cnt as f64).map_err(|e| e.to_string())?;
        }
    }

    // Push all worksheets to workbook in order
    let mut wb = Workbook::new();
    wb.push_worksheet(ws_summary);
    wb.push_worksheet(ws_alerts);
    wb.push_worksheet(ws_sev);
    wb.push_worksheet(ws_assets);
    wb.push_worksheet(ws_ti);
    wb.push_worksheet(ws_ips);

    wb.save_to_buffer().map_err(|e| e.to_string())
}

pub async fn export_report(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,) -> axum::response::Response {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();
    let format = params.get("format").map(|s: &String| s.as_str()).unwrap_or("json");
    let hours: u32 = params.get("hours").and_then(|h: &String| h.parse().ok()).unwrap_or(24);

    let stats    = state.ch_storage.get_stats_by_tenant(&tenant_id, &sensor_ids).await
        .unwrap_or(json!({}));
    let hits     = state.ch_storage.get_recent_hits_by_tenant(500, &tenant_id, &sensor_ids, hours, None).await
        .unwrap_or_default();
    let top_ips  = state.ch_storage.get_top_src_ips_by_tenant(10, &tenant_id, &sensor_ids).await
        .unwrap_or_default();
    let severity = state.ch_storage.get_severity_by_tenant(&tenant_id, &sensor_ids, hours).await
        .unwrap_or(json!({}));
    let threat   = state.ch_storage.get_threat_intel_hits_by_tenant(&tenant_id, &sensor_ids).await
        .unwrap_or_default();
let rules = state.detection.read().await.get_rules();

    let report = json!({
        "generated_at":     chrono::Utc::now().to_rfc3339(),
        "time_range_hours": hours,
        "summary": {
            "total_events":    stats.get("events_total")
                .and_then(|v| v.as_u64()).unwrap_or(0),
            "total_hits":      stats.get("hits_total")
                .and_then(|v| v.as_u64()).unwrap_or(0),
            "events_1h":       stats.get("events_1h")
                .and_then(|v| v.as_u64()).unwrap_or(0),
            "agent_z_events":     stats.get("agent_z_events")
                .and_then(|v| v.as_u64()).unwrap_or(0),
            "agent_s_events": stats.get("agent_s_events")
                .and_then(|v| v.as_u64()).unwrap_or(0),
            "active_rules":    rules.len(),
        },
        "severity_breakdown":  severity,
        "top_source_ips":      top_ips,
        "recent_hits":         hits,
        "threat_intel_hits":   threat,
        "active_rules":        rules,
    });

    match format {
        "csv" => {
            // Helper: quote a CSV field — wraps in double-quotes and escapes any
            // internal double-quotes so values with commas/newlines are safe.
            fn csv_field(s: &str) -> String {
                if s.contains([',', '"', '\n', '\r']) {
                    format!("\"{}\"", s.replace('"', "\"\""))
                } else {
                    s.to_string()
                }
            }

            // Helper: format a unix timestamp as a readable UTC datetime string.
            fn fmt_ts(unix: u64) -> String {
                use chrono::{TimeZone, Utc};
                Utc.timestamp_opt(unix as i64, 0)
                    .single()
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| unix.to_string())
            }

            let mut csv = String::new();
            csv.push_str("NDR Security Report\n");
            csv.push_str(&format!("Generated,{}\n", chrono::Utc::now().to_rfc3339()));
            csv.push_str(&format!("Time Range,Last {} hours\n\n", hours));

            csv.push_str("SUMMARY\n");
            csv.push_str("Metric,Value\n");
            csv.push_str(&format!("Total Events,{}\n",   report["summary"]["total_events"]));
            csv.push_str(&format!("Total Hits,{}\n",     report["summary"]["total_hits"]));
            csv.push_str(&format!("Events Last Hour,{}\n", report["summary"]["events_1h"]));
            csv.push_str(&format!("Agent-Z Events,{}\n", report["summary"]["agent_z_events"]));
            csv.push_str(&format!("Agent-S Events,{}\n", report["summary"]["agent_s_events"]));
            csv.push_str(&format!("Active Rules,{}\n\n", report["summary"]["active_rules"]));

            csv.push_str("CORRELATION HITS\n");
            csv.push_str("Timestamp,Community ID,\
                Source IP,Source Hostname,Source Country,\
                Dest IP,Dest Hostname,Dest Domain,Dest Country,\
                Severity,Score,Threat Intel,Corroborated,Correlation Status,\
                Tags,Sigma Rules,Agent-S Rule,Sensor ID\n");
            if let Some(arr) = report["recent_hits"].as_array() {
                for h in arr {
                    let ts         = h["timestamp"].as_u64().unwrap_or(0);
                    let cid        = h["community_id"].as_str().unwrap_or("-");
                    let src_ip     = h["src_ip"].as_str().unwrap_or("-");
                    let dst_ip     = h["dst_ip"].as_str().unwrap_or("-");
                    let src_host   = h["src_asset"]["hostname"].as_str().unwrap_or("-");
                    let dst_host   = h["dst_asset"]["hostname"].as_str()
                                       .filter(|s| !s.is_empty()).unwrap_or("-");
                    let dst_domain = h["dst_domain"].as_str().unwrap_or("-");
                    let src_ctry   = h["src_country"].as_str().unwrap_or("-");
                    let dst_ctry   = h["dst_country"].as_str().unwrap_or("-");
                    let severity   = h["severity"].as_str().unwrap_or("-");
                    let score      = h["score"].as_f64().unwrap_or(0.0);
                    let threat     = if h["threat_intel"].as_bool().unwrap_or(false) { "Yes" } else { "No" };
                    let corroborate= if h["corroborated"].as_bool().unwrap_or(false) { "Yes" } else { "No" };
                    let cor_status = h["correlation_status"].as_str().unwrap_or("-");
                    let tags       = h["tags"].as_array()
                        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(";"))
                        .unwrap_or_default();
                    let sigma      = h["sigma_hits"].as_array()
                        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(";"))
                        .unwrap_or_default();
                    let agent_s    = h["agent_s_rule_id"].as_str().unwrap_or("-");
                    let sensor     = h["sensor_id"].as_str().unwrap_or("-");

                    csv.push_str(&format!("{},{},{},{},{},{},{},{},{},{},{:.1},{},{},{},{},{},{},{}\n",
                        csv_field(&fmt_ts(ts)),
                        csv_field(cid),
                        csv_field(src_ip),
                        csv_field(src_host),
                        csv_field(src_ctry),
                        csv_field(dst_ip),
                        csv_field(dst_host),
                        csv_field(dst_domain),
                        csv_field(dst_ctry),
                        csv_field(severity),
                        score,
                        threat,
                        corroborate,
                        csv_field(cor_status),
                        csv_field(&tags),
                        csv_field(&sigma),
                        csv_field(agent_s),
                        csv_field(sensor),
                    ));
                }
            }

            csv.push_str("\nTOP SOURCE IPs\n");
            csv.push_str("IP,Alert Count\n");
            if let Some(ips) = report["top_source_ips"].as_array() {
                for ip in ips {
                    csv.push_str(&format!("{},{}\n",
                        csv_field(ip["ip"].as_str().unwrap_or("-")),
                        ip["count"].as_u64().unwrap_or(0),
                    ));
                }
            }

            csv.push_str("\nSEVERITY BREAKDOWN\n");
            csv.push_str("Severity,Count\n");
            if let Some(obj) = report["severity_breakdown"].as_object() {
                for (sev, cnt) in obj {
                    csv.push_str(&format!("{},{}\n",
                        csv_field(sev),
                        cnt.as_u64().unwrap_or(0),
                    ));
                }
            }

            axum::response::Response::builder()
                .header("content-type", "text/csv; charset=utf-8")
                .header("content-disposition",
                    "attachment; filename=\"ndr-report.csv\"")
                .body(axum::body::Body::from(csv))
                .unwrap()
        }

        "pdf" => {
            let hits_rows = report["recent_hits"].as_array()
                .map(|hits| hits.iter().map(|h| format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td>\
                     <td>{}</td><td>{:.0}</td><td>{}</td></tr>",
                    h["timestamp"].as_u64().unwrap_or(0),
                    h["src_ip"].as_str().unwrap_or("-"),
                    h["dst_ip"].as_str().unwrap_or("-"),
                    h["severity"].as_str().unwrap_or("-"),
                    h["score"].as_f64().unwrap_or(0.0),
                    h["sigma_hits"].as_array()
                        .map(|a| a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>().join(", "))
                        .unwrap_or_default(),
                )).collect::<Vec<_>>().join(""))
                .unwrap_or_default();

            let ip_rows = report["top_source_ips"].as_array()
                .map(|ips| ips.iter().map(|ip| format!(
                    "<tr><td>{}</td><td>{}</td></tr>",
                    ip["ip"].as_str().unwrap_or("-"),
                    ip["count"].as_u64().unwrap_or(0),
                )).collect::<Vec<_>>().join(""))
                .unwrap_or_default();

            let threat_rows = report["threat_intel_hits"].as_array()
                .map(|ti| ti.iter().map(|t| format!(
                    "<tr><td style='color:red'>{}</td>\
                     <td>{}</td><td>{}</td></tr>",
                    t["src_ip"].as_str().unwrap_or("-"),
                    t["dst_ip"].as_str().unwrap_or("-"),
                    t["hits"].as_u64().unwrap_or(0),
                )).collect::<Vec<_>>().join(""))
                .unwrap_or_default();

            let rules_rows = rules.iter().map(|r| format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                r["id"].as_str().unwrap_or("-"),
                r["title"].as_str().unwrap_or("-"),
                r["severity"].as_str().unwrap_or("-"),
                r["conditions"].as_u64().unwrap_or(0),
            )).collect::<Vec<_>>().join("");

            let html = format!(r#"<!DOCTYPE html>
<html>
<head>
<title>NDR Security Report</title>
<style>
body{{font-family:Arial,sans-serif;margin:40px;color:#333}}
h1{{color:#1a1a2e;border-bottom:3px solid #69f6b8;padding-bottom:10px}}
h2{{color:#16213e;margin-top:30px}}
table{{width:100%;border-collapse:collapse;margin:15px 0}}
th{{background:#1a1a2e;color:#69f6b8;padding:10px;text-align:left}}
td{{padding:8px 10px;border-bottom:1px solid #ddd}}
tr:nth-child(even){{background:#f9f9f9}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin:20px 0}}
.card{{background:#f0f0f0;padding:15px;border-radius:8px;text-align:center}}
.val{{font-size:28px;font-weight:bold;color:#1a1a2e}}
.lbl{{font-size:12px;color:#666;text-transform:uppercase}}
@media print{{button{{display:none}}}}
</style>
</head>
<body>
<button onclick="window.print()"
  style="background:#69f6b8;border:none;padding:10px 20px;
  border-radius:5px;cursor:pointer;font-weight:bold;margin-bottom:20px">
  Print / Save as PDF
</button>
<h1>NDR Security Report</h1>
<p><strong>Generated:</strong> {}</p>
<p><strong>Time Range:</strong> Last {} hours</p>
<h2>Summary</h2>
<div class="grid">
  <div class="card"><div class="val">{}</div><div class="lbl">Total Events</div></div>
  <div class="card"><div class="val">{}</div><div class="lbl">Hits</div></div>
  <div class="card"><div class="val">{}</div><div class="lbl">Active Rules</div></div>
  <div class="card"><div class="val">{}</div><div class="lbl">Agent-Z Events</div></div>
  <div class="card"><div class="val">{}</div><div class="lbl">Agent-S Events</div></div>
  <div class="card"><div class="val">{}</div><div class="lbl">Events/Hour</div></div>
</div>
<h2>Recent Hits</h2>
<table>
  <tr><th>Timestamp</th><th>Src IP</th><th>Dst IP</th>
      <th>Severity</th><th>Score</th><th>SIGMA</th></tr>
  {}
</table>
<h2>Top Source IPs</h2>
<table><tr><th>IP</th><th>Count</th></tr>{}</table>
<h2>Threat Intel Hits</h2>
<table><tr><th>Src IP</th><th>Dst IP</th><th>Hits</th></tr>{}</table>
<h2>Active SIGMA Rules</h2>
<table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Conditions</th></tr>{}</table>
</body></html>"#,
                chrono::Utc::now().to_rfc3339(),
                hours,
                report["summary"]["total_events"],
                report["summary"]["total_hits"],
                report["summary"]["active_rules"],
                report["summary"]["agent_z_events"],
                report["summary"]["agent_s_events"],
                report["summary"]["events_1h"],
                hits_rows,
                ip_rows,
                threat_rows,
                rules_rows,
            );

            axum::response::Response::builder()
                .header("content-type", "text/html")
                .header("content-disposition",
                    "attachment; filename=\"ndr-report.html\"")
                .body(axum::body::Body::from(html))
                .unwrap()
        }

        "xlsx" => {
            let assets = state.ch_storage.get_assets_by_tenant(&tenant_id).await.unwrap_or_default();
            match build_xlsx_report(&report, &assets) {
                Ok(bytes) => axum::response::Response::builder()
                    .header("content-type",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                    .header("content-disposition",
                        "attachment; filename=\"ndr-report.xlsx\"")
                    .body(axum::body::Body::from(bytes))
                    .unwrap(),
                Err(e) => {
                    warn!("XLSX export failed: {e}");
                    axum::response::Response::builder()
                        .status(500)
                        .body(axum::body::Body::from(format!("XLSX error: {e}")))
                        .unwrap()
                }
            }
        }

        _ => {
            axum::response::Response::builder()
                .header("content-type", "application/json")
                .header("content-disposition",
                    "attachment; filename=\"ndr-report.json\"")
                .body(axum::body::Body::from(report.to_string()))
                .unwrap()
        }
    }
}

pub async fn export_logs(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();

    let format = params.get("format").map(|s: &String| s.as_str()).unwrap_or("csv");
    let hours: u32 = params.get("hours").and_then(|h: &String| h.parse().ok()).unwrap_or(24);
    let limit: u64 = 10000; // Hard limit to prevent crashing

    let events = state.ch_storage.export_events_by_tenant(&tenant_id, hours, limit, &sensor_ids).await.unwrap_or_default();
    
    match format {
        "csv" => {
            let mut csv = String::new();
            csv.push_str("Timestamp,Source IP,Dest IP,Protocol,Source,Event Type\n");
            
            for event in events {
                csv.push_str(&format!("{},{},{},{},{},{}\n",
                    event["timestamp"].as_u64().unwrap_or(0),
                    event["src_ip"].as_str().unwrap_or("-"),
                    event["dst_ip"].as_str().unwrap_or("-"),
                    event["proto"].as_str().unwrap_or("-"),
                    event["source"].as_str().unwrap_or("-"),
                    event["event_type"].as_str().unwrap_or("-"),
                ));
            }
            
            axum::response::Response::builder()
                .header("content-type", "text/csv")
                .header("content-disposition", format!("attachment; filename=\"ndr-logs-{}h.csv\"", hours))
                .body(axum::body::Body::from(csv))
                .unwrap()
        }
        "pdf" | "html" => {
            let rows = events.iter().map(|event| format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                event["timestamp"].as_u64().unwrap_or(0),
                event["src_ip"].as_str().unwrap_or("-"),
                event["dst_ip"].as_str().unwrap_or("-"),
                event["proto"].as_str().unwrap_or("-"),
                event["source"].as_str().unwrap_or("-"),
                event["event_type"].as_str().unwrap_or("-")
            )).collect::<Vec<_>>().join("");
            
            let html = format!(r#"<!DOCTYPE html>
<html>
<head>
<title>NDR Network Logs</title>
<style>
body{{font-family:Arial,sans-serif;margin:40px;color:#333}}
h1{{color:#1a1a2e;border-bottom:3px solid #69f6b8;padding-bottom:10px}}
table{{width:100%;border-collapse:collapse;margin:15px 0}}
th{{background:#1a1a2e;color:#69f6b8;padding:10px;text-align:left}}
td{{padding:8px 10px;border-bottom:1px solid #ddd}}
tr:nth-child(even){{background:#f9f9f9}}
@media print{{button{{display:none}}}}
</style>
</head>
<body>
<button onclick="window.print()"
  style="background:#69f6b8;border:none;padding:10px 20px;
  border-radius:5px;cursor:pointer;font-weight:bold;margin-bottom:20px">
  Print / Save as PDF
</button>
<h1>NDR Network Logs</h1>
<p><strong>Generated:</strong> {}</p>
<p><strong>Time Range:</strong> Last {} hours</p>
<p><strong>Total Logs (Max 10,000):</strong> {}</p>
<table>
  <tr><th>Timestamp</th><th>Source IP</th><th>Dest IP</th><th>Protocol</th><th>Source</th><th>Event Type</th></tr>
  {}
</table>
</body></html>"#,
                chrono::Utc::now().to_rfc3339(),
                hours,
                events.len(),
                rows
            );
            
            axum::response::Response::builder()
                .header("content-type", "text/html")
                .header("content-disposition", format!("attachment; filename=\"ndr-logs-{}h.html\"", hours))
                .body(axum::body::Body::from(html))
                .unwrap()
        }
        _ => {
            // json format
            let json_body = serde_json::json!({
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "time_range_hours": hours,
                "logs_count": events.len(),
                "logs": events
            });
            
            axum::response::Response::builder()
                .header("content-type", "application/json")
                .header("content-disposition", format!("attachment; filename=\"ndr-logs-{}h.json\"", hours))
                .body(axum::body::Body::from(json_body.to_string()))
                .unwrap()
        }
    }
}



// GET /api/soar/integrations
#[cfg(feature = "soar")]
pub async fn get_integrations(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    match state.ch_storage.get_integrations_by_tenant(&tenant_id).await {
        Ok(integrations) => Json(json!({
            "status": "ok",
            "integrations": integrations
        })),
        Err(_) => Json(json!({
            "status": "ok",
            "integrations": []
        }))
    }
}

// POST /api/soar/integrations
#[cfg(feature = "soar")]
pub async fn save_integration(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let id = format!("int-{}",
        chrono::Utc::now().timestamp());
    let name = payload["name"]
        .as_str().unwrap_or("").to_string();
    let int_type = payload["type"]
        .as_str().unwrap_or("").to_string();
    let config = payload["config"].to_string();

    if name.is_empty() || int_type.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "name and type required"
        }));
    }

    // Test connection before saving
    let test_result = test_integration(
        &int_type, &config).await;

    match state.ch_storage.save_integration(
        &id, &name, &int_type, &config, &tenant_id
    ).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "id": id,
            "test": test_result,
            "message": format!(
                "{} integration saved!", name
            )
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// Test integration connection
async fn test_integration(
    int_type: &str,
    config: &str
) -> String {
    let config: Value = serde_json::from_str(config)
        .unwrap_or(json!({}));
    
    match int_type {
        "slack" | "teams" | "discord" | "webhook" => {
            let url = config["webhook_url"]
                .as_str().unwrap_or("");
            if url.is_empty() {
                return "No URL configured".to_string();
            }
            let test_msg = json!({
                "text": "✅ NDR Stack test message"
            });
            match HTTP_CLIENT
                .post(url)
                .json(&test_msg)
                .timeout(std::time::Duration::from_secs(5))
                .send().await {
                Ok(_) => "✅ Connected".to_string(),
                Err(e) => format!("❌ {}", e)
            }
        }
        "pagerduty" => {
            let key = config["routing_key"]
                .as_str().unwrap_or("");
            if key.is_empty() {
                return "No routing key".to_string();
            }
            "✅ PagerDuty configured".to_string()
        }
        "telegram" => {
            let token = config["bot_token"]
                .as_str().unwrap_or("");
            let chat_id = config["chat_id"]
                .as_str().unwrap_or("");
            if token.is_empty() || chat_id.is_empty() {
                return "Missing token or chat_id".to_string();
            }
            let url = format!(
                "https://api.telegram.org/bot{}/sendMessage",
                token
            );
            let msg = json!({
                "chat_id": chat_id,
                "text": "✅ NDR Stack connected!"
            });
            match HTTP_CLIENT
                .post(&url)
                .json(&msg)
                .timeout(std::time::Duration::from_secs(5))
                .send().await {
                Ok(_) => "✅ Telegram connected".to_string(),
                Err(e) => format!("❌ {}", e)
            }
        }
        "jira" => {
    let url = config["url"].as_str().unwrap_or("");
    let email = config["email"].as_str().unwrap_or("");
    let token = config["token"].as_str().unwrap_or("");
    let project = config["project_key"].as_str().unwrap_or("");
    if url.is_empty() || email.is_empty() || token.is_empty() {
        return "Missing Jira config".to_string();
    }
    let test_url = format!("{}/rest/api/3/project/{}", url, project);
    let creds = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", email, token));
    match HTTP_CLIENT
        .get(&test_url)
        .header("Authorization", format!("Basic {}", creds))
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(5))
        .send().await {
        Ok(r) if r.status().is_success() =>
            "✅ Jira connected".to_string(),
        Ok(r) => format!("❌ Jira error: {}", r.status()),
        Err(e) => format!("❌ {}", e)
    }
}
        "smtp" => {
            let host = config["smtp_host"].as_str().unwrap_or("");
            let port = config["smtp_port"].as_u64().unwrap_or(587) as u16;
            if host.is_empty() {
                return "No SMTP host configured".to_string();
            }
            match tokio::net::TcpStream::connect((host, port)).await {
                Ok(_)  => format!("✅ SMTP reachable ({}:{})", host, port),
                Err(e) => format!("❌ SMTP connect failed: {}", e),
            }
        }
        fw @ ("pfsense" | "fortinet" | "panos" | "opnsense") => {
            let host = config["host"].as_str().unwrap_or("");
            let api_key = config["api_key"].as_str().unwrap_or("");
            if host.is_empty() {
                return format!("No host configured for {}", fw);
            }
            if api_key.is_empty() {
                return format!("No API key configured for {}", fw);
            }
            match tokio::net::TcpStream::connect((host, 443u16)).await {
                Ok(_)  => format!("✅ {} reachable at {}", fw, host),
                Err(_) => match tokio::net::TcpStream::connect((host, 80u16)).await {
                    Ok(_)  => format!("✅ {} reachable at {}:80", fw, host),
                    Err(e) => format!("❌ {} unreachable: {}", fw, e),
                }
            }
        }
        "unifi" => {
            let host = config["host"].as_str().unwrap_or("");
            if host.is_empty() {
                return "No host configured for UniFi".to_string();
            }
            match reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(5))
                .build()
            {
                Ok(client) => match client.get(format!("{}/", host)).send().await {
                    Ok(_)  => format!("✅ UniFi reachable at {}", host),
                    Err(e) => format!("❌ UniFi unreachable: {}", e),
                },
                Err(e) => format!("❌ Client error: {}", e),
            }
        }
        sw @ ("cisco" | "aruba" | "snmp") => {
            let host = config["host"].as_str().unwrap_or("");
            if host.is_empty() {
                return format!("No host configured for {}", sw);
            }
            let port: u16 = if sw == "snmp" { 161 } else { 22 };
            match tokio::net::TcpStream::connect((host, port)).await {
                Ok(_)  => format!("✅ {} reachable at {}:{}", sw, host, port),
                Err(e) => format!("❌ {} unreachable ({}:{}): {}", sw, host, port, e),
            }
        }
        "aws_sg" => {
            let sg_id  = config["sg_id"].as_str().unwrap_or("");
            let key_id = config["aws_access_key_id"].as_str().unwrap_or("");
            let secret = config["aws_secret_access_key"].as_str().unwrap_or("");
            if sg_id.is_empty() || key_id.is_empty() || secret.is_empty() {
                return "❌ Missing sg_id, aws_access_key_id, or aws_secret_access_key".to_string();
            }
            "✅ AWS SG config present (credentials not validated at test time)".to_string()
        }
        "azure_nsg" => {
            let rg  = config["resource_group"].as_str().unwrap_or("");
            let nsg = config["nsg_name"].as_str().unwrap_or("");
            if rg.is_empty() || nsg.is_empty() {
                return "❌ Missing resource_group or nsg_name".to_string();
            }
            "✅ Azure NSG config present (az CLI used at enforcement time)".to_string()
        }
        "gcp_vpc" => {
            let project = config["project_id"].as_str().unwrap_or("");
            let network = config["network"].as_str().unwrap_or("");
            if project.is_empty() || network.is_empty() {
                return "❌ Missing project_id or network".to_string();
            }
            "✅ GCP VPC config present (gcloud CLI used at enforcement time)".to_string()
        }
        _ => "Unknown integration".to_string()
    }
}

// POST /api/soar/integrations/test
#[cfg(feature = "soar")]
pub async fn test_integration_endpoint(
    State(_state): State<AppState>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let int_type = payload["type"]
        .as_str().unwrap_or("").to_string();
    let config = payload["config"].to_string();
    
    let result = test_integration(&int_type, &config).await;
    Json(json!({
        "status": if result.starts_with("✅") 
            { "ok" } else { "error" },
        "message": result
    }))
}

// POST /api/soar/integrations/toggle
#[cfg(feature = "soar")]
pub async fn toggle_integration(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let id = payload["id"]
        .as_str().unwrap_or("").to_string();
    let enabled = payload["enabled"]
        .as_bool().unwrap_or(false);
    
    match state.ch_storage
        .toggle_integration(&id, enabled, &tenant_id).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Integration updated"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// DELETE /api/soar/integrations
#[cfg(feature = "soar")]
pub async fn delete_integration(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers).map(|c| c.tenant_id).unwrap_or_else(|| "default".to_string());
    let id = payload["id"]
        .as_str().unwrap_or("").to_string();

    match state.ch_storage
        .delete_integration(&id, &tenant_id).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Integration deleted"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

#[cfg(feature = "soar")]
pub async fn update_integration(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = extract_claims(&headers)
        .map(|c| c.tenant_id)
        .unwrap_or_else(|| "default".to_string());

    let name = payload["name"].as_str().unwrap_or("").to_string();
    let int_type = payload["type"].as_str().unwrap_or("").to_string();
    let config = payload["config"].to_string();

    if name.is_empty() || int_type.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "name and type required"
        }));
    }

    match state.ch_storage
        .update_integration(&id, &name, &int_type, &config, &tenant_id)
        .await
    {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": format!("{} integration updated!", name)
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    }
}


//severity
pub async fn get_severity(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();
    match state.ch_storage.get_severity_by_tenant(&tenant_id, &sensor_ids, 0).await {
        Ok(data) => Json(data),
        Err(e) => {
            tracing::warn!("Severity query error: {}", e);
            Json(json!({
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }))
        }
    }
}

#[derive(serde::Deserialize)]
pub struct ClientErrorPayload {
    pub message: String,
    #[serde(default)]
    pub stack: String,
    #[serde(default)]
    pub url: String,
}

// POST /api/client-errors — real frontend error capture. Intentionally
// works without a valid session (an error on the login page or an expired
// token is exactly the kind of thing that needs to be reported), and never
// fails the caller's request even if storage itself is unreachable — this
// exists so errors are seen somewhere, not to become a second thing that
// can break. Payload sizes are capped so a runaway loop can't fill the table.
pub async fn report_client_error(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<ClientErrorPayload>,
) -> Json<Value> {
    let claims = extract_claims(&headers);
    let username  = claims.as_ref().map(|c| c.sub.clone()).unwrap_or_default();
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_default();
    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();

    let truncate = |s: &str, n: usize| s.chars().take(n).collect::<String>();
    let message = truncate(&payload.message, 2000);
    let stack   = truncate(&payload.stack, 8000);
    let url     = truncate(&payload.url, 500);

    if let Err(e) = state.ch_storage.insert_client_error(&message, &stack, &url, &username, &tenant_id, &user_agent).await {
        tracing::warn!("Failed to persist client error report: {}", e);
    }
    Json(json!({ "status": "ok" }))
}

// GET /api/admin/client-errors — read path for the errors report_client_error
// captures. Deliberately at a different path than the public POST endpoint
// above (that path is exempt from auth in the auth_middleware public list,
// so reusing it here would leak every user's error reports/stack traces to
// anyone unauthenticated). Super-admin only.
pub async fn list_client_errors(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }
    match state.ch_storage.list_client_errors(200).await {
        Ok(errors) => Json(json!({ "errors": errors })),
        Err(e) => Json(json!({ "error": e.to_string() })),
    }
}

// GET /api/admin/severity-all-tenants — platform-wide severity totals for
// the Super Admin Overview (sums every tenant's own hits, not just the
// caller's own tenant). Super-admin only.
pub async fn get_severity_all_tenants(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }
    match state.ch_storage.get_severity_all_tenants().await {
        Ok(data) => Json(data),
        Err(e) => {
            tracing::warn!("All-tenant severity query error: {}", e);
            Json(json!({
                "critical": 0, "high": 0, "medium": 0, "low": 0,
                "tenants_total": 0, "tenants_reporting": 0
            }))
        }
    }
}

// GET /api/announcements
pub async fn get_announcements_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }

    match state.ch_storage.get_announcements().await {
        Ok(announcements) => Json(json!({
            "status": "ok",
            "announcements": announcements
        })),
        Err(e) => Json(json!({
            "status": "error",
            "announcements": [],
            "message": e.to_string()
        }))
    }
}

// GET /api/announcements/active
pub async fn get_active_announcements_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({
            "status": "error",
            "announcements": [],
            "message": "Unauthorized"
        })),
    };

    match state.ch_storage
        .get_active_announcements(&claims.role, &claims.tenant_id, &claims.sub)
        .await {
        Ok(announcements) => Json(json!({
            "status": "ok",
            "announcements": announcements
        })),
        Err(e) => Json(json!({
            "status": "error",
            "announcements": [],
            "message": e.to_string()
        }))
    }
}

// POST /api/announcements/:id/read
pub async fn mark_announcement_read_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({
            "status": "error",
            "message": "Unauthorized"
        })),
    };

    match state.ch_storage.mark_announcement_read(&id, &claims.sub).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Announcement marked as read"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// POST /api/announcements
pub async fn create_announcement_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match require_super_admin(&headers) {
        Ok(claims) => claims,
        Err(response) => return response,
    };

    let title = payload["title"].as_str().unwrap_or("").trim().to_string();
    let message = payload["message"].as_str().unwrap_or("").trim().to_string();
    let announcement_type = payload["announcement_type"]
        .as_str()
        .or_else(|| payload["type"].as_str())
        .unwrap_or("info")
        .trim()
        .to_string();
    let status = announcement_status_from_payload(&payload);
    let (audience, target_roles, target_tenants) = announcement_targets_from_payload(&payload);
    let start_at = payload["start_at"].as_str()
        .or_else(|| payload["starts_at"].as_str());
    let end_at = payload["end_at"].as_str()
        .or_else(|| payload["ends_at"].as_str());

    if title.is_empty() || message.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Title and message are required"
        }));
    }
    if !["draft", "active", "inactive"].contains(&status.as_str()) {
        return Json(json!({
            "status": "error",
            "message": "Invalid status"
        }));
    }

    let id = uuid::Uuid::new_v4().to_string();
    match state.ch_storage.create_announcement(
        &id,
        &title,
        &message,
        &announcement_type,
        &audience,
        &status,
        &target_roles,
        &target_tenants,
        start_at,
        end_at,
        &claims.sub,
    ).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "id": id,
            "message": "Announcement created"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// PUT /api/announcements/:id
pub async fn update_announcement_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }

    let title = payload["title"].as_str().unwrap_or("").trim().to_string();
    let message = payload["message"].as_str().unwrap_or("").trim().to_string();
    let announcement_type = payload["announcement_type"]
        .as_str()
        .or_else(|| payload["type"].as_str())
        .unwrap_or("info")
        .trim()
        .to_string();
    let status = announcement_status_from_payload(&payload);
    let (audience, target_roles, target_tenants) = announcement_targets_from_payload(&payload);
    let start_at = payload["start_at"].as_str()
        .or_else(|| payload["starts_at"].as_str());
    let end_at = payload["end_at"].as_str()
        .or_else(|| payload["ends_at"].as_str());

    if title.is_empty() || message.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Title and message are required"
        }));
    }
    if !["draft", "active", "inactive"].contains(&status.as_str()) {
        return Json(json!({
            "status": "error",
            "message": "Invalid status"
        }));
    }

    match state.ch_storage.update_announcement(
        &id,
        &title,
        &message,
        &announcement_type,
        &audience,
        &status,
        &target_roles,
        &target_tenants,
        start_at,
        end_at,
    ).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Announcement updated"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

// DELETE /api/announcements/:id
pub async fn delete_announcement_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }

    match state.ch_storage.delete_announcement(&id).await {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Announcement deleted"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        }))
    }
}

pub async fn get_engines(
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }

    let output = std::process::Command::new("docker")
        .args(["ps",
            "--filter", "name=ndr-engine",
            "--format", "{{.Names}},{{.Status}},{{.RunningFor}}"])
        .output()
        .unwrap_or_else(|_| std::process::Output {
            status: <std::process::ExitStatus as ExitStatusDefault>::default(),
            stdout: vec![],
            stderr: vec![],
        });

    let engines: Vec<Value> = String::from_utf8_lossy(
        &output.stdout
    ).lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            let parts: Vec<&str> = line.splitn(3, ',').collect();
            json!({
                "name":    parts.get(0).unwrap_or(&""),
                "status":  parts.get(1).unwrap_or(&""),
                "running": parts.get(2).unwrap_or(&"")
            })
        }).collect();

    Json(json!({
        "engines": engines,
        "count": engines.len()
    }))
}

pub async fn scale_engines(
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    if let Err(response) = require_super_admin(&headers) {
        return response;
    }

    let action = payload["action"].as_str().unwrap_or("up");
    let engine_name = payload["engine"].as_str().unwrap_or("");

    match action {
        "up" => {
            // ── Count currently running ndr-engine containers ─────────────────
            let count_out = std::process::Command::new("docker")
                .args(["ps", "-q", "--filter", "name=ndr-engine"])
                .output()
                .unwrap_or_else(|_| std::process::Output {
                    status: <std::process::ExitStatus as ExitStatusDefault>::default(),
                    stdout: vec![],
                    stderr: vec![],
                });
            let count = String::from_utf8_lossy(&count_out.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .count();
            let new_instance_id = count + 1;
            let new_name = format!("ndr-engine-{}", new_instance_id);

            tracing::info!("Scaling up: {} engines running → starting {}", count, new_name);

            // ── Step 1: Clone any running engine and start new one ────────────
            let start_script = format!(r#"set -e
ENGINE=$(docker ps --format '{{{{.Names}}}}' --filter "name=ndr-engine" | head -n 1)
if [ -z "$ENGINE" ]; then echo "No running engine found as blueprint" >&2; exit 1; fi
NEW_ENGINE="{0}"
NEW_INSTANCE_ID="{1}"
IMAGE=$(docker inspect --format '{{{{.Config.Image}}}}' "$ENGINE")
# Each network on its own line — docker run only accepts one --network flag
NETWORKS=$(docker inspect --format '{{{{range $k, $v := .NetworkSettings.Networks}}}}{{{{$k}}}}{{{{"\n"}}}}{{{{end}}}}' "$ENGINE" | grep -v '^$')
PRIMARY_NET=$(echo "$NETWORKS" | head -n 1)
EXTRA_NETS=$(echo "$NETWORKS" | tail -n +2)
BINDS=$(docker inspect --format '{{{{range .HostConfig.Binds}}}}-v {{{{.}}}} {{{{end}}}}' "$ENGINE")
ENVS=$(docker inspect --format '{{{{range .Config.Env}}}}-e {{{{.}}}} {{{{end}}}}' "$ENGINE" | sed "s/INSTANCE_ID=[0-9]*/INSTANCE_ID=$NEW_INSTANCE_ID/")
# Remove any stopped container with the same name to avoid conflicts
docker rm -f "$NEW_ENGINE" 2>/dev/null || true
eval docker run -d --name "$NEW_ENGINE" --privileged --network "$PRIMARY_NET" $BINDS $ENVS "$IMAGE"
# Connect to any additional networks
for net in $EXTRA_NETS; do
    [ -n "$net" ] && docker network connect "$net" "$NEW_ENGINE" || true
done
"#, new_name, new_instance_id);

            tracing::debug!("Start script:\n{}", start_script);
            let engine_out = std::process::Command::new("bash")
                .args(["-c", &start_script])
                .output();

            match &engine_out {
                Ok(o) if o.status.success() => {
                    tracing::info!("✅ Engine {} started (ID: {})", new_name, String::from_utf8_lossy(&o.stdout).trim());
                }
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr);
                    tracing::error!("❌ Failed to start engine: {}", err);
                    return Json(json!({ "status": "error", "message": format!("Engine start failed: {}", err) }));
                }
                Err(e) => {
                    tracing::error!("❌ OS error: {}", e);
                    return Json(json!({ "status": "error", "message": e.to_string() }));
                }
            }

            // ── Step 2: Scale Kafka partitions up to match new engine count ───
            tracing::info!("Scaling Kafka ndr-events partitions to {}", new_instance_id);
            let kafka_out = std::process::Command::new("docker")
                .args([
                    "exec", "kafka1",
                    "/opt/kafka/bin/kafka-topics.sh",
                    "--bootstrap-server", "localhost:9092",
                    "--alter", "--topic", "ndr-events",
                    "--partitions", &new_instance_id.to_string(),
                ])
                .output();
            let kafka_msg = match &kafka_out {
                Ok(o) if o.status.success() => {
                    tracing::info!("✅ Kafka partitions → {}", new_instance_id);
                    format!("Kafka partitions set to {}", new_instance_id)
                }
                Ok(o) => {
                    // Kafka warns if partition count already >= requested; not fatal
                    let warn = String::from_utf8_lossy(&o.stderr);
                    tracing::warn!("⚠️ Kafka alter: {}", warn);
                    format!("Kafka warning: {}", warn)
                }
                Err(e) => { tracing::error!("❌ Kafka exec error: {}", e); e.to_string() }
            };

            // ── Step 3: Inject new server into both Nginx upstreams & reload ────
            let install_dir = std::env::var("INSTALL_DIR").unwrap_or_else(|_| ".".to_string());
            let nginx_conf = format!("{}/config/nginx/nginx.conf", install_dir);
            let api_line = format!("        server {}:3000 max_fails=3 fail_timeout=30s;", new_name);
            let ws_line  = format!("        server {}:3000;", new_name);
            tracing::info!("Adding {} to Nginx upstreams: {}", new_name, nginx_conf);

            let nginx_up_script = format!(r#"set -e
CONF="{0}"
API_LINE="{1}"
WS_LINE="{2}"
if ! grep -qF "$API_LINE" "$CONF"; then
    sed -i "/# ENGINES_MARKER/i\\$API_LINE" "$CONF"
    echo "Added $API_LINE to ndr_engines"
else
    echo "ndr_engines: already present"
fi
if ! grep -qF "$WS_LINE" "$CONF"; then
    sed -i "/# WS_ENGINES_MARKER/i\\$WS_LINE" "$CONF"
    echo "Added $WS_LINE to ws_engines"
else
    echo "ws_engines: already present"
fi
docker exec ndr-nginx nginx -s reload && echo "Nginx reloaded"
"#, nginx_conf, api_line, ws_line);

            let nginx_out = std::process::Command::new("bash")
                .args(["-c", &nginx_up_script])
                .output();
            let nginx_msg = match &nginx_out {
                Ok(o) if o.status.success() => {
                    let msg = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    tracing::info!("✅ Nginx: {}", msg);
                    msg
                }
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr);
                    tracing::error!("❌ Nginx update failed: {}", err);
                    format!("Nginx error: {}", err)
                }
                Err(e) => { tracing::error!("❌ Nginx OS error: {}", e); e.to_string() }
            };

            Json(json!({
                "status": "ok",
                "message": format!("Engine {} started!", new_name),
                "engine": new_name,
                "kafka": kafka_msg,
                "nginx": nginx_msg
            }))
        }

        "down" => {
            if engine_name.is_empty() {
                return Json(json!({ "status": "error", "message": "Engine name required" }));
            }

            // ── Step 1: Remove from both Nginx upstreams BEFORE stopping ─────────
            let install_dir = std::env::var("INSTALL_DIR").unwrap_or_else(|_| ".".to_string());
            let nginx_conf = format!("{}/config/nginx/nginx.conf", install_dir);
            let api_remove = format!("        server {}:3000 max_fails=3 fail_timeout=30s;", engine_name);
            let ws_remove  = format!("        server {}:3000;", engine_name);
            tracing::info!("Removing {} from Nginx upstreams BEFORE stopping container", engine_name);

            let nginx_down_script = format!(r#"set -e
CONF="{0}"
API_ESC=$(printf '%s\n' "{1}" | sed 's/[\/&[\.*^$]/\\&/g')
WS_ESC=$(printf '%s\n' "{2}" | sed 's/[\/&[\.*^$]/\\&/g')
sed -i "/$API_ESC/d" "$CONF"
sed -i "/$WS_ESC/d" "$CONF"
echo "Removed {1} and {2}"
docker exec ndr-nginx nginx -s reload && echo "Nginx reloaded"
"#, nginx_conf, api_remove, ws_remove);

            let nginx_out = std::process::Command::new("bash")
                .args(["-c", &nginx_down_script])
                .output();
            let nginx_msg = match &nginx_out {
                Ok(o) if o.status.success() => {
                    let msg = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    tracing::info!("✅ Nginx drained: {}", msg);
                    msg
                }
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr);
                    tracing::warn!("⚠️ Nginx down warning: {}", err);
                    format!("Nginx warning: {}", err)
                }
                Err(e) => e.to_string()
            };

            // ── Step 2: Brief drain wait — let active connections finish ──────
            tracing::info!("Waiting 2s for active connections to drain from {}", engine_name);
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            // ── Step 3: Stop the container safely ─────────────────────────────
            tracing::info!("Stopping engine container: {}", engine_name);
            let stop_out = std::process::Command::new("docker")
                .args(["stop", engine_name])
                .output();
            match &stop_out {
                Ok(o) if o.status.success() => tracing::info!("✅ Engine {} stopped", engine_name),
                Ok(o) => tracing::error!("❌ Stop failed: {}", String::from_utf8_lossy(&o.stderr)),
                Err(e) => tracing::error!("❌ OS error stopping: {}", e),
            }

            Json(json!({
                "status": "ok",
                "message": format!("{} stopped!", engine_name),
                "engine": engine_name,
                "nginx": nginx_msg,
                "note": "Nginx drained before container stop — zero dropped requests"
            }))
        }

        _ => Json(json!({ "status": "error", "message": "Unknown action" }))
    }
}

//jira ticket
#[cfg(feature = "soar")]
pub async fn get_jira_tickets(
    Json(payload): Json<Value>,
) -> Json<Value> {
    let url = payload["url"].as_str().unwrap_or("");
    let email = payload["email"].as_str().unwrap_or("");
    let token = payload["token"].as_str().unwrap_or("");
    let project = payload["project_key"]
        .as_str().unwrap_or("");

    if url.is_empty() || email.is_empty() {
        return Json(json!({
            "status": "error",
            "tickets": []
        }));
    }

    let creds = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", email, token));
    
    let jql_url = format!(
        "{}/rest/api/3/search?jql=project={}+ORDER+BY+created+DESC&maxResults=20",
        url, project
    );

    match HTTP_CLIENT
        .get(&jql_url)
        .header("Authorization", format!("Basic {}", creds))
        .header("Accept", "application/json")
        .timeout(Duration::from_secs(10))
        .send().await {
        Ok(r) => {
            let data: Value = r.json().await
                .unwrap_or(json!({}));
            let issues = data["issues"]
                .as_array()
                .map(|issues| issues.iter().map(|i| {
                    let fields = &i["fields"];
                    json!({
                        "id": i["id"],
                        "key": i["key"],
                        "summary": fields["summary"],
                        "status": fields["status"]["name"],
                        "priority": fields["priority"]["name"],
                        "created": fields["created"],
                        "url": format!("{}/browse/{}", 
                            url, i["key"].as_str().unwrap_or(""))
                    })
                }).collect::<Vec<_>>())
                .unwrap_or_default();

            Json(json!({
                "status": "ok",
                "tickets": issues
            }))
        }
        Err(e) => Json(json!({
            "status": "error",
            "tickets": [],
            "message": e.to_string()
        }))
    }
}


// ── Support Messages ──────────────────────────────────────────────────────────

fn can_manage_support_message(claims: &AuthClaims, tenant_id: &str, forwarded: u8) -> bool {
    if claims.role == "super_admin" || claims.role == "admin" {
        return forwarded == 1 || tenant_id == "default";
    }
    if claims.role == "tenant_admin" {
        return claims.tenant_id == tenant_id;
    }
    false
}

pub async fn get_support_messages(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({
            "status": "error",
            "message": "Unauthorized",
            "messages": []
        })),
    };

    let result = tokio::time::timeout(Duration::from_secs(8), async {
        if claims.role == "super_admin" || claims.role == "admin" {
            state.ch_storage.get_support_messages_for_super_admin().await
        } else if claims.role == "tenant_admin" {
            state.ch_storage.get_support_messages_for_tenant(&claims.tenant_id).await
        } else {
            state.ch_storage.get_support_messages_for_user(&claims.tenant_id, &claims.sub).await
        }
    }).await;

    match result {
        Ok(Ok(messages)) => Json(json!({
            "status": "ok",
            "messages": messages
        })),
        Ok(Err(e)) => Json(json!({
            "status": "error",
            "message": e.to_string(),
            "messages": []
        })),
        Err(_) => Json(json!({
            "status": "error",
            "message": "Support messages request timed out",
            "messages": []
        })),
    }
}

pub async fn create_support_message(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({
            "status": "error",
            "message": "Unauthorized"
        })),
    };

    let subject = payload["subject"].as_str().unwrap_or("").trim();
    let category = payload["category"].as_str().unwrap_or("General").trim();
    let message = payload["message"].as_str().unwrap_or("").trim();

    if subject.is_empty() || message.is_empty() {
        return Json(json!({
            "status": "error",
            "message": "Subject and message are required"
        }));
    }

    let result = tokio::time::timeout(Duration::from_secs(8), state.ch_storage.create_support_message(
        &claims.tenant_id,
        &claims.sub,
        &claims.role,
        subject,
        if category.is_empty() { "General" } else { category },
        message,
    )).await;

    let result = match result {
        Ok(result) => result,
        Err(_) => return Json(json!({
            "status": "error",
            "message": "Support request timed out"
        })),
    };

    match result {
        Ok(id) => Json(json!({
            "status": "ok",
            "id": id,
            "message": "Support request sent"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    }
}

pub async fn review_support_message(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };

    let scope = match tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.get_support_message_scope(&id)
    ).await {
        Ok(Ok(Some(scope))) => scope,
        Ok(Ok(None)) => return Json(json!({"status": "error", "message": "Support message not found"})),
        Ok(Err(e)) => return Json(json!({"status": "error", "message": e.to_string()})),
        Err(_) => return Json(json!({"status": "error", "message": "Support lookup timed out"})),
    };

    if !can_manage_support_message(&claims, &scope.0, scope.2) {
        return Json(json!({"status": "error", "message": "Forbidden"}));
    }

    let result = tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.update_support_status(&id, "reviewed")
    ).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => return Json(json!({"status": "error", "message": "Support review timed out"})),
    };

    match result {
        Ok(_) => Json(json!({"status": "ok", "message": "Support request marked reviewed"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

pub async fn reply_support_message(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };

    let reply = payload["reply"].as_str().unwrap_or("").trim();
    if reply.is_empty() {
        return Json(json!({"status": "error", "message": "Reply is required"}));
    }

    let scope = match tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.get_support_message_scope(&id)
    ).await {
        Ok(Ok(Some(scope))) => scope,
        Ok(Ok(None)) => return Json(json!({"status": "error", "message": "Support message not found"})),
        Ok(Err(e)) => return Json(json!({"status": "error", "message": e.to_string()})),
        Err(_) => return Json(json!({"status": "error", "message": "Support lookup timed out"})),
    };

    if !can_manage_support_message(&claims, &scope.0, scope.2) {
        return Json(json!({"status": "error", "message": "Forbidden"}));
    }

    let result = tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.reply_support_message(&id, reply, &claims.sub, "replied")
    ).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => return Json(json!({"status": "error", "message": "Support reply timed out"})),
    };

    match result {
        Ok(_) => Json(json!({"status": "ok", "message": "Reply sent"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

pub async fn forward_support_message(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };

    if claims.role != "tenant_admin" {
        return Json(json!({"status": "error", "message": "Only tenant admins can forward support requests"}));
    }

    let scope = match tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.get_support_message_scope(&id)
    ).await {
        Ok(Ok(Some(scope))) => scope,
        Ok(Ok(None)) => return Json(json!({"status": "error", "message": "Support message not found"})),
        Ok(Err(e)) => return Json(json!({"status": "error", "message": e.to_string()})),
        Err(_) => return Json(json!({"status": "error", "message": "Support lookup timed out"})),
    };

    if scope.0 != claims.tenant_id {
        return Json(json!({"status": "error", "message": "Forbidden"}));
    }

    let result = tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.forward_support_message(&id, &claims.sub)
    ).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => return Json(json!({"status": "error", "message": "Support forward timed out"})),
    };

    match result {
        Ok(_) => Json(json!({"status": "ok", "message": "Support request forwarded to super admin"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

pub async fn delete_support_message_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(claims) => claims,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };

    let scope = match tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.get_support_message_scope(&id)
    ).await {
        Ok(Ok(Some(scope))) => scope,
        Ok(Ok(None)) => return Json(json!({"status": "error", "message": "Support message not found"})),
        Ok(Err(e)) => return Json(json!({"status": "error", "message": e.to_string()})),
        Err(_) => return Json(json!({"status": "error", "message": "Support delete timed out"})),
    };

    if !can_manage_support_message(&claims, &scope.0, scope.2) {
        return Json(json!({"status": "error", "message": "Forbidden"}));
    }

    let result = tokio::time::timeout(
        Duration::from_secs(8),
        state.ch_storage.delete_support_message(&id)
    ).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => return Json(json!({"status": "error", "message": "Support delete timed out"})),
    };

    match result {
        Ok(_) => Json(json!({"status": "ok", "message": "Support request deleted"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

// ── Sensor Key Management, Registration & Heartbeat ────────────────────────
fn generate_sensor_key(tenant_id: &str) -> (String, String, String) {
    use rand::Rng;
    let random: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let plain = format!("NDR-{}-{}", tenant_id, random);
    let prefix = plain[..16.min(plain.len())].to_string();
    let hash = bcrypt::hash(&plain, 10).unwrap_or_default();
    (plain, prefix, hash)
}

/// Cached variant — used by handlers that have access to AppState.
/// Falls back to direct bcrypt+DB on cache miss (same as before).
pub async fn validate_sensor_key_cached(
    headers: &axum::http::HeaderMap,
    ch: &Arc<ClickhouseStorage>,
    cache: Option<&crate::auth::sensor_cache::SensorKeyCache>,
) -> Option<String> {
    let key = headers
        .get("X-Sensor-Key")
        .or_else(|| headers.get("x-sensor-key"))?
        .to_str().ok()?;

    if let Some(c) = cache {
        crate::auth::sensor_cache::resolve_tenant(c, ch, key).await
    } else {
        ch.validate_sensor_key(key).await.ok()?
    }
}

fn extract_sensor_key_prefix(
    headers: &axum::http::HeaderMap,
) -> Option<String> {
    let key = headers
        .get("X-Sensor-Key")
        .or_else(|| headers.get("x-sensor-key"))?
        .to_str().ok()?;

    if key.len() < 16 {
        return None;
    }

    Some(key[..16].to_string())
}

/// GET /api/sensor/pcap-uploader.py
/// Extracts the embedded pcap-uploader.py from install-sensor.sh and serves it.
/// Used by sensors to self-update the uploader without a full reinstall.
pub async fn serve_pcap_uploader() -> axum::response::Response {
    let script_path = std::env::var("SENSOR_INSTALL_SCRIPT_PATH")
        .unwrap_or_else(|_| "/scripts/install-sensor.sh".to_string());

    let script = match tokio::fs::read_to_string(&script_path).await {
        Ok(s) => s,
        Err(_) => return axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("# pcap-uploader.py not found\n"))
            .unwrap(),
    };

    // Extract between heredoc markers:
    // cat > /opt/ndr-sensor/pcap-uploader.py << 'UPLOADER'
    // ...
    // UPLOADER
    let start_marker = "<< 'UPLOADER'";
    let end_marker = "\nUPLOADER";
    let uploader = if let Some(start) = script.find(start_marker) {
        let after = &script[start + start_marker.len()..];
        if let Some(end) = after.find(end_marker) {
            after[..end].trim_start_matches('\n').to_string()
        } else { String::new() }
    } else { String::new() };

    if uploader.is_empty() {
        return axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(axum::body::Body::from("# uploader section not found in install script\n"))
            .unwrap();
    }

    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/x-python; charset=utf-8")
        .body(axum::body::Body::from(uploader))
        .unwrap()
}

pub async fn install_sensor_script() -> axum::response::Response {
    let path = std::env::var("SENSOR_INSTALL_SCRIPT_PATH")
        .unwrap_or_else(|_| "/scripts/install-sensor.sh".to_string());

    match tokio::fs::read_to_string(&path).await {
        Ok(script) => axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/x-shellscript; charset=utf-8")
            .body(axum::body::Body::from(script))
            .unwrap(),
        Err(e) => axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(json!({
                "status": "error",
                "message": format!("Installer script not found at {}: {}", path, e)
            }).to_string()))
            .unwrap(),
    }
}

pub async fn uninstall_sensor_script() -> axum::response::Response {
    let path = "/scripts/uninstall-sensor.sh".to_string();

    match tokio::fs::read_to_string(&path).await {
        Ok(script) => axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/x-shellscript; charset=utf-8")
            .body(axum::body::Body::from(script))
            .unwrap(),
        Err(e) => axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(json!({
                "status": "error",
                "message": format!("Uninstall script not found: {}", e)
            }).to_string()))
            .unwrap(),
    }
}

pub async fn create_sensor_key_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };
    let tenant_id = payload["tenant_id"].as_str().unwrap_or("").to_string();
    let name = payload["name"].as_str().unwrap_or("").to_string();
    
    if tenant_id.is_empty() || name.is_empty() {
        return Json(json!({"status": "error", "message": "tenant_id and name are required"}));
    }

    let is_platform_admin = claims.role == "super_admin" || claims.role == "admin";
    if !is_platform_admin && claims.role != "tenant_admin" {
        return Json(json!({"status": "error", "message": "Forbidden: admin or tenant_admin required"}));
    }
    if claims.role == "tenant_admin" && tenant_id != claims.tenant_id {
        return Json(json!({"status": "error", "message": "Forbidden: tenant admins can only create sensor keys for their own tenant"}));
    }
    
    let (plain, prefix, hash) = generate_sensor_key(&tenant_id);
    
    match state.ch_storage.create_sensor_key(&tenant_id, &name, &hash, &prefix).await {
        Ok(id) => Json(json!({
            "status": "ok",
            "key": plain,
            "id": id,
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    }
}

pub async fn get_sensor_keys(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };
    
    let target_tenant = if claims.role == "super_admin" || claims.role == "admin" {
        "all".to_string()
    } else if claims.role == "tenant_admin" {
        claims.tenant_id.clone()
    } else {
        return Json(json!({"status": "error", "message": "Forbidden"}));
    };

    match state.ch_storage.get_sensor_keys(&target_tenant).await {
        Ok(keys) => Json(json!({
            "status": "ok",
            "keys": keys
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    }
}

// GET /api/sensor-keys/event-counts — real per-sensor event counts (last
// hour) for the caller's own tenant, keyed by sensor_id (== key_prefix).
// Replaces any placeholder "throughput" number with an actual measurement.
pub async fn get_sensor_event_counts(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };
    match state.ch_storage.get_sensor_event_counts_by_tenant(&claims.tenant_id, 1).await {
        Ok(counts) => Json(json!({ "status": "ok", "counts": counts })),
        Err(e) => Json(json!({ "status": "error", "message": e.to_string(), "counts": {} })),
    }
}

// GET /api/sensor-keys/recent-ips — real IP most recently seen from each
// sensor's own traffic, for the caller's own tenant. No IP is stored on
// sensor_keys itself, so this is derived from actual ingested events.
pub async fn get_sensor_recent_ips(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };
    match state.ch_storage.get_sensor_recent_ips_by_tenant(&claims.tenant_id).await {
        Ok(ips) => Json(json!({ "status": "ok", "ips": ips })),
        Err(e) => Json(json!({ "status": "error", "message": e.to_string(), "ips": {} })),
    }
}

pub async fn revoke_sensor_key_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };
    // TC-070: a tenant_admin can create a sensor key for their own tenant but
    // previously had no way to revoke one — strictly super_admin-only, no
    // exception for a key that actually belongs to their own tenant. Now
    // allowed for their own tenant's keys only; cross-tenant still forbidden.
    if claims.role != "super_admin" {
        if claims.role != "tenant_admin" {
            return Json(json!({"status": "error", "message": "Forbidden: Only super_admin or tenant_admin can revoke sensor keys"}));
        }
        match state.ch_storage.get_sensor_key_tenant_by_id(&id).await {
            Ok(Some(owner_tenant)) if owner_tenant == claims.tenant_id => {}
            Ok(Some(_)) => return Json(json!({"status": "error", "message": "Forbidden: cannot revoke another tenant's sensor key"})),
            Ok(None) => return Json(json!({"status": "error", "message": "Sensor key not found"})),
            Err(e) => return Json(json!({"status": "error", "message": e.to_string()})),
        }
    }

    match state.ch_storage.revoke_sensor_key(&id).await {
        Ok(_) => {
            // Immediately evict from shared Redis cache so ALL engine
            // instances reject this key on their next request — no 90s wait.
            // We look up by key_prefix (plain api_key is never stored in DB).
            if let Ok(Some(prefix)) = state.ch_storage
                .get_sensor_key_prefix_by_id(&id)
                .await
            {
                state.sensor_key_cache.invalidate_by_prefix(&prefix).await;
            }
            Json(json!({"status": "ok", "message": "Sensor key revoked"}))
        }
        Err(e) => Json(json!({"status": "error", "message": e.to_string()})),
    }
}

pub async fn reactivate_sensor_key_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status": "error", "message": "Unauthorized"})),
    };
    if claims.role != "super_admin" {
        return Json(json!({"status": "error", "message": "Forbidden: Only super_admin can reactivate sensor keys"}));
    }
    
    match state.ch_storage.reactivate_sensor_key(&id).await {
        Ok(_) => {
            // A revoked key is cached as such for a short while; clear it so the
            // reactivated key works immediately.
            if let Ok(Some(prefix)) = state.ch_storage.get_sensor_key_prefix_by_id(&id).await {
                state.sensor_key_cache.invalidate_by_prefix(&prefix).await;
            }
            Json(json!({
                "status": "ok",
                "message": "Sensor key reactivated"
            }))
        },
        Err(e) => Json(json!({
            "status": "error",
            "message": e.to_string()
        })),
    }
}

pub async fn sensor_register(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = match validate_sensor_key_cached(&headers, &state.ch_storage, Some(&state.sensor_key_cache)).await {
        Some(tid) => tid,
        None => return Json(json!({"status": "error", "message": "Invalid or missing X-Sensor-Key"})),
    };

    let hostname  = payload["hostname"].as_str().unwrap_or("unknown");
    let interface = payload["interface"].as_str().unwrap_or("unknown");
    let os        = payload["os"].as_str().unwrap_or("unknown");
    let key_prefix = extract_sensor_key_prefix(&headers);

    if let Some(prefix) = key_prefix.as_deref() {
        if let Err(e) = state.ch_storage
            .update_sensor_registration(prefix, hostname, interface, os)
            .await {
            tracing::warn!(
                "Failed to persist sensor registration for tenant={}: {}",
                tenant_id, e
            );
            return Json(json!({
                "status": "error",
                "message": format!("Failed to persist sensor registration: {}", e)
            }));
        }
    } else {
        return Json(json!({
            "status": "error",
            "message": "Invalid sensor key prefix"
        }));
    }

    tracing::info!(
        "Sensor registered: {} tenant={} iface={} os={}",
        hostname, tenant_id, interface, os
    );

    // Auto-suppress known false positives on sensor registration
    if let Some(prefix) = key_prefix.as_deref() {
        for sid_cmd in &[
            "suppress_sid:2066052",  // ET INFO ngrok-free.dev in TLS SNI (sensor→cloud heartbeat)
            "suppress_sid:2066057",  // Related ngrok tunneling rule
        ] {
            let _ = state.ch_storage
                .set_sensor_command(&tenant_id, prefix, sid_cmd)
                .await;
        }
    }

    Json(json!({
        "status":    "ok",
        "message":   "Sensor registered",
        "tenant_id": tenant_id
    }))
}

pub async fn sensor_heartbeat(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let tenant_id = match validate_sensor_key_cached(&headers, &state.ch_storage, Some(&state.sensor_key_cache)).await {
        Some(tid) => tid,
        None => return Json(json!({"status": "error", "message": "Invalid or missing X-Sensor-Key"})),
    };

    let zeek = payload["agent-z"].as_str().unwrap_or("unknown");
    let suricata = payload["agent-s"].as_str().unwrap_or("unknown");
    let vector = payload["vector"].as_str().unwrap_or("unknown");
    let arkime = payload["arkime"].as_str().unwrap_or("unknown");
    let arkime_url = payload["arkime_url"].as_str().unwrap_or("");
    let arkime_pass = payload["arkime_pass"].as_str().unwrap_or("");
    let key_prefix = extract_sensor_key_prefix(&headers);

    if let Some(prefix) = key_prefix.as_deref() {
        if let Err(e) = state.ch_storage
            .update_sensor_heartbeat(prefix, zeek, suricata, vector, arkime, arkime_url, arkime_pass)
            .await {
            tracing::warn!(
                "Failed to persist sensor heartbeat for tenant={}: {}",
                tenant_id, e
            );
            return Json(json!({
                "status": "error",
                "message": format!("Failed to persist sensor heartbeat: {}", e)
            }));
        }
    } else {
        return Json(json!({
            "status": "error",
            "message": "Invalid sensor key prefix"
        }));
    }

    tracing::info!(
        "Heartbeat from tenant={} zeek={} suricata={} arkime={}",
        tenant_id,
        zeek,
        suricata,
        arkime
    );

    Json(json!({"status": "ok"}))
}

/// Run SIGMA detection on a Linux auditd event and store any hits directly to ClickHouse.
/// Called inline during ingest — Linux events don't participate in the Zeek+Suricata correlator.
async fn handle_linux_endpoint_event(state: &AppState, raw: Value, tenant_id: &str) {
    use crate::storage::clickhouse::NdrHit;

    let event = match crate::normalizer::normalize(&raw) {
        Some(e) => e,
        None    => return,
    };

    let detections = {
        let engine = state.detection.read().await;
        engine.check_for_tenant(&event, tenant_id)
    };

    if detections.is_empty() { return; }

    let now = chrono::Utc::now().timestamp() as u32;

    let sigma_hits: Vec<String> = detections.iter().map(|d| d.title.clone()).collect();
    let tags: Vec<String>       = detections.iter().flat_map(|d| d.tags.clone()).collect();

    // Pick highest severity across all matching rules
    let severity = detections.iter()
        .map(|d| d.severity.as_str())
        .max_by_key(|s| match *s {
            "critical" => 4u8,
            "high"     => 3,
            "medium"   => 2,
            _          => 1,
        })
        .unwrap_or("medium")
        .to_string();

    let score = match severity.as_str() {
        "critical" => 10.0f32,
        "high"     => 7.5,
        "medium"   => 5.0,
        _          => 2.5,
    };

    let community_id = event.community_id.clone().unwrap_or_else(|| format!("linux-{}", now));
    let dst_ip = event.dest_ip.clone().unwrap_or_default();

    let image   = raw.get("Image").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let cmd     = raw.get("CommandLine").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let key     = raw.get("key").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let host    = raw.get("sensor_host").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let rule_id = detections.first().map(|d| d.rule_id.clone()).unwrap_or_default();

    let agent_s_details = serde_json::json!({
        "source":       "linux",
        "host":         host,
        "Image":        image,
        "CommandLine":  cmd,
        "key":          key,
        "sigma_hits":   sigma_hits.clone(),
    }).to_string();

    let hit = NdrHit {
        timestamp:          now,
        community_id,
        src_ip:             String::new(),
        dst_ip,
        score,
        severity,
        tags,
        sigma_hits,
        threat_intel:       0,
        src_country:        String::new(),
        dst_country:        String::new(),
        tenant_id:          tenant_id.to_string(),
        correlation_status: "endpoint".to_string(),
        agent_z_details:    String::new(),
        agent_s_details,
        corroborated_at:    now,
        agent_s_rule_id:    rule_id,
        agent_s_category:   "endpoint".to_string(),
        updated_at:         now,
        sensor_id:          host.clone(),
    };

    if let Err(e) = state.ch_storage.insert_hit_for_tenant(hit, tenant_id).await {
        tracing::warn!("Linux endpoint hit storage failed: {}", e);
    } else {
        tracing::info!("Linux endpoint SIGMA hit stored — tenant={} host={}", tenant_id, host);
    }
}

/// Marker on the "bad key" reply so the wrappers below can tell it apart from
/// other errors and check whether the key was revoked (rather than unknown).
const INVALID_KEY_CODE: &str = "invalid_sensor_key";

/// A sensor holding a key that an admin revoked gets HTTP 401 + `sensor_revoked`
/// instead of the old HTTP 200 + error body. With 200, Vector counted every
/// batch as delivered and kept shipping forever, and the agent never found out.
/// Only someone who holds the real (bcrypt-verified) key can see this answer, so
/// it tells an attacker nothing about which keys exist.
async fn revoked_response(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Option<axum::response::Response> {
    use axum::response::IntoResponse;
    let key = headers.get("X-Sensor-Key")?.to_str().ok()?;
    if !crate::auth::sensor_cache::is_revoked(&state.sensor_key_cache, &state.ch_storage, key).await {
        return None;
    }
    Some((
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "status": "revoked",
            "code": "sensor_revoked",
            "message": "This sensor key was revoked",
            "command": "uninstall",
        })),
    ).into_response())
}

pub async fn ingest_events(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let out = ingest_events_inner(State(state.clone()), headers.clone(), body).await;
    if out.0.get("code").and_then(|c| c.as_str()) == Some(INVALID_KEY_CODE) {
        if let Some(r) = revoked_response(&state, &headers).await { return r; }
    }
    // Only when an INGEST_RATE_LIMIT cap is set and exceeded: answer with a real 429
    // (Vector retries it) instead of HTTP 200, which Vector counts as delivered.
    if out.0.get("code").and_then(|c| c.as_u64()) == Some(429) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "60")],
            out,
        ).into_response();
    }
    // The engine's queue was full and some events were NOT queued. Answering HTTP 200 made
    // Vector treat the whole batch as delivered, so those events were lost silently. A 503 makes
    // Vector retry the batch (events already queued are de-duplicated downstream).
    if ingest_reply_is_overloaded(&out.0) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(axum::http::header::RETRY_AFTER, "2")],
            out,
        ).into_response();
    }
    out.into_response()
}

async fn ingest_events_inner(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Json<Value> {
    // Validate sensor key (cached — avoids bcrypt+DB on every ingest call)
    let tenant_id = match validate_sensor_key_cached(
        &headers, &state.ch_storage, Some(&state.sensor_key_cache)
    ).await {
        Some(tid) => tid,
        None => return Json(json!({
            "status": "error",
            "code": INVALID_KEY_CODE,
            "message": "Invalid or missing X-Sensor-Key"
        })),
    };

    // Parse body which can be standard JSON (Format 1/2) or newline-delimited JSON (ndjson)
    let events_arr: Vec<Value> = if let Ok(payload) = serde_json::from_str::<Value>(&body) {
        if let Some(arr) = payload.get("events").and_then(|e| e.as_array()) {
            arr.clone()
        } else if payload.is_object() {
            vec![payload]
        } else if let Some(arr) = payload.as_array() {
            arr.clone()
        } else {
            return Json(json!({
                "status": "error",
                "message": "Invalid payload format"
            }));
        }
    } else {
        let mut parsed_events = Vec::new();
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                if let Some(arr) = val.get("events").and_then(|e| e.as_array()) {
                    parsed_events.extend(arr.clone());
                } else {
                    parsed_events.push(val);
                }
            } else {
                tracing::warn!("Failed to parse ndjson line: {}", trimmed);
            }
        }
        if parsed_events.is_empty() {
            return Json(json!({
                "status": "error",
                "message": "Invalid JSON or ndjson payload"
            }));
        }
        parsed_events
    };

    let mut published = 0u64;
    let mut failed = 0u64;
    let mut queue_full = 0u64;

    // The sensor key prefix identifies which sensor sent these events.
    let key_prefix = extract_sensor_key_prefix(&headers).unwrap_or_default();

    // Per-sensor event-volume rate limit — prevents a misconfigured or compromised
    // sensor from flooding Kafka. Default: 50,000 events/60s (env: INGEST_RATE_LIMIT).
    if !crate::ratelimit::check_ingest_rate(&key_prefix, events_arr.len()) {
        tracing::warn!(
            "ingest rate limit exceeded for sensor '{}' ({} events in batch)",
            key_prefix, events_arr.len()
        );
        return Json(json!({
            "status": "error",
            "message": "Rate limit exceeded — too many events. Retry after 60s.",
            "code": 429
        }));
    }

    for event in &events_arr {
        // Add tenant_id and sensor_host to event so the consumer can tag hits.
        // Always overwrite sensor_host with the authenticated key_prefix so that
        // sensor_id stored in the DB matches what's used in user_sensor_assignments.
        let mut evt = event.clone();
        if let Some(obj) = evt.as_object_mut() {
            obj.insert("tenant_id".to_string(), serde_json::Value::String(tenant_id.clone()));
            if !key_prefix.is_empty() {
                obj.insert("sensor_host".to_string(), serde_json::Value::String(key_prefix.clone()));
            }
        }

        // Linux auditd endpoint events bypass Kafka — run SIGMA inline and store directly.
        if evt.get("source").and_then(|v| v.as_str()) == Some("linux") {
            handle_linux_endpoint_event(&state, evt, &tenant_id).await;
            published += 1;
            continue;
        }

        // Serialize event to JSON string
        let payload_str = match serde_json::to_string(&evt) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Failed to serialize event: {}", e);
                failed += 1;
                continue;
            }
        };

        // Non-blocking push to async drain channel — returns immediately,
        // background task flushes to Kafka in micro-batches.
        match state.ingest_tx.try_send((tenant_id.clone(), payload_str)) {
            Ok(_) => {
                published += 1;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Queue full: the caller gets HTTP 503 (see ingest_events) and retries the batch.
                queue_full += 1;
                failed += 1;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                tracing::error!("Ingest channel closed — drain task died");
                queue_full += 1;
                failed += 1;
            }
        }
    }

    if queue_full > 0 {
        tracing::warn!(
            "Ingest queue full: {} of {} events not queued for tenant {} - answering 503 so the sensor retries",
            queue_full, events_arr.len(), tenant_id
        );
    }
    tracing::info!(
        "Ingest: queued={} failed={} tenant={}",
        published, failed, tenant_id
    );

    Json(json!({
        "status": "ok",
        "published": published,
        "failed": failed,
        "queue_full": queue_full,
        "tenant_id": tenant_id
    }))
}

pub async fn get_sensor_command_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let tenant_id = match validate_sensor_key_cached(
        &headers, &state.ch_storage, Some(&state.sensor_key_cache)
    ).await {
        Some(tid) => tid,
        None => return Json(json!({ "command": "" })),
    };
    let sensor_id = match extract_sensor_key_prefix(&headers) {
        Some(prefix) => prefix,
        None => return Json(json!({ "command": "" })),
    };

    // Get pending command
    let (command, command_sensor_id) = state.ch_storage
        .get_sensor_command(&tenant_id, &sensor_id).await
        .unwrap_or_default();

    // Clear command after sending
    if !command.is_empty() {
        let _ = state.ch_storage
            .clear_sensor_command(&tenant_id, &command_sensor_id).await;
        tracing::info!(
            "Command '{}' sent to sensor tenant={} sensor={}",
            command, tenant_id, sensor_id
        );
    }

    Json(json!({ "command": command }))
}

// ── Merged sensor check-in ────────────────────────────────────────────────
// Combines heartbeat + command poll + pcap pending into ONE request.
// Cuts per-sensor HTTP traffic by ~3× vs the old 3 separate polls.
// Old endpoints (/heartbeat, /command, /pcap/pending) are kept for
// backward compat with already-deployed sensors.

#[derive(serde::Deserialize)]
#[allow(dead_code)]
pub struct CheckinRequest {
    pub sensor_ip:      Option<String>,
    pub arkime_url:     Option<String>,
    pub arkime_pass:    Option<String>,
    #[serde(rename = "agent-z")]
    pub agent_z:        Option<String>,
    #[serde(rename = "agent-s")]
    pub agent_s:        Option<String>,
    pub vector:         Option<String>,
    pub arkime_capture: Option<String>,
    pub arkime_viewer:  Option<String>,
}

/// POST /api/sensor/checkin
/// Single combined endpoint: heartbeat + command + pcap pending.
pub async fn sensor_checkin(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<CheckinRequest>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let out = sensor_checkin_inner(State(state.clone()), headers.clone(), Json(payload)).await;
    if out.0.get("code").and_then(|c| c.as_str()) == Some(INVALID_KEY_CODE) {
        if let Some(r) = revoked_response(&state, &headers).await { return r; }
    }
    out.into_response()
}

async fn sensor_checkin_inner(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<CheckinRequest>,
) -> Json<Value> {
    let tenant_id = match validate_sensor_key_cached(
        &headers, &state.ch_storage, Some(&state.sensor_key_cache)
    ).await {
        Some(t) => t,
        None => return Json(json!({"status": "error", "code": INVALID_KEY_CODE, "message": "invalid sensor key"})),
    };

    let sensor_id = match extract_sensor_key_prefix(&headers) {
        Some(p) => p,
        None => return Json(json!({"status": "error", "message": "invalid sensor key prefix"})),
    };

    // Remember which public address this sensor checks in from: the countries of a tenant's own
    // sensors are never counted as "sensitive countries" (see homecountry.rs).
    if let Some(ip) = crate::homecountry::client_ip(&headers) {
        let mut rc = state.redis_mux.clone();
        crate::homecountry::record_sensor_ip(&mut rc, &tenant_id, &sensor_id, ip).await;
    }

    // ── 1. Heartbeat / status update (throttled via Redis) ───────────────
    // Only write to ClickHouse when status changes or every 5 minutes —
    // avoids a SELECT FINAL + INSERT on every checkin under stable conditions.
    let zeek_s     = payload.agent_z.as_deref().unwrap_or("unknown");
    let suricata_s = payload.agent_s.as_deref().unwrap_or("unknown");
    let vector_s   = payload.vector.as_deref().unwrap_or("unknown");
    let arkime_status = payload.arkime_capture.as_deref()
        .or(payload.arkime_viewer.as_deref())
        .unwrap_or("unknown");
    let arkime_url  = payload.arkime_url.as_deref().unwrap_or("");
    let arkime_pass = payload.arkime_pass.as_deref().unwrap_or("");

    let status_sig = format!("{}|{}|{}|{}", zeek_s, suricata_s, vector_s, arkime_status);
    if state.sensor_key_cache
        .needs_heartbeat_write(&sensor_id, &status_sig)
        .await
    {
        let _ = state.ch_storage.update_sensor_heartbeat(
            &sensor_id, zeek_s, suricata_s, vector_s,
            arkime_status, arkime_url, arkime_pass,
        ).await;
    }

    // ── 2. Pending command ────────────────────────────────────────────────
    let (command, command_sensor_id) = state.ch_storage
        .get_sensor_command(&tenant_id, &sensor_id).await
        .unwrap_or_default();
    if !command.is_empty() {
        let _ = state.ch_storage
            .clear_sensor_command(&tenant_id, &command_sensor_id).await;
        tracing::info!(
            "Checkin: command '{}' dispatched to sensor {} tenant={}",
            command, sensor_id, tenant_id
        );
    }

    // ── 3. Pending PCAP uploads ───────────────────────────────────────────
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct PendingRow {
        community_id: String,
        severity:     String,
        retry_count:  u8,
    }
    let db = crate::storage::clickhouse::tenant_db_pub(&tenant_id);
    let pcap_rows = state.ch_storage.client
        .query(&format!(
            "SELECT community_id, severity, retry_count \
             FROM {}.pcap_pending FINAL \
             WHERE tenant_id = '{}' \
             AND fulfilled = 0 \
             AND retry_count < 3 \
             AND community_id LIKE '1:%' \
             AND requested_at > now() - INTERVAL 24 HOUR \
             ORDER BY multiIf(severity='CRITICAL',1, severity='HIGH',2, 3) ASC, \
                      requested_at ASC \
             LIMIT 10",
            db, sql_escape(&tenant_id)
        ))
        .fetch_all::<PendingRow>().await
        .unwrap_or_default();

    let pending_cids: Vec<String> = pcap_rows.iter().map(|r| r.community_id.clone()).collect();
    let pending_details: Vec<Value> = pcap_rows.iter().map(|r| json!({
        "community_id": r.community_id,
        "severity":     r.severity,
        "retry_count":  r.retry_count,
    })).collect();

    tracing::info!(
        "Checkin tenant={} sensor={} zeek={} suricata={} pending_pcap={}",
        tenant_id, sensor_id, zeek_s, suricata_s, pending_cids.len()
    );

    Json(json!({
        "status":               "ok",
        "command":              command,
        "pcap_pending":         pending_cids,
        "pcap_details":         pending_details,
        "checkin_interval_secs": 30
    }))
}

// ── Arkime Proxy Endpoints ────────────────────────────────────────────────

fn arkime_basic_auth(pass: &str) -> String {
    let credential = if pass.is_empty() {
        "admin:admin".to_string()
    } else {
        format!("admin:{}", pass)
    };
    base64::engine::general_purpose::STANDARD.encode(credential)
}

async fn get_tenant_arkime_creds(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(String, String), axum::response::Response> {
    use axum::response::IntoResponse;
    let claims = match extract_claims(headers) {
        Some(c) => c,
        None => return Err((axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(json!({"status":"error","message":"Unauthorized"}))).into_response()),
    };
    let (url, pass) = state.ch_storage
        .get_arkime_creds(&claims.tenant_id)
        .await
        .unwrap_or_default();
    if url.is_empty() {
        return Err(axum::Json(json!({
            "status": "error",
            "message": "Arkime not configured for this tenant"
        })).into_response());
    }
    Ok((url, pass))
}

pub async fn arkime_sessions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return axum::Json(json!({"status":"error","message":"Unauthorized"})).into_response(),
    };

    let params: std::collections::HashMap<String, String> = raw_query
        .as_deref()
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            let k = parts.next()?.to_string();
            let raw_v = parts.next().unwrap_or("");
            // percent-decode the value so community_id like "1:abc=" arrives intact
            let v = percent_decode(raw_v);
            Some((k, v))
        })
        .collect();

    let community_id = params.get("cid").cloned();
    let src_ip       = params.get("ip").cloned();
    let filter_src   = params.get("src_ip").cloned();
    let filter_dst   = params.get("dst_ip").cloned();
    let limit        = params.get("limit")
        .and_then(|l| l.parse::<u32>().ok())
        .unwrap_or(50);

    let (arkime_url, _) = state.ch_storage
        .get_arkime_creds(&claims.tenant_id)
        .await
        .unwrap_or_default();

    // ── ON-PREMISE PATH: query OpenSearch directly — always current, zero lag ──
    if claims.tenant_id == "default" {
        let es_url = std::env::var("OPENSEARCH_URL")
            .unwrap_or_else(|_| "http://localhost:9200".to_string());

        let mut must_clauses: Vec<serde_json::Value> = vec![];
        if let Some(ref cid) = community_id {
            must_clauses.push(json!({"term": {"network.community_id": cid}}));
        }
        if let Some(ref ip) = src_ip {
            must_clauses.push(json!({
                "bool": {"should": [
                    {"term": {"source.ip":      ip}},
                    {"term": {"destination.ip": ip}}
                ]}
            }));
        }
        // src_ip + dst_ip pair: match either direction of the flow
        if let (Some(ref s), Some(ref d)) = (&filter_src, &filter_dst) {
            must_clauses.push(json!({
                "bool": {"should": [
                    {"bool": {"must": [{"term": {"source.ip": s}}, {"term": {"destination.ip": d}}]}},
                    {"bool": {"must": [{"term": {"source.ip": d}}, {"term": {"destination.ip": s}}]}}
                ], "minimum_should_match": 1}
            }));
        }

        let es_query = json!({
            "size": limit,
            "sort": [{"firstPacket": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": if must_clauses.is_empty() {
                        vec![json!({"match_all": {}})]
                    } else { must_clauses }
                }
            },
            "_source": [
                "id", "firstPacket", "lastPacket",
                "source.ip", "source.port",
                "destination.ip", "destination.port",
                "ipProtocol", "network.bytes", "network.packets",
                "network.community_id", "node",
                "http.uri", "http.method", "http.statuscode", "http.host",
                "http.user-agent", "http.response-content-type",
                "dns.host", "dns.type", "dns.status",
                "tls.ja3", "tls.ja3s", "tls.server-name",
                "tcpflags.syn", "tcpflags.synack", "tcpflags.rst", "tcpflags.fin",
                "protocol", "totDataBytes", "serverBytes", "clientBytes",
                "tags"
            ]
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| HTTP_CLIENT.clone());

        match client
            .post(&format!("{}/arkime_sessions3-*/_search", es_url))
            .json(&es_query)
            .send()
            .await
        {
            Ok(r) => {
                let data: serde_json::Value = r.json().await.unwrap_or_default();
                let hits = data["hits"]["hits"].as_array().cloned().unwrap_or_default();
                let sessions: Vec<serde_json::Value> = hits.iter().map(|h| {
                    let s = &h["_source"];
                    let proto_num = s["ipProtocol"].as_u64().unwrap_or(0);
                    let proto = match proto_num {
                        6  => "tcp",
                        17 => "udp",
                        _  => "other",
                    };
                    // Build optional layer-7 detail blocks
                    let http = if !s["http"]["uri"].is_null() || !s["http"]["method"].is_null() {
                        json!({
                            "method":       s["http"]["method"].as_str().unwrap_or(""),
                            "uri":          s["http"]["uri"].as_str().unwrap_or(""),
                            "host":         s["http"]["host"].as_str().unwrap_or(""),
                            "status":       s["http"]["statuscode"].as_u64().unwrap_or(0),
                            "user_agent":   s["http"]["user-agent"].as_str().unwrap_or(""),
                            "content_type": s["http"]["response-content-type"].as_str().unwrap_or("")
                        })
                    } else { json!(null) };
                    let dns = if !s["dns"]["host"].is_null() {
                        json!({
                            "host":   s["dns"]["host"].as_str().unwrap_or(""),
                            "type":   s["dns"]["type"].as_str().unwrap_or(""),
                            "status": s["dns"]["status"].as_str().unwrap_or("")
                        })
                    } else { json!(null) };
                    let tls = if !s["tls"]["ja3"].is_null() || !s["tls"]["server-name"].is_null() {
                        json!({
                            "ja3":         s["tls"]["ja3"].as_str().unwrap_or(""),
                            "ja3s":        s["tls"]["ja3s"].as_str().unwrap_or(""),
                            "server_name": s["tls"]["server-name"].as_str().unwrap_or("")
                        })
                    } else { json!(null) };
                    let tcp_flags = if proto == "tcp" {
                        json!({
                            "syn":    s["tcpflags"]["syn"].as_u64().unwrap_or(0),
                            "synack": s["tcpflags"]["synack"].as_u64().unwrap_or(0),
                            "rst":    s["tcpflags"]["rst"].as_u64().unwrap_or(0),
                            "fin":    s["tcpflags"]["fin"].as_u64().unwrap_or(0)
                        })
                    } else { json!(null) };
                    json!({
                        "id":           h["_id"].as_str().unwrap_or(""),
                        "session_id":   h["_id"].as_str().unwrap_or(""),
                        "community_id": s["network"]["community_id"].as_str().unwrap_or(""),
                        "src_ip":       s["source"]["ip"].as_str().unwrap_or(""),
                        "dst_ip":       s["destination"]["ip"].as_str().unwrap_or(""),
                        "src_port":     s["source"]["port"].as_u64().unwrap_or(0),
                        "dst_port":     s["destination"]["port"].as_u64().unwrap_or(0),
                        "proto":        proto,
                        "bytes":        s["network"]["bytes"].as_u64().unwrap_or(0),
                        "packets":      s["network"]["packets"].as_u64().unwrap_or(0),
                        "data_bytes":   s["totDataBytes"].as_u64().unwrap_or(0),
                        "server_bytes": s["serverBytes"].as_u64().unwrap_or(0),
                        "client_bytes": s["clientBytes"].as_u64().unwrap_or(0),
                        "start_time":   s["firstPacket"].as_u64().unwrap_or(0),
                        "end_time":     s["lastPacket"].as_u64().unwrap_or(0),
                        "sensor_host":  s["node"].as_str().unwrap_or(""),
                        "tags":         s["tags"].as_array().cloned().unwrap_or_default(),
                        "http":         http,
                        "dns":          dns,
                        "tls":          tls,
                        "tcp_flags":    tcp_flags,
                        "arkime_url":   &arkime_url,
                        "file_path":    ""
                    })
                }).collect();
                return axum::Json(json!({
                    "status":  "ok",
                    "sessions": sessions,
                    "source":  "opensearch",
                    "total":   data["hits"]["total"]["value"].as_u64().unwrap_or(0)
                })).into_response();
            }
            Err(e) => {
                tracing::warn!("OpenSearch query failed: {}", e);
                return axum::Json(json!({
                    "status":   "error",
                    "message":  "OpenSearch unreachable",
                    "sessions": []
                })).into_response();
            }
        }
    }

    // ── EXTERNAL SENSOR PATH: ClickHouse cache (populated via pcap-upload push) ──
    let sessions = state.ch_storage
        .get_pcap_sessions(
            &claims.tenant_id,
            community_id.as_deref(),
            src_ip.as_deref(),
            limit,
            &claims.sensor_ids,
        )
        .await
        .unwrap_or_default();

    axum::Json(json!({
        "status":   "ok",
        "sessions": sessions,
        "source":   "clickhouse"
    })).into_response()
}

pub async fn arkime_pcap_download(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let (arkime_url, arkime_pass) = match get_tenant_arkime_creds(&state, &headers).await {
        Ok(creds) => creds,
        Err(r) => return r,
    };
    let target = format!("{}/api/session/{}/pcap", arkime_url, session_id);
    match state.http_client
        .get(&target)
        .header("Authorization", format!("Basic {}", arkime_basic_auth(&arkime_pass)))
        .timeout(Duration::from_secs(60))
        .send()
        .await
    {
        Ok(resp) => {
            let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(axum::http::StatusCode::OK);
            let bytes = resp.bytes().await.unwrap_or_default();
            (
                status,
                [
                    (axum::http::header::CONTENT_TYPE, "application/vnd.tcpdump.pcap"),
                    (axum::http::header::CONTENT_DISPOSITION,
                        &format!("attachment; filename=\"{}.pcap\"", session_id)),
                ],
                bytes,
            ).into_response()
        }
        Err(e) => axum::Json(json!({
            "status": "error",
            "message": format!("Failed to reach Arkime: {}", e)
        })).into_response()
    }
}

pub async fn arkime_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let (arkime_url, arkime_pass) = match get_tenant_arkime_creds(&state, &headers).await {
        Ok(creds) => creds,
        Err(r) => return r,
    };
    let target = format!("{}/api/stats", arkime_url);
    match state.http_client
        .get(&target)
        .header("Authorization", format!("Basic {}", arkime_basic_auth(&arkime_pass)))
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) => {
            let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(axum::http::StatusCode::OK);
            let body = resp.text().await.unwrap_or_default();
            (status, [(axum::http::header::CONTENT_TYPE, "application/json")], body).into_response()
        }
        Err(e) => axum::Json(json!({
            "status": "error",
            "message": if e.is_connect() {
                "Arkime is not running on this sensor".to_string()
            } else {
                "Arkime unreachable".to_string()
            }
        })).into_response()
    }
}

pub async fn arkime_session_link(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(community_id): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return axum::Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let (arkime_url, _) = state.ch_storage
        .get_arkime_creds(&claims.tenant_id)
        .await
        .unwrap_or_default();
    if arkime_url.is_empty() {
        return axum::Json(json!({
            "status": "error",
            "message": "No Arkime configured"
        }));
    }
    let link = format!(
        "{}/?expression=communityId%3D%3D{}&startTime=-1h&stopTime=now",
        arkime_url,
        urlencoding_encode(&community_id)
    );
    axum::Json(json!({
        "status": "ok",
        "link": link,
        "arkime_url": arkime_url
    }))
}

pub async fn pcap_upload(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    mut multipart: axum::extract::Multipart,
) -> axum::Json<serde_json::Value> {
    let tenant_id = match validate_sensor_key_cached(&headers, &state.ch_storage, Some(&state.sensor_key_cache)).await {
        Some(tid) => tid,
        None => return axum::Json(json!({
            "status": "error",
            "message": "Unauthorized: invalid sensor key"
        })),
    };

    let mut pcap_bytes: Vec<u8> = Vec::new();
    let mut pcap_filename = String::new();
    let mut community_id = String::new();
    let mut src_ip = String::new();
    let mut dst_ip = String::new();
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut proto = String::new();
    let mut sensor_host = String::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "pcap" => {
                pcap_filename = field.file_name().unwrap_or("").to_string();
                pcap_bytes = match field.bytes().await {
                    Ok(b) => b.to_vec(),
                    Err(e) => return axum::Json(json!({
                        "status": "error",
                        "message": format!("Failed to read pcap field: {}", e)
                    })),
                };
                tracing::info!("pcap_upload: received {}B filename={}", pcap_bytes.len(), pcap_filename);
            }
            "community_id" => {
                community_id = field.text().await.unwrap_or_default();
            }
            "src_ip" => { src_ip = field.text().await.unwrap_or_default(); }
            "dst_ip" => { dst_ip = field.text().await.unwrap_or_default(); }
            "src_port" => {
                src_port = field.text().await.unwrap_or_default()
                    .parse().unwrap_or(0);
            }
            "dst_port" => {
                dst_port = field.text().await.unwrap_or_default()
                    .parse().unwrap_or(0);
            }
            "proto" => { proto = field.text().await.unwrap_or_default(); }
            "sensor_host" => { sensor_host = field.text().await.unwrap_or_default(); }
            _ => { let _ = field.bytes().await; }
        }
    }

    if pcap_bytes.is_empty() {
        tracing::warn!("pcap_upload: no pcap data cid={} tenant={}", community_id, tenant_id);
        return axum::Json(json!({"status":"error","message":"No pcap data received"}));
    }

    if community_id.is_empty() {
        return axum::Json(json!({"status":"error","message":"Missing community_id"}));
    }

    // Dedup: already stored — mark fulfilled and return ok
    if let Ok(Some(_)) = state.ch_storage
        .get_pcap_file_path_by_community_id(&tenant_id, &community_id).await
    {
        let _ = state.ch_storage.mark_pcap_fulfilled(&tenant_id, &community_id).await;
        return axum::Json(json!({
            "status": "ok",
            "message": "already stored",
            "session_id": "existing"
        }));
    }

    // Detect gzip by filename OR magic bytes — NOT by Content-Encoding header.
    // Content-Encoding: gzip on a multipart request corrupts the multipart parser.
    let is_gzip = pcap_filename.ends_with(".gz")
        || (pcap_bytes.len() > 1 && pcap_bytes[0] == 0x1f && pcap_bytes[1] == 0x8b);
    let raw_bytes = if is_gzip {
        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(pcap_bytes.as_slice());
        let mut decompressed = Vec::new();
        match decoder.read_to_end(&mut decompressed) {
            Ok(_) => {
                tracing::info!("pcap_upload: decompressed gzip {}B → {}B", pcap_bytes.len(), decompressed.len());
                decompressed
            }
            Err(e) => return axum::Json(json!({
                "status": "error",
                "message": format!("Failed to decompress pcap: {}", e)
            })),
        }
    } else {
        pcap_bytes
    };

    // Reject non-PCAP content (e.g. raw ZST blobs — fix Arkime: simpleCompression=none)
    let valid_pcap = raw_bytes.len() >= 4 && matches!(
        u32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]),
        0xa1b2c3d4 | 0xd4c3b2a1 | 0xa1b23c4d | 0x4d3cb2a1 | 0x0a0d0d0a
    );
    if !valid_pcap {
        let magic = if raw_bytes.len() >= 4 {
            format!("0x{:08x}", u32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]))
        } else { "too short".to_string() };
        tracing::error!("pcap_upload: invalid PCAP magic {} cid={} — likely zstd-compressed", magic, community_id);
        return axum::Json(json!({
            "status": "error",
            "message": format!("Invalid PCAP file (magic={}). Set simpleCompression=none in Arkime config.", magic)
        }));
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let date_str = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let file_dir = format!("/opt/ndr/pcap/{}/{}", tenant_id, date_str);
    let file_path = format!("{}/{}.pcap", file_dir, session_id);
    let bytes_count = raw_bytes.len() as u64;

    if let Err(e) = tokio::fs::create_dir_all(&file_dir).await {
        tracing::error!("pcap_upload: mkdir failed {}: {}", file_dir, e);
        return axum::Json(json!({
            "status": "error",
            "message": format!("Failed to create storage directory: {}", e)
        }));
    }

    if let Err(e) = tokio::fs::write(&file_path, &raw_bytes).await {
        tracing::error!("pcap_upload: write failed {}: {}", file_path, e);
        return axum::Json(json!({
            "status": "error",
            "message": format!("Failed to write pcap file: {}", e)
        }));
    }

    if let Err(e) = state.ch_storage.save_pcap_session(
        &tenant_id, &session_id, &community_id,
        &src_ip, &dst_ip, src_port, dst_port, &proto,
        bytes_count, "", &file_path, &sensor_host,
    ).await {
        tracing::warn!("pcap_upload: failed to index session: {}", e);
    }

    // Back-fill file_path on any existing pcap_sessions rows for this community_id
    // (e.g. rows created by the Arkime background sync that had file_path = "").
    // ReplacingMergeTree keeps the row with the latest start_time, so re-inserting
    // with now() makes the file_path visible on the next FINAL read.
    let _ = state.ch_storage
        .update_pcap_file_path_by_community_id(&tenant_id, &community_id, &file_path)
        .await;

    let _ = state.ch_storage.mark_pcap_fulfilled(&tenant_id, &community_id).await;
    tracing::info!("pcap_upload: ✅ saved cid={} tenant={} size={}B", community_id, tenant_id, bytes_count);

    axum::Json(json!({
        "status": "ok",
        "session_id": session_id,
        "file_path": file_path,
        "bytes": bytes_count
    }))
}

pub async fn pcap_download_stored(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    let file_path = state.ch_storage
        .get_pcap_file_path(&claims.tenant_id, &session_id)
        .await
        .unwrap_or_default();

    // If a stored file exists (remote sensor upload) — serve it directly
    if !file_path.is_empty() {
        return match tokio::fs::read(&file_path).await {
            Ok(data) => (
                [
                    ("Content-Type", "application/vnd.tcpdump.pcap"),
                    ("Content-Disposition",
                     &format!("attachment; filename=\"{}.pcap\"", session_id)),
                ],
                data,
            ).into_response(),
            Err(e) => (
                axum::http::StatusCode::NOT_FOUND,
                format!("PCAP file not found on disk: {}", e),
            ).into_response(),
        };
    }

    // Fallback: on-premise session — proxy download through Arkime
    // session_id is the Arkime session ID stored by the caching layer
    let (arkime_url, arkime_pass) = state.ch_storage
        .get_arkime_creds(&claims.tenant_id)
        .await
        .unwrap_or_default();

    if arkime_url.is_empty() {
        return (axum::http::StatusCode::NOT_FOUND, "PCAP not available").into_response();
    }

    // Arkime PCAP endpoint requires the node name: /api/session/{node}/{id}/pcap
    // Try ?node= query param first (passed by Angular from session.sensor_host),
    // then fall back to querying OpenSearch directly for the session document.
    let node_from_param = raw_query.as_deref().unwrap_or("").split('&').find_map(|p| {
        p.strip_prefix("node=").map(|v| urlencoding::decode(v).unwrap_or_default().into_owned())
    }).unwrap_or_default();

    let node = if !node_from_param.is_empty() {
        node_from_param
    } else {
        // Query OpenSearch for the session _id to get the node name
        let es_url = std::env::var("OPENSEARCH_URL")
            .unwrap_or_else(|_| "http://localhost:9200".to_string());
        let search = json!({
            "size": 1,
            "_source": ["node"],
            "query": {"ids": {"values": [&session_id]}}
        });
        match state.http_client
            .post(&format!("{}/arkime_sessions3-*/_search", es_url))
            .json(&search)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                r.json::<serde_json::Value>().await
                    .ok()
                    .and_then(|v| v["hits"]["hits"][0]["_source"]["node"].as_str().map(str::to_owned))
                    .unwrap_or_default()
            }
            _ => String::new(),
        }
    };

    let target = if node.is_empty() {
        format!("{}/api/session/{}/pcap", arkime_url, session_id)
    } else {
        format!("{}/api/session/{}/{}/pcap", arkime_url, node, session_id)
    };
    match state.http_client
        .get(&target)
        .header("Authorization", format!("Basic {}", arkime_basic_auth(&arkime_pass)))
        .timeout(Duration::from_secs(60))
        .send()
        .await
    {
        Ok(resp) => {
            if !resp.status().is_success() {
                return (axum::http::StatusCode::NOT_FOUND,
                    format!("Arkime: session not found or no PCAP stored ({})", resp.status())
                ).into_response();
            }
            // Arkime returns HTML (its viewer page) with 200 when the node is missing
            // from the URL or auth fails — check content-type and PCAP magic bytes.
            let ct = resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let bytes = resp.bytes().await.unwrap_or_default();
            let is_pcap = !ct.contains("html") && bytes.len() >= 4 && {
                let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                magic == 0xa1b2_c3d4 || magic == 0xd4c3_b2a1 || magic == 0x0a0d_0d0a
            };
            if !is_pcap {
                // Fall through to raw-file fallback below
                tracing::warn!("Arkime returned non-PCAP for session {} (ct={}), trying raw fallback", session_id, ct);
                let qs = raw_query.as_deref().unwrap_or("");
                let qp = |key: &str| -> String {
                    qs.split('&').find_map(|p| {
                        p.strip_prefix(&format!("{}=", key))
                            .map(|v| urlencoding::decode(v).unwrap_or_default().into_owned())
                    }).unwrap_or_default()
                };
                let src_ip   = qp("src_ip");
                let dst_ip   = qp("dst_ip");
                let src_port = qp("src_port");
                let dst_port = qp("dst_port");
                if let Some(raw_bytes) = pcap_from_raw_direct(&src_ip, &dst_ip, &src_port, &dst_port, &session_id).await {
                    return ([
                        ("Content-Type", "application/vnd.tcpdump.pcap"),
                        ("Content-Disposition", &format!("attachment; filename=\"{}.pcap\"", session_id)),
                    ], raw_bytes).into_response();
                }
                return (axum::http::StatusCode::BAD_GATEWAY,
                    "Arkime returned an unexpected response — session PCAP could not be retrieved."
                ).into_response();
            }
            (
                [
                    ("Content-Type", "application/vnd.tcpdump.pcap"),
                    ("Content-Disposition",
                     &format!("attachment; filename=\"{}.pcap\"", session_id)),
                ],
                bytes,
            ).into_response()
        }
        Err(e) => {
            if !e.is_connect() {
                return (axum::http::StatusCode::BAD_GATEWAY, "Arkime unreachable").into_response();
            }
            // Arkime viewer down — raw files still in /opt/arkime/raw/.
            // Read IPs/ports directly from query params (passed by the frontend from session data).
            let qs = raw_query.as_deref().unwrap_or("");
            let qp = |key: &str| -> String {
                qs.split('&').find_map(|p| {
                    p.strip_prefix(&format!("{}=", key))
                        .map(|v| urlencoding::decode(v).unwrap_or_default().into_owned())
                }).unwrap_or_default()
            };
            let src_ip   = qp("src_ip");
            let dst_ip   = qp("dst_ip");
            let src_port = qp("src_port");
            let dst_port = qp("dst_port");

            if let Some(bytes) = pcap_from_raw_direct(&src_ip, &dst_ip, &src_port, &dst_port, &session_id).await {
                return (
                    [
                        ("Content-Type", "application/vnd.tcpdump.pcap"),
                        ("Content-Disposition",
                         &format!("attachment; filename=\"{}.pcap\"", session_id)),
                    ],
                    bytes,
                ).into_response();
            }
            (
                axum::http::StatusCode::BAD_GATEWAY,
                "Arkime viewer is not running — raw PCAP files exist but could not be extracted \
                 (install tshark or tcpdump, or start arkimeviewer).",
            ).into_response()
        }
    }
}

/// Arkime viewer is down — extract session directly from /opt/arkime/raw/ using
/// IPs from query params (no OpenSearch needed). Handles .pcap.zst files.
/// Arkime viewer is down — extract session from /opt/arkime/raw/ using IPs from query params.
/// Handles Arkime's .pcap.zst compressed files via zstd + tcpdump pipeline.
/// session_id prefix (e.g. "260802-...") is used to find the right date's files first.
#[allow(dead_code)]
async fn pcap_from_raw_arkime(_state: &AppState, _session_id: &str) -> Option<Vec<u8>> {
    // caller passes IPs via query params — see call site
    None // IPs not available here; see pcap_from_raw_direct called at the Err branch
}

async fn pcap_from_raw_direct(
    src_ip: &str, dst_ip: &str,
    src_port: &str, dst_port: &str,
    session_id: &str,
) -> Option<Vec<u8>> {
    if src_ip.is_empty() || dst_ip.is_empty() { return None; }

    let raw_dir = std::path::Path::new("/opt/arkime/raw");
    if !raw_dir.is_dir() { return None; }

    // Session ID starts with YYMMDD (e.g. "260802-...") — prefer files from that date
    let date_prefix = session_id.split('-').next().unwrap_or("");

    // Collect all .pcap and .pcap.zst files; prefer same-date files first
    let mut files: Vec<(u8, std::time::SystemTime, String)> = vec![]; // (priority, mtime, path)
    if let Ok(rd) = std::fs::read_dir(raw_dir) {
        for e in rd.flatten() {
            let p = e.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
            let is_zst  = name.ends_with(".pcap.zst");
            let is_pcap = name.ends_with(".pcap") && !is_zst;
            if !is_zst && !is_pcap { continue; }
            let mtime = e.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
            let priority = if !date_prefix.is_empty() && name.contains(date_prefix) { 0u8 } else { 1u8 };
            files.push((priority, mtime, p.to_string_lossy().into_owned()));
        }
    }
    if files.is_empty() { return None; }
    // Sort: same-date files first, then newest first within each group
    files.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));

    let bpf = if !src_port.is_empty() && !dst_port.is_empty() {
        format!("host {} and host {} and (port {} or port {})", src_ip, dst_ip, src_port, dst_port)
    } else {
        format!("host {} and host {}", src_ip, dst_ip)
    };

    for (_, _, path) in &files {
        let pcap_path = if path.ends_with(".pcap.zst") {
            // Decompress to a temp file, then filter with tcpdump
            let tmp = format!("/tmp/ndr_raw_{}.pcap", std::process::id());
            let ok = tokio::process::Command::new("zstd")
                .args(["-dc", path, "-o", &tmp])
                .stderr(std::process::Stdio::null())
                .status().await
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok { continue; }
            Some(tmp)
        } else {
            None // use original path
        };
        let read_path = pcap_path.as_deref().unwrap_or(path.as_str());
        let out = tokio::process::Command::new("tcpdump")
            .args(["-r", read_path, "-w", "-", &bpf])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output().await;
        if let Some(tmp) = &pcap_path {
            let _ = tokio::fs::remove_file(tmp).await;
        }
        let bytes = match out {
            Ok(o) if o.stdout.len() > 24 => o.stdout,
            _ => continue,
        };
        return Some(bytes);
    }
    None
}

pub async fn pcap_pending(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::Json<serde_json::Value> {
    let tenant_id = match validate_sensor_key_cached(&headers, &state.ch_storage, Some(&state.sensor_key_cache)).await {
        Some(t) => t,
        None => return axum::Json(json!({"status":"error","message":"Unauthorized"})),
    };

    // Priority queue: CRITICAL first, then HIGH, then MEDIUM
    // Retry limit: max 3 attempts — stops infinite retry loops
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct PendingRow {
        community_id: String,
        severity:     String,
        requested_at_str: String,
        retry_count:  u8,
    }
    let db = crate::storage::clickhouse::tenant_db_pub(&tenant_id);
    let rows = state.ch_storage.client
        .query(&format!(
            "SELECT community_id, \
             severity, \
             toString(requested_at) as requested_at_str, \
             retry_count \
             FROM {}.pcap_pending FINAL \
             WHERE tenant_id = '{}' \
             AND fulfilled = 0 \
             AND retry_count < 3 \
             AND community_id LIKE '1:%' \
             AND requested_at > now() - INTERVAL 24 HOUR \
             ORDER BY \
               multiIf(severity='CRITICAL',1, severity='HIGH',2, 3) ASC, \
               requested_at ASC \
             LIMIT 10",
            db, sql_escape(&tenant_id)
        ))
        .fetch_all::<PendingRow>().await
        .unwrap_or_else(|e| {
            tracing::error!("pcap_pending query failed: {}", e);
            vec![]
        });

    let pending: Vec<serde_json::Value> = rows.iter().map(|r| json!({
        "community_id": r.community_id,
        "severity":     r.severity,
        "requested_at": r.requested_at_str,
        "retry_count":  r.retry_count,
        "priority": match r.severity.as_str() {
            "CRITICAL" => 1, "HIGH" => 2, _ => 3
        }
    })).collect();

    // Also return plain list for backward-compatible agent.py
    let plain: Vec<&str> = rows.iter().map(|r| r.community_id.as_str()).collect();

    axum::Json(json!({
        "status":  "ok",
        "pending": plain,
        "details": pending,
        "count":   plain.len()
    }))
}

// ── Asset Management Endpoints ────────────────────────────────────────────────

pub async fn get_assets(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::Json<serde_json::Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();
    match state.ch_storage.get_assets_with_counts_by_tenant(&tenant_id, &sensor_ids).await {
        Ok(assets) => {
            // Filter out link-local and APIPA addresses — not useful in the UI
            let filtered: Vec<_> = assets.into_iter().filter(|a| {
                let ip = a["ip"].as_str().unwrap_or("");
                !ip.starts_with("fe80") && !ip.starts_with("169.254.")
            }).collect();
            axum::Json(json!(filtered))
        },
        Err(e) => axum::Json(json!({"error": e.to_string()})),
    }
}

pub async fn get_asset_by_ip(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(ip): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let tenant_id = extract_claims(&headers)
        .map(|c| c.tenant_id)
        .unwrap_or_else(|| "default".to_string());
    match state.ch_storage.get_asset_by_ip(&tenant_id, &ip).await {
        Ok(Some(asset)) => axum::Json(json!(asset)),
        Ok(None)        => axum::Json(json!({"error": "not found"})),
        Err(e)          => axum::Json(json!({"error": e.to_string()})),
    }
}

pub async fn update_asset_name(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(ip): axum::extract::Path<String>,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let tenant_id = extract_claims(&headers)
        .map(|c| c.tenant_id)
        .unwrap_or_else(|| "default".to_string());
    let custom_name = payload.get("custom_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match state.ch_storage.update_asset_name(&tenant_id, &ip, custom_name).await {
        Ok(_)  => axum::Json(json!({"status": "ok"})),
        Err(e) => axum::Json(json!({"error": e.to_string()})),
    }
}

pub async fn set_asset_trusted_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(ip): axum::extract::Path<String>,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let tenant_id = extract_claims(&headers)
        .map(|c| c.tenant_id)
        .unwrap_or_else(|| "default".to_string());
    let trusted = payload.get("trusted").and_then(|v| v.as_bool()).unwrap_or(false);
    match state.ch_storage.set_asset_trusted(&tenant_id, &ip, trusted).await {
        Ok(_)  => axum::Json(json!({"status": "ok", "trusted": trusted})),
        Err(e) => axum::Json(json!({"error": e.to_string()})),
    }
}

pub async fn get_subnet_roles(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::Json<serde_json::Value> {
    if extract_claims(&headers).is_none() {
        return axum::Json(json!({"error": "unauthorized"}));
    }
    let roles = state.ch_storage.get_subnet_roles("default").await;
    let out: Vec<serde_json::Value> = roles.iter()
        .map(|(cidr, role)| json!({"cidr": cidr, "role": role}))
        .collect();
    axum::Json(json!(out))
}

pub async fn set_subnet_roles(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    if extract_claims(&headers).is_none() {
        return axum::Json(json!({"error": "unauthorized"}));
    }
    let json_str = serde_json::to_string(&payload).unwrap_or_default();
    match state.ch_storage.set_subnet_roles(&json_str).await {
        Ok(_)  => axum::Json(json!({"status": "ok"})),
        Err(e) => axum::Json(json!({"error": e.to_string()})),
    }
}

pub async fn pcap_upload_failed(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let tenant_id = match validate_sensor_key_cached(&headers, &state.ch_storage, Some(&state.sensor_key_cache)).await {
        Some(t) => t,
        None => return axum::Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let community_id = payload["community_id"].as_str().unwrap_or("");
    let error_msg    = payload["error"].as_str().unwrap_or("unknown").replace('\'', "\\'");
    if community_id.is_empty() {
        return axum::Json(json!({"status":"error","message":"missing community_id"}));
    }
    // Increment retry_count; if >= 3, mark fulfilled=2 (failed) so sensor stops
    let db = crate::storage::clickhouse::tenant_db_pub(&tenant_id);
    let _ = state.ch_storage.client
        .query(&format!(
            "ALTER TABLE {}.pcap_pending \
             UPDATE \
               retry_count = retry_count + 1, \
               error_message = '{}', \
               last_retry = now(), \
               fulfilled = if(retry_count >= 2, 2, 0) \
             WHERE community_id = '{}' AND tenant_id = '{}' AND fulfilled = 0",
            db, error_msg,
            sql_escape(community_id),
            sql_escape(&tenant_id)
        ))
        .execute().await;
    tracing::warn!("PCAP upload failed cid={} tenant={} err={}", community_id, tenant_id, error_msg);
    axum::Json(json!({"status":"recorded"}))
}

fn urlencoding_encode(s: &str) -> String {
    s.chars().flat_map(|c| {
        if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            vec![c]
        } else {
            format!("%{:02X}", c as u32).chars().collect()
        }
    }).collect()
}

pub async fn sensor_control_api(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    // JWT auth - admin or tenant_admin only
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({
            "status": "error",
            "message": "Unauthorized"
        }))
    };

    // Only admin or tenant_admin can control sensors
    if claims.role != "admin" 
        && claims.role != "super_admin"
        && claims.role != "tenant_admin" {
        return Json(json!({
            "status": "error",
            "message": "Insufficient permissions"
        }));
    }

    let command = payload["command"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // Validate command
    if !["start", "stop", "restart"].contains(&command.as_str()) {
        return Json(json!({
            "status": "error",
            "message": "Invalid command. Use: start, stop, restart"
        }));
    }

    // Get tenant_id - admin can specify, tenant_admin uses own
    let tenant_id = if claims.role == "super_admin" 
        || claims.role == "admin" {
        payload["tenant_id"]
            .as_str()
            .unwrap_or(&claims.tenant_id)
            .to_string()
    } else {
        claims.tenant_id.clone()
    };

    let sensor_id = payload["sensor_id"]
        .as_str()
        .unwrap_or("")
        .to_string();

    if !sensor_id.is_empty() {
        match state.ch_storage.active_sensor_exists(&tenant_id, &sensor_id).await {
            Ok(true) => {},
            Ok(false) => return Json(json!({
                "status": "error",
                "message": "Sensor not found for tenant or sensor is revoked"
            })),
            Err(e) => return Json(json!({
                "status": "error",
                "message": format!("Failed to verify sensor: {}", e)
            })),
        }
    }

    // Store command for sensor to pick up. Empty sensor_id is kept as a
    // legacy tenant-wide command for older clients.
    match state.ch_storage
        .set_sensor_command(&tenant_id, &sensor_id, &command).await {
        Ok(_) => {
            tracing::info!(
                "Sensor command '{}' set for tenant={} sensor={}",
                command, tenant_id, sensor_id
            );
            Json(json!({
                "status": "ok",
                "message": format!(
                    "Command '{}' queued for sensor {}",
                    command,
                    if sensor_id.is_empty() { tenant_id.as_str() } else { sensor_id.as_str() }
                ),
                "tenant_id": tenant_id,
                "sensor_id": sensor_id,
                "command": command
            }))
        },
        Err(e) => Json(json!({
            "status": "error",
            "message": format!("Failed to set command: {}", e)
        }))
    }
}


pub async fn get_telemetry(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status": "error", "message": "Unauthorized"}))
    };

    if claims.role != "super_admin" && claims.role != "admin" {
        return Json(json!({"status": "error", "message": "Unauthorized"}));
    }

    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    let cpu_usage_percent = sys.global_cpu_info().cpu_usage();
    let memory_total_bytes = sys.total_memory();
    let memory_used_bytes = sys.used_memory();
    let memory_total_gb = memory_total_bytes as f64 / 1_073_741_824.0;
    let memory_used_gb = memory_used_bytes as f64 / 1_073_741_824.0;
    let memory_percent = if memory_total_bytes > 0 {
        (memory_used_bytes as f64 / memory_total_bytes as f64) * 100.0
    } else {
        0.0
    };

    let stats = state.ch_storage.get_stats().await.unwrap_or(json!({}));
    let events_1h = stats.get("events_1h").and_then(|v| v.as_u64()).unwrap_or(0);
    let events_per_sec = events_1h / 3600;

    Json(json!({
        "status": "ok",
        "cpu_usage_percent": cpu_usage_percent,
        "memory_used_gb": memory_used_gb,
        "memory_total_gb": memory_total_gb,
        "memory_percent": memory_percent,
        "events_per_sec": events_per_sec,
        "events_1h": events_1h
    }))
}

// ── Background: Arkime → pcap_sessions proactive sync ────────────────────────
// Called once from main.rs on startup (after 30s delay), then loops every 5 min.
// Fetches the last 5-min window from Arkime for every active tenant and caches
// results into pcap_sessions so the UI is pre-populated without a user visit.
pub async fn sync_arkime_sessions(state: AppState) {
    // Create one shared HTTP client for all tenants / all cycles.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("reqwest::Client::builder failed in sync_arkime_sessions");

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;

        let tenants = match state.ch_storage.get_all_tenants().await {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!("Arkime sync: could not fetch tenants: {}", e);
                continue;
            }
        };

        for tenant_id in &tenants {
            let (arkime_url, arkime_pass) =
                match state.ch_storage.get_arkime_creds(tenant_id).await {
                    Ok(creds) if !creds.0.is_empty() => creds,
                    _ => continue, // tenant has no Arkime configured
                };

            // Query the last 6 minutes (60s overlap guards against boundary gaps)
            let now = chrono::Utc::now().timestamp();
            let window_start = now - 360;

            let query_url = format!(
                "{}/api/sessions?\
length=1000\
&startTime={}&stopTime={}\
&fields=id,network.community_id,\
source.ip,source.port,\
destination.ip,destination.port,\
ipProtocol,network.bytes,\
network.packets,firstPacket,\
lastPacket,node",
                arkime_url, window_start, now
            );

            let resp = match client
                .get(&query_url)
                .basic_auth("admin", Some(&arkime_pass))
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(
                        "Arkime sync: HTTP error tenant={}: {}",
                        tenant_id, e
                    );
                    continue;
                }
            };

            let data = match resp.json::<serde_json::Value>().await {
                Ok(d) => d,
                Err(_) => continue,
            };

            let sessions = match data["data"].as_array() {
                Some(s) => s.clone(),
                None => continue,
            };

            let mut saved = 0u32;
            for s in &sessions {
                let session_id = s["id"]
                    .as_str()
                    .or_else(|| s["_id"].as_str())
                    .unwrap_or("")
                    .to_string();
                if session_id.is_empty() {
                    continue;
                }

                let community_id = s["network"]["community_id"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();

                // Arkime 5 returns flat dotted keys; older versions return nested.
                let src_ip = s.get("source.ip").and_then(|v| v.as_str())
                    .or_else(|| s["source"]["ip"].as_str())
                    .or_else(|| s["srcIp"].as_str())
                    .unwrap_or("").to_string();
                let dst_ip = s.get("destination.ip").and_then(|v| v.as_str())
                    .or_else(|| s["destination"]["ip"].as_str())
                    .or_else(|| s["dstIp"].as_str())
                    .unwrap_or("").to_string();
                let src_port = s.get("source.port").and_then(|v| v.as_u64())
                    .or_else(|| s["source"]["port"].as_u64())
                    .or_else(|| s["srcPort"].as_u64())
                    .unwrap_or(0) as u16;
                let dst_port = s.get("destination.port").and_then(|v| v.as_u64())
                    .or_else(|| s["destination"]["port"].as_u64())
                    .or_else(|| s["dstPort"].as_u64())
                    .unwrap_or(0) as u16;
                let ip_proto = s["ipProtocol"].as_u64()
                    .or_else(|| s.get("ipProtocol").and_then(|v| v.as_u64()))
                    .unwrap_or(0);
                let proto = if ip_proto == 6 { "tcp" }
                            else if ip_proto == 17 { "udp" }
                            else { "other" };
                let bytes = s.get("network.bytes").and_then(|v| v.as_u64())
                    .or_else(|| s["network"]["bytes"].as_u64())
                    .or_else(|| s["totBytes"].as_u64())
                    .unwrap_or(0);
                let sensor_host = s["node"].as_str().unwrap_or("").to_string();

                if state.ch_storage.save_pcap_session(
                    tenant_id,
                    &session_id,
                    &community_id,
                    &src_ip,
                    &dst_ip,
                    src_port,
                    dst_port,
                    proto,
                    bytes,
                    &arkime_url,
                    "",
                    &sensor_host,
                ).await.is_ok() {
                    saved += 1;
                }
            }

            if saved > 0 {
                tracing::info!(
                    "Arkime sync: saved {} sessions for tenant={}",
                    saved, tenant_id
                );
            }
        }
    }
}

// ── NATIVE SOAR API ENDPOINTS ───────────────────────────────────────────────

#[cfg(feature = "soar")]
pub async fn get_soar_cases(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
) -> Json<Value> {
    match state.ch_storage.get_soar_cases(&claims.tenant_id, &claims.sensor_ids).await {
        Ok(cases) => Json(json!({"status": "success", "data": cases})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

#[cfg(feature = "soar")]
pub async fn get_soar_case_comments(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
) -> Json<Value> {
    match state.ch_storage.get_soar_case_comments(&id, &claims.tenant_id).await {
        Ok(comments) => Json(json!({"status": "success", "data": comments})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

#[cfg(feature = "soar")]
pub async fn add_soar_case_comment(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
    axum::extract::Json(payload): axum::extract::Json<Value>,
) -> Json<Value> {
    let comment = payload.get("comment").and_then(|v| v.as_str()).unwrap_or("");
    if comment.is_empty() {
        return Json(json!({"status": "error", "message": "Comment cannot be empty"}));
    }
    match state.ch_storage.insert_soar_case_comment(&id, &claims.sub, comment, &claims.tenant_id).await {
        Ok(_) => Json(json!({"status": "success", "message": "Comment added"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

#[cfg(feature = "soar")]
pub async fn update_soar_case_status(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
    axum::extract::Json(payload): axum::extract::Json<Value>,
) -> Json<Value> {
    let status = payload.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if status.is_empty() {
        return Json(json!({"status": "error", "message": "Status cannot be empty"}));
    }
    match state.ch_storage.update_soar_case_status(&id, status, &claims.tenant_id).await {
        Ok(_) => Json(json!({"status": "success", "message": "Status updated"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

#[cfg(feature = "soar")]
pub async fn create_soar_case(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
    axum::extract::Json(payload): axum::extract::Json<Value>,
) -> Json<Value> {
    let title = payload.get("title").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if title.is_empty() {
        return Json(json!({"status": "error", "message": "Title is required"}));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let case_number = state.ch_storage.get_next_case_number(&claims.tenant_id).await;
    let description = payload.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let severity    = payload.get("severity").and_then(|v| v.as_str()).unwrap_or("MEDIUM").to_string();
    let priority    = payload.get("priority").and_then(|v| v.as_str()).unwrap_or("P2").to_string();
    let assigned_to = payload.get("assigned_to").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let src_ip      = payload.get("src_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let dst_ip      = payload.get("dst_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let community_id = payload.get("community_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let tags: Vec<String> = payload.get("tags")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|t| t.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    match state.ch_storage.insert_soar_case(
        &id, &case_number, &title, &description, &severity, &priority,
        "New", &assigned_to, &src_ip, &dst_ip, &community_id, &tags, &claims.tenant_id,
    ).await {
        Ok(_) => Json(json!({"status": "success", "id": id, "case_number": case_number})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

#[cfg(feature = "soar")]
pub async fn update_soar_case(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
    axum::extract::Json(payload): axum::extract::Json<Value>,
) -> Json<Value> {
    let title       = payload.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let description = payload.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let assigned_to = payload.get("assigned_to").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let priority    = payload.get("priority").and_then(|v| v.as_str()).unwrap_or("P2").to_string();
    let severity    = payload.get("severity").and_then(|v| v.as_str()).unwrap_or("MEDIUM").to_string();
    match state.ch_storage.update_soar_case_fields(&id, &title, &description, &assigned_to, &priority, &severity, &claims.tenant_id).await {
        Ok(_) => Json(json!({"status": "success", "message": "Case updated"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

#[cfg(feature = "soar")]
pub async fn get_native_playbooks(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
) -> Json<Value> {
    match state.ch_storage.get_native_playbooks(&claims.tenant_id).await {
        Ok(pbs) => Json(json!({"status": "success", "data": pbs})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

#[cfg(feature = "soar")]
pub async fn create_native_playbook(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
    axum::extract::Json(payload): axum::extract::Json<Value>,
) -> Json<Value> {
    let pb = crate::soar::SoarNativePlaybook {
        id: uuid::Uuid::new_v4().to_string(),
        name: payload.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        description: payload.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        enabled: payload.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true) as u8,
        cond_field: payload.get("cond_field").and_then(|v| v.as_str()).unwrap_or("score").to_string(),
        cond_op: payload.get("cond_op").and_then(|v| v.as_str()).unwrap_or(">").to_string(),
        cond_value: payload.get("cond_value").and_then(|v| v.as_str()).unwrap_or("75").to_string(),
        action_type: payload.get("action_type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        action_config: payload.get("action_config").and_then(|v| v.as_str()).unwrap_or("{}").to_string(),
        run_count: 0,
        last_run: None,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        tenant_id: claims.tenant_id,
    };

    match state.ch_storage.insert_native_playbook(&pb).await {
        Ok(_) => Json(json!({"status": "success", "message": "Playbook created"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

#[cfg(feature = "soar")]
pub async fn update_native_playbook(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
    axum::extract::Json(payload): axum::extract::Json<Value>,
) -> Json<Value> {
    let name        = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let description = payload.get("description").and_then(|v| v.as_str()).unwrap_or("");
    let enabled     = payload.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true) as u8;
    let cond_field  = payload.get("cond_field").and_then(|v| v.as_str()).unwrap_or("");
    let cond_op     = payload.get("cond_op").and_then(|v| v.as_str()).unwrap_or("");
    let cond_value  = payload.get("cond_value").and_then(|v| v.as_str()).unwrap_or("");
    let action_type = payload.get("action_type").and_then(|v| v.as_str()).unwrap_or("");
    let action_config = payload.get("action_config").and_then(|v| v.as_str()).unwrap_or("{}");

    match state.ch_storage.update_native_playbook(
        &id, name, description, enabled, cond_field, cond_op, cond_value, action_type, action_config, &claims.tenant_id
    ).await {
        Ok(_) => Json(json!({"status": "success", "message": "Playbook updated"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

#[cfg(feature = "soar")]
pub async fn delete_native_playbook(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
) -> Json<Value> {
    match state.ch_storage.delete_native_playbook(&id, &claims.tenant_id).await {
        Ok(_) => Json(json!({"status": "success", "message": "Playbook deleted"})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}

#[cfg(feature = "soar")]
pub async fn get_soar_runs(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<AuthClaims>,
) -> Json<Value> {
    match state.ch_storage.get_soar_playbook_runs(&claims.tenant_id, &claims.sensor_ids).await {
        Ok(runs) => Json(json!({"status": "success", "data": runs})),
        Err(e) => Json(json!({"status": "error", "message": e.to_string()}))
    }
}



// ============================================================
// EVIDENCE MODULE
// ============================================================



/// POST /api/evidence/trigger
/// Trigger evidence bundle capture in background for a given community_id.
/// Returns 202 immediately; build runs async (same path as alert auto-capture).
#[derive(serde::Deserialize)]
pub struct TriggerEvidenceBody { pub community_id: String }

pub async fn trigger_evidence_capture(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(body): axum::extract::Json<TriggerEvidenceBody>,
) -> impl axum::response::IntoResponse {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return (axum::http::StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"error":"unauthorized"}))),
    };

    let cid     = body.community_id.clone();
    let tenant  = claims.tenant_id.clone();
    let ch      = state.ch_storage.clone();

    let alert_json = ch.get_hit_by_community_id(&tenant, &cid).await
        .unwrap_or_default()
        .unwrap_or(serde_json::json!({"community_id": cid, "timestamp": chrono::Utc::now().to_rfc3339()}));

    let opensearch_url = if tenant == "default" {
        std::env::var("OPENSEARCH_URL").unwrap_or_else(|_| "http://localhost:9200".to_string())
    } else {
        String::new()
    };
    let arkime_url  = std::env::var("ARKIME_URL").unwrap_or_default();
    let arkime_pass = std::env::var("ARKIME_PASS").unwrap_or_else(|_| "admin".to_string());
    let pcap_path   = if tenant != "default" {
        ch.get_pcap_file_path_by_community_id(&tenant, &cid).await.unwrap_or_default()
    } else { None };

    tokio::spawn(async move {
        let _permit = evidence_semaphore().acquire_owned().await;
        match crate::evidence::build_evidence_bundle(
            &opensearch_url, &arkime_url, &arkime_pass,
            &cid, alert_json, &tenant, pcap_path,
        ).await {
            Ok((zip_bytes, bundle_sha256, manifest)) => {
                let bundle_id = manifest["bundle_id"].as_str().unwrap_or("").to_string();
                let src_ip    = manifest["summary"]["src_ip"].as_str().unwrap_or("").to_string();
                let dst_ip    = manifest["summary"]["dst_ip"].as_str().unwrap_or("").to_string();
                let severity  = manifest["summary"]["severity"].as_str().unwrap_or("UNKNOWN").to_string();
                let date      = chrono::Utc::now().format("%Y-%m-%d").to_string();
                let dir       = format!("/opt/ndr/evidence/{}/{}", tenant, date);
                let _ = tokio::fs::create_dir_all(&dir).await;
                let file_path = format!("{}/{}.zip", dir, bundle_id);
                let size      = zip_bytes.len() as u64;
                if tokio::fs::write(&file_path, &zip_bytes).await.is_ok() {
                    let _ = ch.save_evidence_bundle(
                        &tenant, &bundle_id, &cid,
                        &file_path, &bundle_sha256, size,
                        0, // manual capture (not auto)
                        90, &src_ip, &dst_ip, &severity, &cid,
                    ).await;
                }
                tracing::info!("Manual collect-pcap triggered bundle {} for cid {}", bundle_id, cid);

                // Queue PCAP upload for the sensor to pull.
                // Case community_id may not be "1:xxx" format — look up real
                // network community IDs from ndr_events using src/dst IP.
                let cids_to_queue: Vec<String> = if cid.starts_with("1:") {
                    vec![cid.clone()]
                } else if !src_ip.is_empty() && !dst_ip.is_empty() {
                    #[derive(clickhouse::Row, serde::Deserialize)]
                    struct CidRow { community_id: String }
                    ch.client
                        .query(&format!(
                            "SELECT DISTINCT community_id \
                             FROM {}.ndr_events \
                             WHERE ((src_ip = '{}' AND dst_ip = '{}') \
                                 OR (src_ip = '{}' AND dst_ip = '{}')) \
                             AND community_id LIKE '1:%' \
                             AND timestamp > now() - INTERVAL 24 HOUR \
                             LIMIT 10",
                            crate::storage::clickhouse::tenant_db_pub(&tenant),
                            sql_escape(&src_ip), sql_escape(&dst_ip),
                            sql_escape(&dst_ip), sql_escape(&src_ip),
                        ))
                        .fetch_all::<CidRow>().await
                        .unwrap_or_default()
                        .into_iter().map(|r| r.community_id).collect()
                } else {
                    vec![]
                };

                for flow_cid in &cids_to_queue {
                    let _ = ch.queue_pcap_request(&tenant, flow_cid).await;
                }
                if !cids_to_queue.is_empty() {
                    tracing::info!(
                        "Queued pcap_pending for {} flow(s) (case cid={})",
                        cids_to_queue.len(), cid
                    );
                }
            }
            Err(e) => tracing::warn!("trigger_evidence_capture failed for cid {}: {}", cid, e),
        }
    });

    (axum::http::StatusCode::ACCEPTED, axum::Json(serde_json::json!({"status":"collection triggered"})))
}

/// GET /api/evidence/:community_id
/// Build and return a ZIP evidence bundle for a community_id.
pub async fn download_evidence_bundle(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(community_id): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::http::HeaderMap::new(),
            axum::body::Bytes::new(),
        ),
    };

    // Get alert context for this community_id
    let alert_json = state.ch_storage
        .get_hit_by_community_id(&claims.tenant_id, &community_id)
        .await
        .unwrap_or_default()
        .unwrap_or(serde_json::json!({"community_id": community_id}));

    // Determine PCAP source (on-premise vs remote)
    let opensearch_url = if claims.tenant_id == "default" {
        std::env::var("OPENSEARCH_URL")
            .unwrap_or_else(|_| String::from("http://localhost:9200"))
    } else {
        String::new()
    };

    let arkime_url = std::env::var("ARKIME_URL").unwrap_or_default();
    let arkime_pass = std::env::var("ARKIME_PASS")
        .unwrap_or_else(|_| String::from("admin"));

    // For remote tenants, check if we have an uploaded PCAP
    let pcap_file_path = if claims.tenant_id != "default" {
        state.ch_storage
            .get_pcap_file_path_by_community_id(&claims.tenant_id, &community_id)
            .await
            .unwrap_or_default()
    } else {
        None
    };

    match evidence::build_evidence_bundle(
        &opensearch_url,
        &arkime_url,
        &arkime_pass,
        &community_id,
        alert_json,
        &claims.tenant_id,
        pcap_file_path,
    ).await {
        Ok((zip_bytes, bundle_sha256, manifest)) => {
            // Persist bundle record to evidence_bundles table
            let bundle_id = manifest["bundle_id"].as_str().unwrap_or("").to_string();
            let src_ip = manifest["summary"]["src_ip"].as_str().unwrap_or("").to_string();
            let dst_ip = manifest["summary"]["dst_ip"].as_str().unwrap_or("").to_string();
            let severity = manifest["summary"]["severity"].as_str().unwrap_or("UNKNOWN").to_string();
            let zip_size = zip_bytes.len() as u64;
            let ch = state.ch_storage.clone();
            let tid = claims.tenant_id.clone();
            let cid = community_id.clone();
            let sha = bundle_sha256.clone();
            tokio::spawn(async move {
                let _ = ch.save_evidence_bundle(
                    &tid, &bundle_id, &cid,
                    "",          // file_path: on-demand, no disk file
                    &sha,
                    zip_size,
                    0,           // auto_captured: 0 = manual download
                    90,          // expires_days
                    &src_ip, &dst_ip, &severity,
                    &cid,
                ).await;
            });

            // Log to chain of custody
            let _ = state.ch_storage.log_evidence_action(
                &claims.tenant_id,
                &community_id,
                "",
                "downloaded",
                &claims.sub,
                "",
                "", "",
                "Manual evidence download",
                headers.get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("unknown"),
            ).await;

            let filename = format!(
                "evidence_{}_{}.zip",
                community_id.replace(':', "_").replace('/', "_"),
                chrono::Utc::now().format("%Y%m%d_%H%M%S")
            );

            let mut resp_headers = axum::http::HeaderMap::new();
            resp_headers.insert(
                "Content-Type",
                "application/zip".parse().unwrap()
            );
            resp_headers.insert(
                "Content-Disposition",
                format!("attachment; filename=\"{}\"", filename)
                    .parse().unwrap()
            );
            resp_headers.insert(
                "X-Evidence-SHA256",
                bundle_sha256.parse().unwrap()
            );

            (
                axum::http::StatusCode::OK,
                resp_headers,
                axum::body::Bytes::from(zip_bytes),
            )
        }
        Err(e) => {
            tracing::error!("Evidence bundle error: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::http::HeaderMap::new(),
                axum::body::Bytes::new(),
            )
        }
    }
}

/// GET /api/evidence/bundles
/// List all evidence bundles for this tenant.
pub async fn list_evidence_bundles(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let limit = params.get("limit")
        .and_then(|l| l.parse::<u32>().ok())
        .unwrap_or(50);
    let bundles = state.ch_storage
        .list_evidence_bundles(&claims.tenant_id, limit, &claims.sensor_ids)
        .await.unwrap_or_default();
    Json(json!({"bundles": bundles, "count": bundles.len()}))
}

/// GET /api/evidence/bundle/:bundle_id
/// Get a specific bundle by ID.
pub async fn get_evidence_bundle(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(bundle_id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    match state.ch_storage
        .get_evidence_bundle(&claims.tenant_id, &bundle_id)
        .await
    {
        Ok(Some(b)) => Json(json!({"bundle": b})),
        Ok(None) => Json(json!({"error": "not found"})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

/// GET /api/evidence/bundle/:id/contents
/// Returns live ClickHouse data augmented with PCAP/session info from the stored ZIP.
/// Always queries live to avoid stale data from bundles captured before Zeek data arrived.
pub async fn get_bundle_contents(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(bundle_id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };

    let bundle = match state.ch_storage
        .get_evidence_bundle(&claims.tenant_id, &bundle_id)
        .await
    {
        Ok(Some(b)) => b,
        _ => return Json(json!({"error": "bundle not found"})),
    };

    let community_id = bundle["community_id"].as_str().unwrap_or("").to_string();
    if community_id.is_empty() {
        return Json(json!({"error": "bundle has no community_id"}));
    }

    // Read ZIP only to extract PCAP size and session_metadata
    let mut pcap_size: u64 = 0;
    let mut session_metadata = json!({});
    let mut alert_from_zip = json!({});

    if let Some(file_path) = bundle["file_path"].as_str().filter(|p| !p.is_empty()) {
        if let Ok(zip_bytes) = tokio::fs::read(file_path).await {
            let cursor = std::io::Cursor::new(&zip_bytes);
            if let Ok(mut archive) = zip::ZipArchive::new(cursor) {
                for i in 0..archive.len() {
                    let mut file = match archive.by_index(i) {
                        Ok(f) => f,
                        Err(_) => continue,
                    };
                    let name = file.name().to_string();
                    if name == "session_metadata.json" {
                        let mut text = String::new();
                        use std::io::Read;
                        let _ = file.read_to_string(&mut text);
                        session_metadata = serde_json::from_str(&text).unwrap_or(json!({}));
                    } else if name == "alert.json" {
                        let mut text = String::new();
                        use std::io::Read;
                        let _ = file.read_to_string(&mut text);
                        alert_from_zip = serde_json::from_str(&text).unwrap_or(json!({}));
                    } else if name.ends_with(".pcap") {
                        pcap_size = file.size();
                    }
                }
            }
        }
    }

    // Fetch all investigation data live from ClickHouse
    let mut live = evidence::fetch_live_investigation(
        &community_id,
        &claims.tenant_id,
        &alert_from_zip,
        &session_metadata,
    ).await;

    // If ZIP has no PCAP (bundle created before upload), check pcap_sessions live
    if pcap_size == 0 {
        if let Ok(fp) = state.ch_storage
            .get_pcap_file_path_by_community_id(&claims.tenant_id, &community_id)
            .await
        {
            if let Some(path) = fp {
                if let Ok(meta) = tokio::fs::metadata(&path).await {
                    pcap_size = meta.len();
                }
            }
        }
    }

    // Live OpenSearch check — same pattern as arkime_sessions endpoint.
    // ZIP pcap_size is stale (built before Arkime ran); always check current state.
    let es_url = std::env::var("OPENSEARCH_URL").unwrap_or_default();
    let http_cli = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let os_hit: Option<serde_json::Value> = if !es_url.is_empty() {
        async {
            let resp = http_cli
                .post(format!("{}/arkime_sessions3-*/_search", es_url))
                .json(&json!({
                    "size": 1,
                    "query": { "term": { "network.community_id": community_id } },
                    "_source": ["node","firstPacket","lastPacket",
                                "source.ip","source.port",
                                "destination.ip","destination.port"]
                }))
                .send().await.ok()?
                .json::<serde_json::Value>().await.ok()?;
            resp["hits"]["hits"].as_array()?.first().cloned()
        }.await
    } else { None };

    let (pcap_available, resolved_session_meta) = match os_hit {
        Some(hit) => {
            let sid = hit["_id"].as_str().unwrap_or("").to_string();
            let meta = json!({
                "arkime_session_id": sid,
                "index":        hit["_index"],
                "node":         hit["_source"]["node"],
                "first_packet": hit["_source"]["firstPacket"],
                "last_packet":  hit["_source"]["lastPacket"],
                "community_id": community_id,
                "query_source": "opensearch"
            });
            (!sid.is_empty(), meta)
        }
        None => (pcap_size > 0, session_metadata),
    };

    // Override threat_intel using the live in-memory feed (same as Intel page).
    // The evidence module queries empty ClickHouse tables; this is the correct source.
    {
        let ti = &state.enrichment.threat_intel;
        let src_ip = alert_from_zip["src_ip"].as_str()
            .or_else(|| live["alert"]["src_ip"].as_str())
            .unwrap_or("");
        let dst_ip = alert_from_zip["dst_ip"].as_str()
            .or_else(|| live["alert"]["dst_ip"].as_str())
            .unwrap_or("");

        let mut checked: Vec<&str> = vec![];
        let mut matches: Vec<serde_json::Value> = vec![];

        for ip in [src_ip, dst_ip].iter().filter(|s| !s.is_empty()) {
            checked.push(ip);
            if ti.is_malicious_ip(ip) {
                matches.push(json!({
                    "ioc_type":   "ip",
                    "ioc_value":  ip,
                    "source":     "abuse.ch",
                    "confidence": 90,
                    "description": format!("{} is listed in the abuse.ch malicious IP feed (Feodo Tracker)", ip)
                }));
            }
        }

        let live_threat_intel = json!({
            "checked_ips": checked,
            "matches":     matches,
            "source":      "in-memory (Feodo Tracker / abuse.ch)"
        });

        if let Some(obj) = live.as_object_mut() {
            obj.insert("threat_intel".to_string(), live_threat_intel);
        }
    }

    if let Some(obj) = live.as_object_mut() {
        obj.insert("pcap_size_bytes".to_string(),  json!(pcap_size));
        obj.insert("pcap_available".to_string(),   json!(pcap_available));
        obj.insert("session_metadata".to_string(), resolved_session_meta);
        obj.insert("bundle_id".to_string(),        json!(bundle_id));
    }

    Json(live)
}

/// GET /api/evidence/:community_id/log
/// Return full chain-of-custody log.
pub async fn get_evidence_log(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(community_id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let log = state.ch_storage
        .get_evidence_log(&claims.tenant_id, &community_id)
        .await.unwrap_or_default();
    Json(json!({"community_id": community_id, "log": log}))
}

/// GET /api/evidence/bundle/:bundle_id/verify
/// Rebuild the bundle in memory and compare its SHA256 to the stored hash.
/// Bundles are generated on-demand (never written to disk), so verification
/// re-runs the same build pipeline and hashes the result.
pub async fn verify_evidence_bundle(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(bundle_id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let bundle = match state.ch_storage
        .get_evidence_bundle(&claims.tenant_id, &bundle_id)
        .await
    {
        Ok(Some(b)) => b,
        _ => return Json(json!({"error": "bundle not found"})),
    };

    let stored_sha256 = bundle["sha256"].as_str().unwrap_or("").to_string();
    let file_path     = bundle["file_path"].as_str().unwrap_or("").to_string();

    // Integrity check: hash the stored ZIP file on disk and compare.
    // Rebuilding from live ClickHouse data was wrong — Zeek logs and events
    // accumulate after capture, so the rebuilt ZIP always differs → false TAMPERED.
    let (matches, computed_sha256) = if file_path.is_empty() {
        (false, "no_file_path_stored".to_string())
    } else {
        match tokio::fs::read(&file_path).await {
            Ok(bytes) => {
                use sha2::Digest;
                let hash = format!("{:x}", sha2::Sha256::digest(&bytes));
                (hash == stored_sha256, hash)
            }
            Err(e) => (false, format!("file_read_error: {}", e))
        }
    };

    let status = if matches { "VERIFIED" } else { "TAMPERED_OR_CORRUPTED" };

    // Log the verification
    let _ = state.ch_storage.log_evidence_action(
        &claims.tenant_id,
        bundle["community_id"].as_str().unwrap_or(""),
        &bundle_id,
        &format!("integrity_check:{}", status),
        &claims.sub,
        "", "", "",
        &format!("stored_sha256={} computed_sha256={}", stored_sha256, computed_sha256),
        "",
    ).await;

    Json(json!({
        "bundle_id": bundle_id,
        "status": status,
        "stored_sha256": stored_sha256,
        "computed_sha256": computed_sha256,
        "verified_at": chrono::Utc::now().to_rfc3339(),
        "verified_by": claims.sub
    }))
}

/// POST /api/evidence/bundle/:bundle_id/hold
/// Set or clear legal hold on a bundle.
/// Body: { "hold": true, "reason": "Active criminal investigation case #1234" }
pub async fn set_evidence_legal_hold(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(bundle_id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let hold = payload["hold"].as_bool().unwrap_or(true);
    let reason = payload["reason"].as_str().unwrap_or("").to_string();

    if hold && reason.is_empty() {
        return Json(json!({
            "error": "reason required when setting legal hold"
        }));
    }

    let _ = state.ch_storage.set_legal_hold(
        &claims.tenant_id,
        &bundle_id,
        if hold { 1 } else { 0 },
        &reason,
        &claims.sub,
    ).await;

    let action = if hold {
        "legal_hold_set"
    } else {
        "legal_hold_cleared"
    };
    let _ = state.ch_storage.log_evidence_action(
        &claims.tenant_id, "", &bundle_id,
        action, &claims.sub,
        "", "", "", &reason, "",
    ).await;

    Json(json!({
        "bundle_id": bundle_id,
        "legal_hold": hold,
        "reason": reason,
        "set_by": claims.sub,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// POST /api/evidence/bundle/:bundle_id/annotate
/// Add analyst note/tag to a bundle.
/// Body: { "note": "Confirmed C2 callback", "tag": "confirmed_malicious" }
pub async fn annotate_evidence_bundle(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(bundle_id): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let note = payload["note"].as_str().unwrap_or("").to_string();
    let tag = payload["tag"].as_str().unwrap_or("").to_string();
    let community_id = payload["community_id"]
        .as_str().unwrap_or("").to_string();

    let _ = state.ch_storage.add_evidence_annotation(
        &claims.tenant_id,
        &bundle_id,
        &community_id,
        &claims.sub,
        &note,
        &tag,
    ).await;

    let _ = state.ch_storage.log_evidence_action(
        &claims.tenant_id, &community_id, &bundle_id,
        "annotated", &claims.sub,
        "", "", "", &note, "",
    ).await;

    Json(json!({"status": "ok", "bundle_id": bundle_id}))
}

/// GET /api/evidence/bundle/:bundle_id/annotations
pub async fn get_evidence_annotations(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(bundle_id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let annotations = state.ch_storage
        .get_annotations(&claims.tenant_id, &bundle_id)
        .await.unwrap_or_default();
    Json(json!({"bundle_id": bundle_id, "annotations": annotations}))
}

/// GET /api/evidence/:community_id/timeline
/// Attack story reconstruction — stitch together events in time order.
pub async fn get_evidence_timeline(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(community_id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };

    // 1. Get the primary alert/hit
    let hit = state.ch_storage
        .get_hit_by_community_id(&claims.tenant_id, &community_id)
        .await.unwrap_or_default()
        .unwrap_or(json!({}));

    let src_ip = hit["src_ip"].as_str().unwrap_or("").to_string();
    let dst_ip = hit["dst_ip"].as_str().unwrap_or("").to_string();
    let alert_time = hit["timestamp"].as_str().unwrap_or("").to_string();
    let severity = hit["severity"].as_str().unwrap_or("").to_string();
    let rule_name = hit["rule_name"].as_str().unwrap_or("").to_string();

    // 2a. All detection rules that fired on this exact CID
    let rule_hits = state.ch_storage
        .get_rule_hits_by_community_id(&claims.tenant_id, &community_id)
        .await.unwrap_or_default();

    // 2b. Related hits from same src_ip in ±30 min (different CIDs)
    let related = state.ch_storage
        .get_related_hits_by_ip(&claims.tenant_id, &src_ip, &alert_time, 30)
        .await.unwrap_or_default();

    // 2c. UID-linked Zeek logs — find all log types for the same connection
    //     Step 1: find the Zeek UID from ndr_events matching this community_id
    //     Step 2: pull every log entry with that UID (conn/dns/ssl/http/weird/quic)
    let db = crate::storage::clickhouse::tenant_db_pub(&claims.tenant_id);
    let t  = crate::storage::clickhouse::sql_escape_pub(&claims.tenant_id);
    let cid_esc = crate::storage::clickhouse::sql_escape_pub(&community_id);

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct UidRow { uid: String }

    // Collect ALL Zeek UIDs for this community_id (one connection can have multiple UIDs
    // e.g. conn.log splits a long session; pick all so we get http/files/weird entries)
    let uid_rows: Vec<UidRow> = state.ch_storage.client
        .query(&format!(
            "SELECT DISTINCT JSONExtractString(raw, 'uid') AS uid \
             FROM {db}.ndr_events \
             WHERE tenant_id = '{t}' \
               AND community_id = '{cid_esc}' \
               AND JSONExtractString(raw, 'uid') != '' \
             LIMIT 10"
        ))
        .fetch_all::<UidRow>().await.unwrap_or_default();

    // Representative UID for display (first one)
    let zeek_uid = uid_rows.first().map(|r| r.uid.clone()).unwrap_or_default();

    // Step 2: logs for ALL UIDs combined, ordered by time
    let uid_logs: Vec<Value> = if !zeek_uid.is_empty() {
        let uid_list = uid_rows.iter()
            .map(|r| format!("'{}'", crate::storage::clickhouse::sql_escape_pub(&r.uid)))
            .collect::<Vec<_>>()
            .join(", ");
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct UidLog {
            event_type: String,
            ts:         f64,
            raw:        String,
        }
        let rows: Vec<UidLog> = state.ch_storage.client
            .query(&format!(
                "SELECT event_type, \
                        toFloat64(timestamp) AS ts, \
                        raw \
                 FROM {db}.ndr_events \
                 WHERE tenant_id = '{t}' \
                   AND JSONExtractString(raw, 'uid') IN ({uid_list}) \
                 ORDER BY ts ASC \
                 LIMIT 100"
            ))
            .fetch_all::<UidLog>().await.unwrap_or_default();

        rows.into_iter().map(|r| {
            let raw: Value = serde_json::from_str(&r.raw).unwrap_or(json!({}));
            let log_type = if r.event_type.is_empty() { "conn".to_string() } else { r.event_type.clone() };
            let description = match log_type.as_str() {
                "conn" => {
                    let state  = raw["conn_state"].as_str().unwrap_or("-");
                    let dur    = raw["duration"].as_f64().unwrap_or(0.0);
                    let bytes  = raw["orig_bytes"].as_u64().unwrap_or(0);
                    format!("Connection {} — {:.3}s, {} bytes sent", state, dur, bytes)
                }
                "dns" => {
                    let query   = raw["query"].as_str().unwrap_or("-");
                    let rcode   = raw["rcode_name"].as_str().unwrap_or("?");
                    let answers = raw["answers"].as_array()
                        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
                        .unwrap_or_default();
                    if answers.is_empty() {
                        format!("DNS query: {} → {}", query, rcode)
                    } else {
                        format!("DNS query: {} → {} [{}]", query, rcode, answers)
                    }
                }
                "ssl" => {
                    let sni     = raw["server_name"].as_str().unwrap_or("");
                    let ver     = raw["version"].as_str().unwrap_or("TLS");
                    let cipher  = raw["cipher"].as_str().unwrap_or("");
                    let resumed = raw["resumed"].as_bool().unwrap_or(false);
                    format!("TLS {} handshake{} — SNI: {} cipher: {}",
                        ver,
                        if resumed { " (resumed)" } else { "" },
                        if sni.is_empty() { "-" } else { sni },
                        cipher)
                }
                "http" => {
                    let method = raw["method"].as_str().unwrap_or("GET");
                    let host   = raw["host"].as_str().unwrap_or("-");
                    let uri    = raw["uri"].as_str().unwrap_or("/");
                    let status = raw["status_code"].as_u64().unwrap_or(0);
                    format!("HTTP {} {}{}  → {}", method, host, uri, status)
                }
                "weird" => {
                    let name = raw["name"].as_str().unwrap_or("unknown anomaly");
                    format!("Agent-Z anomaly: {}", name)
                }
                "quic" => {
                    let ver = raw["version"].as_str().unwrap_or("?");
                    format!("QUIC v{} connection", ver)
                }
                "files" => {
                    let mime = raw["mime_type"].as_str().unwrap_or("?");
                    let size = raw["total_bytes"].as_u64().unwrap_or(0);
                    format!("File transfer: {} ({} bytes)", mime, size)
                }
                _ => format!("{} event", log_type),
            };
            json!({
                "time":        (r.ts as u64) * 1000,
                "log_type":    log_type,
                "source":      "agent-z",
                "description": description,
                "uid":         zeek_uid,
                "raw":         raw,
            })
        }).collect()
    } else {
        vec![]
    };

    // Agent-S events for this CID — no UID, linked by community_id only.
    // Fetched separately and merged so the Connection Story shows Suricata alerts,
    // flow summaries, and DNS events alongside the Zeek UID-linked logs.
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct AgentSLog { event_type: String, ts: f64, raw: String }
    let agent_s_rows: Vec<AgentSLog> = state.ch_storage.client
        .query(&format!(
            "SELECT event_type, toFloat64(timestamp) AS ts, raw \
             FROM {db}.ndr_events \
             WHERE tenant_id = '{t}' \
               AND community_id = '{cid_esc}' \
               AND source = 'agent-s' \
             ORDER BY ts ASC \
             LIMIT 50"
        ))
        .fetch_all::<AgentSLog>().await.unwrap_or_default();

    let agent_s_logs: Vec<Value> = agent_s_rows.into_iter().map(|r| {
        let raw: Value = serde_json::from_str(&r.raw).unwrap_or(json!({}));
        let log_type = if r.event_type.is_empty() { "flow".to_string() } else { r.event_type.clone() };
        let description = match log_type.as_str() {
            "alert" => {
                let sig  = raw["alert"]["signature"].as_str().unwrap_or("Unknown rule");
                let sid  = raw["alert"]["signature_id"].as_u64().unwrap_or(0);
                let sev  = raw["alert"]["severity"].as_u64().unwrap_or(3);
                let slbl = match sev { 1 => "HIGH", 2 => "MEDIUM", _ => "LOW" };
                format!("Agent-S alert: {} (SID {} — {})", sig, sid, slbl)
            }
            "dns" => {
                // Suricata DNS raw: dns.type is "request"/"response",
                // name is in dns.queries[0].rrname (request) or dns.answers[0].rrname (response)
                let dtype = raw["dns"]["type"].as_str().unwrap_or("request");
                let qtype = if dtype == "response" { "response" } else { "request" };
                let name = raw["dns"]["rrname"].as_str()
                    .or_else(|| raw["dns"]["queries"][0]["rrname"].as_str())
                    .or_else(|| raw["dns"]["answers"][0]["rrname"].as_str())
                    .or_else(|| raw["query"].as_str())
                    .unwrap_or("-");
                let rcode = raw["dns"]["rcode"].as_str()
                    .or_else(|| raw["rcode_name"].as_str())
                    .unwrap_or("NOERROR");
                format!("Agent-S DNS {}: {} → {}", qtype, name, rcode)
            }
            "flow" | "netflow" => {
                let pkts  = raw["pkts_toserver"].as_u64()
                    .or_else(|| raw["packets"].as_u64()).unwrap_or(0);
                let bytes = raw["bytes_toserver"].as_u64()
                    .or_else(|| raw["bytes"].as_u64()).unwrap_or(0);
                let app   = raw["app_proto"].as_str().unwrap_or("");
                if app.is_empty() || app == "failed" {
                    format!("Agent-S flow summary: {} pkts, {} bytes", pkts, bytes)
                } else {
                    format!("Agent-S flow summary: {} pkts, {} bytes ({})", pkts, bytes, app)
                }
            }
            _ => format!("Agent-S {}", log_type),
        };
        json!({
            "time":        (r.ts as u64) * 1000,
            "log_type":    log_type,
            "source":      "agent-s",
            "description": description,
            "raw":         raw,
        })
    }).collect();

    // Merge Agent-Z (UID-linked) + Agent-S (CID-linked), sort by time
    let mut uid_logs = uid_logs;
    uid_logs.extend(agent_s_logs);
    uid_logs.sort_by_key(|e| e["time"].as_u64().unwrap_or(0));

    // 3. Get OpenSearch session info (on-premise)
    let session_info = if claims.tenant_id == "default" {
        let opensearch_url = std::env::var("OPENSEARCH_URL")
            .unwrap_or_else(|_| "http://localhost:9200".to_string());
        match state.http_client.post(format!(
            "{}/arkime_sessions3-*/_search", opensearch_url
        ))
        .json(&json!({
            "query": {"term": {"network.community_id": community_id}},
            "size": 1
        }))
        .send().await {
            Ok(r) => r.json::<Value>().await.unwrap_or(json!({})),
            Err(_) => json!({})
        }
    } else {
        json!({})
    };

    let session_src = &session_info["hits"]["hits"][0]["_source"];
    let src_bytes = session_src["network"]["bytes_toserver"]
        .as_u64().unwrap_or(0);
    let dst_bytes = session_src["network"]["bytes_toclient"]
        .as_u64().unwrap_or(0);
    let protocol = session_src["network"]["protocol"]
        .as_str().unwrap_or("unknown");

    // 4. Build ordered event timeline
    let mut events: Vec<Value> = vec![
        json!({
            "time": alert_time,
            "type": "connection",
            "description": format!(
                "{} → {} established {} connection",
                src_ip, dst_ip, protocol
            ),
            "community_id": community_id,
            "bytes_sent": src_bytes,
            "bytes_received": dst_bytes
        }),
        json!({
            "time": alert_time,
            "type": "alert",
            "description": format!(
                "NDR rule triggered: '{}' — severity {}",
                rule_name, severity
            ),
            "rule": rule_name,
            "severity": severity
        }),
    ];

    // Add related events
    for rel in &related {
        if rel["community_id"].as_str() != Some(&community_id) {
            events.push(json!({
                "time": rel["timestamp"],
                "type": "related_alert",
                "description": format!(
                    "Related activity: {} → {} ({})",
                    rel["src_ip"].as_str().unwrap_or(""),
                    rel["dst_ip"].as_str().unwrap_or(""),
                    rel["rule_name"].as_str().unwrap_or("")
                ),
                "community_id": rel["community_id"]
            }));
        }
    }

    // 5. Build attack narrative
    let dns_queries: Vec<&str> = uid_logs.iter()
        .filter(|e| e["log_type"] == "dns")
        .filter_map(|e| e["raw"]["query"].as_str())
        .collect();
    let tls_snis: Vec<&str> = uid_logs.iter()
        .filter(|e| e["log_type"] == "ssl")
        .filter_map(|e| e["raw"]["server_name"].as_str())
        .filter(|s| !s.is_empty())
        .collect();

    let narrative = format!(
        "At {}, host {} established a {} connection to {}. \
        NDR engine triggered rule '{}' with {} severity. \
        {} detection rule(s) fired on this connection. \
        {} log entries linked to this connection (UID: {}). \
        {} related activity events were detected for the same \
        source host within a 30-minute window, suggesting {}.",
        alert_time, src_ip, protocol, dst_ip,
        rule_name, severity,
        rule_hits.len(),
        uid_logs.len(),
        if zeek_uid.is_empty() { "—".to_string() } else { zeek_uid.clone() },
        related.len(),
        if related.len() > 3 {
            "possible lateral movement or automated attack pattern"
        } else {
            "isolated activity"
        }
    );

    Json(json!({
        "community_id":           community_id,
        "zeek_uid":               zeek_uid,
        "narrative":              narrative,
        "primary_alert":          hit,
        "events":                 events,
        "uid_logs":               uid_logs,
        "rule_hits":              rule_hits,
        "related_alerts":         related,
        "related_sessions_count": related.len(),
        "dns_queries":            dns_queries,
        "tls_snis":               tls_snis,
        "src_ip":                 src_ip,
        "dst_ip":                 dst_ip,
        "protocol":               protocol,
        "generated_at":           chrono::Utc::now().to_rfc3339()
    }))
}

/// GET /api/evidence/iocs/check?value=<ip_or_domain>
/// Check a value against the shared IOC database.
pub async fn check_shared_ioc(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let _ = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let value = params.get("value").map(String::as_str).unwrap_or("");
    match state.ch_storage.check_shared_ioc(value).await {
        Ok(Some(ioc)) => Json(json!({"found": true, "ioc": ioc})),
        Ok(None) => Json(json!({"found": false})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

// ═══════════════════════════════════════════
// ARIA SOC ASSISTANT CHAT ENDPOINT
// ═══════════════════════════════════════════

/// POST /api/aria/chat
/// Body: { "message": "...", "history": [...] }
/// Returns: { "reply": "...", "emotion": "..." }
pub async fn aria_chat(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {

    // Auth
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({
            "reply": "Unauthorized.",
            "emotion": "alert"
        })),
    };

    let user_message = match payload["message"]
        .as_str()
    {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => return Json(json!({
            "reply": "Empty message.",
            "emotion": "idle"
        })),
    };

    if claims.role != "super_admin" && !state.ch_storage.get_tenant_ai_enabled(&claims.tenant_id).await {
        return Json(json!({
            "reply": "AI features are not enabled for your organization. Contact your administrator.",
            "emotion": "neutral"
        }));
    }

    // Keep last 6 messages only — prevents prompt bloat on long conversations
    let history_full = payload["history"].as_array().cloned().unwrap_or_default();
    let history = if history_full.len() > 6 {
        history_full[history_full.len() - 6..].to_vec()
    } else {
        history_full
    };

    // Fetch live NDR context — counts + real data based on what user asked
    let (critical, high, bundles) = tokio::join!(
        state.ch_storage.count_hits_by_severity_aria(&claims.tenant_id, "CRITICAL", &claims.sensor_ids),
        state.ch_storage.count_hits_by_severity_aria(&claims.tenant_id, "HIGH", &claims.sensor_ids),
        state.ch_storage.count_evidence_bundles_aria(&claims.tenant_id, &claims.sensor_ids),
    );
    let real_context_raw = state.ch_storage
        .fetch_aria_context(&claims.tenant_id, &user_message, &claims.sensor_ids)
        .await;
    // Truncate context to avoid rate limits on free-tier AI providers (Groq: 6k TPM)
    let real_context: String = real_context_raw.chars().take(3000).collect();

    // Build system prompt with real tenant data only
    let system = crate::ai::build_system_prompt(
        &claims.sub,
        &claims.tenant_id,
        critical.unwrap_or(0),
        high.unwrap_or(0),
        bundles.unwrap_or(0),
        &real_context,
    );

    match crate::ai::provider::generate_chat(
        &state.ch_storage,
        &system,
        &history,
        &user_message,
    ).await {
        Ok((reply, emotion)) => Json(json!({
            "reply": reply,
            "emotion": emotion
        })),
        Err(e) => {
            tracing::error!("ARIA AI error: {}", e);
            Json(json!({
                "reply": "I'm having trouble connecting to the AI provider. \
                    Check AI configuration in Settings.",
                "emotion": "sad"
            }))
        }
    }
}

/// GET /api/aria/status
/// Returns live counts for bot status bar
pub async fn aria_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({
            "error": "unauthorized"
        })),
    };

    let critical = state.ch_storage
        .count_hits_by_severity_aria(
            &claims.tenant_id, "CRITICAL", &claims.sensor_ids)
        .await.unwrap_or(0);

    let high = state.ch_storage
        .count_hits_by_severity_aria(
            &claims.tenant_id, "HIGH", &claims.sensor_ids)
        .await.unwrap_or(0);

    let (latest_critical, rising_prediction) = tokio::join!(
        state.ch_storage.get_latest_critical_hit_for_aria(&claims.tenant_id, &claims.sensor_ids),
        state.ch_storage.get_rising_critical_prediction(&claims.tenant_id),
    );

    let latest_critical  = latest_critical.unwrap_or(None);
    let rising_prediction = rising_prediction.unwrap_or(None);

    let latest_severity = latest_critical
        .as_ref().and_then(|h| h["severity"].as_str()).unwrap_or("none").to_string();
    let latest_src = latest_critical
        .as_ref().and_then(|h| h["src_ip"].as_str()).unwrap_or("").to_string();
    let latest_dst = latest_critical
        .as_ref().and_then(|h| h["dst_ip"].as_str()).unwrap_or("").to_string();
    let latest_cid = latest_critical
        .as_ref().and_then(|h| h["community_id"].as_str()).unwrap_or("").to_string();

    // Rising prediction alert fields
    let pred_id        = rising_prediction.as_ref().and_then(|p| p["id"].as_str()).unwrap_or("").to_string();
    let pred_attack    = rising_prediction.as_ref().and_then(|p| p["attack_type"].as_str()).unwrap_or("").to_string();
    let pred_prob      = rising_prediction.as_ref().and_then(|p| p["probability"].as_f64()).unwrap_or(0.0);
    let pred_level     = rising_prediction.as_ref().and_then(|p| p["alert_level"].as_str()).unwrap_or("").to_string();
    let pred_expl      = rising_prediction.as_ref().and_then(|p| p["explanation"].as_str()).unwrap_or("").to_string();

    Json(json!({
        "critical_count":       critical,
        "high_count":           high,
        "latest_severity":      latest_severity,
        "latest_src_ip":        latest_src,
        "latest_dst_ip":        latest_dst,
        "latest_community_id":  latest_cid,
        "prediction_alert":     !pred_id.is_empty(),
        "prediction_id":        pred_id,
        "prediction_attack":    pred_attack,
        "prediction_prob":      pred_prob,
        "prediction_level":     pred_level,
        "prediction_expl":      pred_expl,
        "emotion": if critical > 0 || !pred_id.is_empty() { "alert" } else { "idle" }
    }))
}

/// POST /api/aria/investigate
/// Body: { "community_id": "..." }
/// Runs AI auto-investigation on the evidence bundle and returns + stores a verdict.
/// Also accepts GET /api/aria/investigate?cid=... to retrieve a cached verdict.
pub async fn aria_investigate(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };

    let community_id = match payload["community_id"].as_str().filter(|s| !s.is_empty()) {
        Some(cid) => cid.to_string(),
        None => return Json(json!({"error": "community_id required"})),
    };

    if claims.role != "super_admin" && !state.ch_storage.get_tenant_ai_enabled(&claims.tenant_id).await {
        return Json(json!({"error": "AI features are not enabled for your tenant. Contact your administrator."}));
    }

    match crate::ai::investigator::auto_investigate(
        &state.ch_storage,
        &claims.tenant_id,
        &community_id,
    ).await {
        Ok(verdict) => {
            let verdict_json = serde_json::to_string(&verdict).unwrap_or_default();
            if let Err(e) = state.ch_storage.save_aria_verdict(
                &claims.tenant_id,
                &community_id,
                &verdict_json,
            ).await {
                tracing::warn!("aria_investigate: failed to save verdict: {}", e);
            }
            Json(json!({
                "status":             "ok",
                "community_id":       community_id,
                "verdict":            verdict.verdict,
                "confidence":         verdict.confidence,
                "reasoning":          verdict.reasoning,
                "recommended_action": verdict.recommended_action,
                "mitre_techniques":   verdict.mitre_techniques,
                "generated_at":       verdict.generated_at,
            }))
        }
        Err(e) => {
            tracing::error!("aria_investigate: investigation failed: {}", e);
            Json(json!({"error": e.to_string()}))
        }
    }
}

/// GET /api/aria/verdict?cid=...
/// Retrieve a previously stored AI verdict without running a new investigation.
pub async fn aria_get_verdict(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };

    let community_id = raw_query
        .as_deref()
        .unwrap_or("")
        .split('&')
        .find_map(|kv| {
            let mut p = kv.splitn(2, '=');
            let k = p.next()?;
            let v = p.next().unwrap_or("");
            if k == "cid" { Some(percent_decode(v)) } else { None }
        })
        .unwrap_or_default();

    if community_id.is_empty() {
        return Json(json!({"error": "cid parameter required"}));
    }

    match state.ch_storage.get_aria_verdict(&claims.tenant_id, &community_id).await {
        Some(v) => Json(json!({"status": "ok", "verdict": v})),
        None    => Json(json!({"status": "not_found", "verdict": null})),
    }
}

/// GET /api/ai-suppressions — list active suppressions (used by UI to filter WS hits)
pub async fn list_ai_suppressions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"error": "unauthorized"})),
    };
    let tid = crate::storage::clickhouse::sql_escape_pub(&claims.tenant_id);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct SupRow {
        suppress_ip:    String,
        signature_name: String,
        community_id:   String,
        suppress_scope: String,
    }
    let rows: Vec<SupRow> = state.ch_storage.client
        .query(&format!(
            "SELECT suppress_ip, signature_name, community_id, suppress_scope \
             FROM {src} \
             WHERE active = 1 \
               AND (expires_at IS NULL OR expires_at > now()) \
               AND (tenant_id = '{tid}' OR tenant_id = '') \
             ORDER BY rowNumberInAllBlocks() DESC \
             LIMIT 200",
            src = crate::storage::clickhouse::suppressions_source(&claims.tenant_id),
        ))
        .fetch_all::<SupRow>().await.unwrap_or_default();

    let list: Vec<Value> = rows.into_iter().map(|r| json!({
        "suppress_ip":    r.suppress_ip,
        "signature_name": r.signature_name,
        "community_id":   r.community_id,
        "suppress_scope": r.suppress_scope,
    })).collect();
    Json(json!(list))
}

/// POST /api/ai-suppressions — analyst manually suppresses an alert pattern
#[derive(serde::Deserialize)]
pub struct ManualSuppressionBody {
    pub src_ip:       String,
    pub dst_ip:       Option<String>,
    pub community_id: Option<String>,
    pub tag:          Option<String>,
    pub duration_hours: Option<u32>,
}

pub async fn create_manual_suppression(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ManualSuppressionBody>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"error": "unauthorized"})),
    };
    let tag    = body.tag.as_deref().unwrap_or("manual");
    let dst_ip = body.dst_ip.as_deref().unwrap_or("");
    let cid    = body.community_id.as_deref().unwrap_or("");
    let hours  = body.duration_hours.unwrap_or(24) as u64;
    let now    = chrono::Utc::now().timestamp() as u64;
    let expires_at = Some((now + hours * 3600) as u32);

    // group = analyst suppressed the whole src_ip+tag group (no specific CID)
    // individual = analyst suppressed one specific alert by CID
    let suppress_scope = if cid.is_empty() { "group" } else { "individual" };
    let reason = format!("Manually suppressed by analyst ({}h)", hours);

    match state.ch_storage.save_ai_suppression(
        &claims.tenant_id,
        0, tag, "by_src", &body.src_ip,
        &body.src_ip, dst_ip, cid,
        &reason, 100, "",
        expires_at,
        suppress_scope,
    ).await {
        Ok(_)  => Json(json!({"ok": true, "suppressed_src": body.src_ip, "tag": tag, "expires_in_hours": hours})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

/// GET /api/ai-activity
/// Returns AI suppression decisions and AI evidence analysis annotations.
pub async fn get_ai_activity(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };

    let suppressions = state.ch_storage
        .list_ai_suppressions(&claims.tenant_id)
        .await
        .unwrap_or_default();

    let analyses = state.ch_storage
        .get_all_ai_annotations(&claims.tenant_id, &claims.sensor_ids)
        .await
        .unwrap_or_default();

    Json(json!({
        "suppressions": suppressions,
        "analyses": analyses
    }))
}

/// PATCH /api/ai-suppressions/:id/deactivate
pub async fn deactivate_ai_suppression_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    match state.ch_storage.deactivate_ai_suppression(&claims.tenant_id, &id).await {
        Ok(_) => Json(json!({"ok": true})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

/// DELETE /api/ai-suppressions/:id
pub async fn delete_ai_suppression_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    match state.ch_storage.delete_ai_suppression(&claims.tenant_id, &id).await {
        Ok(_) => Json(json!({"ok": true})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

pub async fn get_ipam_subnets(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = extract_claims(&headers);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id.clone()).unwrap_or_else(|| "default".to_string());
    let sensor_ids = claims.map(|c| c.sensor_ids).unwrap_or_default();
    match state.ch_storage.get_ipam_subnets(&tenant_id, &sensor_ids).await {
        Ok(subnets) => Json(json!(subnets)),
        Err(e)      => Json(json!({"error": e.to_string()})),
    }
}

// ── Threat Prediction Engine endpoints ───────────────────────────────────────

pub async fn get_threat_predictions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let limit = 20u32;
    match crate::threat::get_predictions(&state.ch_storage, &claims.tenant_id, limit).await {
        Ok(rows) => Json(json!({ "predictions": rows })),
        Err(e)   => Json(json!({ "predictions": [], "error": e.to_string() })),
    }
}

pub async fn get_threat_predictions_history(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    match crate::threat::get_predictions(&state.ch_storage, &claims.tenant_id, 100).await {
        Ok(rows) => Json(json!({ "predictions": rows })),
        Err(e)   => Json(json!({ "predictions": [], "error": e.to_string() })),
    }
}

pub async fn get_threat_exposure(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    let (exposure_res, intel_res) = tokio::join!(
        crate::threat::get_exposure_history(&state.ch_storage, &claims.tenant_id, 24),
        crate::threat::get_threat_intel_summary(&state.ch_storage),
    );
    Json(json!({
        "exposure_history": exposure_res.unwrap_or_default(),
        "intel_summary":    intel_res.unwrap_or_default(),
    }))
}

pub async fn get_threat_patterns(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"error": "unauthorized"})),
    };
    match crate::threat::get_pattern_matches(&state.ch_storage, &claims.tenant_id).await {
        Ok(rows) => Json(json!({ "patterns": rows })),
        Err(e)   => Json(json!({ "error": e.to_string() })),
    }
}

/// GET /api/admin/leader-status
/// Shows which engine instance is the current threat task leader.
pub async fn get_leader_status(
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    if extract_claims(&headers).is_none() {
        return Json(json!({"error": "unauthorized"}));
    }

    let redis_url = std::env::var("VALKEY_URL")
        .or_else(|_| std::env::var("REDIS_URL"))
        .unwrap_or_else(|_| "redis://ndr-valkey:6379".to_string());

    let (current_leader, ttl_ms) = match redis::Client::open(redis_url.clone()) {
        Ok(client) => {
            match client.get_multiplexed_async_connection().await {
                Ok(mut conn) => {
                    let leader: Option<String> = redis::cmd("GET")
                        .arg("ndr:threat_leader")
                        .query_async(&mut conn)
                        .await
                        .unwrap_or(None);
                    let ttl: i64 = redis::cmd("PTTL")
                        .arg("ndr:threat_leader")
                        .query_async(&mut conn)
                        .await
                        .unwrap_or(-1);
                    (leader, ttl)
                }
                Err(e) => {
                    tracing::warn!("Failed to get multiplexed async connection to {}: {}", redis_url, e);
                    (None, -1)
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to open redis client for {}: {}", redis_url, e);
            (None, -1)
        }
    };

    Json(json!({
        "current_leader":  current_leader.unwrap_or_else(|| "none".to_string()),
        "ttl_ms":          ttl_ms,
        "ttl_seconds":     if ttl_ms > 0 { ttl_ms / 1000 } else { 0 },
        "leader_key":      "ndr:threat_leader",
        "election_info":   "Leader renewed every 10s, TTL=30s, failover < 30s",
    }))
}

// ── Trusted Cloud Settings — super_admin only ─────────────────────────────────

pub async fn get_trusted_cloud_settings(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    if let Err(e) = require_super_admin(&headers) { return e; }
    let ch = &state.ch_storage;

    let keywords_str = ch.get_global_setting("trusted_cloud_asn_keywords").await.unwrap_or_default();
    let domains_str  = ch.get_global_setting("trusted_cloud_domains").await.unwrap_or_default();

    let keywords: Vec<&str> = keywords_str.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    let domains:  Vec<&str> = domains_str.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();

    let suggestions = crate::threat::cloud_suggestions::load_suggestions(ch).await;
    let mut suggestions_list: Vec<serde_json::Value> = suggestions.into_iter()
        .map(|(org, hits)| json!({ "org": org, "hits": hits }))
        .collect();
    suggestions_list.sort_by(|a, b| {
        b["hits"].as_u64().unwrap_or(0).cmp(&a["hits"].as_u64().unwrap_or(0))
    });

    Json(json!({
        "keywords":    keywords,
        "domains":     domains,
        "suggestions": suggestions_list,
    }))
}

#[derive(serde::Deserialize)]
pub struct TrustedCloudUpdate {
    pub keywords: Option<Vec<String>>,
    pub domains:  Option<Vec<String>>,
}

pub async fn update_trusted_cloud_settings(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<TrustedCloudUpdate>,
) -> Json<Value> {
    if let Err(e) = require_super_admin(&headers) { return e; }
    let ch = &state.ch_storage;

    if let Some(ref kws) = body.keywords {
        let val = kws.iter().map(|k| k.trim().to_uppercase()).filter(|k| !k.is_empty()).collect::<Vec<_>>().join(",");
        if let Err(e) = ch.set_global_setting("trusted_cloud_asn_keywords", &val).await {
            return Json(json!({"error": e.to_string()}));
        }
        let mut guard = state.trusted.write().await;
        for kw in kws.iter() {
            guard.add_asn_keyword(kw.trim());
        }
    }

    if let Some(ref doms) = body.domains {
        let val = doms.iter().map(|d| d.trim().to_lowercase()).filter(|d| !d.is_empty()).collect::<Vec<_>>().join(",");
        if let Err(e) = ch.set_global_setting("trusted_cloud_domains", &val).await {
            return Json(json!({"error": e.to_string()}));
        }
    }

    Json(json!({"ok": true}))
}

#[derive(serde::Deserialize)]
pub struct SuggestionAction {
    pub org: String,
}

pub async fn approve_trusted_cloud_suggestion(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<SuggestionAction>,
) -> Json<Value> {
    if let Err(e) = require_super_admin(&headers) { return e; }
    match crate::threat::cloud_suggestions::approve_suggestion(
        &state.ch_storage,
        &body.org,
        &state.trusted,
    ).await {
        Ok(_)  => Json(json!({"ok": true, "org": body.org})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

pub async fn reject_trusted_cloud_suggestion(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<SuggestionAction>,
) -> Json<Value> {
    if let Err(e) = require_super_admin(&headers) { return e; }
    match crate::threat::cloud_suggestions::reject_suggestion(&state.ch_storage, &body.org).await {
        Ok(_)  => Json(json!({"ok": true, "org": body.org})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

// ── Trusted Domains — CRUD + AI suggestions ───────────────────────────────────
// GET  /api/trusted-domains        — list (global + caller's tenant)
// POST /api/trusted-domains        — add entry
// POST /api/trusted-domains/delete — remove entry (body: {domain, tenant_id})
// POST /api/trusted-domains/ai-suggest — classify high-freq domains via AI

#[derive(clickhouse::Row, serde::Deserialize)]
struct TrustedDomainRow {
    domain:    String,
    category:  String,
    tenant_id: String,
    note:      String,
    added_by:  String,
    added_at:  String,
}

pub async fn list_trusted_domains(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"error": "Unauthorized"})),
    };
    let ch  = &state.ch_storage;
    let esc = crate::storage::clickhouse::sql_escape_pub;

    let q = if claims.role == "super_admin" {
        "SELECT domain, category, tenant_id, note, added_by, toString(added_at) AS added_at \
         FROM ndr.trusted_domains FINAL ORDER BY tenant_id, category, domain".to_string()
    } else {
        format!(
            "SELECT domain, category, tenant_id, note, added_by, toString(added_at) AS added_at \
             FROM ndr.trusted_domains FINAL \
             WHERE tenant_id = '' OR tenant_id = '{}' \
             ORDER BY tenant_id, category, domain",
            esc(&claims.tenant_id)
        )
    };

    match ch.client.query(&q).fetch_all::<TrustedDomainRow>().await {
        Ok(rows) => {
            let data: Vec<Value> = rows.into_iter().map(|r| {
                let scope = if r.tenant_id.is_empty() { "global" } else { "tenant" };
                json!({
                    "domain":    r.domain,
                    "category":  r.category,
                    "tenant_id": r.tenant_id,
                    "note":      r.note,
                    "added_by":  r.added_by,
                    "added_at":  r.added_at,
                    "scope":     scope,
                })
            }).collect();
            Json(json!({"domains": data}))
        }
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

#[derive(serde::Deserialize)]
pub struct AddTrustedDomainBody {
    pub domain:    String,
    pub category:  Option<String>,
    pub tenant_id: Option<String>,
    pub note:      Option<String>,
}

pub async fn add_trusted_domain(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<AddTrustedDomainBody>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"error": "Unauthorized"})),
    };
    if claims.role != "super_admin" && claims.role != "tenant_admin" {
        return Json(json!({"error": "Forbidden"}));
    }
    let ch  = &state.ch_storage;
    let esc = crate::storage::clickhouse::sql_escape_pub;

    let domain   = body.domain.trim().to_lowercase();
    let category = body.category.as_deref().unwrap_or("dns_beacon").to_string();
    let note     = body.note.as_deref().unwrap_or("").to_string();

    // TC-089: this previously accepted an empty domain and an unbounded-length
    // note with no validation at all. 253 is the real DNS max hostname length;
    // 500 is a sane cap for a free-text note field.
    if domain.is_empty() {
        return Json(json!({"error": "Domain is required"}));
    }
    if domain.chars().count() > 253 {
        return Json(json!({"error": "Domain is too long (max 253 characters)"}));
    }
    if note.chars().count() > 500 {
        return Json(json!({"error": "Note is too long (max 500 characters)"}));
    }

    // super_admin can create global (tenant_id='') or any tenant; others are scoped to their tenant
    let tenant_id = if claims.role == "super_admin" {
        body.tenant_id.clone().unwrap_or_default()
    } else {
        claims.tenant_id.clone()
    };

    let q = format!(
        "INSERT INTO ndr.trusted_domains (domain, category, tenant_id, note, added_by, added_at) \
         VALUES ('{}', '{}', '{}', '{}', '{}', now())",
        esc(&domain), esc(&category), esc(&tenant_id), esc(&note), esc(&claims.sub)
    );
    match ch.client.query(&q).execute().await {
        Ok(_)  => Json(json!({"ok": true, "domain": domain,
                              "scope": if tenant_id.is_empty() { "global" } else { "tenant" }})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

#[derive(serde::Deserialize)]
pub struct DeleteTrustedDomainBody {
    pub domain:    String,
    pub tenant_id: Option<String>,
}

pub async fn delete_trusted_domain(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<DeleteTrustedDomainBody>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"error": "Unauthorized"})),
    };
    if claims.role != "super_admin" && claims.role != "tenant_admin" {
        return Json(json!({"error": "Forbidden"}));
    }
    let ch  = &state.ch_storage;
    let esc = crate::storage::clickhouse::sql_escape_pub;

    let domain    = body.domain.trim().to_lowercase();
    let tenant_id = if claims.role == "super_admin" {
        body.tenant_id.clone().unwrap_or_default()
    } else {
        claims.tenant_id.clone()
    };

    let q = format!(
        "ALTER TABLE ndr.trusted_domains ON CLUSTER ndr_cluster \
         DELETE WHERE domain = '{}' AND tenant_id = '{}' SETTINGS mutations_sync=1",
        esc(&domain), esc(&tenant_id)
    );
    match ch.client.query(&q).execute().await {
        Ok(_)  => Json(json!({"ok": true})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

pub async fn ai_suggest_trusted_domains(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"error": "Unauthorized"})),
    };
    if claims.role != "super_admin" && claims.role != "tenant_admin" {
        return Json(json!({"error": "Forbidden"}));
    }
    let ch  = &state.ch_storage;
    let esc = crate::storage::clickhouse::sql_escape_pub;

    // Check if AI is available (DB providers with keys OR env-var fallback)
    let has_db_ai = ch.list_ai_providers().await.unwrap_or_default().iter().any(|p| {
        p.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false)
    });
    let has_env_ai = std::env::var("GROQ_API_KEY").map(|k| !k.is_empty()).unwrap_or(false)
        || std::env::var("OPENAI_API_KEY").map(|k| !k.is_empty()).unwrap_or(false)
        || std::env::var("ANTHROPIC_API_KEY").map(|k| !k.is_empty()).unwrap_or(false);
    if !has_db_ai && !has_env_ai {
        return Json(json!({"ai_available": false}));
    }

    let tenant_filter = if claims.role == "super_admin" {
        "1=1".to_string()
    } else {
        format!("tenant_id = '{}'", esc(&claims.tenant_id))
    };

    // Top domains queried in the last 24h
    let candidates_q = format!(
        "SELECT JSONExtractString(raw, 'query') AS domain, count() AS cnt \
         FROM ndr.ndr_events \
         WHERE timestamp > now() - INTERVAL 24 HOUR \
           AND {tenant_filter} \
           AND event_type = 'dns' \
           AND JSONExtractString(raw, 'query') != '' \
           AND NOT match(JSONExtractString(raw, 'query'), '\\.(local|internal|lan|corp|home)$') \
         GROUP BY domain HAVING cnt > 30 ORDER BY cnt DESC LIMIT 40"
    );

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct DomainCnt { domain: String, cnt: u64 }

    let candidates: Vec<DomainCnt> = ch.client.query(&candidates_q).fetch_all().await.unwrap_or_default();
    if candidates.is_empty() {
        return Json(json!({"ai_available": true, "suggestions": []}));
    }

    // Filter out already-trusted
    let existing_q = if claims.role == "super_admin" {
        "SELECT domain FROM ndr.trusted_domains FINAL WHERE tenant_id = ''".to_string()
    } else {
        format!(
            "SELECT domain FROM ndr.trusted_domains FINAL \
             WHERE tenant_id = '' OR tenant_id = '{}'",
            esc(&claims.tenant_id)
        )
    };
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct DRow { domain: String }
    let existing: std::collections::HashSet<String> = ch.client.query(&existing_q)
        .fetch_all::<DRow>().await.unwrap_or_default()
        .into_iter().map(|r| r.domain).collect();

    let fresh: Vec<&DomainCnt> = candidates.iter()
        .filter(|c| !existing.iter().any(|e| c.domain == *e || c.domain.ends_with(&format!(".{}", e))))
        .collect();

    if fresh.is_empty() {
        return Json(json!({"ai_available": true, "suggestions": []}));
    }

    let domain_list = fresh.iter()
        .map(|c| format!("- {} ({} queries/24h)", c.domain, c.cnt))
        .collect::<Vec<_>>().join("\n");

    let system = "You are a network security analyst. \
                  Classify domains as TRUSTED (legitimate CDN, cloud, SaaS, update server) or \
                  SUSPICIOUS (potential C2, malware, or out-of-place traffic). \
                  Reply ONLY with valid JSON — no other text.";
    let prompt = format!(
        "Classify these frequently-queried domains from a corporate network (last 24h):\n\
         {}\n\n\
         Return JSON: \
         {{\"suggestions\":[{{\"domain\":\"...\",\"verdict\":\"TRUSTED\",\"reason\":\"...\",\"cnt\":N}}]}}",
        domain_list
    );

    let ai_text = crate::ai::provider::generate(ch, crate::ai::provider::UseCase::ThreatPrediction, system, &prompt).await;

    // Parse JSON out of AI response
    let parsed: Value = if !ai_text.is_empty() {
        let trimmed = ai_text.trim();
        serde_json::from_str(trimmed)
            .or_else(|_| -> Result<Value, _> {
                if let (Some(s), Some(e)) = (trimmed.find('{'), trimmed.rfind('}')) {
                    serde_json::from_str(&trimmed[s..=e])
                } else {
                    Ok(json!({"suggestions": []}))
                }
            })
            .unwrap_or_else(|_| json!({"suggestions": []}))
    } else {
        json!({"suggestions": []})
    };

    Json(json!({
        "ai_available": true,
        "suggestions":  parsed.get("suggestions").cloned().unwrap_or(json!([])),
    }))
}

// ── Active Blocks ─────────────────────────────────────────────────────────

#[cfg(feature = "soar")]
pub async fn list_active_blocks(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let tenant_id = if claims.role == "superadmin" { "superadmin".to_string() } else { claims.tenant_id.clone() };
    match state.ch_storage.list_active_blocks(&tenant_id).await {
        Ok(blocks) => Json(json!({"status":"success","data":blocks})),
        Err(e)     => Json(json!({"status":"error","message":e.to_string()})),
    }
}

#[derive(serde::Deserialize)]
#[cfg(feature = "soar")]
pub struct RevokeBlockBody {
    pub id:                    String,
    #[allow(dead_code)]
    pub sensor_id: Option<String>,
}

#[cfg(feature = "soar")]
pub async fn revoke_active_block(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RevokeBlockBody>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let tenant_id = if claims.role == "superadmin" { "superadmin".to_string() } else { claims.tenant_id.clone() };

    match state.ch_storage.revoke_active_block(&body.id, &tenant_id).await {
        Ok(Some(block)) => {
            // Call firewall API to remove the rule if one was set
            if !block.firewall_type.is_empty() && block.firewall_type != "none" {
                let integrations = state.ch_storage
                    .get_integrations_by_tenant(&block.tenant_id).await.unwrap_or_default();
                if let Some(fw) = integrations.iter().find(|i| {
                    i["type"].as_str() == Some(&block.firewall_type) && i["enabled"] == json!(true)
                }) {
                    let _ = crate::soar::firewall::revoke_block(
                        &block.firewall_type, &fw["config"],
                        &block.src_ip, &block.firewall_rule_id,
                    ).await;
                }
            }
            // Call agent unblock (RST cleanup)
            let agent_url = std::env::var("NDR_AGENT_URL")
                .unwrap_or_else(|_| "http://host.docker.internal:3001".to_string());
            let _ = add_agent_auth(state.http_client
                .post(format!("{}/agent/unblock", agent_url))
                .json(&json!({"ip": block.src_ip}))
                .timeout(std::time::Duration::from_secs(5)))
                .send().await;

            Json(json!({"status":"success","message":format!("Block {} revoked", body.id)}))
        }
        Ok(None) => Json(json!({"status":"error","message":"Block not found"})),
        Err(e)   => Json(json!({"status":"error","message":e.to_string()})),
    }
}

#[derive(serde::Deserialize)]
#[cfg(feature = "soar")]
pub struct ManualBlockBody {
    pub src_ip:         String,
    pub src_port:       Option<u16>,
    pub duration_hours: Option<u64>,
    pub enforcement:    Option<String>,   // "rst" | "firewall" | "both"
    pub reason:         Option<String>,
}

#[cfg(feature = "soar")]
pub async fn manual_block(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ManualBlockBody>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let tenant_id = claims.tenant_id.clone();
    let duration  = body.duration_hours.unwrap_or(24);
    let enforce   = body.enforcement.as_deref().unwrap_or("both");
    let reason    = body.reason.clone().unwrap_or_else(|| format!("Manual block by {}", claims.sub));

    // Validate IP is routable
    let addr: Result<std::net::IpAddr, _> = body.src_ip.parse();
    let is_private = addr.map(|a| match a {
        std::net::IpAddr::V4(v) => v.is_private() || v.is_loopback(),
        std::net::IpAddr::V6(v) => v.is_loopback(),
    }).unwrap_or(true);

    if is_private {
        return Json(json!({"status":"error","message":"Cannot block private/internal addresses"}));
    }

    let agent_url = std::env::var("NDR_AGENT_URL")
        .unwrap_or_else(|_| "http://host.docker.internal:3001".to_string());

    let mut rst_ok   = false;
    let mut expires_at = String::new();

    // RST injection
    if enforce == "rst" || enforce == "both" {
        let rst_payload = json!({
            "src_ip": body.src_ip, "src_port": body.src_port.unwrap_or(0),
            "dst_ip": "", "dst_port": 0,
            "community_id": "", "duration_hours": duration,
        });
        if let Ok(r) = add_agent_auth(state.http_client
            .post(format!("{}/agent/block", agent_url))
            .json(&rst_payload).timeout(std::time::Duration::from_secs(10))).send().await
        {
            if r.status().is_success() {
                let resp = r.json::<serde_json::Value>().await.unwrap_or_default();
                rst_ok     = resp["rst_injected"].as_bool().unwrap_or(false);
                expires_at = resp["expires_at"].as_str().unwrap_or("").to_string();
            }
        }
    }

    // Firewall API
    let (fw_type, fw_rule_id) = if enforce == "firewall" || enforce == "both" {
        let integrations = state.ch_storage.get_integrations_by_tenant(&tenant_id).await.unwrap_or_default();
        if let Some(fw) = integrations.iter().find(|i| {
            matches!(i["type"].as_str(), Some("pfsense"|"fortinet"|"panos"|"opnsense"|"rest"))
            && i["enabled"] == json!(true)
        }) {
            let fw_type = fw["type"].as_str().unwrap_or("none").to_string();
            let result  = crate::soar::firewall::push_block(&fw_type, &fw["config"], &body.src_ip, duration).await;
            (fw_type, result.rule_id)
        } else {
            ("none".to_string(), String::new())
        }
    } else {
        ("none".to_string(), String::new())
    };

    // Persist
    if expires_at.is_empty() {
        use chrono::{Utc, Duration as CDur};
        expires_at = (Utc::now() + CDur::hours(duration as i64)).to_rfc3339();
    }
    let expires_stored = expires_at.replace('T', " ").trim_end_matches('Z').to_string();
    let block_id = uuid::Uuid::new_v4().to_string();

    let block = crate::soar::ActiveBlock {
        id: block_id.clone(),
        src_ip: body.src_ip.clone(), src_port: body.src_port.unwrap_or(0),
        dst_ip: String::new(), dst_port: 0,
        community_id: String::new(),
        triggered_by: "manual".to_string(),
        sensor_id: String::new(),
        firewall_type: fw_type, firewall_rule_id: fw_rule_id,
        rst_injected: if rst_ok { 1 } else { 0 },
        duration_hours: duration as u16,
        expires_at: expires_stored,
        status: "active".to_string(),
        reason,
        tenant_id: tenant_id.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    match state.ch_storage.insert_active_block(&block).await {
        Ok(_)  => Json(json!({"status":"success","id":block_id,"rst_injected":rst_ok})),
        Err(e) => Json(json!({"status":"error","message":e.to_string()})),
    }
}

// ── Device Isolation API ───────────────────────────────────────────────────

// ── Incidents (attack story) ─────────────────────────────────────────────────

pub async fn list_incidents(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    match state.ch_storage.get_incidents(&claims.tenant_id).await {
        Ok(incidents) => Json(json!({"status":"ok","incidents":incidents})),
        Err(e)        => Json(json!({"status":"error","message":e.to_string()})),
    }
}

pub async fn update_incident_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path((id, status)): axum::extract::Path<(String, String)>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let allowed = ["active", "contained", "resolved"];
    if !allowed.contains(&status.as_str()) {
        return Json(json!({"status":"error","message":"invalid status"}));
    }
    match state.ch_storage.update_incident_status(&claims.tenant_id, &id, &status).await {
        Ok(_)  => Json(json!({"status":"ok"})),
        Err(e) => Json(json!({"status":"error","message":e.to_string()})),
    }
}

#[cfg(feature = "soar")]
pub async fn list_isolations(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let tenant_id = if claims.role == "superadmin" { "superadmin".to_string() } else { claims.tenant_id.clone() };
    match state.ch_storage.list_isolations(&tenant_id).await {
        Ok(items) => Json(json!({"status":"success","data":items})),
        Err(e)    => Json(json!({"status":"error","message":e.to_string()})),
    }
}

#[derive(serde::Deserialize)]
#[cfg(feature = "soar")]
pub struct IsolateBody {
    pub target_ip:       String,
    pub gateway_ip:      Option<String>,
    pub enforcement:     Option<String>,   // arp / unifi / cisco / aruba / snmp / aws_sg / azure_nsg / gcp_vpc
    pub quarantine_vlan: Option<u16>,
    pub reason:          Option<String>,
}

#[cfg(feature = "soar")]
pub async fn isolate_device_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<IsolateBody>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let tenant_id   = claims.tenant_id.clone();
    let enforcement = body.enforcement.as_deref().unwrap_or("arp");
    let gateway_ip_owned;
    let gateway_ip = match body.gateway_ip.as_deref().filter(|s| !s.is_empty()) {
        Some(gw) => gw,
        None => {
            // Let the agent auto-detect the gateway from its own routing table
            gateway_ip_owned = String::new();
            &gateway_ip_owned
        }
    };
    let reason      = body.reason.clone().unwrap_or_else(|| format!("Isolated by {}", claims.sub));
    let q_vlan      = body.quarantine_vlan.unwrap_or(999);
    let agent_url   = std::env::var("NDR_AGENT_URL")
        .unwrap_or_else(|_| "http://host.docker.internal:3001".to_string());

    let (method, enforcement_detail) = match enforcement {
        "arp" => {
            // Call ndr-agent ARP isolation
            let payload = json!({"target_ip": body.target_ip, "gateway_ip": gateway_ip});
            let resp = add_agent_auth(state.http_client
                .post(format!("{}/agent/isolate", agent_url))
                .json(&payload)
                .timeout(std::time::Duration::from_secs(10)))
                .send().await;
            let detail = match resp {
                Ok(r)  => r.json::<serde_json::Value>().await.unwrap_or_default().to_string(),
                Err(e) => json!({"error": e.to_string()}).to_string(),
            };
            ("arp".to_string(), detail)
        }
        sw @ ("unifi" | "cisco" | "aruba" | "snmp") => {
            let integrations = state.ch_storage.get_integrations_by_tenant(&tenant_id).await.unwrap_or_default();
            if let Some(cfg) = integrations.iter().find(|i| i["type"].as_str() == Some(sw) && i["enabled"] == json!(true)) {
                // Capture original VLAN before quarantine so restore works correctly
                let original_vlan = crate::soar::switch::get_current_vlan(sw, &cfg["config"]).await.unwrap_or(1);
                let res = crate::soar::switch::quarantine_device(sw, &cfg["config"], &body.target_ip, q_vlan).await;
                // Merge original_vlan into the enforcement_detail JSON
                let mut detail: serde_json::Value = serde_json::from_str(&res.detail).unwrap_or(json!({}));
                detail["original_vlan"] = json!(original_vlan);
                ("switch_vlan".to_string(), detail.to_string())
            } else {
                return Json(json!({"status":"error","message":format!("{sw} integration not configured")}));
            }
        }
        cloud @ ("aws_sg" | "azure_nsg" | "gcp_vpc") => {
            let integrations = state.ch_storage.get_integrations_by_tenant(&tenant_id).await.unwrap_or_default();
            if let Some(cfg) = integrations.iter().find(|i| i["type"].as_str() == Some(cloud) && i["enabled"] == json!(true)) {
                let res = crate::soar::firewall::push_cloud_deny(cloud, &cfg["config"], &body.target_ip).await;
                ("cloud_firewall".to_string(), res.rule_id)
            } else {
                return Json(json!({"status":"error","message":format!("{cloud} integration not configured")}));
            }
        }
        _ => return Json(json!({"status":"error","message":"unsupported enforcement type"})),
    };

    let iso_id = uuid::Uuid::new_v4().to_string();
    let iso = crate::soar::DeviceIsolation {
        id: iso_id.clone(),
        tenant_id,
        target_ip: body.target_ip.clone(),
        gateway_ip: gateway_ip.to_string(),
        method,
        enforcement: enforcement.to_string(),
        enforcement_detail,
        triggered_by: "manual".to_string(),
        sensor_id: String::new(),
        reason,
        status: "active".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    match state.ch_storage.insert_isolation(&iso).await {
        Ok(_)  => Json(json!({"status":"ok","id":iso_id,"target_ip":body.target_ip})),
        Err(e) => Json(json!({"status":"error","message":e.to_string()})),
    }
}

#[derive(serde::Deserialize)]
#[cfg(feature = "soar")]
pub struct UnisolateBody {
    pub id: String,
}

#[cfg(feature = "soar")]
pub async fn unisolate_device_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<UnisolateBody>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None    => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let tenant_id = if claims.role == "superadmin" { "superadmin".to_string() } else { claims.tenant_id.clone() };
    let agent_url = std::env::var("NDR_AGENT_URL")
        .unwrap_or_else(|_| "http://host.docker.internal:3001".to_string());

    let iso = match state.ch_storage.restore_isolation(&body.id, &tenant_id).await {
        Ok(Some(i)) => i,
        Ok(None)    => return Json(json!({"status":"error","message":"Isolation not found"})),
        Err(e)      => return Json(json!({"status":"error","message":e.to_string()})),
    };

    // Call the appropriate unisolation method based on enforcement type
    match iso.enforcement.as_str() {
        "arp" => {
            let _ = add_agent_auth(state.http_client
                .post(format!("{}/agent/unisolate", agent_url))
                .json(&json!({"target_ip": iso.target_ip}))
                .timeout(std::time::Duration::from_secs(10)))
                .send().await;
        }
        sw @ ("unifi" | "cisco" | "aruba" | "snmp") => {
            let integrations = state.ch_storage.get_integrations_by_tenant(&iso.tenant_id).await.unwrap_or_default();
            if let Some(cfg) = integrations.iter().find(|i| i["type"].as_str() == Some(sw) && i["enabled"] == json!(true)) {
                let original_vlan = serde_json::from_str::<serde_json::Value>(&iso.enforcement_detail)
                    .ok().and_then(|v| v["original_vlan"].as_u64()).unwrap_or(1) as u16;
                let _ = crate::soar::switch::restore_device(sw, &cfg["config"], &iso.target_ip, original_vlan).await;
            }
        }
        cloud @ ("aws_sg" | "azure_nsg" | "gcp_vpc") => {
            let integrations = state.ch_storage.get_integrations_by_tenant(&iso.tenant_id).await.unwrap_or_default();
            if let Some(cfg) = integrations.iter().find(|i| i["type"].as_str() == Some(cloud) && i["enabled"] == json!(true)) {
                let _ = crate::soar::firewall::revoke_cloud_deny(cloud, &cfg["config"], &iso.target_ip, &iso.enforcement_detail).await;
            }
        }
        _ => {}
    }

    Json(json!({"status":"success","message":format!("Isolation {} restored", body.id)}))
}
// ── DoH Providers ─────────────────────────────────────────────────────────

pub async fn list_doh_providers(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let _claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    match state.ch_storage.list_doh_providers().await {
        Ok(rows) => Json(json!({"status":"ok","providers":rows})),
        Err(e)   => Json(json!({"status":"error","message":e.to_string()})),
    }
}

pub async fn add_doh_provider(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    let _claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let ip   = match body["ip"].as_str() {
        Some(v) => v.to_string(),
        None => return Json(json!({"status":"error","message":"ip required"})),
    };
    let name = body["provider_name"].as_str().unwrap_or("").to_string();

    if let Err(e) = state.ch_storage.add_doh_provider(&ip, &name).await {
        return Json(json!({"status":"error","message":e.to_string()}));
    }
    // Refresh in-memory cache
    if let Ok(set) = state.ch_storage.load_doh_providers().await {
        *state.doh_ips.write().await = set;
    }
    Json(json!({"status":"ok","ip":ip}))
}

pub async fn delete_doh_provider(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(ip): axum::extract::Path<String>,
) -> Json<Value> {
    let _claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    if let Err(e) = state.ch_storage.remove_doh_provider(&ip).await {
        return Json(json!({"status":"error","message":e.to_string()}));
    }
    // Refresh in-memory cache
    if let Ok(set) = state.ch_storage.load_doh_providers().await {
        *state.doh_ips.write().await = set;
    }
    Json(json!({"status":"ok","removed":ip}))
}

// GET /api/admin/active-sessions — returns all active sessions for the caller's tenant
pub async fn get_active_sessions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    if !matches!(claims.role.as_str(), "admin" | "super_admin" | "tenant_admin") {
        return Json(json!({"status":"error","message":"Forbidden"}));
    }
    let tenant_id = &claims.tenant_id;

    use redis::AsyncCommands;
    let mut mux = state.redis_mux.clone();
    let tenant_set_key = format!("ndr:tenant_sessions:{}", tenant_id);
    let jtis: Vec<String> = mux.smembers(&tenant_set_key).await.unwrap_or_default();

    let mut sessions: Vec<Value> = Vec::new();
    for jti in &jtis {
        let session_key = format!("ndr:session:{}", jti);
        let fields: std::collections::HashMap<String, String> =
            mux.hgetall(&session_key).await.unwrap_or_default();
        if fields.is_empty() {
            // Session expired — clean up the stale JTI from the tenant set
            let _: redis::RedisResult<()> = mux.srem(&tenant_set_key, jti).await;
            continue;
        }
        // Verify the session actually belongs to this tenant (guards against stale keys)
        let session_tenant = fields.get("tenant_id").cloned().unwrap_or_default();
        if !session_tenant.is_empty() && session_tenant != *tenant_id {
            let _: redis::RedisResult<()> = mux.srem(&tenant_set_key, jti).await;
            continue;
        }
        // tenant_admin must not see super_admin sessions
        let session_role = fields.get("role").cloned().unwrap_or_default();
        if claims.role == "tenant_admin" && session_role == "super_admin" {
            continue;
        }
        sessions.push(json!({
            "jti":        jti,
            "username":   fields.get("username").cloned().unwrap_or_default(),
            "role":       fields.get("role").cloned().unwrap_or_default(),
            "ip":         fields.get("ip").cloned().unwrap_or_default(),
            "device":     fields.get("device").cloned().unwrap_or_default(),
            "login_time": fields.get("login_time").cloned().unwrap_or_default(),
        }));
    }
    Json(json!({"status":"ok","sessions":sessions}))
}

#[derive(serde::Deserialize)]
pub struct GeoLookupBody {
    pub ips: Vec<String>,
}

/// Real IP geolocation for arbitrary (e.g. session login) IPs, reusing the
/// same local GeoLite2 DB + ip-api.com fallback as the threat map widgets —
/// added so the frontend no longer has to fabricate a location by hashing
/// the IP string against a fixed list of cities. Private/unresolvable IPs
/// (localhost, LAN ranges, sensors behind NAT) are returned as unresolved
/// rather than assigned a fake city.
pub async fn geo_lookup(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<GeoLookupBody>,
) -> Json<Value> {
    if extract_claims(&headers).is_none() {
        return Json(json!({"status":"error","message":"Unauthorized"}));
    }
    let ips: Vec<String> = body.ips.into_iter().take(100).collect();
    let results = geo_lookup_batch(&state, &ips).await;
    Json(json!({"status":"ok","results":results}))
}

// DELETE /api/admin/sessions/:username — force logout all sessions for a user
pub async fn force_logout_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(target_username): axum::extract::Path<String>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    if !matches!(claims.role.as_str(), "admin" | "super_admin" | "tenant_admin") {
        return Json(json!({"status":"error","message":"Forbidden"}));
    }
    let tenant_id = &claims.tenant_id;

    use redis::AsyncCommands;
    let mut mux = state.redis_mux.clone();
    let user_set_key   = format!("ndr:user_sessions:{}:{}", tenant_id, target_username);
    let tenant_set_key = format!("ndr:tenant_sessions:{}", tenant_id);
    // auth-service checks its own provigil:session:{jti} key, not ndr:session:{jti} —
    // deleting only the ndr: copy left the session alive there, so a "revoked" token
    // kept working on /api/auth/me and could even be renewed via /api/auth/refresh.
    // Both namespaces are written together at login (login.rs), so the same jti list
    // deletes both.
    let provigil_user_set_key   = format!("provigil:user_sessions:{}:{}", tenant_id, target_username);
    let provigil_tenant_set_key = format!("provigil:tenant_sessions:{}", tenant_id);

    let jtis: Vec<String> = mux.smembers(&user_set_key).await.unwrap_or_default();
    let count = jtis.len();
    for jti in &jtis {
        let _: redis::RedisResult<i64> = mux.del(format!("ndr:session:{}", jti)).await;
        let _: redis::RedisResult<i64> = mux.srem(&tenant_set_key, jti).await;
        let _: redis::RedisResult<i64> = mux.del(format!("provigil:session:{}", jti)).await;
        let _: redis::RedisResult<i64> = mux.srem(&provigil_tenant_set_key, jti).await;
    }
    let _: redis::RedisResult<i64> = mux.del(&user_set_key).await;
    let _: redis::RedisResult<i64> = mux.del(&provigil_user_set_key).await;

    // Push force_logout WS message — Angular filters by target_username
    let msg = serde_json::to_string(&json!({
        "type":            "force_logout",
        "target_username": target_username,
        "reason":          "Session terminated by administrator"
    })).unwrap_or_default();
    publish_event(&state, tenant_id, &msg);

    tracing::info!(
        "Admin '{}' force-logged-out '{}' ({} sessions terminated)",
        claims.sub, target_username, count
    );
    Json(json!({"status":"ok","sessions_terminated":count}))
}

// DELETE /api/admin/sessions/:username/device — sign out one specific device (by ip+device string)
#[derive(serde::Deserialize)]
pub struct ForceLogoutDeviceBody { pub ip: String, pub device: String }

pub async fn force_logout_device(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(target_username): axum::extract::Path<String>,
    axum::extract::Json(body): axum::extract::Json<ForceLogoutDeviceBody>,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    if !matches!(claims.role.as_str(), "admin" | "super_admin" | "tenant_admin") {
        return Json(json!({"status":"error","message":"Forbidden"}));
    }
    let tenant_id = &claims.tenant_id;

    use redis::AsyncCommands;
    let mut mux = state.redis_mux.clone();
    let user_set_key   = format!("ndr:user_sessions:{}:{}", tenant_id, target_username);
    let tenant_set_key = format!("ndr:tenant_sessions:{}", tenant_id);
    // Same fix as force_logout_user: also clear the provigil: copy auth-service
    // actually checks, or the session (and a refresh off it) keeps working there.
    let provigil_user_set_key   = format!("provigil:user_sessions:{}:{}", tenant_id, target_username);
    let provigil_tenant_set_key = format!("provigil:tenant_sessions:{}", tenant_id);

    let jtis: Vec<String> = mux.smembers(&user_set_key).await.unwrap_or_default();
    let mut count = 0usize;
    for jti in &jtis {
        let session_key = format!("ndr:session:{}", jti);
        let s_ip:    Option<String> = mux.hget(&session_key, "ip").await.unwrap_or(None);
        let s_device: Option<String> = mux.hget(&session_key, "device").await.unwrap_or(None);
        if s_ip.as_deref() == Some(&body.ip) && s_device.as_deref() == Some(&body.device) {
            let _: redis::RedisResult<i64> = mux.del(&session_key).await;
            let _: redis::RedisResult<i64> = mux.srem(&user_set_key, jti).await;
            let _: redis::RedisResult<i64> = mux.srem(&tenant_set_key, jti).await;
            let _: redis::RedisResult<i64> = mux.del(format!("provigil:session:{}", jti)).await;
            let _: redis::RedisResult<i64> = mux.srem(&provigil_user_set_key, jti).await;
            let _: redis::RedisResult<i64> = mux.srem(&provigil_tenant_set_key, jti).await;
            count += 1;
        }
    }

    tracing::info!(
        "Admin '{}' signed out device '{}' / '{}' for user '{}' ({} sessions)",
        claims.sub, body.device, body.ip, target_username, count
    );
    Json(json!({"status":"ok","sessions_terminated":count}))
}

// GET /api/admin/version — returns current + latest version info (on-prem only)
pub async fn get_version_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<Value> {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return Json(json!({"status":"error","message":"Unauthorized"})),
    };
    let role = claims.role.as_str();
    if !matches!(role, "admin" | "super_admin" | "tenant_admin") {
        return Json(json!({"status":"error","message":"Forbidden"}));
    }
    let status = state.update_status.read().await.clone();
    Json(json!({
        "current_version":  status.current_version,
        "latest_version":   status.latest_version,
        "update_available": status.update_available,
        "last_checked_secs": status.last_checked_secs,
    }))
}

// POST /api/admin/apply-update — admin only; writes flag file picked up by host watcher
pub async fn apply_update(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return (axum::http::StatusCode::UNAUTHORIZED,
                        Json(json!({"status":"error","message":"Unauthorized"}))),
    };
    let role = claims.role.as_str();
    if !matches!(role, "admin" | "super_admin" | "tenant_admin") {
        return (axum::http::StatusCode::FORBIDDEN,
                Json(json!({"status":"error","message":"Forbidden"})));
    }
    let status = state.update_status.read().await.clone();
    if !status.update_available {
        return (axum::http::StatusCode::BAD_REQUEST, Json(json!({
            "status": "error",
            "message": "No update available"
        })));
    }
    // Flag file is at /scripts/.update-requested inside the container,
    // which maps to ${INSTALL_DIR}/scripts/.update-requested on the host.
    // The ndr-updater systemd service on the host watches this path.
    let flag = "/scripts/.update-requested";
    if let Err(e) = std::fs::write(flag, status.latest_version.as_deref().unwrap_or("")) {
        tracing::error!("Failed to write update flag {}: {}", flag, e);
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "status": "error",
            "message": format!("Could not write update flag: {}", e)
        })));
    }
    tracing::info!("Update requested → flag written to {}", flag);
    (axum::http::StatusCode::ACCEPTED, Json(json!({
        "status": "accepted",
        "message": "Update triggered. Services will restart in ~30 seconds.",
        "target_version": status.latest_version
    })))
}

// ── Retrospective scan state ───────────────────────────────────────────────

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RetroScan {
    pub id:           String,
    pub rule_id:      String,  // Sigma rule UUID
    pub rule_name:    String,  // human-readable rule name
    pub rule_content: String,  // optional keyword search
    pub hours_back:   u32,
    pub status:       String, // pending | running | done | failed
    pub started_at:   String,
    pub completed_at: Option<String>,
    pub match_count:  usize,
    pub matches:      Vec<serde_json::Value>,
    pub tenant_id:    String,
}

// ── Honeypot handlers ─────────────────────────────────────────────────────

pub async fn list_honeypots(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return (axum::http::StatusCode::UNAUTHORIZED,
                        Json(json!({"status":"error","message":"Unauthorized"}))),
    };
    let result = if claims.role == "super_admin" {
        state.ch_storage.get_all_honeypots().await
    } else {
        state.ch_storage.get_honeypots(&claims.tenant_id).await
    };
    match result {
        Ok(rows) => (axum::http::StatusCode::OK, Json(json!({"status":"ok","honeypots":rows}))),
        Err(e)   => (axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                     Json(json!({"status":"error","message":e.to_string()}))),
    }
}

pub async fn create_honeypot(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> (axum::http::StatusCode, Json<Value>) {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return (axum::http::StatusCode::UNAUTHORIZED,
                        Json(json!({"status":"error","message":"Unauthorized"}))),
    };
    if !matches!(claims.role.as_str(), "super_admin" | "tenant_admin" | "admin") {
        return (axum::http::StatusCode::FORBIDDEN,
                Json(json!({"status":"error","message":"Forbidden"})));
    }
    let name = body["name"].as_str().unwrap_or("").to_string();
    let cidr = body["cidr"].as_str().unwrap_or("").to_string();
    let description = body["description"].as_str().unwrap_or("").to_string();
    if name.is_empty() || cidr.is_empty() {
        return (axum::http::StatusCode::BAD_REQUEST,
                Json(json!({"status":"error","message":"name and cidr are required"})));
    }
    // Validate CIDR
    if cidr.parse::<ipnetwork::IpNetwork>().is_err() {
        return (axum::http::StatusCode::BAD_REQUEST,
                Json(json!({"status":"error","message":"Invalid CIDR format"})));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let tenant_id = if claims.role == "super_admin" {
        body["tenant_id"].as_str().unwrap_or(&claims.tenant_id).to_string()
    } else {
        claims.tenant_id.clone()
    };
    match state.ch_storage.add_honeypot(&id, &tenant_id, &name, &cidr, &description).await {
        Ok(_) => {
            // Refresh the in-memory CIDR cache
            reload_honeypot_cidrs(&state).await;
            (axum::http::StatusCode::OK, Json(json!({"status":"ok","id":id})))
        }
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                   Json(json!({"status":"error","message":e.to_string()}))),
    }
}

pub async fn remove_honeypot(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return (axum::http::StatusCode::UNAUTHORIZED,
                        Json(json!({"status":"error","message":"Unauthorized"}))),
    };
    if !matches!(claims.role.as_str(), "super_admin" | "tenant_admin" | "admin") {
        return (axum::http::StatusCode::FORBIDDEN,
                Json(json!({"status":"error","message":"Forbidden"})));
    }
    let tenant_id = claims.tenant_id.clone();
    match state.ch_storage.delete_honeypot(&id, &tenant_id).await {
        Ok(_) => {
            reload_honeypot_cidrs(&state).await;
            (axum::http::StatusCode::OK, Json(json!({"status":"ok"})))
        }
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                   Json(json!({"status":"error","message":e.to_string()}))),
    }
}

async fn reload_honeypot_cidrs(state: &AppState) {
    if let Ok(pairs) = state.ch_storage.get_all_honeypot_cidrs().await {
        let parsed: Vec<(ipnetwork::IpNetwork, String)> = pairs.into_iter()
            .filter_map(|(cidr, tid)| {
                cidr.parse::<ipnetwork::IpNetwork>().ok().map(|net| (net, tid))
            })
            .collect();
        *state.honeypot_cidrs.write().await = parsed;
    }
}

// ── Retrospective scan handlers ──────────────────────────────────────────

pub async fn list_fired_rules(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return (axum::http::StatusCode::UNAUTHORIZED,
                        Json(json!({"status":"error","message":"Unauthorized"}))),
    };
    match state.ch_storage.get_fired_rules(&claims.tenant_id).await {
        Ok(rows) => {
            let rules: Vec<serde_json::Value> = rows.into_iter()
                .filter(|(name, _, _)| !name.is_empty())
                .map(|(name, count, sev)| json!({ "name": name, "hit_count": count, "severity": sev }))
                .collect();
            (axum::http::StatusCode::OK, Json(json!({"status":"ok","rules":rules})))
        }
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                   Json(json!({"status":"error","message":e.to_string()}))),
    }
}

pub async fn start_retrospective_scan(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> (axum::http::StatusCode, Json<Value>) {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return (axum::http::StatusCode::UNAUTHORIZED,
                        Json(json!({"status":"error","message":"Unauthorized"}))),
    };
    let rule_id      = body["rule_id"].as_str().unwrap_or("").trim().to_string();
    let rule_name    = body["rule_name"].as_str().unwrap_or("").trim().to_string();
    let rule_content = body["rule_content"].as_str().unwrap_or("").trim().to_string();
    let hours_back   = body["hours_back"].as_u64().unwrap_or(24).min(168) as u32;
    if rule_id.is_empty() && rule_content.is_empty() {
        return (axum::http::StatusCode::BAD_REQUEST,
                Json(json!({"status":"error","message":"rule_id or rule_content required"})));
    }
    let scan_id   = uuid::Uuid::new_v4().to_string();
    let tenant_id = claims.tenant_id.clone();
    let now_str   = chrono::Utc::now().to_rfc3339();
    let scan = RetroScan {
        id:           scan_id.clone(),
        rule_id:      rule_id.clone(),
        rule_name:    rule_name.clone(),
        rule_content: rule_content.clone(),
        hours_back,
        status:       "running".to_string(),
        started_at:   now_str,
        completed_at: None,
        match_count:  0,
        matches:      vec![],
        tenant_id:    tenant_id.clone(),
    };
    state.retro_scans.insert(scan_id.clone(), scan);

    // Spawn background task
    let scans_ref     = state.retro_scans.clone();
    let ch            = state.ch_storage.clone();
    let sid_clone     = scan_id.clone();
    let started_at_ts = chrono::Utc::now().timestamp() as u32;
    tokio::spawn(async move {
        match ch.get_events_for_retrospective(&tenant_id, hours_back, 100_000).await {
            Ok(events) => {
                let matched: Vec<serde_json::Value> = events.into_iter().filter(|ev| {
                    let sig = ev["alert_signature"].as_str().unwrap_or("");
                    let matches_rule = !rule_id.is_empty() && sig.contains(&rule_id);
                    let matches_kw   = !rule_content.is_empty() && (
                        sig.to_lowercase().contains(&rule_content.to_lowercase())
                        || ev["src_ip"].as_str().unwrap_or("").contains(rule_content.as_str())
                        || ev["dst_ip"].as_str().unwrap_or("").contains(rule_content.as_str())
                    );
                    matches_rule || matches_kw
                }).collect();
                let count      = matched.len();
                let done_ts    = chrono::Utc::now().to_rfc3339();
                let done_ts_u32 = chrono::Utc::now().timestamp() as u32;
                let matches_json = serde_json::to_string(&matched).unwrap_or_else(|_| "[]".to_string());
                if let Some(mut entry) = scans_ref.get_mut(&sid_clone) {
                    entry.status       = "done".to_string();
                    entry.completed_at = Some(done_ts);
                    entry.match_count  = count;
                    entry.matches      = matched;
                }
                let _ = ch.save_retro_scan(
                    &sid_clone, &rule_id, &rule_name, &rule_content,
                    hours_back, "done", started_at_ts, done_ts_u32,
                    count, matches_json, &tenant_id,
                ).await;
            }
            Err(e) => {
                let done_ts    = chrono::Utc::now().to_rfc3339();
                let done_ts_u32 = chrono::Utc::now().timestamp() as u32;
                if let Some(mut entry) = scans_ref.get_mut(&sid_clone) {
                    entry.status       = "failed".to_string();
                    entry.completed_at = Some(done_ts);
                }
                let _ = ch.save_retro_scan(
                    &sid_clone, &rule_id, &rule_name, &rule_content,
                    hours_back, "failed", started_at_ts, done_ts_u32,
                    0, "[]".to_string(), &tenant_id,
                ).await;
                tracing::warn!("Retrospective scan {} failed: {}", sid_clone, e);
            }
        }
    });

    (axum::http::StatusCode::OK, Json(json!({"status":"ok","scan_id":scan_id})))
}

pub async fn list_retrospective_scans(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return (axum::http::StatusCode::UNAUTHORIZED,
                        Json(json!({"status":"error","message":"Unauthorized"}))),
    };
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut scans: Vec<serde_json::Value> = state.retro_scans.iter()
        .filter(|e| e.value().tenant_id == claims.tenant_id || claims.role == "super_admin")
        .map(|e| {
            let s = e.value();
            seen_ids.insert(s.id.clone());
            json!({
                "id":           s.id,
                "rule_id":      s.rule_id,
                "rule_name":    s.rule_name,
                "rule_content": s.rule_content,
                "hours_back":   s.hours_back,
                "status":       s.status,
                "started_at":   s.started_at,
                "completed_at": s.completed_at,
                "match_count":  s.match_count,
            })
        })
        .collect();

    // Merge persisted scans from ClickHouse (survive engine restarts)
    if let Ok(rows) = state.ch_storage.list_retro_scans_for_tenant(&claims.tenant_id).await {
        for row in rows {
            if seen_ids.contains(&row.id) { continue; }
            let started = chrono::DateTime::from_timestamp(row.started_at as i64, 0)
                .map(|dt| dt.to_rfc3339()).unwrap_or_default();
            let completed: Option<String> = if row.completed_at > 0 {
                chrono::DateTime::from_timestamp(row.completed_at as i64, 0)
                    .map(|dt| dt.to_rfc3339())
            } else { None };
            scans.push(json!({
                "id":           row.id,
                "rule_id":      row.rule_id,
                "rule_name":    row.rule_name,
                "rule_content": row.rule_content,
                "hours_back":   row.hours_back,
                "status":       row.status,
                "started_at":   started,
                "completed_at": completed,
                "match_count":  row.match_count,
            }));
        }
    }
    (axum::http::StatusCode::OK, Json(json!({"status":"ok","scans":scans})))
}

pub async fn get_retrospective_scan(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    let claims = match extract_claims(&headers) {
        Some(c) => c,
        None => return (axum::http::StatusCode::UNAUTHORIZED,
                        Json(json!({"status":"error","message":"Unauthorized"}))),
    };
    match state.retro_scans.get(&id) {
        Some(e) => {
            let s = e.value();
            if s.tenant_id != claims.tenant_id && claims.role != "super_admin" {
                return (axum::http::StatusCode::FORBIDDEN,
                        Json(json!({"status":"error","message":"Forbidden"})));
            }
            (axum::http::StatusCode::OK, Json(json!({
                "status":       "ok",
                "scan": {
                    "id":           s.id,
                    "rule_id":      s.rule_id,
                    "rule_name":    s.rule_name,
                    "rule_content": s.rule_content,
                    "hours_back":   s.hours_back,
                    "status":       s.status,
                    "started_at":   s.started_at,
                    "completed_at": s.completed_at,
                    "match_count":  s.match_count,
                    "matches":      s.matches,
                }
            })))
        }
        None => {
            // Fallback: look up persisted scan in ClickHouse
            match state.ch_storage.get_retro_scan_by_id(&claims.tenant_id, &id).await {
                Ok(Some(row)) => {
                    let started = chrono::DateTime::from_timestamp(row.started_at as i64, 0)
                        .map(|dt| dt.to_rfc3339()).unwrap_or_default();
                    let completed: Option<String> = if row.completed_at > 0 {
                        chrono::DateTime::from_timestamp(row.completed_at as i64, 0)
                            .map(|dt| dt.to_rfc3339())
                    } else { None };
                    let matches: Vec<serde_json::Value> =
                        serde_json::from_str(&row.matches).unwrap_or_default();
                    (axum::http::StatusCode::OK, Json(json!({
                        "status": "ok",
                        "scan": {
                            "id":           row.id,
                            "rule_id":      row.rule_id,
                            "rule_name":    row.rule_name,
                            "rule_content": row.rule_content,
                            "hours_back":   row.hours_back,
                            "status":       row.status,
                            "started_at":   started,
                            "completed_at": completed,
                            "match_count":  row.match_count,
                            "matches":      matches,
                        }
                    })))
                }
                _ => (axum::http::StatusCode::NOT_FOUND,
                      Json(json!({"status":"error","message":"Scan not found"}))),
            }
        }
    }
}


/// True when the ingest reply says some events could not be queued because the queue was full.
fn ingest_reply_is_overloaded(reply: &Value) -> bool {
    reply.get("queue_full").and_then(|n| n.as_u64()).unwrap_or(0) > 0
}

#[cfg(test)]
mod ingest_reply_tests {
    use super::*;

    #[test]
    fn only_a_full_queue_makes_the_reply_a_retryable_503() {
        assert!(ingest_reply_is_overloaded(&json!({"status":"ok","published":990,"failed":10,"queue_full":10})));
        // a batch that was fully queued: normal 200
        assert!(!ingest_reply_is_overloaded(&json!({"status":"ok","published":1000,"failed":0,"queue_full":0})));
        // events that cannot be serialized are counted as failed but must NOT be retried forever
        assert!(!ingest_reply_is_overloaded(&json!({"status":"ok","published":990,"failed":10,"queue_full":0})));
        // replies from other paths (bad key, rate cap) carry no queue_full field
        assert!(!ingest_reply_is_overloaded(&json!({"status":"error","code":"invalid_sensor_key"})));
    }
}
