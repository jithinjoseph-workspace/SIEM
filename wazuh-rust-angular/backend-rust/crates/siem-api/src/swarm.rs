//! Federated threat swarm (siem-swarm): this deployment shares anonymous attack
//! fingerprints with other AETHER deployments through a hub, and matches its
//! tenants' alerts against what the others saw. Never raw logs.
//!
//! - the super admin joins a hub (URL, member token, community key), and may
//!   also run this deployment as a hub for others (members with tokens);
//! - each tenant admin chooses: off (default), receive only, or share and receive;
//! - every 15 minutes: fingerprints of sharing tenants are sent, the feed is
//!   pulled, and receiving tenants' recent alerts are matched;
//! - a match is shown and makes SOAR's "threat intel" condition true; it never
//!   blocks on its own.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use siem_swarm::{FeedEntry, Fingerprint};

use crate::db::DocTable;
use crate::tenancy::{AuthCtx, DEFAULT_TENANT};
use crate::AppState;

const CONFIG_DOC: &str = "swarm_config";
const MEMBERS_DOC: &str = "swarm_members";
const TENANT_DOC: &str = "swarm_tenant";
const SYNC_SECS: u64 = 900;
const MAX_SUBMIT: usize = 5000;
const REPORT_DAYS: u32 = 90;

pub const DDL: [&str; 1] = [
    // the hub's reports: one row per (organisation, token, day), a resend replaces it
    "CREATE TABLE IF NOT EXISTS swarm_hub_reports (member String, org String, token String, kind LowCardinality(String), techniques Array(String), rule_ids Array(UInt32), severity UInt8, day UInt32, sightings UInt32, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY (org, token, day) TTL toDate(day) + INTERVAL 180 DAY",
];

/// Platform settings (super admin).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Take part (send what sharing tenants allow, pull the feed).
    pub enabled: bool,
    /// The hub; empty = this deployment's own hub.
    pub hub_url: String,
    pub member_token: String,
    /// Shared by all members (the keyed hashes only match within one community).
    pub community_key: String,
    pub epsilon: f64,
    /// Serve as a hub for other deployments.
    pub hub_enabled: bool,
    pub k: u32,
    pub fast_track_critical: bool,
    /// Makes the tenants' organisation ids opaque to the hub; never leaves.
    pub deployment_secret: String,
    pub last_sync: u64,
    pub last_error: String,
}

impl Default for Config {
    fn default() -> Self {
        Config { enabled: false, hub_url: String::new(), member_token: String::new(), community_key: String::new(), epsilon: siem_swarm::DEFAULT_EPSILON, hub_enabled: false, k: siem_swarm::DEFAULT_K, fast_track_critical: true, deployment_secret: String::new(), last_sync: 0, last_error: String::new() }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Member {
    pub id: String,
    pub name: String,
    pub token_sha256: String,
    pub created_at: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSetting {
    /// "off" | "receive" | "share"
    pub level: String,
}

impl Default for TenantSetting {
    fn default() -> Self {
        TenantSetting { level: "off".into() }
    }
}

/// The feed in memory (anonymous tokens only) and the tenants' levels, for the
/// alert-time check SOAR uses.
static FEED: RwLock<Option<BTreeMap<String, FeedEntry>>> = RwLock::new(None);
static KEY: RwLock<Option<Vec<u8>>> = RwLock::new(None);
static LEVELS: RwLock<Option<HashMap<String, String>>> = RwLock::new(None);
/// The tokens each sharing tenant reported itself: a fingerprint only it reported is no news to it.
static OWN: RwLock<Option<HashMap<String, std::collections::HashSet<String>>>> = RwLock::new(None);

/// Another organisation saw it too (not only this tenant's own report).
fn from_others(tenant: &str, e: &FeedEntry) -> bool {
    e.orgs >= 2 || !OWN.read().unwrap().as_ref().and_then(|o| o.get(tenant)).is_some_and(|s| s.contains(&e.token))
}
static SENT: Mutex<u64> = Mutex::new(0);
/// Where the platform's swarm settings and the hub's reports live (the default tenant; tests use a scratch one).
static PLATFORM: RwLock<Option<String>> = RwLock::new(None);
static TABLES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn platform() -> String {
    PLATFORM.read().unwrap().clone().unwrap_or_else(|| DEFAULT_TENANT.to_string())
}

#[cfg(test)]
pub fn set_platform_for_tests(t: &str) {
    *PLATFORM.write().unwrap() = Some(t.to_string());
    TABLES.store(false, std::sync::atomic::Ordering::SeqCst);
}

async fn ensure_tables(state: &AppState) {
    if !TABLES.swap(true, std::sync::atomic::Ordering::SeqCst) {
        for d in DDL {
            let _ = state.db.tenant_client(&platform()).query(d).execute().await;
        }
    }
}

fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

fn today() -> u32 {
    (now() / 86400) as u32
}

fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

async fn load<T: for<'de> Deserialize<'de> + Default>(state: &AppState, tenant: &str, id: &str) -> T {
    state.db.doc(tenant, DocTable::AnalystState, id).await.ok().flatten().and_then(|d| serde_json::from_str(&d).ok()).unwrap_or_default()
}

async fn save<T: Serialize>(state: &AppState, tenant: &str, id: &str, v: &T) -> Result<(), String> {
    state.db.put_doc(tenant, DocTable::AnalystState, id, &serde_json::to_string(v).map_err(|e| e.to_string())?).await
}

pub async fn config(state: &AppState) -> Config {
    let mut c: Config = load(state, &platform(), CONFIG_DOC).await;
    if c.deployment_secret.is_empty() {
        c.deployment_secret = random_hex(32);
        let _ = save(state, &platform(), CONFIG_DOC, &c).await;
    }
    c
}

pub async fn tenant_level(state: &AppState, tenant: &str) -> String {
    load::<TenantSetting>(state, tenant, TENANT_DOC).await.level
}

// ───────────────────────── hub ─────────────────────────

fn valid(f: &Fingerprint) -> bool {
    let tech = |t: &String| t.len() <= 12 && t.starts_with('T') && t[1..].chars().all(|c| c.is_ascii_digit() || c == '.');
    f.token.len() == 32 && f.token.chars().all(|c| c.is_ascii_hexdigit()) && f.org.len() <= 64 && f.severity <= 3 && f.sightings <= 1_000_000 && f.techniques.len() <= 50 && f.techniques.iter().all(tech) && f.rule_ids.len() <= 50 && f.day.abs_diff(today()) <= 7
}

/// Stores reports (the hub side; `member` = the deployment that sent them).
pub async fn hub_store(state: &AppState, member: &str, fps: &[Fingerprint]) -> Result<usize, String> {
    ensure_tables(state).await;
    let good: Vec<&Fingerprint> = fps.iter().filter(|f| valid(f)).take(MAX_SUBMIT).collect();
    let tc = state.db.tenant_client(&platform());
    let version = chrono::Utc::now().timestamp_micros().max(0) as u64;
    for f in &good {
        tc.query("INSERT INTO swarm_hub_reports (member, org, token, kind, techniques, rule_ids, severity, day, sightings, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(member)
            .bind(format!("{member}/{}", f.org))
            .bind(&f.token)
            .bind(serde_json::to_value(f.kind).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default())
            .bind(&f.techniques)
            .bind(&f.rule_ids)
            .bind(f.severity)
            .bind(f.day)
            .bind(f.sightings)
            .bind(version)
            .execute()
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(good.len())
}

#[derive(clickhouse::Row, Deserialize)]
struct ReportRow {
    member: String,
    org: String,
    token: String,
    kind: String,
    techniques: Vec<String>,
    rule_ids: Vec<u32>,
    severity: u8,
    day: u32,
    sightings: u32,
}

/// The published feed (the hub side).
pub async fn hub_feed(state: &AppState, c: &Config) -> Vec<FeedEntry> {
    ensure_tables(state).await;
    let rows = state
        .db
        .tenant_client(&platform())
        .query("SELECT member, org, token, kind, techniques, rule_ids, severity, day, sightings FROM swarm_hub_reports FINAL WHERE day >= ? LIMIT 500000")
        .bind(today().saturating_sub(REPORT_DAYS))
        .fetch_all::<ReportRow>()
        .await
        .unwrap_or_default();
    // Who counts towards k: each of this deployment's tenants, but a remote member only
    // once (it could invent org codes to push a fingerprint over k alone), and an org
    // that reached the hub both ways only once.
    let code = |org: &str| org.split_once('/').map_or(org, |(_, c)| c).to_string();
    let local: std::collections::HashSet<(String, String)> = rows.iter().filter(|r| r.member == "local").map(|r| (r.token.clone(), code(&r.org))).collect();
    let reports: Vec<Fingerprint> = rows
        .into_iter()
        .filter_map(|r| {
            let c = code(&r.org);
            let voter = if r.member == "local" || local.contains(&(r.token.clone(), c.clone())) { c } else { format!("member:{}", r.member) };
            Some(Fingerprint { kind: serde_json::from_value(json!(r.kind)).ok()?, token: r.token, techniques: r.techniques, rule_ids: r.rule_ids, severity: r.severity, day: r.day, sightings: r.sightings, org: voter })
        })
        .collect();
    siem_swarm::aggregate(&reports, c.k.max(1), c.fast_track_critical)
}

/// The member a bearer token belongs to.
async fn member_of(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let tok = headers.get("authorization")?.to_str().ok()?.strip_prefix("Bearer ")?.trim().to_string();
    if tok.len() < 32 {
        return None;
    }
    let h = sha256_hex(&tok);
    let mut members: Vec<Member> = load(state, &platform(), MEMBERS_DOC).await;
    let m = members.iter_mut().find(|m| constant_eq(&m.token_sha256, &h))?;
    m.last_seen = now();
    let name = m.name.clone();
    let _ = save(state, &platform(), MEMBERS_DOC, &members).await;
    Some(name)
}

fn constant_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize)]
pub struct SubmitBody {
    pub fingerprints: Vec<Fingerprint>,
}

/// `POST /api/v1/swarm/hub/submit` (member token).
pub async fn hub_submit(State(state): State<AppState>, headers: HeaderMap, Json(b): Json<SubmitBody>) -> axum::response::Response {
    let c = config(&state).await;
    if !c.hub_enabled {
        return (StatusCode::NOT_FOUND, "this deployment is not a swarm hub").into_response();
    }
    let Some(member) = member_of(&state, &headers).await else { return (StatusCode::UNAUTHORIZED, "unknown member").into_response() };
    match hub_store(&state, &member, &b.fingerprints).await {
        Ok(n) => Json(json!({ "accepted": n, "rejected": b.fingerprints.len() - n })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

/// `GET /api/v1/swarm/hub/feed` (member token).
pub async fn hub_feed_handler(State(state): State<AppState>, headers: HeaderMap) -> axum::response::Response {
    let c = config(&state).await;
    if !c.hub_enabled {
        return (StatusCode::NOT_FOUND, "this deployment is not a swarm hub").into_response();
    }
    if member_of(&state, &headers).await.is_none() {
        return (StatusCode::UNAUTHORIZED, "unknown member").into_response();
    }
    Json(json!({ "fingerprints": hub_feed(&state, &c).await })).into_response()
}

// ───────────────────────── member ─────────────────────────

/// What a tenant would share now (anonymized), from its last 24 h of alerts.
pub async fn fingerprints_of(state: &AppState, tenant: &str, c: &Config) -> Vec<Fingerprint> {
    let since = (chrono::Utc::now().timestamp_millis().max(0) as u64).saturating_sub(86_400_000);
    let alerts: Vec<Value> = state.db.alerts_since(tenant, since, crate::history::MAX_ROWS).await.unwrap_or_default().iter().filter_map(|a| serde_json::to_value(a).ok()).collect();
    let org = siem_swarm::org_id(c.deployment_secret.as_bytes(), tenant);
    let mut rng = rand::thread_rng();
    siem_swarm::observe(&alerts, today()).iter().map(|o| siem_swarm::anonymize(o, c.community_key.as_bytes(), &org, c.epsilon, &mut rng)).collect()
}

async fn send(state: &AppState, c: &Config, fps: &[Fingerprint]) -> Result<(), String> {
    if fps.is_empty() {
        return Ok(());
    }
    if c.hub_url.trim().is_empty() {
        return hub_store(state, "local", fps).await.map(|_| ());
    }
    let r = reqwest::Client::new()
        .post(format!("{}/api/v1/swarm/hub/submit", c.hub_url.trim_end_matches('/')))
        .bearer_auth(&c.member_token)
        .json(&json!({ "fingerprints": fps }))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("hub: {e}"))?;
    if !r.status().is_success() {
        return Err(format!("hub refused the fingerprints: HTTP {}", r.status()));
    }
    Ok(())
}

async fn pull(state: &AppState, c: &Config) -> Result<Vec<FeedEntry>, String> {
    if c.hub_url.trim().is_empty() {
        return Ok(hub_feed(state, c).await);
    }
    let r = reqwest::Client::new()
        .get(format!("{}/api/v1/swarm/hub/feed", c.hub_url.trim_end_matches('/')))
        .bearer_auth(&c.member_token)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| format!("hub: {e}"))?;
    if !r.status().is_success() {
        return Err(format!("hub refused the feed request: HTTP {}", r.status()));
    }
    let v: Value = r.json().await.map_err(|e| format!("hub feed: {e}"))?;
    Ok(serde_json::from_value(v["fingerprints"].clone()).unwrap_or_default())
}

/// One round: send the sharing tenants' fingerprints, pull the feed, match.
pub async fn sync(state: &AppState) -> Result<(usize, usize, usize), String> {
    let mut c = config(state).await;
    if !c.enabled {
        return Ok((0, 0, 0));
    }
    if c.community_key.trim().len() < 16 {
        return Err("the community key is missing (at least 16 characters, the same for every member)".into());
    }
    let tenants = crate::predictions::tenant_ids(state);
    let mut levels = HashMap::new();
    for t in &tenants {
        levels.insert(t.clone(), tenant_level(state, t).await);
    }
    *LEVELS.write().unwrap() = Some(levels.clone());
    *KEY.write().unwrap() = Some(c.community_key.as_bytes().to_vec());

    let mut sent = 0;
    let mut own: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    for t in tenants.iter().filter(|t| levels.get(*t).map(String::as_str) == Some("share")) {
        let fps = fingerprints_of(state, t, &c).await;
        sent += fps.len();
        send(state, &c, &fps).await?;
        own.insert(t.clone(), fps.into_iter().map(|f| f.token).collect());
    }
    *OWN.write().unwrap() = Some(own);
    *SENT.lock().unwrap() += sent as u64;
    let feed = pull(state, &c).await?;
    let n_feed = feed.len();
    *FEED.write().unwrap() = Some(feed.into_iter().map(|e| (e.token.clone(), e)).collect());
    let mut matched = 0;
    for t in tenants.iter().filter(|t| matches!(levels.get(*t).map(String::as_str), Some("share") | Some("receive"))) {
        matched += match_tenant(state, t, &c).await;
    }
    c.last_sync = now();
    c.last_error.clear();
    let _ = save(state, &platform(), CONFIG_DOC, &c).await;
    Ok((sent, n_feed, matched))
}

/// Matches a tenant's alerts of the last 24 h against the feed; new matches are stored.
pub async fn match_tenant(state: &AppState, tenant: &str, c: &Config) -> usize {
    let feed = FEED.read().unwrap().clone().unwrap_or_default();
    if feed.is_empty() {
        return 0;
    }
    let since = (chrono::Utc::now().timestamp_millis().max(0) as u64).saturating_sub(86_400_000);
    let alerts = state.db.alerts_since(tenant, since, crate::history::MAX_ROWS).await.unwrap_or_default();
    let mut seen: std::collections::HashSet<String> = state.db.docs(tenant, DocTable::SwarmMatches, 100_000).await.unwrap_or_default().iter().filter_map(|d| serde_json::from_str::<Value>(d).ok()?["id"].as_str().map(String::from)).collect();
    let mut n = 0;
    for a in alerts {
        let Ok(v) = serde_json::to_value(&a) else { continue };
        for (kind, value, e) in siem_swarm::matches(&v, c.community_key.as_bytes(), &feed).into_iter().filter(|(_, _, e)| from_others(tenant, e)) {
            // the matched value is the tenant's own data: it stays in its database
            let id = format!("{}:{}", e.token, a.agent.id);
            if !seen.insert(id.clone()) {
                continue;
            }
            let doc = json!({
                "id": id, "kind": kind, "value": value, "feed": e,
                "rule_id": a.rule.id, "rule_description": a.rule.description, "level": a.rule.level,
                "agent_id": a.agent.id, "agent_name": a.agent.name, "alert_id": a.id, "seen_at": a.timestamp.timestamp(),
            });
            if state.db.put_doc(tenant, DocTable::SwarmMatches, &id, &doc.to_string()).await.is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// For SOAR at alert time: does this tenant receive the swarm and is the alert in the feed?
pub fn known(tenant: &str, alert: &Value) -> bool {
    let receives = LEVELS.read().unwrap().as_ref().and_then(|l| l.get(tenant).cloned()).is_some_and(|l| l == "receive" || l == "share");
    if !receives {
        return false;
    }
    let (Some(key), Some(feed)) = (KEY.read().unwrap().clone(), FEED.read().unwrap().clone()) else { return false };
    // a fast-tracked fingerprint rests on one report: shown to analysts, not acted on
    siem_swarm::matches(alert, &key, &feed).iter().any(|(_, _, e)| !e.fast_tracked && from_others(tenant, e))
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(120)).await;
        loop {
            if state.db.is_connected() {
                match sync(&state).await {
                    Ok((s, f, m)) if s + m > 0 => tracing::info!("threat swarm: {s} fingerprint(s) sent, feed {f}, {m} match(es)"),
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("threat swarm: {e}");
                        let mut c = config(&state).await;
                        c.last_error = e;
                        let _ = save(&state, &platform(), CONFIG_DOC, &c).await;
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(SYNC_SECS)).await;
        }
    });
}

// ───────────────────────── user API ─────────────────────────

fn deny(m: &str) -> axum::response::Response {
    (StatusCode::FORBIDDEN, Json(json!({ "status": "error", "message": m }))).into_response()
}

/// `GET /api/v1/swarm/status`: the platform's federation and the caller's tenant's participation.
pub async fn status(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    let c = config(&state).await;
    let t = ctx.scope();
    let matches = state.db.docs(&t, DocTable::SwarmMatches, 1000).await.unwrap_or_default().len();
    Json(json!({
        "status": "ok",
        "platform": { "enabled": c.enabled, "hub": if c.hub_url.trim().is_empty() { "this deployment".to_string() } else { c.hub_url.clone() }, "last_sync": c.last_sync, "last_error": c.last_error, "epsilon": c.epsilon, "k": c.k },
        "tenant": { "level": tenant_level(&state, &t).await },
        "feed_size": FEED.read().unwrap().as_ref().map_or(0, |f| f.len()),
        "matches": matches,
    }))
    .into_response()
}

/// `PUT /api/v1/swarm/tenant` (tenant admin): off / receive / share.
pub async fn put_tenant(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(s): Json<TenantSetting>) -> axum::response::Response {
    if !ctx.is_tenant_admin() {
        return deny("Only the tenant admin decides whether the tenant takes part");
    }
    if !matches!(s.level.as_str(), "off" | "receive" | "share") {
        return (StatusCode::BAD_REQUEST, Json(json!({ "status": "error", "message": "level is off, receive or share" }))).into_response();
    }
    let t = ctx.scope();
    match save(&state, &t, TENANT_DOC, &s).await {
        Ok(()) => {
            if let Some(l) = LEVELS.write().unwrap().as_mut() {
                l.insert(t, s.level.clone());
            }
            Json(json!({ "status": "ok", "level": s.level })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "message": e }))).into_response(),
    }
}

/// `GET /api/v1/swarm/preview` (tenant admin): exactly what the tenant would send now.
pub async fn preview(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    if !ctx.is_tenant_admin() {
        return deny("Only the tenant admin sees this");
    }
    let mut c = config(&state).await;
    if c.community_key.is_empty() {
        c.community_key = "preview-only-not-the-community-key".into();
    }
    let fps = fingerprints_of(&state, &ctx.scope(), &c).await;
    Json(json!({ "status": "ok", "count": fps.len(), "fingerprints": fps.into_iter().take(50).collect::<Vec<_>>() })).into_response()
}

/// `GET /api/v1/swarm/matches`: the tenant's alerts that other organisations saw too.
pub async fn matches(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let docs = state.db.docs(&ctx.scope(), DocTable::SwarmMatches, 500).await.unwrap_or_default();
    Json(json!({ "status": "ok", "matches": docs.iter().filter_map(|d| serde_json::from_str::<Value>(d).ok()).collect::<Vec<_>>() }))
}

fn masked(c: &Config) -> Value {
    json!({
        "enabled": c.enabled, "hub_url": c.hub_url, "member_token_set": !c.member_token.is_empty(), "community_key_set": !c.community_key.is_empty(),
        "epsilon": c.epsilon, "hub_enabled": c.hub_enabled, "k": c.k, "fast_track_critical": c.fast_track_critical, "last_sync": c.last_sync, "last_error": c.last_error,
    })
}

/// `GET /api/v1/swarm/config` (super admin; secrets are not returned).
pub async fn get_config(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    if !ctx.is_super() {
        return deny("Only the platform admin manages the federation");
    }
    let c = config(&state).await;
    let members: Vec<Member> = load(&state, &platform(), MEMBERS_DOC).await;
    Json(json!({ "status": "ok", "config": masked(&c), "members": members.iter().map(|m| json!({ "id": m.id, "name": m.name, "created_at": m.created_at, "last_seen": m.last_seen })).collect::<Vec<_>>(), "sent_since_start": *SENT.lock().unwrap() })).into_response()
}

#[derive(Deserialize)]
pub struct ConfigBody {
    pub enabled: bool,
    #[serde(default)]
    pub hub_url: String,
    /// Empty = keep.
    #[serde(default)]
    pub member_token: String,
    #[serde(default)]
    pub community_key: String,
    pub epsilon: Option<f64>,
    pub hub_enabled: bool,
    pub k: Option<u32>,
    pub fast_track_critical: Option<bool>,
}

/// `PUT /api/v1/swarm/config` (super admin).
pub async fn put_config(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(b): Json<ConfigBody>) -> axum::response::Response {
    if !ctx.is_super() {
        return deny("Only the platform admin manages the federation");
    }
    let mut c = config(&state).await;
    let url = b.hub_url.trim().to_string();
    if !url.is_empty() && !(url.starts_with("https://") || url.starts_with("http://")) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "status": "error", "message": "The hub URL starts with https://" }))).into_response();
    }
    if !b.community_key.is_empty() && b.community_key.trim().len() < 16 {
        return (StatusCode::BAD_REQUEST, Json(json!({ "status": "error", "message": "The community key has at least 16 characters" }))).into_response();
    }
    c.enabled = b.enabled;
    c.hub_url = url;
    if !b.member_token.is_empty() {
        c.member_token = b.member_token.trim().into();
    }
    if !b.community_key.is_empty() {
        c.community_key = b.community_key.trim().into();
    }
    c.epsilon = b.epsilon.unwrap_or(c.epsilon).clamp(0.1, 10.0);
    c.hub_enabled = b.hub_enabled;
    c.k = b.k.unwrap_or(c.k).clamp(1, 20);
    c.fast_track_critical = b.fast_track_critical.unwrap_or(c.fast_track_critical);
    match save(&state, &platform(), CONFIG_DOC, &c).await {
        Ok(()) => {
            if !c.enabled {
                // otherwise SOAR keeps flagging alerts from the old feed until a restart
                *FEED.write().unwrap() = None;
                *KEY.write().unwrap() = None;
            }
            Json(json!({ "status": "ok", "config": masked(&c) })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "message": e }))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct MemberBody {
    pub name: String,
}

/// `POST /api/v1/swarm/members` (super admin, hub): a member and its token (shown once).
pub async fn add_member(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(b): Json<MemberBody>) -> axum::response::Response {
    if !ctx.is_super() {
        return deny("Only the platform admin manages the federation");
    }
    let name: String = b.name.trim().chars().filter(|c| c.is_alphanumeric() || " -_.".contains(*c)).take(60).collect();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "status": "error", "message": "A member needs a name" }))).into_response();
    }
    let token = format!("swm_{}", random_hex(24));
    let mut members: Vec<Member> = load(&state, &platform(), MEMBERS_DOC).await;
    members.push(Member { id: random_hex(8), name: name.clone(), token_sha256: sha256_hex(&token), created_at: now(), last_seen: 0 });
    match save(&state, &platform(), MEMBERS_DOC, &members).await {
        Ok(()) => Json(json!({ "status": "ok", "name": name, "token": token })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "message": e }))).into_response(),
    }
}

/// `DELETE /api/v1/swarm/members/:id` (super admin).
pub async fn remove_member(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> axum::response::Response {
    if !ctx.is_super() {
        return deny("Only the platform admin manages the federation");
    }
    let mut members: Vec<Member> = load(&state, &platform(), MEMBERS_DOC).await;
    members.retain(|m| m.id != id);
    match save(&state, &platform(), MEMBERS_DOC, &members).await {
        Ok(()) => Json(json!({ "status": "ok" })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": "error", "message": e }))).into_response(),
    }
}

/// `POST /api/v1/swarm/sync` (super admin): a round now.
pub async fn sync_now(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    if !ctx.is_super() {
        return deny("Only the platform admin runs this");
    }
    match sync(&state).await {
        Ok((s, f, m)) => Json(json!({ "status": "ok", "sent": s, "feed": f, "matched": m })).into_response(),
        Err(e) => Json(json!({ "status": "error", "message": e })).into_response(),
    }
}
