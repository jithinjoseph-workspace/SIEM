//! Alert triage - a separate feature that helps find false positives.
//!
//! It does NOT replace or change the existing per-alert Suricata AI check
//! (api/mod.rs) or manual suppression. It only ever produces *recommendations*
//! that a person applies or dismisses; nothing is suppressed automatically.
//!
//!   1. rules first   - multicast, the platform's own endpoint, known update
//!                      servers, trusted cloud scored low: no AI needed
//!   2. group         - one question per (source, destination, tag), not per alert
//!   3. AI last       - only groups the rules can't decide, with a per-tenant
//!                      hourly call budget and a cache so a group is asked once
//!
//! Config (env, all optional):
//!   TRIAGE_AI_MAX_CALLS_PER_HOUR  per-tenant AI call budget          (default 20)
//!   TRIAGE_AI_MAX_GROUPS_PER_RUN  AI calls per tenant per run        (default 10)
//!   TRIAGE_AI_CONCURRENCY         AI calls in flight, all tenants    (default 2)
//!   TRIAGE_INTERVAL_MINS          background run interval, min 5     (default 30)
//!   TRIAGE_OWN_HOSTS              hostnames of this platform, comma-separated
//!   TRIAGE_BENIGN_CIDRS           "cidr=label,..." extra known-good networks

pub mod rules;

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::api::{extract_claims, AppState};
use crate::storage::ClickhouseStorage;
use rules::*;

const LOOKBACK_HOURS: u32 = 24;
const MAX_ALERTS_PER_RUN: u64 = 3000;
const MIN_MANUAL_RUN_GAP_SECS: u64 = 60;
const OWN_HOSTS_KEY: &str = "triage_own_hosts";
const MAX_STORED_HOSTS: usize = 5;

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}
fn ai_limit_per_hour() -> u32 { env_u32("TRIAGE_AI_MAX_CALLS_PER_HOUR", 20) }
fn ai_max_groups_per_run() -> usize { env_u32("TRIAGE_AI_MAX_GROUPS_PER_RUN", 10) as usize }
fn interval_secs() -> u64 { (env_u32("TRIAGE_INTERVAL_MINS", 30).max(5) as u64) * 60 }

fn unix_now() -> u64 { chrono::Utc::now().timestamp().max(0) as u64 }

// ── Stored state (one JSON document per tenant, in ndr.settings) ──────────────
// Same store cloud_suggestions uses. No new table, so no schema migration for
// existing tenants; bounded to MAX_RECS entries.

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TriageState {
    #[serde(default)] pub last_run: u64,
    #[serde(default)] pub ai:       AiBudget,
    #[serde(default)] pub recs:     Vec<Recommendation>,
}

fn state_key(tenant: &str) -> String { format!("alert_triage:{tenant}") }

async fn load_state(ch: &ClickhouseStorage, tenant: &str) -> TriageState {
    ch.get_global_setting(&state_key(tenant)).await
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

async fn save_state(ch: &ClickhouseStorage, tenant: &str, st: &TriageState) -> anyhow::Result<()> {
    ch.set_global_setting(&state_key(tenant), &serde_json::to_string(st)?).await
}

// ── What the rules know about "our own endpoint" ──────────────────────────────

fn env_hosts() -> Vec<String> {
    std::env::var("TRIAGE_OWN_HOSTS").unwrap_or_default()
        .split(',').map(|h| h.trim().to_lowercase()).filter(|h| !h.is_empty()).collect()
}

async fn stored_hosts(ch: &ClickhouseStorage) -> Vec<String> {
    ch.get_global_setting(OWN_HOSTS_KEY).await.unwrap_or_default()
        .split(',').map(|h| h.trim().to_lowercase()).filter(|h| !h.is_empty()).collect()
}

fn valid_hostname(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.contains('.') && h != "localhost"
        && IpAddr::from_str(h).is_err()
        && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !h.chars().all(|c| c.is_ascii_digit() || c == '.')
}

static KNOWN_HOSTS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

/// Sensors report to the same hostname admins open the UI on, so an admin's
/// request tells us this platform's own address without any setup. Only admin
/// roles can add one (the Host header is client-controlled), at most
/// MAX_STORED_HOSTS are kept, and the effect is only a *recommendation*.
async fn note_host(ch: &ClickhouseStorage, headers: &HeaderMap, role: &str) {
    if role != "super_admin" && role != "tenant_admin" { return; }
    let Some(raw) = headers.get("host").and_then(|v| v.to_str().ok()) else { return };
    let host = raw
        .rsplit_once(':')
        .filter(|(_, p)| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        .map(|(h, _)| h).unwrap_or(raw)
        .to_lowercase();
    if !valid_hostname(&host) { return; }

    let known = KNOWN_HOSTS.get_or_init(|| Mutex::new(HashSet::new()));
    if known.lock().map(|k| k.contains(&host)).unwrap_or(false) { return; }

    let mut stored = stored_hosts(ch).await;
    if !env_hosts().contains(&host) && !stored.contains(&host) && stored.len() < MAX_STORED_HOSTS {
        stored.push(host.clone());
        if ch.set_global_setting(OWN_HOSTS_KEY, &stored.join(",")).await.is_ok() {
            info!("triage: learned platform hostname '{host}' from an admin request");
        }
    }
    if let Ok(mut k) = known.lock() { k.insert(host); }
}

async fn build_context(ch: &ClickhouseStorage) -> Context {
    let mut ctx = Context::builtin();
    if let Ok(v) = std::env::var("TRIAGE_BENIGN_CIDRS") {
        ctx.benign_nets.extend(parse_benign_cidrs(&v));
    }
    let mut hosts = env_hosts();
    for h in stored_hosts(ch).await { if !hosts.contains(&h) { hosts.push(h); } }
    for host in hosts {
        // Resolved on every run: tunnel and CDN endpoints change addresses.
        let looked_up = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::lookup_host((host.as_str(), 443u16)),
        ).await;
        if let Ok(Ok(addrs)) = looked_up {
            for a in addrs { ctx.own_ips.insert(a.ip()); }
        }
    }
    ctx
}

// ── One triage run for one tenant ─────────────────────────────────────────────

static AI_GATE: OnceLock<Arc<Semaphore>> = OnceLock::new();
fn ai_gate() -> Arc<Semaphore> {
    AI_GATE.get_or_init(|| Arc::new(Semaphore::new(env_u32("TRIAGE_AI_CONCURRENCY", 2).max(1) as usize))).clone()
}

/// `use_ai=false` (the manual "Run now") applies the rules and reuses earlier AI
/// answers but makes no AI call, so it returns instantly and costs nothing.
pub async fn run_for_tenant(ch: &ClickhouseStorage, tenant: &str, use_ai: bool) -> anyhow::Result<TriageState> {
    let now = unix_now();
    let mut state = load_state(ch, tenant).await;

    let rows: Vec<AlertRow> = ch
        .get_recent_hits_by_tenant(MAX_ALERTS_PER_RUN, tenant, &[], LOOKBACK_HOURS, None)
        .await.unwrap_or_default()
        .iter().filter_map(AlertRow::from_json).collect();

    if rows.is_empty() && state.recs.is_empty() {
        return Ok(state); // nothing to do and nothing stored - don't write a row per idle tenant
    }

    let groups = group_alerts(&rows);
    let ctx = build_context(ch).await;

    let mut decisions: BTreeMap<String, Decision> = BTreeMap::new();
    for g in &groups {
        let mut d = classify(g, &ctx);
        if d.verdict == Verdict::Unknown {
            if let Some(c) = cached_ai(&state.recs, &g.key) {
                d = Decision { verdict: c.verdict, source: Source::Ai, confidence: c.confidence, reason: c.reason.clone() };
            }
        }
        decisions.insert(g.key.clone(), d);
    }

    // Groups the rules could not decide and the AI has not been asked about yet.
    let mut candidates: Vec<&Group> = groups.iter()
        .filter(|g| decisions[&g.key].verdict == Verdict::Unknown && decisions[&g.key].source == Source::Rule)
        .collect();
    candidates.sort_by(|a, b| b.max_score.partial_cmp(&a.max_score).unwrap_or(std::cmp::Ordering::Equal)
        .then(b.count.cmp(&a.count)));

    if use_ai && !candidates.is_empty() && ch.get_tenant_ai_enabled(tenant).await {
        let now_hour = now / 3600;
        let allowed = (state.ai.remaining(now_hour, ai_limit_per_hour()) as usize).min(ai_max_groups_per_run());
        for g in candidates.into_iter().take(allowed) {
            state.ai.note_call(now_hour); // counted before the call: a failing provider still uses the budget
            let reply = {
                let _permit = ai_gate().acquire_owned().await;
                provigil_common::ai::generate_simple(&ch.client, "threat", AI_SYSTEM, &build_prompt(g)).await
            };
            match parse_ai_reply(&reply) {
                Some(a) => { decisions.insert(g.key.clone(), decision_from_ai(a)); }
                None    => warn!("triage: no usable AI answer for tenant '{tenant}' group '{}'", g.key),
            }
        }
    }

    let fresh: Vec<Recommendation> = groups.iter()
        .map(|g| Recommendation::from_group(g, &decisions[&g.key], now))
        .collect();
    state.recs = merge(&state.recs, fresh, now);
    state.last_run = now;
    save_state(ch, tenant, &state).await?;
    Ok(state)
}

/// Background job: leader only, every TRIAGE_INTERVAL_MINS.
pub fn spawn_triage(ch: Arc<ClickhouseStorage>, is_leader: Arc<AtomicBool>) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(240)).await;
        loop {
            if is_leader.load(Ordering::Relaxed) {
                let tenants = ch.get_all_tenants().await.unwrap_or_default();
                let sem = Arc::new(Semaphore::new(crate::threat::tenant_scan_concurrency()));
                let mut handles = Vec::with_capacity(tenants.len());
                for t in tenants {
                    let ch2 = Arc::clone(&ch);
                    let sem2 = Arc::clone(&sem);
                    handles.push(tokio::spawn(async move {
                        let _permit = sem2.acquire().await;
                        if let Err(e) = run_for_tenant(&ch2, &t, true).await {
                            warn!("triage: tenant '{t}' failed: {e}");
                        }
                    }));
                }
                futures_util::future::join_all(handles).await;
            }
            tokio::time::sleep(Duration::from_secs(interval_secs())).await;
        }
    });
}

// ── API ───────────────────────────────────────────────────────────────────────

fn unauthorized() -> Json<Value> {
    Json(json!({ "status": "error", "message": "Unauthorized" }))
}

async fn view(ch: &ClickhouseStorage, tenant: &str, st: &TriageState, allowed: &[String], extra: Value) -> Json<Value> {
    let now_hour = unix_now() / 3600;
    let limit = ai_limit_per_hour();
    let ai_enabled = ch.get_tenant_ai_enabled(tenant).await;

    // A user restricted to some sensors only sees (and is only counted) the groups made entirely of
    // their own sensors' alerts. Unrestricted users (empty `allowed`) see everything, as before.
    let mine: Vec<&Recommendation> = st.recs.iter().filter(|r| visible_to(&r.sensors, allowed)).collect();
    let count = |verdict: Verdict| mine.iter().filter(|r| r.status == "pending" && r.verdict == verdict).count();
    let pending: Vec<&Recommendation> = mine.iter().copied().filter(|r| r.status == "pending").collect();
    let alerts_in_pending: u32 = pending.iter().map(|r| r.alert_count).sum();
    let alerts_benign: u32 = pending.iter().filter(|r| r.verdict == Verdict::Benign).map(|r| r.alert_count).sum();

    Json(json!({
        "status": "ok",
        "last_run": st.last_run,
        "lookback_hours": LOOKBACK_HOURS,
        "ai": {
            "enabled": ai_enabled,
            "mode": "recommend-only",
            "budget_per_hour": limit,
            "used_this_hour": st.ai.used(now_hour),
            "remaining_this_hour": st.ai.remaining(now_hour, limit),
        },
        "summary": {
            "groups": pending.len(),
            "alerts": alerts_in_pending,
            "benign": count(Verdict::Benign),
            "suspicious": count(Verdict::Suspicious),
            "unknown": count(Verdict::Unknown),
            "alerts_likely_benign": alerts_benign,
            "applied": mine.iter().filter(|r| r.status == "applied").count(),
            "dismissed": mine.iter().filter(|r| r.status == "dismissed").count(),
        },
        "recommendations": pending,
        "info": extra,
    }))
}

/// GET /api/triage
pub async fn get_triage(State(state): State<AppState>, headers: HeaderMap) -> Json<Value> {
    let Some(claims) = extract_claims(&headers) else { return unauthorized() };
    note_host(&state.ch_storage, &headers, &claims.role).await;
    let st = load_state(&state.ch_storage, &claims.tenant_id).await;
    view(&state.ch_storage, &claims.tenant_id, &st, &claims.sensor_ids, Value::Null).await
}

/// POST /api/triage/run - rules + cached answers only, instant, no AI call.
pub async fn run_now(State(state): State<AppState>, headers: HeaderMap) -> Json<Value> {
    let Some(claims) = extract_claims(&headers) else { return unauthorized() };
    note_host(&state.ch_storage, &headers, &claims.role).await;
    let st = load_state(&state.ch_storage, &claims.tenant_id).await;
    if unix_now().saturating_sub(st.last_run) < MIN_MANUAL_RUN_GAP_SECS {
        return view(&state.ch_storage, &claims.tenant_id, &st, &claims.sensor_ids, json!({ "throttled": true })).await;
    }
    match run_for_tenant(&state.ch_storage, &claims.tenant_id, false).await {
        Ok(st)  => view(&state.ch_storage, &claims.tenant_id, &st, &claims.sensor_ids, Value::Null).await,
        Err(e)  => Json(json!({ "status": "error", "message": e.to_string() })),
    }
}

#[derive(Deserialize, Default)]
pub struct ApplyBody { pub hours: Option<u32> }

/// POST /api/triage/:id/apply - the person's decision. Creates the same kind of
/// suppression as the Suppress button on the alerts page (source + tag).
pub async fn apply(
    State(state): State<AppState>, headers: HeaderMap,
    Path(id): Path<String>, Json(body): Json<ApplyBody>,
) -> Json<Value> {
    let Some(claims) = extract_claims(&headers) else { return unauthorized() };
    let mut st = load_state(&state.ch_storage, &claims.tenant_id).await;
    // A group the user cannot see is answered exactly like one that does not exist.
    let Some(rec) = st.recs.iter().find(|r| r.id == id && visible_to(&r.sensors, &claims.sensor_ids)).cloned() else {
        return Json(json!({ "status": "error", "message": "Recommendation not found" }));
    };
    if rec.status != "pending" {
        return Json(json!({ "status": "error", "message": "Already handled" }));
    }
    if rec.verdict == Verdict::Suspicious {
        return Json(json!({ "status": "error", "message": "Suspicious groups can't be suppressed from triage - review the alerts instead." }));
    }

    // The suppression hides a tag for a whole source, not just this destination.
    // If another pending group with the same source and tag needs a human, applying
    // this one would hide it too - refuse instead.
    let covered: Vec<String> = st.recs.iter()
        .filter(|r| r.status == "pending" && r.src_ip == rec.src_ip && r.tag == rec.tag)
        .map(|r| r.id.clone()).collect();
    // The suppression is tenant-wide for this source and tag. A restricted analyst may not use it
    // when it would also hide the same alerts on sensors outside their assignment.
    if st.recs.iter().any(|r| covered.contains(&r.id) && !visible_to(&r.sensors, &claims.sensor_ids)) {
        return Json(json!({
            "status": "error",
            "message": "The same source and alert also occur on sensors that are not assigned to you, so it can't be hidden from here. Ask a tenant admin."
        }));
    }
    if st.recs.iter().any(|r| covered.contains(&r.id) && r.verdict == Verdict::Suspicious) {
        return Json(json!({
            "status": "error",
            "message": "Another group with the same source and tag needs review, and hiding this one would hide it too. Review that one first."
        }));
    }

    let hours = body.hours.unwrap_or(24).clamp(1, 168);
    let now = unix_now();
    let reason: String = format!(
        "Applied from alert triage ({} verdict, {}%): {}",
        if rec.source == Source::Ai { "AI" } else { "rule" }, rec.confidence, rec.reason
    ).chars().take(400).collect();

    // Empty community_id = group scope: hides this tag for this source, as the
    // Suppress button does. Reads the tenant's own table since the suppression fix.
    if let Err(e) = state.ch_storage.save_ai_suppression(
        &claims.tenant_id, 0, &rec.tag, "by_src", &rec.src_ip,
        &rec.src_ip, &rec.dst_ip, "", &reason, rec.confidence, "",
        Some((now + hours as u64 * 3600) as u32), "group",
    ).await {
        return Json(json!({ "status": "error", "message": e.to_string() }));
    }

    // Every pending group with this source and tag is now hidden by that one
    // suppression, so they are all recorded as applied together.
    let mut also = 0usize;
    for r in st.recs.iter_mut().filter(|r| covered.contains(&r.id)) {
        r.status = "applied".into();
        r.updated_at = now;
        if r.id != id { also += 1; }
    }
    let _ = save_state(&state.ch_storage, &claims.tenant_id, &st).await;
    view(&state.ch_storage, &claims.tenant_id, &st, &claims.sensor_ids,
         json!({ "applied_hours": hours, "also_covered_groups": also })).await
}

/// POST /api/triage/:id/dismiss - "keep showing these, stop recommending".
pub async fn dismiss(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Json<Value> {
    let Some(claims) = extract_claims(&headers) else { return unauthorized() };
    let mut st = load_state(&state.ch_storage, &claims.tenant_id).await;
    let now = unix_now();
    let allowed = claims.sensor_ids.clone();
    match st.recs.iter_mut().find(|r| r.id == id && r.status == "pending" && visible_to(&r.sensors, &allowed)) {
        Some(r) => { r.status = "dismissed".into(); r.updated_at = now; }
        None => return Json(json!({ "status": "error", "message": "Recommendation not found" })),
    }
    let _ = save_state(&state.ch_storage, &claims.tenant_id, &st).await;
    view(&state.ch_storage, &claims.tenant_id, &st, &claims.sensor_ids, Value::Null).await
}
