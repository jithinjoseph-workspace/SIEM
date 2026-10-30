//! Neurosymbolic decisions (siem-decision) for the SIEM's high-impact actions,
//! per tenant: SOAR `block_ip` and hiding alerts from AI triage. The AI's
//! evidence (the triage verdict and confidence) and the alert's context become
//! facts; the tenant's policy (hard guardrails it cannot remove, plus rules
//! with thresholds it sets) decides allow / needs approval / deny. Every
//! decision, approval and policy change is a record in the tenant's
//! hash-chained `siem_decisions` table that auditors can export and re-verify.
//!
//! API: `/api/v1/siem/decisions` (list, record, verify, export),
//! `/policy` (tenant admin edits), `/:id/approve` and `/:id/reject` (tenant admin).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;

use axum::extract::{Extension, Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use siem_decision::{cmp, fact, Cond, Effect, Facts, Op, Origin, Outcome, Record, Rule, Val};

use crate::db::DocTable;
use crate::tenancy::AuthCtx;
use crate::AppState;

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS siem_decisions (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id";
const POLICY_DOC: &str = "decision_policy";
/// A held decision can be approved for this long.
const APPROVAL_HOURS: f64 = 24.0;
const MAX_RECORDS: u32 = 1_000_000;

fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

// ───────────────────────── the policy ─────────────────────────

/// What the tenant admin sets; the hard guardrails are always on.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// IPs / CIDRs SOAR never blocks (servers, gateways, partners).
    pub protected: Vec<String>,
    pub max_blocks_per_hour: u32,
    /// Below this alert level a block also needs threat intel to run on its own.
    pub min_level_auto_block: u32,
    pub max_auto_block_hours: u32,
    pub max_suppress_hours: u32,
    /// AI verdicts below this confidence need approval before alerts are hidden.
    pub min_ai_confidence: u32,
    pub max_isolations_per_hour: u32,
    /// Below this alert level an automatic isolation also needs threat intel.
    pub min_level_auto_isolate: u32,
    pub updated_by: String,
    pub updated_at: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self { protected: vec![], max_blocks_per_hour: 10, min_level_auto_block: 10, max_auto_block_hours: 24, max_suppress_hours: 72, min_ai_confidence: 70, max_isolations_per_hour: 2, min_level_auto_isolate: 12, updated_by: String::new(), updated_at: 0 }
    }
}

fn rule(id: &str, title: &str, when: Cond, effect: Effect, hard: bool, reference: &str) -> Rule {
    Rule { id: id.into(), title: title.into(), when, effect, hard, reference: reference.into() }
}

fn n(x: u32) -> Val {
    Val::Num(x as f64)
}

pub fn block_rules(s: &Settings) -> Vec<Rule> {
    vec![
        rule("G1", "Never block an internal, loopback or reserved address", cmp("target.public", Op::Eq, Val::Bool(false)), Effect::Deny, true, "Availability safeguard; NIST SP 800-53 SC-7"),
        rule("G2", "Never block a protected asset", cmp("target.protected", Op::Eq, Val::Bool(true)), Effect::Deny, true, "Tenant's protected-asset list; NIST SP 800-53 AC-4"),
        rule("G3", &format!("At most {} automatic blocks per hour", s.max_blocks_per_hour), cmp("rate.blocks_last_hour", Op::Ge, n(s.max_blocks_per_hour)), Effect::RequireApproval, true, "Blast-radius limit; human oversight (EU AI Act Art. 14)"),
        rule(
            "P1",
            &format!("Weak evidence: below level {} and no threat intel", s.min_level_auto_block),
            Cond::All(vec![cmp("alert.level", Op::Lt, n(s.min_level_auto_block)), cmp("intel.malicious", Op::Eq, Val::Bool(false))]),
            Effect::RequireApproval,
            false,
            "Proportionality",
        ),
        rule("P2", &format!("Blocks longer than {} h", s.max_auto_block_hours), cmp("action.hours", Op::Gt, n(s.max_auto_block_hours)), Effect::RequireApproval, false, "Proportionality"),
        rule(
            "P3",
            "The AI judged this activity harmless",
            Cond::All(vec![cmp("neural.verdict", Op::Eq, Val::Str("benign".into())), cmp("neural.confidence", Op::Ge, n(80))]),
            Effect::RequireApproval,
            false,
            "Conflicting evidence goes to a person",
        ),
    ]
}

pub fn isolate_rules(s: &Settings) -> Vec<Rule> {
    vec![
        rule("G6", "Never isolate a protected asset", cmp("target.protected", Op::Eq, Val::Bool(true)), Effect::Deny, true, "Tenant's protected-asset list; availability"),
        rule("G7", "Only internal hosts are isolated", cmp("target.public", Op::Eq, Val::Bool(true)), Effect::Deny, true, "Isolation quarantines the tenant's own host"),
        rule("G8", &format!("At most {} automatic isolations per hour", s.max_isolations_per_hour), cmp("rate.actions_last_hour", Op::Ge, n(s.max_isolations_per_hour)), Effect::RequireApproval, true, "Blast-radius limit; human oversight (EU AI Act Art. 14)"),
        rule(
            "P6",
            &format!("Weak evidence: below level {} and no threat intel", s.min_level_auto_isolate),
            Cond::All(vec![cmp("alert.level", Op::Lt, n(s.min_level_auto_isolate)), cmp("intel.malicious", Op::Eq, Val::Bool(false))]),
            Effect::RequireApproval,
            false,
            "Proportionality: cutting a host off is disruptive",
        ),
        rule(
            "P7",
            "The AI judged this activity harmless",
            Cond::All(vec![cmp("neural.verdict", Op::Eq, Val::Str("benign".into())), cmp("neural.confidence", Op::Ge, n(80))]),
            Effect::RequireApproval,
            false,
            "Conflicting evidence goes to a person",
        ),
    ]
}

/// A person's block or isolation: refused on a protected asset (an operator may act on an internal host).
pub fn manual_rules(s: &Settings) -> Vec<Rule> {
    vec![block_rules(s).swap_remove(1)]
}

pub fn suppress_rules(s: &Settings) -> Vec<Rule> {
    vec![
        rule("G4", "Critical alerts (level 12+) are never hidden", cmp("alert.max_level", Op::Ge, n(12)), Effect::Deny, true, "Detection integrity; NIST SP 800-53 SI-4"),
        rule("G5", "Activity the AI flags as suspicious is never hidden", cmp("neural.verdict", Op::Eq, Val::Str("suspicious".into())), Effect::Deny, true, "Detection integrity"),
        rule("P4", &format!("Hidden for more than {} h", s.max_suppress_hours), cmp("action.hours", Op::Gt, n(s.max_suppress_hours)), Effect::RequireApproval, false, "Proportionality"),
        rule(
            "P5",
            &format!("AI verdict below {}% confidence", s.min_ai_confidence),
            Cond::All(vec![cmp("neural.source", Op::Eq, Val::Str("ai".into())), cmp("neural.confidence", Op::Lt, n(s.min_ai_confidence))]),
            Effect::RequireApproval,
            false,
            "Human oversight (EU AI Act Art. 14)",
        ),
    ]
}

pub fn review_rules() -> Vec<Rule> {
    vec![
        rule("R1", "Four eyes: the requester cannot approve", cmp("review.same_person", Op::Eq, Val::Bool(true)), Effect::Deny, true, "Segregation of duties; ISO/IEC 27001 A.5.3"),
        rule("R2", &format!("Requests older than {APPROVAL_HOURS} h expire"), cmp("review.age_hours", Op::Gt, Val::Num(APPROVAL_HOURS)), Effect::Deny, true, "No stale actions"),
        rule("R3", "Rejected by the reviewer", cmp("review.approved", Op::Eq, Val::Bool(false)), Effect::Deny, true, ""),
    ]
}

/// The tenant's policy; `None` when it cannot be read (then the protected-asset check is
/// missing evidence, which holds a block instead of passing it).
async fn settings(state: &AppState, tenant: &str) -> Option<Settings> {
    match state.db.doc(tenant, DocTable::AnalystState, POLICY_DOC).await {
        Ok(None) => Some(Settings::default()),
        Ok(Some(d)) => serde_json::from_str(&d).ok(),
        Err(_) => None,
    }
}

/// `target.protected`, unless the policy could not be read.
fn protected_fact(f: &mut Facts, s: Option<&Settings>, ip: Option<IpAddr>) {
    if let Some(s) = s {
        let hit = ip.and_then(|a| s.protected.iter().find(|e| in_range(a, e)).cloned());
        f.insert("target.protected".into(), fact(Val::Bool(hit.is_some()), Origin::Symbolic, &hit.map_or("not on the protected list".into(), |e| format!("matches {e}"))));
    }
}

pub(crate) fn in_range(ip: IpAddr, entry: &str) -> bool {
    let (net, bits) = match entry.trim().split_once('/') {
        Some((a, b)) => (a, b.parse::<u32>().ok()),
        None => (entry.trim(), None),
    };
    let Ok(net) = net.parse::<IpAddr>() else { return false };
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let bits = bits.unwrap_or(32).min(32);
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let bits = bits.unwrap_or(128).min(128);
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

fn valid_range(entry: &str) -> bool {
    let (net, bits) = entry.trim().split_once('/').map_or((entry.trim(), None), |(a, b)| (a, Some(b)));
    net.parse::<IpAddr>().is_ok_and(|ip| bits.is_none_or(|b| b.parse::<u32>().is_ok_and(|b| b <= if ip.is_ipv4() { 32 } else { 128 })))
}

// ───────────────────────── the chain ─────────────────────────

/// One writer at a time: the chain cannot fork, and the rate count, the check for a
/// waiting request and a review's "not reviewed yet" are read and acted on atomically.
fn chain_lock() -> &'static tokio::sync::Mutex<()> {
    static L: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    L.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// The last record by position (not by insert time: a re-inserted old record is not the head).
async fn head(state: &AppState, tenant: &str) -> Result<Option<(u64, String)>, String> {
    let rows = state
        .db
        .tenant_client(tenant)
        .query("SELECT doc FROM siem_decisions FINAL ORDER BY JSONExtractUInt(doc, 'seq') DESC LIMIT 1")
        .fetch_all::<String>()
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows.first().and_then(|d| serde_json::from_str::<Record>(d).ok()).map(|r| (r.seq, r.hash)))
}

/// Appends a record; the caller holds `chain_lock`.
async fn append_locked(state: &AppState, tenant: &str, build: impl FnOnce(Option<(u64, &str)>) -> Record) -> Result<Record, String> {
    let prev = head(state, tenant).await?;
    let rec = build(prev.as_ref().map(|(s, h)| (*s, h.as_str())));
    state.db.put_doc(tenant, DocTable::Decisions, &rec.id, &serde_json::to_string(&rec).map_err(|e| e.to_string())?).await?;
    anchor::save(tenant, rec.seq, &rec.hash);
    Ok(rec)
}

async fn record_locked(state: &AppState, tenant: &str, action: &str, target: &str, by: &str, facts: Facts, policy: Vec<Rule>, params: Value) -> Result<Record, String> {
    let id = format!("dec-{}", uuid::Uuid::new_v4().simple());
    append_locked(state, tenant, |prev| siem_decision::decide(&id, prev, now(), action, target, by, facts, policy, params, "")).await
}

async fn chain(state: &AppState, tenant: &str) -> Result<Vec<Record>, String> {
    let mut recs: Vec<Record> = state.db.docs(tenant, DocTable::Decisions, MAX_RECORDS).await?.iter().filter_map(|d| serde_json::from_str(d).ok()).collect();
    recs.sort_by_key(|r| r.seq);
    Ok(recs)
}

/// The chain's head, also kept outside ClickHouse (siem-api's data folder), so
/// records removed from the end of the chain are found by `/verify` too.
pub mod anchor {
    use std::collections::BTreeMap;

    fn path() -> std::path::PathBuf {
        std::env::var_os("SIEM_DECISION_ANCHORS").map(std::path::PathBuf::from).unwrap_or_else(|| crate::data_file_path("decision_anchors.json"))
    }

    fn all() -> BTreeMap<String, (u64, String)> {
        std::fs::read_to_string(path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    pub fn get(tenant: &str) -> Option<(u64, String)> {
        all().get(tenant).cloned()
    }

    /// Called under the chain lock; written to a temporary file first so it is never half written.
    pub fn save(tenant: &str, seq: u64, hash: &str) {
        let mut m = all();
        m.insert(tenant.to_string(), (seq, hash.to_string()));
        let p = path();
        let tmp = p.with_extension("tmp");
        if std::fs::write(&tmp, serde_json::to_string_pretty(&m).unwrap_or_default()).and_then(|_| std::fs::rename(&tmp, &p)).is_err() {
            tracing::warn!("decision anchor for {tenant} not written to {}", p.display());
        }
    }
}

/// Automatic `action`s that ran (or were approved) in the last hour; `None` if unknown.
async fn allowed_last_hour(state: &AppState, tenant: &str, action: &str) -> Option<u64> {
    state
        .db
        .tenant_client(tenant)
        .query(
            "SELECT count() FROM siem_decisions FINAL WHERE JSONExtractUInt(doc, 'ts') >= ? AND JSONExtractString(doc, 'outcome') = 'allowed' \
             AND (JSONExtractString(doc, 'action') = ? OR (JSONExtractString(doc, 'action') = 'review' AND JSONExtractString(doc, 'params', 'action') = ?))",
        )
        .bind(now().saturating_sub(3600))
        .bind(action)
        .bind(action)
        .fetch_one::<u64>()
        .await
        .ok()
}

/// The same decision on the same target, still standing: a request still waiting (not
/// reviewed, not expired), or a refusal from the last hour.
async fn same_recent(state: &AppState, tenant: &str, action: &str, target: &str, outcome: Outcome) -> Option<String> {
    let (name, since) = match outcome {
        Outcome::NeedsApproval => ("needs_approval", (APPROVAL_HOURS * 3600.0) as u64),
        Outcome::Denied => ("denied", 3600),
        Outcome::Allowed => return None,
    };
    state
        .db
        .tenant_client(tenant)
        .query(
            "SELECT id FROM siem_decisions FINAL WHERE JSONExtractUInt(doc, 'ts') >= ? AND JSONExtractString(doc, 'action') = ? AND JSONExtractString(doc, 'target') = ? \
             AND JSONExtractString(doc, 'outcome') = ? \
             AND id NOT IN (SELECT JSONExtractString(doc, 'ref_id') FROM siem_decisions FINAL WHERE JSONExtractString(doc, 'action') = 'review') \
             ORDER BY JSONExtractUInt(doc, 'seq') DESC LIMIT 1",
        )
        .bind(now().saturating_sub(since))
        .bind(action)
        .bind(target)
        .bind(name)
        .fetch_all::<String>()
        .await
        .ok()?
        .into_iter()
        .next()
}

/// Evaluates and records (caller holds the lock), unless the same request is still
/// waiting or was refused within the hour: then Ok(Err((outcome, id of that decision))),
/// so a burst of alerts makes one record, not one per alert.
async fn decide_once(state: &AppState, tenant: &str, action: &str, target: &str, by: &str, facts: Facts, policy: Vec<Rule>, params: Value) -> Result<Result<Record, (Outcome, String)>, String> {
    let outcome = siem_decision::evaluate(&facts, &policy).0;
    if let Some(id) = same_recent(state, tenant, action, target, outcome).await {
        return Ok(Err((outcome, id)));
    }
    record_locked(state, tenant, action, target, by, facts, policy, params).await.map(Ok)
}

// ───────────────────────── the decisions ─────────────────────────

fn neural_facts(f: &mut Facts, rec: Option<&siem_triage::Recommendation>) {
    match rec {
        Some(r) => {
            let ai = r.source == siem_triage::Source::Ai;
            let origin = if ai { Origin::Neural } else { Origin::Symbolic };
            let v = serde_json::to_value(r.verdict).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
            f.insert("neural.verdict".into(), fact(Val::Str(v), origin, &format!("alert triage ({})", if ai { "AI model" } else { "heuristic rules" })));
            f.insert("neural.confidence".into(), fact(Val::Num(r.confidence as f64), origin, &r.reason.chars().take(300).collect::<String>()));
            f.insert("neural.source".into(), fact(Val::Str(if ai { "ai" } else { "rule" }.into()), Origin::Context, ""));
        }
        None => {
            f.insert("neural.verdict".into(), fact(Val::Str("none".into()), Origin::Neural, "no triage verdict for this alert group yet"));
            f.insert("neural.confidence".into(), fact(Val::Num(0.0), Origin::Neural, ""));
            f.insert("neural.source".into(), fact(Val::Str("none".into()), Origin::Context, ""));
        }
    }
}

/// SOAR `block_ip` (the alert's source IP) and `isolate_host` (the alert's host):
/// Ok = run it now; Err((run status, detail)) = held or denied.
pub async fn gate_network(state: &AppState, pb: &provigil_common::soar::SoarNativePlaybook, ctx: &provigil_common::soar::SoarContext) -> Result<(), (String, String)> {
    let action = pb.action_type.as_str();
    let tenant = &pb.tenant_id;
    let loaded = settings(state, tenant).await;
    let s = loaded.clone().unwrap_or_default();
    let alert = ctx.alert.clone().unwrap_or(Value::Null);
    let agent_id = alert["agent"]["id"].as_str().unwrap_or("").to_string();
    let rule_id = alert["rule"]["id"].as_str().and_then(|r| r.parse::<u32>().ok()).or_else(|| alert["rule"]["id"].as_u64().map(|r| r as u32)).unwrap_or(0);
    let level = alert["rule"]["level"].as_u64().unwrap_or(0);
    let config: Value = serde_json::from_str(&pb.action_config).unwrap_or(json!({}));
    let hours = config["duration_hours"].as_u64().or_else(|| config["duration_hours"].as_str().and_then(|h| h.parse().ok())).unwrap_or(24);
    let (ip, what, rules) = if action == "isolate_host" {
        (alert["agent"]["ip"].as_str().unwrap_or("").to_string(), "the host that raised the alert", isolate_rules(&s))
    } else {
        (ctx.src_ip.clone(), "the alert's source IP", block_rules(&s))
    };
    let parsed = ip.parse::<IpAddr>().ok();

    let triage = crate::triage::load(state, tenant).await;
    let rec = triage.recs.iter().find(|r| r.rule_id == rule_id && r.agent_id == agent_id && (r.src_ip.is_empty() || r.src_ip == ctx.src_ip));
    // the rate is counted and the decision recorded under one lock, so parallel alerts cannot all pass the limit
    let _chain = chain_lock().lock().await;

    let mut f = Facts::new();
    f.insert("target.ip".into(), fact(Val::Str(ip.clone()), Origin::Context, what));
    f.insert("target.public".into(), fact(Val::Bool(parsed.is_some_and(provigil_common::soar::is_public)), Origin::Symbolic, "address class"));
    protected_fact(&mut f, loaded.as_ref(), parsed);
    f.insert("alert.level".into(), fact(Val::Num(level as f64), Origin::Context, &format!("rule {rule_id}: {}", alert["rule"]["description"].as_str().unwrap_or(""))));
    f.insert("intel.malicious".into(), fact(Val::Bool(ctx.is_malicious), Origin::Context, "threat intel, VirusTotal or the threat swarm"));
    // unknown (database error) = missing, which holds the action (fail-safe)
    if let Some(n) = allowed_last_hour(state, tenant, action).await {
        let key = if action == "isolate_host" { "rate.actions_last_hour" } else { "rate.blocks_last_hour" };
        f.insert(key.into(), fact(Val::Num(n as f64), Origin::Symbolic, "allowed or approved since an hour ago"));
    }
    if action == "block_ip" {
        f.insert("action.hours".into(), fact(Val::Num(hours as f64), Origin::Context, "playbook setting"));
    }
    neural_facts(&mut f, rec);

    let params = json!({
        "agent_id": agent_id, "ip": ip, "hours": hours, "playbook": pb.name, "alert_id": alert["id"],
        "enforcement": config["enforcement"], "quarantine_vlan": config["quarantine_vlan"],
    });
    let r = match decide_once(state, tenant, action, &ip, &format!("soar:{}", pb.name), f, rules, params).await {
        Ok(Ok(r)) => r,
        Ok(Err((Outcome::Denied, id))) => return Err(("denied".into(), format!("Refused again, as in decision {id}"))),
        Ok(Err((_, id))) => return Err(("awaiting_approval".into(), format!("Already waiting for approval (decision {id})"))),
        Err(e) => return Err(("failed".into(), format!("decision not recorded, not run: {e}"))),
    };
    match r.outcome {
        Outcome::Allowed => Ok(()),
        Outcome::NeedsApproval => Err(("awaiting_approval".into(), format!("{} (decision {})", r.summary, r.id))),
        Outcome::Denied => Err(("denied".into(), format!("{} (decision {})", r.summary, r.id))),
    }
}

/// Hiding an alert group from AI triage: Ok(decision id) = go ahead; Err = the message for the analyst.
pub async fn gate_suppress(state: &AppState, tenant: &str, user: &str, rec: &siem_triage::Recommendation, req: &siem_suppression::Request) -> Result<String, String> {
    let s = settings(state, tenant).await.ok_or("The AI guardrails could not be read, so nothing was hidden. Try again.")?;
    let hours = req.hours.unwrap_or(24);
    let mut f = Facts::new();
    f.insert("alert.max_level".into(), fact(Val::Num((rec.max_score * 15.0 / 100.0).round() as f64), Origin::Context, &format!("{} alert(s), {}", rec.alert_count, rec.severities.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", "))));
    f.insert("action.hours".into(), fact(Val::Num(hours as f64), Origin::Context, "requested"));
    neural_facts(&mut f, Some(rec));
    let target = format!("rule {} on {}{}", rec.rule_id, rec.agent_name, if rec.src_ip.is_empty() { String::new() } else { format!(" from {}", rec.src_ip) });
    let params = json!({ "request": req, "rec_id": rec.id, "confidence": rec.confidence });
    let _chain = chain_lock().lock().await;
    let r = match decide_once(state, tenant, "suppress", &target, user, f, suppress_rules(&s), params).await {
        Ok(Ok(r)) => r,
        Ok(Err((Outcome::Denied, id))) => return Err(format!("Refused, as in decision {id}.")),
        Ok(Err((_, id))) => return Err(format!("Already waiting for your tenant admin's approval (decision {id}).")),
        Err(e) => return Err(format!("The decision could not be recorded, so nothing was hidden: {e}")),
    };
    match r.outcome {
        Outcome::Allowed => Ok(r.id),
        Outcome::NeedsApproval => Err(format!("Waiting for your tenant admin's approval (decision {}). {}", r.id, r.summary)),
        Outcome::Denied => Err(format!("{} (decision {})", r.summary, r.id)),
    }
}

/// A person blocking or isolating from the console (`manual_block` / `manual_isolate`):
/// recorded, and refused on a protected asset or when that cannot be checked. Ok(decision id).
pub async fn gate_manual(state: &AppState, ctx: &AuthCtx, tenant: &str, action: &str, ip: &str, params: Value) -> Result<String, String> {
    let loaded = settings(state, tenant).await;
    let s = loaded.clone().unwrap_or_default();
    let mut f = Facts::new();
    f.insert("target.ip".into(), fact(Val::Str(ip.to_string()), Origin::Human, &format!("entered by {}", ctx.username)));
    protected_fact(&mut f, loaded.as_ref(), ip.parse::<IpAddr>().ok());
    let _chain = chain_lock().lock().await;
    let r = record_locked(state, tenant, action, ip, &ctx.username, f, manual_rules(&s), params)
        .await
        .map_err(|e| format!("The decision could not be recorded, so nothing was done: {e}"))?;
    match r.outcome {
        Outcome::Allowed => Ok(r.id),
        // a person is acting: when the protected list cannot be checked, refuse rather than ask
        _ => Err(format!("{} (decision {})", r.summary, r.id)),
    }
}

// ───────────────────────── API ─────────────────────────

fn error(code: StatusCode, m: impl std::fmt::Display) -> axum::response::Response {
    (code, Json(json!({ "status": "error", "message": m.to_string() }))).into_response()
}

fn brief(r: &Record) -> Value {
    json!({ "id": r.id, "seq": r.seq, "ts": r.ts, "action": r.action, "target": r.target, "requested_by": r.requested_by, "outcome": r.outcome, "summary": r.summary, "ref_id": r.ref_id })
}

/// `GET /api/v1/siem/decisions`: the latest decisions and the ones waiting for approval.
pub async fn list(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    let t = ctx.scope();
    let docs = match state.db.docs(&t, DocTable::Decisions, 1000).await {
        Ok(d) => d,
        Err(e) => return error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let mut recs: Vec<Record> = docs.iter().filter_map(|d| serde_json::from_str(d).ok()).collect();
    recs.sort_by(|a, b| b.seq.cmp(&a.seq));
    let reviewed: std::collections::HashSet<&str> = recs.iter().filter(|r| r.action == "review").map(|r| r.ref_id.as_str()).collect();
    let cutoff = now().saturating_sub((APPROVAL_HOURS * 3600.0) as u64);
    let pending: Vec<Value> = recs.iter().filter(|r| r.outcome == Outcome::NeedsApproval && r.ts >= cutoff && !reviewed.contains(r.id.as_str())).map(brief).collect();
    let resolved: HashMap<&str, Outcome> = recs.iter().filter(|r| r.action == "review").map(|r| (r.ref_id.as_str(), r.outcome)).collect();
    let items: Vec<Value> = recs
        .iter()
        .take(300)
        .map(|r| {
            let mut b = brief(r);
            b["review"] = json!(resolved.get(r.id.as_str()).map(|o| if *o == Outcome::Allowed { "approved" } else { "rejected" }));
            b
        })
        .collect();
    Json(json!({ "status": "ok", "decisions": items, "pending": pending })).into_response()
}

/// `GET /api/v1/siem/decisions/:id`: the full record (facts, rules, every check).
pub async fn get_one(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> axum::response::Response {
    match state.db.doc(&ctx.scope(), DocTable::Decisions, &id).await {
        Ok(Some(d)) => match serde_json::from_str::<Record>(&d) {
            Ok(r) => Json(json!({ "status": "ok", "record": r, "verified": siem_decision::verify(&r).err() })).into_response(),
            Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
        },
        Ok(None) => error(StatusCode::NOT_FOUND, "No such decision"),
        Err(e) => error(StatusCode::SERVICE_UNAVAILABLE, e),
    }
}

/// `GET /api/v1/siem/decisions/verify`: re-derives every record and checks the chain.
pub async fn verify(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    let recs = match chain(&state, &ctx.scope()).await {
        Ok(r) => r,
        Err(e) => return error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let head = recs.last().map(|r| json!({ "seq": r.seq, "hash": r.hash }));
    match check(&ctx.scope(), &recs) {
        Ok(n) => Json(json!({ "status": "ok", "valid": true, "checked": n, "head": head })).into_response(),
        Err((seq, why)) => Json(json!({ "status": "ok", "valid": false, "checked": recs.len(), "bad_seq": seq, "reason": why, "head": head })).into_response(),
    }
}

/// Every record re-derived, the links, and the end of the chain against the anchor.
fn check(tenant: &str, recs: &[Record]) -> Result<usize, (u64, String)> {
    let n = siem_decision::verify_chain(recs)?;
    if let Some((seq, hash)) = anchor::get(tenant) {
        match recs.iter().find(|r| r.seq == seq) {
            Some(r) if r.hash != hash => return Err((seq, "it differs from the anchored head".into())),
            Some(_) => {}
            None => return Err((recs.last().map_or(1, |r| r.seq + 1), format!("records up to #{seq} were written but the chain ends at #{}", recs.last().map_or(0, |r| r.seq)))),
        }
    }
    Ok(n)
}

/// `GET /api/v1/siem/decisions/export`: the whole chain as one JSON file for auditors.
pub async fn export(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    let t = ctx.scope();
    let recs = match chain(&state, &t).await {
        Ok(r) => r,
        Err(e) => return error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    let body = json!({
        "format": "aether-decision-chain/1",
        "tenant": t,
        "exported_at": now(),
        "exported_by": ctx.username,
        "how_to_verify": "JSON here is compact (no spaces), keys in the order given, non-ASCII not escaped. For each record: sha256 of the JSON of `policy` = policy_hash; evaluating `policy` on `facts` gives `steps` and `outcome` (deny > needs approval > allow; a rule with a missing fact needs approval); sha256 of the record's JSON with `hash` empty = hash; each prev_hash = the hash of the record before it (seq - 1).",
        "valid": check(&t, &recs).is_ok(),
        "records": recs,
    });
    ([(header::CONTENT_TYPE, "application/json"), (header::CONTENT_DISPOSITION, "attachment; filename=\"decision-chain.json\"")], body.to_string()).into_response()
}

/// `GET /api/v1/siem/decisions/policy`
pub async fn get_policy(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    let Some(s) = settings(&state, &ctx.scope()).await else { return error(StatusCode::SERVICE_UNAVAILABLE, "The policy could not be read") };
    Json(json!({ "status": "ok", "settings": s, "rules": { "block_ip": block_rules(&s), "isolate_host": isolate_rules(&s), "manual_block": manual_rules(&s), "suppress": suppress_rules(&s), "review": review_rules() } })).into_response()
}

/// `PUT /api/v1/siem/decisions/policy` (tenant admin). Logged in the chain.
pub async fn put_policy(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(mut s): Json<Settings>) -> axum::response::Response {
    if !ctx.is_tenant_admin() {
        return error(StatusCode::FORBIDDEN, "Only the tenant admin sets the AI guardrails");
    }
    s.protected = s.protected.iter().map(|e| e.trim().to_string()).filter(|e| !e.is_empty()).collect();
    if let Some(bad) = s.protected.iter().find(|e| !valid_range(e)) {
        return error(StatusCode::BAD_REQUEST, format!("'{bad}' is not an IP address or CIDR range"));
    }
    if s.protected.len() > 500 {
        return error(StatusCode::BAD_REQUEST, "At most 500 protected entries");
    }
    s.max_blocks_per_hour = s.max_blocks_per_hour.clamp(1, 100);
    s.max_isolations_per_hour = s.max_isolations_per_hour.clamp(1, 50);
    s.min_level_auto_isolate = s.min_level_auto_isolate.clamp(1, 16);
    s.min_level_auto_block = s.min_level_auto_block.clamp(1, 16);
    s.max_auto_block_hours = s.max_auto_block_hours.clamp(1, 720);
    s.max_suppress_hours = s.max_suppress_hours.clamp(1, siem_suppression::MAX_HOURS);
    s.min_ai_confidence = s.min_ai_confidence.clamp(0, 100);
    s.updated_by = ctx.username.clone();
    s.updated_at = now();
    let t = ctx.scope();
    let mut f = Facts::new();
    f.insert("policy.block_ip".into(), fact(Val::Str(siem_decision::policy_hash(&block_rules(&s))), Origin::Human, "hash of the new block rules"));
    f.insert("policy.suppress".into(), fact(Val::Str(siem_decision::policy_hash(&suppress_rules(&s))), Origin::Human, "hash of the new suppression rules"));
    f.insert("policy.protected".into(), fact(Val::Str(s.protected.join(", ")), Origin::Human, ""));
    // recorded first: a policy that is not in the audit trail never takes effect
    let _chain = chain_lock().lock().await;
    if let Err(e) = record_locked(&state, &t, "policy_change", "AI guardrails", &ctx.username, f, vec![], json!(s)).await {
        return error(StatusCode::SERVICE_UNAVAILABLE, format!("Not saved: the change could not be recorded ({e})"));
    }
    if let Err(e) = state.db.put_doc(&t, DocTable::AnalystState, POLICY_DOC, &serde_json::to_string(&s).unwrap_or_default()).await {
        return error(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    Json(json!({ "status": "ok", "settings": s })).into_response()
}

/// `POST /api/v1/siem/decisions/:id/approve`
pub async fn approve(state: State<AppState>, ctx: Extension<AuthCtx>, id: Path<String>) -> axum::response::Response {
    review(state, ctx, id, true).await
}

/// `POST /api/v1/siem/decisions/:id/reject`
pub async fn reject(state: State<AppState>, ctx: Extension<AuthCtx>, id: Path<String>) -> axum::response::Response {
    review(state, ctx, id, false).await
}

async fn review(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, approve: bool) -> axum::response::Response {
    if !ctx.is_tenant_admin() {
        return error(StatusCode::FORBIDDEN, "Only the tenant admin approves or rejects held actions");
    }
    let t = ctx.scope();
    let held: Record = match state.db.doc(&t, DocTable::Decisions, &id).await.ok().flatten().and_then(|d| serde_json::from_str(&d).ok()) {
        Some(r) => r,
        None => return error(StatusCode::NOT_FOUND, "No such decision"),
    };
    if held.outcome != Outcome::NeedsApproval || held.action == "review" {
        return error(StatusCode::BAD_REQUEST, "This decision is not waiting for approval");
    }
    if siem_decision::verify(&held).is_err() || !in_chain(&state, &t, &held).await {
        return error(StatusCode::CONFLICT, "This decision record fails verification; it cannot be acted on");
    }
    let review_id = format!("review-{id}");
    // under the lock: two admins approving at once cannot both run the action
    let chain = chain_lock().lock().await;
    if state.db.doc(&t, DocTable::Decisions, &review_id).await.ok().flatten().is_some() {
        return error(StatusCode::CONFLICT, "Already reviewed");
    }
    // four eyes (rule R1 records it too): refused before anything is written, so another admin can still review
    if held.requested_by == ctx.username {
        return error(StatusCode::FORBIDDEN, "You asked for this action; another admin has to approve it");
    }
    let mut f = Facts::new();
    f.insert("review.approved".into(), fact(Val::Bool(approve), Origin::Human, &format!("by {}", ctx.username)));
    f.insert("review.same_person".into(), fact(Val::Bool(false), Origin::Symbolic, &format!("requested by {}", held.requested_by)));
    f.insert("review.age_hours".into(), fact(Val::Num(((now().saturating_sub(held.ts)) as f64 / 3600.0 * 100.0).round() / 100.0), Origin::Symbolic, ""));
    f.insert("review.of".into(), fact(Val::Str(held.hash.clone()), Origin::Context, "hash of the decision reviewed"));
    let target = held.target.clone();
    let r = match append_locked(&state, &t, |prev| siem_decision::decide(&review_id, prev, now(), "review", &target, &ctx.username, f, review_rules(), json!({ "action": held.action }), &held.id)).await {
        Ok(r) => r,
        Err(e) => return error(StatusCode::SERVICE_UNAVAILABLE, e),
    };
    drop(chain);
    if r.outcome != Outcome::Allowed {
        return Json(json!({ "status": "ok", "outcome": r.outcome, "summary": r.summary, "decision": r.id })).into_response();
    }
    let ran = execute(&state, &t, &held).await;
    Json(json!({ "status": "ok", "outcome": r.outcome, "summary": r.summary, "decision": r.id, "result": ran })).into_response()
}

/// The record is linked into the tenant's chain: the only record at its position, its
/// predecessor's hash is its prev_hash, and its successor (or the anchor) points at it.
/// A self-consistent record inserted into the database on its own fails this.
async fn in_chain(state: &AppState, tenant: &str, r: &Record) -> bool {
    let near: Vec<Record> = match state
        .db
        .tenant_client(tenant)
        .query("SELECT doc FROM siem_decisions FINAL WHERE JSONExtractUInt(doc, 'seq') BETWEEN ? AND ?")
        .bind(r.seq.saturating_sub(1))
        .bind(r.seq + 1)
        .fetch_all::<String>()
        .await
    {
        Ok(d) => d.iter().filter_map(|x| serde_json::from_str(x).ok()).collect(),
        Err(_) => return false,
    };
    let at = |seq: u64| near.iter().filter(|x| x.seq == seq).collect::<Vec<_>>();
    let me = at(r.seq);
    let prev_ok = if r.seq == 1 { r.prev_hash.is_empty() } else { at(r.seq - 1).first().is_some_and(|p| p.hash == r.prev_hash) };
    let next_ok = match at(r.seq + 1).first() {
        Some(n) => n.prev_hash == r.hash,
        None => anchor::get(tenant).is_none_or(|(seq, hash)| seq == r.seq && hash == r.hash),
    };
    me.len() == 1 && me[0].id == r.id && prev_ok && next_ok
}

/// Runs an approved action.
async fn execute(state: &AppState, tenant: &str, held: &Record) -> Value {
    let p = &held.params;
    let reason = format!("approved decision {}", held.id);
    let res = match held.action.as_str() {
        "block_ip" => crate::response::block(state, tenant, p["ip"].as_str().unwrap_or(""), p["hours"].as_u64().unwrap_or(24), p["enforcement"].as_str().unwrap_or("both"), p["agent_id"].as_str(), &format!("soar:{}", p["playbook"].as_str().unwrap_or("")), &format!("Playbook: {} ({reason})", p["playbook"].as_str().unwrap_or("")))
            .await
            .map(|(_, d)| d),
        "isolate_host" => crate::response::isolate(state, tenant, p["ip"].as_str().unwrap_or(""), p["enforcement"].as_str(), p["quarantine_vlan"].as_u64().map(|v| v as u16), "", &format!("soar:{}", p["playbook"].as_str().unwrap_or("")), &format!("Playbook: {} ({reason})", p["playbook"].as_str().unwrap_or("")), p["agent_id"].as_str())
            .await
            .map(|(_, d)| d),
        "suppress" => match serde_json::from_value::<siem_suppression::Request>(p["request"].clone()) {
            Ok(mut req) => {
                req.reason = format!("{} ({reason})", req.reason);
                crate::triage::apply_approved(state, tenant, &req, p["rec_id"].as_str().unwrap_or(""), p["confidence"].as_u64().unwrap_or(0) as u8, &held.requested_by).await
            }
            Err(e) => Err(e.to_string()),
        },
        a => Err(format!("unknown action {a}")),
    };
    match res {
        Ok(d) => json!({ "ok": true, "detail": d }),
        Err(e) => json!({ "ok": false, "detail": e }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(in_range(ip("203.0.113.7"), "203.0.113.0/24"));
        assert!(!in_range(ip("203.0.114.7"), "203.0.113.0/24"));
        assert!(in_range(ip("8.8.8.8"), "8.8.8.8"));
        assert!(in_range(ip("2001:db8::1"), "2001:db8::/32"));
        assert!(!in_range(ip("8.8.8.8"), "2001:db8::/32"));
        assert!(valid_range("10.0.0.0/8") && valid_range("::1") && !valid_range("10.0.0.0/33") && !valid_range("example.com"));
    }

    fn facts(pairs: &[(&str, Val)]) -> Facts {
        pairs.iter().map(|(k, v)| (k.to_string(), fact(v.clone(), Origin::Context, ""))).collect()
    }

    #[test]
    fn default_block_policy() {
        let s = Settings::default();
        let base = |public: bool, protected: bool, level: f64, intel: bool, verdict: &str, conf: f64| {
            facts(&[
                ("target.public", Val::Bool(public)),
                ("target.protected", Val::Bool(protected)),
                ("rate.blocks_last_hour", Val::Num(0.0)),
                ("alert.level", Val::Num(level)),
                ("intel.malicious", Val::Bool(intel)),
                ("action.hours", Val::Num(24.0)),
                ("neural.verdict", Val::Str(verdict.into())),
                ("neural.confidence", Val::Num(conf)),
            ])
        };
        let o = |f: Facts| siem_decision::evaluate(&f, &block_rules(&s)).0;
        assert_eq!(o(base(true, false, 12.0, false, "none", 0.0)), Outcome::Allowed);
        assert_eq!(o(base(false, false, 12.0, true, "none", 0.0)), Outcome::Denied, "internal address");
        assert_eq!(o(base(true, true, 15.0, true, "suspicious", 99.0)), Outcome::Denied, "protected beats everything");
        assert_eq!(o(base(true, false, 6.0, false, "none", 0.0)), Outcome::NeedsApproval, "weak evidence");
        assert_eq!(o(base(true, false, 6.0, true, "none", 0.0)), Outcome::Allowed, "threat intel is enough");
        assert_eq!(o(base(true, false, 12.0, false, "benign", 90.0)), Outcome::NeedsApproval, "AI disagrees");
    }
}
