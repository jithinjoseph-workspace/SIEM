//! Case investigation: when a SOAR case opens (or an analyst asks), the SIEM
//! gathers the evidence about its attacker IP, host and user (investigate.rs),
//! works out what the logins show (failures, and a success after them), and
//! gives a verdict: by rules always, and by the tenant's AI when it has one
//! (recommend only; nothing is changed). Kept per tenant
//! (`siem_case_investigations`, id = case id) and noted on the case.
//!
//! `GET /api/soar/cases/:id/investigation`, `POST` to run it again.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::db::DocTable;
use crate::tenancy::AuthCtx;
use crate::AppState;

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS siem_case_investigations (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id";

const DAYS: u32 = 7;

fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

/// What the evidence says, for the verdict.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Facts {
    pub alerts: u64,
    pub max_level: u64,
    pub failed_logins: u64,
    pub successful_logins: u64,
    /// a successful login from the attacker after its first failure
    pub success_after_failures: bool,
    pub success_users: Vec<String>,
    pub intel_hits: u64,
    pub swarm_matches: u64,
    pub critical_vulns: u64,
    pub known_exploited_vulns: u64,
    pub previous_cases: u64,
    /// earlier decisions on the same things: "False positive", "Confirmed incident"...
    pub precedents: Vec<String>,
    /// triage verdicts on the same source: "benign", "suspicious"...
    pub triage: Vec<String>,
    pub public_source: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Verdict {
    /// compromised | malicious | attack_attempt | likely_benign | needs_review
    pub label: String,
    pub confidence: u8,
    pub summary: String,
    pub reasons: Vec<String>,
    #[serde(default)]
    pub next_steps: Vec<String>,
}

const LABELS: [&str; 5] = ["compromised", "malicious", "attack_attempt", "likely_benign", "needs_review"];

/// The verdict the evidence supports, without AI.
pub fn rule_verdict(f: &Facts) -> Verdict {
    let mut reasons = Vec::new();
    if f.failed_logins > 0 {
        reasons.push(format!("{} failed login(s) from the source", f.failed_logins));
    }
    if f.successful_logins > 0 {
        reasons.push(format!("{} successful login(s) from the source{}", f.successful_logins, if f.success_users.is_empty() { String::new() } else { format!(" ({})", f.success_users.join(", ")) }));
    }
    if f.intel_hits > 0 {
        reasons.push(format!("listed by {} threat intel source(s)", f.intel_hits));
    }
    if f.swarm_matches > 0 {
        reasons.push("other organisations reported the same attacker (threat swarm)".into());
    }
    if f.known_exploited_vulns > 0 {
        reasons.push(format!("the host has {} actively exploited CVE(s) (CISA KEV)", f.known_exploited_vulns));
    } else if f.critical_vulns > 0 {
        reasons.push(format!("the host has {} critical CVE(s)", f.critical_vulns));
    }
    reasons.push(format!("{} alert(s) in {DAYS} days, highest level {}", f.alerts, f.max_level));
    let benign_before = f.precedents.iter().any(|p| p == "False positive" || p == "Hidden as benign noise") || f.triage.iter().any(|t| t == "benign");
    let v = |label: &str, confidence: u8, summary: &str, next: &[&str], reasons: Vec<String>| Verdict {
        label: label.into(),
        confidence,
        summary: summary.into(),
        reasons,
        next_steps: next.iter().map(|s| s.to_string()).collect(),
    };
    if f.success_after_failures && f.failed_logins >= 3 {
        return v("compromised", 85, "A login succeeded after repeated failures from the same source: the account is probably compromised.",
            &["Disable or reset the account that logged in", "Isolate the host and check what ran after the login", "Block the source IP"], reasons);
    }
    if f.intel_hits > 0 || f.swarm_matches > 0 {
        let c = if f.successful_logins > 0 { 85 } else { 75 };
        return v("malicious", c, "The source is a known attacker.", &["Block the source IP", "Check every host it reached"], reasons);
    }
    if f.failed_logins >= 5 || f.max_level >= 10 {
        return v("attack_attempt", 70, "Attack activity with no sign that it succeeded.",
            &["Block the source IP if it keeps trying", "Make sure the targeted accounts have strong passwords / MFA"], reasons);
    }
    if benign_before && f.max_level < 10 {
        let mut r = reasons;
        r.push("the team decided the same activity was benign before".into());
        return v("likely_benign", 65, "The same activity was judged benign before.", &["Close the case if nothing else changed"], r);
    }
    if f.successful_logins > 0 && f.failed_logins == 0 && f.max_level < 7 && !f.public_source {
        return v("likely_benign", 60, "Ordinary successful logins from an internal source.", &["Confirm the user expected these logins"], reasons);
    }
    v("needs_review", 40, "The evidence is not conclusive.", &["Review the timeline in the investigation"], reasons)
}

/// The JSON object in an AI reply, if it is a usable verdict.
pub fn ai_verdict(reply: &str) -> Option<Verdict> {
    let (a, b) = (reply.find('{')?, reply.rfind('}')?);
    let v: Verdict = serde_json::from_str(reply.get(a..=b)?).ok()?;
    (LABELS.contains(&v.label.as_str()) && v.confidence <= 100 && !v.summary.trim().is_empty()).then_some(v)
}

const SYSTEM: &str = "You are a Tier-2 SOC analyst investigating one SOAR case of a Wazuh-based SIEM. \
Decide only from the evidence given; do not invent facts. Distinguish an attack that failed, an attack \
that succeeded (for example a successful login after many failures), a known malicious source, and normal \
activity (an ordinary user login). Answer with one JSON object and nothing else: \
{\"label\": \"compromised|malicious|attack_attempt|likely_benign|needs_review\", \"confidence\": 0-100, \
\"summary\": \"one or two sentences\", \"reasons\": [\"...\"], \"next_steps\": [\"...\"]}";

/// AI calls per tenant and hour (`SIEM_CASE_AI_PER_HOUR`, default 30).
fn ai_allowed(tenant: &str) -> bool {
    static USED: Mutex<Option<HashMap<String, (u64, u32)>>> = Mutex::new(None);
    let limit = std::env::var("SIEM_CASE_AI_PER_HOUR").ok().and_then(|v| v.parse().ok()).unwrap_or(30u32);
    let hour = now() / 3600;
    let mut g = USED.lock().unwrap();
    let e = g.get_or_insert_with(HashMap::new).entry(tenant.to_string()).or_insert((hour, 0));
    if e.0 != hour {
        *e = (hour, 0);
    }
    if e.1 >= limit {
        return false;
    }
    e.1 += 1;
    true
}

#[derive(clickhouse::Row, Deserialize)]
struct Case {
    case_number: String,
    title: String,
    severity: String,
    src_ip: String,
    community_id: String,
}

#[derive(clickhouse::Row, Deserialize)]
struct FirstAlert {
    agent_id: String,
    user: String,
}

#[derive(clickhouse::Row, Deserialize)]
struct Logins {
    fails: u64,
    oks: u64,
    first_fail: u64,
    last_ok: u64,
    ok_users: Vec<String>,
}

fn n(v: &Value) -> u64 {
    v.as_u64().unwrap_or(0)
}

/// Investigates the tenant's case and stores the result.
pub async fn investigate_case(state: &AppState, tenant: &str, case_id: &str) -> Result<Value, String> {
    let tc = state.db.tenant_client(tenant);
    let case = tc
        .query("SELECT case_number, title, severity, src_ip, community_id FROM soar_cases FINAL WHERE id = ? LIMIT 1")
        .bind(case_id)
        .fetch_optional::<Case>()
        .await
        .map_err(|e| e.to_string())?
        .ok_or("Case not found")?;
    let first = if case.community_id.is_empty() {
        None
    } else {
        tc.query("SELECT agent_id, user FROM siem_alerts WHERE id = ? OR JSONExtractString(alert_json, 'data', 'wazuh_alert_id') = ? ORDER BY timestamp LIMIT 1")
            .bind(&case.community_id)
            .bind(&case.community_id)
            .fetch_optional::<FirstAlert>()
            .await
            .ok()
            .flatten()
    };

    // ── the evidence about each subject ──
    let mut subjects: Vec<(&str, String)> = Vec::new();
    if !case.src_ip.is_empty() {
        subjects.push(("source", case.src_ip.clone()));
    }
    if let Some(a) = &first {
        if !a.agent_id.is_empty() && a.agent_id != "000" {
            subjects.push(("host", a.agent_id.clone()));
        }
        if !a.user.is_empty() {
            subjects.push(("user", a.user.clone()));
        }
    }
    if subjects.is_empty() {
        return Err("The case has no source IP, host or user to investigate".into());
    }
    let mut evidence: Vec<(String, String, Value)> = Vec::new();
    for (role, value) in &subjects {
        evidence.push((role.to_string(), value.clone(), crate::investigate::run(state, tenant, value, DAYS).await));
    }
    let src = evidence.iter().find(|e| e.0 == "source").map(|e| &e.2);
    let host = evidence.iter().find(|e| e.0 == "host").map(|e| &e.2);

    // ── the facts ──
    let mut f = Facts { public_source: case.src_ip.parse::<std::net::IpAddr>().is_ok_and(provigil_common::soar::is_public), ..Default::default() };
    for (_, _, e) in &evidence {
        f.alerts = f.alerts.max(n(&e["summary"]["alerts"]));
        f.max_level = f.max_level.max(n(&e["summary"]["max_level"]));
        for m in e["memory"].as_array().into_iter().flatten() {
            f.precedents.extend(m["outcome"].as_str().map(String::from));
        }
        for t in e["triage"].as_array().into_iter().flatten() {
            f.triage.extend(t["verdict"].as_str().map(String::from));
        }
        f.previous_cases = f.previous_cases.max(e["cases"].as_array().map_or(0, |c| c.iter().filter(|c| c["id"] != json!(case_id)).count() as u64));
    }
    if let Some(e) = src {
        f.intel_hits = e["intel"].as_array().map_or(0, |i| i.iter().filter(|x| x["value"] == json!(case.src_ip)).map(|x| x["hits"].as_array().map_or(0, |h| h.len() as u64)).sum());
        f.swarm_matches = e["swarm"].as_array().map_or(0, |s| s.len() as u64);
    }
    if let Some(e) = host {
        let vulns = e["host"]["vulnerabilities"].as_array().cloned().unwrap_or_default();
        f.critical_vulns = vulns.iter().filter(|v| v["severity"].as_str().is_some_and(|s| s.eq_ignore_ascii_case("critical"))).count() as u64;
        f.known_exploited_vulns = vulns.iter().filter(|v| v["known_exploited"] == json!(true)).count() as u64;
    }
    if !case.src_ip.is_empty() {
        let since = (chrono::Utc::now().timestamp_millis().max(0) as u64).saturating_sub(DAYS as u64 * 86_400_000);
        const FAIL: &str = "positionCaseInsensitive(JSONExtractRaw(alert_json, 'rule', 'groups'), 'authentication_fail') > 0";
        const OK: &str = "positionCaseInsensitive(JSONExtractRaw(alert_json, 'rule', 'groups'), 'authentication_success') > 0";
        let l = tc
            .query(&format!(
                "SELECT countIf({FAIL}) AS fails, countIf({OK}) AS oks, minIf(timestamp, {FAIL}) AS first_fail, maxIf(timestamp, {OK}) AS last_ok, \
                 groupUniqArrayIf(5)(user, {OK} AND user != '') AS ok_users FROM siem_alerts WHERE timestamp >= ? AND src_ip = ?"
            ))
            .bind(since)
            .bind(&case.src_ip)
            .fetch_one::<Logins>()
            .await
            .map_err(|e| e.to_string())?;
        f.failed_logins = l.fails;
        f.successful_logins = l.oks;
        f.success_after_failures = l.fails > 0 && l.oks > 0 && l.last_ok > l.first_fail;
        f.success_users = l.ok_users;
    }
    let rules = rule_verdict(&f);

    // ── the AI's view, when the tenant has one ──
    let timeline: Vec<Value> = evidence.iter().flat_map(|e| e.2["timeline"].as_array().cloned().unwrap_or_default()).take(40).collect();
    let mut ai_note = String::new();
    let ai = if !crate::ai_assist::tenant_ai_enabled(state, tenant) {
        ai_note = "AI is switched off for this tenant".into();
        None
    } else {
        let providers = crate::ai_assist::providers(state, "threat").await;
        if providers.is_empty() {
            ai_note = "No AI provider is configured (Settings > AI Configuration)".into();
            None
        } else if !ai_allowed(tenant) {
            ai_note = "The hourly AI budget for case investigations is used up".into();
            None
        } else {
            let prompt = json!({
                "case": { "number": case.case_number, "title": case.title, "severity": case.severity, "source_ip": case.src_ip },
                "subjects": subjects.iter().map(|(r, v)| json!({ "role": r, "value": v })).collect::<Vec<_>>(),
                "facts": f,
                "rule_based_verdict": rules,
                "geo": src.map(|e| e["geo"].clone()),
                "threat_intel": src.map(|e| e["intel"].clone()),
                "top_rules": evidence.iter().map(|e| e.2["summary"]["top_rules"].clone()).collect::<Vec<_>>(),
                "techniques": evidence.iter().map(|e| e.2["summary"]["techniques"].clone()).collect::<Vec<_>>(),
                "timeline": timeline.iter().map(|t| json!({ "type": t["type"], "title": t["title"], "detail": t["detail"] })).collect::<Vec<_>>(),
            });
            match siem_ai::generate(&providers, SYSTEM, &prompt.to_string()).await {
                Ok(r) => match ai_verdict(&r.text) {
                    Some(v) => Some((v, r.model)),
                    None => {
                        ai_note = "The AI answer was not a usable verdict".into();
                        None
                    }
                },
                Err(e) => {
                    ai_note = format!("The AI did not answer: {e}");
                    None
                }
            }
        }
    };

    let doc = json!({
        "case_id": case_id,
        "case_number": case.case_number,
        "investigated_at": now(),
        "subjects": subjects.iter().map(|(r, v)| json!({ "role": r, "value": v })).collect::<Vec<_>>(),
        "facts": f,
        "verdict": ai.as_ref().map(|(v, _)| v.clone()).unwrap_or_else(|| rules.clone()),
        "verdict_source": if ai.is_some() { "ai" } else { "rules" },
        "rule_verdict": rules,
        "ai": ai.as_ref().map(|(v, m)| json!({ "verdict": v, "model": m })),
        "ai_note": ai_note,
        "geo": src.map(|e| e["geo"].clone()),
        "intel": src.map(|e| e["intel"].clone()).unwrap_or(json!([])),
        "evidence": evidence.iter().map(|(r, v, e)| json!({ "role": r, "value": v, "kind": e["kind"], "summary": e["summary"], "cases": e["cases"], "memory": e["memory"], "host": e["host"] })).collect::<Vec<_>>(),
        "timeline": timeline,
    });
    state.db.put_doc(tenant, DocTable::CaseInvestigations, case_id, &doc.to_string()).await?;
    let v = &doc["verdict"];
    let note = format!(
        "[AI Investigator] {} ({}% , by {}): {} Reasons: {}",
        v["label"].as_str().unwrap_or("").replace('_', " "),
        v["confidence"],
        if ai.is_some() { "AI" } else { "rules" },
        v["summary"].as_str().unwrap_or(""),
        v["reasons"].as_array().map(|r| r.iter().filter_map(|x| x.as_str()).take(4).collect::<Vec<_>>().join("; ")).unwrap_or_default()
    );
    use provigil_common::soar::SoarStore;
    crate::soar::store(state).soar_add_comment(case_id, "AI Investigator", &note, tenant).await;
    Ok(doc)
}

/// A new case: investigated once its alert is stored (a few seconds).
pub fn spawn_for_new_case(state: AppState, tenant: String, case_id: String) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        if let Err(e) = investigate_case(&state, &tenant, &case_id).await {
            tracing::warn!("case investigation {case_id} ({tenant}): {e}");
        }
    });
}

fn bad(code: StatusCode, m: &str) -> Response {
    (code, Json(json!({ "status": "error", "message": m }))).into_response()
}

/// `GET /api/soar/cases/:id/investigation`
pub async fn get(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Response {
    match state.db.doc(&ctx.scope(), DocTable::CaseInvestigations, &id).await {
        Ok(Some(d)) => Json(json!({ "status": "ok", "investigation": serde_json::from_str::<Value>(&d).unwrap_or_default() })).into_response(),
        Ok(None) => Json(json!({ "status": "none" })).into_response(),
        Err(e) => bad(StatusCode::SERVICE_UNAVAILABLE, &e),
    }
}

/// `POST /api/soar/cases/:id/investigation`: investigate (again) now.
pub async fn run(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Response {
    match investigate_case(&state, &ctx.scope(), &id).await {
        Ok(d) => Json(json!({ "status": "ok", "investigation": d })).into_response(),
        Err(e) if e == "Case not found" => bad(StatusCode::NOT_FOUND, &e),
        Err(e) => bad(StatusCode::UNPROCESSABLE_ENTITY, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logins_decide_the_verdict() {
        let brute = Facts { alerts: 40, max_level: 10, failed_logins: 40, public_source: true, ..Default::default() };
        assert_eq!(rule_verdict(&brute).label, "attack_attempt", "many failures, no success");
        let broke_in = Facts { successful_logins: 1, success_after_failures: true, success_users: vec!["admin".into()], ..brute.clone() };
        let v = rule_verdict(&broke_in);
        assert_eq!(v.label, "compromised");
        assert!(v.reasons.iter().any(|r| r.contains("admin")));
        let normal = Facts { alerts: 2, max_level: 3, successful_logins: 2, ..Default::default() };
        assert_eq!(rule_verdict(&normal).label, "likely_benign", "an internal user logging in");
        let known = Facts { alerts: 1, max_level: 5, intel_hits: 2, public_source: true, ..Default::default() };
        assert_eq!(rule_verdict(&known).label, "malicious");
        let fp_before = Facts { alerts: 3, max_level: 7, precedents: vec!["False positive".into()], public_source: true, ..Default::default() };
        assert_eq!(rule_verdict(&fp_before).label, "likely_benign");
        assert_eq!(rule_verdict(&Facts { alerts: 1, max_level: 5, public_source: true, ..Default::default() }).label, "needs_review");
    }

    #[test]
    fn ai_reply_parsing() {
        let r = "Here you go:\n{\"label\": \"attack_attempt\", \"confidence\": 80, \"summary\": \"Brute force, no success.\", \"reasons\": [\"40 failures\"], \"next_steps\": [\"block\"]}";
        assert_eq!(ai_verdict(r).unwrap().label, "attack_attempt");
        assert!(ai_verdict("{\"label\": \"pwned\", \"confidence\": 80, \"summary\": \"x\", \"reasons\": []}").is_none(), "unknown label");
        assert!(ai_verdict("{\"label\": \"malicious\", \"confidence\": 180, \"summary\": \"x\", \"reasons\": []}").is_none(), "confidence over 100");
        assert!(ai_verdict("no json").is_none());
    }
}
