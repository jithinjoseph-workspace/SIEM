//! Organizational security memory (siem-org-memory), per tenant: a lesson is
//! kept (7 years) each time a triage group is decided or a SOAR case is
//! closed, and similar past lessons are shown next to new activity ("seen
//! before"). Context only: a precedent never hides or closes anything.

use std::time::Duration;

use axum::extract::{Extension, Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use siem_org_memory::{Lesson, Probe};

use crate::tenancy::AuthCtx;
use crate::AppState;

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS siem_org_memory (id String, doc String, rule_ids Array(UInt32), techniques Array(String), entities Array(String), outcome LowCardinality(String), decided_at UInt64, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id TTL toDateTime(decided_at) + INTERVAL 7 YEAR";
const CANDIDATES: u64 = 3000;

fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

/// Stores (or replaces) a lesson.
pub async fn record(state: &AppState, tenant: &str, l: &Lesson) {
    if !state.db.is_connected() {
        return;
    }
    let techniques: Vec<String> = l.techniques.iter().map(|t| t.to_lowercase()).collect();
    let r = state
        .db
        .tenant_client(tenant)
        .query("INSERT INTO siem_org_memory (id, doc, rule_ids, techniques, entities, outcome, decided_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(&l.id)
        .bind(serde_json::to_string(l).unwrap_or_default())
        .bind(&l.rule_ids)
        .bind(techniques)
        .bind(l.entities())
        .bind(&l.outcome)
        .bind(l.decided_at)
        .bind(chrono::Utc::now().timestamp_micros().max(0) as u64)
        .execute()
        .await;
    if let Err(e) = r {
        tracing::warn!("org memory: lesson {} not stored: {e}", l.id);
    }
}

/// The latest full alert of a triage group (for its groups, technique and user).
async fn group_alert(state: &AppState, tenant: &str, rule_id: u32, agent_id: &str, src_ip: &str) -> Option<siem_core::Alert> {
    let rows = state
        .db
        .tenant_client(tenant)
        .query("SELECT ?fields FROM siem_alerts WHERE rule_id = ? AND agent_id = ? AND src_ip = ? ORDER BY timestamp DESC LIMIT 1")
        .bind(rule_id)
        .bind(agent_id)
        .bind(src_ip)
        .fetch_all::<crate::db::ClickHouseAlertRow>()
        .await
        .ok()?;
    rows.first().map(|r| r.to_alert())
}

fn mitre_ids(a: &siem_core::Alert) -> Vec<String> {
    a.rule.mitre.as_ref().map(|m| m.id.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default()
}

/// A decided triage group as a lesson.
pub async fn from_triage(state: &AppState, tenant: &str, r: &siem_triage::Recommendation, status: &str, by: &str) -> Lesson {
    let a = group_alert(state, tenant, r.rule_id, &r.agent_id, &r.src_ip).await;
    Lesson {
        id: format!("triage:{}", r.key),
        kind: "triage".into(),
        title: format!("Rule {}: {}", r.rule_id, r.rule_description),
        rule_ids: vec![r.rule_id],
        techniques: a.as_ref().map(mitre_ids).unwrap_or_default(),
        groups: a.as_ref().map(|a| a.rule.groups.clone()).unwrap_or_default(),
        hosts: vec![r.agent_name.clone(), r.agent_id.clone()].into_iter().filter(|s| !s.is_empty()).collect(),
        src_ips: vec![r.src_ip.clone()].into_iter().filter(|s| !s.is_empty()).collect(),
        users: a.as_ref().and_then(|a| a.decoded.user.clone()).into_iter().collect(),
        outcome: if status == "applied" { "benign" } else { "kept_for_review" }.into(),
        rationale: format!("{} ({} {}%) - {} alerts, max level {}", r.reason, if r.source == siem_triage::Source::Ai { "AI" } else { "rule" }, r.confidence, r.alert_count, r.max_level),
        actions: if status == "applied" { vec!["suppressed".into()] } else { Vec::new() },
        decided_by: by.into(),
        decided_at: now(),
        reference: format!("rule {}", r.rule_id),
    }
}

#[derive(clickhouse::Row, Deserialize)]
struct CaseRow {
    case_number: String,
    title: String,
    description: String,
    status: String,
    src_ip: String,
    dst_ip: String,
    community_id: String,
    tags: Vec<String>,
}

/// A closed SOAR case as a lesson (`None` while it is open or unknown).
pub async fn from_case(state: &AppState, tenant: &str, case_id: &str, by: &str) -> Option<Lesson> {
    let tc = state.db.tenant_client(tenant);
    let c = tc
        .query("SELECT case_number, title, description, status, src_ip, dst_ip, community_id, tags FROM soar_cases FINAL WHERE id = ? LIMIT 1")
        .bind(case_id)
        .fetch_all::<CaseRow>()
        .await
        .ok()?
        .into_iter()
        .next()?;
    let outcome = siem_org_memory::case_outcome(&c.status)?;
    let comments: Vec<String> = tc
        .query("SELECT comment FROM soar_case_comments WHERE case_id = ? ORDER BY created_at")
        .bind(case_id)
        .fetch_all::<String>()
        .await
        .unwrap_or_default();
    let actions: Vec<String> = if c.community_id.is_empty() {
        Vec::new()
    } else {
        tc.query("SELECT DISTINCT playbook_name FROM soar_playbook_runs WHERE hit_id = ? AND status = 'success' LIMIT 20").bind(&c.community_id).fetch_all::<String>().await.unwrap_or_default()
    };
    // the playbooks tag a SIEM case with the alert's rule groups and MITRE ids
    let (techniques, groups): (Vec<String>, Vec<String>) = c.tags.iter().cloned().partition(|t| t.len() >= 5 && t.starts_with('T') && t[1..].chars().next().is_some_and(|d| d.is_ascii_digit()));
    let rule_ids: Vec<u32> = [&c.title, &c.description].iter().flat_map(|s| s.split(|ch: char| !ch.is_ascii_alphanumeric())).collect::<Vec<_>>().windows(2).filter(|w| w[0].eq_ignore_ascii_case("rule")).filter_map(|w| w[1].parse().ok()).collect();
    let mut rationale = c.description.clone();
    for cm in comments {
        if rationale.len() > 3000 {
            break;
        }
        rationale.push_str("\n- ");
        rationale.push_str(&cm);
    }
    Some(Lesson {
        id: format!("case:{case_id}"),
        kind: "case".into(),
        title: c.title,
        rule_ids,
        techniques,
        groups,
        hosts: vec![c.dst_ip].into_iter().filter(|s| !s.is_empty()).collect(),
        src_ips: vec![c.src_ip].into_iter().filter(|s| !s.is_empty()).collect(),
        users: Vec::new(),
        outcome: outcome.into(),
        rationale,
        actions,
        decided_by: by.into(),
        decided_at: now(),
        reference: c.case_number,
    })
}

/// Lessons that could match the probe (shared rule, technique or entity; or the words).
async fn candidates(state: &AppState, tenant: &str, p: &Probe) -> Vec<Lesson> {
    let since = now().saturating_sub(siem_org_memory::RETENTION_DAYS as u64 * 86400);
    let techniques: Vec<String> = p.techniques.iter().map(|t| t.to_lowercase()).collect();
    let entities = p.entities();
    let tc = state.db.tenant_client(tenant);
    let rows = if p.rule_ids.is_empty() && techniques.is_empty() && entities.is_empty() {
        let words: Vec<String> = p.text.split(|c: char| !c.is_alphanumeric()).filter(|w| w.len() >= 4).take(20).map(String::from).collect();
        if words.is_empty() {
            return Vec::new();
        }
        tc.query("SELECT doc FROM siem_org_memory FINAL WHERE decided_at >= ? AND multiSearchAnyCaseInsensitive(doc, ?) ORDER BY decided_at DESC LIMIT ?").bind(since).bind(words).bind(CANDIDATES).fetch_all::<String>().await
    } else {
        tc.query("SELECT doc FROM siem_org_memory FINAL WHERE decided_at >= ? AND (hasAny(rule_ids, ?) OR hasAny(techniques, ?) OR hasAny(entities, ?)) ORDER BY decided_at DESC LIMIT ?")
            .bind(since)
            .bind(&p.rule_ids)
            .bind(techniques)
            .bind(entities)
            .bind(CANDIDATES)
            .fetch_all::<String>()
            .await
    };
    rows.unwrap_or_default().iter().filter_map(|d| serde_json::from_str(d).ok()).collect()
}

pub async fn precedents(state: &AppState, tenant: &str, p: &Probe, limit: usize) -> Vec<siem_org_memory::Precedent> {
    siem_org_memory::similar(p, &candidates(state, tenant, p).await, limit)
}

fn view(list: Vec<siem_org_memory::Precedent>) -> Json<Value> {
    let items: Vec<Value> = list
        .into_iter()
        .map(|x| json!({ "score": x.score, "reasons": x.reasons, "lesson": x.lesson, "outcome_label": siem_org_memory::outcome_label(&x.lesson.outcome) }))
        .collect();
    Json(json!({ "status": "ok", "precedents": items }))
}

/// `GET /api/v1/siem/triage/:id/precedents`: what was decided before about similar activity.
pub async fn triage_precedents(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Json<Value> {
    let t = ctx.scope();
    let st = crate::triage::load(&state, &t).await;
    let Some(r) = st.recs.iter().find(|r| r.id == id) else { return Json(json!({ "status": "error", "message": "Recommendation not found" })) };
    let a = group_alert(&state, &t, r.rule_id, &r.agent_id, &r.src_ip).await;
    let p = Probe {
        rule_ids: vec![r.rule_id],
        techniques: a.as_ref().map(mitre_ids).unwrap_or_default(),
        groups: a.as_ref().map(|a| a.rule.groups.clone()).unwrap_or_default(),
        hosts: vec![r.agent_name.clone()],
        src_ips: vec![r.src_ip.clone()].into_iter().filter(|s| !s.is_empty()).collect(),
        users: a.as_ref().and_then(|a| a.decoded.user.clone()).into_iter().collect(),
        text: format!("{} {}", r.rule_description, r.reason),
        exclude_id: format!("triage:{}", r.key),
    };
    view(precedents(&state, &t, &p, 5).await)
}

/// `POST /api/v1/siem/memory/similar`: precedents for any activity (case, alert).
pub async fn similar(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(p): Json<Probe>) -> Json<Value> {
    view(precedents(&state, &ctx.scope(), &p, 10).await)
}

#[derive(Deserialize, Default)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub outcome: String,
    pub limit: Option<u64>,
}

/// `GET /api/v1/siem/memory`: the tenant's lessons, newest first (text search, outcome filter).
pub async fn search(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Query(q): Query<SearchQuery>) -> Json<Value> {
    let limit = q.limit.unwrap_or(100).min(500);
    let rows = state
        .db
        .tenant_client(&ctx.scope())
        .query("SELECT doc FROM siem_org_memory FINAL WHERE (? = '' OR positionCaseInsensitive(doc, ?) > 0) AND (? = '' OR outcome = ?) ORDER BY decided_at DESC LIMIT ?")
        .bind(&q.q)
        .bind(&q.q)
        .bind(&q.outcome)
        .bind(&q.outcome)
        .bind(limit)
        .fetch_all::<String>()
        .await
        .unwrap_or_default();
    let lessons: Vec<Value> = rows
        .iter()
        .filter_map(|d| serde_json::from_str::<Lesson>(d).ok())
        .map(|l| {
            let label = siem_org_memory::outcome_label(&l.outcome);
            let mut v = json!(l);
            v["outcome_label"] = json!(label);
            v
        })
        .collect();
    let stats = state
        .db
        .tenant_client(&ctx.scope())
        .query("SELECT outcome, count(), min(decided_at) FROM siem_org_memory FINAL GROUP BY outcome")
        .fetch_all::<(String, u64, u64)>()
        .await
        .unwrap_or_default();
    let total: u64 = stats.iter().map(|s| s.1).sum();
    let oldest = stats.iter().map(|s| s.2).min().unwrap_or(0);
    Json(json!({
        "status": "ok",
        "lessons": lessons,
        "total": total,
        "oldest": oldest,
        "by_outcome": stats.iter().map(|s| json!({ "outcome": s.0, "label": siem_org_memory::outcome_label(&s.0), "count": s.1 })).collect::<Vec<_>>(),
        "retention_years": siem_org_memory::RETENTION_DAYS / 365,
    }))
}

/// Once per tenant: the cases already closed and triage groups already decided.
pub async fn backfill(state: &AppState, tenant: &str) -> usize {
    let tc = state.db.tenant_client(tenant);
    if tc.query("SELECT count() FROM siem_org_memory").fetch_one::<u64>().await.unwrap_or(1) > 0 {
        return 0;
    }
    let mut n = 0;
    let closed: Vec<(String, String)> = tc
        .query("SELECT id, assigned_to FROM soar_cases FINAL WHERE status IN ('False Positive', 'Resolved', 'Closed') LIMIT 5000")
        .fetch_all::<(String, String)>()
        .await
        .unwrap_or_default();
    for (id, who) in closed {
        if let Some(l) = from_case(state, tenant, &id, if who.is_empty() { "unknown" } else { &who }).await {
            record(state, tenant, &l).await;
            n += 1;
        }
    }
    for r in crate::triage::load(state, tenant).await.recs.iter().filter(|r| r.status != "pending") {
        let mut l = from_triage(state, tenant, r, &r.status, "unknown").await;
        l.decided_at = r.updated_at;
        record(state, tenant, &l).await;
        n += 1;
    }
    n
}

/// The backfill for every tenant, shortly after start.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(90)).await;
        if !state.db.is_connected() {
            return;
        }
        for t in crate::predictions::tenant_ids(&state) {
            let n = backfill(&state, &t).await;
            if n > 0 {
                tracing::info!("org memory: tenant '{t}': {n} past decision(s) imported");
            }
        }
    });
}
