//! Investigation: everything the SIEM knows about one IP, host, user, file hash
//! or domain, in the caller's tenant, on one timeline: alerts and log events,
//! threat intel and swarm matches, SOAR cases and playbook runs, AI decisions,
//! triage verdicts and suppressions, the host's inventory and vulnerabilities
//! (CISA KEV marked), and what the organisation decided before (security memory).
//!
//! `GET /api/v1/siem/investigate?q=<value>&days=<1..90>`

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use axum::extract::{Extension, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::db::DocTable;
use crate::tenancy::AuthCtx;
use crate::AppState;

const MAX_ALERTS: u64 = 500;

#[derive(Deserialize)]
pub struct InvestigateQuery {
    pub q: String,
    pub days: Option<u32>,
}

#[derive(Debug, PartialEq)]
pub enum Kind {
    Ip,
    Hash,
    /// agent id and name
    Host(String, String),
    Domain,
    User,
}

impl Kind {
    fn name(&self) -> &'static str {
        match self {
            Kind::Ip => "ip",
            Kind::Hash => "hash",
            Kind::Host(..) => "host",
            Kind::Domain => "domain",
            Kind::User => "user",
        }
    }
}

/// What was typed: an IP, a hash, one of the tenant's agents (id or name), a domain, else a user.
pub fn classify(q: &str, agents: &[(String, String)]) -> Kind {
    if q.parse::<IpAddr>().is_ok() {
        return Kind::Ip;
    }
    if matches!(q.len(), 32 | 40 | 64) && q.chars().all(|c| c.is_ascii_hexdigit()) {
        return Kind::Hash;
    }
    if let Some((id, name)) = agents.iter().find(|(id, name)| id == q || name.eq_ignore_ascii_case(q)) {
        return Kind::Host(id.clone(), name.clone());
    }
    if q.contains('.') && !q.contains(char::is_whitespace) && !q.contains('@') {
        return Kind::Domain;
    }
    Kind::User
}

#[derive(clickhouse::Row, Deserialize)]
struct AlertRow {
    id: String,
    /// the id SOAR records for its runs (Wazuh's own alert id)
    wazuh_id: String,
    timestamp: u64,
    agent_name: String,
    rule_id: u32,
    rule_level: u8,
    rule_description: String,
    mitre_id: String,
    mitre_tactic: String,
    src_ip: String,
    dst_ip: String,
    user: String,
    location: String,
}

#[derive(clickhouse::Row, Deserialize)]
struct EventRow {
    id: String,
    timestamp: u64,
    agent_id: String,
    location: String,
    message: String,
}

#[derive(clickhouse::Row, Deserialize)]
struct CaseRow {
    id: String,
    case_number: String,
    title: String,
    severity: String,
    status: String,
    created_at: u32,
}

#[derive(clickhouse::Row, Deserialize)]
struct RunRow {
    id: String,
    playbook_name: String,
    hit_id: String,
    status: String,
    detail: String,
    created_at: u32,
}

/// The WHERE clause and its one bound value for the alerts of `kind`.
fn alert_filter(kind: &Kind) -> &'static str {
    match kind {
        Kind::Ip => "(src_ip = ? OR dst_ip = ?)",
        Kind::Host(..) => "(agent_id = ? OR agent_name = ?)",
        Kind::User => "(user = ? OR user = ?)",
        Kind::Hash | Kind::Domain => "(positionCaseInsensitive(alert_json, ?) > 0 OR positionCaseInsensitive(full_log, ?) > 0)",
    }
}

fn fail(m: &str) -> Json<Value> {
    Json(json!({ "status": "error", "message": m }))
}

pub async fn investigate(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Query(p): Query<InvestigateQuery>) -> Json<Value> {
    let q: String = p.q.trim().chars().take(256).collect();
    if q.len() < 2 {
        return fail("Enter an IP address, host, user, file hash or domain");
    }
    let t = ctx.scope();
    let days = p.days.unwrap_or(7).clamp(1, 90);
    let since = (chrono::Utc::now().timestamp_millis().max(0) as u64).saturating_sub(days as u64 * 86_400_000);
    let tenant_agents: Vec<(String, String)> = {
        let owners = state.agent_tenants.read().unwrap().clone();
        state.agents.read().unwrap().values().filter(|a| crate::tenancy::tenant_of(&owners, &a.id) == t).map(|a| (a.id.clone(), a.name.clone())).collect()
    };
    let kind = classify(&q, &tenant_agents);
    let (a1, a2) = match &kind {
        Kind::Host(id, name) => (id.clone(), name.clone()),
        _ => (q.clone(), q.clone()),
    };
    let tc = state.db.tenant_client(&t);

    // ── alerts and events ──
    let alerts = tc
        .query(&format!(
            "SELECT id, JSONExtractString(alert_json, 'data', 'wazuh_alert_id') AS wazuh_id, timestamp, agent_name, rule_id, rule_level, rule_description, mitre_id, mitre_tactic, src_ip, dst_ip, user, location \
             FROM siem_alerts WHERE timestamp >= ? AND {} ORDER BY timestamp DESC LIMIT {MAX_ALERTS}",
            alert_filter(&kind)
        ))
        .bind(since)
        .bind(&a1)
        .bind(&a2)
        .fetch_all::<AlertRow>()
        .await;
    let alerts = match alerts {
        Ok(a) => a,
        Err(e) => return fail(&format!("The alerts could not be read: {e}")),
    };
    let events = match &kind {
        Kind::Host(id, _) => tc.query("SELECT id, timestamp, agent_id, location, message FROM siem_events WHERE timestamp >= ? AND agent_id = ? ORDER BY timestamp DESC LIMIT 100").bind(since).bind(id),
        _ => tc.query("SELECT id, timestamp, agent_id, location, message FROM siem_events WHERE timestamp >= ? AND positionCaseInsensitive(message, ?) > 0 ORDER BY timestamp DESC LIMIT 100").bind(since).bind(&q),
    }
    .fetch_all::<EventRow>()
    .await
    .unwrap_or_default();

    // ── threat intel: the value itself, and the remote IPs a host / user dealt with ──
    let mut intel: Vec<Value> = Vec::new();
    if matches!(kind, Kind::Ip | Kind::Hash | Kind::Domain) {
        let hits = crate::intel::lookup_for(&t, &q);
        if !hits.is_empty() {
            intel.push(json!({ "value": q, "geo": crate::geomap::describe(&q), "hits": hits }));
        }
    }
    let counterparts: BTreeSet<&str> = alerts
        .iter()
        .flat_map(|a| [a.src_ip.as_str(), a.dst_ip.as_str()])
        .filter(|ip| *ip != q && ip.parse::<IpAddr>().is_ok_and(provigil_common::soar::is_public))
        .take(200)
        .collect();
    for ip in counterparts {
        let hits = crate::intel::lookup_for(&t, ip);
        if !hits.is_empty() {
            intel.push(json!({ "value": ip, "geo": crate::geomap::describe(ip), "hits": hits }));
        }
    }

    // ── swarm, triage, suppressions ──
    let about = |v: &Value| -> bool {
        match &kind {
            Kind::Host(id, name) => v["agent_id"].as_str() == Some(id) || v["agent_name"].as_str() == Some(name),
            _ => v["value"].as_str().is_some_and(|x| x.eq_ignore_ascii_case(&q)),
        }
    };
    let swarm: Vec<Value> = state.db.docs(&t, DocTable::SwarmMatches, 2000).await.unwrap_or_default().iter().filter_map(|d| serde_json::from_str::<Value>(d).ok()).filter(about).collect();
    let triage: Vec<Value> = crate::triage::load(&state, &t)
        .await
        .recs
        .into_iter()
        .filter(|r| match &kind {
            Kind::Host(id, _) => &r.agent_id == id,
            Kind::Ip => r.src_ip == q,
            _ => false,
        })
        .map(|r| json!({ "id": r.id, "rule_id": r.rule_id, "rule": r.rule_description, "verdict": r.verdict, "source": r.source, "confidence": r.confidence, "status": r.status, "alerts": r.alert_count, "reason": r.reason }))
        .collect();
    let suppressions: Vec<Value> = crate::suppressions::all(&state, &t)
        .await
        .into_iter()
        .filter(|s| s.active)
        .filter(|s| match &kind {
            Kind::Host(id, _) => s.agent_id.as_deref() == Some(id),
            Kind::Ip => s.src_ip.as_deref() == Some(q.as_str()),
            _ => false,
        })
        .map(|s| json!({ "id": s.id, "rule_id": s.rule_id, "rule": s.rule_name, "reason": s.reason, "expires_at": s.expires_at, "by": s.created_by }))
        .collect();

    // ── SOAR cases and runs, AI decisions ──
    let cases = tc
        .query(
            "SELECT id, case_number, title, severity, status, toUInt32(toUnixTimestamp(created_at)) AS created_at FROM soar_cases FINAL \
             WHERE src_ip = ? OR dst_ip = ? OR positionCaseInsensitive(title, ?) > 0 OR positionCaseInsensitive(description, ?) > 0 ORDER BY created_at DESC LIMIT 50",
        )
        .bind(&a1)
        .bind(&a1)
        .bind(&a2)
        .bind(&a2)
        .fetch_all::<CaseRow>()
        .await
        .unwrap_or_default();
    let alert_ids: Vec<String> = alerts.iter().flat_map(|a| [a.id.clone(), a.wazuh_id.clone()]).filter(|i| !i.is_empty()).collect();
    let runs = tc
        .query("SELECT id, playbook_name, hit_id, status, detail, toUInt32(toUnixTimestamp(created_at)) AS created_at FROM soar_playbook_runs WHERE hit_id IN ? OR positionCaseInsensitive(detail, ?) > 0 ORDER BY created_at DESC LIMIT 100")
        .bind(&alert_ids)
        .bind(&a2)
        .fetch_all::<RunRow>()
        .await
        .unwrap_or_default();
    let decisions: Vec<Value> = tc
        .query("SELECT doc FROM siem_decisions FINAL WHERE JSONExtractString(doc, 'target') = ? OR positionCaseInsensitive(doc, ?) > 0 ORDER BY JSONExtractUInt(doc, 'seq') DESC LIMIT 100")
        .bind(&a1)
        .bind(&a2)
        .fetch_all::<String>()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|d| serde_json::from_str::<siem_decision::Record>(d).ok())
        .map(|r| json!({ "id": r.id, "seq": r.seq, "ts": r.ts, "action": r.action, "target": r.target, "outcome": r.outcome, "summary": r.summary, "by": r.requested_by }))
        .collect();

    // ── the host itself ──
    let host = match &kind {
        Kind::Host(id, name) => {
            let inv = crate::inventory_store::get(&state, id).await;
            let vulns: Vec<Value> = state
                .vulnerabilities
                .read()
                .unwrap()
                .iter()
                .filter(|v| &v.agent_id == id)
                .map(|v| json!({ "cve": v.cve, "severity": v.severity, "cvss": v.cvss_score, "package": v.package_name, "version": v.installed_version, "fixed": v.fixed_version, "status": v.status, "known_exploited": !crate::intel::lookup(&v.cve).is_empty() }))
                .collect();
            let agent = state.agents.read().unwrap().get(id).map(|a| json!({ "id": a.id, "name": a.name, "ip": a.ip, "os": a.os, "os_type": a.os_type, "status": format!("{:?}", a.status).to_lowercase(), "version": a.version, "last_keepalive": a.last_keepalive }));
            json!({ "agent": agent, "name": name, "inventory": inv.map(|i| json!({ "os": i["os"], "hardware": i["hardware"], "ports": i["ports"].as_array().map_or(0, |a| a.len()), "processes": i["processes"].as_array().map_or(0, |a| a.len()), "packages": i["packages"].as_array().map_or(0, |a| a.len()) })), "vulnerabilities": vulns })
        }
        _ => Value::Null,
    };

    // ── summary and what was decided before ──
    let mut techniques: BTreeMap<String, u32> = BTreeMap::new();
    let mut rules: BTreeMap<u32, (String, u32)> = BTreeMap::new();
    for a in &alerts {
        if !a.mitre_id.is_empty() {
            *techniques.entry(a.mitre_id.clone()).or_default() += 1;
        }
        rules.entry(a.rule_id).or_insert((a.rule_description.clone(), 0)).1 += 1;
    }
    let mut top_rules: Vec<(u32, (String, u32))> = rules.into_iter().collect();
    top_rules.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
    let probe = siem_org_memory::Probe {
        rule_ids: top_rules.iter().take(10).map(|r| r.0).collect(),
        techniques: techniques.keys().cloned().collect(),
        hosts: match &kind {
            Kind::Host(_, name) => vec![name.clone()],
            _ => Vec::new(),
        },
        src_ips: if kind == Kind::Ip { vec![q.clone()] } else { Vec::new() },
        users: if kind == Kind::User { vec![q.clone()] } else { Vec::new() },
        ..Default::default()
    };
    let memory: Vec<Value> = crate::org_memory::precedents(&state, &t, &probe, 5)
        .await
        .into_iter()
        .map(|x| json!({ "score": x.score, "reasons": x.reasons, "title": x.lesson.title, "outcome": siem_org_memory::outcome_label(&x.lesson.outcome), "decided_at": x.lesson.decided_at, "by": x.lesson.decided_by, "reason": x.lesson.rationale }))
        .collect();
    let max_level = alerts.iter().map(|a| a.rule_level).max().unwrap_or(0);
    let verdict = if !intel.is_empty() && intel.iter().any(|i| i["value"] == q) || !swarm.is_empty() {
        "malicious"
    } else if max_level >= 12 || !intel.is_empty() {
        "suspicious"
    } else if alerts.is_empty() && events.is_empty() {
        "no activity"
    } else {
        "activity"
    };

    // ── one timeline ──
    let mut timeline: Vec<Value> = Vec::new();
    timeline.extend(alerts.iter().map(|a| json!({ "ts": a.timestamp / 1000, "type": "alert", "level": a.rule_level, "title": format!("{} {}", a.rule_id, a.rule_description), "detail": format!("{} · {} → {}{}", a.agent_name, a.src_ip, a.dst_ip, if a.user.is_empty() { String::new() } else { format!(" · user {}", a.user) }), "mitre": a.mitre_id, "tactic": a.mitre_tactic, "id": a.id })));
    timeline.extend(cases.iter().map(|c| json!({ "ts": c.created_at, "type": "case", "title": format!("{} {}", c.case_number, c.title), "detail": format!("{} · {}", c.severity, c.status), "id": c.id })));
    timeline.extend(runs.iter().map(|r| json!({ "ts": r.created_at, "type": "playbook", "title": r.playbook_name, "detail": format!("{}: {}", r.status, r.detail.chars().take(200).collect::<String>()), "id": r.id })));
    timeline.extend(decisions.iter().map(|d| json!({ "ts": d["ts"], "type": "decision", "title": format!("{} {}", d["action"].as_str().unwrap_or(""), d["target"].as_str().unwrap_or("")), "detail": d["summary"], "outcome": d["outcome"], "id": d["id"] })));
    timeline.extend(swarm.iter().map(|m| json!({ "ts": m["seen_at"], "type": "swarm", "title": format!("Seen by {} other organisation(s)", m["feed"]["orgs"]), "detail": m["rule_description"], "id": m["id"] })));
    timeline.sort_by(|a, b| b["ts"].as_u64().unwrap_or(0).cmp(&a["ts"].as_u64().unwrap_or(0)));
    timeline.truncate(400);

    Json(json!({
        "status": "ok",
        "query": q,
        "kind": kind.name(),
        "geo": if kind == Kind::Ip { crate::geomap::describe(&q) } else { Value::Null },
        "days": days,
        "summary": {
            "verdict": verdict,
            "alerts": alerts.len(),
            "alerts_capped": alerts.len() as u64 == MAX_ALERTS,
            "events": events.len(),
            "first_seen": alerts.last().map(|a| a.timestamp / 1000),
            "last_seen": alerts.first().map(|a| a.timestamp / 1000),
            "max_level": max_level,
            "hosts": alerts.iter().map(|a| a.agent_name.as_str()).filter(|n| !n.is_empty()).collect::<BTreeSet<_>>(),
            "techniques": techniques,
            "top_rules": top_rules.iter().take(8).map(|(id, (d, n))| json!({ "rule_id": id, "description": d, "count": n })).collect::<Vec<_>>(),
            "locations": alerts.iter().map(|a| a.location.as_str()).filter(|l| !l.is_empty()).collect::<BTreeSet<_>>().into_iter().take(10).collect::<Vec<_>>(),
        },
        "timeline": timeline,
        "events": events.iter().map(|e| json!({ "id": e.id, "ts": e.timestamp / 1000, "agent_id": e.agent_id, "location": e.location, "message": e.message.chars().take(400).collect::<String>() })).collect::<Vec<_>>(),
        "intel": intel,
        "swarm": swarm,
        "cases": cases.iter().map(|c| json!({ "id": c.id, "case_number": c.case_number, "title": c.title, "severity": c.severity, "status": c.status, "created_at": c.created_at })).collect::<Vec<_>>(),
        "playbook_runs": runs.iter().map(|r| json!({ "id": r.id, "playbook": r.playbook_name, "alert_id": r.hit_id, "status": r.status, "detail": r.detail, "created_at": r.created_at })).collect::<Vec<_>>(),
        "decisions": decisions,
        "triage": triage,
        "suppressions": suppressions,
        "host": host,
        "memory": memory,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_inputs() {
        let agents = vec![("017".to_string(), "web-01".to_string())];
        assert_eq!(classify("45.1.2.3", &agents), Kind::Ip);
        assert_eq!(classify("2001:db8::1", &agents), Kind::Ip);
        assert_eq!(classify(&"a".repeat(64), &agents), Kind::Hash);
        assert_eq!(classify("WEB-01", &agents), Kind::Host("017".into(), "web-01".into()));
        assert_eq!(classify("017", &agents), Kind::Host("017".into(), "web-01".into()));
        assert_eq!(classify("evil.example.com", &agents), Kind::Domain);
        assert_eq!(classify("alice", &agents), Kind::User);
        assert_eq!(classify("alice@corp.com", &agents), Kind::User);
    }
}
