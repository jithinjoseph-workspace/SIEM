//! Regulatory compliance as Wazuh computes it, from the tenant's own data only:
//! * configuration: the frameworks of each CIS / SCA check as the agent reports them (wazuh-db
//!   `sca_check_compliance`, copied to `siem_sca_checks.compliance`). A requirement passes
//!   when its checks pass on every agent; the framework's score is the passed share of its
//!   checks' results;
//! * alerts: the compliance groups of each Wazuh rule (`rule.pci_dss`, `gdpr`, `hipaa`,
//!   `nist_800_53`, `tsc`), counted per requirement as the Wazuh dashboard's modules do.
//! Nothing is assumed: a framework the checks do not map (GDPR) has no score, only alerts.
//!
//! `GET /api/v1/compliance`

use std::collections::{BTreeMap, HashMap};

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::tenancy::AuthCtx;
use crate::AppState;

const WINDOW_HOURS: i64 = 24;

struct Framework {
    name: &'static str,
    full_name: &'static str,
    /// keys of the framework in the SCA checks (the agent's policy files)
    sca_keys: &'static [&'static str],
    /// the Wazuh rule field
    alert_key: &'static str,
}

/// The frameworks the Wazuh ruleset and the CIS policies tag.
const FRAMEWORKS: [Framework; 5] = [
    Framework { name: "PCI_DSS", full_name: "Payment Card Industry Data Security Standard", sca_keys: &["pci_dss_v4.0", "pci_dss_4.0"], alert_key: "pci_dss" },
    Framework { name: "HIPAA", full_name: "Health Insurance Portability and Accountability Act", sca_keys: &["hipaa"], alert_key: "hipaa" },
    Framework { name: "NIST_800_53", full_name: "NIST SP 800-53 Security and Privacy Controls", sca_keys: &["nist_sp_800-53"], alert_key: "nist_800_53" },
    Framework { name: "GDPR", full_name: "General Data Protection Regulation", sca_keys: &[], alert_key: "gdpr" },
    Framework { name: "SOC_2", full_name: "Trust Services Criteria (SOC 2)", sca_keys: &["soc_2"], alert_key: "tsc" },
];

#[derive(clickhouse::Row, serde::Deserialize)]
struct CheckRow {
    req: String,
    check_id: String,
    title: String,
    rationale: String,
    remediation: String,
    failed: u64,
    passed: u64,
    failed_agents: Vec<String>,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct AlertReqRow {
    req: String,
    n: u64,
    level: u8,
    rules: Vec<(u32, String)>,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct EvidenceRow {
    timestamp: u64,
    agent_id: String,
    agent_name: String,
    rule_id: u32,
    rule_level: u8,
    rule_description: String,
    rule: String,
}

#[derive(Default)]
struct Req {
    checks: Vec<Value>,
    passed: u64,
    failed: u64,
    alerts: u64,
    max_level: u8,
    rules: Vec<(u32, String)>,
}

fn sca_requirements_sql(fw: &Framework) -> String {
    let arrays: Vec<String> = fw.sca_keys.iter().map(|k| format!("JSONExtract(compliance, '{k}', 'Array(String)')")).collect();
    format!(
        "SELECT req, check_id, any(title), any(rationale), any(remediation), countIf(status = 'Failed'), countIf(status = 'Passed'), groupUniqArrayIf(5)(agent_id, status = 'Failed') \
         FROM siem_sca_checks FINAL ARRAY JOIN arrayDistinct(arrayConcat({})) AS req WHERE has(?, agent_id) GROUP BY req, check_id",
        arrays.join(", ")
    )
}

fn alert_requirements_sql(fw: &Framework) -> String {
    format!(
        "SELECT req, count(), max(rule_level), groupUniqArray(10)((rule_id, rule_description)) FROM siem_alerts \
         ARRAY JOIN JSONExtract(alert_json, 'data', 'wazuh_rule', '{}', 'Array(String)') AS req WHERE timestamp >= ? GROUP BY req",
        fw.alert_key
    )
}

fn err(code: StatusCode, m: String) -> Response {
    (code, Json(json!({ "status": "error", "message": m }))).into_response()
}

pub async fn get(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Response {
    let client = state.db.tenant_client(&ctx.scope());
    let agents: Vec<String> = crate::scoped_agents(&state, &ctx).into_iter().map(|a| a.id).collect();
    let since = (chrono::Utc::now() - chrono::Duration::hours(WINDOW_HOURS)).timestamp_millis().max(0) as u64;

    let mut frameworks = Vec::new();
    // check_id -> (title, remediation, rationale, failed agents, requirements it breaks)
    let mut fixes: HashMap<String, (String, String, String, u64, Vec<String>)> = HashMap::new();
    for fw in &FRAMEWORKS {
        let mut reqs: BTreeMap<String, Req> = BTreeMap::new();
        if !fw.sca_keys.is_empty() {
            let rows = client
                .query(&sca_requirements_sql(fw))
                .bind(&agents)
                .fetch_all::<CheckRow>()
                .await;
            let rows = match rows {
                Ok(r) => r,
                Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, format!("configuration checks cannot be read: {e}")),
            };
            for CheckRow { req, check_id, title, rationale, remediation, failed, passed, failed_agents } in rows {
                let r = reqs.entry(req.clone()).or_default();
                r.failed += failed;
                r.passed += passed;
                r.checks.push(json!({ "check_id": check_id, "title": title, "failed_agents": failed, "passed_agents": passed, "failing_on": failed_agents, "remediation": remediation, "rationale": rationale }));
                if failed > 0 {
                    let f = fixes.entry(check_id).or_insert_with(|| (title, remediation, rationale, failed, Vec::new()));
                    f.3 = f.3.max(failed);
                    f.4.push(format!("{} {req}", fw.name));
                }
            }
        }
        let alert_rows = client.query(&alert_requirements_sql(fw)).bind(since).fetch_all::<AlertReqRow>().await;
        let alert_rows = match alert_rows {
            Ok(r) => r,
            Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, format!("alerts cannot be read: {e}")),
        };
        for AlertReqRow { req, n, level, rules } in alert_rows {
            let r = reqs.entry(req).or_default();
            r.alerts = n;
            r.max_level = level;
            r.rules = rules;
        }

        let (mut checks_passed, mut checks_failed, mut alert_count, mut passed_count) = (0u64, 0u64, 0u64, 0usize);
        let mut requirements: Vec<Value> = reqs
            .into_iter()
            .map(|(id, mut r)| {
                checks_passed += r.passed;
                checks_failed += r.failed;
                alert_count += r.alerts;
                let has_checks = r.passed + r.failed > 0;
                // a failed check fails the requirement; alerts alone ask for a review
                let status = if r.failed > 0 { "failed" } else if r.alerts > 0 { "warning" } else { "passed" };
                if status == "passed" {
                    passed_count += 1;
                }
                r.checks.sort_by_key(|c| std::cmp::Reverse(c["failed_agents"].as_u64().unwrap_or(0)));
                let title = r
                    .checks
                    .iter()
                    .find(|c| c["failed_agents"].as_u64().unwrap_or(0) > 0)
                    .or(r.checks.first())
                    .and_then(|c| c["title"].as_str().map(String::from))
                    .or_else(|| r.rules.first().map(|(_, d)| d.clone()))
                    .unwrap_or_default();
                let mut parts = Vec::new();
                if has_checks {
                    parts.push(format!("{} of {} configuration check results fail", r.failed, r.passed + r.failed));
                }
                if r.alerts > 0 {
                    parts.push(format!("{} alert(s) in {WINDOW_HOURS} h", r.alerts));
                }
                let source = match (has_checks, r.alerts > 0) {
                    (true, true) => "both",
                    (true, false) => "configuration",
                    _ => "alerts",
                };
                let rule_ids: Vec<u32> = r.rules.iter().map(|(i, _)| *i).collect();
                let checks: Vec<Value> = r.checks.into_iter().take(25).collect();
                json!({
                    "id": id, "title": title, "description": parts.join(" · "), "status": status, "source": source,
                    "alerts_count": r.alerts, "max_level": r.max_level, "rule_ids": rule_ids,
                    "alerts": r.rules.iter().map(|(i, d)| json!({ "rule_id": i, "description": d })).collect::<Vec<_>>(),
                    "checks_passed": r.passed, "checks_failed": r.failed, "checks": checks,
                })
            })
            .collect();
        let rank = |s: &str| match s {
            "failed" => 0,
            "warning" => 1,
            _ => 2,
        };
        requirements.sort_by(|a, b| {
            rank(a["status"].as_str().unwrap_or("")).cmp(&rank(b["status"].as_str().unwrap_or(""))).then(b["checks_failed"].as_u64().cmp(&a["checks_failed"].as_u64())).then(b["alerts_count"].as_u64().cmp(&a["alerts_count"].as_u64()))
        });
        let scored = checks_passed + checks_failed > 0;
        frameworks.push(json!({
            "name": fw.name, "full_name": fw.full_name,
            "version": if fw.sca_keys.is_empty() { "Wazuh rules".to_string() } else { format!("{} (CIS checks) · Wazuh rules", fw.sca_keys[0]) },
            // the share of passed configuration check results; none when no check maps it
            "score_percent": if scored { json!(((checks_passed as f64 / (checks_passed + checks_failed) as f64) * 1000.0).round() / 10.0) } else { Value::Null },
            "total_requirements": requirements.len(), "passed_count": passed_count, "alert_count": alert_count,
            "checks_passed": checks_passed, "checks_failed": checks_failed, "requirements": requirements,
        }));
    }

    let mut remediations: Vec<Value> = fixes
        .into_iter()
        .map(|(check_id, (title, remediation, rationale, failed, mut reqs))| {
            reqs.sort();
            reqs.dedup();
            json!({ "check_id": check_id, "title": title, "remediation": remediation, "rationale": rationale, "failed_agents": failed, "requirements": reqs })
        })
        .collect();
    remediations.sort_by(|a, b| {
        let n = |v: &Value| v["requirements"].as_array().map_or(0, |x| x.len());
        n(b).cmp(&n(a)).then(b["failed_agents"].as_u64().cmp(&a["failed_agents"].as_u64()))
    });
    remediations.truncate(50);

    // the recent alerts that carry compliance tags: the evidence
    let has: Vec<String> = FRAMEWORKS.iter().map(|f| format!("JSONHas(alert_json, 'data', 'wazuh_rule', '{}')", f.alert_key)).collect();
    let evidence_sql = format!(
        "SELECT timestamp, agent_id, agent_name, rule_id, rule_level, rule_description, JSONExtractRaw(alert_json, 'data', 'wazuh_rule') FROM siem_alerts \
         WHERE timestamp >= ? AND ({}) ORDER BY timestamp DESC LIMIT 100",
        has.join(" OR ")
    );
    let evidence: Vec<Value> = client
        .query(&evidence_sql)
        .bind(since)
        .fetch_all::<EvidenceRow>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|EvidenceRow { timestamp: ts, agent_id, agent_name, rule_id, rule_level: level, rule_description: description, rule }| {
            let rule: Value = serde_json::from_str(&rule).unwrap_or_default();
            let reqs: Vec<String> = FRAMEWORKS.iter().flat_map(|f| rule[f.alert_key].as_array().cloned().unwrap_or_default().into_iter().filter_map(move |r| r.as_str().map(|r| format!("{} {r}", f.name)))).collect();
            json!({ "timestamp": ts, "agent_id": agent_id, "agent_name": agent_name, "rule_id": rule_id, "level": level, "description": description, "requirements": reqs })
        })
        .collect();
    let total_alerts: u64 = client.query("SELECT count() FROM siem_alerts WHERE timestamp >= ?").bind(since).fetch_one().await.unwrap_or(0);

    Json(json!({
        "frameworks": frameworks, "remediations": remediations, "evidence": evidence,
        "window_hours": WINDOW_HOURS, "agents": agents.len(), "total_alerts_evaluated": total_alerts,
        "last_updated": chrono::Utc::now().to_rfc3339(),
    }))
    .into_response()
}
