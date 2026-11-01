//! Regulatory compliance as Wazuh computes it, from the tenant's own data only:
//! * configuration: the frameworks of each CIS / SCA check as the agent reports them (wazuh-db
//!   `sca_check_compliance`, copied to `siem_sca_checks.compliance`). A requirement passes
//!   when its checks pass on every agent; the framework's score is the passed share of its
//!   checks' results;
//! * alerts: the compliance groups of each Wazuh rule (`rule.pci_dss`, `gdpr`, `hipaa`,
//!   `nist_800_53`, `tsc`), counted per requirement as the Wazuh dashboard's modules do.
//! Nothing is assumed: a framework the checks do not map has no score, only alerts.
//!
//! Each tenant keeps a profile (`siem_compliance_profile`): the frameworks it reports on,
//! the agent groups each one covers (its audit scope) and the checks it does not need,
//! which are left out of every score.
//!
//! `GET /api/v1/compliance` (`?refresh=1`: the agents' latest SCA results copied first),
//! `GET|PUT /api/v1/compliance/profile` (saving: the tenant admin)

use std::collections::{BTreeMap, HashMap, HashSet};

use axum::extract::{Extension, Json as JsonBody, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::tenancy::{self, AuthCtx};
use crate::AppState;

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS siem_compliance_profile (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id";
const PROFILE_ID: &str = "profile";
const MAX_EXCLUDED: usize = 20_000;
const MAX_SCOPE_GROUPS: usize = 50;

const WINDOW_HOURS: i64 = 24;
/// Agents brought up to date by a refresh (two cheap wazuh-db queries each when unchanged);
/// beyond them the 10-minute background copy applies.
const REFRESH_AGENTS: usize = 200;

#[derive(serde::Deserialize)]
pub struct CompQuery {
    refresh: Option<String>,
}

struct Framework {
    name: &'static str,
    full_name: &'static str,
    /// keys of the framework in the SCA checks (the agent's policy files)
    sca_keys: &'static [&'static str],
    /// the Wazuh rule field
    alert_key: &'static str,
}

/// The frameworks the Wazuh ruleset and the CIS policies tag (older policies use
/// `nist_800_53`, `tsc` and `gdpr_IV`).
const FRAMEWORKS: [Framework; 5] = [
    Framework { name: "PCI_DSS", full_name: "Payment Card Industry Data Security Standard", sca_keys: &["pci_dss_v4.0", "pci_dss_4.0"], alert_key: "pci_dss" },
    Framework { name: "HIPAA", full_name: "Health Insurance Portability and Accountability Act", sca_keys: &["hipaa"], alert_key: "hipaa" },
    Framework { name: "NIST_800_53", full_name: "NIST SP 800-53 Security and Privacy Controls", sca_keys: &["nist_sp_800-53", "nist_800_53"], alert_key: "nist_800_53" },
    Framework { name: "GDPR", full_name: "General Data Protection Regulation", sca_keys: &["gdpr_IV"], alert_key: "gdpr" },
    Framework { name: "SOC_2", full_name: "Trust Services Criteria (SOC 2)", sca_keys: &["soc_2", "tsc"], alert_key: "tsc" },
];

/// The tenant's compliance profile.
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Profile {
    /// the frameworks reported on (empty: all of them)
    #[serde(default)]
    pub frameworks: Vec<String>,
    /// framework -> the agent groups in its audit scope (none: every agent)
    #[serde(default)]
    pub scope: BTreeMap<String, Vec<String>>,
    /// check ids the tenant does not need, left out of every score
    #[serde(default)]
    pub excluded_checks: Vec<String>,
    #[serde(default)]
    pub updated_by: String,
    #[serde(default)]
    pub updated_at: String,
}

impl Profile {
    fn reports_on(&self, fw: &str) -> bool {
        self.frameworks.is_empty() || self.frameworks.iter().any(|f| f == fw)
    }

    fn scope_of(&self, fw: &str) -> &[String] {
        self.scope.get(fw).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Only known frameworks, group names and numeric check ids, without repeats.
    fn validate(mut self) -> Result<Profile, String> {
        let known = |f: &str| FRAMEWORKS.iter().any(|x| x.name == f);
        if let Some(f) = self.frameworks.iter().find(|f| !known(f)) {
            return Err(format!("unknown framework '{f}'"));
        }
        self.frameworks.sort();
        self.frameworks.dedup();
        for (fw, groups) in self.scope.iter_mut() {
            if !known(fw) {
                return Err(format!("unknown framework '{fw}'"));
            }
            if groups.len() > MAX_SCOPE_GROUPS {
                return Err(format!("at most {MAX_SCOPE_GROUPS} groups per framework"));
            }
            if let Some(g) = groups.iter().find(|g| g.is_empty() || g.len() > 255 || !g.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))) {
                return Err(format!("invalid group name '{g}'"));
            }
            groups.sort();
            groups.dedup();
        }
        self.scope.retain(|_, g| !g.is_empty());
        if self.excluded_checks.len() > MAX_EXCLUDED {
            return Err(format!("at most {MAX_EXCLUDED} checks can be marked not needed"));
        }
        if let Some(c) = self.excluded_checks.iter().find(|c| c.is_empty() || c.len() > 20 || !c.chars().all(|x| x.is_ascii_digit())) {
            return Err(format!("invalid check id '{c}'"));
        }
        self.excluded_checks.sort();
        self.excluded_checks.dedup();
        Ok(self)
    }
}

/// The tenant's saved profile (the default one when none was saved).
pub async fn load_profile(client: &clickhouse::Client) -> Result<Profile, String> {
    let doc = client
        .query("SELECT doc FROM siem_compliance_profile FINAL WHERE id = ?")
        .bind(PROFILE_ID)
        .fetch_optional::<String>()
        .await
        .map_err(|e| e.to_string())?;
    Ok(doc.and_then(|d| serde_json::from_str(&d).ok()).unwrap_or_default())
}

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

/// Binds: agents, excluded check ids. Older NIST tags ("SA.11") are read as "SA-11".
fn sca_requirements_sql(fw: &Framework) -> String {
    let arrays: Vec<String> = fw
        .sca_keys
        .iter()
        .map(|k| format!("arrayMap(x -> if(match(x, '^[A-Z]{{2}}\\.[0-9]'), replaceOne(x, '.', '-'), x), JSONExtract(compliance, '{k}', 'Array(String)'))"))
        .collect();
    format!(
        "SELECT req, check_id, any(title), any(rationale), any(remediation), countIf(status = 'Failed'), countIf(status = 'Passed'), groupUniqArrayIf(5)(agent_id, status = 'Failed') \
         FROM siem_sca_checks FINAL ARRAY JOIN arrayDistinct(arrayConcat({})) AS req WHERE has(?, agent_id) AND NOT has(?, check_id) GROUP BY req, check_id",
        arrays.join(", ")
    )
}

/// Binds: since, then the agents when `scoped`.
fn alert_requirements_sql(fw: &Framework, scoped: bool) -> String {
    format!(
        "SELECT req, count(), max(rule_level), groupUniqArray(10)((rule_id, rule_description)) FROM siem_alerts \
         ARRAY JOIN JSONExtract(alert_json, 'data', 'wazuh_rule', '{}', 'Array(String)') AS req WHERE timestamp >= ?{} GROUP BY req",
        fw.alert_key,
        if scoped { " AND has(?, agent_id)" } else { "" }
    )
}

/// The agents in a framework's audit scope: those in one of its groups, or all of them.
fn scoped(agents: &[String], groups_of: &HashMap<String, Vec<String>>, scope: &[String]) -> Vec<String> {
    if scope.is_empty() {
        return agents.to_vec();
    }
    agents.iter().filter(|a| groups_of.get(*a).is_some_and(|g| g.iter().any(|g| scope.contains(g)))).cloned().collect()
}

fn err(code: StatusCode, m: String) -> Response {
    (code, Json(json!({ "status": "error", "message": m }))).into_response()
}

pub async fn get(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Query(q): Query<CompQuery>) -> Response {
    let client = state.db.tenant_client(&ctx.scope());
    let agents: Vec<String> = crate::scoped_agents(&state, &ctx).into_iter().map(|a| a.id).collect();
    if q.refresh.as_deref().is_some_and(|r| r == "1" || r == "true") && crate::wazuh_manager::enabled() {
        for a in agents.iter().take(REFRESH_AGENTS) {
            crate::posture_store::sync_agent(&state, a).await;
        }
    }
    let since = (chrono::Utc::now() - chrono::Duration::hours(WINDOW_HOURS)).timestamp_millis().max(0) as u64;
    let profile = match load_profile(&client).await {
        Ok(p) => p,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, format!("compliance profile cannot be read: {e}")),
    };
    let groups_of: HashMap<String, Vec<String>> = {
        let tenant = ctx.scope();
        let enrolled = state.enrolled.read().unwrap();
        agents.iter().filter_map(|a| enrolled.get(a).map(|e| (a.clone(), crate::groups::tenant_agent_groups(&tenant, &e.groups)))).collect()
    };

    let mut frameworks = Vec::new();
    // check_id -> (title, remediation, rationale, failed agents, requirements it breaks)
    let mut fixes: HashMap<String, (String, String, String, u64, Vec<String>)> = HashMap::new();
    for fw in FRAMEWORKS.iter().filter(|f| profile.reports_on(f.name)) {
        let scope = profile.scope_of(fw.name);
        let fw_agents = scoped(&agents, &groups_of, scope);
        let mut reqs: BTreeMap<String, Req> = BTreeMap::new();
        if !fw.sca_keys.is_empty() {
            let rows = client
                .query(&sca_requirements_sql(fw))
                .bind(&fw_agents)
                .bind(&profile.excluded_checks)
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
        let mut q = client.query(&alert_requirements_sql(fw, !scope.is_empty())).bind(since);
        if !scope.is_empty() {
            q = q.bind(&fw_agents);
        }
        let alert_rows = q.fetch_all::<AlertReqRow>().await;
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
            "scope_groups": scope, "agents_in_scope": fw_agents.len(),
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
    let reported: Vec<&Framework> = FRAMEWORKS.iter().filter(|f| profile.reports_on(f.name)).collect();
    let has: Vec<String> = reported.iter().map(|f| format!("JSONHas(alert_json, 'data', 'wazuh_rule', '{}')", f.alert_key)).collect();
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
            let reqs: Vec<String> = reported.iter().flat_map(|f| rule[f.alert_key].as_array().cloned().unwrap_or_default().into_iter().filter_map(move |r| r.as_str().map(|r| format!("{} {r}", f.name)))).collect();
            json!({ "timestamp": ts, "agent_id": agent_id, "agent_name": agent_name, "rule_id": rule_id, "level": level, "description": description, "requirements": reqs })
        })
        .collect();
    let total_alerts: u64 = client.query("SELECT count() FROM siem_alerts WHERE timestamp >= ?").bind(since).fetch_one().await.unwrap_or(0);

    Json(json!({
        "frameworks": frameworks, "remediations": remediations, "evidence": evidence,
        "window_hours": WINDOW_HOURS, "agents": agents.len(), "total_alerts_evaluated": total_alerts,
        "excluded_checks": profile.excluded_checks.len(), "profile_updated_by": profile.updated_by, "profile_updated_at": profile.updated_at,
        "last_updated": chrono::Utc::now().to_rfc3339(),
    }))
    .into_response()
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct CatalogRow {
    policy_id: String,
    policy_name: String,
    check_id: String,
    title: String,
    compliance: String,
    failed: u64,
    passed: u64,
}

/// The frameworks a check's tags map (`compliance` JSON of `siem_sca_checks`).
fn check_frameworks(compliance: &str) -> Vec<&'static str> {
    let tags: Value = serde_json::from_str(compliance).unwrap_or_default();
    FRAMEWORKS.iter().filter(|f| f.sca_keys.iter().any(|k| tags.get(*k).is_some())).map(|f| f.name).collect()
}

/// `GET /api/v1/compliance/profile`: the profile, the tenant's groups and every
/// check its agents run (to mark the ones not needed).
pub async fn get_profile(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Response {
    let tenant = ctx.scope();
    let client = state.db.tenant_client(&tenant);
    let profile = match load_profile(&client).await {
        Ok(p) => p,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, format!("compliance profile cannot be read: {e}")),
    };
    let agents: Vec<String> = crate::scoped_agents(&state, &ctx).into_iter().map(|a| a.id).collect();
    let rows = client
        .query(
            "SELECT policy_id, any(policy_name), check_id, any(title), any(compliance), countIf(status = 'Failed'), countIf(status = 'Passed') \
             FROM siem_sca_checks FINAL WHERE has(?, agent_id) GROUP BY policy_id, check_id ORDER BY policy_id, toUInt64OrZero(check_id)",
        )
        .bind(&agents)
        .fetch_all::<CatalogRow>()
        .await;
    let rows = match rows {
        Ok(r) => r,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, format!("configuration checks cannot be read: {e}")),
    };
    let excluded: HashSet<&String> = profile.excluded_checks.iter().collect();
    let checks: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "policy_id": r.policy_id, "policy": r.policy_name, "check_id": r.check_id, "title": r.title,
                "frameworks": check_frameworks(&r.compliance), "failed_agents": r.failed, "passed_agents": r.passed,
                "required": !excluded.contains(&r.check_id),
            })
        })
        .collect();
    let groups: Vec<Value> = {
        let enrolled = state.enrolled.read().unwrap();
        crate::groups::tenant_groups(&tenant)
            .into_iter()
            .map(|g| {
                let n = agents.iter().filter(|a| enrolled.get(*a).is_some_and(|e| crate::groups::tenant_agent_groups(&tenant, &e.groups).contains(&g))).count();
                json!({ "name": g, "agents": n })
            })
            .collect()
    };
    Json(json!({
        "profile": profile,
        "frameworks": FRAMEWORKS.iter().map(|f| json!({ "name": f.name, "full_name": f.full_name })).collect::<Vec<_>>(),
        "groups": groups,
        "checks": checks,
        "editable": ctx.can_manage(&tenant),
    }))
    .into_response()
}

/// `PUT /api/v1/compliance/profile`: what the tenant's audits count (the tenant admin).
pub async fn put_profile(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, JsonBody(body): JsonBody<Profile>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    let mut profile = match body.validate() {
        Ok(p) => p,
        Err(m) => return err(StatusCode::BAD_REQUEST, m),
    };
    profile.updated_by = ctx.username.clone();
    profile.updated_at = chrono::Utc::now().to_rfc3339();
    let doc = serde_json::to_string(&profile).unwrap_or_default();
    let version = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let client = state.db.tenant_client(&tenant);
    if let Err(e) = client.query("INSERT INTO siem_compliance_profile (id, doc, version) VALUES (?, ?, ?)").bind(PROFILE_ID).bind(&doc).bind(version).execute().await {
        return err(StatusCode::SERVICE_UNAVAILABLE, format!("compliance profile not saved: {e}"));
    }
    tracing::info!(
        "compliance profile of tenant {tenant} saved by {}: {} framework(s), {} scoped, {} check(s) not needed",
        ctx.username,
        profile.frameworks.len(),
        profile.scope.len(),
        profile.excluded_checks.len()
    );
    Json(json!({ "status": "ok", "profile": profile })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_validation_and_scope() {
        let p = Profile {
            frameworks: vec!["SOC_2".into(), "PCI_DSS".into(), "SOC_2".into()],
            scope: BTreeMap::from([("PCI_DSS".into(), vec!["pci-scope".into()]), ("SOC_2".into(), vec![])]),
            excluded_checks: vec!["26001".into(), "26000".into(), "26001".into()],
            ..Default::default()
        }
        .validate()
        .unwrap();
        assert_eq!(p.frameworks, vec!["PCI_DSS", "SOC_2"]);
        assert_eq!(p.excluded_checks, vec!["26000", "26001"]);
        assert!(!p.scope.contains_key("SOC_2"), "an empty scope means every agent");
        assert!(p.reports_on("SOC_2") && !p.reports_on("HIPAA"));
        assert!(Profile::default().reports_on("HIPAA"), "no choice: every framework");
        assert!(Profile { frameworks: vec!["ISO".into()], ..Default::default() }.validate().is_err());
        assert!(Profile { excluded_checks: vec!["1; DROP".into()], ..Default::default() }.validate().is_err());
        assert!(Profile { scope: BTreeMap::from([("HIPAA".into(), vec!["bad name".into()])]), ..Default::default() }.validate().is_err());

        let agents = vec!["001".to_string(), "002".to_string(), "003".to_string()];
        let groups = HashMap::from([("001".to_string(), vec!["pci-scope".to_string()]), ("002".to_string(), vec!["default".to_string()])]);
        assert_eq!(scoped(&agents, &groups, &["pci-scope".into()]), vec!["001"]);
        assert_eq!(scoped(&agents, &groups, &[]), agents);
    }

    #[test]
    fn check_tags_map_frameworks() {
        assert_eq!(check_frameworks(r#"{"cis":["1.1"],"pci_dss_v4.0":["8.3.6"],"tsc":["CC6.1"],"nist_800_53":["IA.5"]}"#), vec!["PCI_DSS", "NIST_800_53", "SOC_2"]);
        assert_eq!(check_frameworks("{}"), Vec::<&str>::new());
    }
}
