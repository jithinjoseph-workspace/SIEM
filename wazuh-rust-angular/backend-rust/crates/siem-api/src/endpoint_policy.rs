//! Endpoint control policies, the manager's side (specs/compliance-and-endpoint-policy.md part B;
//! the rule format and checks are `provigil_agent_server::endpoint_policy`).
//!
//! - Stored in the main database (`endpoint_policies`, key tenant + id), where the gateway reads
//!   them and adds each agent's rules to its group settings. Every change also goes to
//!   `endpoint_policy_changes` (who, when, before, after).
//! - Attempts are found here, in the events every agent already sends: a DNS lookup (Sysmon 22)
//!   of a ruled site, a program start (Sysmon 1, Security 4688) of a ruled program, ProVigil's
//!   blocker started in a ruled program's place. The agent reports applying its rules and any
//!   change made to them on the PC (`provigil_policy:` lines).
//!
//! `GET /api/v1/endpoint-policies` (rules, presets, each agent's state),
//! `PUT /api/v1/endpoint-policies/:id` (`new` creates), `DELETE /api/v1/endpoint-policies/:id`
//! (tenant admin for changes).

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use provigil_agent_server::endpoint_policy::{self as ep, Rule};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::tenancy::AuthCtx;
use crate::AppState;

/// In the main database, next to `agent_registry`: the gateway reads it there.
const DDL: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS endpoint_policies (tenant_id String, id String, doc String, deleted UInt8 DEFAULT 0, updated_at UInt64) ENGINE = ReplacingMergeTree(updated_at) ORDER BY (tenant_id, id)",
    "CREATE TABLE IF NOT EXISTS endpoint_policy_changes (tenant_id String, id String, at UInt64, by String, action String, before String, after String) ENGINE = MergeTree ORDER BY (tenant_id, at)",
];

pub const RULE_SITE: u32 = 940300;
pub const RULE_APP: u32 = 940301;
pub const RULE_APPLY_FAILED: u32 = 940303;
pub const RULE_TAMPER: u32 = 940304;

/// The blocker the agent starts in a blocked program's place.
const BLOCKER: &str = "provigil-blocked.exe";

#[derive(clickhouse::Row, Serialize, Deserialize)]
struct Row {
    tenant_id: String,
    id: String,
    doc: String,
    deleted: u8,
    updated_at: u64,
}

#[derive(clickhouse::Row, Serialize, Deserialize)]
struct Change {
    tenant_id: String,
    id: String,
    at: u64,
    by: String,
    action: String,
    before: String,
    after: String,
}

/// What an agent last reported about its rules.
#[derive(Clone, Serialize)]
struct AgentState {
    state: String,
    version: String,
    error: String,
    at: u64,
}

/// tenant -> rules
static RULES: LazyLock<RwLock<HashMap<String, Vec<Rule>>>> = LazyLock::new(Default::default);
/// tenant -> agent -> state.
/// shortcut: kept in memory only, so empty after a restart until each agent reports again (it does on every apply)
static STATES: LazyLock<RwLock<HashMap<String, HashMap<String, AgentState>>>> = LazyLock::new(Default::default);

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

/// Creates the tables and loads the rules (at start).
pub async fn load(state: &AppState) {
    for ddl in DDL {
        if let Err(e) = state.db.main().query(ddl).execute().await {
            tracing::warn!("endpoint policy table: {e}");
        }
    }
    let rows: Vec<Row> = state.db.main().query("SELECT ?fields FROM endpoint_policies FINAL WHERE deleted = 0").fetch_all().await.unwrap_or_default();
    let mut m: HashMap<String, Vec<Rule>> = HashMap::new();
    for r in rows {
        if let Ok(rule) = serde_json::from_str::<Rule>(&r.doc) {
            m.entry(r.tenant_id).or_default().push(rule);
        }
    }
    for v in m.values_mut() {
        v.sort_by(|a, b| a.name.cmp(&b.name));
    }
    tracing::info!("Loaded {} endpoint policy rules", m.values().map(Vec::len).sum::<usize>());
    *RULES.write().unwrap() = m;
}

fn bad(code: StatusCode, m: &str) -> Response {
    (code, Json(json!({ "status": "error", "message": m }))).into_response()
}

/// A rule as the page shows it: groups by their tenant names.
fn view(tenant: &str, r: &Rule) -> Value {
    let mut v = serde_json::to_value(r).unwrap_or_default();
    v["groups"] = json!(r.groups.iter().filter_map(|m| crate::groups::display_name(tenant, m)).collect::<Vec<_>>());
    v
}

/// `GET /api/v1/endpoint-policies`
pub async fn list(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Response {
    let t = ctx.scope();
    let rules: Vec<Value> = RULES.read().unwrap().get(&t).map(|v| v.iter().map(|r| view(&t, r)).collect()).unwrap_or_default();
    let names: HashMap<String, String> = state.agents.read().unwrap().values().map(|a| (a.id.clone(), a.name.clone())).collect();
    let agents: Vec<Value> = STATES
        .read()
        .unwrap()
        .get(&t)
        .map(|m| m.iter().map(|(id, s)| json!({ "agent_id": id, "agent_name": names.get(id).cloned().unwrap_or_default(), "state": s.state, "version": s.version, "error": s.error, "at": s.at / 1000 })).collect())
        .unwrap_or_default();
    Json(json!({ "status": "ok", "rules": rules, "presets": ep::presets(), "agents": agents, "can_edit": ctx.can_manage(&t) })).into_response()
}

async fn write(state: &AppState, tenant: &str, by: &str, action: &str, before: Option<&Rule>, after: &Rule, deleted: bool) -> Result<(), String> {
    let now = now_ms();
    let row = Row { tenant_id: tenant.into(), id: after.id.clone(), doc: serde_json::to_string(after).unwrap_or_default(), deleted: deleted as u8, updated_at: now };
    let mut ins = state.db.main().insert::<Row>("endpoint_policies").map_err(|e| e.to_string())?;
    ins.write(&row).await.map_err(|e| e.to_string())?;
    ins.end().await.map_err(|e| e.to_string())?;
    let ch = Change {
        tenant_id: tenant.into(),
        id: after.id.clone(),
        at: now,
        by: by.into(),
        action: action.into(),
        before: before.map(|b| serde_json::to_string(b).unwrap_or_default()).unwrap_or_default(),
        after: if deleted { String::new() } else { row.doc.clone() },
    };
    // the rule is saved; a lost history row is logged, not a failed save
    match state.db.main().insert::<Change>("endpoint_policy_changes") {
        Ok(mut i) => {
            if let Err(e) = async { i.write(&ch).await?; i.end().await }.await {
                tracing::warn!("endpoint_policy_changes: {e}");
            }
        }
        Err(e) => tracing::warn!("endpoint_policy_changes: {e}"),
    }
    Ok(())
}

/// `PUT /api/v1/endpoint-policies/:id` (tenant admin): the whole rule; `new` creates one.
pub async fn put(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, Json(p): Json<Value>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return crate::tenancy::forbidden();
    }
    let mut rule: Rule = match serde_json::from_value(p) {
        Ok(r) => r,
        Err(e) => return bad(StatusCode::BAD_REQUEST, &format!("Not a rule: {e}")),
    };
    // the page sends the tenant's group names
    let asked: Vec<String> = rule.groups.iter().map(|g| g.trim().to_string()).filter(|g| !g.is_empty()).collect();
    rule.groups = if asked.is_empty() {
        Vec::new()
    } else {
        match crate::groups::resolve(&tenant, &asked) {
            Ok(g) => g,
            Err(m) => return bad(StatusCode::BAD_REQUEST, &m),
        }
    };
    let before = RULES.read().unwrap().get(&tenant).and_then(|v| v.iter().find(|r| r.id == id).cloned());
    if id != "new" && before.is_none() {
        return bad(StatusCode::NOT_FOUND, "No such rule");
    }
    rule.id = if id == "new" { uuid::Uuid::new_v4().simple().to_string()[..12].to_string() } else { id };
    rule.updated_by = ctx.username.clone();
    rule.updated_at = now_ms() / 1000;
    let rule = match rule.validate() {
        Ok(r) => r,
        Err(m) => return bad(StatusCode::BAD_REQUEST, &m),
    };
    {
        let all = RULES.read().unwrap();
        let mine = all.get(&tenant).map(Vec::as_slice).unwrap_or_default();
        if before.is_none() && mine.len() >= ep::MAX_RULES {
            return bad(StatusCode::BAD_REQUEST, &format!("At most {} rules", ep::MAX_RULES));
        }
    }
    if let Err(e) = write(&state, &tenant, &ctx.username, if before.is_some() { "update" } else { "create" }, before.as_ref(), &rule, false).await {
        return bad(StatusCode::INTERNAL_SERVER_ERROR, &format!("The rule could not be saved: {e}"));
    }
    let mut all = RULES.write().unwrap();
    let v = all.entry(tenant.clone()).or_default();
    v.retain(|r| r.id != rule.id);
    v.push(rule.clone());
    v.sort_by(|a, b| a.name.cmp(&b.name));
    Json(json!({ "status": "ok", "rule": view(&tenant, &rule) })).into_response()
}

/// `DELETE /api/v1/endpoint-policies/:id` (tenant admin): agents remove it at their next settings fetch.
pub async fn delete(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return crate::tenancy::forbidden();
    }
    let Some(before) = RULES.read().unwrap().get(&tenant).and_then(|v| v.iter().find(|r| r.id == id).cloned()) else {
        return bad(StatusCode::NOT_FOUND, "No such rule");
    };
    if let Err(e) = write(&state, &tenant, &ctx.username, "delete", Some(&before), &before, true).await {
        return bad(StatusCode::INTERNAL_SERVER_ERROR, &format!("The rule could not be deleted: {e}"));
    }
    if let Some(v) = RULES.write().unwrap().get_mut(&tenant) {
        v.retain(|r| r.id != id);
    }
    Json(json!({ "status": "ok" })).into_response()
}

// ── attempts, in the events the agents send ──

fn st(v: &Value, p: &str) -> String {
    v.pointer(p).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn alert(v: &Value, rule: u32, level: u8, description: String, full_log: String, policy: Value) -> siem_core::Alert {
    let mut data: HashMap<String, Value> = v["data"].as_object().map(|o| o.iter().map(|(k, x)| (k.clone(), x.clone())).collect()).unwrap_or_default();
    data.insert("endpoint_policy".into(), policy);
    siem_core::Alert {
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        rule: siem_core::RuleAlertInfo { id: rule, level, description, groups: vec!["endpoint_policy".into()], mitre: None },
        agent: siem_core::AgentAlertInfo { id: st(v, "/agent/id"), name: st(v, "/agent/name"), ip: st(v, "/agent/ip") },
        manager: None,
        decoder: None,
        full_log,
        decoded: siem_core::DecodedFields { decoder_name: "endpoint_policy".into(), ..Default::default() },
        location: st(v, "/location"),
        data,
    }
}

/// The SHA-256 in Sysmon's `Hashes` (`SHA256=...,MD5=...`).
fn sha256_of(hashes: &str) -> String {
    hashes.split(',').find_map(|h| h.trim().strip_prefix("SHA256=").map(str::to_string)).unwrap_or_default()
}

/// The program a blocker run stood in for: Windows starts it as `provigil-blocked.exe "<program>" <args>`.
fn blocked_program(command_line: &str) -> String {
    let rest = command_line.trim();
    let rest = if let Some(r) = rest.strip_prefix('"') { r.split_once('"').map(|x| x.1).unwrap_or("") } else { rest.split_once(' ').map(|x| x.1).unwrap_or("") };
    let rest = rest.trim();
    if let Some(r) = rest.strip_prefix('"') {
        r.split('"').next().unwrap_or("").to_string()
    } else {
        rest.split(' ').next().unwrap_or("").to_string()
    }
}

/// Alerts for a batch of archived events; `groups` = agent id -> its manager groups.
pub fn check(events: &[(Value, String)], groups: &HashMap<String, Vec<String>>) -> Vec<(siem_core::Alert, String)> {
    let all = RULES.read().unwrap();
    let mut out = Vec::new();
    let none = Vec::new();
    for (v, tenant) in events {
        let agent = st(v, "/agent/id");
        if agent.is_empty() || agent == "000" {
            continue;
        }
        let log = v["full_log"].as_str().unwrap_or("");
        // the agent's own report on its rules
        if let Some(i) = log.find("provigil_policy:") {
            if let Ok(r) = serde_json::from_str::<Value>(log[i + 16..].trim()) {
                if let Some(a) = report(v, tenant, &agent, &r) {
                    out.push((a, tenant.clone()));
                }
            }
            continue;
        }
        let Some(rules) = all.get(tenant).filter(|r| !r.is_empty()) else { continue };
        let ag = groups.get(&agent).unwrap_or(&none);
        let ed = |k: &str| st(v, &format!("/data/win/eventdata/{k}")).replace("\\\\", "\\");
        let id = st(v, "/data/win/system/eventID");
        let sysmon = st(v, "/data/win/system/providerName") == "Microsoft-Windows-Sysmon";
        let user = [ed("user"), ed("subjectUserName")].into_iter().find(|u| !u.is_empty()).unwrap_or_default();
        let found = match id.as_str() {
            "22" if sysmon => {
                let name = ed("queryName");
                let image = ed("image");
                rules.iter().filter(|r| r.kind == "site" && r.applies(ag, "windows")).find_map(|r| r.site_hit(&name).map(|t| (r, t.to_string()))).map(|(r, t)| {
                    let enforce = r.mode == "enforce";
                    let what = if enforce { "Blocked site attempt" } else { "Site in policy visited" };
                    (r, t, RULE_SITE, if enforce { 5 } else { 3 }, format!("{what}: {name}{} in {} ({})", by(&user), file(&image), r.name), name, image)
                })
            }
            "1" | "4688" => {
                let image = [ed("image"), ed("newProcessName")].into_iter().find(|x| !x.is_empty()).unwrap_or_default();
                let cmd = ed("commandLine");
                let (image, ours) = if file(&image).eq_ignore_ascii_case(BLOCKER) { (blocked_program(&cmd), true) } else { (image, false) };
                let sha = sha256_of(&ed("hashes"));
                rules.iter().filter(|r| r.kind == "app" && r.applies(ag, "windows")).find_map(|r| r.app_hit(&image, &sha).map(|t| (r, t.to_string()))).map(|(r, t)| {
                    let blocked = ours || r.mode == "enforce";
                    let what = if blocked { "Blocked application attempt" } else { "Application in policy started" };
                    (r, t, RULE_APP, if blocked { 6 } else { 3 }, format!("{what}: {}{} ({})", file(&image), by(&user), r.name), cmd, image)
                })
            }
            _ => None,
        };
        if let Some((r, target, rule, level, description, detail, image)) = found {
            // one alert an hour per agent, rule, target and person
            let key = format!("policy:{}:{target}:{user}", r.id);
            if crate::file_reputation::reported_recently(tenant, &agent, &key) {
                continue;
            }
            let policy = json!({ "rule_id": r.id, "rule": r.name, "kind": r.kind, "mode": r.mode, "target": target, "user": user, "process": image });
            out.push((alert(v, rule, level, description, detail, policy), tenant.clone()));
        }
    }
    out
}

fn by(user: &str) -> String {
    if user.is_empty() { String::new() } else { format!(" by {user}") }
}

fn file(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// An agent's report: `{"kind": "applied" | "apply_failed" | "tamper", "version", "error", "what"}`.
fn report(v: &Value, tenant: &str, agent: &str, r: &Value) -> Option<siem_core::Alert> {
    let s = |k: &str| r[k].as_str().unwrap_or_default().chars().take(500).collect::<String>();
    let kind = s("kind");
    let state = AgentState { state: kind.clone(), version: s("version"), error: s("error"), at: now_ms() };
    STATES.write().unwrap().entry(tenant.to_string()).or_default().insert(agent.to_string(), state);
    match kind.as_str() {
        "apply_failed" => Some(alert(v, RULE_APPLY_FAILED, 7, format!("Endpoint policy could not be applied: {}", s("error")), s("error"), r.clone())),
        "tamper" => Some(alert(v, RULE_TAMPER, 12, format!("Endpoint policy changed on the computer: {}", s("what")), s("what"), r.clone())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: &str, data: Value) -> Value {
        json!({ "agent": { "id": "007", "name": "pc-7" }, "data": { "win": { "system": { "eventID": id, "providerName": "Microsoft-Windows-Sysmon" }, "eventdata": data } }, "full_log": "" })
    }

    #[test]
    fn attempts_found_in_sysmon_events() {
        let t = "test_ep_tenant";
        let site = Rule { id: "s1".into(), name: "AI sites".into(), kind: "site".into(), mode: "enforce".into(), targets: vec!["chatgpt.com".into()], enabled: true, ..Default::default() };
        let app = Rule { id: "a1".into(), name: "AI apps".into(), kind: "app".into(), mode: "monitor".into(), targets: vec!["chatgpt.exe".into()], groups: vec!["test_ep_tenant.office".into()], enabled: true, ..Default::default() };
        RULES.write().unwrap().insert(t.into(), vec![site, app]);
        let groups = HashMap::from([("007".to_string(), vec!["test_ep_tenant.office".to_string()])]);
        let events = vec![
            (ev("22", json!({ "queryName": "ab.chatgpt.com", "image": "C:\\\\Program Files\\\\Edge\\\\msedge.exe", "user": "ACME\\\\jdoe" })), t.to_string()),
            (ev("22", json!({ "queryName": "example.com" })), t.to_string()),
            (ev("1", json!({ "image": "C:\\\\Users\\\\x\\\\ChatGPT.exe", "hashes": "SHA256=AB,MD5=CD", "user": "ACME\\\\jdoe" })), t.to_string()),
            // the blocker in its place
            (ev("1", json!({ "image": "C:\\\\Program Files\\\\ProVigil\\\\provigil-blocked.exe", "commandLine": "\"C:\\\\Program Files\\\\ProVigil\\\\provigil-blocked.exe\" \"C:\\\\Apps\\\\chatgpt.exe\" --x", "user": "ACME\\\\ann" })), t.to_string()),
        ];
        let a = check(&events, &groups);
        let d: Vec<(u32, u8, &str)> = a.iter().map(|(x, _)| (x.rule.id, x.rule.level, x.rule.description.as_str())).collect();
        assert_eq!(d[0], (RULE_SITE, 5, "Blocked site attempt: ab.chatgpt.com by ACME\\jdoe in msedge.exe (AI sites)"));
        assert_eq!(d[1], (RULE_APP, 3, "Application in policy started: ChatGPT.exe by ACME\\jdoe (AI apps)"));
        assert_eq!(d[2], (RULE_APP, 6, "Blocked application attempt: chatgpt.exe by ACME\\ann (AI apps)"));
        assert_eq!(a.len(), 3);
        assert!(check(&events, &groups).is_empty(), "once an hour per agent, rule, target, person");
        // outside the app rule's groups
        let other = HashMap::from([("007".to_string(), vec!["test_ep_tenant.lab".to_string()])]);
        let e = vec![(ev("1", json!({ "image": "C:\\\\x\\\\chatgpt.exe", "user": "bob" })), t.to_string())];
        assert!(check(&e, &other).is_empty());
    }

    #[test]
    fn agent_reports() {
        let mut e = json!({ "agent": { "id": "008", "name": "pc-8" }, "full_log": "provigil_policy: {\"kind\":\"tamper\",\"what\":\"hosts file section removed\"}" });
        let a = check(&[(e.clone(), "t2".into())], &HashMap::new());
        assert_eq!((a[0].0.rule.id, a[0].0.rule.level), (RULE_TAMPER, 12));
        e["full_log"] = json!("provigil_policy: {\"kind\":\"applied\",\"version\":\"ab12\"}");
        assert!(check(&[(e, "t2".into())], &HashMap::new()).is_empty());
        assert_eq!(STATES.read().unwrap()["t2"]["008"].version, "ab12");
    }

    #[test]
    fn blocker_command_line() {
        assert_eq!(blocked_program("\"C:\\P\\provigil-blocked.exe\" \"C:\\A B\\chatgpt.exe\" -x"), "C:\\A B\\chatgpt.exe");
        assert_eq!(blocked_program("C:\\P\\provigil-blocked.exe C:\\A\\x.exe"), "C:\\A\\x.exe");
    }
}
