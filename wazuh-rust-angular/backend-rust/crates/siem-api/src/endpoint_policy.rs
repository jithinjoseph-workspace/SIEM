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

/// Windows starts the agent itself (`--blocked`) in a blocked program's place.
const BLOCKER: &str = "provigil-agent.exe";

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
        if let Err(e) = state.db.main().query(&provigil_common::ddl::on_cluster(ddl)).execute().await {
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

// ── drafting a rule from a sentence ──

/// Well-known services: words that name them, their sites, their Windows programs. Used without
/// AI, and given to the AI as the known part.
const KNOWN: &[(&[&str], &str, &[&str], &[&str])] = &[
    (&["chatgpt", "openai"], "ChatGPT", &["chatgpt.com", "chat.openai.com"], &["chatgpt.exe"]),
    (&["claude", "anthropic"], "Claude", &["claude.ai"], &["claude.exe"]),
    (&["gemini", "bard"], "Gemini", &["gemini.google.com"], &[]),
    (&["copilot"], "Microsoft Copilot", &["copilot.microsoft.com"], &[]),
    (&["perplexity"], "Perplexity", &["perplexity.ai"], &[]),
    (&["deepseek"], "DeepSeek", &["chat.deepseek.com"], &[]),
    (&["whatsapp"], "WhatsApp", &["web.whatsapp.com"], &["whatsapp.exe"]),
    (&["telegram"], "Telegram", &["web.telegram.org"], &["telegram.exe"]),
    (&["discord"], "Discord", &["discord.com"], &["discord.exe"]),
    (&["facebook"], "Facebook", &["facebook.com"], &[]),
    (&["instagram"], "Instagram", &["instagram.com"], &[]),
    (&["tiktok"], "TikTok", &["tiktok.com"], &[]),
    (&["youtube"], "YouTube", &["youtube.com", "youtu.be"], &[]),
    (&["netflix"], "Netflix", &["netflix.com"], &[]),
    (&["torrent", "utorrent", "bittorrent", "qbittorrent"], "Torrent clients", &[], &["utorrent.exe", "bittorrent.exe", "qbittorrent.exe"]),
    (&["anydesk"], "AnyDesk", &["anydesk.com"], &["anydesk.exe"]),
    (&["teamviewer"], "TeamViewer", &["teamviewer.com"], &["teamviewer.exe"]),
    (&["dropbox"], "Dropbox", &["dropbox.com"], &["dropbox.exe"]),
    (&["steam"], "Steam", &["store.steampowered.com"], &["steam.exe"]),
];

const SUGGEST: &str = "You help a company's IT administrator write endpoint control rules for the ProVigil security platform. From the administrator's request, list the websites (domain names only, e.g. chatgpt.com; each also covers its sub-domains) and the Windows program file names (e.g. chatgpt.exe) to block. Only give names you are confident are real and belong to what was asked; leave out anything you are unsure of. Never list system programs (explorer.exe, svchost.exe, cmd.exe, powershell.exe and the like) or whole country domains. Answer with one JSON object and nothing else: {\"name\": \"short rule name\", \"sites\": [\"...\"], \"apps\": [\"...\"], \"message\": \"one sentence shown to the person when blocked\", \"note\": \"what the administrator should check, or empty\"}";

/// The drafts for `text`: a site rule and an app rule (whichever has entries), in monitor mode.
fn drafts(name: &str, sites: &[String], apps: &[String], message: &str, note: &str) -> (Vec<Value>, Vec<String>) {
    let mut out = Vec::new();
    let mut refused = Vec::new();
    for (kind, list, label) in [("site", sites, "websites"), ("app", apps, "programs")] {
        let mut ok = Vec::new();
        for t in list {
            match if kind == "site" { ep::domain(t) } else { ep::app(t) } {
                Ok(v) => ok.push(v),
                Err(e) => refused.push(e),
            }
        }
        ok.sort();
        ok.dedup();
        if !ok.is_empty() {
            out.push(json!({ "name": format!("{name} {label}"), "kind": kind, "mode": "monitor", "targets": ok, "message": message, "note": note }));
        }
    }
    (out, refused)
}

/// `POST /api/v1/endpoint-policies/suggest` `{text}` (tenant admin): draft rules for a request such
/// as "block ChatGPT and WhatsApp", from the known services and, when the tenant's AI is on, the
/// AI. Drafts only: nothing is saved; every entry passes the same checks as a saved rule.
pub async fn suggest(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(p): Json<Value>) -> Response {
    let t = ctx.scope();
    if !ctx.can_manage(&t) {
        return crate::tenancy::forbidden();
    }
    let text: String = p["text"].as_str().unwrap_or("").trim().chars().filter(|c| !c.is_control()).take(500).collect();
    if text.len() < 3 {
        return bad(StatusCode::BAD_REQUEST, "Say what to block, e.g. \"block ChatGPT and WhatsApp\"");
    }
    let lower = text.to_ascii_lowercase();
    let known: Vec<_> = KNOWN.iter().filter(|(words, ..)| words.iter().any(|w| lower.contains(w))).collect();
    let mut name = known.iter().map(|k| k.1).collect::<Vec<_>>().join(", ");
    let mut sites: Vec<String> = known.iter().flat_map(|k| k.2.iter().map(|s| s.to_string())).collect();
    let mut apps: Vec<String> = known.iter().flat_map(|k| k.3.iter().map(|s| s.to_string())).collect();
    let mut message = "This is not allowed by your organisation's policy.".to_string();
    let mut note = String::new();
    let mut source = "known services";
    let ai_on = crate::ai_assist::tenant_ai_enabled(&state, &t);
    let providers = if ai_on { crate::ai_assist::providers(&state, "chat").await } else { Vec::new() };
    if !providers.is_empty() && crate::case_ai::ai_allowed(&t) {
        let known_text = if known.is_empty() { String::new() } else { format!("\nAlready known for this request: sites {sites:?}, programs {apps:?}.") };
        match siem_ai::generate(&providers, SUGGEST, &format!("Request: {text}{known_text}")).await {
            Ok(r) => {
                let reply = r.text.trim();
                let json_part = reply.find('{').and_then(|a| reply.rfind('}').map(|b| &reply[a..=b])).unwrap_or("");
                if let Ok(v) = serde_json::from_str::<Value>(json_part) {
                    let list = |k: &str| v[k].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string).take(200).collect::<Vec<_>>();
                    sites.extend(list("sites"));
                    apps.extend(list("apps"));
                    if let Some(n) = v["name"].as_str().filter(|n| !n.trim().is_empty()) {
                        name = n.trim().chars().take(60).collect();
                    }
                    if let Some(m) = v["message"].as_str().filter(|m| !m.trim().is_empty()) {
                        message = m.trim().chars().take(300).collect();
                    }
                    note = v["note"].as_str().unwrap_or("").chars().take(300).collect();
                    source = "AI";
                }
            }
            Err(e) => tracing::warn!("endpoint policy suggestion: the AI did not answer: {e}"),
        }
    }
    if name.is_empty() {
        name = "Blocked".into();
    }
    let (out, refused) = drafts(&name, &sites, &apps, &message, &note);
    if out.is_empty() {
        let why = if providers.is_empty() { "No known service matched, and the AI is not available for this tenant: type the sites or programs in a new rule." } else { "Nothing usable came back: type the sites or programs in a new rule." };
        return Json(json!({ "status": "ok", "drafts": [], "refused": refused, "source": source, "message": why })).into_response();
    }
    Json(json!({ "status": "ok", "drafts": out, "refused": refused, "source": source })).into_response()
}

// ── what the rules caught ──

#[derive(clickhouse::Row, Deserialize)]
struct Hit {
    agent_id: String,
    agent_name: String,
    rule_level: u8,
    timestamp: u64,
    rule_id: String,
    target: String,
    user: String,
}

#[derive(Deserialize)]
pub struct ActivityQuery {
    days: Option<u32>,
}

/// The /24 (IPv4) or /64 (IPv6) network of an address, as the "network" an attempt came from.
fn network_of(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => {
            let o = a.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Ok(std::net::IpAddr::V6(a)) => {
            let s = a.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Err(_) => "unknown".into(),
    }
}

/// Counts per key, largest first, at most `n`.
fn top(m: HashMap<String, u64>, n: usize) -> Vec<Value> {
    let mut v: Vec<(String, u64)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.into_iter().take(n).map(|(k, c)| json!({ "key": k, "count": c })).collect()
}

/// `GET /api/v1/endpoint-policies/activity?days=7`: per rule, the attempts (blocked or seen), by
/// agent group, network, device, person and site / program, the devices the rule covers, and
/// the latest attempts.
pub async fn activity(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, axum::extract::Query(q): axum::extract::Query<ActivityQuery>) -> Response {
    let t = ctx.scope();
    let days = q.days.unwrap_or(7).clamp(1, 90);
    let since = now_ms().saturating_sub(days as u64 * 86_400_000);
    let hits: Vec<Hit> = match state
        .db
        .tenant_client(&t)
        .query(
            "SELECT agent_id, agent_name, rule_level, timestamp, JSONExtractString(alert_json, 'data', 'endpoint_policy', 'rule_id') AS rule_id, \
             JSONExtractString(alert_json, 'data', 'endpoint_policy', 'target') AS target, JSONExtractString(alert_json, 'data', 'endpoint_policy', 'user') AS user \
             FROM siem_alerts WHERE rule_id IN (?, ?) AND timestamp >= ? ORDER BY timestamp DESC LIMIT 100000",
        )
        .bind(RULE_SITE)
        .bind(RULE_APP)
        .bind(since)
        .fetch_all()
        .await
    {
        Ok(h) => h,
        Err(e) => return bad(StatusCode::SERVICE_UNAVAILABLE, &format!("The attempts could not be read: {e}")),
    };
    let rules = RULES.read().unwrap().get(&t).cloned().unwrap_or_default();
    let (groups, ips, os): (HashMap<String, Vec<String>>, HashMap<String, String>, HashMap<String, String>) = {
        let enrolled = state.enrolled.read().unwrap();
        let agents = state.agents.read().unwrap();
        let mine: Vec<(&String, &crate::EnrolledAgent)> = enrolled.iter().filter(|(_, e)| e.tenant == t && !e.disabled).collect();
        (
            mine.iter().map(|(id, e)| ((*id).clone(), crate::groups::agent_groups(&e.groups))).collect(),
            mine.iter().map(|(id, _)| ((*id).clone(), agents.get(*id).map(|a| a.ip.clone()).unwrap_or_default())).collect(),
            mine.iter().map(|(id, e)| ((*id).clone(), e.os_type.clone())).collect(),
        )
    };
    let shown = |m: &str| crate::groups::display_name(&t, m).unwrap_or_else(|| m.to_string());
    let per_rule: Vec<Value> = rules
        .iter()
        .map(|r| {
            let mine: Vec<&Hit> = hits.iter().filter(|h| h.rule_id == r.id).collect();
            let (mut by_group, mut by_net, mut by_dev, mut by_user, mut by_target) = (HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
            for h in &mine {
                for g in groups.get(&h.agent_id).cloned().unwrap_or_else(|| vec!["default".into()]) {
                    *by_group.entry(shown(&g)).or_insert(0u64) += 1;
                }
                *by_net.entry(network_of(ips.get(&h.agent_id).map(String::as_str).unwrap_or(""))).or_insert(0u64) += 1;
                *by_dev.entry(h.agent_name.clone()).or_insert(0u64) += 1;
                if !h.user.is_empty() {
                    *by_user.entry(h.user.clone()).or_insert(0u64) += 1;
                }
                *by_target.entry(h.target.clone()).or_insert(0u64) += 1;
            }
            let covered = groups.iter().filter(|(id, g)| r.applies(g, os.get(*id).map(String::as_str).unwrap_or(""))).count();
            json!({
                "rule_id": r.id, "name": r.name, "kind": r.kind, "mode": r.mode, "enabled": r.enabled,
                "attempts": mine.len(),
                "blocked": mine.iter().filter(|h| h.rule_level >= 5).count(),
                "devices": by_dev.len(), "people": by_user.len(), "covered_devices": covered,
                "by_group": top(by_group, 20), "by_network": top(by_net, 20), "by_device": top(by_dev, 20), "by_user": top(by_user, 20), "by_target": top(by_target, 20),
            })
        })
        .collect();
    let names: HashMap<&str, &str> = rules.iter().map(|r| (r.id.as_str(), r.name.as_str())).collect();
    let latest: Vec<Value> = hits
        .iter()
        .take(50)
        .map(|h| json!({ "at": h.timestamp / 1000, "rule": names.get(h.rule_id.as_str()).copied().unwrap_or(h.rule_id.as_str()), "target": h.target, "device": h.agent_name, "user": h.user, "blocked": h.rule_level >= 5, "network": network_of(ips.get(&h.agent_id).map(String::as_str).unwrap_or("")) }))
        .collect();
    Json(json!({ "status": "ok", "days": days, "total": hits.len(), "devices_total": groups.len(), "rules": per_rule, "latest": latest })).into_response()
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

/// The program a blocker run stood in for: Windows starts the agent as
/// `"...\provigil-agent.exe" --blocked <rule> "<program>" <args>`. None: not a blocker run.
fn blocked_program(command_line: &str) -> Option<String> {
    let mut words = Vec::new();
    let (mut cur, mut quoted) = (String::new(), false);
    for c in command_line.chars() {
        match c {
            '"' => quoted = !quoted,
            ' ' | '\t' if !quoted => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    let i = words.iter().position(|w| w == "--blocked")?;
    words.get(i + 2).cloned()
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
                if let Some(a) = report(v, tenant, &agent, &r, all.get(tenant)) {
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
                let (image, ours) = match blocked_program(&cmd).filter(|_| file(&image).eq_ignore_ascii_case(BLOCKER)) {
                    Some(p) => (p, true),
                    None => (image, false),
                };
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

/// An agent's report: `{"kind": "applied" | "apply_failed" | "tamper", "version", "error", "what"}`,
/// or an attempt the agent saw itself (the Linux agent, which has no Sysmon):
/// `{"kind": "site_attempt" | "app_attempt", "rule_id", "mode", "target", "user", "process", "stopped"}`.
fn report(v: &Value, tenant: &str, agent: &str, r: &Value, rules: Option<&Vec<Rule>>) -> Option<siem_core::Alert> {
    let s = |k: &str| r[k].as_str().unwrap_or_default().chars().take(500).collect::<String>();
    let kind = s("kind");
    if kind == "site_attempt" || kind == "app_attempt" {
        let name = rules.and_then(|rs| rs.iter().find(|x| x.id == s("rule_id"))).map(|x| x.name.clone()).unwrap_or_else(|| s("rule_id"));
        let blocked = s("mode") == "enforce";
        let (target, user) = (s("target"), s("user"));
        let key = format!("policy:{}:{target}:{user}", s("rule_id"));
        if crate::file_reputation::reported_recently(tenant, agent, &key) {
            return None;
        }
        let (rule, level, what) = match (kind.as_str(), blocked) {
            ("site_attempt", _) => (RULE_SITE, 5, "Blocked site attempt"),
            (_, true) => (RULE_APP, 6, "Blocked application attempt"),
            _ => (RULE_APP, 3, "Application in policy started"),
        };
        let policy = json!({ "rule_id": s("rule_id"), "rule": name, "kind": if rule == RULE_SITE { "site" } else { "app" }, "mode": s("mode"), "target": target, "user": user, "process": s("process") });
        return Some(alert(v, rule, level, format!("{what}: {}{} ({name})", if s("name").is_empty() { target.clone() } else { s("name") }, by(&user)), s("process"), policy));
    }
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
            (ev("1", json!({ "image": "C:\\\\Program Files\\\\ProVigil\\\\provigil-agent.exe", "commandLine": "\"C:\\\\Program Files\\\\ProVigil\\\\provigil-agent.exe\" --blocked a1 \"C:\\\\Apps\\\\chatgpt.exe\" --x", "user": "ACME\\\\ann" })), t.to_string()),
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
        assert!(check(&[(e.clone(), "t2".into())], &HashMap::new()).is_empty());
        assert_eq!(STATES.read().unwrap()["t2"]["008"].version, "ab12");
        // the Linux agent's own attempt reports
        RULES.write().unwrap().insert("t2".into(), vec![Rule { id: "s9".into(), name: "AI sites".into(), ..Default::default() }]);
        e["full_log"] = json!("provigil_policy: {\"kind\":\"site_attempt\",\"rule_id\":\"s9\",\"mode\":\"enforce\",\"target\":\"chatgpt.com\",\"name\":\"www.chatgpt.com\",\"user\":\"ann\"}");
        let a = check(&[(e.clone(), "t2".into())], &HashMap::new());
        assert_eq!((a[0].0.rule.id, a[0].0.rule.description.as_str()), (RULE_SITE, "Blocked site attempt: www.chatgpt.com by ann (AI sites)"));
        assert_eq!(STATES.read().unwrap()["t2"]["008"].state, "applied", "an attempt is not the agent's state");
        e["full_log"] = json!("provigil_policy: {\"kind\":\"app_attempt\",\"rule_id\":\"x\",\"mode\":\"monitor\",\"target\":\"discord\",\"user\":\"bob\",\"process\":\"/usr/bin/discord\"}");
        let a = check(&[(e, "t2".into())], &HashMap::new());
        assert_eq!((a[0].0.rule.id, a[0].0.rule.level), (RULE_APP, 3));
    }

    #[test]
    fn drafts_keep_only_valid_entries() {
        let (d, refused) = drafts("ChatGPT", &["chatgpt.com".into(), "*.com".into()], &["ChatGPT.exe".into(), "explorer.exe".into()], "No", "");
        assert_eq!(d.len(), 2);
        assert_eq!(d[0]["targets"], json!(["chatgpt.com"]));
        assert_eq!(d[1]["targets"], json!(["chatgpt.exe"]));
        assert_eq!((d[0]["mode"].as_str(), d[1]["kind"].as_str()), (Some("monitor"), Some("app")));
        assert_eq!(refused.len(), 2, "a whole top-level domain and a system program");
        assert!(drafts("x", &[], &[], "", "").0.is_empty());
        assert!(KNOWN.iter().all(|k| k.2.iter().all(|s| ep::domain(s).is_ok()) && k.3.iter().all(|a| ep::app(a).is_ok())), "the known list passes the checks");
    }

    #[test]
    fn networks() {
        assert_eq!(network_of("192.168.1.70"), "192.168.1.0/24");
        assert_eq!(network_of("fe80::1:2:3:4"), "fe80:0:0:0::/64");
        assert_eq!(network_of(""), "unknown");
    }

    #[test]
    fn blocker_command_line() {
        assert_eq!(blocked_program("\"C:\\P\\provigil-agent.exe\" --blocked a1 \"C:\\A B\\chatgpt.exe\" -x").as_deref(), Some("C:\\A B\\chatgpt.exe"));
        assert_eq!(blocked_program("C:\\P\\provigil-agent.exe --blocked a1 C:\\A\\x.exe").as_deref(), Some("C:\\A\\x.exe"));
        assert_eq!(blocked_program("C:\\P\\provigil-agent.exe --service"), None, "the agent itself");
    }
}
