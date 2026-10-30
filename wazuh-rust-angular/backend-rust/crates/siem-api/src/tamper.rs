//! EDR agent tamper protection, the manager's side (the agent's side is siem-active-response
//! `tamper-protect`). Per tenant it can be turned on; then every Windows agent's service is
//! locked (Administrators cannot stop, reconfigure or remove it; a killed agent restarts)
//! when it is turned on and again each time the agent starts. A tenant admin opens a timed
//! maintenance window for an upgrade or removal; the agent locks itself again when it ends.
//! Whatever an administrator does to the agent anyway shows up as an alert: commands that
//! stop / delete / reconfigure the agent service or kill the agent, the service killed,
//! its start type changed, its registry key edited.
//!
//! `GET|PUT /api/v1/edr/tamper` (the setting and each agent's state),
//! `POST /api/v1/agents/:id/tamper` `{action: lock | maintenance, minutes}`

use std::collections::{BTreeMap, HashMap};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::tenancy::{self, AuthCtx};
use crate::AppState;

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS siem_tamper (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id";

pub const RULE_COMMAND: u32 = 940110;
pub const RULE_START_TYPE: u32 = 940111;
pub const RULE_KILLED: u32 = 940112;
pub const RULE_REGISTRY: u32 = 940113;

/// Maintenance windows: the agent's own timeouts (`AR_TIMEOUTS`), in minutes.
const WINDOW_MINUTES: [u64; 3] = [10, 60, 1440];

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub enabled: bool,
    #[serde(default)]
    pub updated_by: String,
    #[serde(default)]
    pub updated_at: String,
}

/// An agent's lock state, from what it last reported (or was last sent).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AgentState {
    pub agent_id: String,
    /// locked | maintenance | off | failed | sent
    pub state: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub window: String,
    #[serde(default)]
    pub window_until: String,
    #[serde(default)]
    pub updated_by: String,
    pub updated_at: String,
}

impl AgentState {
    fn in_window(&self) -> bool {
        self.state == "maintenance" && chrono::DateTime::parse_from_rfc3339(&self.window_until).is_ok_and(|t| t > chrono::Utc::now())
    }
}

fn reply(code: StatusCode, m: impl Into<String>) -> Response {
    (code, Json(json!({ "status": if code.is_success() { "ok" } else { "error" }, "message": m.into() }))).into_response()
}

async fn put_doc<T: Serialize>(client: &clickhouse::Client, id: &str, doc: &T) -> Result<(), String> {
    let d = serde_json::to_string(doc).map_err(|e| e.to_string())?;
    let version = chrono::Utc::now().timestamp_micros().max(0) as u64;
    client.query("INSERT INTO siem_tamper (id, doc, version) VALUES (?, ?, ?)").bind(id).bind(d).bind(version).execute().await.map_err(|e| e.to_string())
}

async fn settings(client: &clickhouse::Client) -> Result<Settings, String> {
    let d = client.query("SELECT doc FROM siem_tamper FINAL WHERE id = 'settings'").fetch_optional::<String>().await.map_err(|e| e.to_string())?;
    Ok(d.and_then(|d| serde_json::from_str(&d).ok()).unwrap_or_default())
}

async fn agent_states(client: &clickhouse::Client) -> Result<HashMap<String, AgentState>, String> {
    let docs = client.query("SELECT doc FROM siem_tamper FINAL WHERE startsWith(id, 'agent:')").fetch_all::<String>().await.map_err(|e| e.to_string())?;
    Ok(docs.iter().filter_map(|d| serde_json::from_str::<AgentState>(d).ok()).map(|s| (s.agent_id.clone(), s)).collect())
}

async fn set_state(client: &clickhouse::Client, s: &AgentState) {
    if let Err(e) = put_doc(client, &format!("agent:{}", s.agent_id), s).await {
        warn!("tamper protection: state of agent {} not stored: {e}", s.agent_id);
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn sent(agent: &str, by: &str, what: &str) -> AgentState {
    AgentState { agent_id: agent.into(), state: "sent".into(), message: what.into(), updated_by: by.into(), updated_at: now(), ..Default::default() }
}

/// The tenant's Windows agents (only they run tamper-protect).
fn windows_agents(state: &AppState, ctx: &AuthCtx) -> Vec<siem_core::Agent> {
    crate::scoped_agents(state, ctx).into_iter().filter(|a| crate::agent_is_windows(state, &a.id)).collect()
}

/// `GET /api/v1/edr/tamper`
pub async fn get(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Response {
    if !ctx.has_permission("siem-agents") {
        return tenancy::forbidden();
    }
    let tenant = ctx.scope();
    let client = state.db.tenant_client(&tenant);
    let (s, states) = match (settings(&client).await, agent_states(&client).await) {
        (Ok(s), Ok(a)) => (s, a),
        (Err(e), _) | (_, Err(e)) => return reply(StatusCode::SERVICE_UNAVAILABLE, format!("Tamper protection state cannot be read: {e}")),
    };
    let agents: Vec<Value> = windows_agents(&state, &ctx)
        .iter()
        .map(|a| {
            let st = states.get(&a.id).cloned().unwrap_or_default();
            let shown = if st.state == "maintenance" && !st.in_window() { "locked" } else { st.state.as_str() };
            json!({ "agent_id": a.id, "name": a.name, "state": if shown.is_empty() { "unknown" } else { shown }, "message": st.message, "window_until": st.window_until, "updated_at": st.updated_at, "updated_by": st.updated_by })
        })
        .collect();
    Json(json!({ "settings": s, "editable": ctx.can_manage(&tenant), "agents": agents, "window_minutes": WINDOW_MINUTES })).into_response()
}

#[derive(Deserialize)]
pub struct SetBody {
    enabled: bool,
}

/// `PUT /api/v1/edr/tamper` `{enabled}`: the tenant admin; locks (or unlocks) every Windows agent now.
pub async fn put(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(b): Json<SetBody>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    let client = state.db.tenant_client(&tenant);
    let s = Settings { enabled: b.enabled, updated_by: ctx.username.clone(), updated_at: now() };
    if let Err(e) = put_doc(&client, "settings", &s).await {
        return reply(StatusCode::SERVICE_UNAVAILABLE, format!("The setting was not saved: {e}"));
    }
    let (mut ok, mut failed) = (0, Vec::new());
    for a in windows_agents(&state, &ctx) {
        let r = if b.enabled { crate::wazuh_manager::tamper_lock(&a.id).await } else { crate::wazuh_manager::tamper_off(&a.id).await };
        match r {
            Ok(()) => {
                ok += 1;
                set_state(&client, &sent(&a.id, &ctx.username, if b.enabled { "Lock sent" } else { "Unlock sent" })).await;
            }
            Err(e) => failed.push(format!("{}: {e}", a.name)),
        }
    }
    info!("tamper protection of tenant {tenant} turned {} by {}: {ok} agent(s) told", if b.enabled { "on" } else { "off" }, ctx.username);
    let mut m = format!("Tamper protection {}; sent to {ok} Windows agent(s).", if b.enabled { "on" } else { "off" });
    if !failed.is_empty() {
        m.push_str(&format!(" Not sent: {}.", failed.join("; ")));
    }
    Json(json!({ "status": "ok", "message": m, "settings": s })).into_response()
}

#[derive(Deserialize)]
pub struct AgentAction {
    action: String,
    #[serde(default)]
    minutes: Option<u64>,
    #[serde(default)]
    reason: Option<String>,
}

/// `POST /api/v1/agents/:id/tamper`: lock now, or open a maintenance window (the tenant admin).
pub async fn agent_action(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(agent_id): Path<String>, Json(b): Json<AgentAction>) -> Response {
    if !crate::agent_is_windows(&state, &agent_id) {
        return reply(StatusCode::BAD_REQUEST, "Tamper protection runs on Windows agents for now");
    }
    let tenant = tenancy::tenant_of(&state.agent_tenants.read().unwrap(), &agent_id);
    let client = state.db.tenant_client(&tenant);
    match b.action.as_str() {
        "lock" => match crate::wazuh_manager::tamper_lock(&agent_id).await {
            Ok(()) => {
                set_state(&client, &sent(&agent_id, &ctx.username, "Lock sent")).await;
                reply(StatusCode::OK, "Lock sent to the agent")
            }
            Err(e) => reply(StatusCode::SERVICE_UNAVAILABLE, e),
        },
        "maintenance" => {
            // it lets administrators remove the agent: the tenant admin, recorded as a decision
            if !ctx.can_manage(&tenant) {
                return reply(StatusCode::FORBIDDEN, "Only a tenant admin can open a maintenance window");
            }
            let Some(minutes) = b.minutes.filter(|m| WINDOW_MINUTES.contains(m)) else {
                return reply(StatusCode::BAD_REQUEST, "A maintenance window lasts 10, 60 or 1440 minutes");
            };
            let ip = state.agents.read().unwrap().get(&agent_id).map(|a| a.ip.clone()).unwrap_or_default();
            let reason = b.reason.as_deref().map(str::trim).filter(|r| !r.is_empty()).unwrap_or("maintenance").chars().take(200).collect::<String>();
            if let Err(m) = crate::decisions::gate_manual(&state, &ctx, &tenant, "manual_tamper_maintenance", &ip, json!({ "agent_id": agent_id, "minutes": minutes, "reason": reason })).await {
                return reply(StatusCode::FORBIDDEN, m);
            }
            let window = uuid::Uuid::new_v4().simple().to_string();
            match crate::wazuh_manager::tamper_window(&agent_id, &window, minutes * 60).await {
                Ok(()) => {
                    let until = (chrono::Utc::now() + chrono::Duration::minutes(minutes as i64)).to_rfc3339();
                    let st = AgentState { agent_id: agent_id.clone(), state: "maintenance".into(), message: format!("Window opened: {reason}"), window, window_until: until.clone(), updated_by: ctx.username.clone(), updated_at: now() };
                    set_state(&client, &st).await;
                    info!("tamper protection: maintenance window on agent {agent_id} for {minutes} min by {} ({reason})", ctx.username);
                    reply(StatusCode::OK, format!("Maintenance window open for {minutes} minutes; the agent locks itself again at {until}"))
                }
                Err(e) => reply(StatusCode::SERVICE_UNAVAILABLE, e),
            }
        }
        _ => reply(StatusCode::BAD_REQUEST, "Unknown action: lock or maintenance"),
    }
}

/// What a batch of archived events holds for tamper protection.
#[derive(Default)]
pub struct Found {
    pub alerts: Vec<(siem_core::Alert, String)>,
    /// (tenant, agent) that started: locked again when the tenant has protection on
    pub started: Vec<(String, String)>,
    /// (tenant, agent, tamper-protect result line)
    pub results: Vec<(String, String, Value)>,
}

fn st(v: &Value, p: &str) -> String {
    v.pointer(p).and_then(Value::as_str).unwrap_or("").to_string()
}

/// A command line that stops, removes, reconfigures or kills the agent.
pub fn is_tamper_command(cmd: &str) -> bool {
    let c = cmd.to_lowercase();
    let agent = c.contains("wazuhsvc") || c.contains("wazuh-agent") || c.contains("ossec-agent") || c.contains("wazuh agent");
    if !agent {
        return false;
    }
    let words: Vec<&str> = c.split(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'' || ch == ';' || ch == '(' || ch == ')').filter(|w| !w.is_empty()).collect();
    let has = |w: &str| words.iter().any(|x| *x == w);
    let sc = words.iter().any(|w| *w == "sc" || w.ends_with("\\sc.exe") || *w == "sc.exe");
    let net = words.iter().any(|w| *w == "net" || *w == "net1" || w.ends_with("\\net.exe") || w.ends_with("\\net1.exe") || *w == "net.exe");
    (sc && ["stop", "delete", "config", "sdset", "failure", "pause"].iter().any(|v| has(v)))
        || (net && (has("stop") || has("pause")))
        || ["stop-service", "set-service", "remove-service", "suspend-service", "taskkill", "taskkill.exe", "stop-process"].iter().any(|v| has(v))
        || (c.contains("wmic") && ["delete", "stopservice", "terminate", "changestartmode"].iter().any(|v| c.contains(v)))
        || (c.contains("msiexec") && (has("/x") || has("-x") || c.contains("/uninstall")))
        || ((has("reg") || has("reg.exe")) && (has("add") || has("delete")) && c.contains("\\services\\wazuhsvc"))
}

/// Our own processes run sc.exe on the agent service (lock, unlock).
fn ours(parent: &str) -> bool {
    let p = parent.to_lowercase();
    ["\\tamper-protect.exe", "\\wazuh-agent.exe", "\\restart-wazuh.exe"].iter().any(|n| p.ends_with(n))
}

fn alert(v: &Value, rule: u32, level: u8, description: String, full_log: String) -> siem_core::Alert {
    let mut data: HashMap<String, Value> = v["data"].as_object().map(|o| o.iter().map(|(k, x)| (k.clone(), x.clone())).collect()).unwrap_or_default();
    data.insert("tamper".into(), json!({ "rule": rule }));
    siem_core::Alert {
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        rule: siem_core::RuleAlertInfo {
            id: rule,
            level,
            description,
            groups: vec!["edr".into(), "tamper_protection".into(), "defense_evasion".into()],
            mitre: Some(siem_core::MitreAttack { id: "T1562.001".into(), tactic: "Defense Evasion".into(), technique: "Impair Defenses: Disable or Modify Tools".into() }),
        },
        agent: siem_core::AgentAlertInfo { id: st(v, "/agent/id"), name: st(v, "/agent/name"), ip: st(v, "/agent/ip") },
        manager: None,
        decoder: None,
        full_log,
        decoded: siem_core::DecodedFields {
            decoder_name: "tamper_protection".into(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            user: None,
            program_name: None,
            process_id: None,
            file_path: None,
            action: None,
            status: None,
            extra: HashMap::new(),
        },
        location: st(v, "/location"),
        data,
    }
}

/// Tamper signs, agent starts and tamper-protect results in a batch of archived events.
pub fn check(events: &[(Value, String)]) -> Found {
    let mut f = Found::default();
    for (v, tenant) in events {
        let agent = st(v, "/agent/id");
        if agent.is_empty() || agent == "000" {
            continue;
        }
        let log = v["full_log"].as_str().unwrap_or("");
        if log.contains("\"script\":\"tamper-protect\"") {
            if let Some(r) = log.find('{').and_then(|i| serde_json::from_str::<Value>(&log[i..]).ok()).filter(|r| r["script"] == "tamper-protect") {
                f.results.push((tenant.clone(), agent.clone(), r));
            }
            continue;
        }
        if log.starts_with("ossec: Agent started") || log.contains("ossec: Agent started:") {
            f.started.push((tenant.clone(), agent.clone()));
            continue;
        }
        // Wazuh's eventchannel decoder doubles the backslashes of event data
        let ed = |k: &str| st(v, &format!("/data/win/eventdata/{k}")).replace("\\\\", "\\");
        let id = st(v, "/data/win/system/eventID");
        let provider = st(v, "/data/win/system/providerName");
        let scm = provider == "Service Control Manager" && ed("param1").eq_ignore_ascii_case("wazuh");
        let found = match id.as_str() {
            // a process started (Sysmon 1, Security 4688)
            "1" | "4688" => {
                let cmd = ed("commandLine");
                let parent = [ed("parentImage"), ed("parentProcessName")].concat();
                // Sysmon and the Security log both see the same attempt: one alert an hour per command
                let key = format!("tamper:{}", cmd.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" "));
                (is_tamper_command(&cmd) && !ours(&parent) && !crate::file_reputation::reported_recently(tenant, &agent, &key)).then(|| {
                    let who = [ed("user"), ed("subjectUserName")].into_iter().find(|u| !u.is_empty()).unwrap_or_default();
                    (RULE_COMMAND, 12, format!("Attempt to stop or remove the SIEM agent{}", if who.is_empty() { String::new() } else { format!(" by {who}") }), format!("Command against the agent: {cmd}"))
                })
            }
            "7040" if scm => Some((RULE_START_TYPE, 12, format!("SIEM agent service start type changed from {} to {}", ed("param2"), ed("param3")), log.to_string())),
            "7031" | "7034" if scm => Some((RULE_KILLED, 13, "SIEM agent service terminated unexpectedly (killed?)".to_string(), log.to_string())),
            "12" | "13" | "14" if provider.contains("Sysmon") => {
                let target = ed("targetObject").to_lowercase();
                let image = ed("image").to_lowercase();
                // the service manager writes it for sc.exe changes (seen above as commands)
                (target.contains("\\services\\wazuhsvc") && !image.ends_with("\\services.exe") && !ours(&image)).then(|| (RULE_REGISTRY, 12, "SIEM agent service registry key changed".to_string(), format!("{} wrote {}", ed("image"), ed("targetObject"))))
            }
            _ => None,
        };
        if let Some((rule, level, desc, full)) = found {
            f.alerts.push((alert(v, rule, level, desc, full), tenant.clone()));
        }
    }
    f
}

/// Stores the agents' reports and locks the agents that started (protection on, no open window).
pub async fn apply(state: &AppState, started: Vec<(String, String)>, results: Vec<(String, String, Value)>) {
    for (tenant, agent, r) in results {
        let client = state.db.tenant_client(&tenant);
        let ok = r["status"] == "success";
        let reported = r["state"].as_str().unwrap_or("");
        if reported == "unchanged" {
            continue;
        }
        let prev = agent_states(&client).await.ok().and_then(|m| m.get(&agent).cloned()).unwrap_or_default();
        let st = AgentState {
            agent_id: agent.clone(),
            state: if ok { reported.to_string() } else { "failed".into() },
            message: r["message"].as_str().unwrap_or("").to_string(),
            window: r["window"].as_str().unwrap_or("").to_string(),
            // the window's end is the manager's: the agent only confirms it opened
            window_until: if reported == "maintenance" { prev.window_until } else { String::new() },
            updated_by: "agent".into(),
            updated_at: now(),
        };
        set_state(&client, &st).await;
    }
    let mut by_tenant: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (t, a) in started {
        by_tenant.entry(t).or_default().push(a);
    }
    for (tenant, agents) in by_tenant {
        let client = state.db.tenant_client(&tenant);
        if !settings(&client).await.is_ok_and(|s| s.enabled) {
            continue;
        }
        let states = agent_states(&client).await.unwrap_or_default();
        for a in agents {
            if !crate::agent_is_windows(state, &a) || states.get(&a).is_some_and(AgentState::in_window) {
                continue;
            }
            match crate::wazuh_manager::tamper_lock(&a).await {
                Ok(()) => info!("tamper protection: agent {a} started; lock sent"),
                Err(e) => warn!("tamper protection: agent {a} started; lock not sent: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(agent: &str, id: &str, provider: &str, ed: Value) -> (Value, String) {
        (json!({ "agent": { "id": agent, "name": "pc" }, "location": "EventChannel", "full_log": "{}", "data": { "win": { "system": { "eventID": id, "providerName": provider }, "eventdata": ed } } }), "acm".to_string())
    }

    #[test]
    fn tamper_commands() {
        for c in [
            "sc stop WazuhSvc",
            "C:\\Windows\\system32\\sc.exe config WazuhSvc start= disabled",
            "sc.exe delete \"WazuhSvc\"",
            "net stop wazuhsvc",
            "powershell Stop-Service -Name WazuhSvc -Force",
            "taskkill /F /IM wazuh-agent.exe",
            "wmic service where name='WazuhSvc' call StopService",
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\WazuhSvc /v Start /d 4 /f",
            "msiexec /x wazuh-agent.msi /qn",
        ] {
            assert!(is_tamper_command(c), "{c}");
        }
        for c in ["sc query WazuhSvc", "Get-Service WazuhSvc", "sc stop Spooler", "Start-Service -Name WazuhSvc", "notepad C:\\Program Files (x86)\\ossec-agent\\ossec.log", "sc sdshow WazuhSvc"] {
            assert!(!is_tamper_command(c), "{c}");
        }
    }

    #[test]
    fn events_found() {
        let evs = vec![
            win("049", "1", "Microsoft-Windows-Sysmon", json!({ "commandLine": "sc stop WazuhSvc", "parentImage": "C:\\\\Windows\\\\System32\\\\cmd.exe", "user": "PC\\\\bob" })),
            // the Security log's copy of the same attempt: no second alert
            win("049", "4688", "Microsoft-Windows-Security-Auditing", json!({ "commandLine": "sc  stop WazuhSvc", "parentProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe", "subjectUserName": "bob" })),
            // the lock itself runs sc.exe: not an attempt
            win("049", "1", "Microsoft-Windows-Sysmon", json!({ "commandLine": "C:\\Windows\\System32\\sc.exe sdset WazuhSvc D:...", "parentImage": "C:\\Program Files (x86)\\ossec-agent\\active-response\\bin\\tamper-protect.exe" })),
            win("049", "7040", "Service Control Manager", json!({ "param1": "Wazuh", "param2": "auto start", "param3": "disabled" })),
            win("049", "7034", "Service Control Manager", json!({ "param1": "Wazuh", "param2": "1" })),
            win("049", "7034", "Service Control Manager", json!({ "param1": "Print Spooler" })),
            // as Wazuh sends it: backslashes doubled
            win("049", "13", "Microsoft-Windows-Sysmon", json!({ "targetObject": "HKLM\\\\System\\\\CurrentControlSet\\\\Services\\\\WazuhSvc\\\\Start", "image": "C:\\\\Windows\\\\regedit.exe" })),
            win("049", "13", "Microsoft-Windows-Sysmon", json!({ "targetObject": "HKLM\\System\\CurrentControlSet\\Services\\WazuhSvc\\Security", "image": "C:\\Windows\\system32\\services.exe" })),
            (json!({ "agent": { "id": "049" }, "full_log": "ossec: Agent started: 'pc->any'." }), "acm".into()),
            (json!({ "agent": { "id": "049" }, "full_log": "2026/10/30 10:00:00 active-response/bin/tamper-protect.exe: {\"message\":\"locked\",\"state\":\"locked\",\"window\":\"\",\"status\":\"success\",\"script\":\"tamper-protect\"}" }), "acm".into()),
        ];
        let f = check(&evs);
        let rules: Vec<u32> = f.alerts.iter().map(|(a, _)| a.rule.id).collect();
        assert_eq!(rules, vec![RULE_COMMAND, RULE_START_TYPE, RULE_KILLED, RULE_REGISTRY]);
        assert!(f.alerts[0].0.rule.description.ends_with("by PC\\bob"), "{}", f.alerts[0].0.rule.description);
        assert_eq!(f.started, vec![("acm".to_string(), "049".to_string())]);
        assert_eq!(f.results.len(), 1);
        assert_eq!(f.results[0].2["state"], "locked");
    }

    #[test]
    fn maintenance_window_ends() {
        let mut s = AgentState { state: "maintenance".into(), window_until: (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(), ..Default::default() };
        assert!(s.in_window());
        s.window_until = (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339();
        assert!(!s.in_window());
    }
}
