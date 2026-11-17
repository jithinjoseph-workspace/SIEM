//! Incidents (specs/alert-lifecycle.md, phase 3): related alerts become one case, so an analyst
//! works on dozens of incidents instead of thousands of alerts.
//!
//! Alerts of one tenant, one agent and one rule belong together; the incident lists the entities
//! involved (the process image when an alert names one, else the user, else the host), so one rule
//! hitting four processes is one incident, not four. An alert of level [`OPEN_LEVEL`] or more opens
//! an incident when none is open for its key; any alert of that key joins an open one while the
//! last alert is at most [`WINDOW_SECS`] old. An incident is an ordinary case (`soar_cases`,
//! number `INC-<year>-<n>`, tag `auto-incident`): its alerts in `hit_ids`, severity and priority
//! from its highest level. Changes are written every [`FLUSH_SECS`]; a write keeps what people
//! set (status, owner, ...), and a case someone closed takes no more alerts.
//!
//! Per rule (specs/alert-lifecycle.md section 6, step 1) a tenant can set how long its incident
//! takes alerts (`window_secs`), how many alerts it takes before a case opens (`open_after`), or
//! that it never opens one (`never`): [`Settings`], `siem_incident_settings`.
//!
//! Risk per computer (step 3, after Splunk's risk-based alerting): each alert adds risk to its
//! computer: points by level (1 / 10 / 25 / 50 for levels under 7 / 7-9 / 10-11 / 12+), raised by
//! its business risk; a rule counts once (its highest), so one noisy rule cannot make a computer
//! risky. A **risk incident** opens when a computer's risk in 24 h reaches the tenant's threshold
//! (default 100) or its alerts of level 7+ span the tenant's number of ATT&CK tactics in 7 days
//! (default 3). It does not take the per-rule cases' alerts: it links those cases (`linked:<id>`).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use serde_json::Value;
use siem_core::Alert;
use tracing::warn;

use crate::AppState;

/// An alert from this level opens an incident.
pub const OPEN_LEVEL: u8 = 7;
/// An incident takes alerts while its last one is at most this old.
pub const WINDOW_SECS: i64 = 3600;
/// Alert ids kept per incident (the count goes on).
pub const MAX_IDS: usize = 500;
const FLUSH_SECS: u64 = 15;
const TAG: &str = "auto-incident";
const RISK_TAG: &str = "risk-incident";
/// Risk counts over this long.
pub const RISK_WINDOW_SECS: i64 = 86_400;
/// ATT&CK tactics count over this long.
pub const TACTIC_WINDOW_SECS: i64 = 7 * 86_400;

pub const SETTINGS_DDL: &str = "CREATE TABLE IF NOT EXISTS siem_incident_settings (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id";

/// One rule's case settings.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RuleCfg {
    /// how long its incident takes alerts after the last one (300 s to 7 days; default 1 h)
    #[serde(default)]
    pub window_secs: Option<i64>,
    /// alerts in the window before a case opens (default 1)
    #[serde(default)]
    pub open_after: Option<u32>,
    /// its alerts never open a case (they stay in the alert queue)
    #[serde(default)]
    pub never: bool,
    #[serde(default)]
    pub updated_by: String,
}

/// A tenant's case settings.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    #[serde(default = "yes")]
    pub risk_enabled: bool,
    #[serde(default = "default_threshold")]
    pub risk_threshold: u32,
    #[serde(default = "default_tactics")]
    pub risk_tactics: u32,
    #[serde(default)]
    pub rules: BTreeMap<u32, RuleCfg>,
}

fn yes() -> bool {
    true
}
fn default_threshold() -> u32 {
    100
}
fn default_tactics() -> u32 {
    3
}

impl Default for Settings {
    fn default() -> Self {
        Settings { risk_enabled: true, risk_threshold: 100, risk_tactics: 3, rules: BTreeMap::new() }
    }
}

impl Settings {
    fn window(&self, rule: u32) -> i64 {
        self.rules.get(&rule).and_then(|r| r.window_secs).unwrap_or(WINDOW_SECS).clamp(300, 7 * 86_400)
    }
    fn open_after(&self, rule: u32) -> u64 {
        self.rules.get(&rule).and_then(|r| r.open_after).unwrap_or(1).clamp(1, 10_000) as u64
    }
    fn never(&self, rule: u32) -> bool {
        self.rules.get(&rule).is_some_and(|r| r.never)
    }
}

fn settings_cache() -> &'static RwLock<HashMap<String, Settings>> {
    static S: std::sync::OnceLock<RwLock<HashMap<String, Settings>>> = std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

/// The tenant's settings (the defaults when none were saved).
pub fn settings_of(tenant: &str) -> Settings {
    settings_cache().read().unwrap().get(tenant).cloned().unwrap_or_default()
}

/// Risk points of one alert: by level, raised by its business risk (0-100: up to double).
pub fn risk_points(level: u8, business_risk: u8) -> u32 {
    let base: u32 = match level {
        12.. => 50,
        10..=11 => 25,
        7..=9 => 10,
        _ => 1,
    };
    base * (100 + business_risk.min(100) as u32) / 100
}

/// What one computer's alerts add up to.
#[derive(Debug, Default, Clone)]
pub struct Risk {
    /// rule -> (points, description, last time, newest alert id, its case id, level)
    pub rules: HashMap<u32, (u32, String, i64, String, String, u8)>,
    /// ATT&CK tactic -> last time (alerts of level 7+)
    pub tactics: HashMap<String, i64>,
}

impl Risk {
    fn prune(&mut self, now: i64) {
        self.rules.retain(|_, r| now - r.2 <= RISK_WINDOW_SECS);
        self.tactics.retain(|_, t| now - *t <= TACTIC_WINDOW_SECS);
    }
    pub fn score(&self) -> u32 {
        self.rules.values().map(|r| r.0).sum()
    }
}

fn risks() -> &'static Mutex<HashMap<String, Risk>> {
    static R: std::sync::OnceLock<Mutex<HashMap<String, Risk>>> = std::sync::OnceLock::new();
    R.get_or_init(Default::default)
}

/// The key of a computer's risk incident.
pub fn risk_key(tenant: &str, agent_id: &str) -> String {
    format!("risk:{tenant}|{agent_id}")
}
const CLOSED: &str = "('Closed', 'Resolved', 'False Positive')";

/// The text at a dot path of the alert, if any.
fn at<'a>(v: &'a Value, path: &str) -> Option<&'a str> {
    path.split('.').try_fold(v, |v, k| v.get(k))?.as_str().map(str::trim).filter(|s| !s.is_empty() && *s != "-")
}

/// What the alert is about on its host: `process:<image file>`, `user:<name>` or `host`.
pub fn entity(a: &Value) -> String {
    entity_at(a).0
}

/// The entity and the alert field it came from (an exception for the incident matches on it).
pub fn entity_at(a: &Value) -> (String, Option<&'static str>) {
    let image = ["data.win.eventdata.image", "data.win.eventdata.sourceImage", "data.win.eventdata.newProcessName"].into_iter().find_map(|p| at(a, p).map(|v| (p, v)));
    if let Some((p, i)) = image {
        let file = i.rsplit(['\\', '/']).next().unwrap_or(i).to_lowercase();
        if !file.is_empty() && file != "<unknown process>" && file != "&lt;unknown process&gt;" {
            return (format!("process:{file}"), Some(p));
        }
    }
    let user = ["decoded.user", "data.dstuser", "data.srcuser", "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName"].into_iter().find_map(|p| at(a, p).map(|v| (p, v)));
    match user {
        Some((p, u)) => (format!("user:{}", u.to_lowercase()), Some(p)),
        None => ("host".into(), None),
    }
}

/// The group an alert belongs to: tenant, agent and rule.
pub fn key(tenant: &str, agent_id: &str, rule_id: u32) -> String {
    format!("{tenant}|{agent_id}|rule:{rule_id}")
}

/// Entities listed per incident.
const MAX_ENTITIES: usize = 20;

pub fn severity(level: u8) -> &'static str {
    match level {
        12.. => "CRITICAL",
        10..=11 => "HIGH",
        7..=9 => "MEDIUM",
        _ => "LOW",
    }
}

/// The risk fabric's business risk (0-100) as a severity, by its own tiers: 70+ Critical or
/// Catastrophic, 45+ High, 25+ Medium.
pub fn risk_severity(risk: u8) -> &'static str {
    match risk {
        70.. => "CRITICAL",
        45..=69 => "HIGH",
        25..=44 => "MEDIUM",
        _ => "LOW",
    }
}

fn rank(severity: &str) -> u8 {
    match severity {
        "CRITICAL" => 3,
        "HIGH" => 2,
        "MEDIUM" => 1,
        _ => 0,
    }
}

/// An incident's severity: the higher of its level's and its business risk's (phase 4), so the
/// same alert ranks higher on a payment server than on a test PC.
pub fn severity_of(level: u8, risk: u8) -> &'static str {
    let (a, b) = (severity(level), risk_severity(risk));
    if rank(b) > rank(a) { b } else { a }
}

fn priority(severity: &str) -> &'static str {
    match severity {
        "CRITICAL" => "P1",
        "HIGH" => "P2",
        "MEDIUM" => "P3",
        _ => "P4",
    }
}

/// One open incident.
#[derive(Debug, Clone, Default)]
pub struct Open {
    pub id: String,
    pub tenant: String,
    pub agent_name: String,
    pub agent_ip: String,
    pub src_ip: String,
    /// the processes or users involved, each with the alert field it came from
    pub entities: Vec<(String, Option<String>)>,
    pub first_rule: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub max_level: u8,
    /// the highest business risk of its alerts (risk fabric, 0-100)
    pub max_risk: u8,
    pub count: u64,
    pub ids: Vec<String>,
    /// rule descriptions, first ones only
    pub rules: Vec<String>,
    /// how long it takes alerts after the last one
    pub window: i64,
    /// a case (else alerts gathered until `open_after` is reached)
    pub opened: bool,
    /// a risk incident's own title, description and tags
    pub custom: Option<(String, String, Vec<String>)>,
    /// not stored yet
    pub new: bool,
    pub dirty: bool,
}

impl Open {
    fn take(&mut self, a: &Alert, ts: i64, (entity, field): (String, Option<&'static str>)) {
        if entity != "host" && self.entities.len() < MAX_ENTITIES && !self.entities.iter().any(|(e, _)| *e == entity) {
            self.entities.push((entity, field.map(String::from)));
        }
        self.last_seen = self.last_seen.max(ts);
        self.max_level = self.max_level.max(a.rule.level);
        let risk = a.data.get("risk_fabric").and_then(|r| r["dynamic_risk_score"].as_u64()).unwrap_or(0).min(100) as u8;
        self.max_risk = self.max_risk.max(risk);
        self.count += 1;
        if self.ids.len() < MAX_IDS {
            self.ids.push(a.id.to_string());
        }
        if self.rules.len() < 10 && !self.rules.contains(&a.rule.description) {
            self.rules.push(a.rule.description.clone());
        }
        if self.src_ip.is_empty() {
            self.src_ip = a.decoded.src_ip.clone().unwrap_or_default();
        }
        self.dirty = true;
    }

    pub fn title(&self) -> String {
        if let Some((t, _, _)) = &self.custom {
            return t.clone();
        }
        let what = match self.entities.as_slice() {
            [] => String::new(),
            [(e, _)] => e.split_once(':').map_or(String::new(), |(k, v)| format!(" ({k} {v})")),
            many => format!(" ({} processes or users)", many.len()),
        };
        format!("{}{}: {}", self.agent_name, what, self.first_rule)
    }

    /// The case's tags: the marker, the key, each entity, and the field of a single entity (an
    /// exception for the incident can then name it; with several it covers the rule on the agent).
    pub fn tags(&self, key: &str) -> Vec<String> {
        if let Some((_, _, tags)) = &self.custom {
            let mut t = vec![RISK_TAG.to_string(), format!("key:{key}")];
            t.extend(tags.iter().cloned());
            return t;
        }
        let mut t = vec![TAG.to_string(), format!("key:{key}")];
        t.extend(self.entities.iter().map(|(e, _)| e.clone()));
        if let [(_, Some(f))] = self.entities.as_slice() {
            t.push(format!("field:{f}"));
        }
        t
    }

    pub fn description(&self) -> String {
        if let Some((_, d, _)) = &self.custom {
            return d.clone();
        }
        format!(
            "Incident opened automatically: {} alert(s) on {} between {} and {} UTC, highest level {}, business risk {}. Rules: {}.",
            self.count,
            self.agent_name,
            chrono::DateTime::from_timestamp(self.first_seen, 0).map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default(),
            chrono::DateTime::from_timestamp(self.last_seen, 0).map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default(),
            self.max_level,
            self.max_risk,
            self.rules.join("; ")
        )
    }
}

/// Puts one alert into the open incidents: joins one, opens one, or neither (`None`).
pub fn place(open: &mut HashMap<String, Open>, tenant: &str, a: &Alert, ent: (String, Option<&'static str>), ts: i64, cfg: &Settings) -> Option<String> {
    if cfg.never(a.rule.id) {
        return None;
    }
    let k = key(tenant, &a.agent.id, a.rule.id);
    let open_after = cfg.open_after(a.rule.id);
    if let Some(o) = open.get_mut(&k) {
        if ts - o.last_seen <= o.window {
            // a low alert joins a case, but does not count towards opening one
            if !o.opened && a.rule.level < OPEN_LEVEL {
                return None;
            }
            o.take(a, ts, ent);
            if !o.opened && o.count >= open_after {
                o.opened = true;
                o.new = true;
            }
            return o.opened.then_some(k);
        }
        // too old: a new alert of level OPEN_LEVEL starts a new incident below
        open.remove(&k);
    }
    if a.rule.level < OPEN_LEVEL {
        return None;
    }
    let mut o = Open {
        id: uuid::Uuid::new_v4().to_string(),
        tenant: tenant.into(),
        agent_name: a.agent.name.clone(),
        agent_ip: a.agent.ip.clone(),
        first_rule: a.rule.description.clone(),
        first_seen: ts,
        last_seen: ts,
        window: cfg.window(a.rule.id),
        ..Open::default()
    };
    o.take(a, ts, ent);
    o.opened = o.count >= open_after;
    o.new = o.opened;
    let opened = o.opened;
    open.insert(k.clone(), o);
    opened.then_some(k)
}

/// Adds an alert to its computer's risk and opens or updates the computer's risk incident
/// (`case_id`: the alert's per-rule case, when it has one).
pub fn add_risk(open: &mut HashMap<String, Open>, risk: &mut Risk, tenant: &str, a: &Alert, ts: i64, case_id: &str, cfg: &Settings) {
    if !cfg.risk_enabled {
        return;
    }
    risk.prune(ts);
    let business = a.data.get("risk_fabric").and_then(|r| r["dynamic_risk_score"].as_u64()).unwrap_or(0).min(100) as u8;
    let pts = risk_points(a.rule.level, business);
    let e = risk.rules.entry(a.rule.id).or_insert((0, a.rule.description.clone(), ts, String::new(), String::new(), 0));
    e.0 = e.0.max(pts);
    e.2 = ts;
    e.3 = a.id.to_string();
    if !case_id.is_empty() {
        e.4 = case_id.to_string();
    }
    e.5 = e.5.max(a.rule.level);
    if a.rule.level >= OPEN_LEVEL {
        for t in a.rule.mitre.iter().flat_map(|m| m.tactic.split(',')).map(str::trim).filter(|t| !t.is_empty()) {
            risk.tactics.insert(t.to_string(), ts);
        }
    }
    let k = risk_key(tenant, &a.agent.id);
    let (score, tactics) = (risk.score(), risk.tactics.len());
    let reached = score >= cfg.risk_threshold || tactics as u32 >= cfg.risk_tactics;
    if !reached && !open.contains_key(&k) {
        return;
    }
    let mut rules: Vec<(&u32, &(u32, String, i64, String, String, u8))> = risk.rules.iter().collect();
    rules.sort_by(|x, y| y.1 .0.cmp(&x.1 .0).then(x.0.cmp(y.0)));
    let mut tactic_names: Vec<&String> = risk.tactics.keys().collect();
    tactic_names.sort();
    let title = format!("{}: risk {score} in 24 h ({} rule{}, {tactics} ATT&CK tactic{})", a.agent.name, rules.len(), if rules.len() == 1 { "" } else { "s" }, if tactics == 1 { "" } else { "s" });
    let description = format!(
        "Risk incident opened automatically: {} reached risk {score} (threshold {}) and {tactics} ATT&CK tactic(s) (threshold {}): {}. Each rule counts once, at its highest. Rules: {}. The rules' own cases are linked; their alerts stay there.",
        a.agent.name,
        cfg.risk_threshold,
        cfg.risk_tactics,
        tactic_names.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(", "),
        rules.iter().map(|(id, r)| format!("{} (rule {id}, level {}, {} points)", r.1, r.5, r.0)).collect::<Vec<_>>().join("; ")
    );
    let mut tags: Vec<String> = rules.iter().filter(|(_, r)| !r.4.is_empty()).map(|(_, r)| format!("linked:{}", r.4)).collect();
    tags.sort();
    tags.dedup();
    let ids: Vec<String> = rules.iter().map(|(_, r)| r.3.clone()).take(MAX_IDS).collect();
    let max_level = rules.iter().map(|(_, r)| r.5).max().unwrap_or(0);
    let o = open.entry(k).or_insert_with(|| Open {
        id: uuid::Uuid::new_v4().to_string(),
        tenant: tenant.into(),
        agent_name: a.agent.name.clone(),
        agent_ip: a.agent.ip.clone(),
        first_seen: ts,
        window: RISK_WINDOW_SECS,
        opened: true,
        new: true,
        ..Open::default()
    });
    o.custom = Some((title, description, tags));
    o.last_seen = ts;
    o.max_level = o.max_level.max(max_level);
    o.max_risk = o.max_risk.max(business);
    o.count = risk.rules.len() as u64;
    o.ids = ids;
    o.dirty = true;
}

fn open() -> &'static Mutex<HashMap<String, Open>> {
    static O: std::sync::OnceLock<Mutex<HashMap<String, Open>>> = std::sync::OnceLock::new();
    O.get_or_init(Default::default)
}

/// The shown alerts of `deliver`, after suppression.
pub fn on_alerts(state: &AppState, alerts: &[Alert]) {
    let tenants = state.agent_tenants.read().unwrap().clone();
    let mut map = open().lock().unwrap();
    for a in alerts {
        // a configuration check that changed is a compliance finding (Compliance page), not an incident
        if crate::is_simulation(a) || a.rule.groups.iter().any(|g| g == "sca") {
            continue;
        }
        let tenant = crate::tenancy::alert_tenant(a, &tenants);
        let cfg = settings_of(&tenant);
        let v = serde_json::to_value(a).unwrap_or_default();
        let ts = a.timestamp.timestamp();
        let case = place(&mut map, &tenant, a, entity_at(&v), ts, &cfg).and_then(|k| map.get(&k).map(|o| o.id.clone())).unwrap_or_default();
        let mut r = risks().lock().unwrap();
        let risk = r.entry(format!("{tenant}|{}", a.agent.id)).or_default();
        add_risk(&mut map, risk, &tenant, a, ts, &case, &cfg);
    }
}

/// Loads the open incidents of every tenant (after a restart), then writes changes every
/// [`FLUSH_SECS`].
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        if state.db.is_connected() {
            for t in crate::predictions::tenant_ids(&state) {
                load_settings(&state, &t).await;
                load(&state, &t).await;
            }
        }
        loop {
            tokio::time::sleep(Duration::from_secs(FLUSH_SECS)).await;
            if state.db.is_connected() {
                flush(&state).await;
            }
        }
    });
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct OpenRow {
    id: String,
    title: String,
    tags: Vec<String>,
    hit_ids: Vec<String>,
    updated: u32,
}

async fn load(state: &AppState, tenant: &str) {
    let sql = format!("SELECT id, title, tags, hit_ids, toUInt32(toUnixTimestamp(updated_at)) AS updated FROM soar_cases FINAL WHERE (has(tags, ?) OR has(tags, ?)) AND status NOT IN {CLOSED} AND updated_at >= now() - INTERVAL 1 DAY");
    let rows: Vec<OpenRow> = state.db.tenant_client(tenant).query(&sql).bind(TAG).bind(RISK_TAG).fetch_all().await.unwrap_or_default();
    let cfg = settings_of(tenant);
    let mut map = open().lock().unwrap();
    for r in rows {
        let Some(k) = r.tags.iter().find_map(|t| t.strip_prefix("key:")) else { continue };
        // an incident of the earlier per-process grouping is not continued (another key)
        let risk = k.starts_with("risk:");
        if !k.contains("|rule:") && !risk {
            continue;
        }
        let window = if risk { RISK_WINDOW_SECS } else { k.rsplit("rule:").next().and_then(|r| r.parse().ok()).map_or(WINDOW_SECS, |r| cfg.window(r)) };
        // a per-rule incident older than its window is done
        if !risk && chrono::Utc::now().timestamp() - r.updated as i64 > window {
            continue;
        }
        let field = r.tags.iter().find_map(|t| t.strip_prefix("field:")).map(String::from);
        let entities: Vec<(String, Option<String>)> = r.tags.iter().filter(|t| t.starts_with("process:") || t.starts_with("user:")).map(|t| (t.clone(), field.clone())).collect();
        map.entry(k.to_string()).or_insert(Open {
            id: r.id,
            tenant: tenant.into(),
            agent_name: r.title.split(':').next().unwrap_or("").split(" (").next().unwrap_or("").into(),
            entities,
            first_rule: r.title.splitn(2, ": ").nth(1).unwrap_or("").into(),
            first_seen: r.updated as i64,
            last_seen: r.updated as i64,
            count: r.hit_ids.len() as u64,
            ids: r.hit_ids,
            window,
            opened: true,
            // until its computer's next alert recomputes it
            custom: risk.then(|| (r.title.clone(), String::new(), r.tags.iter().filter(|t| t.starts_with("linked:")).cloned().collect())),
            ..Open::default()
        });
    }
}

async fn load_settings(state: &AppState, tenant: &str) {
    let doc: Option<String> = state.db.tenant_client(tenant).query("SELECT doc FROM siem_incident_settings FINAL WHERE id = 'settings'").fetch_optional().await.ok().flatten();
    if let Some(s) = doc.and_then(|d| serde_json::from_str::<Settings>(&d).ok()) {
        settings_cache().write().unwrap().insert(tenant.to_string(), s);
    }
}

/// `GET /api/v1/siem/incidents/settings`: the tenant's case settings and their defaults.
pub async fn get_settings(axum::Extension(ctx): axum::Extension<crate::tenancy::AuthCtx>) -> axum::Json<Value> {
    axum::Json(serde_json::json!({ "status": "ok", "settings": settings_of(&ctx.scope()), "defaults": { "window_secs": WINDOW_SECS, "open_level": OPEN_LEVEL, "risk_window_secs": RISK_WINDOW_SECS }, "can_edit": ctx.can_manage(&ctx.scope()) }))
}

/// `PUT /api/v1/siem/incidents/settings` (tenant admin): the whole settings, checked.
pub async fn put_settings(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::Extension(ctx): axum::Extension<crate::tenancy::AuthCtx>,
    axum::Json(mut s): axum::Json<Settings>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let t = ctx.scope();
    if !ctx.can_manage(&t) {
        return crate::tenancy::forbidden();
    }
    let bad = |m: &str| (axum::http::StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({ "status": "error", "message": m }))).into_response();
    if !(10..=10_000).contains(&s.risk_threshold) || !(2..=14).contains(&s.risk_tactics) {
        return bad("Risk threshold 10 to 10000, tactics 2 to 14");
    }
    if s.rules.len() > 2000 {
        return bad("At most 2000 rule settings");
    }
    for r in s.rules.values_mut() {
        if r.window_secs.is_some_and(|w| !(300..=7 * 86_400).contains(&w)) || r.open_after.is_some_and(|n| !(1..=10_000).contains(&n)) {
            return bad("A rule's window is 5 minutes to 7 days, and it opens a case after 1 to 10000 alerts");
        }
        r.updated_by = ctx.username.clone();
    }
    // a rule left with nothing set is no setting
    s.rules.retain(|_, r| r.window_secs.is_some() || r.open_after.is_some() || r.never);
    let doc = serde_json::to_string(&s).unwrap_or_default();
    let version = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let r = state.db.tenant_client(&t).query("INSERT INTO siem_incident_settings (id, doc, version) VALUES ('settings', ?, ?)").bind(doc).bind(version).execute().await;
    if let Err(e) = r {
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({ "status": "error", "message": format!("Not saved: {e}") }))).into_response();
    }
    settings_cache().write().unwrap().insert(t, s.clone());
    axum::Json(serde_json::json!({ "status": "ok", "settings": s })).into_response()
}

async fn flush(state: &AppState) {
    let now = chrono::Utc::now().timestamp();
    let work: Vec<(String, Open)> = {
        let mut map = open().lock().unwrap();
        // incidents past their window are done: forgotten once written
        map.retain(|_, o| o.dirty || now - o.last_seen <= o.window.max(300));
        // alerts still counting towards a case are not written
        map.iter_mut().filter(|(_, o)| o.dirty && o.opened).map(|(k, o)| {
            o.dirty = false;
            (k.clone(), o.clone())
        }).collect()
    };
    for (k, o) in work {
        let client = state.db.tenant_client(&o.tenant);
        let sev = severity_of(o.max_level, o.max_risk);
        let result = if o.new {
            let number = crate::soar::next_case_number(state, &o.tenant).await;
            let tags = o.tags(&k);
            // soar_cases replaces rows by (tenant, created_at in seconds): two cases of one second
            // would become one, so each incident takes a second after the newest case
            let newest: u32 = client.query("SELECT toUInt32(toUnixTimestamp(max(created_at))) FROM soar_cases").fetch_one().await.unwrap_or(0);
            let created = unique_second(now, newest as i64);
            client
                .query("INSERT INTO soar_cases (id, case_number, title, description, severity, priority, status, assigned_to, src_ip, dst_ip, community_id, hit_ids, tags, tenant_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'New', '', ?, ?, '', ?, ?, ?, toDateTime(?), toDateTime(?))")
                .bind(&o.id).bind(&number).bind(o.title()).bind(o.description()).bind(sev).bind(priority(sev))
                .bind(&o.src_ip).bind(&o.agent_ip).bind(&o.ids).bind(&tags).bind(&o.tenant).bind(created).bind(created)
                .execute()
                .await
                .map(|_| true)
        } else {
            // still open? a closed case takes no more alerts
            let status: Option<String> = client.query("SELECT status FROM soar_cases FINAL WHERE id = ?").bind(&o.id).fetch_optional().await.ok().flatten();
            if status.as_deref().is_none_or(|s| ["Closed", "Resolved", "False Positive"].contains(&s)) {
                open().lock().unwrap().remove(&k);
                // a closed risk incident: the computer's risk starts again from nothing
                if let Some(rk) = k.strip_prefix("risk:") {
                    risks().lock().unwrap().remove(rk);
                }
                continue;
            }
            // what people set stays; only the alerts, the title and text (the entities grow), the
            // tags and the severity move on
            let sql = format!(
                "INSERT INTO soar_cases ({}) SELECT id, case_number, ? AS title, ? AS description, ? AS severity, priority, status, assigned_to, src_ip, dst_ip, community_id, ? AS hit_ids, ? AS tags, tenant_id, created_at, now() AS updated_at, closed_at FROM soar_cases FINAL WHERE id = ? AND status NOT IN {CLOSED}",
                "id, case_number, title, description, severity, priority, status, assigned_to, src_ip, dst_ip, community_id, hit_ids, tags, tenant_id, created_at, updated_at, closed_at"
            );
            client.query(&sql).bind(o.title()).bind(o.description()).bind(sev).bind(&o.ids).bind(o.tags(&k)).bind(&o.id).execute().await.map(|_| false)
        };
        match result {
            Ok(created) => {
                if created {
                    if let Some(x) = open().lock().unwrap().get_mut(&k) {
                        x.new = false;
                    }
                    // like every new case: its history starts, and it is triaged (evidence and a
                    // verdict by rules and, when the tenant has one, its AI; recommend only)
                    crate::case_detail::created(state, &o.tenant, &o.id, "ProVigil").await;
                    crate::case_ai::spawn_for_new_case(state.clone(), o.tenant.clone(), o.id.clone());
                }
            }
            Err(e) => {
                warn!("incident {} of tenant {} not written: {e}", o.id, o.tenant);
                if let Some(x) = open().lock().unwrap().get_mut(&k) {
                    x.dirty = true;
                }
            }
        }
    }
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct CaseOf {
    id: String,
    case_number: String,
    status: String,
    hit_ids: Vec<String>,
}

/// Each alert's case, as `data.incident` = `{id, number, status}`: an alert's state is its case's.
pub async fn attach(state: &AppState, tenant: &str, alerts: &mut [Alert]) {
    if alerts.is_empty() || !state.db.is_connected() {
        return;
    }
    let ids: Vec<String> = alerts.iter().map(|a| a.id.to_string()).collect();
    let cases: Vec<CaseOf> = state
        .db
        .tenant_client(tenant)
        .query("SELECT id, case_number, status, hit_ids FROM soar_cases FINAL WHERE hasAny(hit_ids, ?)")
        .bind(&ids)
        .fetch_all()
        .await
        .unwrap_or_default();
    if cases.is_empty() {
        return;
    }
    let mut of: HashMap<&str, &CaseOf> = HashMap::new();
    for c in &cases {
        for h in &c.hit_ids {
            of.insert(h.as_str(), c);
        }
    }
    for a in alerts.iter_mut() {
        if let Some(c) = of.get(a.id.to_string().as_str()) {
            a.data.insert("incident".into(), serde_json::json!({ "id": c.id, "number": c.case_number, "status": c.status }));
        }
    }
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct Totals {
    cases: u64,
    open: u64,
    auto_incidents: u64,
    risk_incidents: u64,
    mttr: f64,
}

#[derive(clickhouse::Row, serde::Deserialize, serde::Serialize)]
struct RuleOutcome {
    rule_id: u32,
    rule: String,
    incidents: u64,
    false_positive: u64,
}

#[derive(serde::Deserialize)]
pub struct MetricsQuery {
    days: Option<u32>,
}

/// `GET /api/v1/siem/incidents/metrics?days=30` (phase 6): the tenant's cases over the last days
/// (1 to 90): how many, how many open or opened automatically, the mean time to the first action
/// (status, edit, note, disposition) and to closing, and per rule how many incidents ended as false
/// positives (the Resolve disposition or the False Positive status), most first: the rules worth tuning.
pub async fn metrics(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::Extension(ctx): axum::Extension<crate::tenancy::AuthCtx>,
    axum::extract::Query(q): axum::extract::Query<MetricsQuery>,
) -> axum::Json<Value> {
    let days = q.days.unwrap_or(30).clamp(1, 90);
    let db = state.db.tenant_client(&ctx.scope());
    let totals: Option<Totals> = db
        .query(&format!("SELECT toUInt64(count()) AS cases, toUInt64(countIf(status NOT IN {CLOSED})) AS open, toUInt64(countIf(has(tags, 'auto-incident'))) AS auto_incidents, toUInt64(countIf(has(tags, 'risk-incident'))) AS risk_incidents, toFloat64(ifNotFinite(ifNull(avgIf(dateDiff('second', created_at, closed_at), closed_at IS NOT NULL), 0), 0)) AS mttr FROM soar_cases FINAL WHERE created_at >= now() - INTERVAL ? DAY"))
        .bind(days)
        .fetch_optional()
        .await
        .ok()
        .flatten();
    let mtta: f64 = db
        .query("SELECT toFloat64(ifNotFinite(avg(first_s), 0)) FROM (SELECT c.id, dateDiff('second', any(c.created_at), min(e.at)) AS first_s FROM soar_cases AS c FINAL INNER JOIN soar_case_events AS e ON e.case_id = c.id WHERE c.created_at >= now() - INTERVAL ? DAY AND e.kind IN ('status', 'edited', 'note', 'disposition', 'resolved') GROUP BY c.id)")
        .bind(days)
        .fetch_one()
        .await
        .unwrap_or(0.0);
    let rules: Vec<RuleOutcome> = db
        .query("WITH c AS (SELECT id, hit_ids, status FROM soar_cases FINAL WHERE created_at >= now() - INTERVAL ? DAY AND notEmpty(hit_ids)), d AS (SELECT case_id, JSONExtractString(doc, 'disposition') AS disp FROM soar_case_details FINAL), a AS (SELECT id, rule_id, rule_description FROM siem_alerts WHERE id IN (SELECT arrayJoin(hit_ids) FROM c)) SELECT a.rule_id AS rule_id, any(a.rule_description) AS rule, toUInt64(uniqExact(c.id)) AS incidents, toUInt64(uniqExactIf(c.id, d.disp = 'False Positive' OR c.status = 'False Positive')) AS false_positive FROM c ARRAY JOIN c.hit_ids AS hid INNER JOIN a ON a.id = hid LEFT JOIN d ON d.case_id = c.id GROUP BY a.rule_id ORDER BY false_positive DESC, incidents DESC LIMIT 20")
        .bind(days)
        .fetch_all()
        .await
        .unwrap_or_default();
    let t = totals.unwrap_or(Totals { cases: 0, open: 0, auto_incidents: 0, risk_incidents: 0, mttr: 0.0 });
    axum::Json(serde_json::json!({
        "days": days, "cases": t.cases, "open": t.open, "auto_incidents": t.auto_incidents, "risk_incidents": t.risk_incidents,
        "mean_secs_to_first_action": mtta.round() as u64, "mean_secs_to_close": t.mttr.round() as u64,
        "rules": rules.iter().map(|r| serde_json::json!({
            "rule_id": r.rule_id, "rule": r.rule, "incidents": r.incidents, "false_positive": r.false_positive,
            "false_positive_rate": if r.incidents == 0 { 0.0 } else { (r.false_positive as f64 / r.incidents as f64 * 100.0).round() / 100.0 },
        })).collect::<Vec<_>>(),
    }))
}

/// A creation second later than the newest case's (cases of one second would merge).
pub fn unique_second(now: i64, newest: i64) -> i64 {
    now.max(newest + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn alert(level: u8, agent: &str, rule: &str) -> Alert {
        let mut a: Alert = serde_json::from_value(json!({
            "id": uuid::Uuid::new_v4(), "timestamp": "2026-11-16T10:00:00Z",
            "rule": {"id": 1, "level": level, "description": rule, "groups": []},
            "agent": {"id": agent, "name": format!("pc-{agent}"), "ip": "10.0.0.5"},
            "full_log": "", "location": "EventChannel", "decoded": {"decoder_name": "", "extra": {}}, "data": {}
        }))
        .unwrap();
        a.rule.level = level;
        a
    }

    #[test]
    fn severity_is_the_higher_of_level_and_business_risk() {
        assert_eq!(severity_of(7, 10), "MEDIUM");
        assert_eq!(severity_of(7, 88), "CRITICAL", "a payment server");
        assert_eq!(severity_of(12, 0), "CRITICAL");
        assert_eq!(severity_of(4, 50), "HIGH", "low level, high business risk");
        let mut m = HashMap::new();
        let mut a = alert(8, "8084", "Suspicious process");
        a.data.insert("risk_fabric".into(), json!({"dynamic_risk_score": 72}));
        let k = place(&mut m, "acm", &a, ("process:x.exe".into(), None), 0, &Settings::default()).unwrap();
        assert_eq!((m[&k].max_risk, severity_of(m[&k].max_level, m[&k].max_risk)), (72, "CRITICAL"));
    }

    #[test]
    fn each_new_case_gets_its_own_second() {
        assert_eq!(unique_second(100, 50), 100);
        assert_eq!(unique_second(100, 100), 101, "a case already in this second");
        assert_eq!(unique_second(100, 104), 105, "a burst ahead of the clock keeps counting");
    }

    #[test]
    fn entity_is_the_process_then_the_user_then_the_host() {
        assert_eq!(entity(&json!({"data": {"win": {"eventdata": {"image": r"C:\Program Files\Docker\docker.exe", "targetUserName": "bob"}}}})), "process:docker.exe");
        assert_eq!(entity(&json!({"data": {"win": {"eventdata": {"image": "<unknown process>", "targetUserName": "Bob"}}}})), "user:bob");
        assert_eq!(entity(&json!({"data": {}})), "host");
        assert_eq!(entity_at(&json!({"data": {"dstuser": "alice"}})), ("user:alice".to_string(), Some("data.dstuser")), "the field it came from");
    }

    fn alert_r(level: u8, agent: &str, rule: u32, desc: &str) -> Alert {
        let mut a = alert(level, agent, desc);
        a.rule.id = rule;
        a
    }

    #[test]
    fn alerts_group_by_agent_and_rule_within_the_window() {
        let mut m = HashMap::new();
        let t0 = 1_800_000_000;
        let p = |e: &str| (e.to_string(), Some("data.win.eventdata.image"));
        assert_eq!(place(&mut m, "acm", &alert_r(4, "8084", 92153, "VaultCli"), p("process:svchost.exe"), t0, &Settings::default()), None, "a low alert opens nothing");
        let k = place(&mut m, "acm", &alert_r(10, "8084", 92153, "VaultCli"), p("process:winword.exe"), t0, &Settings::default()).unwrap();
        assert_eq!(m[&k].tags(&k).last().map(String::as_str), Some("field:data.win.eventdata.image"), "one process: its field is named");
        // the same rule on other processes joins the same incident (it opened 4 before)
        for proc_ in ["process:svchost.exe", "process:backgroundtaskhost.exe", "process:winword.exe"] {
            assert_eq!(place(&mut m, "acm", &alert_r(10, "8084", 92153, "VaultCli"), p(proc_), t0 + 60, &Settings::default()), Some(k.clone()));
        }
        assert_eq!(place(&mut m, "acm", &alert_r(3, "8084", 92153, "VaultCli"), p("process:svchost.exe"), t0 + 600, &Settings::default()), Some(k.clone()), "a low alert joins an open incident");
        assert_ne!(place(&mut m, "acm", &alert_r(10, "8084", 92078, "Cmd"), p("process:winword.exe"), t0, &Settings::default()).unwrap(), k, "another rule: another incident");
        assert_ne!(place(&mut m, "acm", &alert_r(10, "8087", 92153, "VaultCli"), p("process:winword.exe"), t0, &Settings::default()).unwrap(), k, "another agent: another incident");
        let o = &m[&k];
        assert_eq!((o.count, o.entities.len(), severity(o.max_level)), (5, 3, "HIGH"));
        assert_eq!(o.title(), "pc-8084 (3 processes or users): VaultCli");
        assert!(!o.tags(&k).iter().any(|t| t.starts_with("field:")), "several processes: no single field");
        // past the window: a new incident
        let id = m[&k].id.clone();
        place(&mut m, "acm", &alert_r(8, "8084", 92153, "VaultCli"), p("process:svchost.exe"), t0 + 600 + WINDOW_SECS + 1, &Settings::default());
        assert_ne!(m[&k].id, id);
        assert_eq!(m[&k].title(), "pc-8084 (process svchost.exe): VaultCli");
    }

    #[test]
    fn per_rule_settings_never_open_after_and_window() {
        let mut cfg = Settings::default();
        cfg.rules.insert(960270, RuleCfg { never: true, ..Default::default() });
        cfg.rules.insert(92032, RuleCfg { open_after: Some(3), window_secs: Some(600), ..Default::default() });
        let mut m = HashMap::new();
        let t0 = 1_800_000_000;
        let e = || ("host".to_string(), None);
        assert_eq!(place(&mut m, "acm", &alert_r(12, "1", 960270, "Raw disk"), e(), t0, &cfg), None, "never: not even level 12");
        assert_eq!(place(&mut m, "acm", &alert_r(7, "1", 92032, "cmd"), e(), t0, &cfg), None, "1 of 3");
        assert_eq!(place(&mut m, "acm", &alert_r(7, "1", 92032, "cmd"), e(), t0 + 60, &cfg), None, "2 of 3");
        let k = place(&mut m, "acm", &alert_r(7, "1", 92032, "cmd"), e(), t0 + 120, &cfg).unwrap();
        assert_eq!((m[&k].count, m[&k].new, m[&k].window), (3, true, 600), "the third opens it, with all three");
        // past its own 10-minute window: counting starts again
        assert_eq!(place(&mut m, "acm", &alert_r(7, "1", 92032, "cmd"), e(), t0 + 120 + 601, &cfg), None);
    }

    #[test]
    fn risk_incident_links_the_rule_cases_once_the_computer_is_risky() {
        let cfg = Settings::default();
        let mut m = HashMap::new();
        let mut risk = Risk::default();
        let t0 = 1_800_000_000;
        let rk = risk_key("acm", "8084");
        // one noisy rule many times: counts once
        for i in 0..50 {
            add_risk(&mut m, &mut risk, "acm", &alert_r(10, "8084", 92153, "VaultCli"), t0 + i, "case-a", &cfg);
        }
        assert_eq!(risk.score(), 25);
        assert!(!m.contains_key(&rk));
        // more rules on the same computer: 25 + 50 + 25 = 100 reaches the threshold
        add_risk(&mut m, &mut risk, "acm", &alert_r(12, "8084", 92213, "Executable dropped"), t0 + 60, "case-b", &cfg);
        assert!(!m.contains_key(&rk));
        add_risk(&mut m, &mut risk, "acm", &alert_r(10, "8084", 92041, "Base64 registry"), t0 + 70, "", &cfg);
        let o = &m[&rk];
        assert!(o.new && o.opened);
        assert_eq!(o.title(), "pc-8084: risk 100 in 24 h (3 rules, 0 ATT&CK tactics)");
        let tags = o.tags(&rk);
        assert!(tags.contains(&"risk-incident".to_string()) && tags.contains(&"linked:case-a".to_string()) && tags.contains(&"linked:case-b".to_string()), "{tags:?}");
        assert_eq!(o.ids.len(), 3, "one alert per rule, the rules' cases keep theirs");
        // three tactics at level 7+ open one on their own, on another computer
        let mut r2 = Risk::default();
        for (i, t) in ["Execution", "Persistence", "Defense Evasion"].iter().enumerate() {
            add_risk(&mut m, &mut r2, "acm", &with_tactic(alert_r(7, "9", 1000 + i as u32, "x"), t), t0, "", &cfg);
        }
        assert!(m.contains_key(&risk_key("acm", "9")), "3 tactics");
        // a day later the old rules no longer count
        let mut later = risk.clone();
        later.prune(t0 + 70 + RISK_WINDOW_SECS + 1);
        assert_eq!(later.score(), 0);
        // risk off: nothing
        let off = Settings { risk_enabled: false, ..Settings::default() };
        let mut m2 = HashMap::new();
        add_risk(&mut m2, &mut Risk::default(), "acm", &alert_r(15, "7", 1, "x"), t0, "", &off);
        assert!(m2.is_empty());
        assert_eq!((risk_points(12, 100), risk_points(5, 0)), (100, 1), "business risk doubles at most");
    }

    fn with_tactic(mut a: Alert, tactic: &str) -> Alert {
        a.rule.mitre = Some(siem_core::MitreAttack { id: "T0000".into(), tactic: tactic.into(), technique: "t".into() });
        a
    }
}
