//! Incidents (specs/alert-lifecycle.md, phase 3): related alerts become one case, so an analyst
//! works on dozens of incidents instead of thousands of alerts.
//!
//! One computer, one incident (owner's choice 2026-11-17, after one busy PC opened 41 cases in two
//! hours with one per agent and rule): the alerts of one tenant's agent belong together while its
//! last alert is at most [`WINDOW_SECS`] old, and the case lists every rule with its count, so an
//! attack that sets off ten rules is one story, not ten cases.
//!
//! Alerts of level [`OPEN_LEVEL`] or more are gathered per computer; they become a case when one
//! is of level [`OPEN_ALONE`] or more, or when they span [`MIN_TACTICS`] different ATT&CK tactics
//! (several stages of an attack). Until then they stay in the alert queue only. Once a case is
//! open, every alert of that computer joins it (lower levels too). The incident lists the
//! entities involved (process image, else user). An incident is an ordinary case (`soar_cases`,
//! number `INC-<year>-<n>`, tag `auto-incident`): its alerts in `hit_ids`, severity and priority
//! from its highest level and business risk. Changes are written every [`FLUSH_SECS`]; a write
//! keeps what people set (status, owner, ...), and a case someone closed takes no more alerts.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;
use siem_core::Alert;
use tracing::warn;

use crate::AppState;

/// Alerts from this level are gathered towards a case.
pub const OPEN_LEVEL: u8 = 7;
/// One alert from this level opens the case on its own.
pub const OPEN_ALONE: u8 = 10;
/// Gathered alerts spanning this many ATT&CK tactics open the case.
pub const MIN_TACTICS: usize = 2;
/// An incident takes alerts while its last one is at most this old.
pub const WINDOW_SECS: i64 = 86_400;
/// Rules listed per incident.
const MAX_RULES: usize = 50;
/// Alert ids kept per incident (the count goes on).
pub const MAX_IDS: usize = 500;
const FLUSH_SECS: u64 = 15;
const TAG: &str = "auto-incident";
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

/// The group an alert belongs to: tenant and agent (computer).
pub fn key(tenant: &str, agent_id: &str) -> String {
    format!("{tenant}|{agent_id}|host")
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
    /// the description of its highest-level alert
    pub top_rule: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub max_level: u8,
    /// the highest business risk of its alerts (risk fabric, 0-100)
    pub max_risk: u8,
    pub count: u64,
    pub ids: Vec<String>,
    /// each rule: id, description, alerts, highest level
    pub rules: Vec<(u32, String, u64, u8)>,
    /// the ATT&CK tactics of its alerts
    pub tactics: Vec<String>,
    /// a case (else alerts gathered until one opens it)
    pub opened: bool,
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
        if a.rule.level > self.max_level || self.top_rule.is_empty() {
            self.top_rule = a.rule.description.clone();
        }
        self.max_level = self.max_level.max(a.rule.level);
        for t in a.rule.mitre.iter().flat_map(|m| m.tactic.split(',')).map(str::trim).filter(|t| !t.is_empty()) {
            if !self.tactics.iter().any(|x| x.eq_ignore_ascii_case(t)) {
                self.tactics.push(t.to_string());
            }
        }
        let risk = a.data.get("risk_fabric").and_then(|r| r["dynamic_risk_score"].as_u64()).unwrap_or(0).min(100) as u8;
        self.max_risk = self.max_risk.max(risk);
        self.count += 1;
        if self.ids.len() < MAX_IDS {
            self.ids.push(a.id.to_string());
        }
        if let Some(r) = self.rules.iter_mut().find(|r| r.0 == a.rule.id) {
            r.2 += 1;
            r.3 = r.3.max(a.rule.level);
        } else if self.rules.len() < MAX_RULES {
            self.rules.push((a.rule.id, a.rule.description.clone(), 1, a.rule.level));
        }
        if self.src_ip.is_empty() {
            self.src_ip = a.decoded.src_ip.clone().unwrap_or_default();
        }
        self.dirty = true;
    }

    pub fn title(&self) -> String {
        let top = if self.top_rule.is_empty() { &self.first_rule } else { &self.top_rule };
        match self.rules.len() {
            0 | 1 => format!("{}: {}", self.agent_name, top),
            n => format!("{}: {} (+{} more rule{})", self.agent_name, top, n - 1, if n == 2 { "" } else { "s" }),
        }
    }

    /// Whether the gathered alerts are worth a case.
    fn worth_a_case(&self) -> bool {
        self.max_level >= OPEN_ALONE || self.tactics.len() >= MIN_TACTICS
    }

    /// The case's tags: the marker, the key, each entity, and the field of a single entity (an
    /// exception for the incident can then name it; with several it covers the rule on the agent).
    pub fn tags(&self, key: &str) -> Vec<String> {
        let mut t = vec![TAG.to_string(), format!("key:{key}")];
        t.extend(self.entities.iter().map(|(e, _)| e.clone()));
        if let [(_, Some(f))] = self.entities.as_slice() {
            t.push(format!("field:{f}"));
        }
        t
    }

    pub fn description(&self) -> String {
        format!(
            "Incident opened automatically: {} alert(s) on {} between {} and {} UTC, highest level {}, business risk {}. Rules: {}.",
            self.count,
            self.agent_name,
            chrono::DateTime::from_timestamp(self.first_seen, 0).map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default(),
            chrono::DateTime::from_timestamp(self.last_seen, 0).map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default(),
            self.max_level,
            self.max_risk,
            {
                let mut r = self.rules.clone();
                r.sort_by(|a, b| b.3.cmp(&a.3).then(b.2.cmp(&a.2)));
                r.iter().map(|(id, d, n, l)| format!("{d} (rule {id}, level {l}, {n} alert{})", if *n == 1 { "" } else { "s" })).collect::<Vec<_>>().join("; ")
            }
        )
    }
}

/// Puts one alert into the open incidents: joins one, opens one, or neither (`None`).
pub fn place(open: &mut HashMap<String, Open>, tenant: &str, a: &Alert, ent: (String, Option<&'static str>), ts: i64) -> Option<String> {
    let k = key(tenant, &a.agent.id);
    if let Some(o) = open.get_mut(&k) {
        if ts - o.last_seen <= WINDOW_SECS {
            // a low alert joins a case, but does not gather towards one
            if !o.opened && a.rule.level < OPEN_LEVEL {
                return None;
            }
            o.take(a, ts, ent);
            if !o.opened && o.worth_a_case() {
                o.opened = true;
                o.new = true;
            }
            return o.opened.then_some(k);
        }
        // too old: a new alert of level OPEN_LEVEL starts gathering again below
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
        ..Open::default()
    };
    o.take(a, ts, ent);
    o.opened = o.worth_a_case();
    o.new = o.opened;
    let opened = o.opened;
    open.insert(k.clone(), o);
    opened.then_some(k)
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
        let v = serde_json::to_value(a).unwrap_or_default();
        place(&mut map, &tenant, a, entity_at(&v), a.timestamp.timestamp());
    }
}

/// Loads the open incidents of every tenant (after a restart), then writes changes every
/// [`FLUSH_SECS`].
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        if state.db.is_connected() {
            for t in crate::predictions::tenant_ids(&state) {
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
    let sql = format!("SELECT id, title, tags, hit_ids, toUInt32(toUnixTimestamp(updated_at)) AS updated FROM soar_cases FINAL WHERE has(tags, ?) AND status NOT IN {CLOSED} AND updated_at >= now() - INTERVAL {WINDOW_SECS} SECOND");
    let rows: Vec<OpenRow> = state.db.tenant_client(tenant).query(&sql).bind(TAG).fetch_all().await.unwrap_or_default();
    let mut map = open().lock().unwrap();
    for r in rows {
        let Some(k) = r.tags.iter().find_map(|t| t.strip_prefix("key:")) else { continue };
        // an incident of an earlier grouping (per process, per rule) is not continued (another key)
        if !k.ends_with("|host") {
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
            opened: true,
            ..Open::default()
        });
    }
}

async fn flush(state: &AppState) {
    let now = chrono::Utc::now().timestamp();
    let work: Vec<(String, Open)> = {
        let mut map = open().lock().unwrap();
        // incidents past their window are done: forgotten once written
        map.retain(|_, o| o.dirty || now - o.last_seen <= WINDOW_SECS);
        // alerts still gathering towards a case are not written
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
        .query(&format!("SELECT toUInt64(count()) AS cases, toUInt64(countIf(status NOT IN {CLOSED})) AS open, toUInt64(countIf(has(tags, 'auto-incident'))) AS auto_incidents, toFloat64(ifNotFinite(ifNull(avgIf(dateDiff('second', created_at, closed_at), closed_at IS NOT NULL), 0), 0)) AS mttr FROM soar_cases FINAL WHERE created_at >= now() - INTERVAL ? DAY"))
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
    let t = totals.unwrap_or(Totals { cases: 0, open: 0, auto_incidents: 0, mttr: 0.0 });
    axum::Json(serde_json::json!({
        "days": days, "cases": t.cases, "open": t.open, "auto_incidents": t.auto_incidents,
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
        let mut a = alert(10, "8084", "Suspicious process");
        a.data.insert("risk_fabric".into(), json!({"dynamic_risk_score": 72}));
        let k = place(&mut m, "acm", &a, ("process:x.exe".into(), None), 0).unwrap();
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

    fn with_tactic(mut a: Alert, tactic: &str) -> Alert {
        a.rule.mitre = Some(siem_core::MitreAttack { id: "T0000".into(), tactic: tactic.into(), technique: "t".into() });
        a
    }

    #[test]
    fn one_case_per_computer_opened_when_it_matters() {
        let mut m = HashMap::new();
        let t0 = 1_800_000_000;
        let p = |e: &str| (e.to_string(), Some("data.win.eventdata.image"));
        assert_eq!(place(&mut m, "acm", &alert_r(4, "8084", 92153, "VaultCli"), p("process:svchost.exe"), t0), None, "a low alert opens nothing");
        // level 7-9 of one tactic: gathered, no case yet
        assert_eq!(place(&mut m, "acm", &with_tactic(alert_r(7, "8084", 92052, "Cmd by odd parent"), "Execution"), p("process:cmd.exe"), t0), None);
        assert_eq!(place(&mut m, "acm", &with_tactic(alert_r(8, "8084", 92052, "Cmd by odd parent"), "Execution"), p("process:cmd.exe"), t0 + 10), None, "the same tactic again");
        // a second tactic on the same computer: the case opens, with what was gathered
        let k = place(&mut m, "acm", &with_tactic(alert_r(7, "8084", 92041, "Base64 registry value"), "Defense Evasion"), p("process:reg.exe"), t0 + 20).unwrap();
        assert_eq!((m[&k].count, m[&k].new), (3, true));
        // any later alert of that computer joins it, other rules and lower levels too
        assert_eq!(place(&mut m, "acm", &alert_r(3, "8084", 92153, "VaultCli"), p("process:svchost.exe"), t0 + 600), Some(k.clone()));
        assert_eq!(place(&mut m, "acm", &alert_r(12, "8084", 92213, "Executable dropped"), p("process:powershell.exe"), t0 + 700), Some(k.clone()));
        let o = &m[&k];
        assert_eq!((o.count, o.rules.len(), severity(o.max_level)), (5, 4, "CRITICAL"));
        assert_eq!(o.title(), "pc-8084: Executable dropped (+3 more rules)", "named by its worst rule");
        assert!(o.description().contains("Cmd by odd parent (rule 92052, level 8, 2 alerts)"), "{}", o.description());
        // another computer: its own; level 10 opens on its own
        let k2 = place(&mut m, "acm", &alert_r(10, "8087", 92153, "VaultCli"), p("process:winword.exe"), t0).unwrap();
        assert_ne!(k2, k);
        assert_eq!(m[&k2].tags(&k2).last().map(String::as_str), Some("field:data.win.eventdata.image"), "one process: its field is named");
        // a day without alerts: the next one starts over
        let id = m[&k].id.clone();
        assert_eq!(place(&mut m, "acm", &alert_r(8, "8084", 92153, "VaultCli"), p("process:svchost.exe"), t0 + 700 + WINDOW_SECS + 1), None, "gathering again");
        assert_ne!(m[&k].id, id);
    }
}
