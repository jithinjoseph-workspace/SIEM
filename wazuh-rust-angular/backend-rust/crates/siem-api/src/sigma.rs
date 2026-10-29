//! Sigma detection for the SIEM, with provigil-common's engine and SigmaHQ rule
//! sync (`ndr.sigma_rules`, shared with the NDR engine): every event the manager
//! archives (Windows event channel, Linux audit, syslog) is checked against the
//! enabled rules, in addition to the Wazuh ruleset; a match becomes a SIEM alert
//! (rule id 950000-999999 from the Sigma rule's id, groups "sigma" + its tags,
//! MITRE from its `attack.*` tags), so triage, SOAR and the investigation see it.
//!
//! First sync when the table is empty, then weekly; rules reload every 30 minutes.
//! API: `/api/v1/siem/sigma` (status and rules), `/api/v1/siem/sigma/sync` (super admin).

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use provigil_common::detection::{parse_rule_content, DetectionEngine, DetectionMatch};
use provigil_common::normalizer::{EventSource, NormalizedEvent};
use serde_json::{json, Map, Value};

use crate::tenancy::AuthCtx;
use crate::AppState;

const RELOAD_SECS: u64 = 1800;
const SYNC_SECS: u64 = 7 * 24 * 3600;

fn engine() -> &'static RwLock<DetectionEngine> {
    static E: OnceLock<RwLock<DetectionEngine>> = OnceLock::new();
    E.get_or_init(|| RwLock::new(DetectionEngine::new("")))
}

/// Rules loaded now.
pub fn rule_count() -> usize {
    engine().read().unwrap().rule_count()
}

/// provigil-common's own ClickHouse client (its crate version), with siem-api's settings.
fn common_config() -> provigil_common::clickhouse::ClickHouseConfig {
    provigil_common::clickhouse::ClickHouseConfig {
        url: std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".into()),
        database: "ndr".into(),
        user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into()),
        password: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default(),
    }
}

fn rules_dir() -> String {
    crate::data_file_path("sigma").to_string_lossy().into_owned()
}

/// The enabled rules of `ndr.sigma_rules` into the engine; the number loaded.
pub async fn reload(state: &AppState) -> Result<usize, String> {
    let rows = state
        .db
        .root()
        .query("SELECT id, content, tenant_id FROM ndr.sigma_rules FINAL WHERE enabled = 1")
        .fetch_all::<(String, String, String)>()
        .await
        .map_err(|e| e.to_string())?;
    let mut rules = Vec::with_capacity(rows.len());
    for (id, content, tenant) in rows {
        match parse_rule_content(&content) {
            Ok(mut r) => {
                r.tenant_id = if tenant.is_empty() { "*".into() } else { crate::tenancy::normalize_tenant(&tenant) };
                if r.id.is_empty() {
                    r.id = id;
                }
                rules.push(r);
            }
            Err(e) => tracing::debug!("sigma rule {id} not loaded: {e}"),
        }
    }
    let n = rules.len();
    engine().write().unwrap().set_rules(rules, HashMap::new());
    Ok(n)
}

async fn stored(state: &AppState) -> u64 {
    state.db.root().query("SELECT count() FROM ndr.sigma_rules FINAL").fetch_one::<u64>().await.unwrap_or(0)
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(20)).await;
        let mut last_sync = None::<std::time::Instant>;
        loop {
            if state.db.is_connected() {
                if stored(&state).await == 0 || last_sync.is_some_and(|t| t.elapsed() >= Duration::from_secs(SYNC_SECS)) {
                    match provigil_common::sigma_sync::sync_now(&common_config().build_client(), &rules_dir()).await {
                        Ok(n) => tracing::info!("sigma: {n} new SigmaHQ rule(s) saved"),
                        Err(e) => tracing::warn!("sigma: SigmaHQ sync failed: {e}"),
                    }
                    last_sync = Some(std::time::Instant::now());
                }
                if last_sync.is_none() {
                    last_sync = Some(std::time::Instant::now());
                }
                match reload(&state).await {
                    Ok(n) => tracing::info!("sigma: {n} rule(s) loaded"),
                    Err(e) => tracing::warn!("sigma: rules not loaded: {e}"),
                }
            }
            tokio::time::sleep(Duration::from_secs(RELOAD_SECS)).await;
        }
    });
}

/// `commandLine` -> `CommandLine` (Wazuh's eventdata names are Sigma's, lower-camel).
fn pascal(k: &str) -> String {
    let mut c = k.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

/// A Wazuh archive event as the Sigma engine sees it; `None` when it has nothing to match.
pub fn normalize(v: &Value) -> Option<NormalizedEvent> {
    let s = |x: &Value| x.as_str().filter(|t| !t.is_empty()).map(String::from);
    let mut raw = Map::new();
    let win = &v["data"]["win"];
    let source = if win.is_object() {
        if let Some(ed) = win["eventdata"].as_object() {
            for (k, val) in ed {
                if let Some(t) = val.as_str() {
                    // the Wazuh agent doubles every backslash of eventchannel values; Sigma paths have single ones
                    raw.insert(pascal(k), json!(t.replace("\\\\", "\\")));
                }
            }
        }
        let sys = &win["system"];
        for (from, to) in [("eventID", "EventID"), ("channel", "Channel"), ("providerName", "Provider_Name"), ("computer", "Computer"), ("level", "Level")] {
            if let Some(t) = s(&sys[from]) {
                raw.insert(to.into(), json!(t));
            }
        }
        // Security 4688 is a process_creation event under Sysmon's field names (SigmaHQ's windows-audit mapping)
        if raw.get("EventID").and_then(Value::as_str) == Some("4688") {
            for (from, to) in [("NewProcessName", "Image"), ("ParentProcessName", "ParentImage"), ("SubjectUserName", "User")] {
                if let Some(t) = raw.get(from).cloned() {
                    raw.entry(to).or_insert(t);
                }
            }
        }
        EventSource::WindowsEvent
    } else if v["data"]["audit"].is_object() {
        let a = &v["data"]["audit"];
        for (from, to) in [("exe", "exe"), ("exe", "Image"), ("command", "comm"), ("type", "record_type"), ("cwd", "CurrentDirectory"), ("execve", "CommandLine")] {
            let val = if from == "execve" { a["execve"].as_object().map(|m| m.values().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" ")) } else { s(&a[from]) };
            if let Some(t) = val.filter(|t| !t.is_empty()) {
                raw.insert(to.into(), json!(t));
            }
        }
        if let Some(u) = s(&a["auid"]).or_else(|| s(&a["uid"])) {
            raw.insert("User".into(), json!(u));
        }
        EventSource::Linux
    } else {
        // syslog lines: only keyword rules can match, on the message
        let log = s(&v["full_log"])?;
        raw.insert("message".into(), json!(log));
        if let Some(p) = s(&v["predecoder"]["program_name"]) {
            raw.insert("program".into(), json!(p));
        }
        EventSource::Syslog
    };
    let src = s(&v["data"]["srcip"]);
    let dst = s(&v["data"]["dstip"]);
    if let Some(ip) = &src {
        raw.insert("SourceIp".into(), json!(ip));
    }
    let mut ev = NormalizedEvent::blank();
    ev.event_source = source;
    ev.log_source = s(&v["location"]);
    ev.source_ip = src;
    ev.dest_ip = dst;
    ev.raw = Value::Object(raw);
    Some(ev)
}

fn level(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 13,
        "high" => 10,
        "medium" => 7,
        "low" => 4,
        _ => 3,
    }
}

/// 950000-999999 from the Sigma rule's id, so triage and suppressions group per rule.
pub fn rule_number(id: &str) -> u32 {
    // FNV-1a: stable across runs and builds
    let h = id.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3));
    950_000 + (h % 50_000) as u32
}

/// The SIEM alert for a Sigma match on an archived Wazuh event.
pub fn alert_for(v: &Value, m: &DetectionMatch) -> siem_core::Alert {
    let s = |x: &Value| x.as_str().unwrap_or("").to_string();
    // attack.t1087.001 is a technique, attack.discovery a tactic (attack.g0016 / s0002: groups, software)
    let technique = m.tags.iter().find_map(|t| t.strip_prefix("attack.t").filter(|x| x.starts_with(|c: char| c.is_ascii_digit())).map(|x| format!("T{}", x.to_uppercase())));
    let tactic = m.tags.iter().find_map(|t| t.strip_prefix("attack.").filter(|x| !x.chars().any(|c| c.is_ascii_digit())).map(|x| x.replace('_', " ")));
    let mut groups = vec!["sigma".to_string()];
    groups.extend(m.tags.iter().cloned());
    let mut data: HashMap<String, Value> = v["data"].as_object().map(|o| o.iter().map(|(k, x)| (k.clone(), x.clone())).collect()).unwrap_or_default();
    data.insert("sigma".into(), json!({ "rule_id": m.rule_id, "title": m.title, "severity": m.severity, "tags": m.tags }));
    let ts = v["timestamp"].as_str().and_then(|t| chrono::DateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%.3f%z").ok()).map(|t| t.with_timezone(&chrono::Utc)).unwrap_or_else(chrono::Utc::now);
    siem_core::Alert {
        id: uuid::Uuid::new_v4(),
        timestamp: ts,
        rule: siem_core::RuleAlertInfo {
            id: rule_number(&m.rule_id),
            level: level(&m.severity),
            description: format!("Sigma: {}", m.title),
            groups,
            mitre: technique.map(|t| siem_core::MitreAttack { id: t, tactic: tactic.unwrap_or_default(), technique: String::new() }),
        },
        agent: siem_core::AgentAlertInfo { id: s(&v["agent"]["id"]), name: s(&v["agent"]["name"]), ip: s(&v["agent"]["ip"]) },
        manager: None,
        decoder: None,
        full_log: v["full_log"].as_str().map(String::from).unwrap_or_else(|| v["data"]["win"]["system"]["message"].as_str().unwrap_or("").trim_matches('"').to_string()),
        decoded: siem_core::DecodedFields {
            decoder_name: s(&v["decoder"]["name"]),
            src_ip: v["data"]["srcip"].as_str().map(String::from),
            dst_ip: v["data"]["dstip"].as_str().map(String::from),
            src_port: None,
            dst_port: None,
            user: v["data"]["win"]["eventdata"]["targetUserName"].as_str().or(v["data"]["dstuser"].as_str()).map(String::from),
            program_name: None,
            process_id: None,
            file_path: None,
            action: None,
            status: None,
            extra: HashMap::new(),
        },
        location: s(&v["location"]),
        data,
    }
}

/// The Sigma alerts of a batch of archived events (each with its tenant), in event order.
/// A large batch is split over half the cores: the rest stay with analysisd and ClickHouse.
pub fn check(events: &[(Value, String)]) -> Vec<(siem_core::Alert, String)> {
    let e = engine().read().unwrap();
    if e.rule_count() == 0 {
        return Vec::new();
    }
    let one = |part: &[(Value, String)]| {
        let mut out = Vec::new();
        for (v, tenant) in part {
            let Some(ev) = normalize(v) else { continue };
            for m in e.check_for_tenant(&ev, tenant) {
                out.push((alert_for(v, &m), tenant.clone()));
            }
        }
        out
    };
    let threads = std::thread::available_parallelism().map_or(1, |n| (n.get() / 2).max(1));
    if threads == 1 || events.len() < 512 {
        return one(events);
    }
    std::thread::scope(|s| {
        let parts: Vec<_> = events.chunks(events.len().div_ceil(threads)).map(|p| s.spawn(move || one(p))).collect();
        parts.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    })
}

// ───────────────────────── API ─────────────────────────

/// `GET /api/v1/siem/sigma`: rules loaded (by platform) and the tenant's Sigma alerts of 24 h.
pub async fn status(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let rules = engine().read().unwrap().get_rules();
    let mut by_product: HashMap<String, u64> = HashMap::new();
    for r in &rules {
        *by_product.entry(r["logsource"]["product"].as_str().unwrap_or("any").to_string()).or_default() += 1;
    }
    let since = (chrono::Utc::now().timestamp_millis().max(0) as u64).saturating_sub(86_400_000);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Hit {
        rule_id: u32,
        title: String,
        level: u8,
        alerts: u64,
        last: u64,
        hosts: Vec<String>,
    }
    let recent = state
        .db
        .tenant_client(&ctx.scope())
        .query("SELECT rule_id, rule_description AS title, rule_level AS level, count() AS alerts, max(timestamp) AS last, groupUniqArray(5)(agent_name) AS hosts FROM siem_alerts WHERE timestamp >= ? AND rule_id >= 950000 AND rule_id < 1000000 GROUP BY rule_id, rule_description, rule_level ORDER BY count() DESC LIMIT 100")
        .bind(since)
        .fetch_all::<Hit>()
        .await
        .unwrap_or_default();
    Json(json!({
        "status": "ok",
        "loaded": rules.len(),
        "stored": stored(&state).await,
        "by_product": by_product,
        "matches_24h": recent.iter().map(|r| json!({ "rule_id": r.rule_id, "title": r.title, "level": r.level, "alerts": r.alerts, "last_seen": r.last / 1000, "hosts": r.hosts })).collect::<Vec<_>>(),
        "rules": rules.iter().take(5000).map(|r| json!({ "id": r["id"], "title": r["title"], "severity": r["severity"], "product": r["logsource"]["product"], "category": r["logsource"]["category"], "service": r["logsource"]["service"], "tags": r["tags"] })).collect::<Vec<_>>(),
    }))
}

/// `POST /api/v1/siem/sigma/sync` (super admin): fetch new SigmaHQ rules now and reload.
pub async fn sync(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    if !ctx.is_super() {
        return (StatusCode::FORBIDDEN, Json(json!({ "status": "error", "message": "Platform admins only" }))).into_response();
    }
    let saved = provigil_common::sigma_sync::sync_now(&common_config().build_client(), &rules_dir()).await;
    let loaded = reload(&state).await;
    match (saved, loaded) {
        (Ok(s), Ok(l)) => Json(json!({ "status": "ok", "saved": s, "loaded": l })).into_response(),
        (Err(e), _) => Json(json!({ "status": "error", "message": format!("SigmaHQ sync failed: {e}") })).into_response(),
        (_, Err(e)) => Json(json!({ "status": "error", "message": format!("rules not reloaded: {e}") })).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = r#"
title: Local Accounts Discovery via net1
id: 11111111-2222-3333-4444-555555555555
status: test
tags:
    - attack.discovery
    - attack.t1087.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4798
        CallerProcessName|endswith: '\net1.exe'
    condition: selection
level: medium
"#;

    #[test]
    fn windows_event_matches_a_sigma_rule() {
        let rule = parse_rule_content(RULE).unwrap();
        let mut e = DetectionEngine::new("");
        e.set_rules(vec![rule], HashMap::new());
        let ev = json!({
            "timestamp": "2026-10-26T08:48:49.815+0000", "agent": { "id": "043", "name": "win-node", "ip": "192.168.1.70" }, "location": "EventChannel",
            "decoder": { "name": "windows_eventchannel" },
            "data": { "win": { "system": { "eventID": "4798", "channel": "Security", "providerName": "Microsoft-Windows-Security-Auditing" },
                               // as the Wazuh agent sends it: every backslash doubled
                               "eventdata": { "targetUserName": "Guest", "callerProcessName": "C:\\\\Windows\\\\System32\\\\net1.exe" } } }
        });
        let n = normalize(&ev).unwrap();
        assert_eq!(n.get_field("CallerProcessName").as_deref(), Some("C:\\Windows\\System32\\net1.exe"));
        let m = e.check_for_tenant(&n, "default");
        assert_eq!(m.len(), 1, "matched");
        let a = alert_for(&ev, &m[0]);
        assert_eq!((a.rule.level, a.rule.description.as_str()), (7, "Sigma: Local Accounts Discovery via net1"));
        assert_eq!(a.rule.mitre.as_ref().map(|x| (x.id.as_str(), x.tactic.as_str())), Some(("T1087.001", "discovery")));
        assert!((950_000..1_000_000).contains(&a.rule.id) && a.rule.id == rule_number("11111111-2222-3333-4444-555555555555"));
        assert_eq!(a.decoded.user.as_deref(), Some("Guest"));
        // another process: no match
        let mut other = ev.clone();
        other["data"]["win"]["eventdata"]["callerProcessName"] = json!("C:\\Windows\\explorer.exe");
        assert!(e.check_for_tenant(&normalize(&other).unwrap(), "default").is_empty());
    }

    /// SigmaHQ "WMI Event Subscription" (Sysmon 19/20/21) once matched every Security 4798.
    #[test]
    fn number_lists_match_exactly() {
        let rule = parse_rule_content("title: WMI Event Subscription\nid: 0f06a3a5-6a09-413f-8743-e6cf35561297\ntags:\n    - attack.t1546.003\nlogsource:\n    product: windows\n    category: wmi_event\ndetection:\n    selection:\n        EventID:\n            - 19\n            - 20\n            - 21\n    condition: selection\nlevel: medium\n").unwrap();
        let mut e = DetectionEngine::new("");
        e.set_rules(vec![rule], HashMap::new());
        let ev = |id: &str, channel: &str| {
            normalize(&json!({ "data": { "win": { "system": { "eventID": id, "channel": channel, "providerName": "Microsoft-Windows-Security-Auditing" },
                                                  "eventdata": { "targetUserName": "Guest", "callerProcessName": "C:\\Windows\\System32\\net1.exe" } } } })).unwrap()
        };
        assert!(e.check_for_tenant(&ev("4798", "Security"), "default").is_empty(), "4798 is not 19, 20 or 21");
        assert!(e.check_for_tenant(&ev("20", "Security"), "default").is_empty(), "a wmi_event rule reads only the Sysmon log");
        assert_eq!(e.check_for_tenant(&ev("20", "Microsoft-Windows-Sysmon/Operational"), "default").len(), 1);
    }

    /// A Sigma category is a Sysmon event id: a "not filter" raw-disk rule once matched every Sysmon 1.
    #[test]
    fn categories_need_their_event_ids() {
        let raw_disk = parse_rule_content("title: Raw Disk\nid: r1\nlogsource:\n    product: windows\n    category: raw_access_thread\ndetection:\n    filter:\n        Image|startswith: 'C:\\Windows\\System32\\'\n    condition: not filter\nlevel: low\n").unwrap();
        let netsh = parse_rule_content("title: Netsh\nid: r2\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    selection:\n        Image|endswith: '\\netsh.exe'\n    condition: selection\nlevel: low\n").unwrap();
        let odd = parse_rule_content("title: Odd\nid: r3\nlogsource:\n    product: windows\n    service: some-unknown-log\ndetection:\n    filter:\n        Image: x\n    condition: not filter\nlevel: low\n").unwrap();
        let mut e = DetectionEngine::new("");
        e.set_rules(vec![raw_disk, netsh, odd], HashMap::new());
        let ev = |id: &str, channel: &str, ed: Value| normalize(&json!({ "data": { "win": { "system": { "eventID": id, "channel": channel }, "eventdata": ed } } })).unwrap();
        let titles = |n: &NormalizedEvent| e.check_for_tenant(n, "default").into_iter().map(|m| m.title).collect::<Vec<_>>();
        let sysmon = "Microsoft-Windows-Sysmon/Operational";
        assert_eq!(titles(&ev("1", sysmon, json!({ "image": "C:\\\\Temp\\\\netsh.exe" }))), ["Netsh"], "Sysmon 1 is not raw disk access");
        assert_eq!(titles(&ev("9", sysmon, json!({ "image": "C:\\\\Temp\\\\x.exe" }))), ["Raw Disk"]);
        assert!(titles(&ev("9", sysmon, json!({ "image": "C:\\\\Windows\\\\System32\\\\svchost.exe" }))).is_empty(), "the filter excludes System32");
        assert_eq!(titles(&ev("4688", "Security", json!({ "newProcessName": "C:\\\\Windows\\\\System32\\\\netsh.exe" }))), ["Netsh"], "Security 4688 is process creation");
        assert!(titles(&ev("4624", "Security", json!({ "newProcessName": "C:\\\\Windows\\\\System32\\\\netsh.exe" }))).is_empty());
    }

    #[test]
    fn linux_audit_and_syslog() {
        let a = normalize(&json!({ "data": { "audit": { "exe": "/usr/bin/curl", "type": "EXECVE", "execve": { "a0": "curl", "a1": "http://x" } } } })).unwrap();
        assert_eq!((a.get_field("Image").as_deref(), a.get_field("CommandLine").as_deref()), (Some("/usr/bin/curl"), Some("curl http://x")));
        assert!(matches!(normalize(&json!({ "full_log": "sshd: Failed password" })).unwrap().event_source, EventSource::Syslog));
        assert!(normalize(&json!({ "data": {} })).is_none(), "nothing to match");
    }
}
