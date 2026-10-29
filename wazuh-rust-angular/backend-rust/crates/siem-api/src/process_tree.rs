//! Process tree of a Windows alert (EDR step 3): the alert's process, the processes that
//! started it and the ones it started, each with what it did (network, files, registry,
//! DNS, ...). Built from the Sysmon events ClickHouse already keeps for the agent
//! (`siem_events` of the caller's tenant), around the alert's time: nothing new is stored.
//!
//! `GET /api/v1/agents/:id/process-tree?guid=<Sysmon ProcessGuid>&at=<alert time, ms>`
//! (the agent's tenant is checked by the auth layer, like every `/api/v1/agents/:id` route).

use std::collections::{HashMap, HashSet};

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::tenancy::AuthCtx;
use crate::AppState;

/// Process starts and ends read: from 24 h before the alert (its ancestors) to 1 h after
/// (what it started then).
const BEFORE_MS: u64 = 24 * 3600 * 1000;
const AFTER_MS: u64 = 3600 * 1000;
/// Bounds of one tree, so a busy host cannot make it slow or big.
const MAX_STARTS: u64 = 50_000;
const MAX_ANCESTORS: usize = 32;
const MAX_DESCENDANTS: usize = 300;
const MAX_ACTIVITY: u64 = 5_000;
const SAMPLES_PER_NODE: usize = 25;

/// The agent's Sysmon events in the window, with their event data (`d`).
// shortcut: siem_events is ordered by (timestamp, agent_id), so this reads the tenant's whole
// 25 h window; when trees get slow on big tenants, keep Sysmon events in their own table
// ordered by (agent_id, timestamp).
const SYSMON: &str = "SELECT timestamp, JSONExtractString(raw_metadata, 'data_json') AS d FROM siem_events \
     WHERE timestamp >= ? AND timestamp <= ? AND agent_id = ? AND location = 'EventChannel' \
     AND position(raw_metadata, 'Microsoft-Windows-Sysmon/Operational') > 0";

fn ed(k: &str) -> String {
    format!("JSONExtractString(d, 'win', 'eventdata', '{k}')")
}

const EVENT_ID: &str = "trim(BOTH '\"' FROM JSONExtractRaw(d, 'win', 'system', 'eventID'))";

#[derive(clickhouse::Row, Deserialize, Clone, Debug, Default)]
pub struct Start {
    pub ts: u64,
    pub event_id: String,
    pub guid: String,
    pub parent_guid: String,
    pub pid: String,
    pub image: String,
    pub command_line: String,
    pub user: String,
    pub hashes: String,
    pub parent_pid: String,
    pub parent_image: String,
    pub parent_command_line: String,
}

#[derive(clickhouse::Row, Deserialize, Clone, Debug)]
pub struct Activity {
    pub ts: u64,
    pub event_id: String,
    pub guid: String,
    pub detail: String,
}

/// Wazuh doubles the backslashes of Windows event data.
fn undouble(s: &str) -> String {
    s.replace("\\\\", "\\")
}

fn kind(event_id: &str) -> &'static str {
    match event_id {
        "3" => "network",
        "22" => "dns",
        "2" | "11" | "15" | "23" | "26" | "29" => "file",
        "12" | "13" | "14" => "registry",
        "7" => "image_load",
        "8" => "remote_thread",
        "10" => "process_access",
        "17" | "18" => "pipe",
        "25" => "tampering",
        _ => "other",
    }
}

fn node(s: &Start, role: &str, depth: usize, ended: Option<u64>) -> Value {
    json!({
        "guid": s.guid, "parent_guid": s.parent_guid, "pid": s.pid.parse::<u64>().ok(),
        "image": undouble(&s.image), "command_line": undouble(&s.command_line), "user": undouble(&s.user),
        "hashes": s.hashes, "started": s.ts, "ended": ended, "role": role, "depth": depth, "known": true,
    })
}

/// The tree in display order (ancestors from the oldest, the alert's process, then what it
/// started, depth first by start time). A process started before the window is shown from
/// what its child's start event says about it (`known: false`).
pub fn assemble(focal: &str, starts: &[Start], ends: &HashMap<String, u64>) -> Vec<Value> {
    let by_guid: HashMap<&str, &Start> = starts.iter().map(|s| (s.guid.as_str(), s)).collect();
    let mut children: HashMap<&str, Vec<&Start>> = HashMap::new();
    for s in starts {
        children.entry(s.parent_guid.as_str()).or_default().push(s);
    }
    // ancestors, nearest first
    let mut chain: Vec<&Start> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::from([focal]);
    let mut cur = by_guid.get(focal).copied();
    while let Some(c) = cur {
        let Some(p) = by_guid.get(c.parent_guid.as_str()).copied().filter(|p| seen.insert(p.guid.as_str())) else { break };
        if chain.len() == MAX_ANCESTORS {
            break;
        }
        chain.push(p);
        cur = Some(p);
    }
    let mut out: Vec<Value> = Vec::new();
    // the oldest ancestor's parent, from its start event
    let oldest = chain.last().copied().or_else(|| by_guid.get(focal).copied());
    if let Some(o) = oldest.filter(|o| !o.parent_guid.is_empty() && !o.parent_image.is_empty() && !seen.contains(o.parent_guid.as_str())) {
        out.push(json!({
            "guid": o.parent_guid, "parent_guid": "", "pid": o.parent_pid.parse::<u64>().ok(),
            "image": undouble(&o.parent_image), "command_line": undouble(&o.parent_command_line), "user": "",
            "hashes": "", "started": null, "ended": ends.get(&o.parent_guid), "role": "ancestor", "depth": 0, "known": false,
        }));
    }
    for a in chain.iter().rev() {
        let d = out.len();
        out.push(node(a, "ancestor", d, ends.get(&a.guid).copied()));
    }
    let depth = out.len();
    match by_guid.get(focal) {
        Some(f) => out.push(node(f, "focal", depth, ends.get(focal).copied())),
        None => out.push(json!({ "guid": focal, "parent_guid": "", "pid": null, "image": "", "command_line": "", "user": "",
            "hashes": "", "started": null, "ended": ends.get(focal), "role": "focal", "depth": depth, "known": false })),
    }
    // descendants, depth first
    fn push_children<'a>(stack: &mut Vec<(&'a Start, usize)>, children: &HashMap<&str, Vec<&'a Start>>, guid: &str, d: usize) {
        let mut c: Vec<&Start> = children.get(guid).cloned().unwrap_or_default();
        // popped earliest first
        c.sort_by_key(|s| std::cmp::Reverse(s.ts));
        stack.extend(c.into_iter().map(|s| (s, d)));
    }
    let mut stack: Vec<(&Start, usize)> = Vec::new();
    push_children(&mut stack, &children, focal, depth + 1);
    let mut n = 0;
    while let Some((s, d)) = stack.pop() {
        if n == MAX_DESCENDANTS || !seen.insert(s.guid.as_str()) {
            continue;
        }
        n += 1;
        out.push(node(s, "descendant", d, ends.get(&s.guid).copied()));
        push_children(&mut stack, &children, &s.guid, d + 1);
    }
    out
}

/// Adds each process's activity: counts per kind and the first samples.
pub fn attach_activity(nodes: &mut [Value], activity: &[Activity]) {
    let mut per: HashMap<&str, Vec<&Activity>> = HashMap::new();
    for a in activity {
        per.entry(a.guid.as_str()).or_default().push(a);
    }
    for n in nodes.iter_mut() {
        let guid = n["guid"].as_str().unwrap_or("").to_string();
        let list = per.get(guid.as_str()).cloned().unwrap_or_default();
        let mut counts: HashMap<&str, u64> = HashMap::new();
        for a in &list {
            *counts.entry(kind(&a.event_id)).or_default() += 1;
        }
        let samples: Vec<Value> = list.iter().take(SAMPLES_PER_NODE).map(|a| json!({ "ts": a.ts, "kind": kind(&a.event_id), "event_id": a.event_id, "detail": undouble(&a.detail) })).collect();
        n["activity"] = json!({ "counts": counts, "samples": samples });
    }
}

#[derive(Deserialize)]
pub struct TreeQuery {
    guid: String,
    at: Option<u64>,
}

/// A Sysmon ProcessGuid: `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
fn valid_guid(g: &str) -> bool {
    g.len() <= 40 && g.len() >= 32 && g.chars().all(|c| c.is_ascii_hexdigit() || matches!(c, '-' | '{' | '}'))
}

pub async fn get(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(agent_id): Path<String>, Query(q): Query<TreeQuery>) -> Response {
    let err = |code: StatusCode, m: &str| (code, Json(json!({ "status": "error", "message": m }))).into_response();
    let guid = q.guid.trim().to_string();
    if !valid_guid(&guid) {
        return err(StatusCode::BAD_REQUEST, "A Sysmon process GUID is required");
    }
    let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let at = q.at.unwrap_or(now).min(now);
    let (from, to) = (at.saturating_sub(BEFORE_MS), at + AFTER_MS);
    let client = state.db.tenant_client(&ctx.scope());
    let starts_sql = format!(
        "SELECT timestamp AS ts, {EVENT_ID} AS event_id, {} AS guid, {} AS parent_guid, {} AS pid, {} AS image, {} AS command_line, {} AS user, {} AS hashes, {} AS parent_pid, {} AS parent_image, {} AS parent_command_line \
         FROM ({SYSMON}) WHERE event_id IN ('1', '5') ORDER BY ts LIMIT ?",
        ed("processGuid"), ed("parentProcessGuid"), ed("processId"), ed("image"), ed("commandLine"), ed("user"), ed("hashes"), ed("parentProcessId"), ed("parentImage"), ed("parentCommandLine"),
    );
    let rows = match client.query(&starts_sql).bind(from).bind(to).bind(&agent_id).bind(MAX_STARTS).fetch_all::<Start>().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("process tree of agent {agent_id}: {e}");
            return err(StatusCode::SERVICE_UNAVAILABLE, "The agent's events cannot be read right now");
        }
    };
    let (starts, ends): (Vec<Start>, Vec<Start>) = rows.into_iter().partition(|r| r.event_id == "1");
    let ends: HashMap<String, u64> = ends.into_iter().map(|e| (e.guid, e.ts)).collect();
    let mut nodes = assemble(&guid, &starts, &ends);
    let guids: Vec<String> = nodes.iter().filter_map(|n| n["guid"].as_str().map(String::from)).collect();
    let activity_sql = format!(
        "SELECT timestamp AS ts, {EVENT_ID} AS event_id, if({p} != '', {p}, {sp}) AS guid, \
         multiIf(event_id = '3', concat({dip}, ':', {dport}, if({dhost} != '', concat(' (', {dhost}, ')'), '')), \
                 event_id IN ('2', '11', '15', '23', '26', '29'), {tf}, \
                 event_id IN ('12', '13', '14'), concat({to}, if({det} != '', concat(' = ', {det}), '')), \
                 event_id = '22', concat({qn}, if({qr} != '', concat(' -> ', {qr}), '')), \
                 event_id = '7', {il}, event_id IN ('8', '10'), {ti}, event_id IN ('17', '18'), {pn}, '') AS detail \
         FROM ({SYSMON}) WHERE event_id NOT IN ('1', '5') AND has(?, guid) ORDER BY ts LIMIT ?",
        p = ed("processGuid"), sp = ed("sourceProcessGuid"), dip = ed("destinationIp"), dport = ed("destinationPort"), dhost = ed("destinationHostname"),
        tf = ed("targetFilename"), to = ed("targetObject"), det = ed("details"), qn = ed("queryName"), qr = ed("queryResults"),
        il = ed("imageLoaded"), ti = ed("targetImage"), pn = ed("pipeName"),
    );
    let activity = client.query(&activity_sql).bind(from).bind(to).bind(&agent_id).bind(&guids).bind(MAX_ACTIVITY).fetch_all::<Activity>().await.unwrap_or_else(|e| {
        tracing::warn!("process activity of agent {agent_id}: {e}");
        Vec::new()
    });
    attach_activity(&mut nodes, &activity);
    let found = nodes.iter().any(|n| n["role"] == "focal" && n["known"] == true);
    Json(json!({ "agent_id": agent_id, "guid": guid, "from": from, "to": to, "found": found, "processes": starts.len(), "nodes": nodes })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(ts: u64, guid: &str, parent: &str, image: &str) -> Start {
        Start { ts, event_id: "1".into(), guid: guid.into(), parent_guid: parent.into(), pid: ts.to_string(), image: image.into(), parent_image: format!("parent-of-{image}"), ..Default::default() }
    }

    #[test]
    fn tree_has_ancestors_focal_and_descendants_in_order() {
        let starts = vec![
            start(1, "e", "w", "C:\\\\Windows\\\\explorer.exe"),
            start(2, "c", "e", "cmd.exe"),
            start(3, "p", "c", "powershell.exe"),
            start(5, "who", "p", "whoami.exe"),
            start(4, "net", "p", "net.exe"),
            start(6, "x", "net", "net1.exe"),
            start(7, "other", "e", "notepad.exe"),
            // a loop in bad data must not hang
            start(8, "l1", "l2", "a.exe"),
            start(9, "l2", "l1", "b.exe"),
        ];
        let ends = HashMap::from([("who".to_string(), 10)]);
        let t = assemble("p", &starts, &ends);
        let row = |n: &Value| (n["guid"].as_str().unwrap().to_string(), n["role"].as_str().unwrap().to_string(), n["depth"].as_u64().unwrap());
        let rows: Vec<_> = t.iter().map(row).collect();
        assert_eq!(rows, [
            ("w".into(), "ancestor".into(), 0), ("e".into(), "ancestor".into(), 1), ("c".into(), "ancestor".into(), 2),
            ("p".into(), "focal".into(), 3), ("net".into(), "descendant".into(), 4), ("x".into(), "descendant".into(), 5), ("who".into(), "descendant".into(), 4),
        ]);
        assert_eq!(t[0]["known"], false, "explorer's parent is only known from explorer's start");
        assert_eq!(t[1]["image"], "C:\\Windows\\explorer.exe", "backslashes un-doubled");
        assert_eq!(t[6]["ended"], 10);
        assert_eq!(assemble("l1", &starts, &HashMap::new()).len(), 2, "loop: l2 and l1 once each");
        let unknown = assemble("zz", &starts, &HashMap::new());
        assert_eq!((unknown.len(), unknown[0]["known"].as_bool()), (1, Some(false)));
    }

    #[test]
    fn activity_is_counted_per_process() {
        let mut t = assemble("p", &[start(1, "p", "c", "powershell.exe")], &HashMap::new());
        let a = |id: &str, d: &str| Activity { ts: 2, event_id: id.into(), guid: "p".into(), detail: d.into() };
        attach_activity(&mut t, &[a("3", "1.2.3.4:443"), a("3", "5.6.7.8:80"), a("13", "HKLM\\\\Run\\\\x = y"), a("22", "evil.com")]);
        let f = t.iter().find(|n| n["role"] == "focal").unwrap();
        assert_eq!(f["activity"]["counts"]["network"], 2);
        assert_eq!(f["activity"]["counts"]["registry"], 1);
        assert_eq!(f["activity"]["samples"][2]["detail"], "HKLM\\Run\\x = y");
        assert!(valid_guid("{a1b2c3d4-0000-1111-2222-333344445555}") && !valid_guid("x' OR 1=1"));
    }
}
