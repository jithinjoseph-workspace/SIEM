//! The SIEM state that used to live only in memory: active responses,
//! vulnerability detections and queued agent commands. Every change is
//! written to the agent's tenant database; the in-memory lists are a cache
//! loaded at startup.

use chrono::Utc;
use clickhouse::Client;
use serde::{Deserialize, Serialize};
use crate::vulnerability::VulnItem;
use tracing::{info, warn};

use crate::{tenancy, ActiveResponseRecord, AppState};

/// Tables of every tenant database (copied from `ndr` by the tenant provisioning).
pub const TABLES: &[(&str, &str)] = &[
    (
        "siem_active_responses",
        // one row per action; a release re-inserts it with a newer updated_at
        "CREATE TABLE IF NOT EXISTS siem_active_responses (
            id String,
            triggered_at UInt64,
            agent_id LowCardinality(String),
            command LowCardinality(String),
            target_ip String,
            reason String,
            duration_seconds UInt64,
            status LowCardinality(String),
            updated_at UInt64
        ) ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY id",
    ),
    (
        "siem_vulnerabilities",
        // a full snapshot per scan of an agent; the latest snapshot is the current state
        // (an empty scan writes one marker row with an empty detection)
        "CREATE TABLE IF NOT EXISTS siem_vulnerabilities (
            snapshot_at UInt64,
            agent_id LowCardinality(String),
            cve_id String,
            package_name String,
            severity LowCardinality(String),
            status LowCardinality(String),
            detection String
        ) ENGINE = MergeTree
        ORDER BY (agent_id, snapshot_at)
        TTL toDateTime(intDiv(snapshot_at, 1000)) + INTERVAL 180 DAY",
    ),
    (
        "siem_agent_commands",
        // queued commands until the agent fetches them (delivered = 1)
        "CREATE TABLE IF NOT EXISTS siem_agent_commands (
            agent_id LowCardinality(String),
            command_id String,
            payload String,
            created_at UInt64,
            delivered UInt8,
            updated_at UInt64
        ) ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY (agent_id, command_id)",
    ),
];

/// Creates the tables in `db`, replacing the old (never written) shape of
/// `siem_active_responses` when it is still empty.
pub async fn ensure_tables(root: &Client, db: &str) {
    let has_status: u64 = root
        .query(&format!("SELECT count() FROM system.columns WHERE database = '{db}' AND table = 'siem_active_responses' AND name = 'status'"))
        .fetch_one()
        .await
        .unwrap_or(1);
    if has_status == 0 {
        let rows: u64 = root.query(&format!("SELECT count() FROM `{db}`.siem_active_responses")).fetch_one().await.unwrap_or(1);
        if rows == 0 {
            let _ = root.query(&format!("DROP TABLE IF EXISTS `{db}`.siem_active_responses")).execute().await;
            info!("{db}.siem_active_responses: old empty table replaced");
        } else {
            warn!("{db}.siem_active_responses has rows in the old format; it is kept and active responses are not saved there");
        }
    }
    let c = root.clone().with_database(db);
    for (name, ddl) in TABLES {
        if let Err(e) = c.query(ddl).execute().await {
            warn!("{db}.{name}: {e}");
        }
    }
}

fn now_ms() -> u64 {
    Utc::now().timestamp_millis() as u64
}

fn tenant_of(state: &AppState, agent_id: &str) -> String {
    tenancy::tenant_of(&state.agent_tenants.read().unwrap(), agent_id)
}

#[derive(clickhouse::Row, Serialize, Deserialize)]
struct ArRow {
    id: String,
    triggered_at: u64,
    agent_id: String,
    command: String,
    target_ip: String,
    reason: String,
    duration_seconds: u64,
    status: String,
    updated_at: u64,
}

#[derive(clickhouse::Row, Serialize, Deserialize)]
struct VulnRow {
    snapshot_at: u64,
    agent_id: String,
    cve_id: String,
    package_name: String,
    severity: String,
    status: String,
    detection: String,
}

#[derive(clickhouse::Row, Serialize, Deserialize)]
struct CmdRow {
    agent_id: String,
    command_id: String,
    payload: String,
    created_at: u64,
    delivered: u8,
    updated_at: u64,
}

async fn insert<T: clickhouse::Row + Serialize>(c: Client, table: &str, rows: &[T]) -> bool {
    let mut ins = match c.insert(table) {
        Ok(i) => i,
        Err(e) => {
            warn!("{table}: insert: {e}");
            return false;
        }
    };
    for r in rows {
        if let Err(e) = ins.write(r).await {
            warn!("{table}: write: {e}");
            return false;
        }
    }
    match ins.end().await {
        Ok(()) => true,
        Err(e) => {
            warn!("{table}: commit: {e}");
            false
        }
    }
}

/// Saves an active-response action (new, or with a changed status).
pub async fn save_active_response(state: &AppState, r: &ActiveResponseRecord) {
    if !state.db.is_connected() {
        return;
    }
    let row = ArRow {
        id: r.id.clone(),
        triggered_at: r.triggered_at.timestamp_millis() as u64,
        agent_id: r.agent_id.clone(),
        command: r.command.clone(),
        target_ip: r.target_ip.clone(),
        reason: r.reason.clone(),
        duration_seconds: r.duration_seconds,
        status: r.status.clone(),
        updated_at: now_ms(),
    };
    insert(state.db.tenant_client(&tenant_of(state, &r.agent_id)), "siem_active_responses", &[row]).await;
}

/// Saves the current detections of one agent (a new snapshot).
pub async fn save_vulnerabilities(state: &AppState, agent_id: &str, detections: &[VulnItem]) {
    if !state.db.is_connected() {
        return;
    }
    let snapshot_at = now_ms();
    let mut rows: Vec<VulnRow> = detections
        .iter()
        .map(|d| VulnRow {
            snapshot_at,
            agent_id: agent_id.to_string(),
            cve_id: d.cve.clone(),
            package_name: d.package_name.clone(),
            severity: d.severity.to_ascii_lowercase(),
            status: d.status.clone(),
            detection: serde_json::to_string(d).unwrap_or_default(),
        })
        .collect();
    if rows.is_empty() {
        rows.push(VulnRow { snapshot_at, agent_id: agent_id.to_string(), cve_id: String::new(), package_name: String::new(), severity: String::new(), status: String::new(), detection: String::new() });
    }
    insert(state.db.tenant_client(&tenant_of(state, agent_id)), "siem_vulnerabilities", &rows).await;
}

/// Saves a queued command (`delivered` = false) or marks it fetched.
pub async fn save_commands(state: &AppState, agent_id: &str, commands: &[serde_json::Value], delivered: bool) {
    if !state.db.is_connected() || commands.is_empty() {
        return;
    }
    let t = now_ms();
    let rows: Vec<CmdRow> = commands
        .iter()
        .map(|c| CmdRow {
            agent_id: agent_id.to_string(),
            command_id: c.get("command_id").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            payload: c.to_string(),
            created_at: t,
            delivered: delivered as u8,
            updated_at: t,
        })
        .collect();
    insert(state.db.tenant_client(&tenant_of(state, agent_id)), "siem_agent_commands", &rows).await;
}

/// Loads the three lists from every tenant database (startup).
pub async fn load_all(state: &AppState) {
    if !state.db.is_connected() {
        return;
    }
    let mut dbs: Vec<String> = vec![tenancy::DEFAULT_DB.to_string()];
    for t in state.tenants.read().unwrap().iter().filter(|t| t.active) {
        let db = tenancy::tenant_db_name(&t.id);
        if !dbs.contains(&db) {
            dbs.push(db);
        }
    }
    let root = state.db.root().clone();
    let (mut ars, mut vulns, mut cmds) = (Vec::new(), Vec::new(), Vec::new());
    for db in &dbs {
        ensure_tables(&root, db).await;
        match root.query(&format!("SELECT ?fields FROM `{db}`.siem_active_responses FINAL ORDER BY triggered_at DESC")).fetch_all::<ArRow>().await {
            Ok(rows) => ars.extend(rows),
            Err(e) => warn!("{db}.siem_active_responses: {e}"),
        }
        let q = format!(
            "SELECT ?fields FROM `{db}`.siem_vulnerabilities WHERE detection != '' AND (agent_id, snapshot_at) IN \
             (SELECT agent_id, max(snapshot_at) FROM `{db}`.siem_vulnerabilities GROUP BY agent_id)"
        );
        match root.query(&q).fetch_all::<VulnRow>().await {
            Ok(rows) => vulns.extend(rows),
            Err(e) => warn!("{db}.siem_vulnerabilities: {e}"),
        }
        match root.query(&format!("SELECT ?fields FROM `{db}`.siem_agent_commands FINAL WHERE delivered = 0 ORDER BY created_at")).fetch_all::<CmdRow>().await {
            Ok(rows) => cmds.extend(rows),
            Err(e) => warn!("{db}.siem_agent_commands: {e}"),
        }
    }
    let (na, nv, nc) = (ars.len(), vulns.len(), cmds.len());
    {
        let mut list = state.active_responses.write().unwrap();
        list.clear();
        list.extend(ars.into_iter().map(|r| ActiveResponseRecord {
            id: r.id,
            command: r.command,
            target_ip: r.target_ip,
            agent_id: r.agent_id,
            reason: r.reason,
            triggered_at: chrono::DateTime::from_timestamp_millis(r.triggered_at as i64).unwrap_or_default(),
            duration_seconds: r.duration_seconds,
            status: r.status,
        }));
    }
    {
        let mut list = state.vulnerabilities.write().unwrap();
        list.clear();
        list.extend(vulns.iter().filter_map(|r| serde_json::from_str::<VulnItem>(&r.detection).ok()));
    }
    {
        let mut map = state.pending_commands.write().unwrap();
        map.clear();
        for r in cmds {
            if let Ok(v) = serde_json::from_str(&r.payload) {
                map.entry(r.agent_id).or_default().push(v);
            }
        }
    }
    info!("Loaded from ClickHouse: {na} active responses, {nv} vulnerability detections, {nc} queued agent commands ({} databases)", dbs.len());
}
