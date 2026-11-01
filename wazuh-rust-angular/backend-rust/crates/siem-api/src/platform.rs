//! The platform endpoints the shared UI also asks the NDR engine for, answered
//! with what this SIEM really has (they used to return sample data):
//! `/api/health`, `/api/admin/engines` (+ `/scale`), `/api/admin/leader-status`,
//! `/api/interfaces`, `/api/agent-status`, and the NDR sensor keys. NDR sensors
//! are managed by the NDR engine: here they are listed from ClickHouse
//! (`sensor_keys`, `ndr_events`), and changing them says so instead of
//! pretending it worked.

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};

use crate::tenancy::{self, AuthCtx};
use crate::AppState;

fn started() -> &'static std::time::Instant {
    static S: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    S.get_or_init(std::time::Instant::now)
}

/// Called at startup so uptimes count from there.
pub fn mark_start() {
    started();
    host();
}

fn uptime() -> String {
    let s = started().elapsed().as_secs();
    format!("{}d {}h {}m", s / 86_400, (s / 3600) % 24, (s / 60) % 60)
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "siem-api".into())
}

/// Agents of the caller's tenant (all of them for a platform admin without a tenant picked).
fn agents_in_scope(state: &AppState, ctx: &AuthCtx) -> (usize, usize) {
    let owners = state.agent_tenants.read().unwrap().clone();
    let t = ctx.scope();
    let agents = state.agents.read().unwrap();
    let mine: Vec<_> = agents.values().filter(|a| tenancy::tenant_of(&owners, &a.id) == t).collect();
    (mine.len(), mine.iter().filter(|a| matches!(a.status, siem_core::AgentStatus::Active)).count())
}

/// `GET /api/health`
pub async fn health(State(state): State<AppState>, ctx: Option<Extension<AuthCtx>>) -> Json<Value> {
    // polled by every open page (navbar, every 10 s): counts only, never the rows
    let (counts, active) = match &ctx {
        Some(Extension(c)) => (crate::history::counts(&state, c, crate::history::DEFAULT_HOURS).await, agents_in_scope(&state, c).1),
        None => (Default::default(), 0),
    };
    let ch = state.db.is_connected() && state.db.root().query("SELECT 1").fetch_one::<u8>().await.is_ok();
    Json(json!({
        "status": "ok",
        "events_total": counts.events,
        "hits_total": counts.alerts(),
        "events_1h": counts.events_1h,
        // the SIEM's sessions are its connected agents
        "sessions": active,
        "sigma_rules": crate::sigma::rule_count(),
        "services": {
            "kafka": "not used",
            "engine": "running",
            "clickhouse": if ch { "running" } else { "stopped" },
            "valkey": if tenancy::valkey_ok().await { "running" } else { "stopped" },
            "wazuh_manager": if !crate::wazuh_manager::enabled() { "not used" } else if crate::wazuh_manager::running().is_empty() { "stopped" } else { "running" },
        }
    }))
}

/// CPU and memory, sampled every 5 s (a CPU reading needs two samples apart).
fn host() -> &'static std::sync::Mutex<(f32, u64, u64)> {
    static H: std::sync::OnceLock<std::sync::Mutex<(f32, u64, u64)>> = std::sync::OnceLock::new();
    H.get_or_init(|| {
        std::thread::spawn(|| {
            let mut sys = sysinfo::System::new();
            loop {
                sys.refresh_cpu_usage();
                sys.refresh_memory();
                *host().lock().unwrap() = (sys.global_cpu_info().cpu_usage(), sys.used_memory(), sys.total_memory());
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        });
        std::sync::Mutex::new((0.0, 0, 0))
    })
}

/// `GET /api/admin/telemetry` (platform admins): this machine's CPU and memory, and the event rate.
pub async fn telemetry(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    if !ctx.is_super() {
        return (StatusCode::FORBIDDEN, Json(json!({ "status": "error", "message": "Platform admins only" }))).into_response();
    }
    let (cpu, used, total) = *host().lock().unwrap();
    let gb = |b: u64| b as f64 / 1_073_741_824.0;
    let hour_ago = (chrono::Utc::now().timestamp_millis().max(0) as u64).saturating_sub(3_600_000);
    let mut events_1h = 0u64;
    for t in crate::predictions::tenant_ids(&state) {
        events_1h += state.db.tenant_client(&t).query("SELECT count() FROM siem_events WHERE timestamp >= ?").bind(hour_ago).fetch_one::<u64>().await.unwrap_or(0);
    }
    Json(json!({
        "status": "ok", "cpu_usage_percent": cpu, "memory_used_gb": gb(used), "memory_total_gb": gb(total),
        "memory_percent": if total > 0 { used as f64 * 100.0 / total as f64 } else { 0.0 },
        "events_per_sec": events_1h / 3600, "events_1h": events_1h, "uptime_seconds": started().elapsed().as_secs(),
    }))
    .into_response()
}

/// `GET /api/monitor/kafka`: the SIEM does not use Kafka.
pub async fn kafka() -> Json<Value> {
    Json(json!({ "connected": false, "used": false, "brokers_online": 0, "total_brokers": 0, "lag": 0, "topics": [], "message": "This SIEM reads the Wazuh manager's files directly; it has no Kafka" }))
}

/// `GET /api/scale-status`: one node.
pub async fn scale_status() -> Json<Value> {
    Json(json!({ "status": "standalone", "nodes": 1, "capacity_percent": host().lock().unwrap().0.round() }))
}

/// `GET /api/admin/engines`: siem-api, each Wazuh manager daemon, ClickHouse and Valkey.
pub async fn engines(State(state): State<AppState>) -> Json<Value> {
    let mut engines = vec![json!({ "name": "siem-api", "status": format!("Up {}", uptime()), "running": "true", "host": hostname(), "version": env!("CARGO_PKG_VERSION"), "sigma_rules": crate::sigma::rule_count() })];
    if crate::wazuh_manager::enabled() {
        let running = crate::wazuh_manager::running();
        for d in crate::wazuh_manager::daemons() {
            let up = running.iter().any(|r| r == d);
            engines.push(json!({ "name": d, "status": if up { "Up" } else { "Exited" }, "running": up.to_string() }));
        }
    }
    let version = state.db.root().query("SELECT version()").fetch_one::<String>().await.ok();
    engines.push(json!({ "name": "clickhouse", "status": version.as_ref().map_or("Unreachable".to_string(), |v| format!("Up (ClickHouse {v})")), "running": version.is_some().to_string() }));
    let valkey = tenancy::valkey_ok().await;
    engines.push(json!({ "name": "valkey", "status": if valkey { "Up" } else { "Unreachable" }, "running": valkey.to_string() }));
    let n = engines.len();
    Json(json!({ "status": "ok", "engines": engines, "count": n }))
}

/// `POST /api/admin/engines/scale`: this SIEM has no engine pool to scale.
pub async fn scale() -> axum::response::Response {
    (StatusCode::CONFLICT, Json(json!({ "status": "error", "message": "This SIEM runs as one siem-api process with its Wazuh manager daemons; there are no engine replicas to scale. Run more siem-api instances behind the load balancer instead." }))).into_response()
}

/// `GET /api/admin/leader-status`: one node, always its own leader.
pub async fn leader() -> Json<Value> {
    Json(json!({ "is_leader": true, "term": 0, "leader_id": hostname(), "active_nodes": 1, "cluster_size": 1, "election_state": "Standalone" }))
}

/// `GET /api/interfaces`: this machine's network interfaces.
pub async fn interfaces() -> Json<Vec<String>> {
    let mut names: Vec<String> = local_ip_address::list_afinet_netifas().map(|l| l.into_iter().map(|(n, _)| n).collect()).unwrap_or_default();
    names.sort();
    names.dedup();
    Json(names)
}

/// `GET /api/agent-status`
pub async fn agent_status(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let (all, active) = agents_in_scope(&state, &ctx);
    Json(json!({ "running": true, "connected": crate::wazuh_manager::enabled() && !crate::wazuh_manager::running().is_empty(), "agents_count": all, "active_count": active }))
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct SensorRow {
    id: String,
    key_prefix: String,
    tenant_id: String,
    name: String,
    hostname: String,
    interface_name: String,
    os_name: String,
    agent_z_status: String,
    agent_s_status: String,
    vector_status: String,
    arkime_status: String,
    arkime_url: String,
    active: u8,
    created_at: u32,
    last_seen: u32,
}

fn iso(ts: u32) -> String {
    chrono::DateTime::from_timestamp(ts as i64, 0).map(|d| d.to_rfc3339()).unwrap_or_default()
}

/// `GET /api/sensor-keys`: the NDR sensors registered for the tenant (no key material).
pub async fn sensor_keys(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let rows = state
        .db
        .tenant_client(&ctx.scope())
        .query("SELECT id, key_prefix, tenant_id, name, hostname, interface_name, os_name, agent_z_status, agent_s_status, vector_status, arkime_status, arkime_url, active, toUInt32(created_at) AS created_at, toUInt32(last_seen) AS last_seen FROM sensor_keys FINAL ORDER BY created_at DESC")
        .fetch_all::<SensorRow>()
        .await
        .unwrap_or_default();
    let keys: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id, "key_prefix": r.key_prefix, "tenant_id": r.tenant_id, "name": r.name, "hostname": r.hostname,
                "interface": r.interface_name, "os": r.os_name, "agent-z": r.agent_z_status, "agent-s": r.agent_s_status,
                "vector": r.vector_status, "arkime": r.arkime_status, "arkime_url": r.arkime_url, "active": r.active == 1,
                "created_at": iso(r.created_at), "last_seen": iso(r.last_seen),
            })
        })
        .collect();
    Json(json!({ "status": "ok", "keys": keys }))
}

/// `GET /api/sensor-keys/event-counts`: events per sensor in the last hour.
pub async fn sensor_event_counts(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let rows = state
        .db
        .tenant_client(&ctx.scope())
        .query("SELECT sensor_id, count() FROM ndr_events WHERE sensor_id != '' AND timestamp >= now() - INTERVAL 1 HOUR GROUP BY sensor_id")
        .fetch_all::<(String, u64)>()
        .await
        .unwrap_or_default();
    Json(json!({ "status": "ok", "counts": rows.into_iter().collect::<std::collections::HashMap<_, _>>() }))
}

/// `GET /api/sensor-keys/recent-ips`: the latest source IP each sensor reported.
pub async fn sensor_recent_ips(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let rows = state
        .db
        .tenant_client(&ctx.scope())
        .query("SELECT sensor_id, argMax(src_ip, timestamp) FROM ndr_events WHERE sensor_id != '' AND src_ip != '' GROUP BY sensor_id")
        .fetch_all::<(String, String)>()
        .await
        .unwrap_or_default();
    Json(json!({ "status": "ok", "ips": rows.into_iter().collect::<std::collections::HashMap<_, _>>() }))
}

/// Creating, revoking, reactivating or controlling NDR sensors: the NDR engine's job.
pub async fn sensors_managed_by_ndr() -> axum::response::Response {
    (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "status": "error", "message": "NDR sensors are managed by the NDR engine, which does not answer here. Start the NDR engine (or route /api/sensor-keys to it) to add or change sensors." }))).into_response()
}

#[cfg(test)]
mod tests {
    #[test]
    fn uptime_text() {
        super::mark_start();
        assert!(super::uptime().starts_with("0d 0h"));
        assert!(!super::interfaces_sync().is_empty(), "this machine has at least one interface");
    }
}

#[cfg(test)]
fn interfaces_sync() -> Vec<String> {
    local_ip_address::list_afinet_netifas().map(|l| l.into_iter().map(|(n, _)| n).collect()).unwrap_or_default()
}
