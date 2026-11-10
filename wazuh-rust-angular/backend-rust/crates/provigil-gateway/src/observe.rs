//! The stats listener: `/metrics`, `/state`, `/state/agents`, `/health`, `POST /shutdown`; a token
//! when it is not on loopback. Every minute one row in ClickHouse for the manager status page.

use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use provigil_agent_server::keys::ct_eq;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::watch;

use crate::core::Gw;
use crate::queue::now_ms;
use crate::server::OPEN;

/// Agents of one `/state/agents` page.
const PAGE: usize = 150;

pub const STATE_DDL: &str = "CREATE TABLE IF NOT EXISTS gateway_state (
    gateway_id String, host String, version String, started_at UInt64, updated_at UInt64, counters String
) ENGINE = ReplacingMergeTree(updated_at) ORDER BY gateway_id";

#[derive(clickhouse::Row, Serialize, Deserialize)]
pub struct StateRow {
    pub gateway_id: String,
    pub host: String,
    pub version: String,
    pub started_at: u64,
    pub updated_at: u64,
    pub counters: String,
}

pub fn state_row(gw: &Gw) -> StateRow {
    StateRow { gateway_id: gw.s.id.clone(), host: sysinfo::System::host_name().unwrap_or_default(), version: env!("CARGO_PKG_VERSION").to_string(), started_at: gw.started_ms, updated_at: now_ms(), counters: state(gw).to_string() }
}

fn gauges(gw: &Gw) -> Vec<(&'static str, f64)> {
    let (keys, registry, tenant_keys, _) = gw.cache.sizes();
    let (open, marks) = gw.queue.sizes();
    let e = &gw.engine;
    vec![
        ("uptime_seconds", now_ms().saturating_sub(gw.started_ms) as f64 / 1000.0),
        ("connections_open", OPEN.total.load(Relaxed) as f64),
        ("connections_open_grpc", OPEN.by_listener[0].load(Relaxed) as f64),
        ("connections_open_https", OPEN.by_listener[1].load(Relaxed) as f64),
        ("engine_behind", e.behind.load(Relaxed) as u8 as f64),
        ("engine_running", e.running.load(Relaxed) as u8 as f64),
        ("engine_lag", e.lag.load(Relaxed) as f64),
        ("engine_queue_usage", e.usage_permille.load(Relaxed) as f64 / 1000.0),
        ("engine_last_answer_age_seconds", now_ms().saturating_sub(e.last_answer_ms.load(Relaxed)) as f64 / 1000.0),
        ("commands_cached", open as f64),
        ("background_marks", marks as f64),
        ("background_jobs", (crate::core::JOBS_MAX - gw.jobs.capacity()) as f64),
        ("background_inventories", gw.inventory.iter().map(|l| l.max_capacity() - l.capacity()).sum::<usize>() as f64),
        ("cache_keys", keys as f64),
        ("cache_registry", registry as f64),
        ("cache_tenant_keys", tenant_keys as f64),
        ("cache_poll_age_seconds", now_ms().saturating_sub(gw.cache.last_poll_ms.load(Relaxed)) as f64 / 1000.0),
        ("agents_active", gw.agents.len() as f64),
    ]
}

fn state(gw: &Gw) -> serde_json::Value {
    let gauges: serde_json::Map<String, serde_json::Value> = gauges(gw).into_iter().map(|(k, v)| (k.to_string(), json!(v))).collect();
    let mut v = gw.stats.json();
    v["gauges"] = gauges.into();
    v["settings"] = gw.s.public();
    v
}

fn ready(gw: &Gw) -> bool {
    gw.cache.ready.load(Relaxed) && gw.engine.running.load(Relaxed) && !gw.stopping.load(Relaxed)
}

async fn metrics(State((gw, _)): State<App>) -> impl IntoResponse {
    ([("content-type", "text/plain; version=0.0.4")], gw.stats.metrics(&gauges(&gw)))
}

async fn state_route(State((gw, _)): State<App>) -> impl IntoResponse {
    Json(state(&gw))
}

#[derive(Deserialize)]
struct Page {
    #[serde(default)]
    last_id: String,
}

async fn state_agents(State((gw, _)): State<App>, Query(p): Query<Page>) -> impl IntoResponse {
    let (agents, more) = gw.agents.page(&p.last_id, PAGE);
    let items: Vec<_> = agents
        .iter()
        .map(|a| {
            json!({
                "id": a.id, "keepalives": a.keepalives.load(Relaxed), "events": a.events.load(Relaxed), "commands": a.commands.load(Relaxed),
                "results": a.results.load(Relaxed), "refusals": a.refusals.load(Relaxed), "last_seen_ms": a.last_seen_ms.load(Relaxed),
                "protocol": if a.protocol.load(Relaxed) == 1 { "grpc" } else { "https" }, "cloned_identity": a.flagged_clone.load(Relaxed),
            })
        })
        .collect();
    Json(json!({ "agents": items, "more": more }))
}

async fn health(State((gw, _)): State<App>) -> Response {
    let body = json!({ "ready": ready(&gw), "caches": gw.cache.ready.load(Relaxed), "engine": gw.engine.running.load(Relaxed), "stopping": gw.stopping.load(Relaxed) });
    (if ready(&gw) { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE }, Json(body)).into_response()
}

async fn shutdown(State((_, stop)): State<App>) -> impl IntoResponse {
    let _ = stop.send(true);
    Json(json!({ "status": "stopping" }))
}

async fn guard(State((gw, _)): State<App>, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request, next: Next) -> Response {
    let token = req.headers().get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or_default();
    if !peer.ip().to_canonical().is_loopback() && !ct_eq(token.as_bytes(), gw.s.internal_token.as_bytes()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(req).await
}

type App = (Arc<Gw>, Arc<watch::Sender<bool>>);

pub fn app(gw: Arc<Gw>, stop: watch::Sender<bool>) -> Router {
    let state: App = (gw, Arc::new(stop));
    Router::new()
        .route("/metrics", get(metrics))
        .route("/state", get(state_route))
        .route("/state/agents", get(state_agents))
        .route("/health", get(health))
        .route("/shutdown", post(shutdown))
        .layer(from_fn_with_state(state.clone(), guard))
        .with_state(state)
}
