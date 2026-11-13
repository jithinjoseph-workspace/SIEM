//! The routes of the agent listeners and the gate in front of them. The gate does every check that
//! needs only the headers, so nothing of a refused request's body is read or decoded.

use std::net::IpAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use http_body_util::Limited;
use provigil_agent_server::published;
use serde_json::{json, Value};
use tracing::warn;

use crate::agents::AgentRt;
use crate::cache::Authed;
use crate::core::{self, Gw, Refuse};
use crate::queue::now_ms;
use crate::server::Conn;
use crate::stats::Kind;

const CALL_LIMIT: Duration = Duration::from_secs(14);
pub const MAX_EVENTS: usize = 16 * 1024 * 1024;
const MAX_KEEPALIVE: usize = 64 * 1024;
const MAX_RESULT: usize = 1024 * 1024;
const MAX_ENROLL: usize = 16 * 1024;
const MAX_NONE: usize = 16 * 1024;
const CHUNK: usize = 1024 * 1024;
const GRPC_PREFIX: &str = "/provigil.agent.v1.AgentService/";

/// Which call a request is, its body limit, and the id its path names.
fn classify<'a>(method: &Method, path: &'a str) -> (Kind, usize, Option<&'a str>) {
    if let Some(call) = path.strip_prefix(GRPC_PREFIX) {
        return match call {
            "Enroll" => (Kind::Enroll, MAX_ENROLL, None),
            "Keepalive" => (Kind::Keepalive, MAX_KEEPALIVE, None),
            "Events" => (Kind::Events, MAX_EVENTS + 1024, None),
            "Result" => (Kind::Result, MAX_RESULT, None),
            "Config" => (Kind::Config, MAX_NONE, None),
            "Yara" => (Kind::Yara, MAX_NONE, None),
            "Upgrade" => (Kind::Upgrade, MAX_NONE, None),
            _ => (Kind::Other, MAX_NONE, None),
        };
    }
    let p = path.trim_end_matches('/');
    if matches!(p, "/api/v1/ingest" | "/api/events/ingest" | "/api/v1/events/ingest") {
        return (Kind::Events, MAX_EVENTS, None);
    }
    if p == "/api/v1/agents/enroll" {
        return (Kind::Enroll, MAX_ENROLL, None);
    }
    if p == "/api/v1/agent/state" {
        return (Kind::AgentState, MAX_NONE, None);
    }
    if matches!(p, "/api/v1/agent/commands" | "/api/v1/agent/commands/ack") {
        return (Kind::Legacy, MAX_NONE, None);
    }
    if method == Method::GET && p.starts_with("/downloads/") {
        return (Kind::Download, MAX_NONE, None);
    }
    if let Some(rest) = p.strip_prefix("/api/agents/") {
        if let Some(id) = rest.strip_suffix("/commands") {
            return (Kind::Legacy, MAX_NONE, Some(id));
        }
    }
    if let Some((id, op)) = p.strip_prefix("/api/v1/agents/").and_then(|r| r.split_once('/')) {
        return match op {
            "keepalive" => (Kind::Keepalive, MAX_KEEPALIVE, Some(id)),
            "response_result" => (Kind::Result, MAX_RESULT, Some(id)),
            "config" => (Kind::Config, MAX_NONE, Some(id)),
            "yara-rules" => (Kind::Yara, MAX_NONE, Some(id)),
            _ => (Kind::Other, MAX_NONE, None),
        };
    }
    (Kind::Other, MAX_NONE, None)
}

fn head<'a>(h: &'a HeaderMap, k: &str) -> Option<&'a str> {
    h.get(k).and_then(|v| v.to_str().ok())
}

/// The agent's key: `Authorization: Bearer`, or `X-Agent-Key`.
fn agent_key(h: &HeaderMap) -> Option<&str> {
    head(h, "authorization").and_then(|v| v.strip_prefix("Bearer ")).or(head(h, "x-agent-key"))
}

fn query_id(q: Option<&str>) -> Option<&str> {
    q?.split('&').find_map(|kv| kv.strip_prefix("agent_id="))
}

/// A status as gRPC (S13), the agent maps them back.
pub fn grpc_status(code: u16, msg: &str) -> tonic::Status {
    use tonic::Code;
    let c = match code {
        400 => Code::InvalidArgument,
        401 => Code::Unauthenticated,
        403 | 410 => Code::PermissionDenied,
        404 => Code::NotFound,
        409 => Code::AlreadyExists,
        412 => Code::FailedPrecondition,
        429 => Code::ResourceExhausted,
        503 => Code::Unavailable,
        _ => Code::Internal,
    };
    tonic::Status::new(c, msg)
}

/// The HTTP status of a finished call, gRPC's own codes taken back.
fn outcome(r: &Response) -> u16 {
    match head(r.headers(), "grpc-status") {
        None => r.status().as_u16(),
        Some("0") => 200,
        Some("3") => 400,
        Some("16") => 401,
        Some("7") => 403,
        Some("5") => 404,
        Some("6") => 409,
        Some("8") => 429,
        Some("14") => 503,
        Some(_) => 500,
    }
}

fn refused(grpc: bool, r: Refuse) -> Response {
    let msg = match r.0 {
        401 => "invalid agent key",
        404 => "agent removed",
        410 => "agent deactivated",
        429 => "come back later",
        503 => "not available, come back later",
        _ => r.1,
    };
    if grpc {
        return grpc_status(r.0, msg).into_http().map(Body::new);
    }
    let code = StatusCode::from_u16(r.0).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (code, Json(json!({ "status": "error", "message": msg }))).into_response()
}

/// Everything before the handler: readiness, keys, tenant, limits, body limit, time limit.
async fn gate(State(gw): State<Arc<Gw>>, mut req: Request, next: Next) -> Response {
    let grpc = head(req.headers(), "content-type").is_some_and(|c| c.starts_with("application/grpc"));
    let (kind, limit, path_id) = classify(req.method(), req.uri().path());
    let peer = req.extensions().get::<Conn>().cloned();
    let addr: IpAddr = peer.as_ref().map_or(IpAddr::from([127, 0, 0, 1]), |c| c.peer.ip());
    let now = now_ms();
    let refuse = |gw: &Gw, r: Refuse| {
        gw.stats.call(kind, r.0);
        refused(grpc, gw.refuse(r))
    };
    if !gw.cache.ready.load(Relaxed) && !matches!(kind, Kind::Download | Kind::Other) {
        return refuse(&gw, Refuse(503, "not_ready"));
    }
    if head(req.headers(), "content-length").and_then(|l| l.parse::<usize>().ok()).is_some_and(|l| l > limit) {
        return refuse(&gw, Refuse(413, "too_large"));
    }
    let tenant_key = head(req.headers(), "x-tenant-key").map(str::to_string);
    let key = agent_key(req.headers()).map(str::to_string);
    let claimed = path_id.map(str::to_string).or_else(|| head(req.headers(), "x-agent-id").map(str::to_string)).or_else(|| (kind == Kind::Legacy).then(|| query_id(req.uri().query()).map(str::to_string)).flatten());

    // held until the call ends
    let mut turn = None;
    match kind {
        Kind::Other => {}
        Kind::Enroll => {
            // no default tenant from any address: a key of a live tenant, or nothing
            if let Err(code) = gw.cache.tenant_of_key(tenant_key.as_deref()) {
                return refuse(&gw, Refuse(code, "tenant_key"));
            }
            if !gw.limits.enroll_addr.allow(addr, now) || !gw.limits.enroll_total.allow(now) {
                return refuse(&gw, Refuse(429, "enroll_rate"));
            }
        }
        Kind::AgentState => {
            if !gw.limits.state_addr.allow(addr, now) {
                return refuse(&gw, Refuse(429, "address_rate"));
            }
        }
        Kind::Download => {
            // an agent with its key fetches its upgrade; only strangers share the address's slots
            let agent = key.as_deref().is_some_and(|k| gw.cache.check(Some(k), None, None, addr).is_ok());
            if !agent {
                match gw.limits.downloads.take(addr) {
                    Some(slot) => {
                        req.extensions_mut().insert(Arc::new(slot));
                    }
                    None => return refuse(&gw, Refuse(429, "download_slots")),
                }
            }
        }
        _ => {
            let a = match gw.cache.check(key.as_deref(), claimed.as_deref(), tenant_key.as_deref(), addr) {
                Ok(a) => a,
                Err(code) => {
                    gw.stats.call(kind, code);
                    let what = format!("refused {code}: agent {} from {addr}", claimed.as_deref().unwrap_or("?"));
                    if code == 401 {
                        tracing::debug!("{what}");
                    } else {
                        warn!("{what}");
                    }
                    return refused(grpc, Refuse(code, "agent"));
                }
            };
            let rt = gw.agents.get(&a.id);
            rt.last_seen_ms.store(now, Relaxed);
            if let Some(other) = rt.on_peer(addr, now) {
                gw.stats.c.cloned_identities.fetch_add(1, Relaxed);
                warn!("agent {}: the same key from {addr} and {other} within a minute", a.id);
            }
            if let Some(c) = &peer {
                rt.on_connection(c.id, &c.close);
            }
            rt.protocol.store(if grpc { 1 } else { 2 }, Relaxed);
            match kind {
                Kind::Keepalive if !rt.keepalive_allowed(now) => {
                    rt.refusals.fetch_add(1, Relaxed);
                    return refuse(&gw, Refuse(429, "keepalive_rate"));
                }
                Kind::Events => {
                    if !rt.eps_allowed(gw.s.agent_max_eps, Instant::now()) {
                        rt.refusals.fetch_add(1, Relaxed);
                        return refuse(&gw, Refuse(429, "agent_eps"));
                    }
                    turn = rt.events_turn();
                    if turn.is_none() {
                        rt.refusals.fetch_add(1, Relaxed);
                        return refuse(&gw, Refuse(429, "events_in_flight"));
                    }
                }
                _ => {}
            }
            req.extensions_mut().insert(a);
            req.extensions_mut().insert(rt);
        }
    }

    let req = req.map(|b| Body::new(Limited::new(b, limit)));
    let r = tokio::time::timeout(CALL_LIMIT, next.run(req)).await;
    drop(turn);
    let r = match r {
        Ok(r) => r,
        Err(_) => {
            gw.stats.c.time_limits.fetch_add(1, Relaxed);
            return refuse(&gw, Refuse(503, "time_limit"));
        }
    };
    gw.stats.call(kind, outcome(&r));
    r
}

fn plain(r: Refuse) -> Response {
    refused(false, r)
}

/// `POST /api/v1/agents/enroll`
async fn enroll(State(gw): State<Arc<Gw>>, Extension(c): Extension<Conn>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let tk = head(&headers, "x-tenant-key").unwrap_or_default();
    match core::enroll(&gw, &body, tk, &c.peer.ip().to_string()).await {
        Ok(v) => Json(v).into_response(),
        Err((code, msg)) => (StatusCode::from_u16(code).unwrap_or(StatusCode::SERVICE_UNAVAILABLE), Json(json!({ "status": "error", "message": msg }))).into_response(),
    }
}

/// `POST /api/v1/agents/:id/keepalive`
async fn keepalive(State(gw): State<Arc<Gw>>, Extension(a): Extension<Authed>, Extension(rt): Extension<Arc<AgentRt>>, body: Bytes) -> Response {
    match core::keepalive(&gw, &a, &rt, &body) {
        Ok(c) => {
            let commands: Vec<Value> = c.iter().filter_map(|c| serde_json::from_str(c).ok()).collect();
            Json(json!({ "status": "success", "agent_id": a.id, "commands": commands })).into_response()
        }
        Err(r) => plain(r),
    }
}

/// The body forms: a list, an object with `events`, or one event.
fn body_events(payload: Value) -> (String, Vec<Value>) {
    match payload {
        Value::Array(a) => (String::new(), a),
        Value::Object(mut o) => {
            let batch = o.get("batch_id").and_then(Value::as_str).unwrap_or_default().to_string();
            match o.remove("events") {
                Some(Value::Array(a)) => (batch, a),
                other => {
                    if let Some(e) = other {
                        o.insert("events".into(), e);
                    }
                    (String::new(), vec![Value::Object(o)])
                }
            }
        }
        other => (String::new(), vec![other]),
    }
}

/// `POST /api/v1/events/ingest` (and its other two spellings)
async fn ingest(State(gw): State<Arc<Gw>>, Extension(a): Extension<Authed>, Extension(rt): Extension<Arc<AgentRt>>, body: Bytes) -> Response {
    let Ok(payload) = serde_json::from_slice::<Value>(&body) else { return plain(Refuse(400, "not JSON")) };
    let (batch, items) = body_events(payload);
    match core::events(&gw, &a, &rt, &batch, items).await {
        Ok(_) => Json(Value::Null).into_response(),
        Err(r) => plain(r),
    }
}

/// `POST /api/v1/agents/:id/response_result`
async fn result(State(gw): State<Arc<Gw>>, Extension(a): Extension<Authed>, Extension(rt): Extension<Arc<AgentRt>>, body: Bytes) -> Response {
    let Ok(v) = serde_json::from_slice::<Value>(&body) else { return plain(Refuse(400, "not JSON")) };
    match core::result(&gw, &a, &rt, &v) {
        Ok(()) => Json(json!({ "status": "acknowledged", "agent_id": a.id })).into_response(),
        Err(r) => plain(r),
    }
}

/// `GET /api/v1/agents/:id/config`
async fn config(State(gw): State<Arc<Gw>>, Extension(a): Extension<Authed>) -> Response {
    match core::config(&gw, &a) {
        Ok(v) => Json(v).into_response(),
        Err(r) => plain(r),
    }
}

/// `GET /api/v1/agents/:id/yara-rules`
async fn yara(State(gw): State<Arc<Gw>>) -> Response {
    match core::yara(&gw).await {
        Ok(b) => ([(header::CONTENT_TYPE, "application/octet-stream")], b).into_response(),
        Err(r) => r_code(r),
    }
}

fn r_code(r: Refuse) -> Response {
    StatusCode::from_u16(r.0).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR).into_response()
}

/// Legacy fetch, by `?agent_id=` or by path: the commands, taken.
async fn legacy_commands(State(gw): State<Arc<Gw>>, Extension(a): Extension<Authed>) -> Response {
    Json(core::legacy_commands(&gw, &a)).into_response()
}

/// Legacy ack: only logged; it needs the agent's key now.
async fn legacy_ack(Extension(a): Extension<Authed>, Json(v): Json<Value>) -> Response {
    tracing::info!("Command ack from agent {}: {v}", a.id);
    Json(json!({ "status": "acknowledged" })).into_response()
}

#[derive(serde::Deserialize)]
struct StateQuery {
    agent_id: String,
}

/// `GET /api/v1/agent/state?agent_id=`
async fn agent_state_route(State(gw): State<Arc<Gw>>, Query(q): Query<StateQuery>) -> Response {
    let st = match gw.cache.registered(&q.agent_id) {
        Some(r) if r.deleted => "deleted",
        Some(r) if r.disabled => "deactivated",
        _ => "active",
    };
    Json(json!({ "agent_id": q.agent_id, "state": st })).into_response()
}

/// `file` in 1 MiB chunks, read as the client takes them; `hold` lives as long as the download.
pub fn file_chunks<H: Send + 'static>(file: tokio::fs::File, hold: H) -> impl futures_util::Stream<Item = std::io::Result<Vec<u8>>> + Send {
    futures_util::stream::unfold(Some((file, hold)), |state| async move {
        use tokio::io::AsyncReadExt;
        let (mut f, hold) = state?;
        let mut data = Vec::with_capacity(CHUNK);
        match (&mut f).take(CHUNK as u64).read_to_end(&mut data).await {
            Ok(0) => None,
            Ok(_) => Some((Ok(data), Some((f, hold)))),
            Err(e) => Some((Err(e), None)),
        }
    })
}

async fn send_file(path: std::path::PathBuf, name: &str, slot: Option<Extension<Arc<crate::limits::Slot>>>) -> Response {
    let Ok(file) = tokio::fs::File::open(&path).await else { return StatusCode::NOT_FOUND.into_response() };
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let body = Body::from_stream(file_chunks(file, slot));
    let mut r = Response::new(body);
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    r
}

async fn download_package(gw: &Gw, name: &str, slot: Option<Extension<Arc<crate::limits::Slot>>>) -> Response {
    match core::package_file(gw, name, "").await {
        Ok(p) => send_file(p, name, slot).await,
        Err(r) => r_code(r),
    }
}

/// `GET /downloads/provigil-agent.exe`
async fn download_agent(State(gw): State<Arc<Gw>>, slot: Option<Extension<Arc<crate::limits::Slot>>>) -> Response {
    download_package(&gw, published::AGENT_EXE, slot).await
}

/// `GET /downloads/windows/:file`: the package, and the Sysmon configuration of the deploy script.
async fn download_windows(State(gw): State<Arc<Gw>>, Path(file): Path<String>, slot: Option<Extension<Arc<crate::limits::Slot>>>) -> Response {
    if file == "sysmon.xml" {
        return ([(header::CONTENT_TYPE, "application/xml; charset=utf-8")], include_str!("../../siem-api/src/sysmon.xml")).into_response();
    }
    download_package(&gw, &file, slot).await
}

/// The first of `paths` that exists (the published copy, else the build's).
fn first_file(paths: &[std::path::PathBuf]) -> std::path::PathBuf {
    paths.iter().find(|p| p.is_file()).unwrap_or(&paths[0]).clone()
}

/// `GET /downloads/provigil-agent-linux`, `/downloads/siem-agent-linux`, and `/downloads/install.sh`:
/// the Linux deploy script's files.
async fn download_linux(State(gw): State<Arc<Gw>>, slot: Option<Extension<Arc<crate::limits::Slot>>>) -> Response {
    let path = first_file(&[
        gw.s.dist.join("linux").join("provigil-agent-linux"),
        gw.s.dist.join("linux").join("provigil-agent"),
        "target/x86_64-unknown-linux-gnu/release/provigil-agent".into(),
        "target/x86_64-unknown-linux-gnu/debug/provigil-agent".into(),
        gw.s.dist.join("linux").join("siem-agent-linux"),
        "target/release/siem-agent-linux".into(),
        "target/debug/siem-agent-linux".into(),
    ]);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("provigil-agent-linux")
        .to_string();
    send_file(path, &name, slot).await
}

async fn download_install(State(gw): State<Arc<Gw>>, slot: Option<Extension<Arc<crate::limits::Slot>>>) -> Response {
    let path = first_file(&[gw.s.dist.join("linux").join("install.sh"), "crates/siem-agent-linux/install.sh".into()]);
    send_file(path, "install.sh", slot).await
}

/// `GET /downloads/sca/:file`: an assessment policy the Linux deploy script fetches, from the
/// ruleset's policy folders.
async fn download_sca(Path(file): Path<String>, slot: Option<Extension<Arc<crate::limits::Slot>>>) -> Response {
    if file.is_empty() || file.contains("..") || file.contains(['/', '\\']) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let found = std::fs::read_dir("ruleset/sca").into_iter().flatten().flatten().map(|d| d.path().join(&file)).find(|p| p.is_file());
    match found {
        Some(p) => send_file(p, &file, slot).await,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The agent listeners' routes: gRPC and HTTPS, on either port.
pub fn app(gw: Arc<Gw>) -> Router {
    let grpc = provigil_proto::AgentServiceServer::new(crate::grpc::Service(gw.clone())).max_decoding_message_size(MAX_EVENTS).max_encoding_message_size(MAX_EVENTS);
    Router::new()
        .route("/api/v1/agents/enroll", post(enroll))
        .route("/api/v1/agents/:id/keepalive", post(keepalive))
        .route("/api/v1/agents/:id/response_result", post(result))
        .route("/api/v1/agents/:id/config", get(config))
        .route("/api/v1/agents/:id/yara-rules", get(yara))
        .route("/api/v1/ingest", post(ingest))
        .route("/api/events/ingest", post(ingest))
        .route("/api/v1/events/ingest", post(ingest))
        .route("/api/v1/agent/commands", get(legacy_commands))
        .route("/api/agents/:id/commands", get(legacy_commands))
        .route("/api/v1/agent/commands/ack", post(legacy_ack))
        .route("/api/v1/agent/state", get(agent_state_route))
        .route("/downloads/provigil-agent.exe", get(download_agent))
        .route("/downloads/windows/:file", get(download_windows))
        .route("/downloads/provigil-agent-linux", get(download_linux))
        .route("/downloads/siem-agent-linux", get(download_linux))
        .route("/downloads/install.sh", get(download_install))
        .route("/downloads/sca/:file", get(download_sca))
        .route_service("/provigil.agent.v1.AgentService/*call", grpc)
        // the gate holds each route to its own size
        .layer(DefaultBodyLimit::disable())
        .layer(from_fn_with_state(gw.clone(), gate))
        .with_state(gw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_by_path() {
        let g = Method::GET;
        let p = Method::POST;
        assert_eq!(classify(&p, "/api/v1/agents/007/keepalive"), (Kind::Keepalive, MAX_KEEPALIVE, Some("007")));
        assert_eq!(classify(&p, "/api/v1/agents/007/response_result").0, Kind::Result);
        assert_eq!(classify(&g, "/api/v1/agents/007/yara-rules").0, Kind::Yara);
        assert_eq!(classify(&p, "/api/v1/events/ingest").1, MAX_EVENTS);
        assert_eq!(classify(&p, "/api/events/ingest").0, Kind::Events);
        assert_eq!(classify(&p, "/provigil.agent.v1.AgentService/Events").0, Kind::Events);
        assert_eq!(classify(&p, "/api/v1/agents/enroll"), (Kind::Enroll, MAX_ENROLL, None));
        assert_eq!(classify(&g, "/api/agents/7/commands"), (Kind::Legacy, MAX_NONE, Some("7")));
        assert_eq!(classify(&g, "/downloads/windows/netsh.exe").0, Kind::Download);
        assert_eq!(classify(&g, "/api/v1/agents").0, Kind::Other, "the console stays on siem-api");
    }

    #[test]
    fn statuses_as_the_agent_maps_them() {
        use tonic::Code::*;
        for (code, want) in [(400, InvalidArgument), (401, Unauthenticated), (403, PermissionDenied), (410, PermissionDenied), (404, NotFound), (409, AlreadyExists), (412, FailedPrecondition), (429, ResourceExhausted), (503, Unavailable), (500, Internal)] {
            assert_eq!(grpc_status(code, "").code(), want, "{code}");
        }
    }

    #[test]
    fn body_forms() {
        assert_eq!(body_events(json!([{ "a": 1 }])).1.len(), 1);
        let (b, e) = body_events(json!({ "batch_id": "b", "events": [{}, {}] }));
        assert_eq!((b.as_str(), e.len()), ("b", 2));
        assert_eq!(body_events(json!({ "event_type": "x" })).1.len(), 1);
    }
}
