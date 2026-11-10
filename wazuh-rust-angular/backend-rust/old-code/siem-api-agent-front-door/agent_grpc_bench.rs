//! Benchmarks of the agent gRPC transport against the HTTPS routes (`#[ignore]`, run by hand):
//!
//! cargo test --release -p siem-api --bin siem-api agent_grpc::bench:: -- --ignored --nocapture --test-threads=1
//!
//! The servers run in a child process (this test binary again, `server_child`), so its memory
//! and CPU are the server's alone. Nothing here talks to the services running on this PC: the
//! state is the tests' (ClickHouse unreachable, manager off, a temp home with a stub provigil-db).

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use provigil_proto::*;
use serde_json::{json, Value};
use tonic::transport::{server::TcpIncoming, Endpoint, Server};
use tonic::{Request, Response, Status};

use crate::AppState;

const LIMIT: Duration = Duration::from_secs(15); // the agent's REQUEST_LIMIT

// ---------- the server side (child process) ----------

fn home() -> PathBuf {
    std::env::temp_dir().join(format!("pv-grpc-bench-{}", std::process::id()))
}

fn bench_exe() -> Option<PathBuf> {
    Some(home().join("provigil-agent.exe"))
}

/// A provigil-db stand-in on the Windows port file of `queue/db/wdb`: answers `ok []` after
/// `delay`, and counts the queries.
async fn stub_wdb(delay: Duration, count: Arc<AtomicU64>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = home().join("queue").join("db");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("wdb.port"), l.local_addr().unwrap().port().to_string()).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let count = count.clone();
            tokio::spawn(async move {
                while siem_ipc::framing::recv(&mut s, 1 << 20).await.is_ok() {
                    count.fetch_add(1, Ordering::Relaxed);
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    if siem_ipc::framing::send(&mut s, b"ok []\0").await.is_err() {
                        return;
                    }
                }
            });
        }
    });
}

pub(crate) async fn state() -> AppState {
    // PV_BENCH_CLICKHOUSE: a private ClickHouse for the stream bench, never the live one
    std::env::set_var("CLICKHOUSE_URL", std::env::var("PV_BENCH_CLICKHOUSE").unwrap_or_else(|_| "http://127.0.0.1:1".into()));
    std::env::set_var("PROVIGIL_MANAGER", "0");
    std::env::set_var("PROVIGIL_MANAGER_HOME", home());
    state_with(crate::db::ClickHouseDb::init().await)
}

/// A state that leaves the process environment alone (tests run side by side).
pub(crate) fn state_with(db: crate::db::ClickHouseDb) -> AppState {
    let (broadcast_tx, _) = tokio::sync::broadcast::channel(16);
    let tmp = |n: &str| home().join(format!("{n}.json"));
    AppState {
        engine: siem_engine::AnalysisEngine::new(),
        events: Arc::new(RwLock::new(Vec::new())),
        alerts: Arc::new(RwLock::new(Vec::new())),
        agents: Arc::new(RwLock::new(HashMap::new())),
        broadcast_tx,
        pending_commands: Arc::new(RwLock::new(HashMap::new())),
        db,
        wdb: Arc::new(siem_wdb::ProVigilDbManager::new()),
        threat_intel: Arc::new(siem_cdb::ThreatIntelManager::new()),
        active_responses: Arc::new(RwLock::new(Vec::new())),
        parser_registry: Arc::new(siem_parser_gen::DynamicParserRegistry::new("")),
        parser_tenants: Arc::new(RwLock::new(HashMap::new())),
        auth_keystore: Arc::new(RwLock::new(siem_crypto::keys::KeyStore::new())),
        tenants: Arc::new(RwLock::new(Vec::new())),
        agent_keys: Arc::new(crate::tenancy::AgentKeys::new()),
        agent_tenants: Arc::new(RwLock::new(HashMap::new())),
        enrolled: Arc::new(RwLock::new(HashMap::new())),
        max_agent_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        deleted_agents: Arc::new(RwLock::new(std::collections::HashSet::new())),
        deleted_agent_names: Arc::new(RwLock::new(std::collections::HashSet::new())),
        risk_fabric: Arc::new(siem_risk_fabric::RiskFabricEngine::new("")),
        redswarm: Arc::new(siem_redswarm::RedSwarmService::new()),
        intent_engine: Arc::new(siem_intent_engine::IntentEngine::new(tmp("intent"))),
        deception_engine: Arc::new(siem_deception::DeceptionEngine::new(tmp("deception"))),
    }
}

/// Answers every call at once (the transport alone).
struct Noop;

#[tonic::async_trait]
impl AgentService for Noop {
    async fn enroll(&self, _: Request<EnrollRequest>) -> Result<Response<EnrollReply>, Status> {
        Ok(Response::new(EnrollReply::default()))
    }
    async fn keepalive(&self, _: Request<KeepaliveRequest>) -> Result<Response<KeepaliveReply>, Status> {
        Ok(Response::new(KeepaliveReply::default()))
    }
    async fn events(&self, r: Request<EventsRequest>) -> Result<Response<EventsReply>, Status> {
        Ok(Response::new(EventsReply { accepted: r.get_ref().events_json.len() as u32 }))
    }
    async fn result(&self, _: Request<ResultRequest>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }
    async fn config(&self, _: Request<ConfigRequest>) -> Result<Response<ConfigReply>, Status> {
        Ok(Response::new(ConfigReply::default()))
    }
    async fn yara(&self, _: Request<YaraRequest>) -> Result<Response<YaraReply>, Status> {
        Ok(Response::new(YaraReply::default()))
    }
    async fn upgrade(&self, _: Request<UpgradeChunkRequest>) -> Result<Response<ChunkStream>, Status> {
        Err(Status::unimplemented(""))
    }
}

async fn listener() -> (tokio::net::TcpListener, u16) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    (l, p)
}

/// The servers as siem-api runs them: gRPC (`server()`, default `Server::builder()`) and the
/// HTTPS routes (the same handlers and auth middleware, axum::serve), plus no-op twins.
async fn start_servers(state: AppState) -> [u16; 4] {
    let (l, grpc) = listener().await;
    let inc = TcpIncoming::from_listener(l, true, None).unwrap();
    tokio::spawn(Server::builder().add_service(super::server(state.clone(), bench_exe)).serve_with_incoming(inc));

    let app = axum::Router::new()
        .route("/api/v1/events/ingest", axum::routing::post(crate::ingest_event))
        .route("/api/v1/agents/:id/keepalive", axum::routing::post(crate::post_agent_keepalive_handler))
        .route("/api/v1/agents/enroll", axum::routing::post(crate::post_agent_enroll_handler))
        .route("/api/v1/agents/:id/config", axum::routing::get(crate::agent_config::get))
        .layer(axum::middleware::from_fn_with_state(state.clone(), crate::tenancy::auth_middleware))
        // what the console and the install script ask (a signed-in analyst of the agents' tenant)
        .merge(
            axum::Router::new()
                .route("/api/v1/agents", axum::routing::get(crate::get_agents))
                .layer(axum::Extension(crate::tenancy::AuthCtx { username: "bench".into(), role: "analyst".into(), tenant_id: "default".into(), permissions: vec![], features: vec![], requested_tenant: None })),
        )
        .route("/api/server-info", axum::routing::get(crate::get_server_info_handler))
        .with_state(state.clone());
    let (l, http) = listener().await;
    tokio::spawn(async move { axum::serve(l, app).await });

    let (l, grpc_noop) = listener().await;
    let inc = TcpIncoming::from_listener(l, true, None).unwrap();
    tokio::spawn(Server::builder().add_service(AgentServiceServer::new(Noop).max_decoding_message_size(16 << 20)).serve_with_incoming(inc));

    let noop = axum::Router::new()
        .route("/api/v1/events/ingest", axum::routing::post(|_: axum::Json<Value>| async { "{}" }))
        .route("/api/v1/agents/:id/keepalive", axum::routing::post(|_: axum::body::Bytes| async { r#"{"commands":[]}"# }));
    let (l, http_noop) = listener().await;
    tokio::spawn(async move { axum::serve(l, noop).await });
    [grpc, http, grpc_noop, http_noop]
}

/// The server process: prints `READY <grpc> <http> <grpc_noop> <http_noop> <tenant key>`, runs until stdin closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore]
async fn server_child() {
    if std::env::var("BENCH_CHILD").is_err() {
        return;
    }
    let _ = std::fs::remove_dir_all(home());
    std::fs::create_dir_all(home()).unwrap();
    let delay = std::env::var("BENCH_WDB_DELAY_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let wdb_queries = Arc::new(AtomicU64::new(0));
    if std::env::var("BENCH_WDB_DOWN").is_err() {
        stub_wdb(Duration::from_millis(delay), wdb_queries.clone()).await;
    }
    let mut exe = b"MZ provigil-agent-version:9.9.9 ".to_vec();
    exe.resize(20 << 20, 7);
    std::fs::write(bench_exe().unwrap(), &exe).unwrap();
    let state = state().await;
    let p = start_servers(state.clone()).await;
    let key = state.agent_keys.get_or_create(&state.db, "loadtest").await;
    println!("READY {} {} {} {} {key}", p[0], p[1], p[2], p[3]);
    std::io::stdout().flush().unwrap();
    // stdin: `cmd <agent id>` queues a command for that agent; `wdb` prints the query count
    tokio::task::spawn_blocking(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if let Some(id) = line.strip_prefix("cmd ") {
                state.pending_commands.write().unwrap().entry(id.to_string()).or_default().push(json!({ "command_id": "isolate-1", "type": "isolate" }));
                println!("OK");
            } else if line == "wdb" {
                println!("WDB {}", wdb_queries.load(Ordering::Relaxed));
            }
            std::io::stdout().flush().unwrap();
        }
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(home());
}

// ---------- the client side (this process) ----------

struct ChildServer {
    child: Child,
    out: std::sync::mpsc::Receiver<String>,
    ports: [u16; 4],
    tenant_key: String,
}

impl ChildServer {
    fn start(env: &[(&str, &str)]) -> Self {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--ignored", "--exact", "agent_grpc::bench::server_child", "--nocapture", "--test-threads=1"])
            .env("BENCH_CHILD", "1")
            .env("RUST_LOG", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, out) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = tx.send(l);
            }
        });
        let (ports, tenant_key) = loop {
            let l = out.recv_timeout(Duration::from_secs(120)).expect("child server READY");
            // the test harness prints `test ... ` on the same line first
            if let Some(rest) = l.split_once("READY ").map(|(_, r)| r) {
                let v: Vec<&str> = rest.split(' ').collect();
                let p = |i: usize| v[i].parse().unwrap();
                break ([p(0), p(1), p(2), p(3)], v[4].to_string());
            }
        };
        Self { child, out, ports, tenant_key }
    }

    fn ask(&mut self, line: &str, prefix: &str) -> String {
        writeln!(self.child.stdin.as_mut().unwrap(), "{line}").unwrap();
        loop {
            let l = self.out.recv_timeout(Duration::from_secs(10)).unwrap();
            if let Some(i) = l.find(prefix) {
                return l[i..].to_string();
            }
        }
    }

    fn pid(&self) -> sysinfo::Pid {
        sysinfo::Pid::from_u32(self.child.id())
    }

    /// (working set MiB, CPU % since the last call; 100 % = one core)
    fn usage(&self, sys: &mut sysinfo::System) -> (f64, f32) {
        sys.refresh_process(self.pid());
        let p = sys.process(self.pid()).unwrap();
        (p.memory() as f64 / 1048576.0, p.cpu_usage())
    }

    /// Established TCP connections on the server side of `port`.
    fn connections(&self, port: u16) -> usize {
        let out = Command::new("netstat").args(["-ano", "-p", "TCP"]).output().unwrap();
        let local = format!("127.0.0.1:{port}");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| {
                let c: Vec<&str> = l.split_whitespace().collect();
                c.len() >= 5 && c[1] == local && c[3] == "ESTABLISHED" && c[4] == self.child.id().to_string()
            })
            .count()
    }
}

impl Drop for ChildServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The agent's channel: `GrpcLink::new` â†’ `grpc_channel` (plain): `connect_lazy`, no settings.
fn agent_client(port: u16) -> AgentServiceClient {
    let ch = Endpoint::from_shared(format!("http://127.0.0.1:{port}")).unwrap().connect_lazy();
    AgentServiceClient::new(ch).max_decoding_message_size(16 << 20).max_encoding_message_size(16 << 20)
}

/// The agent's HTTPS client (`http_client`).
fn agent_http() -> reqwest::Client {
    reqwest::Client::builder().timeout(LIMIT).build().unwrap()
}

fn authed<M>(id: &str, key: &str, m: M) -> Request<M> {
    let mut r = Request::new(m);
    r.metadata_mut().insert("authorization", format!("Bearer {key}").parse().unwrap());
    r.metadata_mut().insert("x-agent-id", id.parse().unwrap());
    r
}

/// A Windows event as the agent sends it (~600 bytes of JSON).
fn event(id: &str, i: usize) -> Value {
    json!({
        "event_type": "windows_event",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "agent": { "id": id, "name": format!("bench-{id}") },
        "windows": {
            "channel": "Security",
            "event_id": 4624,
            "message": format!("An account was successfully logged on. Subject: Security ID: S-1-5-18 Account Name: BENCH$ Logon Type: 3 New Logon: Account Name: user{i} Account Domain: CORP Logon ID: 0x{i:x} Network Information: Workstation Name: WS-{i} Source Network Address: 10.0.{}.{} Source Port: 51234 Detailed Authentication Information: Logon Process: NtLmSsp Authentication Package: NTLM", i % 250, i % 200),
        },
        "seq": i,
    })
}

fn keepalive_body(id: &str) -> Value {
    json!({ "agent_id": id, "agent_name": format!("bench-{id}"), "tenant_id": "default", "timestamp": chrono::Utc::now().to_rfc3339(), "status": "active", "labels": [], "agent_ip": "127.0.0.1", "version": "1.0.0", "group_config_version": "bench" })
}

async fn enroll(port: u16, n: usize) -> (Vec<(String, String)>, Duration) {
    let mut c = agent_client(port);
    let t = Instant::now();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let e = c.enroll(Request::new(EnrollRequest { name: format!("bench-{i:04}"), ..Default::default() })).await.unwrap().into_inner();
        out.push((e.agent_id, e.raw_key));
    }
    (out, t.elapsed())
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 * p).ceil() as usize).clamp(1, v.len()) - 1]
}

#[derive(Default)]
struct Samples {
    ms: HashMap<&'static str, Vec<f64>>,
    errors: HashMap<String, usize>,
}

impl Samples {
    fn add(&mut self, kind: &'static str, t: Instant, r: Result<(), String>) {
        match r {
            Ok(()) => self.ms.entry(kind).or_default().push(t.elapsed().as_secs_f64() * 1000.0),
            Err(e) => *self.errors.entry(format!("{kind}: {e}")).or_default() += 1,
        }
    }
    fn merge(&mut self, o: Samples) {
        for (k, v) in o.ms {
            self.ms.entry(k).or_default().extend(v);
        }
        for (k, v) in o.errors {
            *self.errors.entry(k).or_default() += v;
        }
    }
    fn report(&mut self, label: &str) {
        for (k, v) in self.ms.iter_mut() {
            let n = v.len();
            println!("{label} {k}: n={n} p50={:.2}ms p99={:.2}ms max={:.2}ms", pct(v, 0.5), pct(v, 0.99), pct(v, 1.0));
        }
        println!("{label} errors: {:?}", self.errors);
    }
}

async fn grpc_call<A>(f: impl std::future::Future<Output = Result<Response<A>, Status>>) -> Result<(), String> {
    match tokio::time::timeout(LIMIT, f).await {
        Err(_) => Err("timeout".into()),
        Ok(Err(s)) => Err(format!("{:?}", s.code())),
        Ok(Ok(_)) => Ok(()),
    }
}

async fn http_call(r: reqwest::RequestBuilder) -> Result<(), String> {
    match r.send().await {
        Err(e) if e.is_timeout() => Err("timeout".into()),
        Err(e) => Err(format!("send: {}", e.without_url())),
        Ok(r) if r.status().is_success() => r.bytes().await.map(drop).map_err(|e| e.to_string()),
        Ok(r) => Err(r.status().to_string()),
    }
}

/// Events over gRPC vs HTTPS, batches of 100, one agent sending one batch at a time (as
/// `flush_events` does) and 16 agents at once; the real handlers and the no-op twins.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn throughput() {
    let s = ChildServer::start(&[]);
    let [grpc, http, grpc_noop, http_noop] = s.ports;
    let (agents, _) = enroll(grpc, 16).await;
    let batches: Vec<Vec<Value>> = agents.iter().map(|(id, _)| (0..100).map(|i| event(id, i)).collect()).collect();
    println!("event JSON bytes: {}", batches[0][0].to_string().len());
    const SECS: u64 = 10;

    for (label, gport, hport) in [("handler", grpc, http), ("noop", grpc_noop, http_noop)] {
        for conc in [1usize, 16] {
            for proto in ["grpc", "https"] {
                let deadline = Instant::now() + Duration::from_secs(SECS);
                let mut tasks = Vec::new();
                for a in 0..conc {
                    let (id, key) = agents[a].clone();
                    let batch = batches[a].clone();
                    tasks.push(tokio::spawn(async move {
                        let mut s = Samples::default();
                        let (mut c, h) = (agent_client(gport), agent_http());
                        while Instant::now() < deadline {
                            let t = Instant::now();
                            let r = if proto == "grpc" {
                                // as GrpcLink::events: each event as JSON text
                                let q = EventsRequest { events_json: batch.iter().map(Value::to_string).collect(), batch_id: uuid::Uuid::new_v4().to_string() };
                                grpc_call(c.events(authed(&id, &key, q))).await
                            } else {
                                let payload = json!({ "agent_id": id, "tenant_id": "default", "events": batch, "batch_id": uuid::Uuid::new_v4().to_string() });
                                http_call(h.post(format!("http://127.0.0.1:{hport}/api/v1/events/ingest")).header("Authorization", format!("Bearer {key}")).json(&payload)).await
                            };
                            s.add("events", t, r);
                        }
                        s
                    }));
                }
                let mut all = Samples::default();
                for t in tasks {
                    all.merge(t.await.unwrap());
                }
                let n = all.ms.get("events").map_or(0, Vec::len);
                println!("THROUGHPUT {label} {proto} agents={conc}: {:.0} events/s ({n} batches in {SECS}s)", n as f64 * 100.0 / SECS as f64);
                all.report(&format!("  {label} {proto} agents={conc}"));
            }
        }
    }

    // keepalive latency, one agent, 2000 calls in a row
    let (id, key) = agents[0].clone();
    for (label, gport, hport) in [("handler", grpc, http), ("noop", grpc_noop, http_noop)] {
        let (mut c, h) = (agent_client(gport), agent_http());
        let mut s = Samples::default();
        for _ in 0..2000 {
            let t = Instant::now();
            let r = grpc_call(c.keepalive(authed(&id, &key, KeepaliveRequest { body_json: keepalive_body(&id).to_string() }))).await;
            s.add("keepalive grpc", t, r);
            let t = Instant::now();
            let r = http_call(h.post(format!("http://127.0.0.1:{hport}/api/v1/agents/{id}/keepalive")).header("Authorization", format!("Bearer {key}")).json(&keepalive_body(&id))).await;
            s.add("keepalive https", t, r);
        }
        s.report(&format!("KEEPALIVE {label}"));
    }
}

/// `n` agents, each on its own connection: keepalive every 10 s, then a batch of `batch` events.
/// Every 2 s the console's calls and one more enrollment, on a connection of their own.
async fn scale_run(n: usize, proto: &'static str, noop: bool, secs: u64, batch: usize, env: &[(&str, &str)]) {
    let mut s = ChildServer::start(env);
    let mut sys = sysinfo::System::new();
    let (base, _) = s.usage(&mut sys);
    let (agents, took) = enroll(s.ports[0], n).await;
    let [grpc, http] = if noop { [s.ports[2], s.ports[3]] } else { [s.ports[0], s.ports[1]] };
    let [real_grpc, real_http] = [s.ports[0], s.ports[1]];
    println!("SCALE {proto} n={n}: enrolled in {:.1}s ({:.0}/s)", took.as_secs_f64(), n as f64 / took.as_secs_f64());
    let (mem0, _) = s.usage(&mut sys);
    let start = Instant::now();
    let deadline = start + Duration::from_secs(secs);
    let mut tasks = Vec::new();
    for (i, (id, key)) in agents.iter().cloned().enumerate() {
        let offset = Duration::from_millis((i as u64 * 10_000) / n as u64);
        tasks.push(tokio::spawn(async move {
            let mut s = Samples::default();
            let (mut c, h) = (agent_client(grpc), agent_http());
            let batch: Vec<Value> = (0..batch).map(|j| event(&id, j)).collect();
            let mut next = start + offset;
            while next < deadline {
                tokio::time::sleep_until(next.into()).await;
                let t = Instant::now();
                let r = if proto == "grpc" {
                    grpc_call(c.keepalive(authed(&id, &key, KeepaliveRequest { body_json: keepalive_body(&id).to_string() }))).await
                } else {
                    http_call(h.post(format!("http://127.0.0.1:{http}/api/v1/agents/{id}/keepalive")).header("Authorization", format!("Bearer {key}")).json(&keepalive_body(&id))).await
                };
                // the first one also opens the agent's connection
                s.add(if next == start + offset { "first keepalive" } else { "keepalive" }, t, r);
                let t = Instant::now();
                let r = if proto == "grpc" {
                    let q = EventsRequest { events_json: batch.iter().map(Value::to_string).collect(), batch_id: uuid::Uuid::new_v4().to_string() };
                    grpc_call(c.events(authed(&id, &key, q))).await
                } else {
                    let payload = json!({ "agent_id": id, "tenant_id": "default", "events": batch, "batch_id": uuid::Uuid::new_v4().to_string() });
                    http_call(h.post(format!("http://127.0.0.1:{http}/api/v1/events/ingest")).header("Authorization", format!("Bearer {key}")).json(&payload)).await
                };
                s.add("events", t, r);
                next += Duration::from_secs(10);
            }
            // keep the connection open until the end of the run
            tokio::time::sleep_until((deadline + Duration::from_secs(3)).into()).await;
            drop((c, h));
            s
        }));
    }
    let console = tokio::spawn(async move {
        let mut s = Samples::default();
        let (mut c, h) = (agent_client(real_grpc), agent_http());
        for i in 0.. {
            if Instant::now() >= deadline {
                break;
            }
            let t = Instant::now();
            s.add("server-info", t, http_call(h.get(format!("http://127.0.0.1:{real_http}/api/server-info"))).await);
            let t = Instant::now();
            s.add("agents list", t, http_call(h.get(format!("http://127.0.0.1:{real_http}/api/v1/agents"))).await);
            let t = Instant::now();
            s.add("enroll under load", t, grpc_call(c.enroll(Request::new(EnrollRequest { name: format!("late-{i:04}"), ..Default::default() }))).await);
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        s
    });
    let (mut peak, mut conns) = (mem0, 0);
    s.usage(&mut sys);
    let mut cpu_sum = 0.0f64;
    let mut cpu_n = 0;
    while Instant::now() < deadline + Duration::from_secs(1) {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (m, c) = s.usage(&mut sys);
        peak = peak.max(m);
        cpu_sum += c as f64;
        cpu_n += 1;
        if conns == 0 && Instant::now() > start + Duration::from_secs(12) {
            conns = s.connections(if proto == "grpc" { grpc } else { http });
        }
    }
    let (mem_end, _) = s.usage(&mut sys);
    let mut all = Samples::default();
    for t in tasks {
        all.merge(t.await.unwrap());
    }
    all.merge(console.await.unwrap());
    let wdb = s.ask("wdb", "WDB ");
    println!(
        "SCALE {proto} noop={noop} n={n} batch={batch} {secs}s env={env:?}: server mem empty={base:.1}MiB enrolled={mem0:.1}MiB peak={peak:.1}MiB end={mem_end:.1}MiB ({:.1} KiB/agent), cpu avg={:.1}% of one core, established={conns}, {wdb}",
        (mem_end - base) * 1024.0 / n as f64,
        cpu_sum / cpu_n.max(1) as f64
    );
    all.report(&format!("  SCALE {proto} n={n}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn scale() {
    let secs = std::env::var("BENCH_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(60);
    let only = std::env::var("BENCH_SCALE").unwrap_or_default();
    // 5,000 and 10,000 agents at the 16 Oct rates: 1 and 0.4 events/s per agent
    for (n, proto, noop, batch, env) in [
        (1, "grpc", false, 100, &[][..]),
        (100, "grpc", false, 100, &[][..]),
        (1000, "grpc", false, 100, &[][..]),
        (1000, "https", false, 100, &[][..]),
        (1000, "grpc", true, 100, &[][..]),
        (1000, "https", true, 100, &[][..]),
        (5000, "grpc", false, 10, &[][..]),
        (10000, "grpc", false, 4, &[][..]),
    ] {
        let tag = format!("{n}-{proto}-{noop}");
        if !only.is_empty() && !only.split(',').any(|o| o == tag) {
            continue;
        }
        scale_run(n, proto, noop, secs, batch, env).await;
    }
}

/// The load test tool against the real handlers, 200 agents over gRPC and over HTTP
/// (first: cargo build --release -p provigil-loadtest).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn loadtest_tool() {
    let s = ChildServer::start(&[]);
    let exe = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().join("provigil-loadtest.exe");
    let file = std::env::temp_dir().join(format!("pv-loadtest-{}.json", std::process::id()));
    for (url, secs) in [(format!("grpc://127.0.0.1:{}", s.ports[0]), "30"), (format!("http://127.0.0.1:{}", s.ports[1]), "15")] {
        let out = Command::new(&exe).args(["--url", &url, "--tenant-key", &s.tenant_key, "--agents", "200", "--eps", "1", "--secs", secs, "--ramp", "5"]).arg("--state").arg(&file).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        println!("{url}\n{text}{}", String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success() && text.contains("errors: none"));
        let state: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        assert!(state["sent"].as_u64().unwrap() > 0 && state["unconfirmed"] == 0);
    }
    let _ = std::fs::remove_file(&file);
}

/// provigil-db down: the keepalive handler waits 1+2+3+4+5 s to connect, holding the one
/// connection's lock; a command queued for the agent is taken before that wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn keepalive_with_provigil_db_down() {
    let mut s = ChildServer::start(&[("BENCH_WDB_DOWN", "1")]);
    let grpc = s.ports[0];
    let (agents, _) = enroll(grpc, 20).await;
    let (id, key) = agents[0].clone();
    s.ask(&format!("cmd {id}"), "OK");
    let mut c = agent_client(grpc);
    let t = Instant::now();
    let r = grpc_call(c.keepalive(authed(&id, &key, KeepaliveRequest { body_json: keepalive_body(&id).to_string() }))).await;
    println!("WDB-DOWN first keepalive (command queued): {r:?} after {:.1}s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let r = tokio::time::timeout(LIMIT, c.keepalive(authed(&id, &key, KeepaliveRequest { body_json: keepalive_body(&id).to_string() }))).await;
    let cmds = match &r {
        Ok(Ok(a)) => a.get_ref().commands_json.len() as i64,
        _ => -1,
    };
    println!("WDB-DOWN second keepalive: ok={} commands={cmds} after {:.1}s", matches!(r, Ok(Ok(_))), t.elapsed().as_secs_f64());

    // 20 agents at once: the calls queue behind the one provigil-db connection
    let t0 = Instant::now();
    let tasks: Vec<_> = agents[1..]
        .iter()
        .cloned()
        .map(|(id, key)| {
            tokio::spawn(async move {
                let mut c = agent_client(grpc);
                let t = Instant::now();
                let r = grpc_call(c.keepalive(authed(&id, &key, KeepaliveRequest { body_json: keepalive_body(&id).to_string() }))).await;
                (r, t.elapsed().as_secs_f64())
            })
        })
        .collect();
    let mut ok = 0;
    let mut timeouts = 0;
    for t in tasks {
        match t.await.unwrap() {
            (Ok(()), _) => ok += 1,
            (Err(_), _) => timeouts += 1,
        }
    }
    println!("WDB-DOWN 19 agents at once: ok={ok} failed={timeouts} in {:.1}s", t0.elapsed().as_secs_f64());
}

/// A handler slower than the client's limit: does the server finish it, and does the resend
/// run it again? (1 s client limit, 3 s handler; the agent's are 15 s.)
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn slow_handler_and_timeouts() {
    static STARTED: AtomicU64 = AtomicU64::new(0);
    static DONE: AtomicU64 = AtomicU64::new(0);
    struct Slow;
    #[tonic::async_trait]
    impl AgentService for Slow {
        async fn enroll(&self, _: Request<EnrollRequest>) -> Result<Response<EnrollReply>, Status> {
            unreachable!()
        }
        async fn keepalive(&self, _: Request<KeepaliveRequest>) -> Result<Response<KeepaliveReply>, Status> {
            unreachable!()
        }
        async fn events(&self, r: Request<EventsRequest>) -> Result<Response<EventsReply>, Status> {
            STARTED.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(3)).await;
            DONE.fetch_add(1, Ordering::SeqCst);
            Ok(Response::new(EventsReply { accepted: r.get_ref().events_json.len() as u32 }))
        }
        async fn result(&self, _: Request<ResultRequest>) -> Result<Response<Empty>, Status> {
            unreachable!()
        }
        async fn config(&self, _: Request<ConfigRequest>) -> Result<Response<ConfigReply>, Status> {
            unreachable!()
        }
        async fn yara(&self, _: Request<YaraRequest>) -> Result<Response<YaraReply>, Status> {
            unreachable!()
        }
        async fn upgrade(&self, _: Request<UpgradeChunkRequest>) -> Result<Response<ChunkStream>, Status> {
            unreachable!()
        }
    }
    let (l, port) = listener().await;
    tokio::spawn(Server::builder().add_service(AgentServiceServer::new(Slow)).serve_with_incoming(TcpIncoming::from_listener(l, true, None).unwrap()));
    let mut c = agent_client(port);
    let r = tokio::time::timeout(Duration::from_secs(1), c.events(Request::new(EventsRequest { events_json: vec!["{}".into()], ..Default::default() }))).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    println!("SLOW grpc: client timed out={} ; server handler started={} finished={}", r.is_err(), STARTED.load(Ordering::SeqCst), DONE.load(Ordering::SeqCst));

    let (s2, d2) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let (s3, d3) = (s2.clone(), d2.clone());
    let app = axum::Router::new().route(
        "/api/v1/events/ingest",
        axum::routing::post(move |_: axum::Json<Value>| {
            let (s, d) = (s3.clone(), d3.clone());
            async move {
                s.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(3)).await;
                d.fetch_add(1, Ordering::SeqCst);
                "{}"
            }
        }),
    );
    let (l, port) = listener().await;
    tokio::spawn(async move { axum::serve(l, app).await });
    let h = reqwest::Client::builder().timeout(Duration::from_secs(1)).build().unwrap();
    let r = h.post(format!("http://127.0.0.1:{port}/api/v1/events/ingest")).json(&json!({"events": [{}]})).send().await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    println!("SLOW https: client timed out={} ; server handler started={} finished={}", r.as_ref().err().is_some_and(|e| e.is_timeout()), s2.load(Ordering::SeqCst), d2.load(Ordering::SeqCst));
}

/// Message limits: a gRPC batch near / over 16 MiB, an HTTPS batch over axum's default 2 MiB body
/// limit, against the real servers.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn large_messages() {
    let s = ChildServer::start(&[]);
    let [grpc, http, _, _] = s.ports;
    let (agents, _) = enroll(grpc, 1).await;
    let (id, key) = agents[0].clone();
    let big = |each: usize| -> Vec<Value> {
        (0..100).map(|i| { let mut e = event(&id, i); e["windows"]["message"] = json!("x".repeat(each)); e }).collect()
    };
    for each in [20_000usize, 150_000, 170_000] {
        let batch = big(each);
        let q = EventsRequest { events_json: batch.iter().map(Value::to_string).collect(), ..Default::default() };
        let bytes: usize = q.events_json.iter().map(String::len).sum();
        let mut c = agent_client(grpc);
        let t = Instant::now();
        let r = tokio::time::timeout(LIMIT, c.events(authed(&id, &key, q))).await;
        let r = match r {
            Err(_) => "timeout".to_string(),
            Ok(Ok(_)) => "OK".into(),
            Ok(Err(s)) => format!("{:?}: {}", s.code(), s.message()),
        };
        println!("LARGE grpc {:.2} MiB: {r} in {:.0} ms", bytes as f64 / 1048576.0, t.elapsed().as_secs_f64() * 1000.0);
        let payload = json!({ "agent_id": id, "tenant_id": "default", "events": batch });
        let len = payload.to_string().len();
        let r = agent_http().post(format!("http://127.0.0.1:{http}/api/v1/events/ingest")).header("Authorization", format!("Bearer {key}")).json(&payload).send().await;
        println!("LARGE https {:.2} MiB: {:?}", len as f64 / 1048576.0, r.map(|r| r.status()).map_err(|e| e.to_string()));
    }

    // the upgrade stream: 20 MiB package; k downloads that read one chunk and then stall
    let mut sys = sysinfo::System::new();
    for k in [1usize, 10, 40] {
        let (m0, _) = s.usage(&mut sys);
        let mut streams = Vec::new();
        for _ in 0..k {
            let mut c = agent_client(grpc);
            let mut st = c.upgrade(authed(&id, &key, UpgradeChunkRequest { version: "9.9.9".into() })).await.unwrap().into_inner();
            st.message().await.unwrap();
            streams.push((c, st));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        let (m1, _) = s.usage(&mut sys);
        println!("UPGRADE {k} stalled downloads of 20 MiB: server mem {m0:.0} -> {m1:.0} MiB ({:.1} MiB each)", (m1 - m0) / k as f64);
        drop(streams);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Where the ingest handler's time goes (in-process, no transport).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn ingest_profile() {
    let _ = std::fs::remove_dir_all(home());
    stub_wdb(Duration::ZERO, Arc::new(AtomicU64::new(0))).await;
    let state = state().await;
    let headers = axum::http::HeaderMap::new();
    let batch: Vec<Value> = (0..100).map(|i| event("101", i)).collect();
    let raw: Vec<crate::RawEvent> = batch.iter().filter_map(|e| crate::parse_agent_telemetry_to_raw_event(e, "101")).collect();
    let t = Instant::now();
    let mut alerts = 0;
    for e in &raw {
        alerts += state.engine.process_event(e, "bench-101", "127.0.0.1").is_some() as usize;
    }
    println!("PROFILE engine.process_event x100: {:.1} ms, {alerts} alerts", t.elapsed().as_secs_f64() * 1000.0);
    for round in 0..30 {
        let t = Instant::now();
        crate::ingest(&state, &headers, json!({ "agent_id": "101", "events": batch })).await.unwrap();
        let ingest_ms = t.elapsed().as_secs_f64() * 1000.0;
        let t = Instant::now();
        for e in &raw {
            state.engine.process_event(e, "bench-101", "127.0.0.1");
        }
        let engine_ms = t.elapsed().as_secs_f64() * 1000.0;
        let t = Instant::now();
        let reg = crate::parsers_store::for_tenant(&state, "default");
        for e in &raw {
            reg.execute(&e.message);
        }
        let parse_ms = t.elapsed().as_secs_f64() * 1000.0;
        let t = Instant::now();
        crate::keep_events(&state, raw.iter().cloned());
        let keep_ms = t.elapsed().as_secs_f64() * 1000.0;
        if round % 5 == 0 || round == 29 {
            println!("PROFILE round {round}: ingest x100 {ingest_ms:.1} ms | process_event x100 {engine_ms:.1} ms | learned parsers x100 {parse_ms:.1} ms | keep_events x100 {keep_ms:.2} ms | events in memory {}", state.events.read().unwrap().len());
        }
    }
    let Some(a) = state.alerts.read().unwrap().last().cloned() else { return };
    let t = Instant::now();
    for _ in 0..100 {
        crate::keep_alerts(&state, [a.clone()]);
    }
    println!("PROFILE keep_alerts x100: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    let t = Instant::now();
    for _ in 0..100 {
        let mut a = a.clone();
        a.data.remove("risk_fabric");
        state.risk_fabric.evaluate_alert(&mut a);
    }
    println!("PROFILE risk_fabric.evaluate_alert x100: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    let t = Instant::now();
    for _ in 0..100 {
        state.intent_engine.ingest_live_alerts(std::slice::from_ref(&a));
    }
    println!("PROFILE intent_engine.ingest_live_alerts x100: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    // 8 batches at once
    let t = Instant::now();
    let tasks: Vec<_> = (0..8).map(|_| { let (s, b) = (state.clone(), batch.clone()); tokio::spawn(async move { crate::ingest(&s, &axum::http::HeaderMap::new(), json!({ "agent_id": "101", "events": b })).await.unwrap(); }) }).collect();
    for t in tasks { t.await.unwrap(); }
    println!("PROFILE 8 concurrent ingest x100: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
}
