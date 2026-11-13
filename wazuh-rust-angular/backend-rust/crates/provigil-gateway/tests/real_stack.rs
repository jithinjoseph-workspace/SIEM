//! The gateway with the REAL siem-api, analysis engine and provigil-db, on a private stack: a
//! private ClickHouse, a temp manager home, random ports. Never the running services.
//!   GATEWAY_TEST_CLICKHOUSE=http://127.0.0.1:PORT PV_SIEM_API_EXE=<target>/release/siem-api.exe \
//!   PV_TEST_VALKEY=redis://127.0.0.1:PORT PROVIGIL_SOURCE_DIR=<the ruleset source> cargo test -p provigil-gateway --test real_stack -- --ignored --nocapture
//! siem-api starts the engine and provigil-db from the folder of its exe.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clickhouse::Client;
use provigil_agent::sca::{results_hash, Outcome};
use provigil_agent::transport::{ca_certs, Cert, Creds, GrpcLink, Link};
use provigil_agent::wevt::build_payload;
use provigil_agent_server::commands::{CommandRow, DEFAULT_TTL_MS};
use serde_json::{json, Value};
use provigil_ipc::agentdb::{DbQuery, DbSocket, DB_SOCKET};

const SECRET: &str = "real-stack-secret";
const TOKEN: &str = "real-stack-token";
const TENANT_KEY: &str = "tk_realstack";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The env every child gets: the system's own, nothing of the live services.
fn base(c: &mut Command) -> &mut Command {
    c.env_clear().envs(std::env::vars().filter(|(k, _)| matches!(k.to_uppercase().as_str(), "SYSTEMROOT" | "WINDIR" | "PATH" | "TEMP" | "TMP" | "USERPROFILE" | "COMPUTERNAME" | "PROGRAMDATA")))
}

async fn until(what: &str, secs: u64, mut ok: impl AsyncFnMut() -> bool) {
    let t = Instant::now();
    while !ok().await {
        assert!(t.elapsed() < Duration::from_secs(secs), "not within {secs} s: {what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

struct Stack {
    ch: String,
    db: Client,
    home: PathBuf,
    ca_dir: PathBuf,
    api_internal: String,
    roots: Vec<Cert>,
    _api: Proc,
}

impl Drop for Stack {
    /// siem-api's daemons outlive it on Windows: those whose program is in this stack's home stop.
    fn drop(&mut self) {
        let _ = self._api.0.kill();
        let _ = self._api.0.wait();
        let home = self.home.display().to_string().replace('/', "\\");
        let _ = Command::new("powershell").args(["-NoProfile", "-Command", &format!("Get-Process | Where-Object {{ $_.Path -like '{home}\\*' }} | Stop-Process -Force")]).status();
    }
}

impl Stack {
    fn gateway(&self, grpc: u16, tls: u16, stats: u16) -> Proc {
        let mut c = Command::new(env!("CARGO_BIN_EXE_provigil-gateway"));
        base(&mut c)
            .env("GATEWAY_GRPC_PORT", grpc.to_string())
            .env("GATEWAY_TLS_PORT", tls.to_string())
            .env("GATEWAY_BIND", "127.0.0.1")
            .env("GATEWAY_STATS_ADDR", format!("127.0.0.1:{stats}"))
            .env("GATEWAY_INTERNAL_TOKEN", TOKEN)
            .env("SIEM_API_INTERNAL_URL", &self.api_internal)
            .env("GATEWAY_ENROLL_PER_MINUTE", "100000")
            .env("PROVIGIL_MANAGER_HOME", &self.home)
            .env("GATEWAY_CA_DIR", &self.ca_dir)
            .env("GATEWAY_AGENT_DIST", self.home.join("no-dist"))
            .env("CLICKHOUSE_URL", &self.ch)
            .env("AGENT_KEYS_SECRET", SECRET)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null());
        Proc(c.spawn().unwrap())
    }

    async fn wdb(&self, q: &str) -> Value {
        let r = DbSocket::new(self.home.join(DB_SOCKET)).query(q).await.unwrap_or_default();
        r.strip_prefix("ok ").and_then(|j| serde_json::from_str(j).ok()).unwrap_or_default()
    }

    async fn count(&self, sql: &str) -> u64 {
        self.db.query(sql).fetch_one::<u64>().await.unwrap_or(0)
    }
}

async fn ready(stats: u16) {
    until("the gateway is ready", 60, async || reqwest::get(format!("http://127.0.0.1:{stats}/health")).await.is_ok_and(|r| r.status().is_success())).await;
}

fn windows_event(agent: &str, name: &str, marker: &str, seq: u64, level: u8) -> Value {
    let message = format!("Faulting application name: realstack.exe, run {marker}, event {seq}, version: 1.0.0.1, time stamp: 0x65a1b2c3");
    let xml = format!(
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Application Error'/><EventID>1000</EventID><Version>0</Version><Level>{level}</Level><Task>100</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='{}'/><EventRecordID>{seq}</EventRecordID><Channel>Application</Channel><Computer>{name}</Computer></System><EventData><Data Name='AppName'>realstack.exe</Data><Data Name='RunId'>{marker}</Data></EventData></Event>",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ")
    );
    json!({ "event_type": "windows_eventchannel", "agent": { "id": agent, "name": name }, "location": "EventChannel", "message": build_payload(Some(&message), &xml) })
}

fn sca_events(agent: &str) -> Vec<Value> {
    let ev = |m: Value| json!({ "event_type": "sca", "agent": { "id": agent }, "location": "sca", "message": m.to_string() });
    let (policy, policy_id, scan_id) = ("Real stack policy", "provigil_realstack", 4242);
    let outcome = |i: usize| if i % 2 == 0 { Outcome::Failed } else { Outcome::Passed };
    let mut out = vec![ev(json!({ "type": "policies", "policies": [policy_id] }))];
    for i in 0..4 {
        out.push(ev(json!({ "type": "check", "id": scan_id, "policy": policy, "policy_id": policy_id, "check": { "id": 95000 + i, "title": format!("Real stack check {i}"), "description": "d", "remediation": "r", "compliance": {}, "rules": ["r:HKLM"], "condition": "all", "result": outcome(i).as_str() } })));
    }
    let outcomes: Vec<Outcome> = (0..4).map(outcome).collect();
    let results: Vec<(u32, &Outcome)> = outcomes.iter().enumerate().map(|(i, o)| (95000 + i as u32, o)).collect();
    let now = chrono::Utc::now().timestamp();
    out.push(ev(json!({ "type": "summary", "scan_id": scan_id, "name": policy, "policy_id": policy_id, "file": "realstack.yml", "start_time": now - 1, "end_time": now, "passed": 2, "failed": 2, "invalid": 0, "total_checks": 4, "score": 50, "hash": results_hash(&results), "hash_file": format!("{:064x}", 7), "first_scan": 1 })));
    out
}

fn inventory(agent: &str, version: &str) -> Value {
    let inv = json!({ "packages": [{ "name": "Real Stack Package", "version": version, "publisher": "ProVigil", "architecture": "x86_64", "location": "C:\\RS" }], "processes": [], "ports": [], "services": [], "users": [], "network_interfaces": [] });
    json!({ "event_type": "system_inventory", "agent": { "id": agent }, "location": "syscollector/inventory", "message": "inventory", "inventory_json": inv.to_string(),
        "os_info": { "hostname": "rs", "os_name": "Microsoft Windows 11 Pro", "os_version": "10.0.22631", "os_major": "10", "os_minor": "0", "os_build": "22631", "architecture": "x86_64" }, "hotfixes": ["KB1"] })
}

async fn send_until_taken(link: &dyn Link, batch: &[Value]) {
    loop {
        if link.events(batch).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a private ClickHouse and a release siem-api: see the file's header"]
async fn real_siem_api_engine_and_provigil_db() {
    let ch = std::env::var("GATEWAY_TEST_CLICKHOUSE").expect("GATEWAY_TEST_CLICKHOUSE");
    let api_exe = PathBuf::from(std::env::var("PV_SIEM_API_EXE").expect("PV_SIEM_API_EXE"));
    let source = std::env::var("PROVIGIL_SOURCE_DIR").expect("PROVIGIL_SOURCE_DIR");
    let dir = tempfile::tempdir().unwrap();
    let (cwd, home) = (dir.path().join("api"), dir.path().join("home"));
    std::fs::create_dir_all(cwd.join("data")).unwrap();
    let root = Client::default().with_url(&ch);
    for q in ["DROP DATABASE IF EXISTS ndr", "DROP DATABASE IF EXISTS ndr_rstack", "CREATE DATABASE IF NOT EXISTS ndr", "CREATE TABLE IF NOT EXISTS ndr.tenants (id String, name String, active UInt8, ai_enabled UInt8 DEFAULT 0, features String DEFAULT '', updated_at DateTime DEFAULT now()) ENGINE = ReplacingMergeTree(updated_at) ORDER BY id", "CREATE TABLE IF NOT EXISTS ndr.tenant_agent_keys (tenant_id LowCardinality(String), agent_key String, created_at UInt64) ENGINE = ReplacingMergeTree() ORDER BY tenant_id"] {
        root.query(q).execute().await.unwrap();
    }
    root.query("INSERT INTO ndr.tenants (id, name, active) VALUES ('rstack', 'rstack', 1)").execute().await.unwrap();
    root.query(&format!("INSERT INTO ndr.tenant_agent_keys VALUES ('rstack', '{TENANT_KEY}', 1)")).execute().await.unwrap();

    let (api_port, internal) = (free_port(), free_port());
    let mut c = Command::new(&api_exe);
    base(&mut c)
        .current_dir(&cwd)
        .env("SIEM_PORT", api_port.to_string())
        .env("SIEM_API_INTERNAL_ADDR", format!("127.0.0.1:{internal}"))
        .env("GATEWAY_INTERNAL_TOKEN", TOKEN)
        .env("JWT_SECRET", "real-stack-jwt")
        .env("VALKEY_URL", std::env::var("PV_TEST_VALKEY").expect("PV_TEST_VALKEY: a private Valkey (siem-api needs one)"))
        .env("CLICKHOUSE_URL", &ch)
        .env("CLICKHOUSE_DB", "ndr")
        .env("AGENT_KEYS_SECRET", SECRET)
        .env("PROVIGIL_MANAGER_HOME", &home)
        .env("PROVIGIL_SOURCE_DIR", &source)
        .env("SYSLOG_UDP_PORT", free_port().to_string())
        .env("SYSLOG_TCP_PORT", free_port().to_string())
        .env("SYSLOG_TLS_PORT", free_port().to_string())
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(dir.path().join("siem-api.log")).unwrap());
    let api = Proc(c.spawn().unwrap());
    let ca_dir = cwd.join("data").join("tls");
    let engine_up = |home: &Path| home.join("queue/sockets/analysis.port").is_file() || home.join("queue/sockets/analysis").exists();
    until("siem-api, its engine and provigil-db", 180, async || engine_up(&home) && ca_dir.join("ca.crt.pem").is_file() && tokio::net::TcpStream::connect(("127.0.0.1", internal)).await.is_ok()).await;
    let stack = Stack { ch: ch.clone(), db: root.clone(), home: home.clone(), ca_dir: ca_dir.clone(), api_internal: format!("http://127.0.0.1:{internal}"), roots: ca_certs(Some(&ca_dir.join("ca.crt.pem"))), _api: api };
    let (grpc, tls, stats) = (free_port(), free_port(), free_port());
    let mut gw = stack.gateway(grpc, tls, stats);
    ready(stats).await;
    let link_for = |c: Creds| GrpcLink::new(&format!("grpcs://localhost:{grpc}"), c, false, &stack.roots).unwrap();

    // enroll: through the gateway into the real siem-api
    let e = link_for(Creds { tenant_key: Some(TENANT_KEY.into()), ..Default::default() }).enroll(&json!({ "name": "real-stack-pc", "os_type": "windows", "groups": "" })).await.expect("enrolled");
    let s = |k: &str| e[k].as_str().unwrap().to_string();
    assert_eq!(s("tenant_id"), "rstack");
    let (id, name) = (s("agent_id"), s("agent_name"));
    let creds = Creds { agent_id: id.clone(), key: s("raw_key"), tenant_id: "rstack".into(), tenant_key: Some(TENANT_KEY.into()) };
    let link = link_for(creds.clone());
    until("the key reached the gateway", 10, async || link.keepalive(&json!({ "status": "active", "version": "1.0.0" })).await.is_ok()).await;
    println!("enrolled agent {id}");

    // events: through the real engine, alerts stored in ClickHouse
    let marker = uuid::Uuid::new_v4().simple().to_string()[..10].to_string();
    let batch: Vec<Value> = (0..10).map(|i| windows_event(&id, &name, &marker, i, if i % 2 == 0 { 2 } else { 4 })).collect();
    send_until_taken(&link, &batch).await;
    let events_sql = format!("SELECT count() FROM ndr_rstack.siem_events WHERE position(message, '{marker}') > 0 OR position(raw_metadata, '{marker}') > 0");
    until("the events stored", 60, async || stack.count(&events_sql).await >= 10).await;
    // a fresh database: this run's agent's alerts are this batch's (full_log is not stored for these)
    let alerts_sql = format!("SELECT count() FROM ndr_rstack.siem_alerts WHERE agent_id = '{id}'");
    until("an alert stored", 60, async || stack.count(&alerts_sql).await >= 1).await;
    println!("events and alerts: ok ({} alerts)", stack.count(&alerts_sql).await);

    // configuration assessment: checks in the agent's provigil-db
    send_until_taken(&link, &sca_events(&id)).await;
    let sca = format!("agent {id} sql SELECT count(*) AS n FROM sca_check WHERE policy_id = 'provigil_realstack'");
    until("the checks in provigil-db", 60, async || stack.wdb(&sca).await[0]["n"].as_u64() >= Some(4)).await;
    println!("sca: ok");

    // inventory, then a delta: the package's new version in provigil-db
    send_until_taken(&link, &[inventory(&id, "1.0.0")]).await;
    let pkg = format!("agent {id} sql SELECT version FROM sys_programs WHERE name = 'Real Stack Package'");
    until("the inventory", 60, async || stack.wdb(&pkg).await[0]["version"] == "1.0.0").await;
    let tables = provigil_agent::syscollector::delta::tables(&serde_json::from_str(inventory(&id, "1.0.0")["inventory_json"].as_str().unwrap()).unwrap(), &json!({}), &[]);
    let saved = tables.iter().map(|t| (t.name.to_string(), t.items.iter().map(|(k, (h, _))| (k.clone(), h.clone())).collect())).collect();
    let newer = provigil_agent::syscollector::delta::tables(&serde_json::from_str(inventory(&id, "2.0.0")["inventory_json"].as_str().unwrap()).unwrap(), &json!({}), &[]);
    let (changes, n) = provigil_agent::syscollector::delta::changes(&newer, &saved);
    send_until_taken(&link, &[provigil_agent::syscollector::delta::event((&id, &name), changes, n)]).await;
    until("the delta", 60, async || stack.wdb(&pkg).await.as_array().is_some_and(|r| r.iter().any(|x| x["version"] == "2.0.0"))).await;
    println!("inventory delta: ok");

    // a command round trip through the shared queue
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let row = CommandRow { agent_id: id.clone(), command_id: "rt-1".into(), tenant_id: "rstack".into(), command: json!({ "command_id": "rt-1", "type": "getstate" }).to_string(), origin: "console:test".into(), created_at: now, expires_at: now + DEFAULT_TTL_MS, state: "queued".into(), state_at: now, gateway: String::new(), attempts: 0, result: String::new(), version: now };
    let mut ins = root.clone().with_database("ndr").insert("agent_command_queue").unwrap();
    ins.write(&row).await.unwrap();
    ins.end().await.unwrap();
    let mut got = Vec::new();
    until("the command handed out", 20, async || {
        got = link.keepalive(&json!({ "status": "active" })).await.unwrap_or_default();
        got.iter().any(|c| c["command_id"] == "rt-1")
    }).await;
    link.result(&json!({ "command_id": "rt-1", "status": "done", "state": {} })).await.unwrap();
    until("the result in ClickHouse", 10, async || stack.count("SELECT count() FROM ndr.agent_command_queue FINAL WHERE command_id = 'rt-1' AND state = 'done'").await == 1).await;
    println!("command round trip: ok");

    // an engine-triggered response for this ProVigil agent: siem-api queues it, the gateway hands it out
    let ar = provigil_ipc::aio::DatagramSender::connect(home.join(provigil_ipc::queue::AGENT_AR_QUEUE)).await.expect("siem-api reads the engine's responses");
    let msg = format!(r#"(local_source) [] NNS {id} {{"version":1,"origin":{{"name":"","module":"provigil-analysisd"}},"command":"firewall-drop600","parameters":{{"extra_args":[],"alert":{{"rule":{{"id":"100101"}}}}}}}}"#);
    let mut response = None;
    until("the engine's response at a keepalive", 40, async || {
        ar.send(msg.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        response = link.keepalive(&json!({ "status": "active" })).await.unwrap_or_default().into_iter().find(|c| c["type"] == "ar");
        response.is_some()
    }).await;
    assert_eq!(response.unwrap()["message"]["command"], "firewall-drop600");
    println!("engine-triggered response: ok");

    // a gateway restart in the middle of a run: every event is stored, none lost
    let marker = uuid::Uuid::new_v4().simple().to_string()[..10].to_string();
    let sender = {
        let (link, id, name, marker) = (Arc::new(link_for(creds.clone())), id.clone(), name.clone(), marker.clone());
        tokio::spawn(async move {
            for i in 0..300u64 {
                let batch: Vec<Value> = (0..5).map(|j| windows_event(&id, &name, &marker, i * 5 + j, 4)).collect();
                send_until_taken(link.as_ref(), &batch).await;
            }
        })
    };
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = gw.0.kill();
    let _ = gw.0.wait();
    tokio::time::sleep(Duration::from_secs(1)).await;
    gw = stack.gateway(grpc, tls, stats);
    ready(stats).await;
    sender.await.unwrap();
    let stored = format!("SELECT uniqExact(extract(message, 'event [0-9]+')) FROM ndr_rstack.siem_events WHERE position(message, '{marker}') > 0 OR position(raw_metadata, '{marker}') > 0");
    until("all 1,500 events stored", 120, async || stack.count(&stored).await >= 1500).await;
    println!("gateway restart: 1500 of 1500 stored");
    drop(gw);
}
