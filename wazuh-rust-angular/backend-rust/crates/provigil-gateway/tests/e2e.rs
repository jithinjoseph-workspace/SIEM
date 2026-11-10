//! The real gateway process, real agent links, a real ClickHouse; the engine, provigil-db and
//! siem-api are stand-ins (`tests/stub`). Needs a private ClickHouse, never the live one:
//!   GATEWAY_TEST_CLICKHOUSE=http://127.0.0.1:PORT cargo test -p provigil-gateway --test e2e -- --ignored --nocapture

mod stub;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clickhouse::Client;
use provigil_agent::transport::{ca_certs, http_client, Cert, Creds, Fail, GrpcLink, HttpsLink, Link};
use provigil_agent_server::commands::{CommandRow, DEFAULT_TTL_MS};
use provigil_agent_server::tls;
use serde_json::{json, Value};
use stub::Stub;

const SECRET: &str = "e2e-secret";
const TENANT_KEY: &str = "tk_acme";
const EXE: &[u8] = b"MZ provigil-agent-version:9.9.9 the agent program";

struct World {
    home: PathBuf,
    ca_dir: PathBuf,
    dist: PathBuf,
    ch: String,
    api: String,
    db: Client,
    stub: Arc<Stub>,
    roots: Vec<Cert>,
}

#[derive(Clone, Copy)]
struct Ports {
    grpc: u16,
    tls: u16,
    stats: u16,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn ports() -> Ports {
    Ports { grpc: free_port(), tls: free_port(), stats: free_port() }
}

impl World {
    /// Starts a gateway process.
    fn gateway(&self, p: Ports, extra: &[(&str, &str)]) -> Gateway {
        let mut c = Command::new(env!("CARGO_BIN_EXE_provigil-gateway"));
        c.env_clear()
            .envs(std::env::vars().filter(|(k, _)| matches!(k.to_uppercase().as_str(), "SYSTEMROOT" | "WINDIR" | "PATH" | "TEMP" | "TMP")))
            .env("GATEWAY_GRPC_PORT", p.grpc.to_string())
            .env("GATEWAY_TLS_PORT", p.tls.to_string())
            .env("GATEWAY_BIND", "127.0.0.1")
            .env("GATEWAY_ID", format!("gw-{}", p.grpc))
            .env("GATEWAY_STATS_ADDR", format!("127.0.0.1:{}", p.stats))
            .env("GATEWAY_INTERNAL_TOKEN", "internal")
            .env("SIEM_API_INTERNAL_URL", &self.api)
            .env("GATEWAY_ENROLL_PER_MINUTE", "1000")
            .env("PROVIGIL_MANAGER_HOME", &self.home)
            .env("GATEWAY_AGENT_DIST", &self.dist)
            .env("GATEWAY_CA_DIR", &self.ca_dir)
            .env("CLICKHOUSE_URL", &self.ch)
            .env("AGENT_KEYS_SECRET", SECRET)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null());
        for (k, v) in extra {
            c.env(k, v);
        }
        Gateway { child: c.spawn().unwrap(), p }
    }

    fn grpc(&self, p: Ports, c: Creds) -> GrpcLink {
        GrpcLink::new(&format!("grpcs://localhost:{}", p.grpc), c, false, &self.roots).unwrap()
    }

    fn https(&self, p: Ports, c: Creds) -> HttpsLink {
        HttpsLink::new(&format!("https://localhost:{}", p.tls), c, http_client(false, &self.roots))
    }

    fn links(&self, p: Ports, c: Creds) -> [Box<dyn Link>; 2] {
        [Box::new(self.grpc(p, c.clone())), Box::new(self.https(p, c))]
    }

    async fn enroll(&self, p: Ports, name: &str) -> Creds {
        let link = self.grpc(p, Creds { tenant_key: Some(TENANT_KEY.into()), ..Default::default() });
        let a = link.enroll(&json!({ "name": name, "os_type": "windows", "groups": "" })).await.unwrap();
        let s = |k: &str| a[k].as_str().unwrap().to_string();
        Creds { agent_id: s("agent_id"), key: s("raw_key"), tenant_id: s("tenant_id"), tenant_key: Some(TENANT_KEY.into()) }
    }

    async fn queue_command(&self, agent: &str, id: &str, kind: &str) {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let row = CommandRow { agent_id: agent.into(), command_id: id.into(), tenant_id: "acme".into(), command: json!({ "command_id": id, "type": kind }).to_string(), origin: "console:u".into(), created_at: now, expires_at: now + DEFAULT_TTL_MS, state: "queued".into(), state_at: now, gateway: String::new(), attempts: 0, result: String::new(), version: now };
        let mut i = self.db.insert("agent_command_queue").unwrap();
        i.write(&row).await.unwrap();
        i.end().await.unwrap();
    }

    async fn command_state(&self, id: &str) -> String {
        self.db.query("SELECT state FROM agent_command_queue FINAL WHERE command_id = ?").bind(id).fetch_one::<String>().await.unwrap_or_default()
    }
}

struct Gateway {
    child: Child,
    p: Ports,
}

impl Gateway {
    fn stats(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.p.stats)
    }

    async fn metric(&self, name: &str) -> f64 {
        let t = reqwest::get(self.stats("/metrics")).await.unwrap().text().await.unwrap();
        t.lines().find_map(|l| l.strip_prefix(&format!("provigil_gateway_{name} "))?.parse().ok()).unwrap_or(0.0)
    }

    /// Until `/health` says ready.
    async fn ready(&self) {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(r) = reqwest::get(self.stats("/health")).await {
                if r.status().is_success() {
                    return;
                }
            }
            assert!(Instant::now() < until, "gateway on {} not ready", self.p.grpc);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// A planned stop: waits for the process to end.
    async fn stop(&mut self) {
        reqwest::Client::new().post(self.stats("/shutdown")).send().await.unwrap();
        for _ in 0..400 {
            if self.child.try_wait().unwrap().is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the gateway did not stop");
    }

    fn crash(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn windows_event(text: &str) -> Value {
    json!({ "event_type": "windows_eventchannel", "location": "EventChannel", "message": text })
}

async fn until(what: &str, secs: u64, mut ok: impl AsyncFnMut() -> bool) {
    let t = Instant::now();
    while !ok().await {
        assert!(t.elapsed() < Duration::from_secs(secs), "not within {secs} s: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Every call over a real link.
async fn every_call(w: &World, p: Ports) {
    w.stub.keep.store(true, Relaxed);
    for proto in ["grpc", "https"] {
        let enroll: Box<dyn Link> = if proto == "grpc" { Box::new(w.grpc(p, Creds { tenant_key: Some(TENANT_KEY.into()), ..Default::default() })) } else { Box::new(w.https(p, Creds { tenant_key: Some(TENANT_KEY.into()), ..Default::default() })) };
        let a = enroll.enroll(&json!({ "name": format!("pc-{proto}"), "os_type": "windows", "groups": "" })).await.unwrap_or_else(|e| panic!("{proto}: {e}"));
        let s = |k: &str| a[k].as_str().unwrap().to_string();
        assert_eq!(s("tenant_id"), "acme");
        let creds = Creds { agent_id: s("agent_id"), key: s("raw_key"), tenant_id: s("tenant_id"), tenant_key: Some(TENANT_KEY.into()) };
        let link: Box<dyn Link> = if proto == "grpc" { Box::new(w.grpc(p, creds.clone())) } else { Box::new(w.https(p, creds.clone())) };

        // the key works at once on the gateway it enrolled through
        let id = format!("c-{proto}");
        w.queue_command(&creds.agent_id, &id, "getconfig").await;
        let mut got = Vec::new();
        for _ in 0..60 {
            got = link.keepalive(&json!({ "status": "active", "version": "1.2.3", "fim_state_wanted": true, "labels": [{ "key": "site", "value": "kochi" }], "agent_ip": "10.0.0.7", "group_config_version": "old" })).await.unwrap_or_else(|e| panic!("{proto} keepalive: {e}"));
            if got.iter().any(|c| c["command_id"] == id.as_str()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
        assert!(got.iter().any(|c| c["command_id"] == id.as_str()), "{proto}: command: {got:?}");
        assert!(got.iter().any(|c| c["type"] == "fim_state_allowed"), "{proto}: baseline slot");

        let before = w.stub.received.load(Relaxed);
        link.events(&[windows_event(&format!("one-{proto}")), windows_event(&format!("two-{proto}"))]).await.unwrap_or_else(|e| panic!("{proto} events: {e}"));
        until("the engine read both", 5, async || w.stub.received.load(Relaxed) >= before + 2).await;
        // the same batch again: answered, not taken twice
        link.events(&[windows_event(&format!("one-{proto}")), windows_event(&format!("two-{proto}"))]).await.unwrap();
        // fim, a baseline, inventory, ar_log and other events go their ways
        let mine = json!({ "id": creds.agent_id });
        let others = w.stub.other_events.load(Relaxed);
        link.events(&[
            json!({ "event_type": "fim", "agent": mine, "syscheck": { "path": "C:\\a", "event": "added", "sha256_after": "aa" } }),
            json!({ "event_type": "fim_state", "agent": mine, "last": true, "entries": [{ "path": "C:\\a", "sha256_after": "aa" }] }),
            json!({ "event_type": "system_inventory", "agent": mine, "inventory_json": "{\"packages\":[]}", "os_info": { "os_name": "Windows" } }),
            json!({ "event_type": "ar_log", "agent": mine, "log": "a line" }),
            json!({ "event_type": "agent_status", "agent": mine }),
        ]).await.unwrap_or_else(|e| panic!("{proto} mixed: {e}"));
        assert_eq!(w.stub.other_events.load(Relaxed), others + 1, "the status event");
        until("the inventory's copy for the event store", 5, async || w.stub.other_events.load(Relaxed) == others + 2).await;

        link.result(&json!({ "command_id": id, "status": "done", "config": {} })).await.unwrap();
        until("the result in ClickHouse", 5, async || w.command_state(&id).await == "done").await;
        assert!(link.config().await.unwrap()["version"].as_str().unwrap().len() == 16, "{proto}");
        assert_eq!(link.yara().await.unwrap(), b"YARA RULES", "{proto}");
        let mut d = link.download("/downloads/provigil-agent.exe", "9.9.9").await.unwrap();
        let mut bytes = Vec::new();
        while let Some(c) = d.chunk().await.unwrap() {
            bytes.extend(c);
        }
        assert_eq!(bytes, EXE, "{proto}");

        // a batch naming another agent is refused, whole
        let r = link.events(&[json!({ "event_type": "logfile", "location": "x", "message": "m", "agent": { "id": "1" } })]).await;
        assert!(matches!(r, Err(Fail::Status(400, _))), "{proto}: {:?}", r.err());
        // the keepalive with `stopping`
        tokio::time::sleep(Duration::from_millis(1100)).await;
        link.keepalive(&json!({ "status": "stopping" })).await.unwrap();
        let stopped = format!("Agent stopped: 'pc-{proto}->10.0.0.7'");
        until("the engine told the agent stopped", 5, async || w.stub.messages.lock().unwrap().keys().any(|m| m.contains(&stopped))).await;
    }
    until("labels with the manager's in global.db", 5, async || {
        let q = w.stub.statements.lock().unwrap();
        ["\"site\"", "_manager_hostname", "_node_name", "_agent_version", "_agent_ip"].iter().all(|k| q.iter().any(|s| s.contains("INSERT INTO labels") && s.contains(k)))
    }).await;
    until("group status in global.db", 5, async || w.stub.statements.lock().unwrap().iter().any(|s| s.contains("group_config_status = 'not synced'"))).await;
    until("stopped in global.db", 5, async || w.stub.statements.lock().unwrap().iter().any(|s| s.contains("connection_status = 'disconnected'"))).await;
    let wrong = load_other_ca();
    for link in [Box::new(GrpcLink::new(&format!("grpcs://localhost:{}", p.grpc), Creds::default(), false, &wrong).unwrap()) as Box<dyn Link>, Box::new(HttpsLink::new(&format!("https://localhost:{}", p.tls), Creds::default(), http_client(false, &wrong)))] {
        assert!(matches!(link.enroll(&json!({ "name": "x" })).await, Err(Fail::Down(_))), "a foreign CA is refused");
    }
}

fn make_ca(dir: &Path) -> Vec<Cert> {
    let key = rcgen::KeyPair::generate().unwrap();
    let ca = tls::named_ca_params(tls::CA_CN).self_signed(&key).unwrap();
    std::fs::write(dir.join("ca.key.pem"), key.serialize_pem()).unwrap();
    std::fs::write(dir.join("ca.crt.pem"), ca.pem()).unwrap();
    ca_certs(Some(&dir.join("ca.crt.pem")))
}

fn load_other_ca() -> Vec<Cert> {
    let d = tempfile::tempdir().unwrap();
    make_ca(d.path())
}

/// Who gets in, on both protocols.
async fn refusals(w: &World, p: Ports) {
    // enrollment without a tenant key, and with an unknown or inactive tenant's
    for tk in [None, Some("nope".to_string())] {
        for link in w.links(p, Creds { tenant_key: tk.clone(), ..Default::default() }) {
            let r = link.enroll(&json!({ "name": "no-tenant" })).await;
            assert!(matches!(r, Err(Fail::Status(401, _))), "{}: {:?}", link.url(), r.err());
        }
    }
    for link in w.links(p, Creds { tenant_key: Some("tk_off".into()), ..Default::default() }) {
        assert!(matches!(link.enroll(&json!({ "name": "off" })).await, Err(Fail::Status(403, _))), "{}", link.url());
    }
    // an agent id with no key
    let stranger = Creds { agent_id: "99999".into(), key: "not-a-key".into(), ..Default::default() };
    for link in w.links(p, stranger) {
        assert!(matches!(link.keepalive(&json!({})).await, Err(Fail::Status(401, _))), "{}", link.url());
        let r = link.events(&[windows_event("x")]).await;
        assert!(matches!(r, Err(Fail::Status(401, _))), "{}: {:?}", link.url(), r.err());
        assert!(matches!(link.config().await, Err(Fail::Status(401, _))), "{}", link.url());
    }
    let c = w.enroll(p, "guarded").await;
    // the right key with another agent's id, a wrong key with the right id, another tenant's key
    let other = w.enroll(p, "other").await;
    let mixed = Creds { agent_id: other.agent_id.clone(), ..c.clone() };
    let wrong = Creds { key: "wrong".into(), ..c.clone() };
    let foreign = Creds { tenant_key: Some("tk_other".into()), ..c.clone() };
    let unknown = Creds { tenant_key: Some("nope".into()), ..c.clone() };
    for (creds, code) in [(mixed, 401), (wrong, 401), (foreign, 409), (unknown, 401)] {
        for link in w.links(p, creds) {
            let r = link.yara().await;
            assert!(matches!(&r, Err(Fail::Status(x, _)) if *x == code), "{}: {code}: {:?}", link.url(), r.err());
        }
    }
    // removed and deactivated agents: within 3 s of the row
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let row = |c: &Creds, deleted, disabled| stub::RegistryRow { agent_id: c.agent_id.clone(), name: "x".into(), tenant_id: "acme".into(), groups: String::new(), os_type: "windows".into(), deleted, enrolled_at: now, updated_at: now + 1, disabled };
    let mut i = w.db.insert("agent_registry").unwrap();
    i.write(&row(&c, 1, 0)).await.unwrap();
    i.write(&row(&other, 0, 1)).await.unwrap();
    i.end().await.unwrap();
    let t = Instant::now();
    for (creds, code) in [(c, 404u16), (other, 410)] {
        for link in w.links(p, creds) {
            // gRPC has one code for 403 and 410 (S13)
            let want = if code == 410 && link.url().starts_with("grpc") { 403 } else { code };
            until("the change takes effect", 3, async || matches!(link.yara().await, Err(Fail::Status(x, _)) if x == want)).await;
        }
    }
    println!("removal took effect in {:?}", t.elapsed());
}

/// The status of a request whose head is `head`, followed by `mib` chunks of 1 MiB.
async fn raw_status(w: &World, p: Ports, head: &str, mib: usize) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(w.roots.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", p.tls)).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let s = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await.unwrap();
    let (mut rd, mut wr) = tokio::io::split(s);
    wr.write_all(head.as_bytes()).await.unwrap();
    let chunk = format!("100000\r\n{}\r\n", "x".repeat(1024 * 1024));
    // read while writing: the answer comes before the body is all there
    let send = async {
        for _ in 0..mib {
            if wr.write_all(chunk.as_bytes()).await.is_err() {
                break;
            }
        }
    };
    let mut got = [0u8; 12];
    let (read, ()) = tokio::join!(tokio::time::timeout(Duration::from_secs(10), rd.read_exact(&mut got)), send);
    read.expect("answered").unwrap();
    String::from_utf8_lossy(&got[9..12]).parse().unwrap()
}

/// Refused before the body is read.
async fn oversized(w: &World, gw: &Gateway) {
    let p = gw.p;
    let c = w.enroll(p, "big").await;
    let http = http_client(false, &w.roots);
    let auth = format!("Bearer {}", c.key);
    let head = |key: &str, length: &str| format!("POST /api/v1/events/ingest HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {key}\r\n{length}\r\n\r\n");
    // over the limit, with the right key: the length alone refuses it; no body is sent
    assert_eq!(raw_status(w, p, &head(&c.key, &format!("Content-Length: {}", 16 * 1024 * 1024 + 1)), 0).await, 413);
    // under the limit, with a wrong key: refused with no byte of the body sent
    let before = gw.metric("bytes_in_total").await;
    assert_eq!(raw_status(w, p, &head("wrong", &format!("Content-Length: {}", 16 * 1024 * 1024)), 0).await, 401);
    assert!(gw.metric("bytes_in_total").await - before < 16_384.0);
    // no length told: stopped at the limit while reading
    assert_eq!(raw_status(w, p, &head(&c.key, "Transfer-Encoding: chunked"), 17).await, 413);
    // a keepalive's limit is its own
    let r = http.post(format!("https://localhost:{}/api/v1/agents/{}/keepalive", p.tls, c.agent_id)).header("authorization", &auth).body(vec![b' '; 70 * 1024]).send().await.unwrap();
    assert_eq!(r.status(), 413);
    // over gRPC the message limit answers, and the connection goes on
    let link = w.grpc(p, c.clone());
    let e = link.events(&[windows_event(&"x".repeat(17 * 1024 * 1024))]).await;
    assert!(e.is_err(), "too large for gRPC");
    // one event too large for the engine: dropped from its batch, the rest accepted
    let before = w.stub.received.load(Relaxed);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let link = w.grpc(p, c);
    link.events(&[windows_event(&"x".repeat(70_000)), windows_event("small")]).await.unwrap();
    until("the small one read", 5, async || w.stub.received.load(Relaxed) > before).await;
    assert!(gw.metric("events_too_large_total").await >= 1.0);
}

/// Backpressure, the engine down, siem-api down.
async fn engine_states(w: &World, gw: &Gateway) {
    let c = w.enroll(gw.p, "load").await;
    let link = w.grpc(gw.p, c.clone());
    w.stub.usage.store(500, Relaxed);
    until("429 while behind", 3, async || matches!(link.events(&[windows_event("late")]).await, Err(Fail::Status(429, _)))).await;
    link.keepalive(&json!({})).await.expect("keepalives go on");
    w.stub.usage.store(0, Relaxed);
    until("taken again", 3, async || link.events(&[windows_event("late")]).await.is_ok()).await;
    w.stub.down.store(true, Relaxed);
    until("503 with the engine down", 3, async || matches!(link.events(&[windows_event("down")]).await, Err(Fail::Down(_)))).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    link.keepalive(&json!({})).await.expect("keepalives go on");
    w.stub.down.store(false, Relaxed);
    until("open again", 3, async || link.events(&[windows_event("down")]).await.is_ok()).await;
    w.stub.api_down.store(true, Relaxed);
    let sent = w.stub.received.load(Relaxed);
    let r = link.events(&[windows_event("with an ar line"), json!({ "event_type": "ar_log", "log": "x" })]).await;
    assert!(matches!(r, Err(Fail::Down(_))), "{:?}", r.err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(w.stub.received.load(Relaxed), sent, "nothing of the batch reached the engine");
    w.stub.api_down.store(false, Relaxed);
    link.events(&[windows_event("with an ar line"), json!({ "event_type": "ar_log", "log": "x" })]).await.expect("the same batch, processed now");
    // limits per agent
    let r = async {
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let empty = json!({});
        let (a, b) = tokio::join!(link.keepalive(&empty), link.keepalive(&empty));
        [a.is_ok(), b.is_ok()]
    }.await;
    assert_eq!(r.iter().filter(|x| **x).count(), 1, "one keepalive a second");
    let http = http_client(false, &w.roots);
    let mut last = 0;
    for _ in 0..3 {
        // public downloads: the published files only
        last = http.get(format!("https://localhost:{}/downloads/windows/evil.exe", gw.p.tls)).send().await.unwrap().status().as_u16();
    }
    assert_eq!(last, 404);
    assert_eq!(http.get(format!("https://localhost:{}/api/v1/agents", gw.p.tls)).send().await.unwrap().status(), 404, "no console here");
    assert_eq!(http.get(format!("https://localhost:{}/api/v1/agent/state?agent_id={}", gw.p.tls, c.agent_id)).send().await.unwrap().json::<Value>().await.unwrap()["state"], "active");
}

/// A sender that does what an agent does: a batch stays until it is answered.
async fn send_until_taken(link: &dyn Link, batch: &[Value]) {
    loop {
        if link.events(batch).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Kill and planned stop in the middle of a run: no event, no command lost.
async fn restarts(w: &World, gw: &mut Gateway, extra: &[(&str, &str)]) {
    let p = gw.p;
    let c = w.enroll(p, "restart").await;
    w.stub.keep.store(true, Relaxed);
    w.stub.messages.lock().unwrap().clear();
    let sender = {
        let link: Arc<dyn Link> = Arc::new(w.grpc(p, c.clone()));
        tokio::spawn(async move {
            let mut n = 0;
            for i in 0..600 {
                let batch: Vec<Value> = (0..5).map(|j| windows_event(&format!("run {i} {j} end"))).collect();
                send_until_taken(link.as_ref(), &batch).await;
                n += 5;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            n
        })
    };
    w.queue_command(&c.agent_id, "before-kill", "scan").await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    gw.crash();
    w.queue_command(&c.agent_id, "while-down", "scan").await;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    *gw = w.gateway(p, extra);
    gw.ready().await;
    tokio::time::sleep(Duration::from_millis(2000)).await;
    gw.stop().await;
    w.queue_command(&c.agent_id, "while-stopped", "scan").await;
    *gw = w.gateway(p, extra);
    gw.ready().await;
    let sent = sender.await.unwrap();
    until("the engine read the last", 10, async || w.stub.messages.lock().unwrap().len() >= sent).await;
    let m = w.stub.messages.lock().unwrap();
    let missing: Vec<_> = (0..600).flat_map(|i| (0..5).map(move |j| format!("run {i} {j} end"))).filter(|t| !m.keys().any(|k| k.ends_with(t.as_str()))).collect();
    let repeats = m.values().filter(|n| **n > 1).count();
    println!("restart: {sent} events sent, {} distinct read, {repeats} read twice", m.len());
    assert!(missing.is_empty(), "lost: {:?}", &missing[..missing.len().min(5)]);
    drop(m);
    w.stub.keep.store(false, Relaxed);

    let link = w.grpc(p, c.clone());
    let mut got = Vec::new();
    until("every command handed out", 15, async || {
        if let Ok(cmds) = link.keepalive(&json!({})).await {
            got.extend(cmds.iter().filter_map(|c| c["command_id"].as_str().map(str::to_string)));
        }
        ["before-kill", "while-down", "while-stopped"].iter().all(|id| got.iter().any(|g| g == id))
    }).await;
    for id in ["before-kill", "while-down", "while-stopped"] {
        assert_eq!(got.iter().filter(|g| *g == id).count(), 1, "{id} once: {got:?}");
    }
}

/// Two gateways, one ClickHouse, one engine.
async fn two_gateways(w: &World, a: &Gateway) {
    let extra = [("GATEWAY_COUNT", "2"), ("GATEWAY_SENDER", "2")];
    let q = ports();
    let b = w.gateway(q, &extra);
    b.ready().await;
    let c = w.enroll(a.p, "both").await;
    let (la, lb) = (w.grpc(a.p, c.clone()), w.grpc(q, c.clone()));
    until("the other gateway knows the key", 4, async || lb.yara().await.is_ok()).await;
    // a command is handed out once, whichever gateway the agent speaks to
    w.queue_command(&c.agent_id, "one-of-two", "getstate").await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let empty = json!({});
    let (x, y) = tokio::join!(la.keepalive(&empty), async {
        // a real agent's keepalives are 10 s apart: "handed out" reaches the other gateway by then
        tokio::time::sleep(Duration::from_millis(std::env::var("GATEWAY_TEST_GAP_MS").ok().and_then(|g| g.parse().ok()).unwrap_or(10_000))).await;
        lb.keepalive(&empty).await
    });
    let n = x.unwrap().len() + y.unwrap().len();
    assert_eq!(n, 1, "handed out once");
    // the result goes through the other one; both forget the command
    lb.result(&json!({ "command_id": "one-of-two", "status": "done" })).await.unwrap();
    until("done, from the other gateway", 5, async || w.command_state("one-of-two").await == "done").await;
    // events through either reach the one engine; each counts its own
    let before = w.stub.received.load(Relaxed);
    la.events(&[windows_event("via a")]).await.unwrap();
    lb.events(&[windows_event("via b")]).await.unwrap();
    until("both read", 5, async || w.stub.received.load(Relaxed) >= before + 2).await;
    assert!(b.metric("engine_datagrams_sent_total").await >= 1.0);
    // a planned stop of one: the agent goes on with the other
    let mut b = b;
    b.stop().await;
    la.events(&[windows_event("after b stopped")]).await.unwrap();
}

async fn observability(w: &World, gw: &Gateway) {
    let text = reqwest::get(gw.stats("/metrics")).await.unwrap().text().await.unwrap();
    for k in ["provigil_gateway_keepalives_received_total", "provigil_gateway_tls_ok_total", "provigil_gateway_engine_lag", "provigil_gateway_cache_keys", "provigil_gateway_calls_total{kind=\"keepalive\",outcome=\"200\"}"] {
        assert!(text.contains(k), "{k} in {text}");
    }
    let s: Value = reqwest::get(gw.stats("/state")).await.unwrap().json().await.unwrap();
    assert!(s["settings"]["grpc_port"].is_number() && s["gauges"]["cache_keys"].as_f64() > Some(0.0), "{s}");
    assert!(!s.to_string().contains(SECRET) && !s.to_string().contains("internal\""), "no secret");
    let a: Value = reqwest::get(gw.stats("/state/agents")).await.unwrap().json().await.unwrap();
    assert!(a["agents"].as_array().is_some_and(|x| !x.is_empty()), "{a}");
    assert_eq!(reqwest::get(gw.stats("/health")).await.unwrap().status(), 200);
    let mut gw2 = w.gateway(ports(), &[]);
    gw2.ready().await;
    gw2.stop().await;
    let rows = w.db.query("SELECT count() FROM gateway_state").fetch_one::<u64>().await.unwrap();
    assert!(rows >= 1, "the state row");
}

/// A stand-in for ClickHouse going away and coming back: a port that forwards to the real one
/// only while this task runs; aborting it ends every connection.
fn forward_clickhouse(l: tokio::net::TcpListener, target: String) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut open = tokio::task::JoinSet::new();
        while let Ok((mut c, _)) = l.accept().await {
            let target = target.clone();
            open.spawn(async move {
                if let Ok(mut t) = tokio::net::TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut c, &mut t).await;
                }
            });
        }
    })
}

/// ClickHouse away at start: not ready, agents told to come back; ready within 5 s of its return.
/// Away later: agents go on with the cached keys.
async fn clickhouse_away(w: &World) {
    let port = free_port();
    let target = w.ch.trim_start_matches("http://").to_string();
    let p = ports();
    let gw = w.gateway(p, &[("CLICKHOUSE_URL", &format!("http://127.0.0.1:{port}"))]);
    let health = async || {
        let r = reqwest::get(gw.stats("/health")).await.ok()?;
        Some((r.status().as_u16(), r.json::<Value>().await.ok()?))
    };
    until("the stats listener", 10, async || health().await.is_some()).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (code, body) = health().await.unwrap();
    assert_eq!((code, body["caches"].as_bool()), (503, Some(false)), "{body}");
    let c = Creds { agent_id: "001".into(), key: "k".into(), ..Default::default() };
    let e = w.grpc(p, c.clone()).keepalive(&json!({})).await;
    assert!(matches!(e, Err(Fail::Down(_))), "gRPC UNAVAILABLE: {:?}", e.err());
    let e = w.https(p, c).keepalive(&json!({})).await;
    assert!(matches!(e, Err(Fail::Status(503, _))), "HTTPS 503: {:?}", e.err());

    let l = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let back = forward_clickhouse(l, target.clone());
    let t = Instant::now();
    gw.ready().await;
    println!("ready {:?} after ClickHouse returned", t.elapsed());
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());

    let creds = w.enroll(p, "away").await;
    let link = w.grpc(p, creds);
    link.keepalive(&json!({})).await.unwrap();
    back.abort();
    let _ = back.await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    link.keepalive(&json!({})).await.expect("keepalives go on without ClickHouse");
    link.events(&[windows_event("while ClickHouse is away")]).await.expect("events go on");
    link.result(&json!({ "command_id": "none", "status": "done" })).await.expect("results go on");
    assert!(gw.metric("cache_poll_failures_total").await >= 1.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a private ClickHouse: GATEWAY_TEST_CLICKHOUSE"]
async fn gateway_end_to_end() {
    let ch = std::env::var("GATEWAY_TEST_CLICKHOUSE").expect("GATEWAY_TEST_CLICKHOUSE");
    let dir = tempfile::tempdir().unwrap();
    let (home, ca_dir, dist) = (dir.path().join("home"), dir.path().join("tls"), dir.path().join("dist"));
    for d in [home.join("etc/shared/default"), ca_dir.clone(), dist.join("windows")] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(home.join("etc/shared/default/siem-yara.rules"), "YARA RULES").unwrap();
    std::fs::write(dist.join("windows/provigil-agent.exe"), EXE).unwrap();
    let roots = make_ca(&ca_dir);
    let db = stub::prepare(&ch).await;
    stub::add_tenant(&db, "acme", TENANT_KEY, 1).await;
    stub::add_tenant(&db, "other", "tk_other", 1).await;
    stub::add_tenant(&db, "off", "tk_off", 0).await;
    let s = Arc::new(Stub::default());
    s.keep_queries.store(true, Relaxed);
    s.start_sockets(&home).await;
    let tenants: HashMap<String, String> = [(TENANT_KEY.to_string(), "acme".to_string()), ("tk_other".to_string(), "other".to_string())].into_iter().collect();
    let api = s.start_api(db.clone(), SECRET, tenants).await;
    let w = World { home, ca_dir, dist, ch, api, db, stub: s, roots };

    let p = ports();
    let mut gw = w.gateway(p, &[("GATEWAY_ENGINE_QUEUES", "0")]);
    gw.ready().await;
    every_call(&w, p).await;
    println!("every call: ok");
    refusals(&w, p).await;
    println!("refusals: ok");
    oversized(&w, &gw).await;
    println!("oversized: ok");
    engine_states(&w, &gw).await;
    println!("engine states: ok");
    observability(&w, &gw).await;
    println!("metrics: ok");
    two_gateways(&w, &gw).await;
    println!("two gateways: ok");
    restarts(&w, &mut gw, &[("GATEWAY_ENGINE_QUEUES", "0")]).await;
    println!("restarts: ok");
    clickhouse_away(&w).await;
    println!("ClickHouse away: ok");
}
