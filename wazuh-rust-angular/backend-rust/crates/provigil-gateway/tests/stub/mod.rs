//! Stand-ins for what surrounds a gateway: the engine (its input and load socket), provigil-db and
//! siem-api's internal API. Enrollment writes real rows to ClickHouse, as siem-api does.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use clickhouse::Client;
use provigil_agent_server::keys;
use serde::Serialize;
use serde_json::{json, Value};
use provigil_ipc::aio::{DatagramReceiver, StreamListener};
use provigil_ipc::aio::framing;
use tokio::sync::{mpsc, oneshot};

#[derive(clickhouse::Row, Serialize)]
pub struct KeyRow {
    pub agent_id: String,
    pub key_enc: String,
    pub deleted: u8,
    pub updated_at: u64,
}

#[derive(clickhouse::Row, Serialize)]
pub struct RegistryRow {
    pub agent_id: String,
    pub name: String,
    pub tenant_id: String,
    pub groups: String,
    pub os_type: String,
    pub deleted: u8,
    pub enrolled_at: u64,
    pub updated_at: u64,
    pub disabled: u8,
}

pub const TABLES: [&str; 5] = [
    "CREATE DATABASE IF NOT EXISTS ndr",
    "CREATE TABLE IF NOT EXISTS ndr.agent_keys (agent_id String, key_enc String, deleted UInt8, updated_at UInt64) ENGINE = ReplacingMergeTree(updated_at) ORDER BY agent_id",
    "CREATE TABLE IF NOT EXISTS ndr.agent_registry (agent_id String, name String, tenant_id LowCardinality(String), groups String, os_type LowCardinality(String), deleted UInt8, enrolled_at UInt64, updated_at UInt64, disabled UInt8 DEFAULT 0) ENGINE = ReplacingMergeTree(updated_at) ORDER BY agent_id",
    "CREATE TABLE IF NOT EXISTS ndr.tenant_agent_keys (tenant_id LowCardinality(String), agent_key String, created_at UInt64) ENGINE = ReplacingMergeTree() ORDER BY tenant_id",
    "CREATE TABLE IF NOT EXISTS ndr.tenants (id String, name String, active UInt8) ENGINE = ReplacingMergeTree() ORDER BY id",
];

/// A client of ClickHouse with the tables, for the stub and the tests.
pub async fn prepare(url: &str) -> Client {
    let root = Client::default().with_url(url);
    for t in TABLES {
        root.query(t).execute().await.expect("ClickHouse");
    }
    root.with_database("ndr")
}

pub async fn add_tenant(db: &Client, tenant: &str, key: &str, active: u8) {
    db.query("INSERT INTO ndr.tenants (id, name, active) VALUES (?, ?, ?)").bind(tenant).bind(tenant).bind(active).execute().await.unwrap();
    db.query("INSERT INTO ndr.tenant_agent_keys (tenant_id, agent_key, created_at) VALUES (?, ?, 1)").bind(tenant).bind(key).execute().await.unwrap();
}

#[derive(Default)]
pub struct Stub {
    /// Datagrams the engine read.
    pub received: AtomicU64,
    /// The engine's fullest queue, in thousandths.
    pub usage: AtomicU64,
    /// The engine does not answer its load socket.
    pub down: AtomicBool,
    /// Keep the messages (tests): text -> how often.
    pub keep: AtomicBool,
    pub messages: Mutex<HashMap<String, u32>>,
    /// provigil-db statements.
    pub queries: AtomicU64,
    pub keep_queries: AtomicBool,
    pub statements: Mutex<Vec<String>>,
    /// Forwarded to siem-api: ar_log lines and other events.
    pub ar_lines: AtomicU64,
    pub other_events: AtomicU64,
    pub api_down: AtomicBool,
    pub next_id: AtomicU64,
}

impl Stub {
    /// Engine and provigil-db at `home`.
    pub async fn start_sockets(self: &Arc<Self>, home: &std::path::Path) {
        for d in ["queue/sockets", "queue/db", "queue/alerts", "queue/router"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        let input = DatagramReceiver::bind(home.join(provigil_ipc::queue::EVENT_QUEUE)).await.unwrap();
        let me = self.clone();
        tokio::spawn(async move {
            while let Ok(m) = input.recv(70_000).await {
                me.received.fetch_add(1, Relaxed);
                if me.keep.load(Relaxed) {
                    let text = String::from_utf8_lossy(&m).to_string();
                    *me.messages.lock().unwrap().entry(text).or_default() += 1;
                }
            }
        });
        let load = StreamListener::bind(home.join("queue/sockets/analysis")).await.unwrap();
        let me = self.clone();
        tokio::spawn(async move {
            while let Ok(mut s) = load.accept().await {
                let me = me.clone();
                tokio::spawn(async move {
                    while framing::recv(&mut s, 4096).await.is_ok() {
                        if me.down.load(Relaxed) {
                            return;
                        }
                        // every gateway of the tests is sender 1 unless told otherwise; each counts its own
                        let n = me.received.load(Relaxed);
                        let a = json!({ "data": { "queue_usage": me.usage.load(Relaxed) as f64 / 1000.0, "received": 0, "senders": { "1": n, "2": n } } });
                        if framing::send(&mut s, a.to_string().as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let wdb = StreamListener::bind(home.join("queue/db/wdb")).await.unwrap();
        let me = self.clone();
        tokio::spawn(async move {
            while let Ok(mut s) = wdb.accept().await {
                let me = me.clone();
                tokio::spawn(async move {
                    while let Ok(q) = framing::recv(&mut s, 70_000).await {
                        me.queries.fetch_add(1, Relaxed);
                        let q = String::from_utf8_lossy(&q).to_string();
                        let a = if q.starts_with("global get-agent-info") { "ok [{\"id\":1}]".to_string() } else { "ok []".to_string() };
                        if me.keep_queries.load(Relaxed) {
                            me.statements.lock().unwrap().push(q);
                        }
                        if framing::send(&mut s, a.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
    }

    /// siem-api's internal API; the address.
    pub async fn start_api(self: &Arc<Self>, db: Client, secret: &str, tenants: HashMap<String, String>) -> String {
        // a batch of rows per write: a part per enrollment would hold them all up
        let (tx, mut rx) = mpsc::channel::<(KeyRow, RegistryRow, oneshot::Sender<()>)>(1024);
        tokio::spawn(async move {
            while let Some(first) = rx.recv().await {
                let mut batch = vec![first];
                while let Ok(n) = rx.try_recv() {
                    batch.push(n);
                }
                let mut keys_in = db.insert("agent_keys").unwrap();
                let mut reg_in = db.insert("agent_registry").unwrap();
                for (k, r, _) in &batch {
                    keys_in.write(k).await.unwrap();
                    reg_in.write(r).await.unwrap();
                }
                reg_in.end().await.unwrap();
                keys_in.end().await.unwrap();
                batch.into_iter().for_each(|(_, _, done)| {
                    let _ = done.send(());
                });
            }
        });
        let me = self.clone();
        let m2 = self.clone();
        let m3 = self.clone();
        let cipher = Arc::new(keys::cipher(secret).unwrap());
        let tenants = Arc::new(tenants);
        let app = Router::new()
            .route("/internal/gateway/enroll", post(move |Json(v): Json<Value>| {
                let (me, cipher, tenants, tx) = (me.clone(), cipher.clone(), tenants.clone(), tx.clone());
                async move {
                    if me.api_down.load(Relaxed) {
                        return Err(StatusCode::SERVICE_UNAVAILABLE);
                    }
                    let tenant = tenants.get(v["tenant_key"].as_str().unwrap_or_default()).cloned().ok_or(StatusCode::UNAUTHORIZED)?;
                    let name = v["request"]["name"].as_str().unwrap_or_default().to_string();
                    let id = format!("{:03}", 1000 + me.next_id.fetch_add(1, Relaxed));
                    let key = uuid::Uuid::new_v4().simple().to_string();
                    let now = chrono::Utc::now().timestamp_millis() as u64;
                    let key_enc = keys::encrypt(&cipher, &format!("{id} {name} any {key}")).unwrap();
                    let (done, wait) = oneshot::channel();
                    let reg = RegistryRow { agent_id: id.clone(), name: name.clone(), tenant_id: tenant.clone(), groups: String::new(), os_type: "windows".into(), deleted: 0, enrolled_at: now, updated_at: now, disabled: 0 };
                    tx.send((KeyRow { agent_id: id.clone(), key_enc, deleted: 0, updated_at: now }, reg, done)).await.unwrap();
                    wait.await.unwrap();
                    Ok(Json(json!({ "agent_id": id, "agent_name": name, "agent_ip": "any", "raw_key": key, "tenant_id": tenant, "groups": "default" })))
                }
            }))
            .route("/internal/gateway/ar_log", post(move |Json(v): Json<Value>| {
                let me = m2.clone();
                async move {
                    if me.api_down.load(Relaxed) {
                        return Err(StatusCode::SERVICE_UNAVAILABLE);
                    }
                    me.ar_lines.fetch_add(v["lines"].as_array().map_or(0, Vec::len) as u64, Relaxed);
                    Ok(Json(json!({})))
                }
            }))
            .route("/internal/gateway/events", post(move |Json(v): Json<Value>| {
                let me = m3.clone();
                async move {
                    if me.api_down.load(Relaxed) {
                        return Err(StatusCode::SERVICE_UNAVAILABLE);
                    }
                    me.other_events.fetch_add(v["events"].as_array().map_or(0, Vec::len) as u64, Relaxed);
                    Ok(Json(json!({})))
                }
            }));
        let me = self.clone();
        let app = app.route("/stats", get(move || {
            let me = me.clone();
            async move { Json(json!({ "received": me.received.load(Relaxed), "queries": me.queries.load(Relaxed), "ar_lines": me.ar_lines.load(Relaxed), "other": me.other_events.load(Relaxed) })) }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        format!("http://{addr}")
    }
}
