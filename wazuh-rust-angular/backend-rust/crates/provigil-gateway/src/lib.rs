//! `provigil-gateway`: the agent front door (`specs/provigil-gateway.md`). One process serves gRPC
//! and HTTPS to agents with no state of its own: keys, registry, tenants and commands are read
//! from ClickHouse, agent state goes to provigil-db, events to the engine.

pub mod agents;
pub mod cache;
pub mod core;
pub mod engine_link;
pub mod engine_queues;
pub mod grpc;
pub mod http;
pub mod limits;
pub mod observe;
pub mod queue;
pub mod server;
pub mod settings;
pub mod stats;
pub mod upstream;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

use provigil_agent_server::{agent_state, commands, keys, DEFAULT_DB};
use serde_json::Value;
use provigil_ipc::agentdb::{DbQuery, DbSocket, DB_SOCKET};
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use crate::core::Gw;
use crate::settings::Settings;

const POLL_EVERY: Duration = Duration::from_secs(2);
const QUEUE_POLL_EVERY: Duration = Duration::from_secs(1);
/// Under 5 s, so a gateway is ready within 5 s of ClickHouse returning.
const RETRY_EVERY: Duration = Duration::from_secs(4);
const MARKS_EVERY: Duration = Duration::from_millis(500);
const FLUSH_EVERY: Duration = Duration::from_secs(10);
const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// Flushes between rewrites of every agent's node, IP and version (about an hour).
const ROW_REFRESH_FLUSHES: u32 = 360;
/// What a stop waits for at most: the longest call.
const DRAIN: Duration = Duration::from_secs(14);

struct Host {
    gw: Arc<Gw>,
    wdb: DbSocket,
    inventory: Vec<DbSocket>,
}

impl agent_state::Host for Host {
    fn home(&self) -> PathBuf {
        self.gw.s.home.clone()
    }
    fn wdb(&self) -> &dyn DbQuery {
        &self.wdb
    }
    fn inventory_wdb(&self, agent_id: &str) -> &dyn DbQuery {
        &self.inventory[core::lane(agent_id, self.inventory.len())]
    }
    fn queue_command(&self, agent_id: &str, command: Value) {
        let tenant = self.gw.cache.registered(agent_id).map(|r| r.tenant.clone()).unwrap_or_default();
        core::push_full_send(&self.gw, &tenant, agent_id, &command);
    }
}

/// The ClickHouse client of the shared database.
pub fn database(s: &Settings) -> clickhouse::Client {
    let c = clickhouse::Client::default().with_url(&s.clickhouse_url).with_user(&s.clickhouse_user).with_database(DEFAULT_DB);
    if s.clickhouse_password.is_empty() {
        c
    } else {
        c.with_password(&s.clickhouse_password)
    }
}

async fn write_state_row(gw: &Gw, db: &clickhouse::Client) {
    let row = observe::state_row(gw);
    if let Err(e) = async {
        let mut i = db.insert("gateway_state")?;
        i.write(&row).await?;
        i.end().await
    }
    .await
    {
        warn!("gateway_state: {e}");
    }
}

/// Keeps the caches and the command queue current. Until the first load the gateway answers
/// UNAVAILABLE / 503 and its health says not ready.
async fn cache_loop(gw: Arc<Gw>, db: clickhouse::Client, cipher: keys::Cipher) {
    let mut lost = false;
    loop {
        let first = !gw.cache.ready.load(Relaxed);
        let tables = async {
            if first {
                db.query(commands::DDL).execute().await?;
                db.query(commands::PROTOCOL_DDL).execute().await?;
                db.query(observe::STATE_DDL).execute().await?;
            }
            gw.queue.poll(&db, first).await?;
            gw.cache.poll(&db, &cipher).await
        };
        match tables.await {
            Ok(changed) => {
                gw.cache.last_poll_ms.store(queue::now_ms(), Relaxed);
                if lost {
                    lost = false;
                    warn!("ClickHouse is back");
                }
                if !changed.is_empty() {
                    gw.stats.c.key_reloads.fetch_add(1, Relaxed);
                }
                for id in changed {
                    gw.agents.forget(&id);
                    agent_state::forget(&id);
                }
            }
            Err(e) => {
                gw.stats.c.cache_poll_failures.fetch_add(1, Relaxed);
                if !lost {
                    lost = true;
                    error!("ClickHouse lost: agents go on with the cached keys: {e}");
                }
                if first {
                    tokio::time::sleep(RETRY_EVERY).await;
                    continue;
                }
            }
        }
        tokio::time::sleep(POLL_EVERY).await;
    }
}

/// Commands between the key polls: written here reach another gateway within about 3 s.
async fn queue_loop(gw: Arc<Gw>, db: clickhouse::Client) {
    loop {
        tokio::time::sleep(QUEUE_POLL_EVERY).await;
        if gw.cache.ready.load(Relaxed) {
            if let Err(e) = gw.queue.poll(&db, false).await {
                tracing::debug!("agent_command_queue: {e}");
            }
        }
    }
}

async fn marks_loop(gw: Arc<Gw>, db: clickhouse::Client) {
    loop {
        tokio::time::sleep(MARKS_EVERY).await;
        gw.queue.flush(&db).await;
    }
}

async fn flush_keepalives(gw: &Gw) {
    let (seen, meta) = gw.agents.take_seen_with_meta();
    if seen.is_empty() && meta.is_empty() {
        return;
    }
    let items: Vec<Value> = meta
        .into_iter()
        .map(|(id, ip, ver)| serde_json::json!({ "agent_id": id, "version": ver, "ip": ip }))
        .collect();
    let n = seen.len() as u64;
    if !seen.is_empty() {
        agent_state::flush_seen(seen).await;
        gw.stats.c.keepalive_rows_flushed.fetch_add(n, Relaxed);
    }
    if !gw.up.is_empty() && !items.is_empty() {
        let up = gw.up.clone();
        tokio::spawn(async move {
            let _ = up.keepalives(&items).await;
        });
    }
}

async fn flush_loop(gw: Arc<Gw>) {
    let mut flushes = 0u32;
    loop {
        tokio::time::sleep(FLUSH_EVERY).await;
        flushes = flushes.wrapping_add(1);
        // a row re-created behind our back (a restored provigil-db) gets its fields back
        if flushes.is_multiple_of(ROW_REFRESH_FLUSHES) {
            agent_state::refresh_rows();
        }
        flush_keepalives(&gw).await;
        gw.agents.prune(queue::now_ms(), gw.s.disconnection_secs * 1000);
        // once a minute: agents gone silent are shown disconnected
        if flushes.is_multiple_of(6) {
            let n = agent_state::disconnect_silent(gw.s.disconnection_secs).await;
            if n > 0 {
                tracing::info!("{n} silent agent(s) marked disconnected");
            }
        }
    }
}

async fn sweep_loop(gw: Arc<Gw>, db: clickhouse::Client) {
    let mut n = 0u32;
    loop {
        tokio::time::sleep(SWEEP_EVERY).await;
        gw.queue.sweep();
        n += 1;
        if n.is_multiple_of(2) {
            write_state_row(&gw, &db).await;
        }
    }
}

async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut t) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = t.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// Runs until a stop: Ctrl-C, SIGTERM or `POST /shutdown` on the stats listener.
pub async fn run(s: Settings) -> Result<(), String> {
    std::fs::create_dir_all(&s.home).map_err(|e| format!("{}: {e}", s.home.display()))?;
    let cipher = keys::cipher(&s.keys_secret).ok_or("AGENT_KEYS_SECRET cannot be used")?;
    let stats = Arc::new(stats::Stats::default());
    let (jobs, jobs_rx) = mpsc::channel(core::JOBS_MAX);
    // one lane per provigil-db connection; an agent always takes the same one, so its inventory
    // and its deltas are applied in order
    let (inventory, inventory_rx): (Vec<_>, Vec<_>) = (0..s.inventory_workers).map(|_| mpsc::channel(core::INVENTORIES_MAX / s.inventory_workers)).unzip();
    let (stop_tx, stop_rx) = watch::channel(false);
    let db = database(&s);
    let gw = Arc::new(Gw {
        cache: cache::Cache::default(),
        queue: Arc::new(queue::Queue::new(&s.id, stats.clone())),
        agents: agents::Agents::default(),
        engine: Arc::default(),
        up: upstream::Upstream::new(&s.api_url, &s.internal_token),
        limits: limits::Limits::new(s.enroll_per_minute, s.enroll_per_second),
        jobs,
        inventory,
        started_ms: queue::now_ms(),
        stopping: AtomicBool::new(false),
        stats: stats.clone(),
        s,
    });
    let sock = || DbSocket::new(gw.s.home.join(DB_SOCKET));
    agent_state::set_host(Arc::new(Host { gw: gw.clone(), wdb: sock(), inventory: (0..gw.s.inventory_workers).map(|_| sock()).collect() }));

    // every listener first: a port that cannot be bound stops the start
    let (_, tls_cfg) = server::start_tls(&gw)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));
    let bind = |port| server::listeners(gw.s.bind, port).map_err(|e| format!("port {port}: {e}"));
    let (grpc_l, tls_l) = (bind(gw.s.grpc_port)?, bind(gw.s.tls_port)?);
    let stats_l = tokio::net::TcpListener::bind(gw.s.stats_addr).await.map_err(|e| format!("{}: {e}", gw.s.stats_addr))?;

    tokio::spawn(core::state_worker(gw.clone(), jobs_rx));
    for rx in inventory_rx {
        tokio::spawn(core::inventory_worker(gw.clone(), rx));
    }
    tokio::spawn(gw.engine.clone().run(gw.s.home.clone(), gw.s.sender, stats));
    tokio::spawn(cache_loop(gw.clone(), db.clone(), cipher));
    tokio::spawn(queue_loop(gw.clone(), db.clone()));
    tokio::spawn(marks_loop(gw.clone(), db.clone()));
    tokio::spawn(flush_loop(gw.clone()));
    tokio::spawn(sweep_loop(gw.clone(), db.clone()));
    if gw.s.engine_queues {
        engine_queues::start(gw.clone());
    }

    let app = http::app(gw.clone());
    let mut serving = Vec::new();
    for l in grpc_l {
        serving.push(tokio::spawn(server::serve(l, app.clone(), Some(acceptor.clone()), gw.clone(), 0, stop_rx.clone())));
    }
    for l in tls_l {
        serving.push(tokio::spawn(server::serve(l, app.clone(), Some(acceptor.clone()), gw.clone(), 1, stop_rx.clone())));
    }
    if gw.s.plain_loopback {
        let l = server::listener(([127, 0, 0, 1], gw.s.plain_port).into()).map_err(|e| format!("port {}: {e}", gw.s.plain_port))?;
        serving.push(tokio::spawn(server::serve(l, app.clone(), None, gw.clone(), 2, stop_rx.clone())));
    }
    let (ask_stop, asked) = watch::channel(false);
    let observe_app = observe::app(gw.clone(), ask_stop);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(stats_l, observe_app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await {
            error!("Stats listener stopped: {e}");
        }
    });
    info!("provigil-gateway {} listening: gRPC {}, HTTPS {}, stats {}", gw.s.id, gw.s.grpc_port, gw.s.tls_port, gw.s.stats_addr);

    let mut asked = asked;
    tokio::select! {
        _ = stop_signal() => {}
        _ = asked.changed() => {}
    }
    info!("Stopping: draining calls in progress");
    gw.stopping.store(true, Relaxed);
    let _ = stop_tx.send(true);
    for s in serving {
        let _ = s.await;
    }
    let until = tokio::time::Instant::now() + DRAIN;
    while server::OPEN.total.load(Relaxed) > 0 && tokio::time::Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    flush_keepalives(&gw).await;
    write_state_row(&gw, &db).await;
    if !gw.queue.flush(&db).await {
        warn!("Stopped with command marks not written: a command handed out may be handed out again");
    }
    info!("Stopped");
    Ok(())
}
