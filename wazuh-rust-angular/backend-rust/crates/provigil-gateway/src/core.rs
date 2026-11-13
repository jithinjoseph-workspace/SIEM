//! The agent calls, the same for gRPC and HTTPS. Keepalives and events touch memory and the engine
//! link only: provigil-db and ClickHouse work is queued for the background, bounded.

use std::path::PathBuf;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Instant;

use provigil_agent_server::{agent_config, agent_state, commands as cmd, engine, published};
use serde_json::{json, Value};
use siem_ipc::mq::queues;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::agents::{AgentRt, Agents};
use crate::cache::{Authed, Cache, Registered};
use crate::engine_link::EngineLink;
use crate::queue::{now_ms, Queue};
use crate::settings::Settings;
use crate::stats::Stats;
use crate::upstream::Upstream;

/// provigil-db work waiting at most.
pub const JOBS_MAX: usize = 10_000;
/// Full inventories waiting at most: each holds the whole list (hundreds of KiB), so 10,000
/// would be gigabytes; beyond this the agent keeps it (503) and sends it again.
pub const INVENTORIES_MAX: usize = 256;

/// A refusal: the status and why.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Refuse(pub u16, pub &'static str);

pub enum Job {
    Keepalive { id: String, tenant: String, name: String, groups: String, body: Value },
    Stopped { id: String, name: String, ip: String },
    Inventory { id: String, tenant: String, items: Vec<Value> },
}

pub struct Gw {
    pub s: Settings,
    pub stats: Arc<Stats>,
    pub cache: Cache,
    pub queue: Arc<Queue>,
    pub agents: Agents,
    pub engine: Arc<EngineLink>,
    pub up: Upstream,
    pub jobs: mpsc::Sender<Job>,
    /// One per provigil-db connection for inventories ([`lane`]).
    pub inventory: Vec<mpsc::Sender<Job>>,
    pub started_ms: u64,
    pub stopping: std::sync::atomic::AtomicBool,
    pub limits: crate::limits::Limits,
}

impl Gw {
    /// Counts a 429 or 503 by its reason.
    pub fn refuse(&self, r: Refuse) -> Refuse {
        if matches!(r.0, 429 | 503) {
            self.stats.refused(r.1, now_ms());
        }
        r
    }

    fn engine_open(&self) -> Result<(), Refuse> {
        if !self.engine.running.load(Relaxed) {
            return Err(self.refuse(Refuse(503, "engine_down")));
        }
        if self.engine.behind.load(Relaxed) {
            return Err(self.refuse(Refuse(429, "engine_behind")));
        }
        Ok(())
    }
}

/// The manager-added labels (R32): as the engine puts them on the agent's alerts.
fn manager_labels(gw: &Gw, version: Option<&str>) -> Vec<(String, String)> {
    let mut l = vec![("_manager_hostname".to_string(), sysinfo::System::host_name().unwrap_or_default()), ("_node_name".to_string(), gw.s.node_name.clone())];
    if let Some(v) = version {
        l.push(("_agent_version".to_string(), v.to_string()));
    }
    l
}

/// The background writer of keepalive state; one at a time keeps provigil-db's order.
pub async fn state_worker(gw: Arc<Gw>, mut rx: mpsc::Receiver<Job>) {
    while let Some(job) = rx.recv().await {
        match job {
            Job::Keepalive { id, tenant, name, groups, body } => {
                let version = agent_state::clean_version(body["version"].as_str());
                agent_state::labels(&id, &body, &manager_labels(&gw, version.as_deref())).await;
                if let Some(applied) = body["group_config_version"].as_str() {
                    let current = gw.agents.get(&id).group_version(now_ms(), || agent_config::for_agent(&gw.s.home, &tenant, &name, &groups)["version"].as_str().unwrap_or_default().to_string());
                    agent_state::group_config(&id, current == applied).await;
                }
            }
            Job::Stopped { id, name, ip } => {
                agent_state::stopped(&id).await;
                // what the engine's rule on a stopped agent reads
                let message = format!("ossec: Agent stopped: '{name}->{ip}'.");
                if let Some(d) = engine::source(&id, &name, &ip).and_then(|s| engine::datagram(gw.s.sender, &s, queues::LOCALFILE_MQ, "ossec", &message)) {
                    if let Err(e) = gw.engine.send(&gw.stats, &[d]).await {
                        warn!("agent {id}: \"agent stopped\" not sent to the engine: {e}");
                    }
                }
            }
            Job::Inventory { .. } => {}
        }
    }
}

/// The lane of an agent's inventories: always the same for one agent.
pub fn lane(agent_id: &str, lanes: usize) -> usize {
    agent_id.parse::<usize>().unwrap_or_else(|_| agent_id.bytes().map(usize::from).sum()) % lanes.max(1)
}

/// Copies of full inventories on their way to siem-api at most.
const COPIES: usize = 16;

/// The background writer of inventories, on its own connection. A full inventory then also goes
/// to siem-api's event store (the agent's inventory page reads the latest there); provigil-db
/// holds the inventory itself, so a copy siem-api cannot take now is counted and skipped.
pub async fn inventory_worker(gw: Arc<Gw>, mut rx: mpsc::Receiver<Job>) {
    static COPYING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(COPIES);
    while let Some(job) = rx.recv().await {
        let Job::Inventory { id, tenant, items } = job else { continue };
        agent_state::store(&id, &items).await;
        let full: Vec<Value> = items.into_iter().filter(|i| kind_of(i) == Some("system_inventory")).collect();
        if full.is_empty() {
            continue;
        }
        let Ok(permit) = COPYING.try_acquire() else {
            gw.stats.c.inventory_copies_skipped.fetch_add(1, Relaxed);
            continue;
        };
        let gw = gw.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match gw.up.events(&id, &tenant, &full).await {
                Ok(()) => gw.stats.c.events_forwarded.fetch_add(1, Relaxed),
                Err(_) => gw.stats.c.inventory_copies_skipped.fetch_add(1, Relaxed),
            };
        });
    }
}

/// An agent's keepalive: the commands to give it, as JSON text.
pub fn keepalive(gw: &Gw, a: &Authed, rt: &Arc<AgentRt>, body: &[u8]) -> Result<Vec<String>, Refuse> {
    if body.is_empty() {
        return Err(Refuse(400, "empty"));
    }
    gw.stats.c.keepalives_received.fetch_add(1, Relaxed);
    rt.keepalives.fetch_add(1, Relaxed);
    let v: Value = serde_json::from_slice(body).unwrap_or_default();
    let mut commands = gw.queue.take(&a.id);
    rt.commands.fetch_add(commands.len() as u64, Relaxed);
    if !rt.marked.swap(true, Relaxed) {
        gw.queue.mark_protocol(&a.id, if rt.protocol.load(Relaxed) == 1 { "grpc" } else { "https" });
    }
    if let Some(ip) = v["agent_ip"].as_str().filter(|i| i.parse::<std::net::IpAddr>().is_ok()) {
        let mut stored = rt.ip.lock().unwrap();
        if *stored != ip {
            *stored = ip.to_string();
        }
    }
    let version = agent_state::clean_version(v["version"].as_str());
    if version.is_some() {
        *rt.version.lock().unwrap() = version;
    }
    if v["status"] == "stopping" {
        let ip = rt.ip.lock().unwrap().clone();
        let job = Job::Stopped { id: a.id.clone(), name: a.reg.name.clone(), ip: if ip.is_empty() { "any".into() } else { ip } };
        if gw.jobs.try_send(job).is_err() {
            gw.stats.c.state_jobs_dropped.fetch_add(1, Relaxed);
        }
        return Ok(commands);
    }
    rt.seen.store(true, Relaxed);
    if v["fim_state_wanted"] == true && agent_state::fim_slot(&a.tenant, &a.id, Instant::now(), gw.s.fim_slots()) {
        commands.push(json!({ "type": "fim_state_allowed" }).to_string());
    }
    if v.is_object() {
        let job = Job::Keepalive { id: a.id.clone(), tenant: a.tenant.clone(), name: a.reg.name.clone(), groups: a.reg.groups.clone(), body: v };
        // the next keepalive brings the same state again
        if gw.jobs.try_send(job).is_err() {
            gw.stats.c.keepalives_coalesced.fetch_add(1, Relaxed);
        }
    }
    Ok(commands)
}

/// The kinds that go to the engine.
fn to_engine(kind: Option<&str>, i: &Value) -> bool {
    matches!(kind, Some("windows_eventchannel" | "logfile" | "command" | "rootcheck" | "fim" | "registry")) || (kind == Some("sca") && i.get("message").is_some_and(Value::is_string))
}

fn kind_of(i: &Value) -> Option<&str> {
    i.get("event_type").or(i.get("type")).and_then(Value::as_str)
}

/// One event as the engine's message, `None` when it cannot be one.
fn engine_message(i: &Value) -> Option<(u8, String, String)> {
    let kind = kind_of(i);
    if matches!(kind, Some("fim" | "registry")) {
        return Some((queues::SYSCHECK_MQ, "syscheck".into(), agent_state::syscheck_message(i)?));
    }
    let q = match kind {
        Some("windows_eventchannel") => queues::WIN_EVT_MQ,
        Some("rootcheck") => queues::ROOTCHECK_MQ,
        Some("sca") => queues::SCA_MQ,
        _ => queues::LOCALFILE_MQ,
    };
    Some((q, i["location"].as_str().filter(|l| !l.is_empty())?.to_string(), i["message"].as_str()?.to_string()))
}

/// A batch of an agent's events: how many it was. A refusal means nothing of the batch reached
/// the engine: what can refuse comes first, the hand-off last.
pub async fn events(gw: &Gw, a: &Authed, rt: &Arc<AgentRt>, batch_id: &str, mut items: Vec<Value>) -> Result<u32, Refuse> {
    let total = items.len() as u32;
    if items.is_empty() {
        return Err(Refuse(400, "empty"));
    }
    // one agent per request: the id comes from the key, the body's tenant is ignored
    for i in items.iter_mut() {
        match i["agent"]["id"].as_str().or(i["agent_id"].as_str()) {
            Some(id) if id != a.id && id.parse::<u32>().ok() != a.id.parse::<u32>().ok() => return Err(Refuse(400, "another_agent")),
            Some(_) => {}
            None if i.is_object() => i["agent"] = json!({ "id": a.id, "name": a.reg.name }),
            None => return Err(Refuse(400, "not_an_event")),
        }
    }
    gw.stats.c.events_received.fetch_add(total as u64, Relaxed);
    rt.events.fetch_add(total as u64, Relaxed);
    rt.spend(items.len());
    if items.iter().any(|i| to_engine(kind_of(i), i)) {
        gw.engine_open()?;
    }
    let Some(taking) = rt.take_batch(batch_id) else {
        gw.stats.c.batches_repeated.fetch_add(1, Relaxed);
        return Ok(total);
    };

    let (mut baseline, mut ar, mut engine_items, mut inventory, mut other) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for i in items {
        match kind_of(&i) {
            Some("fim_state") => baseline.push(i),
            Some("ar_log") => ar.extend(i["log"].as_str().filter(|l| !l.trim().is_empty()).map(str::to_string)),
            Some("system_inventory" | "system_inventory_delta") => inventory.push(i),
            k if to_engine(k, &i) => engine_items.push(i),
            _ => other.push(i),
        }
    }

    for i in &baseline {
        if !agent_state::store_fim_state(&a.id, i).await {
            return Err(gw.refuse(Refuse(503, "provigil_db")));
        }
        gw.stats.c.baseline_rows_stored.fetch_add(i["entries"].as_array().map_or(0, Vec::len) as u64, Relaxed);
        if i["last"] == true {
            agent_state::fim_slot_free(&a.tenant, &a.id);
        }
    }
    let ip = rt.ip.lock().unwrap().clone();
    if !ar.is_empty() {
        gw.up.ar_log(&a.id, &a.tenant, &a.reg.name, &ip, &ar).await.map_err(|e| gw.refuse(api_refused(e)))?;
    }
    if !other.is_empty() {
        gw.up.events(&a.id, &a.tenant, &other).await.map_err(|e| gw.refuse(api_refused(e)))?;
        gw.stats.c.events_forwarded.fetch_add(other.len() as u64, Relaxed);
    }
    if !inventory.is_empty() {
        let n = inventory.len() as u64;
        if gw.inventory[lane(&a.id, gw.inventory.len())].try_send(Job::Inventory { id: a.id.clone(), tenant: a.tenant.clone(), items: inventory }).is_err() {
            return Err(gw.refuse(Refuse(503, "backlog")));
        }
        gw.stats.c.inventories_queued.fetch_add(n, Relaxed);
    }

    let source = engine::source(&a.id, &a.reg.name, &ip).ok_or(Refuse(400, "agent_id"))?;
    let mut datagrams = Vec::with_capacity(engine_items.len());
    for i in &engine_items {
        let Some((q, location, message)) = engine_message(i) else {
            gw.stats.c.events_unusable.fetch_add(1, Relaxed);
            continue;
        };
        // no batch is refused forever for one event: it alone is dropped
        match (message.len() + location.len() < engine::MAX_MESSAGE - 512).then(|| engine::datagram(gw.s.sender, &source, q, &location, &message)).flatten() {
            Some(d) => datagrams.push(d),
            None => {
                gw.stats.c.events_too_large.fetch_add(1, Relaxed);
                warn!("agent {}: event of {} bytes too large for the engine, dropped", a.id, message.len());
            }
        }
    }
    if !engine_items.is_empty() {
        gw.engine.send(&gw.stats, &datagrams).await.map_err(|_| gw.refuse(Refuse(503, "engine_send")))?;
        agent_state::watch_sca(&a.id, &engine_items);
    }
    taking.taken();
    Ok(total)
}

fn api_refused((code, _): (u16, String)) -> Refuse {
    Refuse(code, "api_down")
}

/// An agent's result: stored by command id, for that agent's commands only.
pub fn result(gw: &Gw, a: &Authed, rt: &AgentRt, body: &Value) -> Result<(), Refuse> {
    info!(agent_id = %a.id, result = %body, "Command result");
    rt.results.fetch_add(1, Relaxed);
    let Some(id) = body["command_id"].as_str() else { return Ok(()) };
    match gw.queue.result(&a.id, id, body) {
        Ok(true) => Ok(()),
        Ok(false) => {
            gw.stats.c.results_unknown.fetch_add(1, Relaxed);
            Ok(())
        }
        Err(()) => Err(gw.refuse(Refuse(503, "backlog"))),
    }
}

/// An enrollment, forwarded to siem-api: the agent can use its key at once on this gateway.
pub async fn enroll(gw: &Gw, body: &Value, tenant_key: &str, peer: &str) -> Result<Value, (u16, String)> {
    let v = gw.up.enroll(body, tenant_key, peer).await?;
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    if !s("agent_id").is_empty() && !s("raw_key").is_empty() {
        gw.cache.learn(&s("agent_id"), &s("raw_key"), Registered { name: s("agent_name"), tenant: s("tenant_id"), groups: s("groups"), os_type: body["os_type"].as_str().unwrap_or_default().to_string(), ..Default::default() });
    }
    Ok(v)
}

/// `{"version", "config"}`.
pub fn config(gw: &Gw, a: &Authed) -> Result<Value, Refuse> {
    Ok(agent_config::for_agent(&gw.s.home, &a.tenant, &a.reg.name, &a.reg.groups))
}

/// The YARA rule file.
pub async fn yara(gw: &Gw) -> Result<Vec<u8>, Refuse> {
    tokio::fs::read(gw.s.home.join("etc/shared/default/siem-yara.rules")).await.map_err(|_| Refuse(404, "no_rules"))
}

/// The published file for a download by name; the agent program's version checked when `asked`.
pub async fn package_file(gw: &Gw, name: &str, asked: &str) -> Result<PathBuf, Refuse> {
    let dist = gw.s.dist.clone();
    let path = published::windows_agent_file(&dist, name).ok_or(Refuse(404, "not_published"))?;
    if name == published::AGENT_EXE && !asked.is_empty() {
        let found = tokio::task::spawn_blocking(move || published::published_version(&dist)).await.ok().flatten().unwrap_or_default();
        if found != asked {
            return Err(Refuse(412, "version"));
        }
    }
    Ok(path)
}

/// Commands of the legacy route: taken like a keepalive's.
pub fn legacy_commands(gw: &Gw, a: &Authed) -> Vec<Value> {
    gw.queue.take(&a.id).iter().filter_map(|c| serde_json::from_str(c).ok()).collect()
}

/// What the gateway queues itself lives a day, like the console's.
pub fn push_full_send(gw: &Gw, tenant: &str, agent: &str, command: &Value) {
    gw.stats.c.full_sends_asked.fetch_add(1, Relaxed);
    gw.queue.push(agent, tenant, "gateway", command, cmd::DEFAULT_TTL_MS);
}
