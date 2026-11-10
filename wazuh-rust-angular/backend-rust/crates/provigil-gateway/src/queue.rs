//! The shared command queue: a cache of each agent's open commands, filled by polling ClickHouse,
//! and marks written back in batches. An agent with nothing waiting costs one map lookup.
//!
//! Marks wait in one map keyed by command, so a later state replaces an earlier one and the map
//! stays bounded by the commands open, not by the keepalives.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};

use clickhouse::Client;
use provigil_agent_server::commands::{self as cmd, CommandRow, ProtocolRow};
use serde_json::Value;
use tracing::warn;

use crate::stats::Stats;

/// Marks and results waiting for ClickHouse at most: beyond it results get 503.
pub const MARKS_MAX: usize = 50_000;
/// A write may commit after a later one was read: the last seconds are read again.
const OVERLAP_MS: u64 = 10_000;

#[derive(Default)]
struct AgentQueue {
    /// Open commands by (created, id), oldest first.
    open: BTreeMap<(u64, String), CommandRow>,
}

pub struct Queue {
    gateway: String,
    agents: RwLock<HashMap<String, Arc<Mutex<AgentQueue>>>>,
    marks: Mutex<HashMap<(String, String), CommandRow>>,
    protocol: Mutex<Vec<ProtocolRow>>,
    mark: AtomicU64,
    clock: AtomicU64,
    pub stats: Arc<Stats>,
}

pub fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

fn kind_of(r: &CommandRow) -> String {
    serde_json::from_str::<Value>(&r.command).ok().and_then(|v| v["type"].as_str().map(str::to_string)).unwrap_or_default()
}

impl Queue {
    pub fn new(gateway: &str, stats: Arc<Stats>) -> Self {
        Self { gateway: gateway.to_string(), agents: RwLock::default(), marks: Mutex::default(), protocol: Mutex::default(), mark: AtomicU64::new(0), clock: AtomicU64::new(0), stats }
    }

    /// Never twice the same version from here: later states of a row win.
    fn version(&self) -> u64 {
        let now = now_ms();
        self.clock.fetch_max(now, Relaxed);
        self.clock.fetch_add(1, Relaxed) + 1
    }

    fn agent(&self, id: &str) -> Arc<Mutex<AgentQueue>> {
        if let Some(q) = self.agents.read().unwrap().get(id) {
            return q.clone();
        }
        self.agents.write().unwrap().entry(id.to_string()).or_default().clone()
    }

    fn mark(&self, r: &CommandRow) {
        self.marks.lock().unwrap().insert((r.agent_id.clone(), r.command_id.clone()), r.clone());
    }

    /// Moves a row on and writes it.
    fn set(&self, r: &mut CommandRow, state: &str, now: u64) {
        r.state = state.to_string();
        r.state_at = now;
        r.gateway = self.gateway.clone();
        r.version = self.version();
        self.mark(r);
    }

    /// One row read from ClickHouse: the newest of a command stays, a final one leaves.
    fn apply(&self, r: CommandRow) {
        let q = self.agent(&r.agent_id);
        let mut q = q.lock().unwrap();
        let key = (r.created_at, r.command_id.clone());
        if q.open.get(&key).is_some_and(|c| c.version >= r.version) {
            return;
        }
        if cmd::terminal(&r.state) {
            q.open.remove(&key);
            return;
        }
        q.open.insert(key, r);
        self.trim(&mut q, now_ms());
    }

    /// The oldest waiting commands beyond the cap expire, counted, never silently gone.
    fn trim(&self, q: &mut AgentQueue, now: u64) {
        let waiting: Vec<(u64, String)> = q.open.iter().filter(|(_, r)| r.state == cmd::QUEUED).map(|(k, _)| k.clone()).collect();
        for k in waiting.iter().take(waiting.len().saturating_sub(cmd::MAX_PER_AGENT)) {
            if let Some(mut r) = q.open.remove(k) {
                self.set(&mut r, cmd::EXPIRED, now);
                self.stats.c.commands_expired.fetch_add(1, Relaxed);
            }
        }
    }

    /// Reads the rows written since the last poll. `first`: every open command.
    pub async fn poll(&self, db: &Client, first: bool) -> Result<(), clickhouse::error::Error> {
        let rows: Vec<CommandRow> = if first {
            db.query("SELECT ?fields FROM agent_command_queue FINAL WHERE state IN ('queued', 'handed') AND expires_at > ?").bind(now_ms()).fetch_all().await?
        } else {
            db.query("SELECT ?fields FROM agent_command_queue WHERE version >= ?").bind(self.mark.load(Relaxed).saturating_sub(OVERLAP_MS)).fetch_all().await?
        };
        if first {
            self.mark.fetch_max(now_ms(), Relaxed);
        }
        for r in rows {
            self.mark.fetch_max(r.version, Relaxed);
            self.apply(r);
        }
        Ok(())
    }

    /// What goes out with this keepalive: waiting commands, and for a repeatable one with no
    /// result after [`cmd::RESULT_WAIT_MS`] one more try. An expired command never goes out.
    pub fn take(&self, agent: &str) -> Vec<String> {
        let Some(q) = self.agents.read().unwrap().get(agent).cloned() else { return Vec::new() };
        let mut q = q.lock().unwrap();
        if q.open.is_empty() {
            return Vec::new();
        }
        let now = now_ms();
        let (mut out, mut gone) = (Vec::new(), Vec::new());
        for (k, r) in q.open.iter_mut() {
            if r.expires_at <= now {
                self.set(r, cmd::EXPIRED, now);
                self.stats.c.commands_expired.fetch_add(1, Relaxed);
                gone.push(k.clone());
            } else if r.state == cmd::QUEUED {
                r.attempts = r.attempts.saturating_add(1);
                self.set(r, cmd::HANDED, now);
                self.stats.c.commands_handed_out.fetch_add(1, Relaxed);
                out.push(r.command.clone());
            } else if now.saturating_sub(r.state_at) >= cmd::RESULT_WAIT_MS {
                if r.attempts < 2 && cmd::repeatable(&kind_of(r)) {
                    r.attempts += 1;
                    self.set(r, cmd::HANDED, now);
                    self.stats.c.commands_offered_again.fetch_add(1, Relaxed);
                    out.push(r.command.clone());
                } else {
                    self.set(r, cmd::NO_RESULT, now);
                    self.stats.c.commands_no_result.fetch_add(1, Relaxed);
                    gone.push(k.clone());
                }
            }
        }
        gone.iter().for_each(|k| {
            q.open.remove(k);
        });
        out
    }

    /// An agent's result: `Ok(true)` stored, `Ok(false)` not one of its open commands.
    /// `Err`: the marks are full, the agent keeps it and sends it again.
    pub fn result(&self, agent: &str, command_id: &str, result: &Value) -> Result<bool, ()> {
        if self.marks.lock().unwrap().len() >= MARKS_MAX {
            return Err(());
        }
        let Some(q) = self.agents.read().unwrap().get(agent).cloned() else { return Ok(false) };
        let mut q = q.lock().unwrap();
        let Some(k) = q.open.keys().find(|(_, id)| id == command_id).cloned() else { return Ok(false) };
        let mut r = q.open.remove(&k).expect("the key was just found");
        r.result = result.to_string();
        let failed = matches!(result["status"].as_str(), Some("failed" | "error"));
        self.set(&mut r, if failed { cmd::FAILED } else { cmd::DONE }, now_ms());
        self.stats.c.results_stored.fetch_add(1, Relaxed);
        Ok(true)
    }

    /// A command this gateway adds (a full send, an engine response).
    pub fn push(&self, agent: &str, tenant: &str, origin: &str, command: &Value, ttl_ms: u64) {
        let now = now_ms();
        let command_id = command["command_id"].as_str().map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_string);
        let mut text = command.clone();
        text["command_id"] = Value::String(command_id.clone());
        let mut r = CommandRow { agent_id: agent.to_string(), command_id, tenant_id: tenant.to_string(), command: text.to_string(), origin: origin.to_string(), created_at: now, expires_at: now + ttl_ms, state: String::new(), state_at: now, gateway: String::new(), attempts: 0, result: String::new(), version: 0 };
        self.set(&mut r, cmd::QUEUED, now);
        self.stats.c.commands_queued.fetch_add(1, Relaxed);
        self.apply(r);
    }

    /// The agent proved it speaks the protocol: written once per process.
    pub fn mark_protocol(&self, agent: &str, protocol: &str) {
        self.protocol.lock().unwrap().push(ProtocolRow { agent_id: agent.to_string(), protocol: protocol.to_string(), updated_at: now_ms() });
    }

    /// Commands of agents that never came back: expired, so the table says so.
    pub fn sweep(&self) {
        let now = now_ms();
        let all: Vec<_> = self.agents.read().unwrap().values().cloned().collect();
        for q in all {
            let mut q = q.lock().unwrap();
            let gone: Vec<_> = q.open.iter().filter(|(_, r)| r.expires_at <= now).map(|(k, _)| k.clone()).collect();
            for k in gone {
                if let Some(mut r) = q.open.remove(&k) {
                    self.set(&mut r, cmd::EXPIRED, now);
                    self.stats.c.commands_expired.fetch_add(1, Relaxed);
                }
            }
        }
    }

    /// (commands open, marks waiting)
    pub fn sizes(&self) -> (usize, usize) {
        let open = self.agents.read().unwrap().values().map(|q| q.lock().unwrap().open.len()).sum();
        (open, self.marks.lock().unwrap().len())
    }

    /// Writes the marks; those that failed stay for the next try.
    pub async fn flush(&self, db: &Client) -> bool {
        let protocol = std::mem::take(&mut *self.protocol.lock().unwrap());
        let mut ok = true;
        if !protocol.is_empty() {
            let wrote = write(db, cmd::PROTOCOL_TABLE, &protocol).await;
            if !wrote {
                ok = false;
                self.protocol.lock().unwrap().extend(protocol);
            }
        }
        let rows: Vec<CommandRow> = self.marks.lock().unwrap().values().cloned().collect();
        if rows.is_empty() {
            return ok;
        }
        if !write(db, cmd::TABLE, &rows).await {
            self.stats.c.command_mark_failures.fetch_add(1, Relaxed);
            return false;
        }
        self.stats.c.command_marks_written.fetch_add(rows.len() as u64, Relaxed);
        let mut m = self.marks.lock().unwrap();
        for r in &rows {
            let k = (r.agent_id.clone(), r.command_id.clone());
            // a newer state came meanwhile: it stays for the next write
            if m.get(&k).is_some_and(|x| x.version == r.version) {
                m.remove(&k);
            }
        }
        ok
    }
}

async fn write<T: clickhouse::Row + serde::Serialize>(db: &Client, table: &str, rows: &[T]) -> bool {
    let r = async {
        let mut ins = db.insert(table)?;
        for r in rows {
            ins.write(r).await?;
        }
        ins.end().await
    };
    match r.await {
        Ok(()) => true,
        Err(e) => {
            warn!("{table}: {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn queue() -> Queue {
        Queue::new("gw-1", Arc::new(Stats::default()))
    }

    fn row(id: &str, kind: &str, created: u64) -> CommandRow {
        CommandRow { agent_id: "001".into(), command_id: id.into(), tenant_id: "t".into(), command: json!({ "command_id": id, "type": kind }).to_string(), origin: "console:u".into(), created_at: created, expires_at: now_ms() + 60_000, state: cmd::QUEUED.into(), state_at: created, gateway: String::new(), attempts: 0, result: String::new(), version: created }
    }

    #[test]
    fn handed_out_once_and_marked() {
        let q = queue();
        q.apply(row("c1", "scan", 1));
        assert_eq!(q.take("001").len(), 1);
        assert!(q.take("001").is_empty(), "once");
        assert!(q.take("002").is_empty());
        let m = q.marks.lock().unwrap();
        let r = &m[&("001".to_string(), "c1".to_string())];
        assert_eq!((r.state.as_str(), r.attempts, r.gateway.as_str()), (cmd::HANDED, 1, "gw-1"));
    }

    #[test]
    fn another_gateways_hand_out_stops_this_one() {
        let q = queue();
        q.apply(row("c1", "scan", 1));
        q.apply(CommandRow { state: cmd::HANDED.into(), state_at: now_ms(), gateway: "gw-2".into(), attempts: 1, version: 5, ..row("c1", "scan", 1) });
        assert!(q.take("001").is_empty());
        // an older row read again changes nothing
        q.apply(row("c1", "scan", 1));
        assert!(q.take("001").is_empty());
    }

    #[test]
    fn expired_is_never_handed_out_and_is_counted() {
        let q = queue();
        q.apply(CommandRow { expires_at: 1, ..row("c1", "scan", 1) });
        assert!(q.take("001").is_empty());
        assert_eq!(q.stats.c.commands_expired.load(Relaxed), 1);
        q.apply(CommandRow { expires_at: 1, ..row("c2", "scan", 2) });
        q.sweep();
        assert_eq!(q.stats.c.commands_expired.load(Relaxed), 2);
        assert_eq!(q.sizes().0, 0);
    }

    #[test]
    fn the_201st_expires_the_oldest() {
        let q = queue();
        for i in 0..=cmd::MAX_PER_AGENT as u64 {
            q.apply(row(&format!("c{i}"), "scan", i + 1));
        }
        assert_eq!(q.stats.c.commands_expired.load(Relaxed), 1);
        let out = q.take("001");
        assert_eq!(out.len(), cmd::MAX_PER_AGENT);
        assert!(!out.iter().any(|c| c.contains("\"c0\"")), "the oldest went");
    }

    #[test]
    fn repeatable_offered_once_more_response_not() {
        let q = queue();
        let long_ago = now_ms() - cmd::RESULT_WAIT_MS - 1;
        q.apply(CommandRow { state: cmd::HANDED.into(), state_at: long_ago, attempts: 1, ..row("scan", "scan", 1) });
        q.apply(CommandRow { state: cmd::HANDED.into(), state_at: long_ago, attempts: 1, ..row("kill", "ar", 2) });
        assert_eq!(q.take("001").len(), 1, "the scan, not the response");
        assert_eq!(q.stats.c.commands_offered_again.load(Relaxed), 1);
        assert_eq!(q.stats.c.commands_no_result.load(Relaxed), 1, "the response is marked no result");
        assert!(q.take("001").is_empty(), "once");
    }

    #[test]
    fn result_closes_a_command_of_that_agent_only() {
        let q = queue();
        q.apply(row("c1", "getconfig", 1));
        q.take("001");
        assert_eq!(q.result("002", "c1", &json!({})), Ok(false), "another agent's");
        assert_eq!(q.result("001", "c1", &json!({ "status": "error" })), Ok(true));
        assert_eq!(q.result("001", "c1", &json!({})), Ok(false), "already closed");
        assert_eq!(q.marks.lock().unwrap()[&("001".to_string(), "c1".to_string())].state, cmd::FAILED);
    }

    #[test]
    fn a_full_mark_map_refuses_results() {
        let q = queue();
        for i in 0..MARKS_MAX {
            q.marks.lock().unwrap().insert(("a".into(), i.to_string()), row("x", "scan", 1));
        }
        assert_eq!(q.result("001", "c1", &json!({})), Err(()));
    }
}
