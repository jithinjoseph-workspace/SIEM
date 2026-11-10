//! What a gateway keeps per agent in memory: counters, limits, batch ids. Each agent has its own
//! locks; the map is locked only to add or prune an agent.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use tokio::sync::Notify;

/// Batch ids remembered per agent.
const BATCH_IDS: usize = 64;
/// Connections of one key.
pub const CONNECTIONS_PER_KEY: usize = 4;
/// The same key from two addresses within this long is a cloned identity.
const CLONE_WINDOW_MS: u64 = 60_000;
/// Logged once per this long per agent.
const CLONE_LOG_MS: u64 = 3_600_000;
/// How long a computed group configuration version is used.
const GROUP_VERSION_MS: u64 = 60_000;

#[derive(Default)]
struct Peer {
    addr: Option<IpAddr>,
    at_ms: u64,
}

#[derive(Default)]
pub struct AgentRt {
    pub id: String,
    pub last_seen_ms: AtomicU64,
    last_keepalive_ms: AtomicU64,
    events_busy: AtomicBool,
    tokens: Mutex<Option<(f64, Instant)>>,
    batches: Mutex<VecDeque<String>>,
    conns: Mutex<VecDeque<(u64, Arc<Notify>)>>,
    last_conn: AtomicU64,
    peer: Mutex<Peer>,
    clone_logged_ms: AtomicU64,
    pub flagged_clone: AtomicBool,
    /// The address it reports, for the engine's source label.
    pub ip: Mutex<String>,
    /// Heard from since the last flush, with the version it reports.
    pub seen: AtomicBool,
    pub version: Mutex<Option<String>>,
    /// (when, version) of its group configuration.
    pub group_version: Mutex<Option<(u64, String)>>,
    pub marked: AtomicBool,
    /// 1 gRPC, 2 HTTPS.
    pub protocol: AtomicU8,
    pub keepalives: AtomicU64,
    pub events: AtomicU64,
    pub commands: AtomicU64,
    pub results: AtomicU64,
    pub refusals: AtomicU64,
}

/// One events request of an agent: dropped when it ends.
pub struct EventsTurn(Arc<AgentRt>);

impl Drop for EventsTurn {
    fn drop(&mut self) {
        self.0.events_busy.store(false, Relaxed);
    }
}

/// A batch id being taken: forgotten unless its batch was taken (refused, or cut short by the
/// call's time limit), so a later try is processed.
pub struct Taking {
    rt: Arc<AgentRt>,
    id: Option<String>,
}

impl Taking {
    pub fn taken(mut self) {
        self.id = None;
    }
}

impl Drop for Taking {
    fn drop(&mut self) {
        if let Some(id) = &self.id {
            self.rt.batches.lock().unwrap_or_else(|e| e.into_inner()).retain(|b| b != id);
        }
    }
}

impl AgentRt {
    /// At most one keepalive per second.
    pub fn keepalive_allowed(&self, now_ms: u64) -> bool {
        let last = self.last_keepalive_ms.load(Relaxed);
        now_ms.saturating_sub(last) >= 1_000 && self.last_keepalive_ms.compare_exchange(last, now_ms, Relaxed, Relaxed).is_ok()
    }

    pub fn events_turn(self: &Arc<Self>) -> Option<EventsTurn> {
        (!self.events_busy.swap(true, Relaxed)).then(|| EventsTurn(self.clone()))
    }

    /// Whether events may come: the rate is held to `eps`, a batch paying for itself afterwards
    /// ([`Self::spend`]), so one larger than a second's worth is not refused forever.
    pub fn eps_allowed(&self, eps: f64, now: Instant) -> bool {
        let mut t = self.tokens.lock().unwrap();
        let (tokens, at) = t.get_or_insert((eps, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * eps).min(eps);
        *at = now;
        *tokens > 0.0
    }

    pub fn spend(&self, n: usize) {
        if let Some((tokens, _)) = self.tokens.lock().unwrap().as_mut() {
            *tokens -= n as f64;
        }
    }

    /// Takes a batch id: `None` when it was taken before, so the batch is answered and not
    /// processed.
    pub fn take_batch(self: &Arc<Self>, id: &str) -> Option<Taking> {
        if id.is_empty() {
            return Some(Taking { rt: self.clone(), id: None });
        }
        let mut b = self.batches.lock().unwrap();
        if b.iter().any(|x| x == id) {
            return None;
        }
        b.push_back(id.to_string());
        if b.len() > BATCH_IDS {
            b.pop_front();
        }
        Some(Taking { rt: self.clone(), id: Some(id.to_string()) })
    }

    /// A request on connection `conn`: the newest [`CONNECTIONS_PER_KEY`] stay, the oldest closes.
    pub fn on_connection(&self, conn: u64, close: &Arc<Notify>) {
        if self.last_conn.swap(conn, Relaxed) == conn {
            return;
        }
        let mut c = self.conns.lock().unwrap();
        if c.iter().any(|(id, _)| *id == conn) {
            return;
        }
        c.push_back((conn, close.clone()));
        if c.len() > CONNECTIONS_PER_KEY {
            if let Some((_, oldest)) = c.pop_front() {
                oldest.notify_one();
            }
        }
    }

    /// The source of a request: `Some` when the same key came from another address within the
    /// minute, once per hour.
    pub fn on_peer(&self, addr: IpAddr, now_ms: u64) -> Option<IpAddr> {
        let mut p = self.peer.lock().unwrap();
        let other = p.addr.filter(|a| *a != addr && now_ms.saturating_sub(p.at_ms) < CLONE_WINDOW_MS);
        *p = Peer { addr: Some(addr), at_ms: now_ms };
        drop(p);
        let other = other?;
        self.flagged_clone.store(true, Relaxed);
        let last = self.clone_logged_ms.load(Relaxed);
        (last == 0 || now_ms.saturating_sub(last) >= CLONE_LOG_MS).then(|| {
            self.clone_logged_ms.store(now_ms, Relaxed);
            other
        })
    }

    /// The agent's group configuration version, computed by `f` at most once a minute.
    pub fn group_version(&self, now_ms: u64, f: impl FnOnce() -> String) -> String {
        let mut g = self.group_version.lock().unwrap();
        match g.as_ref() {
            Some((at, v)) if now_ms.saturating_sub(*at) < GROUP_VERSION_MS => v.clone(),
            _ => {
                let v = f();
                *g = Some((now_ms, v.clone()));
                v
            }
        }
    }
}

#[derive(Default)]
pub struct Agents {
    map: RwLock<HashMap<String, Arc<AgentRt>>>,
}

impl Agents {
    pub fn get(&self, id: &str) -> Arc<AgentRt> {
        if let Some(a) = self.map.read().unwrap().get(id) {
            return a.clone();
        }
        self.map.write().unwrap().entry(id.to_string()).or_insert_with(|| Arc::new(AgentRt { id: id.to_string(), ..Default::default() })).clone()
    }

    /// Its key changed: batch ids and the like start again.
    pub fn forget(&self, id: &str) {
        self.map.write().unwrap().remove(id);
    }

    /// The per-agent state of agents not heard from within `older_than_ms` goes.
    pub fn prune(&self, now_ms: u64, older_than_ms: u64) {
        self.map.write().unwrap().retain(|_, a| now_ms.saturating_sub(a.last_seen_ms.load(Relaxed)) < older_than_ms);
    }

    pub fn len(&self) -> usize {
        self.map.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// What the flush writes: agent number -> version, for those heard from since the last one.
    pub fn take_seen(&self) -> BTreeMap<u32, Option<String>> {
        let all: Vec<_> = self.map.read().unwrap().values().cloned().collect();
        all.iter().filter(|a| a.seen.swap(false, Relaxed)).filter_map(|a| Some((a.id.parse().ok()?, a.version.lock().unwrap().clone()))).collect()
    }

    /// One page of `/state/agents`: agents after `last`, by id.
    pub fn page(&self, last: &str, n: usize) -> (Vec<Arc<AgentRt>>, bool) {
        let mut v: Vec<_> = self.map.read().unwrap().values().filter(|a| a.id.as_str() > last).cloned().collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        let more = v.len() > n;
        v.truncate(n);
        (v, more)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_once_a_second() {
        let a = AgentRt::default();
        assert!(a.keepalive_allowed(10_000));
        assert!(!a.keepalive_allowed(10_500));
        assert!(a.keepalive_allowed(11_000));
    }

    #[test]
    fn one_events_request_at_a_time() {
        let a = Arc::new(AgentRt::default());
        let t = a.events_turn().unwrap();
        assert!(a.events_turn().is_none());
        drop(t);
        assert!(a.events_turn().is_some());
    }

    #[test]
    fn events_rate() {
        let a = AgentRt::default();
        let t0 = Instant::now();
        assert!(a.eps_allowed(100.0, t0));
        a.spend(250);
        assert!(!a.eps_allowed(100.0, t0));
        assert!(!a.eps_allowed(100.0, t0 + std::time::Duration::from_secs(1)));
        assert!(a.eps_allowed(100.0, t0 + std::time::Duration::from_secs(2)), "paid off");
    }

    #[test]
    fn batch_ids_repeat_forgotten_and_bounded() {
        let a = Arc::new(AgentRt::default());
        a.take_batch("b1").unwrap().taken();
        assert!(a.take_batch("b1").is_none(), "a repeat");
        drop(a.take_batch("b2").unwrap());
        assert!(a.take_batch("b2").is_some(), "not taken: a later try is processed");
        for i in 0..BATCH_IDS {
            a.take_batch(&i.to_string()).unwrap().taken();
        }
        assert!(a.take_batch("b1").is_some(), "only the last 64");
        assert!(a.take_batch("").is_some() && a.take_batch("").is_some(), "no id: never a repeat");
    }

    #[tokio::test]
    async fn the_fifth_connection_closes_the_oldest() {
        let a = AgentRt::default();
        let n: Vec<_> = (0..5).map(|_| Arc::new(Notify::new())).collect();
        for (i, c) in n.iter().enumerate() {
            a.on_connection(i as u64 + 1, c);
            a.on_connection(i as u64 + 1, c);
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), n[0].notified()).await.expect("the oldest told to close");
        assert!(tokio::time::timeout(std::time::Duration::from_millis(50), n[1].notified()).await.is_err());
    }

    #[test]
    fn cloned_identity_logged_once_an_hour() {
        let a = AgentRt::default();
        let (x, y): (IpAddr, IpAddr) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
        assert_eq!(a.on_peer(x, 1_000), None);
        assert_eq!(a.on_peer(x, 2_000), None);
        assert_eq!(a.on_peer(y, 3_000), Some(x));
        assert_eq!(a.on_peer(x, 4_000), None, "once per hour");
        assert!(a.flagged_clone.load(Relaxed));
        assert_eq!(a.on_peer(y, 100_000), None, "a move after a minute is no clone");
    }

    #[test]
    fn pruned_and_paged() {
        let m = Agents::default();
        for id in ["001", "002", "003"] {
            m.get(id).last_seen_ms.store(1_000, Relaxed);
        }
        m.get("004").last_seen_ms.store(9_000, Relaxed);
        let (p, more) = m.page("001", 2);
        assert_eq!((p.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(), more), (vec!["002", "003"], true));
        m.prune(10_000, 5_000);
        assert_eq!(m.len(), 1);
        m.get("004").seen.store(true, Relaxed);
        assert_eq!(m.take_seen().len(), 1);
        assert!(m.take_seen().is_empty());
    }
}
