//! The link to the analysis engine: a sender re-made at each load reading (so a restarted engine
//! on a new address is found), and the backpressure signal. Nothing here waits per message.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, RwLock};

use provigil_agent_server::engine;
use provigil_ipc::aio::DatagramSender;
use tracing::{error, warn};

use crate::queue::now_ms;
use crate::stats::Stats;

#[derive(Default)]
pub struct EngineLink {
    sender: RwLock<Option<Arc<DatagramSender>>>,
    pub sent: AtomicU64,
    /// some queue is filling up or the engine is behind (the stats; [`EngineLink::open_for`] decides)
    pub behind: AtomicBool,
    /// the engine as a whole is behind (lag, or no answer in time): every event waits
    pub stalled: AtomicBool,
    /// the queues over [`engine::QUEUE_MAX`], by name; from an engine that does not tell each
    /// queue, `*` (all events wait, as before)
    pub full_queues: RwLock<Vec<String>>,
    pub running: AtomicBool,
    pub lag: AtomicU64,
    pub usage_permille: AtomicU64,
    pub last_answer_ms: AtomicU64,
}

impl EngineLink {
    /// Hands datagrams to the engine; every one sent is counted.
    pub async fn send(&self, stats: &Stats, datagrams: &[Vec<u8>]) -> Result<(), String> {
        let s = self.sender.read().unwrap().clone().ok_or("the engine is not running")?;
        for d in datagrams {
            s.send(d).await.map_err(|e| e.to_string())?;
            self.sent.fetch_add(1, Relaxed);
            stats.c.engine_datagrams_sent.fetch_add(1, Relaxed);
        }
        Ok(())
    }

    /// Reads the engine's load every 500 ms until the process ends: its queues, and the datagrams
    /// of this gateway (`sender`) it read, so several gateways on one engine each see their own lag.
    pub async fn run(self: Arc<Self>, home: PathBuf, sender: u8, stats: Arc<Stats>) {
        let (load_path, queue_path) = (home.join(engine::LOAD_SOCKET), home.join(provigil_ipc::queue::EVENT_QUEUE));
        let mut lag = engine::Lag::default();
        // the first check runs at once: agents connecting at start were refused for 500 ms
        let mut first = true;
        loop {
            if !std::mem::take(&mut first) {
                tokio::time::sleep(engine::LOAD_EVERY).await;
            }
            let r = engine::load(&load_path, sender).await;
            let up = r.is_ok() || r == Err(true);
            let sender = if up { DatagramSender::connect(&queue_path).await.ok().map(Arc::new) } else { None };
            *self.sender.write().unwrap() = sender;
            if up != self.running.swap(up, Relaxed) {
                if up && self.last_answer_ms.load(Relaxed) == 0 {
                    tracing::info!("The engine is running: agent events open");
                } else if up {
                    warn!("The engine is back: agent events open again");
                } else {
                    warn!("The engine is not running: agent events answer 503");
                }
            }
            let behind = match r {
                Ok(engine::Load { usage, queues, received }) => {
                    self.last_answer_ms.store(now_ms(), Relaxed);
                    self.usage_permille.store((usage * 1000.0) as u64, Relaxed);
                    let n = lag.observe(self.sent.load(Relaxed), received);
                    self.lag.store(n, Relaxed);
                    if let Some(lost) = lag.lost_at_restart {
                        stats.c.engine_restarts_seen.fetch_add(1, Relaxed);
                        stats.c.engine_datagrams_possibly_lost.fetch_add(lost, Relaxed);
                        error!("The engine restarted: up to {lost} events may have been in its buffer");
                    }
                    let stalled = n > engine::LAG_MAX;
                    let mut full: Vec<String> = if queues.is_empty() && usage > engine::QUEUE_MAX {
                        vec!["*".into()]
                    } else {
                        queues.iter().filter(|(_, u)| **u > engine::QUEUE_MAX).map(|(k, _)| k.clone()).collect()
                    };
                    full.sort();
                    let behind = stalled || !full.is_empty();
                    let was = (self.stalled.swap(stalled, Relaxed), self.full_queues.read().unwrap().clone());
                    if was != (stalled, full.clone()) {
                        if stalled {
                            warn!("The engine is {n} message(s) behind: agent events answer 429");
                        } else if full.is_empty() {
                            warn!("The engine is {n} message(s) behind, fullest queue {:.0}%: agent events open again", usage * 100.0);
                        } else {
                            warn!("Engine queue(s) {} over {:.0}% (fullest {:.0}%): their events answer 429, the others flow", full.join(", "), engine::QUEUE_MAX * 100.0, usage * 100.0);
                        }
                    }
                    *self.full_queues.write().unwrap() = full;
                    behind
                }
                Err(busy) => {
                    if busy && !self.stalled.load(Relaxed) {
                        warn!("The engine did not answer within 1 s: agent events answer 429");
                    }
                    self.stalled.store(busy, Relaxed);
                    busy
                }
            };
            self.behind.store(behind, Relaxed);
        }
    }

    /// Whether events for these engine queues may go in now (see [`engine::queue_of`]).
    pub fn open_for<'a>(&self, queues: impl IntoIterator<Item = &'a str>) -> bool {
        if self.stalled.load(Relaxed) {
            return false;
        }
        let full = self.full_queues.read().unwrap();
        full.is_empty() || (!full.iter().any(|q| q == "*") && queues.into_iter().all(|q| !full.iter().any(|f| f == q)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_events_for_a_full_queue_wait() {
        let l = EngineLink::default();
        assert!(l.open_for(["winevt", "sca"]));
        *l.full_queues.write().unwrap() = vec!["sca".into()];
        assert!(l.open_for(["winevt"]), "Windows events flow while the configuration checks wait");
        assert!(l.open_for(["winevt", "event"]));
        assert!(!l.open_for(["winevt", "sca"]), "a batch with a check for the full queue waits");
        *l.full_queues.write().unwrap() = vec!["*".into()];
        assert!(!l.open_for(["winevt"]), "an engine that does not tell each queue: all wait");
        l.full_queues.write().unwrap().clear();
        l.stalled.store(true, Relaxed);
        assert!(!l.open_for(["winevt"]), "an engine behind as a whole: all wait");
    }
}
