//! Analysis workers (specs/provigil-analysisd.md, "Scaling with the cores"): Windows and log
//! messages are cleaned and decoded, and every event's archive line is built and streamed to
//! siem-api, on worker threads; rule matching stays one ordered stage on the main thread, so
//! correlation across agents (one attacker against many computers) is exactly as before. An
//! agent's messages always go to the same worker: its events keep their order. Automatic: one
//! worker per core beyond two (kept for the gateway, siem-api and the database writer), at least
//! one and at most [`AUTO_MAX`]; `PROVIGIL_ANALYSIS_WORKERS` sets the number (0: automatic).
//!
//! Measured (tests/bench_throughput.rs, 16 cores, mixed Windows events with their archive lines
//! streamed): one thread 11,000 events/s; 2 workers 2.4x; 3 to 5 workers 2.7-2.9x (about 31,000/s);
//! 6 to 12 workers less again: the ordered rule stage is then the limit and more workers only
//! contend for the stream. So spare cores go to siem-api and ClickHouse instead.

use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as Clock};

use provigil_ipc::platform_stream::{self as stream, Stream};

use crate::builtin::{windows::Windows, Builtin};
use crate::daemon::ServiceLog;
use crate::engine::Engine;
use crate::event::{Event, Instant, Label};
use crate::host::Host;
use crate::messages::Messages;
use crate::queues::Kind;
use crate::responses::{AgentVersion, ResponseSink};

/// Messages handed to one worker and not yet back (decoding).
pub const IN_FLIGHT: usize = 2048;
/// Jobs one worker's queue holds.
const QUEUE: usize = 4096;
/// The most workers.
const MAX_WORKERS: usize = 32;
/// The most workers chosen automatically (the gain stops there, see the module notes).
pub const AUTO_MAX: usize = 4;

/// The number of workers: `PROVIGIL_ANALYSIS_WORKERS`, else one per core beyond two.
pub fn worker_count() -> usize {
    let set = std::env::var("PROVIGIL_ANALYSIS_WORKERS").ok().and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0);
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    if set > 0 { set.min(MAX_WORKERS) } else { auto(cores) }
}

/// One worker per core beyond two, at least one, at most [`AUTO_MAX`].
pub fn auto(cores: usize) -> usize {
    cores.saturating_sub(2).clamp(1, AUTO_MAX)
}

/// The worker of an agent's messages: the id inside `[...]` of the message's source.
pub fn worker_of(msg: &[u8], workers: usize) -> usize {
    let id = msg.iter().position(|&c| c == b'[').and_then(|s| msg[s + 1..].iter().position(|&c| c == b']').map(|e| &msg[s + 1..s + 1 + e])).unwrap_or(b"");
    id.iter().fold(0usize, |h, &b| h.wrapping_mul(31).wrapping_add(usize::from(b))) % workers.max(1)
}

pub enum Job {
    Decode { kind: Kind, msg: Vec<u8>, manager: Vec<u8>, now: Instant },
    /// An event's archive line to the stream.
    Archive(Box<Event>),
}

/// A decoded message (`ev`: None when it was dropped) and what it cost.
pub struct Done {
    pub kind: Kind,
    /// the message's queue character (for the per-module statistics)
    pub first: u8,
    pub ev: Option<Box<Event>>,
    pub logs: Vec<(&'static str, Vec<u8>)>,
    pub clean: Duration,
    pub decode: Duration,
}

pub struct Analysis {
    jobs: Vec<SyncSender<Job>>,
    pub done: Receiver<Done>,
    pub in_flight: usize,
    /// archive lines streamed (benchmarks wait for them)
    pub archived: Arc<std::sync::atomic::AtomicU64>,
}

impl Analysis {
    /// `n` workers, each with its own copy of the engine's ruleset (`Engine::fork`).
    pub fn start(n: usize, engine: &Engine, builtin: Builtin, stream: Option<Arc<Mutex<Stream>>>, log: Arc<ServiceLog>) -> Analysis {
        let (done_tx, done) = channel();
        let order = engine.settings.rules.order_size;
        let archived = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let jobs = (0..n.max(1))
            .map(|i| {
                let (tx, rx) = sync_channel::<Job>(QUEUE);
                let (done_tx, mut eng, stream, log, archived) = (done_tx.clone(), engine.fork(), stream.clone(), log.clone(), archived.clone());
                std::thread::Builder::new()
                    .name(format!("analysis-{i}"))
                    .spawn(move || work(&rx, &done_tx, &mut eng, builtin, order, stream.as_deref(), &log, &archived))
                    .expect("an analysis thread");
                tx
            })
            .collect();
        Analysis { jobs, done, in_flight: 0, archived }
    }

    pub fn workers(&self) -> usize {
        self.jobs.len()
    }

    pub fn room(&self) -> bool {
        self.in_flight < IN_FLIGHT * self.jobs.len()
    }

    /// A message to decode, on its agent's worker.
    pub fn decode(&mut self, kind: Kind, msg: &[u8], manager: Vec<u8>, now: Instant) {
        let i = worker_of(msg, self.jobs.len());
        self.in_flight += 1;
        if self.jobs[i].send(Job::Decode { kind, msg: msg.to_vec(), manager, now }).is_err() {
            self.in_flight -= 1;
        }
    }

    /// An event's archive line, built and streamed by its agent's worker.
    pub fn archive(&self, ev: Event) {
        let i = ev.agent_id.iter().flatten().fold(0usize, |h, &b| h.wrapping_mul(31).wrapping_add(usize::from(b))) % self.jobs.len();
        let _ = self.jobs[i].send(Job::Archive(Box::new(ev)));
    }
}

#[allow(clippy::too_many_arguments)]
fn work(rx: &Receiver<Job>, done: &Sender<Done>, eng: &mut Engine, builtin: Builtin, order: usize, stream: Option<&Mutex<Stream>>, log: &ServiceLog, archived: &std::sync::atomic::AtomicU64) {
    let mut windows = Windows::default();
    while let Ok(job) = rx.recv() {
        match job {
            Job::Decode { kind, msg, manager, now } => {
                let t0 = Clock::now();
                let mut ev = eng.new_event();
                let logs = std::cell::RefCell::new(Vec::new());
                let cleaned = ev.clean(&msg, &manager, now);
                let clean = t0.elapsed();
                let t1 = Clock::now();
                let keep = match cleaned {
                    Err(_) => {
                        logs.borrow_mut().push(("ERROR", crate::event::FORMAT_ERROR.as_bytes().to_vec()));
                        logs.borrow_mut().push(("ERROR", [&b"(1222): Invalid msg: "[..], &msg].concat()));
                        false
                    }
                    Ok(_) if kind == Kind::Winevt => windows.decode(&mut LogTo(&logs), &mut eng.decoders, builtin.windows, order, &mut ev),
                    Ok(_) => {
                        eng.decode(&mut ev);
                        true
                    }
                };
                let d = Done { kind, first: msg.first().copied().unwrap_or(0), ev: keep.then(|| Box::new(ev)), logs: logs.into_inner(), clean, decode: t1.elapsed() };
                if done.send(d).is_err() {
                    return;
                }
            }
            Job::Archive(ev) => {
                let Some(st) = stream else { continue };
                let mut msgs = Messages::default();
                if let Some(l) = crate::text_logs::json_archive(eng, &ev, &mut msgs) {
                    if let Some(w) = st.lock().unwrap().send(stream::EVENT, &l) {
                        msgs.warn(w);
                    }
                }
                for m in msgs.take() {
                    log.log(if m.level == crate::messages::Level::Error { "ERROR" } else { "WARNING" }, &m.text);
                }
                archived.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

/// A host whose log lines are kept (a worker's decoder logs; the main thread writes them, in order).
struct LogTo<'a>(&'a std::cell::RefCell<Vec<(&'static str, Vec<u8>)>>);

impl ResponseSink for LogTo<'_> {
    fn agent_version(&mut self, _: i32) -> AgentVersion {
        AgentVersion::NoInfo
    }
    fn active_agents(&mut self) -> Option<Vec<i32>> {
        None
    }
    fn node_name(&mut self) -> String {
        "undefined".into()
    }
    fn send_exec(&mut self, _: &[u8]) {}
    fn send_ar(&mut self, _: &[u8]) {}
}

impl Host for LogTo<'_> {
    fn labels(&mut self, _: &[u8]) -> Vec<Label> {
        Vec::new()
    }
    fn log(&self, level: &str, msg: &[u8]) {
        let level = match level {
            "ERROR" => "ERROR",
            "WARNING" => "WARNING",
            "INFO" => "INFO",
            "DEBUG" => "DEBUG",
            _ => "DEBUG2",
        };
        self.0.borrow_mut().push((level, msg.to_vec()));
    }
    fn responses(&mut self) -> &mut dyn ResponseSink {
        self
    }
    fn agents_of_node(&mut self, _: i32, _: i32) -> Option<Vec<i32>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workers_follow_the_cores_and_agents_stay_on_one() {
        assert_eq!(auto(1), 1);
        assert_eq!(auto(2), 1);
        assert_eq!(auto(4), 2);
        assert_eq!(auto(5), 3);
        assert_eq!(auto(8), AUTO_MAX);
        assert_eq!(auto(256), AUTO_MAX);
        let m = |id: &str| format!("f:[{id}] (pc) any->EventChannel:{{}}").into_bytes();
        assert_eq!(worker_of(&m("007"), 6), worker_of(&m("007"), 6), "an agent always on the same worker");
        let spread: std::collections::HashSet<usize> = (0..100).map(|i| worker_of(&m(&format!("{i:03}")), 6)).collect();
        assert_eq!(spread.len(), 6, "agents spread over every worker");
        assert!(worker_of(b"1:manager-local message", 6) < 6, "no agent: worker 0's place");
    }
}
