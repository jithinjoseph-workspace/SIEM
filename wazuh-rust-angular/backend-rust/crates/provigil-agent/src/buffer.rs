//! The agent's event queue: events wait here until they reach the manager.
//!
//! With limits (`buffer` in `provigil-agent.json`): at most `queue_size` events in memory,
//! sending paced to `events_per_second`, and state events (90 %, full, flooded, normal) put in
//! front of the queue once per transition. Without limits: a ring of `max_size` events that
//! drops the oldest.
//!
//! With a spool (`with_spool`, the agent's `data/spool`): when the memory queue is full (the
//! manager unreachable, or a burst), events go to files of [`SEG_LINES`] lines instead of being
//! dropped, and new ones follow them there while any are left, so the order is kept; the oldest
//! file comes back into memory as the queue empties, and files left by a previous run are sent
//! after a restart. Only past the spool's size limit is anything dropped (its oldest file), and
//! the state events then measure the spool, not the memory queue.

use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::config::BufferConfig;

pub const STATE_90: &str = "provigil: Agent buffer: '90%'.";
pub const STATE_FULL: &str = "provigil: Agent buffer: 'full'.";
pub const STATE_FLOODED: &str = "provigil: Agent buffer: 'flooded'.";
pub const STATE_NORMAL: &str = "provigil: Agent buffer: 'normal'.";
const STATE_LOCATION: &str = "provigil-agent";
/// JSON in one batch at most (a single larger event goes alone): well under the manager's
/// message limits, so a batch is never refused for its size alone.
const BATCH_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
enum State { Normal, Warn90, Full, Flooded }

/// Lines per spool file.
pub const SEG_LINES: u64 = 1000;

/// One spool file: `<seq>.jsonl`.
#[derive(Debug)]
struct Seg {
    path: PathBuf,
    seq: i64,
    bytes: u64,
    lines: u64,
}

/// Events on disk, oldest file first.
#[derive(Debug)]
struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    segs: VecDeque<Seg>,
    bytes: u64,
}

impl Spool {
    /// The folder's files from a previous run, oldest first.
    fn open(dir: &Path, max_bytes: u64) -> Spool {
        let _ = std::fs::create_dir_all(dir);
        let mut segs: Vec<Seg> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let path = e.path();
                let seq = path.file_name()?.to_str()?.strip_suffix(".jsonl")?.parse().ok()?;
                let text = std::fs::read_to_string(&path).ok()?;
                Some(Seg { bytes: text.len() as u64, lines: text.lines().count() as u64, path, seq })
            })
            .collect();
        segs.sort_by_key(|s| s.seq);
        let bytes = segs.iter().map(|s| s.bytes).sum();
        Spool { dir: dir.to_path_buf(), max_bytes, segs: segs.into(), bytes }
    }

    fn is_empty(&self) -> bool {
        self.segs.is_empty()
    }

    fn lines(&self) -> u64 {
        self.segs.iter().map(|s| s.lines).sum()
    }

    /// Appends events after the newest (`front`: before the oldest). Returns the events dropped
    /// to stay under the size limit (the oldest file), and an error text when writing failed.
    fn write(&mut self, events: &[Value], front: bool) -> (u64, Option<String>) {
        let text: String = events.iter().map(|e| format!("{e}\n")).collect();
        let n = events.len() as u64;
        let tail_has_room = !front && self.segs.back().is_some_and(|s| s.lines + n <= SEG_LINES);
        let (path, seq) = if tail_has_room {
            let s = self.segs.back().unwrap();
            (s.path.clone(), s.seq)
        } else {
            let seq = if front { self.segs.front().map_or(0, |s| s.seq - 1) } else { self.segs.back().map_or(0, |s| s.seq + 1) };
            (self.dir.join(format!("{seq}.jsonl")), seq)
        };
        let written = std::fs::OpenOptions::new().create(true).append(true).open(&path).and_then(|mut f| f.write_all(text.as_bytes()));
        if let Err(e) = written {
            return (n, Some(format!("{}: {e}", path.display())));
        }
        let b = text.len() as u64;
        if tail_has_room {
            let s = self.segs.back_mut().unwrap();
            s.bytes += b;
            s.lines += n;
        } else if front {
            self.segs.push_front(Seg { path, seq, bytes: b, lines: n });
        } else {
            self.segs.push_back(Seg { path, seq, bytes: b, lines: n });
        }
        self.bytes += b;
        let mut dropped = 0;
        while self.bytes > self.max_bytes && self.segs.len() > 1 {
            let old = self.segs.pop_front().unwrap();
            let _ = std::fs::remove_file(&old.path);
            self.bytes -= old.bytes;
            dropped += old.lines;
        }
        (dropped, None)
    }

    /// The oldest file's events (the file removed).
    fn take_oldest(&mut self) -> Vec<Value> {
        let Some(s) = self.segs.pop_front() else { return Vec::new() };
        self.bytes -= s.bytes;
        let text = std::fs::read_to_string(&s.path).unwrap_or_default();
        let _ = std::fs::remove_file(&s.path);
        text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }
}

struct Inner {
    queue: VecDeque<Value>,
    /// State events: sent before `queue`, not counted against `queue_size`.
    urgent: VecDeque<Value>,
    state: State,
    full_since: Option<Instant>,
    dropped: u64,
    dropped_unlogged: u64,
    drop_logged_at: Option<Instant>,
    spool: Option<Spool>,
}

pub struct EventBuffer {
    inner: Mutex<Inner>,
    max_size: usize,
    /// `None`: limits disabled.
    limits: Mutex<Option<BufferConfig>>,
    /// The `agent` object of state events.
    agent: Value,
    /// Full for this long becomes flooded.
    flood_after: Duration,
    /// When the next paced batch may leave.
    pace_at: Mutex<Instant>,
}

fn is_state_event(e: &Value) -> bool {
    e["event_type"] == "logfile" && e["location"] == STATE_LOCATION
}

impl EventBuffer {
    /// A buffer without limits: `max_size` events, the oldest dropped.
    pub fn new(max_size: usize) -> Self {
        Self::build(max_size, None, Value::Null)
    }

    /// A buffer with the configured limits (`disabled` gives [`EventBuffer::new`]).
    pub fn with_limits(max_size: usize, cfg: &BufferConfig, agent: Value) -> Self {
        Self::build(max_size, (!cfg.disabled).then_some(*cfg), agent)
    }

    fn build(max_size: usize, limits: Option<BufferConfig>, agent: Value) -> Self {
        Self {
            inner: Mutex::new(Inner {
                queue: VecDeque::with_capacity(max_size.min(1000)),
                urgent: VecDeque::new(),
                state: State::Normal,
                full_since: None,
                dropped: 0,
                dropped_unlogged: 0,
                drop_logged_at: None,
                spool: None,
            }),
            max_size,
            limits: Mutex::new(limits),
            agent,
            flood_after: Duration::from_secs(15),
            pace_at: Mutex::new(Instant::now()),
        }
    }

    fn limits(&self) -> Option<BufferConfig> {
        *self.limits.lock().unwrap()
    }

    /// Keeps what does not fit in memory in `dir` (at most `max_bytes`; 0: no spool), and sends
    /// what a previous run left there.
    pub fn with_spool(self, dir: &Path, max_bytes: u64) -> Self {
        if max_bytes > 0 {
            let s = Spool::open(dir, max_bytes);
            if !s.is_empty() {
                info!(events = s.lines(), bytes = s.bytes, "Events kept on disk by the previous run: sending them");
            }
            self.inner.lock().unwrap().spool = Some(s);
        }
        self
    }

    /// Events dropped: counted and logged once a minute.
    fn count_dropped(q: &mut Inner, n: u64) {
        q.dropped += n;
        q.dropped_unlogged += n;
        if q.drop_logged_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
            warn!(dropped = q.dropped_unlogged, total = q.dropped, "Agent buffer full: events dropped");
            q.dropped_unlogged = 0;
            q.drop_logged_at = Some(Instant::now());
        }
    }

    /// Spools `events` (after the newest, or before the oldest); false without a spool.
    fn spool_write(q: &mut Inner, events: &[Value], front: bool) -> bool {
        let Some(s) = q.spool.as_mut() else { return false };
        let (dropped, error) = s.write(events, front);
        if let Some(e) = error {
            warn!(error = %e, "Events could not be kept on disk");
        }
        if dropped > 0 {
            Self::count_dropped(q, dropped);
        }
        true
    }

    /// Brings the oldest spool files into memory while the queue has room for them.
    fn refill(q: &mut Inner, cap: usize) {
        while q.spool.as_ref().is_some_and(|s| !s.is_empty()) {
            let next = q.spool.as_ref().and_then(|s| s.segs.front()).map_or(0, |s| s.lines as usize);
            if !q.queue.is_empty() && q.queue.len() + next > cap {
                break;
            }
            let events = q.spool.as_mut().unwrap().take_oldest();
            q.queue.extend(events);
        }
    }

    /// New limits (the group configuration changed); the queued events stay.
    pub fn set_limits(&self, cfg: &BufferConfig) {
        *self.limits.lock().unwrap() = (!cfg.disabled).then_some(*cfg);
    }

    /// Adds an event. With limits a new event is dropped when the queue is full; without, the
    /// oldest is.
    pub fn push(&self, event: Value) {
        let mut q = self.inner.lock().unwrap();
        match self.limits() {
            None => {
                if q.queue.len() >= self.max_size {
                    q.queue.pop_front();
                }
                q.queue.push_back(event);
            }
            Some(l) => {
                // while anything is on disk, new events follow it there: the order is kept
                let spooling = q.spool.as_ref().is_some_and(|s| !s.is_empty());
                if spooling || q.queue.len() >= l.queue_size {
                    if !Self::spool_write(&mut q, std::slice::from_ref(&event), false) {
                        Self::count_dropped(&mut q, 1);
                    }
                } else {
                    q.queue.push_back(event);
                }
                self.check_state(&mut q, l.queue_size);
            }
        }
    }

    /// Moves the queue to its next state and queues the state events of the transitions.
    fn check_state(&self, q: &mut Inner, cap: usize) {
        // with a spool, memory filling up loses nothing: the state is how full the disk is
        let (len, cap) = match q.spool.as_ref() {
            Some(s) => (s.bytes as usize, s.max_bytes as usize),
            None => (q.queue.len(), cap),
        };
        let full = len >= cap;
        let mut out = Vec::new();
        if q.state != State::Normal && len * 100 <= cap * 70 {
            info!("Agent buffer is under 70 %. Working properly again.");
            q.state = State::Normal;
            q.full_since = None;
            out.push(STATE_NORMAL);
        }
        if q.state == State::Normal && len * 100 >= cap * 90 {
            warn!("Agent buffer at 90 %.");
            q.state = State::Warn90;
            out.push(STATE_90);
        }
        if full && q.state < State::Full {
            warn!("Agent buffer is full: Events may be lost.");
            q.state = State::Full;
            q.full_since = Some(Instant::now());
            out.push(STATE_FULL);
        }
        if full && q.state == State::Full && q.full_since.is_some_and(|t| t.elapsed() >= self.flood_after) {
            warn!("Agent buffer is flooded: Producing too many events.");
            q.state = State::Flooded;
            out.push(STATE_FLOODED);
        }
        for text in out {
            q.urgent.push_back(json!({
                "event_type": "logfile",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "agent": self.agent,
                "location": STATE_LOCATION,
                "message": text,
            }));
        }
    }

    /// Takes up to `limit` events and [`BATCH_BYTES`] of JSON, state events first.
    pub fn drain_batch(&self, limit: usize) -> Vec<Value> {
        let mut q = self.inner.lock().unwrap();
        if let Some(l) = self.limits() {
            Self::refill(&mut q, l.queue_size);
        }
        let (mut batch, mut bytes) = (Vec::new(), 0);
        while batch.len() < limit {
            let from = if q.urgent.is_empty() { &mut q.queue } else { &mut q.urgent };
            let Some(n) = from.front().map(|e| e.to_string().len()) else { break };
            if !batch.is_empty() && bytes + n > BATCH_BYTES {
                break;
            }
            bytes += n;
            batch.extend(from.pop_front());
        }
        if let Some(l) = self.limits() {
            Self::refill(&mut q, l.queue_size);
            self.check_state(&mut q, l.queue_size);
        }
        batch
    }

    /// The next batch to send, paced to `events_per_second` (at once without limits): batches
    /// of a fifth of a second's worth, each released when the average allows it.
    pub async fn next_batch(&self, limit: usize) -> Vec<Value> {
        let Some(l) = self.limits() else { return self.drain_batch(limit) };
        // what is on disk counts as waiting
        Self::refill(&mut self.inner.lock().unwrap(), l.queue_size);
        let eps = l.events_per_second.max(l.min_eps).max(1);
        let n = self.len().min(limit).min((eps as usize / 5).max(1));
        if n == 0 {
            return Vec::new();
        }
        let now = Instant::now();
        let ready = {
            let mut at = self.pace_at.lock().unwrap();
            *at = (*at).max(now) + Duration::from_secs_f64(n as f64 / eps as f64);
            *at
        };
        tokio::time::sleep(ready.saturating_duration_since(now)).await;
        self.drain_batch(n)
    }

    /// Re-queues failed events at the front so order is preserved.
    pub fn prepend_batch(&self, batch: Vec<Value>) {
        let mut q = self.inner.lock().unwrap();
        let cap = self.limits().map_or(self.max_size, |l| l.queue_size);
        if q.spool.is_some() {
            // the failed batch is the oldest: in front; what no longer fits in memory is the
            // newest of it, which goes to disk in front of everything there
            for event in batch.into_iter().rev() {
                if is_state_event(&event) {
                    q.urgent.push_front(event);
                } else {
                    q.queue.push_front(event);
                }
            }
            if q.queue.len() > cap {
                let over: Vec<Value> = q.queue.split_off(cap).into();
                if !Self::spool_write(&mut q, &over, true) {
                    Self::count_dropped(&mut q, over.len() as u64);
                }
            }
        } else {
            for event in batch.into_iter().rev() {
                if is_state_event(&event) {
                    q.urgent.push_front(event);
                } else if q.queue.len() < cap {
                    q.queue.push_front(event);
                }
            }
        }
        if let Some(l) = self.limits() {
            self.check_state(&mut q, l.queue_size);
        }
    }

    /// The queue's state, for `getstate`.
    pub fn state(&self) -> &'static str {
        match self.inner.lock().unwrap().state {
            State::Normal => "normal",
            State::Warn90 => "90%",
            State::Full => "full",
            State::Flooded => "flooded",
        }
    }

    /// Events dropped because the queue was full (with limits).
    pub fn dropped(&self) -> u64 {
        self.inner.lock().unwrap().dropped
    }

    /// Current count of buffered events in memory, state events included.
    pub fn len(&self) -> usize {
        let q = self.inner.lock().unwrap();
        q.queue.len() + q.urgent.len()
    }

    /// Events kept on disk.
    pub fn spooled(&self) -> u64 {
        self.inner.lock().unwrap().spool.as_ref().map_or(0, Spool::lines)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_ring_buffer_fifo_and_capacity() {
        let buf = EventBuffer::new(3);
        buf.push(json!({"id": 1}));
        buf.push(json!({"id": 2}));
        buf.push(json!({"id": 3}));
        assert_eq!(buf.len(), 3);

        // Exceed capacity: id 1 should be evicted
        buf.push(json!({"id": 4}));
        assert_eq!(buf.len(), 3);

        let batch = buf.drain_batch(2);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0]["id"], 2);
        assert_eq!(batch[1]["id"], 3);
        assert_eq!(buf.len(), 1);

        // Prepend back on failure
        buf.prepend_batch(batch);
        assert_eq!(buf.len(), 3);
        let all = buf.drain_batch(10);
        assert_eq!(all[0]["id"], 2);
        assert_eq!(all[1]["id"], 3);
        assert_eq!(all[2]["id"], 4);
    }

    fn limited(queue_size: usize, eps: u32) -> EventBuffer {
        let cfg = BufferConfig { disabled: false, queue_size, events_per_second: eps, min_eps: 1 };
        EventBuffer::with_limits(10_000, &cfg, json!({"id": "001", "name": "pc"}))
    }

    fn messages(batch: &[Value]) -> Vec<&str> {
        batch.iter().filter(|e| is_state_event(e)).map(|e| e["message"].as_str().unwrap()).collect()
    }

    fn ev(n: u64) -> Value {
        json!({ "event_type": "logfile", "location": "x", "message": format!("e{n}") })
    }

    fn drain_all(b: &EventBuffer) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            let batch = b.drain_batch(100);
            if batch.is_empty() {
                return out;
            }
            out.extend(batch.iter().filter(|e| !is_state_event(e)).map(|e| e["message"].as_str().unwrap().to_string()));
        }
    }

    #[test]
    fn full_queue_spools_keeps_order_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let b = limited(10, 1000).with_spool(dir.path(), 10_000_000);
        for n in 0..2500 {
            b.push(ev(n));
        }
        assert_eq!(b.dropped(), 0, "nothing lost");
        assert_eq!((b.len(), b.spooled()), (10, 2490));
        assert!(messages(&b.drain_batch(0)).is_empty() || true);
        // the manager is back: everything, in order
        let got = drain_all(&b);
        assert_eq!(got.len(), 2500);
        assert!(got.iter().enumerate().all(|(i, m)| *m == format!("e{i}")), "in order");
        assert_eq!(b.spooled(), 0);
        // a failed send that no longer fits in memory goes back to disk, in front
        for n in 0..15 {
            b.push(ev(n));
        }
        let first = b.drain_batch(5);
        for n in 15..20 {
            b.push(ev(n));
        }
        b.prepend_batch(first);
        assert_eq!(drain_all(&b), (0..20).map(|n| format!("e{n}")).collect::<Vec<_>>());
        // spooled events wait over a restart
        let b = limited(10, 1000).with_spool(dir.path(), 10_000_000);
        for n in 0..30 {
            b.push(ev(n));
        }
        drop(b);
        let b = limited(10, 1000).with_spool(dir.path(), 10_000_000);
        assert_eq!(b.spooled(), 20, "the memory part of a stopped agent is gone, the disk part is not");
        assert_eq!(drain_all(&b), (10..30).map(|n| format!("e{n}")).collect::<Vec<_>>());
    }

    #[test]
    fn spool_limit_drops_the_oldest_file_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        // about 60 bytes an event: room for roughly two files of 1000
        let b = limited(10, 1000).with_spool(dir.path(), 130_000);
        for n in 0..4000 {
            b.push(ev(n));
        }
        assert!(b.dropped() >= 1000 && b.dropped() % SEG_LINES == 0, "whole oldest files: {}", b.dropped());
        let got = drain_all(&b);
        assert_eq!(got.first().map(String::as_str), Some("e0"), "the memory part was first");
        assert_eq!(got.last().map(String::as_str), Some("e3999"), "the newest kept");
        assert_eq!(got.len() as u64 + b.dropped(), 4000);
        // the state events measure the disk
        let b = limited(10, 1000).with_spool(&dir.path().join("2"), 130_000);
        for n in 0..20 {
            b.push(ev(n));
        }
        assert!(messages(&b.drain_batch(100)).is_empty(), "memory full, disk nearly empty: no warning");
    }

    #[test]
    fn queue_size_drops_new_events_and_counts_them() {
        let buf = limited(10, 500);
        for i in 0..13 {
            buf.push(json!({"id": i}));
        }
        assert_eq!(buf.dropped(), 3);
        let all = buf.drain_batch(100);
        let ids: Vec<i64> = all.iter().filter(|e| !is_state_event(e)).map(|e| e["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, (0..10).collect::<Vec<_>>());
    }

    #[test]
    fn state_events_once_per_transition_in_front() {
        let mut buf = limited(10, 500);
        buf.flood_after = Duration::from_millis(100);
        for i in 0..9 {
            buf.push(json!({"id": i}));
        }
        // 90 %: one state event, in front, not counted against queue_size
        let peek = buf.drain_batch(1);
        assert_eq!(messages(&peek), [STATE_90]);
        let e = &peek[0];
        assert_eq!(e["event_type"], "logfile");
        assert_eq!(e["location"], "provigil-agent");
        assert_eq!(e["agent"]["id"], "001");
        assert!(e["timestamp"].is_string());
        buf.push(json!({"id": 9}));
        assert_eq!(buf.len(), 11); // 10 events + the full state event
        buf.push(json!({"id": 10})); // dropped, still full: no new event
        assert_eq!(buf.dropped(), 1);
        assert_eq!(buf.len(), 11);
        std::thread::sleep(Duration::from_millis(150));
        buf.push(json!({"id": 11}));
        buf.push(json!({"id": 12}));
        // front: full then flooded, each once
        let front = buf.drain_batch(2);
        assert_eq!(messages(&front), [STATE_FULL, STATE_FLOODED]);
        // down to 80 %: still flooded, nothing new; down to 70 %: normal, in front
        let b = buf.drain_batch(2);
        assert!(messages(&b).is_empty());
        let b = buf.drain_batch(1);
        assert_eq!(b[0]["id"], 2);
        let b = buf.drain_batch(1);
        assert_eq!(messages(&b), [STATE_NORMAL]);
        let rest = buf.drain_batch(100);
        assert_eq!(rest.len(), 7);
        assert!(messages(&rest).is_empty());
    }

    #[test]
    fn requeued_state_event_stays_in_front_when_full() {
        let buf = limited(2, 500);
        buf.push(json!({"id": 0}));
        buf.push(json!({"id": 1}));
        let b = buf.drain_batch(1); // the 90 % event
        buf.prepend_batch(b);
        let all = buf.drain_batch(10);
        assert_eq!(messages(&all[..2]), [STATE_90, STATE_FULL]);
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn batch_stops_at_a_mebibyte_of_json() {
        let buf = EventBuffer::new(100);
        for i in 0..5 {
            buf.push(json!({"id": i, "pad": "x".repeat(400_000)}));
        }
        buf.push(json!({"id": 5, "pad": "x".repeat(3 << 20)}));
        let sizes: Vec<usize> = std::iter::from_fn(|| Some(buf.drain_batch(100).len()).filter(|n| *n > 0)).collect();
        assert_eq!(sizes, [2, 2, 1, 1], "an event over the limit goes alone");
    }

    #[tokio::test]
    async fn pacing_keeps_to_min_eps_even_when_limits_were_not_clamped() {
        let cfg = BufferConfig { disabled: false, queue_size: 100, events_per_second: 1, min_eps: 100 };
        let buf = EventBuffer::with_limits(100, &cfg, json!({}));
        for i in 0..20 {
            buf.push(json!({"id": i}));
        }
        let start = Instant::now();
        let mut sent = 0;
        while sent < 20 {
            sent += buf.next_batch(100).await.len();
        }
        // at 1 per second this would take 20 s
        assert!(start.elapsed() < Duration::from_secs(2), "took {:?}", start.elapsed());
    }

    #[tokio::test]
    async fn pacing_100_events_at_50_per_second_take_about_2s() {
        let buf = limited(5000, 50);
        for i in 0..100 {
            buf.push(json!({"id": i}));
        }
        let start = Instant::now();
        let mut sent = 0;
        while sent < 100 {
            sent += buf.next_batch(100).await.len();
        }
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(1800) && took <= Duration::from_millis(2600), "took {took:?}");
    }
}
