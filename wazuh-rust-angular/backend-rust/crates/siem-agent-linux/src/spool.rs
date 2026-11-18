//! Events the manager did not take (not reachable, or a server error) kept on disk until it
//! answers again, so a network outage, a new address or a manager restart loses nothing.
//! Segment files `<seq>.jsonl` (one event per line) in the spool folder, oldest sent first;
//! at most `max_bytes` (the oldest segments are deleted first) and `keep_secs` old.
//! `PROVIGIL_SPOOL_DIR`, `PROVIGIL_SPOOL_MAX_MB` (512) and `PROVIGIL_SPOOL_KEEP_DAYS` (7).

use siem_core::RawEvent;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::warn;

/// A segment is closed at this size and a new one started.
const SEGMENT_BYTES: u64 = 4 << 20;

pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    keep: Duration,
    /// the segment written to now
    seq: u64,
    /// whether any segment is on disk (the folder is not listed on every send)
    pending: bool,
}

impl Spool {
    /// From the environment, in the agent's folder.
    pub fn from_env() -> Spool {
        let dir = std::env::var("PROVIGIL_SPOOL_DIR").map(PathBuf::from).unwrap_or_else(|_| {
            if Path::new("/opt/provigil-agent").is_dir() { PathBuf::from("/opt/provigil-agent/var/spool") } else { PathBuf::from("/var/lib/provigil-agent/spool") }
        });
        let num = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(d);
        Spool::open(dir, num("PROVIGIL_SPOOL_MAX_MB", 512) << 20, Duration::from_secs(num("PROVIGIL_SPOOL_KEEP_DAYS", 7) * 86_400))
    }

    pub fn open(dir: PathBuf, max_bytes: u64, keep: Duration) -> Spool {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            warn!("Spool folder {} not usable ({e}): events the manager does not take are lost", dir.display());
        }
        let mut s = Spool { dir, max_bytes, keep, seq: 0, pending: true };
        s.seq = s.segments().last().map_or(0, |(n, _)| n + 1);
        s.expire();
        s.pending = !s.segments().is_empty();
        s
    }

    /// The segments, oldest first.
    fn segments(&self) -> Vec<(u64, PathBuf)> {
        let mut v: Vec<(u64, PathBuf)> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                let n = p.file_name()?.to_str()?.strip_suffix(".jsonl")?.parse().ok()?;
                Some((n, p))
            })
            .collect();
        v.sort();
        v
    }

    pub fn is_empty(&self) -> bool {
        !self.pending
    }

    /// Keeps `events` (appended to the current segment).
    pub fn put(&mut self, events: &[RawEvent]) {
        let path = self.dir.join(format!("{}.jsonl", self.seq));
        let mut text = String::new();
        for e in events {
            if let Ok(line) = serde_json::to_string(e) {
                text.push_str(&line);
                text.push('\n');
            }
        }
        let written = std::fs::OpenOptions::new().create(true).append(true).open(&path).and_then(|mut f| f.write_all(text.as_bytes()));
        if let Err(e) = written {
            warn!("{} event(s) not kept in {}: {e}", events.len(), path.display());
            return;
        }
        if std::fs::metadata(&path).map_or(0, |m| m.len()) >= SEGMENT_BYTES {
            self.seq += 1;
        }
        self.expire();
        self.pending = !self.segments().is_empty();
    }

    /// The oldest segment and its events, to send; new events then go to a new segment.
    pub fn take_oldest(&mut self) -> Option<(PathBuf, Vec<RawEvent>)> {
        if !self.pending {
            return None;
        }
        let Some((n, path)) = self.segments().into_iter().next() else {
            self.pending = false;
            return None;
        };
        if n >= self.seq {
            self.seq = n + 1;
        }
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        // a line cut short (a stop while writing) is skipped, the rest kept
        let events = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
        Some((path, events))
    }

    /// A segment fully sent.
    pub fn done(&mut self, path: &Path) {
        let _ = std::fs::remove_file(path);
        self.pending = !self.segments().is_empty();
    }

    /// Deletes segments older than `keep`, then the oldest beyond `max_bytes`.
    fn expire(&self) {
        let segs = self.segments();
        let now = SystemTime::now();
        let mut kept: Vec<(PathBuf, u64)> = Vec::new();
        for (_, p) in segs {
            let Ok(m) = std::fs::metadata(&p) else { continue };
            if m.modified().ok().and_then(|t| now.duration_since(t).ok()).is_some_and(|age| age > self.keep) {
                warn!("Kept events older than {} days deleted: {}", self.keep.as_secs() / 86_400, p.display());
                let _ = std::fs::remove_file(&p);
            } else {
                kept.push((p, m.len()));
            }
        }
        let mut total: u64 = kept.iter().map(|(_, n)| n).sum();
        for (p, n) in kept {
            if total <= self.max_bytes {
                break;
            }
            warn!("Spool over {} MB: the oldest kept events deleted ({})", self.max_bytes >> 20, p.display());
            let _ = std::fs::remove_file(&p);
            total -= n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siem_core::EventSource;

    fn ev(i: usize) -> RawEvent {
        RawEvent::new("001", EventSource::Syslog, "test", format!("event {i}"))
    }

    #[test]
    fn keeps_in_order_across_restarts_and_limits() {
        let dir = std::env::temp_dir().join(format!("provigil-spool-{}", uuid::Uuid::new_v4()));
        let mut s = Spool::open(dir.clone(), 1 << 30, Duration::from_secs(3600));
        assert!(s.is_empty() && s.take_oldest().is_none());
        s.put(&[ev(1), ev(2)]);
        let (p, got) = s.take_oldest().unwrap();
        // written after the take: a newer segment, sent after this one
        s.put(&[ev(3)]);
        assert_eq!(got.iter().map(|e| e.message.clone()).collect::<Vec<_>>(), ["event 1", "event 2"]);
        s.done(&p);
        // a restart finds what is left
        let mut s = Spool::open(dir.clone(), 1 << 30, Duration::from_secs(3600));
        let (p, got) = s.take_oldest().unwrap();
        assert_eq!(got.len(), 1);
        s.done(&p);
        assert!(s.is_empty());
        // over the size limit: the oldest go first
        let mut s = Spool::open(dir.clone(), 1, Duration::from_secs(3600));
        s.put(&[ev(4)]);
        assert!(s.is_empty(), "a spool of 1 byte keeps nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
