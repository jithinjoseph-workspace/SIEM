//! Durable queue on a key-value store (`default` column only).
//! Key: sequence as 20-digit zero-padded decimal. Value: prefix, one zero byte, item bytes.

use crate::kvstore::{KvStore, DEFAULT_COLUMN};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

type Items = BTreeMap<u64, (String, Vec<u8>)>;

pub struct DurableQueue {
    store: KvStore,
    /// Items by sequence, and the next sequence number.
    items: Mutex<(Items, u64)>,
    ready: Condvar,
}

pub fn seq_key(seq: u64) -> String {
    format!("{seq:020}")
}

impl DurableQueue {
    pub fn open(dir: &Path) -> Result<DurableQueue, String> {
        let store = KvStore::open(dir)?;
        let mut items = BTreeMap::new();
        store.scan(DEFAULT_COLUMN, b"", |k, v| {
            let Some(seq) = std::str::from_utf8(k).ok().filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())).and_then(|t| t.parse::<u64>().ok()) else {
                return true;
            };
            let (prefix, item) = match v.iter().position(|b| *b == 0) {
                Some(p) => (String::from_utf8_lossy(&v[..p]).into_owned(), v[p + 1..].to_vec()),
                // No separator: read as no prefix and the value minus its first byte.
                None => (String::new(), v.get(1..).unwrap_or(&[]).to_vec()),
            };
            items.insert(seq, (prefix, item));
            true
        })?;
        let next = items.keys().next_back().map_or(0, |s| s + 1);
        Ok(DurableQueue { store, items: Mutex::new((items, next)), ready: Condvar::new() })
    }

    /// Appends an item; write errors are ignored (the in-memory queue still changes).
    pub fn push(&self, prefix: &str, item: &[u8]) -> u64 {
        let mut g = self.items.lock().unwrap();
        let seq = g.1;
        g.1 += 1;
        let mut v = Vec::with_capacity(prefix.len() + 1 + item.len());
        v.extend_from_slice(prefix.as_bytes());
        v.push(0);
        v.extend_from_slice(item);
        let _ = self.store.put(DEFAULT_COLUMN, seq_key(seq).as_bytes(), &v);
        g.0.insert(seq, (prefix.to_string(), item.to_vec()));
        drop(g);
        self.ready.notify_all();
        seq
    }

    /// Oldest item whose prefix passes `filter`.
    pub fn front(&self, filter: impl Fn(&str) -> bool) -> Option<(u64, String, Vec<u8>)> {
        let g = self.items.lock().unwrap();
        g.0.iter().find(|(_, (p, _))| filter(p)).map(|(s, (p, i))| (*s, p.clone(), i.clone()))
    }

    /// Waits up to `timeout` for the queue to be non-empty, then returns the oldest item.
    pub fn wait_front(&self, timeout: Duration) -> Option<(u64, String, Vec<u8>)> {
        let g = self.items.lock().unwrap();
        let g = if g.0.is_empty() { self.ready.wait_timeout(g, timeout).unwrap().0 } else { g };
        g.0.iter().next().map(|(s, (p, i))| (*s, p.clone(), i.clone()))
    }

    pub fn remove(&self, seq: u64) {
        let mut g = self.items.lock().unwrap();
        if g.0.remove(&seq).is_some() {
            let _ = self.store.delete(DEFAULT_COLUMN, seq_key(seq).as_bytes());
        }
    }

    pub fn count(&self, prefix: &str) -> usize {
        self.items.lock().unwrap().0.values().filter(|(p, _)| p == prefix).count()
    }

    pub fn len(&self) -> usize {
        self.items.lock().unwrap().0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes the items with `prefix`, or every item.
    pub fn clear(&self, prefix: Option<&str>) {
        let mut g = self.items.lock().unwrap();
        let gone: Vec<u64> = g.0.iter().filter(|(_, (p, _))| prefix.is_none_or(|x| x == p)).map(|(s, _)| *s).collect();
        for s in gone {
            g.0.remove(&s);
            let _ = self.store.delete(DEFAULT_COLUMN, seq_key(s).as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_take_reopen_clear() {
        let d = tempfile::tempdir().unwrap();
        {
            let q = DurableQueue::open(d.path()).unwrap();
            q.push("001", b"a");
            q.push("002", b"b");
            q.push("001", b"c");
            let (s, _, i) = q.front(|p| p == "002").unwrap();
            assert_eq!(i, b"b");
            q.remove(s);
        }
        {
            let q = DurableQueue::open(d.path()).unwrap();
            assert_eq!(q.len(), 2);
            assert_eq!(q.front(|_| true).unwrap().2, b"a");
            assert_eq!(q.count("001"), 2);
            q.push("003", b"d");
            q.clear(Some("001"));
        }
        let q = DurableQueue::open(d.path()).unwrap();
        assert_eq!(q.front(|_| true).unwrap(), (3, "003".to_string(), b"d".to_vec()));
        let s = KvStore::open(d.path()).unwrap();
        assert_eq!(s.get(DEFAULT_COLUMN, b"00000000000000000003").unwrap().unwrap(), b"003\0d");
    }

    #[test]
    fn value_without_separator() {
        let d = tempfile::tempdir().unwrap();
        {
            let s = KvStore::open(d.path()).unwrap();
            s.put(DEFAULT_COLUMN, b"00000000000000000007", b"jabc").unwrap();
            s.put(DEFAULT_COLUMN, b"notanumber", b"x\0y").unwrap();
        }
        let q = DurableQueue::open(d.path()).unwrap();
        assert_eq!(q.len(), 1);
        assert_eq!(q.front(|_| true).unwrap(), (7, String::new(), b"abc".to_vec()));
        assert_eq!(q.push("", b"z"), 8);
    }
}
