//! Least-recently-used cache. Inserting into a full cache evicts the least recently used entry
//! first, even when the key is already present (kept behaviour).

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

pub struct Lru<K, V> {
    cap: usize,
    tick: u64,
    map: HashMap<K, (V, u64)>,
    order: BTreeMap<u64, K>,
}

impl<K: Hash + Eq + Clone, V: Clone> Lru<K, V> {
    pub fn new(cap: usize) -> Self {
        Lru { cap: cap.max(1), tick: 0, map: HashMap::new(), order: BTreeMap::new() }
    }

    pub fn get(&mut self, k: &K) -> Option<V> {
        self.tick += 1;
        let t = self.tick;
        let (v, old) = self.map.get_mut(k)?;
        let prev = std::mem::replace(old, t);
        let v = v.clone();
        self.order.remove(&prev);
        self.order.insert(t, k.clone());
        Some(v)
    }

    pub fn insert(&mut self, k: K, v: V) {
        if self.map.len() >= self.cap {
            if let Some((_, oldest)) = self.order.pop_first() {
                self.map.remove(&oldest);
            }
        }
        self.tick += 1;
        if let Some((_, prev)) = self.map.insert(k.clone(), (v, self.tick)) {
            self.order.remove(&prev);
        }
        self.order.insert(self.tick, k);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eviction_rules() {
        let mut c = Lru::new(2);
        c.insert(1, "a");
        c.insert(2, "b");
        assert_eq!(c.get(&1), Some("a"));
        c.insert(3, "c");
        assert_eq!(c.get(&2), None);
        c.insert(3, "c2");
        assert_eq!(c.get(&1), None);
        assert_eq!(c.get(&3), Some("c2"));
        assert_eq!(c.len(), 1);
    }
}
