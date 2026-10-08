//! Shared utilities module (utils)
//!
//! Provides fundamental concurrency, caching, pipeline, and cryptographic building blocks
//! mirroring Wazuh's `src/shared_modules/utils` (threadSafeQueue, cacheLRU, pipelinePattern, roundRobinSelector, etc.).

use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Thread-safe bounded queue (`threadSafeQueue.h`).
#[derive(Debug, Clone)]
pub struct ThreadSafeQueue<T> {
    inner: Arc<Mutex<VecDeque<T>>>,
    max_capacity: usize,
}

impl<T> ThreadSafeQueue<T> {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            max_capacity,
        }
    }

    /// Push item into queue. Returns false if queue reached max capacity.
    pub fn push(&self, item: T) -> bool {
        let mut queue = self.inner.lock().unwrap();
        if queue.len() >= self.max_capacity {
            return false;
        }
        queue.push_back(item);
        true
    }

    /// Pop item from queue.
    pub fn pop(&self) -> Option<T> {
        let mut queue = self.inner.lock().unwrap();
        queue.pop_front()
    }

    /// Current queue length.
    pub fn len(&self) -> usize {
        let queue = self.inner.lock().unwrap();
        queue.len()
    }

    /// Check if queue is empty.
    pub fn is_empty(&self) -> bool {
        let queue = self.inner.lock().unwrap();
        queue.is_empty()
    }
}

/// Thread-safe Least Recently Used (LRU) Cache (`cacheLRU.hpp`).
#[derive(Debug)]
pub struct LruCache<K: Hash + Eq + Clone, V: Clone> {
    capacity: usize,
    map: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K: Hash + Eq + Clone, V: Clone> LruCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "Capacity must be > 0");
        Self {
            capacity,
            map: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        }
    }

    /// Retrieve value and update its access position.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        if self.map.contains_key(key) {
            // Move key to front of order
            if let Some(pos) = self.order.iter().position(|x| x == key) {
                self.order.remove(pos);
            }
            self.order.push_front(key.clone());
            self.map.get(key)
        } else {
            None
        }
    }

    /// Insert or update value. Evicts oldest item if at capacity.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if let Some(pos) = self.order.iter().position(|x| x == &key) {
            self.order.remove(pos);
        } else if self.order.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_back() {
                self.map.remove(&oldest);
            }
        }

        self.order.push_front(key.clone());
        self.map.insert(key, value)
    }

    /// Current count of items in cache.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Pipeline processing pattern (`pipelinePattern.h`).
pub struct Pipeline<T> {
    stages: Vec<Box<dyn Fn(T) -> Option<T> + Send + Sync>>,
}

impl<T: 'static> Pipeline<T> {
    pub fn new() -> Self {
        Self { stages: Vec::new() }
    }

    /// Add a stage to the pipeline. If a stage returns None, the pipeline halts.
    pub fn add_stage<F>(mut self, stage: F) -> Self
    where
        F: Fn(T) -> Option<T> + Send + Sync + 'static,
    {
        self.stages.push(Box::new(stage));
        self
    }

    /// Execute input through each stage sequentially.
    pub fn process(&self, mut item: T) -> Option<T> {
        for stage in &self.stages {
            item = stage(item)?;
        }
        Some(item)
    }
}

/// Round-robin selector across endpoints or servers (`roundRobinSelector.hpp`).
#[derive(Debug)]
pub struct RoundRobinSelector<T: Clone> {
    items: Vec<T>,
    index: AtomicUsize,
}

impl<T: Clone> RoundRobinSelector<T> {
    pub fn new(items: Vec<T>) -> Self {
        Self {
            items,
            index: AtomicUsize::new(0),
        }
    }

    /// Select next item round-robin.
    pub fn next(&self) -> Option<T> {
        if self.items.is_empty() {
            return None;
        }
        let idx = self.index.fetch_add(1, Ordering::Relaxed) % self.items.len();
        Some(self.items[idx].clone())
    }
}

/// Cryptographic digest helpers (`hashHelper.h`).
pub struct CryptoHelper;

impl CryptoHelper {
    /// Compute hex SHA-1 of byte slice.
    pub fn sha1(data: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Compute hex SHA-256 of byte slice.
    pub fn sha256(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}
