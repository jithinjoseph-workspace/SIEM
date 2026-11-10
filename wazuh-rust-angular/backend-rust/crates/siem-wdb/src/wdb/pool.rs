//! The database pool (wazuh_db/wdb_pool.c): one `wdb_t` per database name in
//! a sorted tree (`rbtree`), handed out locked (`wdb_pool_get*`) and given
//! back with `wdb_pool_leave`, which unlocks it, drops the reference and
//! stamps the last use.

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::lock_api::ArcMutexGuard;
use parking_lot::{Mutex, RawMutex};

use super::Wdb;

/// A pool entry: the `wdb_t` fields kept outside its mutex.
pub struct Node {
    pub id: String,
    /// `refcount` (changed under the pool mutex)
    refcount: AtomicU32,
    /// `last`
    last: AtomicI64,
    m: Arc<Mutex<Wdb>>,
}

impl Node {
    pub fn refcount(&self) -> u32 {
        self.refcount.load(Ordering::SeqCst)
    }

    pub fn last(&self) -> i64 {
        self.last.load(Ordering::SeqCst)
    }
}

/// `wdb_pool_t`
#[derive(Default)]
pub struct Pool {
    nodes: Mutex<BTreeMap<String, Arc<Node>>>,
}

/// A locked database (`wdb_t *` between `wdb_pool_get*` and
/// `wdb_pool_leave`). Dropping it leaves the pool.
pub struct Guard {
    pool: Arc<Pool>,
    node: Arc<Node>,
    g: Option<ArcMutexGuard<RawMutex, Wdb>>,
    now: i64,
}

impl Guard {
    pub fn node(&self) -> &Arc<Node> {
        &self.node
    }

    /// The time `wdb_pool_leave` stamps as the last use.
    pub fn set_leave_time(&mut self, now: i64) {
        self.now = now;
    }
}

impl Deref for Guard {
    type Target = Wdb;
    fn deref(&self) -> &Wdb {
        self.g.as_ref().expect("locked")
    }
}

impl DerefMut for Guard {
    fn deref_mut(&mut self) -> &mut Wdb {
        self.g.as_mut().expect("locked")
    }
}

impl Drop for Guard {
    /// `wdb_pool_leave`
    fn drop(&mut self) {
        self.g = None;
        {
            let _p = self.pool.nodes.lock();
            self.node.refcount.fetch_sub(1, Ordering::SeqCst);
        }
        self.node.last.store(self.now, Ordering::SeqCst);
    }
}

impl Pool {
    fn lock_node(self: &Arc<Self>, node: Arc<Node>, now: i64) -> Guard {
        let g = node.m.lock_arc();
        Guard { pool: self.clone(), node, g: Some(g), now }
    }

    /// `wdb_pool_get`
    pub fn get(self: &Arc<Self>, name: &str, now: i64) -> Option<Guard> {
        let node = {
            let nodes = self.nodes.lock();
            let node = nodes.get(name)?.clone();
            node.refcount.fetch_add(1, Ordering::SeqCst);
            node
        };
        Some(self.lock_node(node, now))
    }

    /// `wdb_pool_get_or_create`
    pub fn get_or_create(self: &Arc<Self>, name: &str, now: i64) -> Guard {
        let node = {
            let mut nodes = self.nodes.lock();
            let node = nodes
                .entry(name.to_string())
                .or_insert_with(|| {
                    Arc::new(Node {
                        id: name.to_string(),
                        refcount: AtomicU32::new(0),
                        last: AtomicI64::new(0),
                        m: Arc::new(Mutex::new(Wdb::new(name))),
                    })
                })
                .clone();
            node.refcount.fetch_add(1, Ordering::SeqCst);
            node
        };
        self.lock_node(node, now)
    }

    /// `wdb_pool_keys` (sorted like the red-black tree's in-order walk)
    pub fn keys(&self) -> Vec<String> {
        self.nodes.lock().keys().cloned().collect()
    }

    /// `wdb_pool_clean`: drop the closed databases nobody holds.
    pub fn clean(&self) {
        let mut nodes = self.nodes.lock();
        let keys: Vec<String> = nodes.keys().cloned().collect();
        for k in keys {
            let remove = match nodes.get(&k) {
                Some(n) => n.refcount() == 0 && n.m.try_lock().map(|w| w.db.is_none()).unwrap_or(false),
                None => false,
            };
            if remove {
                nodes.remove(&k);
            }
        }
    }

    /// `wdb_pool_size`
    pub fn size(&self) -> u32 {
        self.nodes.lock().len() as u32
    }

    /// Removes a node from the pool (`rbtree_delete`, used by the global
    /// backup restore).
    pub fn remove(&self, name: &str) {
        self.nodes.lock().remove(name);
    }
}
