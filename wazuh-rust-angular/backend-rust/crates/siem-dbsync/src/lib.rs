//! Port of Wazuh 4.14.7's `shared_modules/dbsync` and `shared_modules/rsync`.
//!
//! * dbsync keeps an inventory in SQLite and reports what changed: row
//!   syncs (`syncRow`), whole-table snapshots (`updateWithSnapshot`),
//!   transactions that report the rows not seen again (`DBSyncTxn`),
//!   selects, deletes, row limits and table relationships.
//! * rsync answers the manager's integrity protocol over a dbsync database:
//!   range checksums (`integrity_check_*`) and `state` rows.
//!
//! Both have the C++ API (`DBSync`, `DBSyncTxn`, `RemoteSync`, on
//! nlohmann-compatible JSON) and the C API (`dbsync_*`, `rsync_*`, on cJSON,
//! in [`capi`] and [`rsync::capi`]). Exceptions are [`error::Error`].

pub mod capi;
mod cconv;
pub mod dbsync;
pub mod engine;
pub mod error;
pub mod rsync;
pub mod sqlite;

pub use dbsync::{initialize, teardown, DBSync, DBSyncTxn, DbSyncHandle, Query, ResultCallback, TxnHandle};
pub use error::{Error, R};

use parking_lot::lock_api::RawRwLock as _;

static CERR: std::sync::OnceLock<Box<dyn Fn(&[u8]) + Send + Sync>> = std::sync::OnceLock::new();

/// Where the modules' `std::cerr` lines go (stderr unless a hook is set,
/// once, before use): the line without its newline.
pub fn set_cerr_hook(f: impl Fn(&[u8]) + Send + Sync + 'static) {
    let _ = CERR.set(Box::new(f));
}

/// `std::cerr << line << '\n'`
pub(crate) fn cerr_line(line: &[u8]) {
    match CERR.get() {
        Some(f) => f(line),
        None => {
            use std::io::Write;
            let mut e = std::io::stderr().lock();
            let _ = e.write_all(line);
            let _ = e.write_all(b"\n");
        }
    }
}

/// `ReturnTypeCallback`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum ReturnTypeCallback {
    Modified = 0,
    Deleted = 1,
    Inserted = 2,
    MaxRows = 3,
    DbError = 4,
    Selected = 5,
    Generic = 6,
}

/// `HostType`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HostType {
    Manager = 0,
    Agent = 1,
}

/// `DbEngineType`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DbEngineType {
    Undefined = 0,
    Sqlite3 = 1,
}

impl DbEngineType {
    pub fn from_i32(v: i32) -> DbEngineType {
        if v == 1 {
            DbEngineType::Sqlite3
        } else {
            DbEngineType::Undefined
        }
    }
}

/// `DbManagement`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DbManagement {
    Volatile = 0,
    Persistent = 1,
}

/// `UNLIMITED_QUEUE_SIZE`
pub const UNLIMITED_QUEUE_SIZE: usize = 0;

/// `std::shared_timed_mutex` (a context's `m_syncMutex`).
pub struct SyncMutex(parking_lot::RawRwLock);

impl SyncMutex {
    pub fn new() -> SyncMutex {
        SyncMutex(parking_lot::RawRwLock::INIT)
    }
}

impl Default for SyncMutex {
    fn default() -> Self {
        SyncMutex::new()
    }
}

/// `Utils::ILocking`: the engine releases the lock around callbacks.
pub trait Locking {
    fn lock(&mut self);
    fn unlock(&mut self);
}

/// `ExclusiveLocking` / `std::unique_lock`
pub struct ExclusiveLocking<'a> {
    m: &'a SyncMutex,
    held: bool,
}

impl<'a> ExclusiveLocking<'a> {
    pub fn new(m: &'a SyncMutex) -> Self {
        m.0.lock_exclusive();
        ExclusiveLocking { m, held: true }
    }
}

impl Locking for ExclusiveLocking<'_> {
    fn lock(&mut self) {
        if !self.held {
            self.m.0.lock_exclusive();
            self.held = true;
        }
    }

    fn unlock(&mut self) {
        if self.held {
            unsafe { self.m.0.unlock_exclusive() };
            self.held = false;
        }
    }
}

impl Drop for ExclusiveLocking<'_> {
    fn drop(&mut self) {
        self.unlock();
    }
}

/// `SharedLocking` / `std::shared_lock`
pub struct SharedLocking<'a> {
    m: &'a SyncMutex,
    held: bool,
}

impl<'a> SharedLocking<'a> {
    pub fn new(m: &'a SyncMutex) -> Self {
        m.0.lock_shared();
        SharedLocking { m, held: true }
    }
}

impl Locking for SharedLocking<'_> {
    fn lock(&mut self) {
        if !self.held {
            self.m.0.lock_shared();
            self.held = true;
        }
    }

    fn unlock(&mut self) {
        if self.held {
            unsafe { self.m.0.unlock_shared() };
            self.held = false;
        }
    }
}

impl Drop for SharedLocking<'_> {
    fn drop(&mut self) {
        self.unlock();
    }
}
