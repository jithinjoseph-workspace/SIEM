//! Faithful port of Wazuh 4.14.7 syscheckd (`src/syscheckd`, `config/syscheck-config.c`).
//! The modules at the crate root are an earlier prototype, not used by the agent.

pub mod cfmt;
pub mod config;
pub mod create_db;
pub mod diff;
pub mod fimdb;
pub mod msgs;
#[cfg(windows)]
pub mod realtime;
#[cfg(windows)]
pub mod registry;
pub mod run_check;
pub mod syscheck;
#[cfg(windows)]
pub mod whodata;
#[cfg(windows)]
pub mod win;

use std::sync::{Arc, OnceLock};

use siem_log::WLog;

/// The process logger (`mdebug1`, `minfo`, ... of the syscheck objects).
static LOG: OnceLock<Arc<WLog>> = OnceLock::new();

pub fn set_log(log: Arc<WLog>) {
    let _ = LOG.set(log);
}

pub fn log() -> Option<&'static Arc<WLog>> {
    LOG.get()
}

pub fn mdebug1(m: impl AsRef<[u8]>) {
    if let Some(l) = log() {
        l.debug1(m);
    }
}
pub fn mdebug2(m: impl AsRef<[u8]>) {
    if let Some(l) = log() {
        l.debug2(m);
    }
}
pub fn minfo(m: impl AsRef<[u8]>) {
    if let Some(l) = log() {
        l.info(m);
    }
}
pub fn mwarn(m: impl AsRef<[u8]>) {
    if let Some(l) = log() {
        l.warn(m);
    }
}
pub fn merror(m: impl AsRef<[u8]>) {
    if let Some(l) = log() {
        l.error(m);
    }
}
/// `isDebug()`
pub fn is_debug() -> bool {
    log().map(|l| l.is_debug() > 0).unwrap_or(false)
}
