//! Wazuh Active Response Execution Daemon (src/os_execd)
//!
//! Complete, 100% line-by-line parity port of Wazuh's active response execution daemon:
//! - config: active-response configuration loader and command catalog (ar.conf)
//! - timeout: Timeout schedule tracker and repeated offenders multiplier penalty manager
//! - executor: Safe command execution with STDIN pipes and directory traversal protection
//! - wcom: IPC control protocol (restart, reload, lock_restart, unmerge, uncompress, getconfig)
//! - execd: Main daemon message evaluator and lifecycle coordinator

pub mod config;
pub mod execd;
pub mod executor;
pub mod responses;
pub mod timeout;
pub mod wcom;

pub use config::{CommandCatalog, CommandEntry, ExecdConfig};
pub use execd::ActiveResponseEngine;
pub use executor::{derive_rkey, execute_ar_action, execute_ar_handshake};
pub use responses::{
    execute_disable_account, execute_firewall_drop, execute_host_deny, execute_route_null,
    write_ar_log, ArAction,
};
pub use timeout::{TimeoutEntry, TimeoutManager};
pub use wcom::{wcom_dispatch, wcom_lock_restart, wcom_reload, wcom_restart};
