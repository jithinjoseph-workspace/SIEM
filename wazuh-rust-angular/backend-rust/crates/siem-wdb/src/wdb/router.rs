//! The router providers wazuh-db publishes to (`wdb-agent-events`,
//! `wdb-inventory-events`), shared by the Linux and the portable daemon.

use std::sync::Arc;

use parking_lot::Mutex;
use siem_log::WLog;

/// `WDB_AGENT_EVENTS_TOPIC` / `WDB_INVENTORY_EVENTS_TOPIC`
pub const WDB_AGENT_EVENTS_TOPIC: &str = "wdb-agent-events";
pub const WDB_INVENTORY_EVENTS_TOPIC: &str = "wdb-inventory-events";

/// The router providers the daemon publishes to (`router_provider_send`).
pub trait RouterSink: Send + Sync {
    /// `router_provider_create(topic, false)`: whether a handle was created.
    fn create(&self, topic: &str) -> bool;
    /// `router_provider_send(handle, msg, len)`
    fn send(&self, topic: &str, msg: &[u8]) -> i32;
}

/// The router module (siem-router): remote providers of the topics,
/// `router_provider_create(topic, false)` / `router_provider_send`.
#[derive(Default)]
pub struct WazuhRouter {
    handles: Mutex<std::collections::HashMap<String, siem_router::ProviderHandle>>,
}

impl RouterSink for WazuhRouter {
    fn create(&self, topic: &str) -> bool {
        let h = siem_router::router_provider_create(topic, false);
        if h == 0 {
            return false;
        }
        self.handles.lock().insert(topic.to_string(), h);
        true
    }
    fn send(&self, topic: &str, msg: &[u8]) -> i32 {
        let h = self.handles.lock().get(topic).copied().unwrap_or(0);
        siem_router::router_provider_send(h, msg)
    }
}

/// `router_initialize(taggedLogFunction)`: the module logs with the
/// ":router" tag.
pub fn router_initialize(log: Arc<WLog>) {
    siem_router::router_initialize(Arc::new(move |level: &str, msg: &[u8]| {
        let lv = match level {
            "ERROR" => "ERROR",
            "ERROR_EXIT" => "CRITICAL",
            "INFO" => "INFO",
            "WARNING" => "WARNING",
            "DEBUG" => "DEBUG",
            "DEBUG_VERBOSE" => "DEBUG2",
            _ => return,
        };
        log.tagged(":router", lv, msg);
        if level == "ERROR_EXIT" {
            std::process::exit(1);
        }
    }));
}

/// A router without a broker: providers are created and messages dropped.
pub struct NullRouter;

impl RouterSink for NullRouter {
    fn create(&self, _topic: &str) -> bool {
        true
    }
    fn send(&self, _topic: &str, _msg: &[u8]) -> i32 {
        0
    }
}

