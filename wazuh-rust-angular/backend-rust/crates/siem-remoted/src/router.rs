//! `router_message_forward` (`secure.c`): forwards syscollector deltas and
//! rsync messages to the inventory harvester / vulnerability scanner via the
//! router (`shared_modules/router`). FIM messages are never forwarded.

const DBSYNC_HEADER: &[u8] = b"5:";
const SYSCOLLECTOR_HEADER: &[u8] = b"d:syscollector:";
const SYSCHECK_HEADER: &[u8] = b"8:syscheck:";
const SYSCOLLECTOR_SYNC_HEADER: &[u8] = b"syscollector:";
const SYSCHECK_FILE_HEADER: &[u8] = b"fim_file:";
const SYSCHECK_REGISTRY_KEY_HEADER: &[u8] = b"fim_registry_key:";
const SYSCHECK_REGISTRY_VALUE_HEADER: &[u8] = b"fim_registry_value:";

/// `MT_SYS_DELTAS` / `MT_SYNC`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaType {
    SysDeltas,
    Sync,
}

/// `agent_ctx`
#[derive(Debug, Clone)]
pub struct AgentCtx<'a> {
    pub agent_id: &'a str,
    pub agent_name: &'a str,
    pub agent_ip: &'a str,
    pub agent_version: Option<&'a str>,
}

/// The router providers `deltas-syscollector` and `rsync`.
pub trait Router: Send + Sync {
    fn provider_available(&self, schema: SchemaType) -> bool;
    /// `router_provider_send_fb_json`
    fn send(&self, schema: SchemaType, msg: &[u8], agent: &AgentCtx<'_>) -> bool;
}

/// Router with no subscribers (providers unavailable).
pub struct NoRouter;

impl Router for NoRouter {
    fn provider_available(&self, _: SchemaType) -> bool {
        false
    }
    fn send(&self, _: SchemaType, _: &[u8], _: &AgentCtx<'_>) -> bool {
        false
    }
}

/// The real router (`secure.c`'s HandleSecure start): `router_initialize`
/// with the ":router" tagged log and the remote providers
/// `deltas-syscollector` and `rsync` on wazuh-modulesd's broker.
#[cfg(target_os = "linux")]
pub struct WazuhRouter {
    syscollector: siem_router::ProviderHandle,
    rsync: siem_router::ProviderHandle,
}

#[cfg(target_os = "linux")]
impl WazuhRouter {
    pub fn new() -> Self {
        siem_router::router_initialize(std::sync::Arc::new(|level: &str, msg: &[u8]| {
            let m = String::from_utf8_lossy(msg);
            match level {
                "ERROR" | "ERROR_EXIT" => tracing::error!(target: "router", "{m}"),
                "WARNING" => tracing::warn!(target: "router", "{m}"),
                "INFO" => tracing::info!(target: "router", "{m}"),
                "DEBUG" => tracing::debug!(target: "router", "{m}"),
                _ => tracing::trace!(target: "router", "{m}"),
            }
            if level == "ERROR_EXIT" {
                std::process::exit(1);
            }
        }));
        let syscollector = siem_router::router_provider_create("deltas-syscollector", false);
        if syscollector == 0 {
            tracing::trace!("Failed to create router handle for 'syscollector'.");
        }
        let rsync = siem_router::router_provider_create("rsync", false);
        if rsync == 0 {
            tracing::trace!("Failed to create router handle for 'rsync'.");
        }
        WazuhRouter { syscollector, rsync }
    }
}

#[cfg(target_os = "linux")]
impl Default for WazuhRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl Router for WazuhRouter {
    fn provider_available(&self, schema: SchemaType) -> bool {
        match schema {
            SchemaType::SysDeltas => self.syscollector != 0,
            SchemaType::Sync => self.rsync != 0,
        }
    }

    fn send(&self, schema: SchemaType, msg: &[u8], agent: &AgentCtx<'_>) -> bool {
        let (handle, t) = match schema {
            SchemaType::SysDeltas => (self.syscollector, siem_router::adapter::MT_SYS_DELTAS),
            SchemaType::Sync => (self.rsync, siem_router::adapter::MT_SYNC),
        };
        let ctx = siem_router::adapter::AgentCtx {
            agent_id: agent.agent_id.as_bytes(),
            agent_name: agent.agent_name.as_bytes(),
            agent_ip: agent.agent_ip.as_bytes(),
            agent_version: agent.agent_version.map(str::as_bytes),
        };
        siem_router::router_provider_send_fb_json(handle, Some(msg), Some(&ctx), t) == 0
    }
}

#[cfg(target_os = "linux")]
impl Drop for WazuhRouter {
    fn drop(&mut self) {
        siem_router::router_provider_destroy(self.syscollector);
        siem_router::router_provider_destroy(self.rsync);
    }
}

/// `router_message_forward`
pub fn router_message_forward(r: &dyn Router, msg: &[u8], agent_id: &str, agent_ip: &str, agent_name: &str, version: Option<&str>) {
    let after_dbsync = msg.get(DBSYNC_HEADER.len()..).unwrap_or(&[]);
    if msg.starts_with(SYSCHECK_HEADER)
        || (msg.starts_with(DBSYNC_HEADER)
            && (after_dbsync.starts_with(SYSCHECK_FILE_HEADER)
                || after_dbsync.starts_with(SYSCHECK_REGISTRY_KEY_HEADER)
                || after_dbsync.starts_with(SYSCHECK_REGISTRY_VALUE_HEADER)))
    {
        tracing::trace!("FIM event detected, not forwarding to Inventory Harvester.");
        return;
    }
    let (schema, header_size) = if msg.starts_with(SYSCOLLECTOR_HEADER) {
        if !r.provider_available(SchemaType::SysDeltas) {
            tracing::trace!("Router handle for 'syscollector' not available.");
            return;
        }
        (SchemaType::SysDeltas, SYSCOLLECTOR_HEADER.len())
    } else if msg.starts_with(DBSYNC_HEADER) {
        if !r.provider_available(SchemaType::Sync) {
            tracing::trace!("Router handle for 'rsync' not available.");
            return;
        }
        if after_dbsync.starts_with(SYSCOLLECTOR_SYNC_HEADER) {
            (SchemaType::Sync, DBSYNC_HEADER.len() + SYSCOLLECTOR_SYNC_HEADER.len())
        } else {
            tracing::trace!("DBSYNC message not recognized {}", String::from_utf8_lossy(msg));
            return;
        }
    } else {
        tracing::trace!("{agent_id} message not recognized {}", String::from_utf8_lossy(msg));
        return;
    };
    let start = &msg[header_size..];
    if start.len() + header_size < siem_ipc::OS_MAXSTR {
        let ctx = AgentCtx { agent_id, agent_name, agent_ip, agent_version: version };
        if !r.send(schema, start, &ctx) {
            tracing::trace!("Unable to forward message '{}' for agent '{agent_id}'.", String::from_utf8_lossy(start));
        }
    }
}
