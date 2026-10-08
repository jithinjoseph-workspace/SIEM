use crate::delta_sync::{SyncDelta, TableSyncCache};
use crate::normalizer::SysNormalizer;
use crate::tables::{
    BrowserExtensionItem, GroupItem, HardwareItem, HotfixItem, NetworkAddressItem,
    NetworkIfaceItem, NetworkProtocolItem, OsItem, PackageItem, PortItem, ProcessItem,
    ServiceItem, UserItem,
};
use serde::{Deserialize, Serialize};

/// Configuration for syscollector scanning.
/// Ported from Wazuh include/syscollector.h.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscollectorConfig {
    pub interval_secs: u64,
    pub scan_hardware: bool,
    pub scan_os: bool,
    pub scan_network: bool,
    pub scan_packages: bool,
    pub scan_ports: bool,
    pub scan_processes: bool,
    pub scan_hotfixes: bool,
    pub scan_users: bool,
    pub scan_groups: bool,
    pub scan_services: bool,
    pub scan_browser_extensions: bool,
}

impl Default for SyscollectorConfig {
    fn default() -> Self {
        Self {
            interval_secs: 3600, // 1 hour
            scan_hardware: true,
            scan_os: true,
            scan_network: true,
            scan_packages: true,
            scan_ports: true,
            scan_processes: true,
            scan_hotfixes: true,
            scan_users: true,
            scan_groups: true,
            scan_services: true,
            scan_browser_extensions: true,
        }
    }
}

/// Core Syscollector Engine managing normalization and delta synchronization.
/// Ported from Wazuh src/syscollectorImp.cpp.
pub struct SyscollectorEngine {
    pub config: SyscollectorConfig,
    pub normalizer: SysNormalizer,
    hw_cache: TableSyncCache,
    os_cache: TableSyncCache,
    network_iface_cache: TableSyncCache,
    network_proto_cache: TableSyncCache,
    network_addr_cache: TableSyncCache,
    package_cache: TableSyncCache,
    port_cache: TableSyncCache,
    process_cache: TableSyncCache,
    hotfix_cache: TableSyncCache,
    user_cache: TableSyncCache,
    group_cache: TableSyncCache,
    service_cache: TableSyncCache,
    browser_ext_cache: TableSyncCache,
}

impl Default for SyscollectorEngine {
    fn default() -> Self {
        Self::new(SyscollectorConfig::default())
    }
}

impl SyscollectorEngine {
    pub fn new(config: SyscollectorConfig) -> Self {
        Self {
            config,
            normalizer: SysNormalizer::new(),
            hw_cache: TableSyncCache::new(),
            os_cache: TableSyncCache::new(),
            network_iface_cache: TableSyncCache::new(),
            network_proto_cache: TableSyncCache::new(),
            network_addr_cache: TableSyncCache::new(),
            package_cache: TableSyncCache::new(),
            port_cache: TableSyncCache::new(),
            process_cache: TableSyncCache::new(),
            hotfix_cache: TableSyncCache::new(),
            user_cache: TableSyncCache::new(),
            group_cache: TableSyncCache::new(),
            service_cache: TableSyncCache::new(),
            browser_ext_cache: TableSyncCache::new(),
        }
    }

    /// Process hardware scan: computes hardware changes (dbsync_hwinfo).
    pub fn sync_hardware(&mut self, hw: &HardwareItem) -> Vec<SyncDelta> {
        let json_items: Vec<serde_json::Value> = serde_json::to_value(hw).ok().into_iter().collect();
        self.hw_cache.compute_deltas("hwinfo", &json_items, &["cpu_name", "cpu_cores"])
    }

    /// Process OS scan: computes OS metadata changes (dbsync_osinfo).
    pub fn sync_os(&mut self, os: &OsItem) -> Vec<SyncDelta> {
        let json_items: Vec<serde_json::Value> = serde_json::to_value(os).ok().into_iter().collect();
        self.os_cache.compute_deltas("osinfo", &json_items, &["os_name", "os_version"])
    }

    /// Process network interfaces scan (dbsync_network_iface).
    pub fn sync_network_interfaces(&mut self, ifaces: &[NetworkIfaceItem]) -> Vec<SyncDelta> {
        let json_items: Vec<serde_json::Value> = ifaces.iter().filter_map(|i| serde_json::to_value(i).ok()).collect();
        self.network_iface_cache.compute_deltas("network_iface", &json_items, &["name"])
    }

    /// Process network protocols scan (dbsync_network_protocol).
    pub fn sync_network_protocols(&mut self, protos: &[NetworkProtocolItem]) -> Vec<SyncDelta> {
        let json_items: Vec<serde_json::Value> = protos.iter().filter_map(|p| serde_json::to_value(p).ok()).collect();
        self.network_proto_cache.compute_deltas("network_protocol", &json_items, &["iface", "proto_type"])
    }

    /// Process network addresses scan (dbsync_network_address).
    pub fn sync_network_addresses(&mut self, addrs: &[NetworkAddressItem]) -> Vec<SyncDelta> {
        let json_items: Vec<serde_json::Value> = addrs.iter().filter_map(|a| serde_json::to_value(a).ok()).collect();
        self.network_addr_cache.compute_deltas("network_address", &json_items, &["iface", "proto", "address"])
    }

    /// Process a package inventory scan: normalizes all packages and generates delta events (dbsync_packages).
    pub fn sync_packages(&mut self, packages: &mut [PackageItem]) -> Vec<SyncDelta> {
        let mut json_items = Vec::new();

        for pkg in packages.iter_mut() {
            if self.normalizer.is_excluded(&pkg.name) {
                continue;
            }
            self.normalizer.normalize_package(pkg);

            if let Ok(json_val) = serde_json::to_value(&*pkg) {
                json_items.push(json_val);
            }
        }

        self.package_cache.compute_deltas(
            "packages",
            &json_items,
            &["name", "version", "architecture"],
        )
    }

    /// Process a ports inventory scan: computes port delta events (dbsync_ports).
    pub fn sync_ports(&mut self, ports: &[PortItem]) -> Vec<SyncDelta> {
        let json_items: Vec<serde_json::Value> = ports
            .iter()
            .filter_map(|p| serde_json::to_value(p).ok())
            .collect();

        self.port_cache.compute_deltas(
            "ports",
            &json_items,
            &["protocol", "local_ip", "local_port"],
        )
    }

    /// Process a processes inventory scan: computes process lifecycle deltas (dbsync_processes).
    pub fn sync_processes(&mut self, processes: &[ProcessItem]) -> Vec<SyncDelta> {
        let json_items: Vec<serde_json::Value> = processes
            .iter()
            .filter_map(|p| serde_json::to_value(p).ok())
            .collect();

        self.process_cache.compute_deltas(
            "processes",
            &json_items,
            &["pid", "name"],
        )
    }

    /// Process Windows Hotfixes scan: computes hotfix installed/removed deltas (dbsync_hotfixes).
    pub fn sync_hotfixes(&mut self, hotfixes: &[HotfixItem]) -> Vec<SyncDelta> {
        let json_items: Vec<serde_json::Value> = hotfixes
            .iter()
            .filter_map(|h| serde_json::to_value(h).ok())
            .collect();

        self.hotfix_cache.compute_deltas(
            "hotfixes",
            &json_items,
            &["hotfix"],
        )
    }

    /// Process user accounts scan: computes user additions, deletions and updates (dbsync_users).
    pub fn sync_users(&mut self, users: &[UserItem]) -> Vec<SyncDelta> {
        let json_items: Vec<serde_json::Value> = users
            .iter()
            .filter_map(|u| serde_json::to_value(u).ok())
            .collect();

        self.user_cache.compute_deltas(
            "users",
            &json_items,
            &["user_name"],
        )
    }

    /// Process groups scan: computes group additions and modifications (dbsync_groups).
    pub fn sync_groups(&mut self, groups: &[GroupItem]) -> Vec<SyncDelta> {
        let json_items: Vec<serde_json::Value> = groups
            .iter()
            .filter_map(|g| serde_json::to_value(g).ok())
            .collect();

        self.group_cache.compute_deltas(
            "groups",
            &json_items,
            &["group_name"],
        )
    }

    /// Process system services scan: computes service state / binary changes (dbsync_services).
    pub fn sync_services(&mut self, services: &[ServiceItem]) -> Vec<SyncDelta> {
        let json_items: Vec<serde_json::Value> = services
            .iter()
            .filter_map(|s| serde_json::to_value(s).ok())
            .collect();

        self.service_cache.compute_deltas(
            "services",
            &json_items,
            &["service_id"],
        )
    }

    /// Process browser extensions scan (dbsync_browser_extensions).
    pub fn sync_browser_extensions(&mut self, extensions: &[BrowserExtensionItem]) -> Vec<SyncDelta> {
        let json_items: Vec<serde_json::Value> = extensions
            .iter()
            .filter_map(|e| serde_json::to_value(e).ok())
            .collect();

        self.browser_ext_cache.compute_deltas(
            "browser_extensions",
            &json_items,
            &["browser_name", "package_id"],
        )
    }
}

