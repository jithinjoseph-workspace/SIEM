use serde::{Deserialize, Serialize};

/// Hardware Inventory Item.
/// Ported from Wazuh include/syscollectorTablesDef.hpp (Hardware table).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HardwareItem {
    pub board_serial: Option<String>,
    pub cpu_name: String,
    pub cpu_cores: usize,
    pub cpu_mhz: Option<f64>,
    pub ram_total: u64, // In KB
    pub ram_free: u64,  // In KB
    pub ram_usage: u8,  // Percentage (0-100)
}

/// Operating System Inventory Item.
/// Ported from Wazuh include/syscollectorTablesDef.hpp (OS table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsItem {
    pub os_name: String,
    pub os_version: String,
    pub os_major: Option<String>,
    pub os_minor: Option<String>,
    pub os_build: Option<String>,
    pub os_platform: String, // "linux", "windows", "darwin"
    pub sysname: String,
    pub release: String,     // Kernel release
    pub architecture: String, // "x86_64", "arm64"
    pub hostname: String,
}

/// Network Interface Item.
/// Ported from Wazuh include/syscollectorTablesDef.hpp (Network Interface table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkIfaceItem {
    pub name: String,
    pub adapter: Option<String>,
    pub iface_type: String, // "ethernet", "wireless", "loopback"
    pub state: String,      // "up", "down"
    pub mtu: Option<u32>,
    pub mac: Option<String>,
}

/// Network Protocol Item.
/// Ported from Wazuh include/syscollectorTablesDef.hpp (Network Protocol table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkProtocolItem {
    pub iface: String,
    pub proto_type: String, // "ipv4", "ipv6"
    pub gateway: Option<String>,
    pub dhcp: Option<String>, // "enabled", "disabled"
}

/// Network Address Item.
/// Ported from Wazuh include/syscollectorTablesDef.hpp (Network Address table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAddressItem {
    pub iface: String,
    pub proto: String,
    pub address: String,
    pub netmask: Option<String>,
    pub broadcast: Option<String>,
}

/// Installed Software Package Item.
/// Ported from Wazuh include/syscollectorTablesDef.hpp (Packages table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageItem {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub format: String, // "deb", "rpm", "win", "pkg"
    pub vendor: Option<String>,
    pub description: Option<String>,
    pub size: Option<u64>,
    pub install_time: Option<String>,
}

/// Windows Hotfix Item.
/// Ported from Wazuh include/syscollectorTablesDef.hpp (Hotfixes table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotfixItem {
    pub hotfix: String, // "KB5005565"
    pub install_time: Option<String>,
}

/// Network Port / Socket Item.
/// Ported from Wazuh include/syscollectorTablesDef.hpp (Ports table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortItem {
    pub protocol: String, // "tcp", "udp", "tcp6", "udp6"
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub tx_queue: Option<u32>,
    pub rx_queue: Option<u32>,
    pub inode: Option<u64>,
    pub state: String, // "listening", "established", "close_wait"
    pub pid: Option<u32>,
    pub process: Option<String>,
}

/// Running Process Item.
/// Ported from Wazuh include/syscollectorTablesDef.hpp (Processes table).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessItem {
    pub pid: u32,
    pub name: String,
    pub state: String,
    pub ppid: Option<u32>,
    pub utime: Option<u64>,
    pub stime: Option<u64>,
    pub cmd: Option<String>,
    pub argvs: Option<String>,
    pub euser: Option<String>,
    pub ruser: Option<String>,
    pub priority: Option<i32>,
    pub nice: Option<i32>,
    pub size: Option<u64>,    // In pages
    pub vm_size: Option<u64>, // Virtual memory in KB
}

/// System User Account Item.
/// Ported from Wazuh include/syscollectorTablesDef.hpp (Users table - dbsync_users).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserItem {
    pub user_name: String,
    pub user_full_name: Option<String>,
    pub user_home: Option<String>,
    pub user_id: Option<i64>,
    pub user_uid_signed: Option<i64>,
    pub user_uuid: Option<String>,
    pub user_groups: Option<String>,
    pub user_group_id: Option<i64>,
    pub user_group_id_signed: Option<i64>,
    pub user_created: Option<f64>,
    pub user_roles: Option<String>,
    pub user_shell: Option<String>,
    pub user_type: Option<String>,
    pub user_is_hidden: Option<i32>,
    pub user_is_remote: Option<i32>,
    pub user_last_login: Option<i64>,
    pub user_auth_failed_count: Option<i64>,
    pub user_auth_failed_timestamp: Option<f64>,
    pub user_password_last_change: Option<f64>,
    pub user_password_expiration_date: Option<i32>,
    pub user_password_hash_algorithm: Option<String>,
    pub user_password_inactive_days: Option<i32>,
    pub user_password_max_days_between_changes: Option<i32>,
    pub user_password_min_days_between_changes: Option<i32>,
    pub user_password_status: Option<String>,
    pub user_password_warning_days_before_expiration: Option<i32>,
    pub process_pid: Option<i64>,
    pub host_ip: Option<String>,
    pub login_status: Option<i32>,
    pub login_tty: Option<String>,
    pub login_type: Option<String>,
}

/// System Group Item.
/// Ported from Wazuh include/syscollectorTablesDef.hpp (Groups table - dbsync_groups).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupItem {
    pub group_id: Option<i64>,
    pub group_name: String,
    pub group_description: Option<String>,
    pub group_id_signed: Option<i64>,
    pub group_uuid: Option<String>,
    pub group_is_hidden: Option<i32>,
    pub group_users: Option<String>,
}

/// System Service Item.
/// Ported from Wazuh include/syscollectorTablesDef.hpp (Services table - dbsync_services).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceItem {
    pub service_id: String,
    pub file_path: Option<String>,
    pub service_name: Option<String>,
    pub service_description: Option<String>,
    pub service_type: Option<String>,
    pub service_state: Option<String>,
    pub service_sub_state: Option<String>,
    pub service_enabled: Option<String>,
    pub service_start_type: Option<String>,
    pub service_restart: Option<String>,
    pub service_frequency: Option<i64>,
    pub service_starts_on_mount: Option<i32>,
    pub service_starts_on_path_modified: Option<String>,
    pub service_starts_on_not_empty_directory: Option<String>,
    pub service_inetd_compatibility: Option<i32>,
    pub process_pid: Option<i64>,
    pub process_executable: Option<String>,
    pub process_args: Option<String>,
    pub process_user_name: Option<String>,
    pub process_group_name: Option<String>,
    pub process_working_dir: Option<String>,
    pub process_root_dir: Option<String>,
    pub service_address: Option<String>,
    pub log_file_path: Option<String>,
    pub error_log_file_path: Option<String>,
    pub service_exit_code: Option<i32>,
    pub service_win32_exit_code: Option<i32>,
    pub service_following: Option<String>,
    pub service_object_path: Option<String>,
    pub service_target_ephemeral_id: Option<i64>,
    pub service_target_type: Option<String>,
    pub service_target_address: Option<String>,
}

/// Browser Extension Item.
/// Ported from Wazuh include/syscollectorTablesDef.hpp (Browser Extensions table - dbsync_browser_extensions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserExtensionItem {
    pub browser_name: String,
    pub user_id: Option<String>,
    pub package_name: String,
    pub package_id: String,
    pub package_version: Option<String>,
    pub package_description: Option<String>,
    pub package_vendor: Option<String>,
    pub package_build_version: Option<String>,
    pub package_path: Option<String>,
    pub browser_profile_name: Option<String>,
    pub browser_profile_path: Option<String>,
    pub package_reference: Option<String>,
    pub package_permissions: Option<String>,
    pub package_type: Option<String>,
    pub package_enabled: Option<i32>,
    pub package_visible: Option<i32>,
    pub package_autoupdate: Option<i32>,
    pub package_persistent: Option<i32>,
    pub package_from_webstore: Option<i32>,
    pub browser_profile_referenced: Option<i32>,
    pub package_installed: Option<String>,
    pub file_hash_sha256: Option<String>,
}
