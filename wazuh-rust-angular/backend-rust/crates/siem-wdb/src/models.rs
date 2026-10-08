use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FimEntryType {
    File,
    RegistryKey,
    RegistryValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimEntry {
    pub full_path: String,
    pub file_name: String,
    pub entry_type: FimEntryType,
    pub size: Option<u64>,
    pub perm: Option<String>,
    pub uid: Option<String>,
    pub gid: Option<String>,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub mtime: u64,
    pub inode: Option<u64>,
    pub changes: u32,
    pub date: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FimAction {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimDelta {
    pub path: String,
    pub action: FimAction,
    pub old_entry: Option<FimEntry>,
    pub new_entry: Option<FimEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysProgram {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub vendor: Option<String>,
    pub format: Option<String>, // deb, rpm, win, pkg
    pub description: Option<String>,
    pub size_bytes: Option<u64>,
    pub install_time: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SysHwInfo {
    pub board_serial: Option<String>,
    pub cpu_name: String,
    pub cpu_cores: usize,
    pub cpu_mhz: f32,
    pub ram_total_mb: u64,
    pub ram_free_mb: u64,
    pub ram_usage_percent: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysOsInfo {
    pub hostname: String,
    pub architecture: String,
    pub os_name: String,
    pub os_version: String,
    pub os_codename: Option<String>,
    pub os_major: Option<String>,
    pub os_minor: Option<String>,
    pub os_build: Option<String>,
    pub platform: String,
    pub release: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysPort {
    pub protocol: String, // tcp, udp
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub state: String, // LISTEN, ESTABLISHED
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysNetIface {
    pub name: String,
    pub adapter: Option<String>,
    pub iface_type: Option<String>,
    pub state: String,
    pub mac: Option<String>,
    pub mtu: Option<u32>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScaStatus {
    Passed,
    Failed,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScaCheckResult {
    pub policy_id: String,
    pub check_id: u32,
    pub title: String,
    pub description: String,
    pub rationale: Option<String>,
    pub remediation: Option<String>,
    pub status: ScaStatus,
}
