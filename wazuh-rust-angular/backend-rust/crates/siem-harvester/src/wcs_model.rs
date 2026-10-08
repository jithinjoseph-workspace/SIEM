use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Wazuh Common Schema (WCS) Agent Metadata.
/// Ported from src/wcsModel/wcsClasses/agent.hpp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WcsAgent {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
}

/// Wazuh Common Schema (WCS) Host Metadata.
/// Ported from src/wcsModel/wcsClasses/host.hpp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WcsHost {
    pub hostname: String,
    pub architecture: String,
    pub os_name: String,
    pub os_version: String,
    pub os_platform: String,
}

/// Wazuh Common Schema (WCS) Package payload.
/// Ported from src/wcsModel/wcsClasses/package.hpp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WcsPackage {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Wazuh Common Schema (WCS) Port payload.
/// Ported from src/wcsModel/wcsClasses/port.hpp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WcsPort {
    pub protocol: String,
    pub local_ip: String,
    pub local_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
}

/// Wazuh Common Schema (WCS) Process payload.
/// Ported from src/wcsModel/wcsClasses/process.hpp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WcsProcess {
    pub pid: u32,
    pub name: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub euser: Option<String>,
}

/// Wazuh Common Schema (WCS) FIM File payload.
/// Ported from src/wcsModel/wcsClasses/file.hpp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WcsFile {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<String>,
}

/// Complete WCS State Document for Inventory (wazuh-states-inventory-*).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WcsInventoryDocument {
    #[serde(rename = "@timestamp")]
    pub timestamp: DateTime<Utc>,
    pub agent: WcsAgent,
    pub host: WcsHost,
    pub data_type: String, // "package", "port", "process", "hardware", "os"
    pub operation: String, // "INSERTED", "MODIFIED", "DELETED"
    pub item_id: String,
    pub checksum: String,
    pub data: serde_json::Value,
}

/// Complete WCS State Document for FIM (wazuh-states-fim-*).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WcsFimDocument {
    #[serde(rename = "@timestamp")]
    pub timestamp: DateTime<Utc>,
    pub agent: WcsAgent,
    pub file: WcsFile,
    pub operation: String, // "ADDED", "MODIFIED", "DELETED"
    pub checksum: String,
}
