use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpgradeCommand {
    Upgrade,
    UpgradeCustom,
    UpgradeGetStatus,
    UpgradeUpdateStatus,
    UpgradeResult,
    UpgradeCancelTasks,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeTask {
    pub wpk_repository: Option<String>,
    pub custom_version: Option<String>,
    pub use_http: bool,
    pub force_upgrade: bool,
    pub wpk_version: Option<String>,
    pub wpk_file: Option<String>,
    pub wpk_sha1: Option<String>,
    pub package_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeCustomTask {
    pub custom_file_path: String,
    pub custom_installer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeAgentStatusTask {
    pub error_code: u32,
    pub message: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id: u32,
    pub platform: String,
    pub major_version: Option<String>,
    pub minor_version: Option<String>,
    pub architecture: String,
    pub wazuh_version: String,
    pub connection_status: String,
    pub package_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskData {
    Standard(UpgradeTask),
    Custom(UpgradeCustomTask),
    StatusUpdate(UpgradeAgentStatusTask),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    pub agent_info: AgentInfo,
    pub command: UpgradeCommand,
    pub task_data: TaskData,
}
