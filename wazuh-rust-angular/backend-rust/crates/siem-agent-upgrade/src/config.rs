use serde::{Deserialize, Serialize};

pub const WM_UPGRADE_WPK_REPO_URL_3_X: &str = "packages.wazuh.com/wpk/";
pub const WM_UPGRADE_WPK_REPO_URL: &str = "packages.wazuh.com/{}.x/wpk/";
pub const WM_UPGRADE_CHUNK_SIZE: usize = 32768;
pub const WM_UPGRADE_CHUNK_SIZE_MIN: usize = 64;
pub const WM_UPGRADE_CHUNK_SIZE_MAX: usize = 60000;
pub const WM_UPGRADE_MAX_THREADS: usize = 8;
pub const WM_UPGRADE_WAIT_START: u64 = 30;
pub const WM_UPGRADE_WAIT_MAX: u64 = 3600;
pub const WM_UPGRADE_WAIT_FACTOR_INCREASE: f32 = 2.0;

/// Configuration for agent side of wm_agent_upgrade
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfigs {
    pub upgrade_wait_start: u64,
    pub upgrade_wait_max: u64,
    pub upgrade_wait_factor_increase: f32,
    pub enable_ca_verification: bool,
    pub ca_store: Vec<String>,
}

impl Default for AgentConfigs {
    fn default() -> Self {
        Self {
            upgrade_wait_start: WM_UPGRADE_WAIT_START,
            upgrade_wait_max: WM_UPGRADE_WAIT_MAX,
            upgrade_wait_factor_increase: WM_UPGRADE_WAIT_FACTOR_INCREASE,
            enable_ca_verification: true,
            ca_store: Vec::new(),
        }
    }
}

/// Configuration for manager side of wm_agent_upgrade
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerConfigs {
    pub max_threads: usize,
    pub chunk_size: usize,
    pub wpk_repository: Option<String>,
}

impl Default for ManagerConfigs {
    fn default() -> Self {
        Self {
            max_threads: WM_UPGRADE_MAX_THREADS,
            chunk_size: WM_UPGRADE_CHUNK_SIZE,
            wpk_repository: None,
        }
    }
}

/// Top-level configuration matching wm_agent_upgrade
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentUpgradeConfig {
    pub enabled: bool,
    pub agent_config: AgentConfigs,
    pub manager_config: ManagerConfigs,
}

impl Default for AgentUpgradeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            agent_config: AgentConfigs::default(),
            manager_config: ManagerConfigs::default(),
        }
    }
}
