use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{error, info};

pub const UPGRADE_RESULT_FILE: &str = "upgrade_result";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeResultState {
    Successful = 0,
    FailedDependency = 1,
    Failed = 2,
}

impl UpgradeResultState {
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Self::Successful,
            1 => Self::FailedDependency,
            _ => Self::Failed,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Successful => "Upgrade was successful",
            Self::FailedDependency => "Upgrade failed due missing dependency",
            Self::Failed => "Upgrade failed",
        }
    }

    pub fn task_status(&self) -> &'static str {
        match self {
            Self::Successful => "Done",
            Self::FailedDependency | Self::Failed => "Failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeStatusAckMessage {
    pub command: String,
    pub parameters: UpgradeStatusAckParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeStatusAckParams {
    pub status: String,
    pub error_code: u32,
    pub error_msg: String,
}

/// Agent-side upgrade manager
pub struct AgentUpgradeReporter {
    pub base_dir: PathBuf,
}

impl AgentUpgradeReporter {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Checks if upgrade_result file exists and reads the result code
    pub fn check_upgrade_result(&self) -> Option<UpgradeResultState> {
        let result_path = self.base_dir.join(UPGRADE_RESULT_FILE);
        if !result_path.exists() {
            return None;
        }

        match std::fs::read_to_string(&result_path) {
            Ok(content) => {
                let trimmed = content.trim();
                let code = trimmed.parse::<u32>().unwrap_or(2);
                let state = UpgradeResultState::from_code(code);
                info!("Found upgrade result file with code {code} ({})", state.as_str());
                Some(state)
            }
            Err(e) => {
                error!("Failed to read upgrade result file {}: {e}", result_path.display());
                Some(UpgradeResultState::Failed)
            }
        }
    }

    /// Builds the ACK notification payload to send to the manager
    pub fn build_ack_payload(&self, state: UpgradeResultState) -> UpgradeStatusAckMessage {
        UpgradeStatusAckMessage {
            command: "upgrade_update_status".to_string(),
            parameters: UpgradeStatusAckParams {
                status: state.task_status().to_string(),
                error_code: state as u32,
                error_msg: state.as_str().to_string(),
            },
        }
    }

    /// Cleans up the upgrade_result file once reported
    pub fn clear_upgrade_result(&self) -> std::io::Result<()> {
        let result_path = self.base_dir.join(UPGRADE_RESULT_FILE);
        if result_path.exists() {
            std::fs::remove_file(result_path)?;
        }
        Ok(())
    }
}
