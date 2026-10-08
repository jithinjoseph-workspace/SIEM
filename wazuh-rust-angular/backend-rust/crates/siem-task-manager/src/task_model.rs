use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Task status lifecycle.
/// Matches Wazuh wm_task_manager status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    InProgress,
    Done,
    Failed,
    Timeout,
    Cancelled,
    Legacy,
}

impl fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaskStatus::Pending => write!(f, "Pending"),
            TaskStatus::InProgress => write!(f, "In progress"),
            TaskStatus::Done => write!(f, "Done"),
            TaskStatus::Failed => write!(f, "Failed"),
            TaskStatus::Timeout => write!(f, "Timeout"),
            TaskStatus::Cancelled => write!(f, "Cancelled"),
            TaskStatus::Legacy => write!(f, "Legacy"),
        }
    }
}

impl TaskStatus {
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "pending" => TaskStatus::Pending,
            "in progress" | "in_progress" => TaskStatus::InProgress,
            "done" | "success" => TaskStatus::Done,
            "failed" | "error" => TaskStatus::Failed,
            "timeout" => TaskStatus::Timeout,
            "cancelled" | "canceled" => TaskStatus::Cancelled,
            "legacy" => TaskStatus::Legacy,
            _ => TaskStatus::Pending,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, TaskStatus::Done | TaskStatus::Failed | TaskStatus::Timeout | TaskStatus::Cancelled)
    }
}

/// Task commands supported by wm_task_manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskCommand {
    Upgrade,
    UpgradeCustom,
    UpgradeGetStatus,
    UpgradeUpdateStatus,
    UpgradeResult,
    UpgradeCancelTasks,
}

/// Error codes matching Wazuh error_code enum in wm_task_manager.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskErrorCode {
    Success = 0,
    InvalidMessage = 1,
    InvalidCommand = 2,
    DatabaseNoTask = 3,
    DatabaseError = 4,
    DatabaseParseError = 5,
    DatabaseRequestError = 6,
    UnknownError = 7,
}

/// Persistent record of an agent task in the task database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRecord {
    pub task_id: u64,
    pub agent_id: String,
    pub node: String,
    pub module: String,
    pub command: TaskCommand,
    pub status: TaskStatus,
    pub error_message: Option<String>,
    pub custom_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TaskRecord {
    pub fn new(
        task_id: u64,
        agent_id: impl Into<String>,
        node: impl Into<String>,
        module: impl Into<String>,
        command: TaskCommand,
        custom_url: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            task_id,
            agent_id: agent_id.into(),
            node: node.into(),
            module: module.into(),
            command,
            status: TaskStatus::Pending,
            error_message: None,
            custom_url,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Parameters for initiating an upgrade task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeRequest {
    pub node: Option<String>,
    pub module: Option<String>,
    pub agents: Vec<String>,
    pub custom_url: Option<String>,
}

/// Response returned to API clients for upgrade dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeResponseItem {
    pub agent_id: String,
    pub task_id: Option<u64>,
    pub status: TaskStatus,
    pub error_message: Option<String>,
}
