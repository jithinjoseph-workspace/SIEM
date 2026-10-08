use super::parsing::UpgradeResponseItem;
use super::validate::UpgradeErrorCode;
use siem_task_manager::{TaskManager, TaskStatus, UpgradeRequest};
use std::sync::Arc;

pub struct TaskCallbacks {
    task_manager: Arc<TaskManager>,
}

impl TaskCallbacks {
    pub fn new(task_manager: Arc<TaskManager>) -> Self {
        Self { task_manager }
    }

    /// Dispatches new upgrade tasks to TaskManager
    pub fn create_tasks(&self, agent_ids: &[u32], module: &str, node: Option<&str>) -> Vec<UpgradeResponseItem> {
        let req = UpgradeRequest {
            node: node.map(|s| s.to_string()),
            module: Some(module.to_string()),
            agents: agent_ids.iter().map(|id| format!("{id:03}")).collect(),
            custom_url: None,
        };

        let responses = self.task_manager.upgrade(req);
        responses
            .into_iter()
            .map(|item| {
                let agent_id = item.agent_id.parse::<u32>().ok();
                if let Some(err) = item.error_message {
                    UpgradeResponseItem {
                        error: UpgradeErrorCode::UpgradeAlreadyInProgress as u32,
                        message: err,
                        agent: agent_id,
                        task_id: item.task_id,
                        status: Some(item.status.to_string()),
                    }
                } else {
                    UpgradeResponseItem {
                        error: UpgradeErrorCode::Success as u32,
                        message: "Success".to_string(),
                        agent: agent_id,
                        task_id: item.task_id,
                        status: Some(item.status.to_string()),
                    }
                }
            })
            .collect()
    }

    /// Updates task status in TaskManager
    pub fn update_status(&self, agent_id: u32, status: TaskStatus, error_msg: Option<&str>) -> bool {
        self.task_manager.upgrade_update_status(
            &format!("{agent_id:03}"),
            status,
            error_msg.map(|s| s.to_string()),
        )
    }

    /// Gets latest task status for an agent
    pub fn get_status(&self, agent_id: u32) -> Option<UpgradeResponseItem> {
        let res_list = self.task_manager.upgrade_get_status(&[format!("{agent_id:03}")]);
        res_list.into_iter().next().map(|record| UpgradeResponseItem {
            error: if record.status == TaskStatus::Failed { 1 } else { 0 },
            message: record.error_message.unwrap_or_else(|| "Success".to_string()),
            agent: Some(agent_id),
            task_id: record.task_id,
            status: Some(record.status.to_string()),
        })
    }

    /// Cancels all pending tasks
    pub fn cancel_pending_tasks(&self) -> usize {
        self.task_manager.upgrade_cancel_tasks(None, None)
    }
}
