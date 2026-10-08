use crate::task_model::{
    TaskCommand, TaskStatus, UpgradeRequest, UpgradeResponseItem,
};
use crate::task_store::TaskStore;
use std::sync::Arc;

/// Task Manager engine ported from Wazuh wm_task_manager_commands.c.
pub struct TaskManager {
    store: Arc<TaskStore>,
    default_node: String,
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskManager {
    pub fn new() -> Self {
        Self {
            store: Arc::new(TaskStore::new()),
            default_node: "master".to_string(),
        }
    }

    pub fn with_store(store: Arc<TaskStore>) -> Self {
        Self {
            store,
            default_node: "master".to_string(),
        }
    }

    pub fn store(&self) -> Arc<TaskStore> {
        self.store.clone()
    }

    /// Process WM_TASK_UPGRADE command:
    /// Schedules remote binary upgrades for the specified agents.
    pub fn upgrade(&self, req: UpgradeRequest) -> Vec<UpgradeResponseItem> {
        let node = req.node.unwrap_or_else(|| self.default_node.clone());
        let module = req.module.unwrap_or_else(|| "api".to_string());

        let mut results = Vec::new();
        for agent_id in req.agents {
            // Check if agent already has an in-progress or pending upgrade task
            let last_task = self.store.get_last_agent_task(&agent_id);
            if let Some(task) = last_task {
                if task.status == TaskStatus::Pending || task.status == TaskStatus::InProgress {
                    results.push(UpgradeResponseItem {
                        agent_id: agent_id.clone(),
                        task_id: Some(task.task_id),
                        status: task.status,
                        error_message: Some("An upgrade task is already in progress for this agent".to_string()),
                    });
                    continue;
                }
            }

            // Create new upgrade task
            let task_id = self.store.create_task(
                agent_id.clone(),
                node.clone(),
                module.clone(),
                TaskCommand::Upgrade,
                None,
            );

            results.push(UpgradeResponseItem {
                agent_id,
                task_id: Some(task_id),
                status: TaskStatus::Pending,
                error_message: None,
            });
        }

        results
    }

    /// Process WM_TASK_UPGRADE_CUSTOM command:
    /// Schedules upgrade using custom repository or download URL.
    pub fn upgrade_custom(&self, req: UpgradeRequest) -> Vec<UpgradeResponseItem> {
        let node = req.node.unwrap_or_else(|| self.default_node.clone());
        let module = req.module.unwrap_or_else(|| "api".to_string());
        let custom_url = req.custom_url.clone();

        let mut results = Vec::new();
        for agent_id in req.agents {
            let last_task = self.store.get_last_agent_task(&agent_id);
            if let Some(task) = last_task {
                if task.status == TaskStatus::Pending || task.status == TaskStatus::InProgress {
                    results.push(UpgradeResponseItem {
                        agent_id: agent_id.clone(),
                        task_id: Some(task.task_id),
                        status: task.status,
                        error_message: Some("An upgrade task is already in progress for this agent".to_string()),
                    });
                    continue;
                }
            }

            let task_id = self.store.create_task(
                agent_id.clone(),
                node.clone(),
                module.clone(),
                TaskCommand::UpgradeCustom,
                custom_url.clone(),
            );

            results.push(UpgradeResponseItem {
                agent_id,
                task_id: Some(task_id),
                status: TaskStatus::Pending,
                error_message: None,
            });
        }

        results
    }

    /// Process WM_TASK_UPGRADE_GET_STATUS command:
    /// Queries the current status of the latest task for each requested agent.
    pub fn upgrade_get_status(&self, agent_ids: &[String]) -> Vec<UpgradeResponseItem> {
        let mut results = Vec::new();

        for agent_id in agent_ids {
            if let Some(task) = self.store.get_last_agent_task(agent_id) {
                results.push(UpgradeResponseItem {
                    agent_id: agent_id.clone(),
                    task_id: Some(task.task_id),
                    status: task.status,
                    error_message: task.error_message,
                });
            } else {
                results.push(UpgradeResponseItem {
                    agent_id: agent_id.clone(),
                    task_id: None,
                    status: TaskStatus::Pending,
                    error_message: Some("No tasks found for agent".to_string()),
                });
            }
        }

        results
    }

    /// Process WM_TASK_UPGRADE_UPDATE_STATUS command:
    /// Updates the state of an agent's upgrade task (e.g. from agent side).
    pub fn upgrade_update_status(
        &self,
        agent_id: &str,
        new_status: TaskStatus,
        error_message: Option<String>,
    ) -> bool {
        if let Some(task) = self.store.get_last_agent_task(agent_id) {
            self.store.update_status(task.task_id, new_status, error_message)
        } else {
            false
        }
    }

    /// Process WM_TASK_UPGRADE_RESULT command:
    /// Retrieves the terminal outcome of an agent's upgrade.
    pub fn upgrade_result(&self, agent_ids: &[String]) -> Vec<UpgradeResponseItem> {
        let mut results = Vec::new();

        for agent_id in agent_ids {
            if let Some(task) = self.store.get_last_agent_task(agent_id) {
                results.push(UpgradeResponseItem {
                    agent_id: agent_id.clone(),
                    task_id: Some(task.task_id),
                    status: task.status,
                    error_message: task.error_message,
                });
            } else {
                results.push(UpgradeResponseItem {
                    agent_id: agent_id.clone(),
                    task_id: None,
                    status: TaskStatus::Pending,
                    error_message: Some("No task history for agent".to_string()),
                });
            }
        }

        results
    }

    /// Process WM_TASK_UPGRADE_CANCEL_TASKS command:
    /// Cancels queued pending tasks for a given node or agent.
    pub fn upgrade_cancel_tasks(&self, node: Option<&str>, agent_id: Option<&str>) -> usize {
        self.store.cancel_pending_tasks(node, agent_id)
    }
}
