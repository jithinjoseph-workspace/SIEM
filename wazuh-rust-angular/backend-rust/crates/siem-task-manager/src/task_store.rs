use crate::task_model::{TaskCommand, TaskRecord, TaskStatus};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// In-memory and persistent concurrent store for agent tasks.
/// Ported from Wazuh wm_task_manager_tasks.c & wm_task_manager_commands.c.
pub struct TaskStore {
    tasks: RwLock<HashMap<u64, TaskRecord>>,
    agent_tasks: RwLock<HashMap<String, Vec<u64>>>,
    next_task_id: AtomicU64,
}

impl Default for TaskStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskStore {
    pub fn new() -> Self {
        Self {
            tasks: RwLock::new(HashMap::new()),
            agent_tasks: RwLock::new(HashMap::new()),
            next_task_id: AtomicU64::new(1),
        }
    }

    /// Create a new task and return the generated task ID.
    pub fn create_task(
        &self,
        agent_id: impl Into<String>,
        node: impl Into<String>,
        module: impl Into<String>,
        command: TaskCommand,
        custom_url: Option<String>,
    ) -> u64 {
        let task_id = self.next_task_id.fetch_add(1, Ordering::SeqCst);
        let agent = agent_id.into();
        let record = TaskRecord::new(
            task_id,
            agent.clone(),
            node,
            module,
            command,
            custom_url,
        );

        let mut tasks_lock = self.tasks.write().unwrap();
        tasks_lock.insert(task_id, record);

        let mut agent_lock = self.agent_tasks.write().unwrap();
        agent_lock.entry(agent).or_default().push(task_id);

        task_id
    }

    /// Retrieve a task by its unique ID.
    pub fn get_task(&self, task_id: u64) -> Option<TaskRecord> {
        let lock = self.tasks.read().unwrap();
        lock.get(&task_id).cloned()
    }

    /// Retrieve all tasks for a specific agent.
    pub fn get_agent_tasks(&self, agent_id: &str) -> Vec<TaskRecord> {
        let agent_lock = self.agent_tasks.read().unwrap();
        let tasks_lock = self.tasks.read().unwrap();

        if let Some(ids) = agent_lock.get(agent_id) {
            ids.iter()
                .filter_map(|id| tasks_lock.get(id).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Retrieve the most recent task for an agent.
    pub fn get_last_agent_task(&self, agent_id: &str) -> Option<TaskRecord> {
        let agent_lock = self.agent_tasks.read().unwrap();
        let tasks_lock = self.tasks.read().unwrap();

        if let Some(ids) = agent_lock.get(agent_id) {
            ids.last().and_then(|id| tasks_lock.get(id).cloned())
        } else {
            None
        }
    }

    /// Update the status and optional error message of a task.
    pub fn update_status(
        &self,
        task_id: u64,
        new_status: TaskStatus,
        error_message: Option<String>,
    ) -> bool {
        let mut lock = self.tasks.write().unwrap();
        if let Some(task) = lock.get_mut(&task_id) {
            task.status = new_status;
            task.updated_at = Utc::now();
            if let Some(err) = error_message {
                task.error_message = Some(err);
            }
            true
        } else {
            false
        }
    }

    /// Cancel all pending tasks for a given cluster node or specific agent.
    pub fn cancel_pending_tasks(
        &self,
        node_filter: Option<&str>,
        agent_filter: Option<&str>,
    ) -> usize {
        let mut count = 0;
        let mut lock = self.tasks.write().unwrap();

        for task in lock.values_mut() {
            if task.status == TaskStatus::Pending {
                let node_matches = node_filter.map_or(true, |n| task.node == n);
                let agent_matches = agent_filter.map_or(true, |a| task.agent_id == a);

                if node_matches && agent_matches {
                    task.status = TaskStatus::Cancelled;
                    task.updated_at = Utc::now();
                    count += 1;
                }
            }
        }

        count
    }

    /// Timeout tasks that have been in Progress longer than max_seconds (Wazuh default: 900s = 15m).
    pub fn timeout_expired_tasks(&self, max_in_progress_seconds: i64) -> usize {
        let mut count = 0;
        let now = Utc::now();
        let threshold = Duration::seconds(max_in_progress_seconds);

        let mut lock = self.tasks.write().unwrap();
        for task in lock.values_mut() {
            if task.status == TaskStatus::InProgress {
                if now.signed_duration_since(task.updated_at) > threshold {
                    task.status = TaskStatus::Timeout;
                    task.error_message = Some("Task exceeded maximum execution time".to_string());
                    task.updated_at = now;
                    count += 1;
                }
            }
        }

        count
    }

    /// Cleanup old completed tasks past the retention period (Wazuh default: 604800s = 7 days).
    pub fn cleanup_old_tasks(&self, max_age_seconds: i64) -> usize {
        let now = Utc::now();
        let threshold = Duration::seconds(max_age_seconds);

        let mut to_remove = Vec::new();
        {
            let lock = self.tasks.read().unwrap();
            for (id, task) in lock.iter() {
                if task.status.is_terminal() && (now.signed_duration_since(task.updated_at) > threshold) {
                    to_remove.push(*id);
                }
            }
        }

        if to_remove.is_empty() {
            return 0;
        }

        let mut tasks_lock = self.tasks.write().unwrap();
        let mut agent_lock = self.agent_tasks.write().unwrap();

        for id in &to_remove {
            if let Some(task) = tasks_lock.remove(id) {
                if let Some(agent_list) = agent_lock.get_mut(&task.agent_id) {
                    agent_list.retain(|existing_id| existing_id != id);
                }
            }
        }

        to_remove.len()
    }

    /// Return total active tasks count.
    pub fn total_tasks(&self) -> usize {
        self.tasks.read().unwrap().len()
    }
}
