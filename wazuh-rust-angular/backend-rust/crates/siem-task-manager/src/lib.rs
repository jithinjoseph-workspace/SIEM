pub mod commands;
pub mod reaper;
pub mod task_model;
pub mod task_store;

pub use commands::TaskManager;
pub use reaper::TaskReaper;
pub use task_model::{
    TaskCommand, TaskErrorCode, TaskRecord, TaskStatus, UpgradeRequest, UpgradeResponseItem,
};
pub use task_store::TaskStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_manager_upgrade_dispatch() {
        let manager = TaskManager::new();

        let req = UpgradeRequest {
            node: Some("master-node".to_string()),
            module: Some("api".to_string()),
            agents: vec!["001".to_string(), "002".to_string(), "003".to_string()],
            custom_url: None,
        };

        let responses = manager.upgrade(req);
        assert_eq!(responses.len(), 3);
        for res in &responses {
            assert!(res.task_id.is_some());
            assert_eq!(res.status, TaskStatus::Pending);
            assert!(res.error_message.is_none());
        }

        // Verify task IDs are sequential and distinct
        let id1 = responses[0].task_id.unwrap();
        let id2 = responses[1].task_id.unwrap();
        let id3 = responses[2].task_id.unwrap();
        assert_eq!(id2, id1 + 1);
        assert_eq!(id3, id2 + 1);
    }

    #[test]
    fn test_duplicate_upgrade_prevention() {
        let manager = TaskManager::new();

        let req = UpgradeRequest {
            node: None,
            module: None,
            agents: vec!["005".to_string()],
            custom_url: None,
        };

        // First upgrade succeeds
        let res1 = manager.upgrade(req.clone());
        assert_eq!(res1[0].status, TaskStatus::Pending);

        // Second upgrade while pending is rejected
        let res2 = manager.upgrade(req);
        assert!(res2[0].error_message.is_some());
        assert_eq!(
            res2[0].error_message.as_deref(),
            Some("An upgrade task is already in progress for this agent")
        );
    }

    #[test]
    fn test_task_status_lifecycle_and_result() {
        let manager = TaskManager::new();

        let req = UpgradeRequest {
            node: None,
            module: None,
            agents: vec!["007".to_string()],
            custom_url: None,
        };

        let dispatched = manager.upgrade(req);
        let task_id = dispatched[0].task_id.unwrap();

        // 1. Initial status is Pending
        let status1 = manager.upgrade_get_status(&["007".to_string()]);
        assert_eq!(status1[0].status, TaskStatus::Pending);

        // 2. Agent receives task -> transitions to InProgress
        assert!(manager.upgrade_update_status("007", TaskStatus::InProgress, None));
        let status2 = manager.upgrade_get_status(&["007".to_string()]);
        assert_eq!(status2[0].status, TaskStatus::InProgress);

        // 3. Agent finishes upgrade -> transitions to Done
        assert!(manager.upgrade_update_status("007", TaskStatus::Done, None));
        let results = manager.upgrade_result(&["007".to_string()]);
        assert_eq!(results[0].status, TaskStatus::Done);

        // Verify final record in store
        let stored = manager.store().get_task(task_id).unwrap();
        assert_eq!(stored.status, TaskStatus::Done);
    }

    #[test]
    fn test_task_cancellation() {
        let manager = TaskManager::new();

        let req = UpgradeRequest {
            node: Some("worker-1".to_string()),
            module: None,
            agents: vec!["010".to_string(), "011".to_string()],
            custom_url: None,
        };
        manager.upgrade(req);

        // Cancel all pending tasks for worker-1
        let cancelled = manager.upgrade_cancel_tasks(Some("worker-1"), None);
        assert_eq!(cancelled, 2);

        // Verify status is Cancelled
        let status = manager.upgrade_get_status(&["010".to_string(), "011".to_string()]);
        assert_eq!(status[0].status, TaskStatus::Cancelled);
        assert_eq!(status[1].status, TaskStatus::Cancelled);
    }

    #[test]
    fn test_task_reaper_timeout() {
        let manager = TaskManager::new();

        let req = UpgradeRequest {
            node: None,
            module: None,
            agents: vec!["020".to_string()],
            custom_url: None,
        };
        manager.upgrade(req);
        manager.upgrade_update_status("020", TaskStatus::InProgress, None);

        // Configure reaper with 0 second timeout threshold to simulate expiration
        let reaper = TaskReaper::with_custom_intervals(
            manager.store(),
            1,
            -1, // any task in progress is expired
            10,
            604800,
        );

        let timed_out = reaper.check_timeouts();
        assert_eq!(timed_out, 1);

        let status = manager.upgrade_get_status(&["020".to_string()]);
        assert_eq!(status[0].status, TaskStatus::Timeout);
    }

    #[test]
    fn test_custom_upgrade_url() {
        let manager = TaskManager::new();

        let req = UpgradeRequest {
            node: None,
            module: None,
            agents: vec!["030".to_string()],
            custom_url: Some("https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.7-1_amd64.deb".to_string()),
        };

        let res = manager.upgrade_custom(req);
        let task_id = res[0].task_id.unwrap();

        let stored = manager.store().get_task(task_id).unwrap();
        assert_eq!(stored.command, TaskCommand::UpgradeCustom);
        assert_eq!(
            stored.custom_url.as_deref(),
            Some("https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.7-1_amd64.deb")
        );
    }
}
