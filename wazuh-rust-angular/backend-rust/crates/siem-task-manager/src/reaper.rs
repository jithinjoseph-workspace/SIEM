use crate::task_store::TaskStore;
use std::sync::Arc;
use tokio::time::{interval, Duration};

/// Background task reaper ported from Wazuh wm_task_manager.c timeout and cleanup threads.
pub struct TaskReaper {
    store: Arc<TaskStore>,
    timeout_check_interval: Duration,
    max_in_progress_seconds: i64,
    cleanup_check_interval: Duration,
    max_retention_seconds: i64,
}

impl TaskReaper {
    pub fn new(store: Arc<TaskStore>) -> Self {
        Self {
            store,
            timeout_check_interval: Duration::from_secs(10),
            max_in_progress_seconds: 900, // 15 minutes (WM_TASK_MAX_IN_PROGRESS_TIME)
            cleanup_check_interval: Duration::from_secs(86400), // 1 day (WM_TASK_CLEANUP_DB_SLEEP_TIME)
            max_retention_seconds: 604800, // 7 days (WM_TASK_DEFAULT_CLEANUP_TIME)
        }
    }

    pub fn with_custom_intervals(
        store: Arc<TaskStore>,
        timeout_interval_secs: u64,
        max_in_progress_secs: i64,
        cleanup_interval_secs: u64,
        max_retention_secs: i64,
    ) -> Self {
        Self {
            store,
            timeout_check_interval: Duration::from_secs(timeout_interval_secs),
            max_in_progress_seconds: max_in_progress_secs,
            cleanup_check_interval: Duration::from_secs(cleanup_interval_secs),
            max_retention_seconds: max_retention_secs,
        }
    }

    /// Spawns the background monitoring loop in Tokio.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut timeout_timer = interval(self.timeout_check_interval);
            let mut cleanup_timer = interval(self.cleanup_check_interval);

            loop {
                tokio::select! {
                    _ = timeout_timer.tick() => {
                        let timed_out = self.store.timeout_expired_tasks(self.max_in_progress_seconds);
                        if timed_out > 0 {
                            println!("[TaskReaper] Timed out {} stale in-progress tasks", timed_out);
                        }
                    }
                    _ = cleanup_timer.tick() => {
                        let cleaned = self.store.cleanup_old_tasks(self.max_retention_seconds);
                        if cleaned > 0 {
                            println!("[TaskReaper] Purged {} expired task records", cleaned);
                        }
                    }
                }
            }
        })
    }

    /// Run a single timeout check synchronously.
    pub fn check_timeouts(&self) -> usize {
        self.store.timeout_expired_tasks(self.max_in_progress_seconds)
    }

    /// Run a single cleanup check synchronously.
    pub fn check_cleanup(&self) -> usize {
        self.store.cleanup_old_tasks(self.max_retention_seconds)
    }
}
