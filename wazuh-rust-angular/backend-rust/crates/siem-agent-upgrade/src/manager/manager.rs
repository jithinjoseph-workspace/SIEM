use super::commands::UpgradeCommander;
use super::tasks_callbacks::TaskCallbacks;
use super::upgrades::UpgradeTransport;
use crate::config::ManagerConfigs;
use siem_task_manager::TaskManager;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::info;

pub struct AgentUpgradeManager<T: UpgradeTransport> {
    pub config: ManagerConfigs,
    pub commander: Arc<UpgradeCommander<T>>,
    pub concurrency_limiter: Arc<Semaphore>,
}

impl<T: UpgradeTransport + 'static> AgentUpgradeManager<T> {
    pub fn new(
        config: ManagerConfigs,
        transport: Arc<T>,
        task_manager: Arc<TaskManager>,
        manager_version: impl Into<String>,
    ) -> Self {
        let callbacks = Arc::new(TaskCallbacks::new(task_manager));
        let commander = Arc::new(UpgradeCommander::new(
            transport,
            callbacks,
            manager_version,
            config.chunk_size,
        ));
        let concurrency_limiter = Arc::new(Semaphore::new(config.max_threads));

        info!(
            "AgentUpgradeManager initialized with max_threads={}, chunk_size={}",
            config.max_threads, config.chunk_size
        );

        Self {
            config,
            commander,
            concurrency_limiter,
        }
    }
}
