use super::parsing::UpgradeResponseItem;
use super::tasks::{AgentInfo, UpgradeAgentStatusTask, UpgradeCustomTask, UpgradeTask};
use super::tasks_callbacks::TaskCallbacks;
use super::upgrades::{send_wpk_to_agent, UpgradeTransport};
use super::validate::{
    build_wpk_file_spec, compare_wazuh_versions, validate_id, validate_status, validate_system,
    validate_version, verify_sha1, UpgradeErrorCode, WM_UPGRADE_NEW_UPGRADE_MECHANISM,
};
use siem_task_manager::TaskStatus;
use std::sync::Arc;

pub struct UpgradeCommander<T: UpgradeTransport> {
    transport: Arc<T>,
    callbacks: Arc<TaskCallbacks>,
    manager_version: String,
    chunk_size: usize,
}

impl<T: UpgradeTransport + 'static> UpgradeCommander<T> {
    pub fn new(
        transport: Arc<T>,
        callbacks: Arc<TaskCallbacks>,
        manager_version: impl Into<String>,
        chunk_size: usize,
    ) -> Self {
        Self {
            transport,
            callbacks,
            manager_version: manager_version.into(),
            chunk_size,
        }
    }

    /// Process standard upgrade command across a fleet of agents
    pub async fn process_upgrade(
        &self,
        agents: &[AgentInfo],
        task: &UpgradeTask,
        wpk_provider: impl Fn(&str) -> Option<(Vec<u8>, String)>,
    ) -> Vec<UpgradeResponseItem> {
        let mut results = Vec::new();

        for agent in agents {
            let agent_id = agent.agent_id;

            // 1. Validate Agent ID
            if let Err(e) = validate_id(agent_id) {
                results.push(UpgradeResponseItem {
                    error: e as u32,
                    message: e.as_str().to_string(),
                    agent: Some(agent_id),
                    task_id: None,
                    status: None,
                });
                continue;
            }

            // 2. Validate Connection Status
            if let Err(e) = validate_status(&agent.connection_status) {
                results.push(UpgradeResponseItem {
                    error: e as u32,
                    message: e.as_str().to_string(),
                    agent: Some(agent_id),
                    task_id: None,
                    status: None,
                });
                continue;
            }

            // 3. Validate Platform & deduce package type
            let package_type = match validate_system(
                &agent.platform,
                agent.major_version.as_deref(),
                agent.minor_version.as_deref(),
                Some(&agent.architecture),
            ) {
                Ok(pkg) => pkg,
                Err(e) => {
                    results.push(UpgradeResponseItem {
                        error: e as u32,
                        message: e.as_str().to_string(),
                        agent: Some(agent_id),
                        task_id: None,
                        status: None,
                    });
                    continue;
                }
            };

            // 4. Validate Version
            let target_version = task
                .custom_version
                .as_deref()
                .unwrap_or(&self.manager_version);

            if let Err(e) = validate_version(
                &agent.wazuh_version,
                &agent.platform,
                target_version,
                &self.manager_version,
                task.force_upgrade,
            ) {
                results.push(UpgradeResponseItem {
                    error: e as u32,
                    message: e.as_str().to_string(),
                    agent: Some(agent_id),
                    task_id: None,
                    status: None,
                });
                continue;
            }

            // 5. Build WPK spec
            let repo = task.wpk_repository.as_deref().unwrap_or("packages.wazuh.com/wpk");
            let (_, wpk_file) = build_wpk_file_spec(
                repo,
                target_version,
                &agent.platform,
                &package_type,
                &agent.architecture,
                agent.major_version.as_deref(),
                agent.minor_version.as_deref(),
            );

            // 6. Fetch WPK data and expected SHA1
            let (wpk_data, expected_sha1) = match wpk_provider(&wpk_file) {
                Some((data, sha1)) => {
                    if !verify_sha1(&data, &sha1) {
                        results.push(UpgradeResponseItem {
                            error: UpgradeErrorCode::WpkSha1DoesNotMatch as u32,
                            message: UpgradeErrorCode::WpkSha1DoesNotMatch.as_str().to_string(),
                            agent: Some(agent_id),
                            task_id: None,
                            status: None,
                        });
                        continue;
                    }
                    (data, sha1)
                }
                None => {
                    results.push(UpgradeResponseItem {
                        error: UpgradeErrorCode::WpkFileDoesNotExist as u32,
                        message: UpgradeErrorCode::WpkFileDoesNotExist.as_str().to_string(),
                        agent: Some(agent_id),
                        task_id: None,
                        status: None,
                    });
                    continue;
                }
            };

            // 7. Register task in TaskManager
            let task_items = self.callbacks.create_tasks(&[agent_id], "agent_upgrade", None);
            let task_id = task_items.first().and_then(|t| t.task_id);

            if let Some(first_res) = task_items.into_iter().next() {
                if first_res.error != 0 {
                    results.push(first_res);
                    continue;
                }
            }

            // 8. Update task status to InProgress
            self.callbacks.update_status(agent_id, TaskStatus::InProgress, None);

            // 9. Dispatch Upgrade stream
            let installer = if agent.platform.eq_ignore_ascii_case("windows") {
                "upgrade.bat"
            } else {
                "upgrade.sh"
            };

            let stream_result = send_wpk_to_agent(
                self.transport.as_ref(),
                agent,
                &wpk_file,
                &wpk_data,
                &expected_sha1,
                installer,
                self.chunk_size,
            )
            .await;

            match stream_result {
                Ok(()) => {
                    // Check if legacy mechanism
                    let is_legacy = compare_wazuh_versions(
                        target_version,
                        WM_UPGRADE_NEW_UPGRADE_MECHANISM,
                    ) == std::cmp::Ordering::Less;

                    if is_legacy {
                        self.callbacks.update_status(agent_id, TaskStatus::Legacy, None);
                    }

                    results.push(UpgradeResponseItem {
                        error: UpgradeErrorCode::Success as u32,
                        message: "Success".to_string(),
                        agent: Some(agent_id),
                        task_id,
                        status: Some(if is_legacy { "Legacy" } else { "In progress" }.to_string()),
                    });
                }
                Err(err_code) => {
                    self.callbacks.update_status(
                        agent_id,
                        TaskStatus::Failed,
                        Some(err_code.as_str()),
                    );

                    results.push(UpgradeResponseItem {
                        error: err_code as u32,
                        message: err_code.as_str().to_string(),
                        agent: Some(agent_id),
                        task_id,
                        status: Some("Failed".to_string()),
                    });
                }
            }
        }

        results
    }

    /// Process custom upgrade command
    pub async fn process_upgrade_custom(
        &self,
        agents: &[AgentInfo],
        custom_task: &UpgradeCustomTask,
        custom_package_data: &[u8],
        expected_sha1: &str,
    ) -> Vec<UpgradeResponseItem> {
        let mut results = Vec::new();

        for agent in agents {
            let agent_id = agent.agent_id;

            if let Err(e) = validate_id(agent_id) {
                results.push(UpgradeResponseItem {
                    error: e as u32,
                    message: e.as_str().to_string(),
                    agent: Some(agent_id),
                    task_id: None,
                    status: None,
                });
                continue;
            }

            if let Err(e) = validate_status(&agent.connection_status) {
                results.push(UpgradeResponseItem {
                    error: e as u32,
                    message: e.as_str().to_string(),
                    agent: Some(agent_id),
                    task_id: None,
                    status: None,
                });
                continue;
            }

            let task_items = self.callbacks.create_tasks(&[agent_id], "agent_upgrade_custom", None);
            let task_id = task_items.first().and_then(|t| t.task_id);

            self.callbacks.update_status(agent_id, TaskStatus::InProgress, None);

            let installer = custom_task
                .custom_installer
                .as_deref()
                .unwrap_or(if agent.platform.eq_ignore_ascii_case("windows") {
                    "upgrade.bat"
                } else {
                    "upgrade.sh"
                });

            let file_name = std::path::Path::new(&custom_task.custom_file_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("custom_upgrade.wpk");

            match send_wpk_to_agent(
                self.transport.as_ref(),
                agent,
                file_name,
                custom_package_data,
                expected_sha1,
                installer,
                self.chunk_size,
            )
            .await
            {
                Ok(()) => {
                    results.push(UpgradeResponseItem {
                        error: UpgradeErrorCode::Success as u32,
                        message: "Success".to_string(),
                        agent: Some(agent_id),
                        task_id,
                        status: Some("In progress".to_string()),
                    });
                }
                Err(e) => {
                    self.callbacks.update_status(agent_id, TaskStatus::Failed, Some(e.as_str()));
                    results.push(UpgradeResponseItem {
                        error: e as u32,
                        message: e.as_str().to_string(),
                        agent: Some(agent_id),
                        task_id,
                        status: Some("Failed".to_string()),
                    });
                }
            }
        }

        results
    }

    /// Process agent result command (acknowledgement from agent)
    pub fn process_agent_result(&self, agent_id: u32, status_task: &UpgradeAgentStatusTask) -> UpgradeResponseItem {
        let status = TaskStatus::from_str_loose(&status_task.status);
        let error_msg = status_task.message.as_deref();

        self.callbacks.update_status(agent_id, status, error_msg);

        UpgradeResponseItem {
            error: status_task.error_code,
            message: status_task
                .message
                .clone()
                .unwrap_or_else(|| "Success".to_string()),
            agent: Some(agent_id),
            task_id: None,
            status: Some(status.to_string()),
        }
    }

    /// Process query status result
    pub fn process_upgrade_result(&self, agent_id: u32) -> Option<UpgradeResponseItem> {
        self.callbacks.get_status(agent_id)
    }

    /// Cancels all pending tasks
    pub fn cancel_pending_upgrades(&self) -> usize {
        self.callbacks.cancel_pending_tasks()
    }
}
