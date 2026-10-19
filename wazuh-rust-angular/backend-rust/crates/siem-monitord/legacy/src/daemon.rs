//! Monitord Main Daemon Loop (`src/monitord/monitord.c`)
//!
//! Orchestrates periodic agent keepalive polling, size-based and daily log rotations,
//! cryptographic log signing, report generation, and management IPC.

use crate::config::MonitorConfig;
use crate::generate_reports::generate_report_from_file;
use crate::manage_files::DailyFileManager;
use crate::moncom::moncom_dispatch;
use crate::monitor_actions::AgentMonitorEngine;
use crate::rotate_log::rotate_log_file;
use crate::time_control::MonitorTimeControl;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

pub struct MonitorDaemon {
    pub config: MonitorConfig,
    pub agent_engine: AgentMonitorEngine,
    pub file_manager: DailyFileManager,
    pub time_control: MonitorTimeControl,
    pub base_dir: PathBuf,
    pub log_file: PathBuf,
    pub json_log_file: PathBuf,
    pub running: Arc<AtomicBool>,
}

impl MonitorDaemon {
    pub fn new<P: AsRef<Path>>(config: MonitorConfig, base_dir: P) -> Self {
        let b = base_dir.as_ref().to_path_buf();
        let log_file = b.join("logs/ossec.log");
        let json_log_file = b.join("logs/ossec.json");

        let agent_engine = AgentMonitorEngine::new(
            config.agents_disconnection_time,
            config.agents_disconnection_alert_time,
            config.delete_old_agents,
        );

        let file_manager = DailyFileManager::new(&b, config.compress);
        let time_control = MonitorTimeControl::new();

        Self {
            config,
            agent_engine,
            file_manager,
            time_control,
            base_dir: b,
            log_file,
            json_log_file,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Performs one step of the monitoring loop.
    pub async fn step(&mut self) {
        self.time_control.step_time(
            self.config.monitor_agents,
            self.config.delete_old_agents,
        );

        // 1. Agent Disconnection Trigger
        if self
            .time_control
            .check_disconnection_trigger(self.config.agents_disconnection_time)
        {
            self.agent_engine.check_disconnections().await;
        }

        // 2. Agent Disconnection Alert Trigger
        if self.time_control.check_alert_trigger(
            self.config.monitor_agents,
            self.config.agents_disconnection_alert_time,
        ) {
            self.agent_engine.check_alerts().await;
        }

        // 3. Agent Deletion Trigger
        if self.time_control.check_deletion_trigger(
            self.config.monitor_agents,
            self.config.delete_old_agents,
        ) {
            self.agent_engine.check_deletions().await;
        }

        // 4. Log Rotation Trigger (Day changed or Size reached)
        if self.time_control.check_logs_time_trigger() {
            info!("Day change detected: running daily rotation and report generation...");
            self.run_daily_rotation().await;
            self.time_control.update_date();
        } else {
            self.check_size_rotation().await;
        }
    }

    /// Executes daily rotation, file management, and reporting.
    pub async fn run_daily_rotation(&self) {
        let logs_base = self.base_dir.join("logs/wazuh");

        // Rotate ossec.log and ossec.json
        let _ = rotate_log_file(
            &logs_base,
            &self.log_file,
            false,
            self.config.compress,
            self.config.keep_log_days,
            true,
            self.config.daily_rotations,
        );

        let _ = rotate_log_file(
            &logs_base,
            &self.json_log_file,
            true,
            self.config.compress,
            self.config.keep_log_days,
            true,
            self.config.daily_rotations,
        );

        // Run daily signing and file compression
        if let Err(e) = self.file_manager.manage_daily_files() {
            warn!("Daily file management error: {}", e);
        }

        // Run reports
        for rep in &self.config.reports {
            let alerts_file = self.base_dir.join("logs/alerts/ossec-alerts.log");
            if let Ok(summary) = generate_report_from_file(rep, &alerts_file) {
                info!(
                    "Report '{}' generated: {}/{} alerts matched",
                    summary.title, summary.matched_alerts, summary.total_alerts_processed
                );
            }
        }
    }

    /// Checks if active log files exceeded `size_rotate`.
    pub async fn check_size_rotation(&self) {
        if !self.config.rotate_log || self.config.size_rotate == 0 {
            return;
        }

        let logs_base = self.base_dir.join("logs/wazuh");

        if let Ok(meta) = fs::metadata(&self.log_file) {
            if meta.len() >= self.config.size_rotate {
                info!("File {} exceeded size threshold. Rotating...", self.log_file.display());
                let _ = rotate_log_file(
                    &logs_base,
                    &self.log_file,
                    false,
                    self.config.compress,
                    self.config.keep_log_days,
                    false,
                    self.config.daily_rotations,
                );
            }
        }

        if let Ok(meta) = fs::metadata(&self.json_log_file) {
            if meta.len() >= self.config.size_rotate {
                info!("File {} exceeded size threshold. Rotating...", self.json_log_file.display());
                let _ = rotate_log_file(
                    &logs_base,
                    &self.json_log_file,
                    true,
                    self.config.compress,
                    self.config.keep_log_days,
                    false,
                    self.config.daily_rotations,
                );
            }
        }
    }

    /// Dispatches IPC control command.
    pub fn handle_ipc(&self, command: &str) -> String {
        moncom_dispatch(command, &self.config)
    }

    /// Runs daemon loop until stopped.
    pub async fn run(&mut self) {
        info!("Monitord daemon started.");
        while self.running.load(Ordering::SeqCst) {
            self.step().await;
            sleep(Duration::from_secs(1)).await;
        }
        info!("Monitord daemon stopped.");
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_daemon_step_lifecycle() {
        let dir = tempdir().unwrap();
        let config = MonitorConfig {
            agents_disconnection_time: 2,
            agents_disconnection_alert_time: 1,
            size_rotate: 100, // Small threshold for test
            ..Default::default()
        };

        let mut daemon = MonitorDaemon::new(config, dir.path());

        // Create large dummy log to trigger size rotation
        fs::create_dir_all(dir.path().join("logs")).unwrap();
        fs::write(&daemon.log_file, vec![b'a'; 150]).unwrap();

        daemon.step().await;

        // Size rotation should have occurred
        assert!(!daemon.log_file.exists());
    }
}
