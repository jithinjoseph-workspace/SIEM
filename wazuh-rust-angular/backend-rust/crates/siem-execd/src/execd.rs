//! Wazuh Active Response Daemon Core Runtime (`src/os_execd/execd.c`)
//!
//! Handles active response message parsing, execution orchestration, timeout scheduling,
//! and graceful termination cleanup.

use crate::config::{CommandCatalog, ExecdConfig};
use crate::executor::{derive_rkey, execute_ar_action};
use crate::timeout::TimeoutManager;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

fn get_current_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The Active Response Execution Engine.
pub struct ActiveResponseEngine {
    pub config: ExecdConfig,
    pub catalog: CommandCatalog,
    pub timeout_manager: TimeoutManager,
}

impl ActiveResponseEngine {
    pub fn new(config: ExecdConfig, catalog: CommandCatalog) -> Self {
        let repeated_table = config.repeated_offenders.clone();
        Self {
            config,
            catalog,
            timeout_manager: TimeoutManager::new(repeated_table),
        }
    }

    /// Processes an incoming active response message matching `ExecdRun` in `execd.c`.
    /// Returns the executed command name and action performed ("continue", "abort", "restart", or "disabled").
    pub fn process_message(&mut self, exec_msg: &str) -> Result<String, String> {
        if self.config.disabled {
            info!("Active response is disabled. Skipping message.");
            return Ok("disabled".to_string());
        }

        let mut json_root: serde_json::Value = serde_json::from_str(exec_msg)
            .map_err(|e| format!("Invalid JSON in active response message: {}", e))?;

        let command_name = json_root
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing 'command' field in active response message".to_string())?
            .to_string();

        if command_name == "restart-wazuh" {
            info!("Received restart-wazuh command.");
            crate::wcom::wcom_restart();
            return Ok("restart".to_string());
        }

        // Lookup command path and timeout
        let (cmd_path, base_timeout) = self
            .catalog
            .get_command(&command_name)
            .ok_or_else(|| format!("Command '{}' not found in active response catalog", command_name))?;

        let curr_time = get_current_epoch();

        // Extract alert keys for deduplication
        let mut alert_keys = Vec::new();
        if let Some(params) = json_root.get("parameters") {
            if let Some(alert) = params.get("alert") {
                if let Some(data) = alert.get("data") {
                    if let Some(srcip) = data.get("srcip").and_then(|v| v.as_str()) {
                        alert_keys.push(srcip);
                    }
                }
            }
        }

        let rkey = derive_rkey(&cmd_path, &alert_keys);

        // Prepare "add" parameters
        if let Some(obj) = json_root.as_object_mut() {
            obj.insert("command".to_string(), serde_json::json!("add"));
            if let Some(origin) = obj.get_mut("origin").and_then(|v| v.as_object_mut()) {
                origin.insert("module".to_string(), serde_json::json!("wazuh-execd"));
            }
            if let Some(parameters) = obj.get_mut("parameters").and_then(|v| v.as_object_mut()) {
                parameters.insert("program".to_string(), serde_json::json!(&cmd_path));
            }
        }

        let mut added_before = false;

        if base_timeout > 0 {
            // Prepare "delete" parameters for timeout queue
            let mut delete_json = json_root.clone();
            if let Some(obj) = delete_json.as_object_mut() {
                obj.insert("command".to_string(), serde_json::json!("delete"));
            }
            let delete_str = delete_json.to_string();

            let (dup, effective_timeout) = self.timeout_manager.add_or_update(
                cmd_path.clone(),
                delete_str,
                rkey.clone(),
                base_timeout,
                curr_time,
            );
            added_before = dup;
            debug!(
                "Active response '{}' (key: '{}') scheduled with timeout {}s (duplicate={})",
                command_name, rkey, effective_timeout, added_before
            );
        }

        let final_action = if !added_before {
            // Continue command
            if let Some(obj) = json_root.as_object_mut() {
                obj.insert("command".to_string(), serde_json::json!("continue"));
            }
            "continue"
        } else {
            // Abort command
            if let Some(obj) = json_root.as_object_mut() {
                obj.insert("command".to_string(), serde_json::json!("abort"));
            }
            "abort"
        };

        debug!("Active response action completed: {}", final_action);
        Ok(final_action.to_string())
    }

    /// Checks for and executes expired active responses matching `ExecdTimeoutRun`.
    pub fn check_timeouts(&mut self) -> usize {
        let curr_time = get_current_epoch();
        let expired = self.timeout_manager.drain_expired(curr_time);
        let count = expired.len();

        for entry in expired {
            debug!("Executing timeout deletion for active response '{}'", entry.rkey);
            if let Ok(params_json) = serde_json::from_str(&entry.parameters) {
                let _ = execute_ar_action(&entry.command, &params_json);
            }
        }

        count
    }

    /// Reverts all pending active responses on shutdown matching `ExecdShutdown`.
    pub fn shutdown(&mut self) -> usize {
        info!("Executing active response shutdown cleanup...");
        let pending = self.timeout_manager.drain_all();
        let count = pending.len();

        for entry in pending {
            debug!("Removing pending AR on shutdown: '{}'", entry.rkey);
            if let Ok(params_json) = serde_json::from_str(&entry.parameters) {
                let _ = execute_ar_action(&entry.command, &params_json);
            }
        }

        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_process_message_flow() {
        let mut catalog = CommandCatalog::new(PathBuf::from("/var/ossec/active-response/bin"));
        catalog.parse_config("firewall-drop - firewall-drop.sh - 60\nhost-deny - host-deny.sh - 0\n");

        let config = ExecdConfig {
            disabled: false,
            repeated_offenders: vec![5, 10],
            request_timeout: 0,
            max_restart_lock: 0,
        };

        let mut engine = ActiveResponseEngine::new(config, catalog);

        let msg = r#"{
            "version": 1,
            "origin": {"name": "", "module": "analysisd"},
            "command": "firewall-drop",
            "parameters": {
                "extra_args": [],
                "alert": {
                    "rule": {"id": "5715"},
                    "data": {"srcip": "192.168.1.100"}
                }
            }
        }"#;

        // First execution -> "continue"
        let res = engine.process_message(msg).unwrap();
        assert_eq!(res, "continue");
        assert_eq!(engine.timeout_manager.len(), 1);

        // Immediate duplicate execution -> "abort"
        let res2 = engine.process_message(msg).unwrap();
        assert_eq!(res2, "abort");
        assert_eq!(engine.timeout_manager.len(), 1);

        // Test shutdown drains all
        let reverted = engine.shutdown();
        assert_eq!(reverted, 1);
        assert_eq!(engine.timeout_manager.len(), 0);
    }
}
