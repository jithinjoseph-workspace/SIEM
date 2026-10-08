use crate::buffer::AgentBuffer;
use siem_core::{EventSource, RawEvent};
use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

pub struct RegistryMonitor {
    agent_id: String,
    monitored_keys: Vec<String>,
    baseline: HashMap<String, HashMap<String, String>>, // Key -> (ValueName -> ValueData)
}

impl RegistryMonitor {
    pub fn new(agent_id: String) -> Self {
        // High-value persistence and security-critical registry paths from Wazuh ossec.conf
        let default_keys = vec![
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce".to_string(),
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx".to_string(),
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce".to_string(),
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon".to_string(),
            r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows".to_string(), // AppInit_DLLs
            r"HKLM\Software\Microsoft\Active Setup\Installed Components".to_string(),
            r"HKLM\System\CurrentControlSet\Control\Session Manager\KnownDLLs".to_string(),
            r"HKLM\System\CurrentControlSet\Control\SecurePipeServers\winreg".to_string(),
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System".to_string(),
            r"HKLM\Software\Policies\Microsoft\Windows Defender".to_string(),
            r"HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters".to_string(),
            r"HKLM\Software\Classes\batfile\shell\open\command".to_string(),
            r"HKLM\Software\Classes\cmdfile\shell\open\command".to_string(),
            r"HKLM\Software\Classes\exefile\shell\open\command".to_string(),
        ];

        Self {
            agent_id,
            monitored_keys: default_keys,
            baseline: HashMap::new(),
        }
    }

    /// Query registry key entries via Windows `reg query`
    fn query_key(&self, key: &str) -> HashMap<String, String> {
        let mut values = HashMap::new();

        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = Command::new("reg").args(["query", key]).output() {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with("HKEY_") {
                            continue;
                        }
                        // Format: <ValueName>    <REG_TYPE>    <ValueData>
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 3 {
                            let name = parts[0].to_string();
                            let data = parts[2..].join(" ");
                            values.insert(name, data);
                        } else if parts.len() == 2 {
                            values.insert(parts[0].to_string(), parts[1].to_string());
                        }
                    }
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Simulated baseline for cross-platform dev
            if key.contains("Run") {
                values.insert("SecurityHealth".into(), "%ProgramFiles%\\Windows Defender\\MSASCuiL.exe".into());
            }
        }

        values
    }

    /// Initial snapshot of all monitored keys
    pub fn build_baseline(&mut self) {
        for key in &self.monitored_keys {
            let current = self.query_key(key);
            self.baseline.insert(key.clone(), current);
        }
        info!(
            "Windows Registry Monitor: Baseline initialized for {} critical hives",
            self.monitored_keys.len()
        );
    }

    /// Scan registry keys and report added, modified, or deleted persistence entries
    pub async fn check_registry(&mut self, buffer: &AgentBuffer) {
        let keys = self.monitored_keys.clone();

        for key in keys {
            let current_vals = self.query_key(&key);
            let prev_vals = self.baseline.entry(key.clone()).or_default();

            // 1. Detect New Entries (Persistence Mechanism, MITRE T1547.001)
            for (name, val) in &current_vals {
                if !prev_vals.contains_key(name) {
                    let msg = format!(
                        "registry: NEW entry added in '{}': Value='{}' Data='{}'",
                        key, name, val
                    );
                    warn!("{}", msg);

                    let mut event = RawEvent::new(&self.agent_id, EventSource::Registry, &key, msg);
                    event.metadata.insert("action".into(), "added".into());
                    event.metadata.insert("key".into(), key.clone());
                    event.metadata.insert("value_name".into(), name.clone());
                    event.metadata.insert("value_data".into(), val.clone());
                    event.metadata.insert("mitre_tactic".into(), "Persistence".into());
                    event.metadata.insert("mitre_technique".into(), "T1547.001".into());
                    buffer.push(event).await;
                } else if prev_vals.get(name) != Some(val) {
                    // 2. Detect Modified Entries
                    let old_val = prev_vals.get(name).cloned().unwrap_or_default();
                    let msg = format!(
                        "registry: Entry MODIFIED in '{}': Value='{}' Old='{}' New='{}'",
                        key, name, old_val, val
                    );
                    warn!("{}", msg);

                    let mut event = RawEvent::new(&self.agent_id, EventSource::Registry, &key, msg);
                    event.metadata.insert("action".into(), "modified".into());
                    event.metadata.insert("key".into(), key.clone());
                    event.metadata.insert("value_name".into(), name.clone());
                    event.metadata.insert("old_data".into(), old_val);
                    event.metadata.insert("new_data".into(), val.clone());
                    buffer.push(event).await;
                }
            }

            // 3. Detect Deleted Entries
            for (name, val) in prev_vals.iter() {
                if !current_vals.contains_key(name) {
                    let msg = format!(
                        "registry: Entry DELETED in '{}': Value='{}' Data='{}'",
                        key, name, val
                    );
                    info!("{}", msg);

                    let mut event = RawEvent::new(&self.agent_id, EventSource::Registry, &key, msg);
                    event.metadata.insert("action".into(), "deleted".into());
                    event.metadata.insert("key".into(), key.clone());
                    event.metadata.insert("value_name".into(), name.clone());
                    buffer.push(event).await;
                }
            }

            *prev_vals = current_vals;
        }
    }
}

pub fn spawn_registry_worker(
    agent_id: String,
    buffer: Arc<AgentBuffer>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut monitor = RegistryMonitor::new(agent_id);
        monitor.build_baseline();

        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            debug!("Registry: Scanning monitored keys for persistence changes...");
            monitor.check_registry(&buffer).await;
        }
    })
}
