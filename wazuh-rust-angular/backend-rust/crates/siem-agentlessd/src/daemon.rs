//! Agentlessd Main Scheduling Loop (`src/agentlessd/agentlessd.c`)
//!
//! Evaluates configured periodic checks, manages execution cooldowns,
//! handles error thresholds, and routes generated security events.

use crate::config::{AgentlessConfig, LESSD_STATE_PERIODIC};
use crate::executor::{AgentlessExecutor, ScriptOutputMessage};
use crate::lessdcom::lessdcom_dispatch;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

pub struct AgentlessDaemon {
    pub config: Arc<RwLock<AgentlessConfig>>,
    pub executor: AgentlessExecutor,
    pub base_dir: PathBuf,
    pub event_sink: Arc<RwLock<Vec<ScriptOutputMessage>>>,
    pub running: Arc<AtomicBool>,
}

impl AgentlessDaemon {
    pub fn new<P: AsRef<Path>>(config: AgentlessConfig, base_dir: P) -> Self {
        let b = base_dir.as_ref().to_path_buf();
        let agentless_dir = b.join("agentless");
        let diff_dir = b.join("queue/diff");

        let daemon = Self {
            config: Arc::new(RwLock::new(config)),
            executor: AgentlessExecutor::new(agentless_dir, diff_dir),
            base_dir: b,
            event_sink: Arc::new(RwLock::new(Vec::new())),
            running: Arc::new(AtomicBool::new(true)),
        };

        // Record entries in queue/agentless for control tooling
        daemon.save_all_agentless_entries();
        daemon
    }

    /// Records all configured agentless hosts to `<base_dir>/queue/agentless/(script) host`
    /// (parity with save_agentless_entry in agentlessd.c)
    pub fn save_all_agentless_entries(&self) {
        let entry_dir = self.base_dir.join("queue").join("agentless");
        let _ = std::fs::create_dir_all(&entry_dir);

        if let Ok(cfg) = self.config.try_read() {
            for entry in &cfg.entries {
                for server in &entry.servers {
                    let clean_host = if server.len() > 1 && (server.starts_with('o') || server.starts_with('s')) {
                        &server[1..]
                    } else {
                        server.as_str()
                    };
                    
                    let filename = if cfg!(windows) {
                        format!("_{}_{}", entry.script_type, clean_host.replace(':', "_"))
                    } else {
                        format!("({}) {}", entry.script_type, clean_host)
                    };

                    let file_path = entry_dir.join(filename);
                    let content = format!("type: {}\n", entry.script_type);
                    let _ = std::fs::write(file_path, content);
                }
            }
        }
    }

    /// Performs one step of the scheduling cycle.
    pub async fn step(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut cfg = self.config.write().await;

        for entry in cfg.entries.iter_mut() {
            if entry.error_flag >= 10 {
                if entry.error_flag != 99 {
                    error!("Too many failures for '{}'. Ignoring it.", entry.script_type);
                    entry.error_flag = 99;
                }
                continue;
            }

            // Check if frequency elapsed
            if (entry.state & LESSD_STATE_PERIODIC != 0)
                && (entry.current_state + entry.frequency <= now)
            {
                for server in entry.servers.clone() {
                    match self.executor.run_periodic_check(entry, &server).await {
                        Ok(messages) => {
                            let mut sink = self.event_sink.write().await;
                            for msg in messages {
                                info!(
                                    "Agentless event generated for [{}]: {}",
                                    msg.location, msg.message
                                );
                                sink.push(msg);
                            }
                        }
                        Err(e) => {
                            warn!("Agentless check error on {}: {}", server, e);
                        }
                    }
                }
                entry.current_state = now;
            }
        }
    }

    /// Dispatches IPC command.
    pub async fn handle_ipc(&self, command: &str) -> String {
        let cfg = self.config.read().await;
        lessdcom_dispatch(command, &cfg)
    }

    /// Runs daemon loop until stopped.
    pub async fn run(&self) {
        info!("Agentlessd daemon started.");
        while self.running.load(Ordering::SeqCst) {
            self.step().await;
            sleep(Duration::from_secs(1)).await;
        }
        info!("Agentlessd daemon stopped.");
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentlessEntry;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_daemon_step_empty() {
        let dir = tempdir().unwrap();
        let mut config = AgentlessConfig::default();
        config.entries.push(AgentlessEntry {
            script_type: "test_script".to_string(),
            frequency: 10,
            servers: vec!["host1".to_string()],
            ..Default::default()
        });

        let daemon = AgentlessDaemon::new(config, dir.path());
        daemon.step().await;

        let res = daemon.handle_ipc("getconfig agentless").await;
        assert!(res.contains("test_script"));

        // Verify queue/agentless directory entries created
        let agentless_dir = dir.path().join("queue").join("agentless");
        assert!(agentless_dir.exists());
        let entries: Vec<_> = std::fs::read_dir(agentless_dir).unwrap().flatten().collect();
        assert_eq!(entries.len(), 1);
    }
}
