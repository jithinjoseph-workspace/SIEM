use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentLifecycleState {
    Active,
    Dormant,
    Decommissioned,
}

#[derive(Clone)]
pub struct LifecycleCoordinator {
    agent_id: String,
    manager_url: String,
    is_active: Arc<AtomicBool>,
    is_terminated: Arc<AtomicBool>,
}

impl LifecycleCoordinator {
    pub fn new(agent_id: String, manager_url: String) -> Self {
        Self {
            agent_id,
            manager_url,
            is_active: Arc::new(AtomicBool::new(true)),
            is_terminated: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_active(&self) -> bool {
        self.is_active.load(Ordering::Relaxed) && !self.is_terminated.load(Ordering::Relaxed)
    }

    pub fn is_terminated(&self) -> bool {
        self.is_terminated.load(Ordering::Relaxed)
    }

    pub fn set_state(&self, state: AgentLifecycleState) {
        match state {
            AgentLifecycleState::Active => {
                let was_active = self.is_active.swap(true, Ordering::SeqCst);
                if !was_active {
                    info!("wazuh-agentd: [LIFECYCLE] Agent REACTIVATED by manager. Resuming all monitoring and event transmission.");
                }
            }
            AgentLifecycleState::Dormant => {
                let was_active = self.is_active.swap(false, Ordering::SeqCst);
                if was_active {
                    warn!("wazuh-agentd: [LIFECYCLE] Agent DEACTIVATED by manager. Pausing monitoring workers and event transmission.");
                }
            }
            AgentLifecycleState::Decommissioned => {
                self.is_active.store(false, Ordering::SeqCst);
                self.is_terminated.store(true, Ordering::SeqCst);
                warn!("wazuh-agentd: [LIFECYCLE] Agent DECOMMISSIONED by manager. Archiving keys and executing clean shutdown.");
                self.decommission_local();
            }
        }
    }

    /// Archive client.keys, write decommission marker, and exit with status 42 (preventing systemd restart)
    fn decommission_local(&self) {
        let keys_candidates = [
            std::path::PathBuf::from("/var/ossec/etc/client.keys"),
            std::path::PathBuf::from("/etc/wazuh-agent/client.keys"),
            std::path::PathBuf::from("client.keys"),
        ];

        for path in &keys_candidates {
            if path.exists() {
                let archived = path.with_extension("keys.deleted");
                if let Err(e) = std::fs::rename(path, &archived) {
                    warn!("wazuh-agentd: Failed to archive {}: {}", path.display(), e);
                } else {
                    info!("wazuh-agentd: Archived identity {} -> {}", path.display(), archived.display());
                }
            }
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    let marker = parent.join(".decommissioned");
                    let _ = std::fs::write(&marker, format!("agent_id={}\ndecommissioned_at={}\n", self.agent_id, chrono::Utc::now().to_rfc3339()));
                }
            }
        }
        let _ = std::fs::write(".decommissioned", format!("agent_id={}\ndecommissioned_at={}\n", self.agent_id, chrono::Utc::now().to_rfc3339()));

        // Clean termination sequence with exit code 42 (matching RestartPreventExitStatus=42)
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            #[cfg(unix)]
            {
                let _ = std::process::Command::new("systemctl")
                    .args(["disable", "--now", "wazuh-rust-agent"])
                    .status();
            }
            std::process::exit(42);
        });
    }

    /// Fetch latest state from manager
    pub async fn fetch_state(&self) -> Option<AgentLifecycleState> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .ok()?;
        let url = format!("{}/api/v1/agent/state?agent_id={}", self.manager_url.trim_end_matches('/'), self.agent_id);
        let resp = client.get(&url).send().await.ok()?;
        let body: serde_json::Value = resp.json().await.ok()?;
        match body.get("state").and_then(|v| v.as_str()) {
            Some("deactivated") => Some(AgentLifecycleState::Dormant),
            Some("deleted") => Some(AgentLifecycleState::Decommissioned),
            Some("active") => Some(AgentLifecycleState::Active),
            _ => None,
        }
    }

    /// Spawn background loop polling manager state every 15s
    pub fn spawn_poll_worker(self: Arc<Self>, poll_interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(poll_interval).await;
                if self.is_terminated() {
                    break;
                }
                if let Some(state) = self.fetch_state().await {
                    self.set_state(state);
                }
            }
        })
    }
}

/// Checks if this endpoint was permanently decommissioned
pub fn is_decommissioned() -> bool {
    let markers = [
        "/var/ossec/etc/.decommissioned",
        "/var/ossec/etc/client.keys.deleted",
        "/etc/wazuh-agent/.decommissioned",
        "/etc/wazuh-agent/client.keys.deleted",
        ".decommissioned",
        "client.keys.deleted",
    ];
    markers.iter().any(|p| std::path::Path::new(p).exists())
}
