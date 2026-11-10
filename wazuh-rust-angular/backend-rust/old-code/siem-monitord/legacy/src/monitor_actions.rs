//! Agent Disconnection Detector & Purge Engine (`src/monitord/monitor_actions.c`)
//!
//! Evaluates agent keepalive timestamps, marks inactive agents disconnected,
//! generates disconnection security alerts, and purges permanently abandoned agents.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

pub const AG_DISCON_MSG_HEADER: &str = "1:wazuh-monitord:ossec: Agent disconnected: ";
pub const AG_REMOVED_MSG_HEADER: &str = "1:wazuh-monitord:ossec: Agent removed: ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentStatus {
    Active,
    Disconnected,
}

#[derive(Debug, Clone)]
pub struct MonitoredAgent {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub status: AgentStatus,
    pub last_keepalive: u64,
}

pub struct AgentMonitorEngine {
    pub agents: Arc<RwLock<HashMap<String, MonitoredAgent>>>,
    pub pending_alerts: Arc<RwLock<HashMap<String, u64>>>, // Agent ID -> timestamp disconnected
    pub disconnection_time: u64,
    pub disconnection_alert_time: u64,
    pub delete_old_agents_secs: u64,
    pub alert_sink: Arc<RwLock<Vec<String>>>, // Message queue buffer
}

impl AgentMonitorEngine {
    pub fn new(
        disconnection_time: u64,
        disconnection_alert_time: u64,
        delete_old_agents_min: u32,
    ) -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            pending_alerts: Arc::new(RwLock::new(HashMap::new())),
            disconnection_time,
            disconnection_alert_time,
            delete_old_agents_secs: (delete_old_agents_min as u64) * 60,
            alert_sink: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Updates or registers an agent's last keepalive timestamp.
    pub async fn update_agent_keepalive(&self, id: &str, name: &str, ip: &str, timestamp: u64) {
        let mut agents = self.agents.write().await;
        let entry = agents.entry(id.to_string()).or_insert_with(|| MonitoredAgent {
            id: id.to_string(),
            name: name.to_string(),
            ip: ip.to_string(),
            status: AgentStatus::Active,
            last_keepalive: timestamp,
        });

        entry.status = AgentStatus::Active;
        entry.last_keepalive = timestamp;

        // If it was in pending alerts, remove it since it reconnected
        let mut pending = self.pending_alerts.write().await;
        pending.remove(id);
    }

    /// Evaluates agents for disconnection matching `monitor_agents_disconnection`.
    pub async fn check_disconnections(&self) -> Vec<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut agents = self.agents.write().await;
        let mut pending = self.pending_alerts.write().await;
        let mut newly_disconnected = Vec::new();

        for (id, agent) in agents.iter_mut() {
            if agent.status == AgentStatus::Active {
                let diff = now.saturating_sub(agent.last_keepalive);
                if diff >= self.disconnection_time {
                    agent.status = AgentStatus::Disconnected;
                    pending.insert(id.clone(), now);
                    newly_disconnected.push(id.clone());
                    info!(
                        "Agent '{}' ({}) marked DISCONNECTED (inactive for {}s)",
                        agent.name, id, diff
                    );
                }
            }
        }

        newly_disconnected
    }

    /// Generates alerts for agents that remained disconnected matching `monitor_agents_alert`.
    pub async fn check_alerts(&self) -> Vec<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let agents = self.agents.read().await;
        let mut pending = self.pending_alerts.write().await;
        let mut sink = self.alert_sink.write().await;
        let mut generated_alerts = Vec::new();

        let mut to_remove = Vec::new();

        for (id, _disc_time) in pending.iter() {
            if let Some(agent) = agents.get(id) {
                if agent.status == AgentStatus::Active {
                    to_remove.push(id.clone());
                    continue;
                }

                let diff = now.saturating_sub(agent.last_keepalive);
                if diff >= (self.disconnection_time + self.disconnection_alert_time) {
                    let msg = format!("{}{}-{}", AG_DISCON_MSG_HEADER, agent.name, agent.ip);
                    sink.push(msg.clone());
                    generated_alerts.push(msg);
                    to_remove.push(id.clone());
                    warn!("Generated disconnection alert for agent '{}' ({})", agent.name, id);
                }
            } else {
                to_remove.push(id.clone());
            }
        }

        for id in to_remove {
            pending.remove(&id);
        }

        generated_alerts
    }

    /// Deletes abandoned agents exceeding `delete_old_agents` matching `monitor_agents_deletion`.
    pub async fn check_deletions(&self) -> Vec<String> {
        if self.delete_old_agents_secs == 0 {
            return Vec::new();
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut agents = self.agents.write().await;
        let mut sink = self.alert_sink.write().await;
        let mut deleted_agents = Vec::new();

        let mut to_delete = Vec::new();

        for (id, agent) in agents.iter() {
            if agent.status == AgentStatus::Disconnected {
                let diff = now.saturating_sub(agent.last_keepalive);
                if diff >= (self.disconnection_time + self.delete_old_agents_secs) {
                    let msg = format!("{}{}-{}", AG_REMOVED_MSG_HEADER, agent.name, agent.ip);
                    sink.push(msg.clone());
                    deleted_agents.push(msg);
                    to_delete.push(id.clone());
                    info!(
                        "Agent '{}' ({}) deleted: inactive for {}s (exceeded purge limit)",
                        agent.name, id, diff
                    );
                }
            }
        }

        for id in to_delete {
            agents.remove(&id);
        }

        deleted_agents
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_agent_monitoring_lifecycle() {
        let engine = AgentMonitorEngine::new(10, 5, 1); // 10s discon, 5s alert, 1min delete

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 1. Add active agent
        engine.update_agent_keepalive("001", "node-1", "10.0.0.1", now).await;

        // Immediately check: no disconnections
        assert!(engine.check_disconnections().await.is_empty());

        // 2. Set keepalive to 15 seconds ago
        {
            let mut agents = engine.agents.write().await;
            agents.get_mut("001").unwrap().last_keepalive = now - 15;
        }

        // Check disconnection: should transition to Disconnected
        let disc = engine.check_disconnections().await;
        assert_eq!(disc, vec!["001"]);

        // 3. Check alert: diff = 15 >= 10 + 5 -> triggers alert
        let alerts = engine.check_alerts().await;
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].contains("Agent disconnected: node-1-10.0.0.1"));
    }
}
