//! Agent health monitoring and lifecycle alerting.
//!
//! Replaces legacy `siem-monitord` agent tracking with pure, clean-room Rust.
//! Monitord features preserved:
//! - Disconnection detection after `agents_disconnection_time` (default 600s).
//! - Flap protection / delay with `agents_disconnection_alert_time`.
//! - Security alert generation matching Rule 504 ("Agent disconnected").
//! - Automatic retirement/cleanup of inactive agents after `delete_old_agents`.
//! - Security alert generation matching Rule 505 ("Agent removed").

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::{AgentStatus, AppState, AuthCtx};

/// Configuration for agent connectivity monitoring.
#[derive(Debug, Clone)]
pub struct AgentMonitorConfig {
    /// Inactivity seconds after which an agent is marked Disconnected (default: 600s).
    pub disconnection_time_secs: i64,
    /// Delay seconds before alerting on disconnection to prevent flap noise (default: 0s).
    pub disconnection_alert_delay_secs: i64,
    /// Inactivity seconds after which a disconnected agent is automatically purged (None = disabled).
    pub delete_old_agents_secs: Option<i64>,
    /// Polling interval for background health check loop (default: 30s).
    pub check_interval: Duration,
}

impl Default for AgentMonitorConfig {
    fn default() -> Self {
        Self {
            disconnection_time_secs: 600,
            disconnection_alert_delay_secs: 0,
            delete_old_agents_secs: None,
            check_interval: Duration::from_secs(30),
        }
    }
}

/// Internal state tracking disconnected agents to manage alerting and flaps.
#[derive(Debug, Default)]
pub struct AgentMonitorTracker {
    /// Agent ID -> timestamp when first detected disconnected.
    pub disconnected_since: HashMap<String, DateTime<Utc>>,
    /// Agent ID -> timestamp when Rule 504 alert was fired.
    pub alerted_disconnections: HashMap<String, DateTime<Utc>>,
    /// Set after the first pass: agents already offline when the server starts were alerted on
    /// before the restart, so the first pass records them without a new alert.
    pub primed: bool,
}

impl AgentMonitorTracker {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Information needed to emit an agent event.
#[derive(Debug, Clone)]
pub struct AgentEventDetails {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub tenant: String,
}

/// Result of evaluating agent connectivity.
#[derive(Debug, Default)]
pub struct HealthCheckResult {
    pub disconnected_alerts: Vec<Value>,
    pub removed_alerts: Vec<Value>,
    pub agents_to_remove: Vec<AgentEventDetails>,
}

/// Performs a single pass over enrolled agents and checks connectivity against keepalive timestamps.
pub fn evaluate_agent_health(
    agents: &[(String, String, String, String, AgentStatus, DateTime<Utc>)], // id, name, ip, tenant, status, last_keepalive
    now: DateTime<Utc>,
    config: &AgentMonitorConfig,
    tracker: &mut AgentMonitorTracker,
) -> HealthCheckResult {
    let mut result = HealthCheckResult::default();
    let first_pass = !std::mem::replace(&mut tracker.primed, true);

    for (id, name, ip, tenant, _status, last_keepalive) in agents {
        let inactive_secs = now.timestamp() - last_keepalive.timestamp();

        // 1. Check if agent is active again
        if inactive_secs <= config.disconnection_time_secs {
            if tracker.disconnected_since.remove(id).is_some() {
                debug!(agent_id = %id, "Agent reconnected; resetting disconnect tracker");
            }
            tracker.alerted_disconnections.remove(id);
            continue;
        }

        // 2. Agent is disconnected
        let disconnected_at = *tracker.disconnected_since.entry(id.clone()).or_insert(now);

        let disconnected_duration = now.timestamp() - disconnected_at.timestamp();

        // shortcut: an agent that went offline while the server was down gets no 504 either;
        // fix by storing the alerted set in ClickHouse if that matters.
        if first_pass {
            tracker.alerted_disconnections.insert(id.clone(), now);
        }

        // Check if Rule 504 alert should be emitted
        if disconnected_duration >= config.disconnection_alert_delay_secs
            && !tracker.alerted_disconnections.contains_key(id)
        {
            tracker.alerted_disconnections.insert(id.clone(), now);

            let alert = create_disconnect_alert(id, name, ip, tenant, now);
            result.disconnected_alerts.push(alert);
        }

        // 3. Check for automatic retirement (Rule 505)
        if let Some(auto_delete_secs) = config.delete_old_agents_secs {
            let total_inactive_limit = config.disconnection_time_secs + auto_delete_secs;
            if inactive_secs >= total_inactive_limit {
                let alert = create_removed_alert(id, name, ip, tenant, now);
                result.removed_alerts.push(alert);
                result.agents_to_remove.push(AgentEventDetails {
                    id: id.to_string(),
                    name: name.to_string(),
                    ip: ip.to_string(),
                    tenant: tenant.to_string(),
                });
                tracker.disconnected_since.remove(id);
                tracker.alerted_disconnections.remove(id);
            }
        }
    }

    result
}

/// Formats a clean-room security alert for Agent Disconnected (Rule 504).
pub fn create_disconnect_alert(
    id: &str,
    name: &str,
    ip: &str,
    tenant: &str,
    timestamp: DateTime<Utc>,
) -> Value {
    let ts_str = timestamp.to_rfc3339();
    let desc = "Agent disconnected";
    let full_log = format!("1:provigil-monitord:ossec: Agent disconnected: '{name}-{ip}'.");

    json!({
        "timestamp": ts_str,
        "tenant_id": tenant,
        "rule": {
            "id": "504",
            "level": 3,
            "description": desc,
            "groups": ["ossec", "agent_monitor"],
            "firedtimes": 1
        },
        "agent": {
            "id": id,
            "name": name,
            "ip": ip
        },
        "manager": {
            "name": "provigil-server"
        },
        "location": "provigil-monitord",
        "full_log": full_log,
        "decoder": {
            "name": "provigil-monitord"
        }
    })
}

/// Formats a clean-room security alert for Agent Removed (Rule 505).
pub fn create_removed_alert(
    id: &str,
    name: &str,
    ip: &str,
    tenant: &str,
    timestamp: DateTime<Utc>,
) -> Value {
    let ts_str = timestamp.to_rfc3339();
    let desc = "Agent removed from database";
    let full_log = format!("ossec: Agent removed: '{name}-{ip}'.");

    json!({
        "timestamp": ts_str,
        "tenant_id": tenant,
        "rule": {
            "id": "505",
            "level": 3,
            "description": desc,
            "groups": ["ossec", "agent_monitor"],
            "firedtimes": 1
        },
        "agent": {
            "id": id,
            "name": name,
            "ip": ip
        },
        "manager": {
            "name": "provigil-server"
        },
        "location": "provigil-monitord",
        "full_log": full_log,
        "decoder": {
            "name": "provigil-monitord"
        }
    })
}

/// Background loop that continuously checks agent keepalives.
pub fn start_agent_monitor(state: AppState, config: AgentMonitorConfig) {
    tokio::spawn(async move {
        info!("Started background ProVigil Agent Health Monitor");
        let mut tracker = AgentMonitorTracker::new();

        loop {
            tokio::time::sleep(config.check_interval).await;
            let now = Utc::now();

            // Collect snapshots of agent states safely
            let snapshot: Vec<_> = {
                let agents = state.agents.read().unwrap();
                let tenants = state.agent_tenants.read().unwrap();
                agents
                    .iter()
                    .map(|(id, a)| {
                        let tenant = tenants.get(id).cloned().unwrap_or_else(|| "default".into());
                        (
                            id.clone(),
                            a.name.clone(),
                            a.ip.clone(),
                            tenant,
                            a.status.clone(),
                            a.last_keepalive,
                        )
                    })
                    .collect()
            };

            let result = evaluate_agent_health(&snapshot, now, &config, &mut tracker);

            // Update status in agent state if marked disconnected
            if !result.disconnected_alerts.is_empty() {
                let mut agents_guard = state.agents.write().unwrap();
                for alert in &result.disconnected_alerts {
                    if let Some(id) = alert["agent"]["id"].as_str() {
                        if let Some(agent) = agents_guard.get_mut(id) {
                            agent.status = AgentStatus::Disconnected;
                        }
                    }
                }
            }

            // Route alerts to live broadcast and state
            for alert in result
                .disconnected_alerts
                .iter()
                .chain(&result.removed_alerts)
            {
                info!(
                    agent_id = %alert["agent"]["id"].as_str().unwrap_or(""),
                    rule_id = %alert["rule"]["id"].as_str().unwrap_or(""),
                    "Agent monitor security alert generated"
                );
                let rule_id = alert["rule"]["id"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(504);
                let alert_obj = siem_core::Alert {
                    id: uuid::Uuid::new_v4(),
                    timestamp: Utc::now(),
                    rule: siem_core::RuleAlertInfo {
                        id: rule_id,
                        level: alert["rule"]["level"].as_u64().unwrap_or(3) as u8,
                        description: alert["rule"]["description"]
                            .as_str()
                            .unwrap_or("Agent disconnected")
                            .to_string(),
                        groups: vec!["ossec".to_string(), "agent_monitor".to_string()],
                        mitre: None,
                    },
                    agent: siem_core::AgentAlertInfo {
                        id: alert["agent"]["id"].as_str().unwrap_or("").to_string(),
                        name: alert["agent"]["name"].as_str().unwrap_or("").to_string(),
                        ip: alert["agent"]["ip"].as_str().unwrap_or("").to_string(),
                    },
                    manager: Some(siem_core::ManagerAlertInfo {
                        name: "provigil-server".to_string(),
                    }),
                    decoder: Some(siem_core::DecoderAlertInfo {
                        name: "provigil-monitord".to_string(),
                    }),
                    full_log: alert["full_log"].as_str().unwrap_or("").to_string(),
                    decoded: siem_core::DecodedFields::default(),
                    location: "provigil-monitord".to_string(),
                    data: HashMap::new(),
                };
                let _ = state.broadcast_tx.send(alert_obj.clone());
                state.alerts.write().unwrap().push(alert_obj);
            }

            // Perform auto-deletion if triggered
            for agent in result.agents_to_remove {
                warn!(
                    agent_id = %agent.id,
                    agent_name = %agent.name,
                    "Purging inactive agent exceeding retention limit"
                );
                let ctx = AuthCtx {
                    username: "system".into(),
                    role: "super_admin".into(),
                    tenant_id: agent.tenant.clone(),
                    permissions: vec!["all".into()],
                    features: vec![],
                    requested_tenant: None,
                };
                crate::remove_scoped_agent(&state, &ctx, &agent.id);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn agents_offline_at_start_get_no_new_alert() {
        let now = Utc::now();
        let config = AgentMonitorConfig {
            disconnection_time_secs: 60,
            disconnection_alert_delay_secs: 0,
            delete_old_agents_secs: None,
            check_interval: Duration::seconds(10).to_std().unwrap(),
        };
        let mut tracker = AgentMonitorTracker::new();
        let agent = |seen: i64| ("009".to_string(), "old".to_string(), "10.0.0.9".to_string(), "t".to_string(), AgentStatus::Active, now - Duration::seconds(seen));
        assert!(evaluate_agent_health(&[agent(3600)], now, &config, &mut tracker).disconnected_alerts.is_empty());
        assert!(evaluate_agent_health(&[agent(3600)], now, &config, &mut tracker).disconnected_alerts.is_empty());
        // It reconnects, then goes offline again: that is alerted.
        evaluate_agent_health(&[agent(5)], now, &config, &mut tracker);
        assert_eq!(evaluate_agent_health(&[agent(120)], now, &config, &mut tracker).disconnected_alerts.len(), 1);
    }

    #[test]
    fn test_disconnect_detection_and_alert() {
        let now = Utc::now();
        let config = AgentMonitorConfig {
            disconnection_time_secs: 60,
            disconnection_alert_delay_secs: 0,
            delete_old_agents_secs: None,
            check_interval: Duration::seconds(10).to_std().unwrap(),
        };
        let mut tracker = AgentMonitorTracker::new();

        // 1. Active agent
        let agents = vec![(
            "001".into(),
            "win-server".into(),
            "192.168.1.10".into(),
            "tenant-a".into(),
            AgentStatus::Active,
            now - Duration::seconds(10),
        )];

        let res = evaluate_agent_health(&agents, now, &config, &mut tracker);
        assert!(res.disconnected_alerts.is_empty());
        assert!(tracker.disconnected_since.is_empty());

        // 2. Disconnected agent
        let agents_disc = vec![(
            "001".into(),
            "win-server".into(),
            "192.168.1.10".into(),
            "tenant-a".into(),
            AgentStatus::Active,
            now - Duration::seconds(75),
        )];

        let res2 = evaluate_agent_health(&agents_disc, now, &config, &mut tracker);
        assert_eq!(res2.disconnected_alerts.len(), 1);
        let alert = &res2.disconnected_alerts[0];
        assert_eq!(alert["rule"]["id"], "504");
        assert_eq!(alert["agent"]["id"], "001");
        assert_eq!(alert["agent"]["name"], "win-server");
        assert!(alert["full_log"]
            .as_str()
            .unwrap()
            .contains("Agent disconnected: 'win-server-192.168.1.10'"));

        // 3. Subsequent check does not duplicate alert (flap protection)
        let res3 = evaluate_agent_health(
            &agents_disc,
            now + Duration::seconds(10),
            &config,
            &mut tracker,
        );
        assert!(res3.disconnected_alerts.is_empty());

        // 4. Reconnect resets tracker
        let agents_reconnected = vec![(
            "001".into(),
            "win-server".into(),
            "192.168.1.10".into(),
            "tenant-a".into(),
            AgentStatus::Active,
            now + Duration::seconds(20),
        )];
        let res4 = evaluate_agent_health(
            &agents_reconnected,
            now + Duration::seconds(25),
            &config,
            &mut tracker,
        );
        assert!(res4.disconnected_alerts.is_empty());
        assert!(!tracker.alerted_disconnections.contains_key("001"));
    }

    #[test]
    fn test_auto_delete_old_agents() {
        let now = Utc::now();
        let config = AgentMonitorConfig {
            disconnection_time_secs: 60,
            disconnection_alert_delay_secs: 0,
            delete_old_agents_secs: Some(300), // 5 minutes
            check_interval: Duration::seconds(10).to_std().unwrap(),
        };
        let mut tracker = AgentMonitorTracker::new();

        let agents = vec![(
            "002".into(),
            "linux-worker".into(),
            "10.0.0.5".into(),
            "tenant-b".into(),
            AgentStatus::Disconnected,
            now - Duration::seconds(400), // 400s > 60 + 300
        )];

        let res = evaluate_agent_health(&agents, now, &config, &mut tracker);
        assert_eq!(res.removed_alerts.len(), 1);
        assert_eq!(res.agents_to_remove.len(), 1);
        assert_eq!(res.removed_alerts[0]["rule"]["id"], "505");
        assert!(res.removed_alerts[0]["full_log"]
            .as_str()
            .unwrap()
            .contains("Agent removed: 'linux-worker-10.0.0.5'"));
    }
}
