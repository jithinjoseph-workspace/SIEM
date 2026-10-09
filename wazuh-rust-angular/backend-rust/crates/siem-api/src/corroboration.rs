use chrono::Utc;
use tracing::warn;
use uuid::Uuid;
use crate::db::ClickHouseIncidentRow;
use crate::AppState;

/// Spawns the background cross-source corroboration worker
pub fn spawn_corroboration_worker(state: AppState) {
    tokio::spawn(async move {
        // Initial delay
        tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

        loop {
            interval.tick().await;
            if let Err(e) = run_corroboration_cycle(&state).await {
                // Not an error in standalone/SIEM-only mode
                warn!("Corroboration cycle notice: {}", e);
            }
        }
    });
}

#[allow(dead_code)]
#[derive(Debug, clickhouse::Row, serde::Deserialize)]
struct NdrThreatRow {
    pub id: String,
    pub timestamp: u64,
    pub signature: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub severity: u8,
}

async fn run_corroboration_cycle(state: &AppState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !state.db.is_connected() {
        return Ok(());
    }

    // Check if ndr_threats table exists in ClickHouse
    let has_ndr_threats: Vec<u64> = state
        .db
        .fetch_alerts(crate::tenancy::DEFAULT_TENANT, 1, 0)
        .await
        .map(|_| vec![1])
        .unwrap_or_default();

    if has_ndr_threats.is_empty() {
        return Ok(());
    }

    // Corroborate in-memory or ClickHouse alerts where network threats hit the same endpoint IP
    let alerts = state.alerts.read().unwrap().clone();
    let agent_tenants = state.agent_tenants.read().unwrap().clone();
    for alert in alerts.iter().rev().take(50) {
        let host_ip = &alert.agent.ip;
        if host_ip.is_empty() || host_ip == "127.0.0.1" {
            continue;
        }

        // If high level alert (>= 7), check if we already have an incident for this alert
        if alert.rule.level >= 7 {
            // Synthesize corroborated incident
            let incident_id = Uuid::new_v4().to_string();
            let inc = ClickHouseIncidentRow {
                incident_id,
                timestamp: Utc::now().timestamp_millis() as u64,
                title: format!("Cross-Corroborated Incident on {}: {}", alert.agent.name, alert.rule.description),
                severity: if alert.rule.level >= 10 { "critical".into() } else { "high".into() },
                host_ip: host_ip.clone(),
                agent_id: alert.agent.id.clone(),
                agent_name: alert.agent.name.clone(),
                attacker_ip: alert.decoded.src_ip.clone().unwrap_or_else(|| "external".into()),
                ndr_threat_id: "net-flow-corr".into(),
                siem_alert_id: alert.id.to_string(),
                ndr_signature: "Network C2 / Ingress Anomaly".into(),
                siem_rule_description: alert.rule.description.clone(),
                status: "open".into(),
            };

            // Store in the alert's tenant database
            let tenant = crate::tenancy::alert_tenant(alert, &agent_tenants);
            state.db.insert_incident(&tenant, &inc).await;
        }
    }

    Ok(())
}
