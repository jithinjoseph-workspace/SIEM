use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use siem_wdb::{ConnectionStatus, GlobalAgent, GlobalDb};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentFilter {
    All,
    ActiveOnly,
    DisconnectedOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Csv,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSummary {
    pub id: u32,
    pub name: String,
    pub ip: String,
    pub status: String,
}

pub struct AgentControlOps;

impl AgentControlOps {
    /// Formats list of agents based on filter and output format
    pub fn list_agents(global: &GlobalDb, filter: AgentFilter, format: OutputFormat) -> String {
        let all = global.get_all_agents();
        let mut filtered: Vec<GlobalAgent> = all
            .into_iter()
            .filter(|a| match filter {
                AgentFilter::All => true,
                AgentFilter::ActiveOnly => a.connection_status == ConnectionStatus::Active,
                AgentFilter::DisconnectedOnly => {
                    a.connection_status == ConnectionStatus::Disconnected
                        || a.connection_status == ConnectionStatus::NeverConnected
                }
            })
            .collect();

        filtered.sort_by_key(|a| a.id);

        match format {
            OutputFormat::Json => {
                let items: Vec<AgentSummary> = filtered
                    .into_iter()
                    .map(|a| AgentSummary {
                        id: a.id,
                        name: a.name,
                        ip: a.ip.unwrap_or_else(|| "any".to_string()),
                        status: a.connection_status.as_str().to_string(),
                    })
                    .collect();
                json!(items).to_string()
            }
            OutputFormat::Csv => {
                let mut out = String::from("id,name,ip,status\n");
                for a in filtered {
                    out.push_str(&format!(
                        "{},{},{},{}\n",
                        a.id,
                        a.name,
                        a.ip.unwrap_or_else(|| "any".to_string()),
                        a.connection_status.as_str()
                    ));
                }
                out
            }
            OutputFormat::Text => {
                if filtered.is_empty() {
                    return "** No agent available.\n".to_string();
                }
                let mut out = String::from("\nWazuh agent_control. Available agents:\n");
                for a in filtered {
                    let ip = a.ip.unwrap_or_else(|| "any".to_string());
                    let status = match a.connection_status {
                        ConnectionStatus::Active => "Active",
                        ConnectionStatus::Disconnected => "Disconnected",
                        ConnectionStatus::NeverConnected => "Never connected",
                        ConnectionStatus::Pending => "Pending",
                    };
                    out.push_str(&format!(
                        "   ID: {:03}, Name: {}, IP: {}, Status: {}\n",
                        a.id, a.name, ip, status
                    ));
                }
                out
            }
        }
    }

    /// Formats detailed agent information
    pub fn get_agent_info(global: &GlobalDb, agent_id: u32, format: OutputFormat) -> Result<String, String> {
        let agent = global
            .get_agent_info(agent_id)
            .ok_or_else(|| format!("Agent '{agent_id:03}' not found."))?;

        match format {
            OutputFormat::Json => Ok(json!(agent).to_string()),
            OutputFormat::Csv => {
                let out = format!(
                    "id,name,ip,status,os,version,last_keepalive\n{},{},{},{},{},{},{}\n",
                    agent.id,
                    agent.name,
                    agent.ip.unwrap_or_else(|| "any".to_string()),
                    agent.connection_status.as_str(),
                    agent.os_name.unwrap_or_else(|| "Unknown".to_string()),
                    agent.version.unwrap_or_else(|| "Unknown".to_string()),
                    agent.last_keepalive.unwrap_or(0)
                );
                Ok(out)
            }
            OutputFormat::Text => {
                let mut out = String::new();
                out.push_str(&format!("\nWazuh agent_control. Agent information:\n"));
                out.push_str(&format!("   Agent ID:   {:03}\n", agent.id));
                out.push_str(&format!("   Agent Name: {}\n", agent.name));
                out.push_str(&format!("   IP address: {}\n", agent.ip.unwrap_or_else(|| "any".to_string())));
                out.push_str(&format!("   Status:     {}\n\n", agent.connection_status.as_str()));

                let os_info = format!(
                    "{} {}",
                    agent.os_name.unwrap_or_default(),
                    agent.os_version.unwrap_or_default()
                )
                .trim()
                .to_string();

                out.push_str(&format!("   Operating system:    {}\n", if os_info.is_empty() { "Unknown" } else { &os_info }));
                out.push_str(&format!("   Client version:      {}\n", agent.version.as_deref().unwrap_or("Unknown")));
                out.push_str(&format!("   Configuration/Group: {}\n", agent.group_name));

                if let Some(ka) = agent.last_keepalive {
                    if let Some(dt) = Utc.timestamp_opt(ka, 0).single() {
                        out.push_str(&format!("   Last keep alive:     {}\n", dt.to_rfc2822()));
                    }
                } else {
                    out.push_str("   Last keep alive:     Never\n");
                }

                out.push_str("\n   Syscheck last started at:  [Active]\n");
                out.push_str("   Rootcheck last started at: [Active]\n");

                Ok(out)
            }
        }
    }

    /// Generates agent restart wire command
    pub fn build_restart_command(agent_id: Option<u32>) -> String {
        if let Some(id) = agent_id {
            format!("{id:03} restart-ossec")
        } else {
            "ALL restart-ossec".to_string()
        }
    }

    /// Generates syscheck/rootcheck run wire command
    pub fn build_syscheck_command(agent_id: Option<u32>) -> String {
        if let Some(id) = agent_id {
            format!("{id:03} syscheck check_now")
        } else {
            "ALL syscheck check_now".to_string()
        }
    }

    /// Generates Active Response command
    pub fn build_active_response_command(agent_id: Option<u32>, ar_name: &str, ip: Option<&str>) -> String {
        let target = if let Some(id) = agent_id {
            format!("{id:03}")
        } else {
            "ALL".to_string()
        };
        let param = ip.unwrap_or("0.0.0.0");
        format!("{target} active-response {ar_name} {param}")
    }
}
