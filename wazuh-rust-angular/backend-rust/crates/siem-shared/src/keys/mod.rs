//! Wazuh Agent Keys and Fleet Management (agent_op.c, read-agents.c, enrollment_op.c)
//!
//! Provides parsing, atomic persistence, validation, and status resolution for the canonical
//! Wazuh `client.keys` registry (`ID NAME IP KEY`).

use crate::validate::{is_valid_agent_id, is_valid_agent_ip, is_valid_agent_name};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentStatus {
    Active,
    Disconnected,
    Pending,
    NeverConnected,
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentStatus::Active => write!(f, "active"),
            AgentStatus::Disconnected => write!(f, "disconnected"),
            AgentStatus::Pending => write!(f, "pending"),
            AgentStatus::NeverConnected => write!(f, "never_connected"),
        }
    }
}

/// A single entry in the canonical `client.keys` file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentKeyEntry {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub key: String,
}

/// The `client.keys` registry manager.
#[derive(Debug, Clone, Default)]
pub struct ClientKeys {
    agents_by_id: HashMap<String, AgentKeyEntry>,
    agents_by_name: HashMap<String, String>, // name -> id
}

impl ClientKeys {
    pub fn new() -> Self {
        Self {
            agents_by_id: HashMap::new(),
            agents_by_name: HashMap::new(),
        }
    }

    /// Parse `client.keys` text format: `ID NAME IP KEY` per line.
    pub fn parse_str(content: &str) -> Result<Self, String> {
        let mut keys = Self::new();
        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                return Err(format!(
                    "Invalid client.keys format at line {}: expected 4 tokens, found {}",
                    line_num + 1,
                    parts.len()
                ));
            }

            let id = parts[0];
            let name = parts[1];
            let ip = parts[2];
            let key = parts[3];

            keys.add_agent(id, name, ip, key)?;
        }
        Ok(keys)
    }

    /// Load `client.keys` from a file path.
    pub fn load_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("Failed to open client.keys: {}", e))?;
        let reader = BufReader::new(file);
        let mut content = String::new();
        for line in reader.lines() {
            let line = line.map_err(|e| format!("Failed to read client.keys line: {}", e))?;
            content.push_str(&line);
            content.push('\n');
        }
        Self::parse_str(&content)
    }

    /// Add or update an agent entry with strict validation.
    pub fn add_agent(&mut self, id: &str, name: &str, ip: &str, key: &str) -> Result<(), String> {
        if !is_valid_agent_id(id) {
            return Err(format!("Invalid agent ID: '{}'", id));
        }
        if !is_valid_agent_name(name) {
            return Err(format!("Invalid agent name: '{}'", name));
        }
        if !is_valid_agent_ip(ip) {
            return Err(format!("Invalid agent IP/CIDR: '{}'", ip));
        }
        if key.trim().is_empty() {
            return Err("Agent key cannot be empty".to_string());
        }

        let entry = AgentKeyEntry {
            id: id.to_string(),
            name: name.to_string(),
            ip: ip.to_string(),
            key: key.to_string(),
        };

        self.agents_by_id.insert(id.to_string(), entry);
        self.agents_by_name.insert(name.to_string(), id.to_string());
        Ok(())
    }

    /// Remove an agent by ID.
    pub fn remove_agent(&mut self, id: &str) -> Option<AgentKeyEntry> {
        if let Some(entry) = self.agents_by_id.remove(id) {
            self.agents_by_name.remove(&entry.name);
            Some(entry)
        } else {
            None
        }
    }

    /// Find an agent by ID.
    pub fn get_by_id(&self, id: &str) -> Option<&AgentKeyEntry> {
        self.agents_by_id.get(id)
    }

    /// Find an agent by Name.
    pub fn get_by_name(&self, name: &str) -> Option<&AgentKeyEntry> {
        self.agents_by_name.get(name).and_then(|id| self.get_by_id(id))
    }

    /// List all agents.
    pub fn list_agents(&self) -> Vec<&AgentKeyEntry> {
        self.agents_by_id.values().collect()
    }

    /// Total count of registered agents.
    pub fn count(&self) -> usize {
        self.agents_by_id.len()
    }

    /// Serialize to canonical `client.keys` format.
    pub fn to_client_keys_string(&self) -> String {
        let mut lines = Vec::new();
        let mut sorted_agents: Vec<&AgentKeyEntry> = self.agents_by_id.values().collect();
        sorted_agents.sort_by(|a, b| a.id.cmp(&b.id));

        for agent in sorted_agents {
            lines.push(format!("{} {} {} {}", agent.id, agent.name, agent.ip, agent.key));
        }
        lines.join("\n")
    }

    /// Atomic safe save to file (writes to .tmp file then renames atomically).
    pub fn save_atomic<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let path = path.as_ref();
        let tmp_path = path.with_extension("tmp");

        let content = self.to_client_keys_string();
        let mut file = File::create(&tmp_path)
            .map_err(|e| format!("Failed to create temporary keys file: {}", e))?;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write to temporary keys file: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("Failed to sync temporary keys file: {}", e))?;

        fs::rename(&tmp_path, path)
            .map_err(|e| format!("Failed to atomically rename keys file: {}", e))?;

        Ok(())
    }

    /// Compute agent connection status based on keepalive timestamp.
    pub fn resolve_agent_status(
        last_keepalive: Option<i64>,
        current_time: i64,
        disconnected_threshold_secs: i64,
    ) -> AgentStatus {
        match last_keepalive {
            None => AgentStatus::NeverConnected,
            Some(0) => AgentStatus::NeverConnected,
            Some(ts) => {
                let diff = current_time - ts;
                if diff <= disconnected_threshold_secs {
                    AgentStatus::Active
                } else {
                    AgentStatus::Disconnected
                }
            }
        }
    }
}
