use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use rand::RngCore;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum KeyError {
    #[error("Agent ID not found: {0}")]
    AgentNotFound(String),
    #[error("Invalid client.keys line format: {0}")]
    InvalidLineFormat(String),
    #[error("Invalid key hex format: {0}")]
    InvalidHexKey(String),
    #[error("Replay attack detected: received counter {received} <= last counter {last}")]
    ReplayAttack { received: u64, last: u64 },
    #[error("Agent already registered with ID: {0}")]
    AgentAlreadyExists(String),
}

#[derive(Debug, Clone)]
pub struct AgentKey {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub raw_key: String,
    pub key_bytes: [u8; 32],
    pub last_counter: u64,
}

impl AgentKey {
    pub fn parse_line(line: &str) -> Result<Self, KeyError> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Err(KeyError::InvalidLineFormat("Empty or comment line".to_string()));
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(KeyError::InvalidLineFormat(format!(
                "Expected 'ID NAME IP KEY', got {} parts",
                parts.len()
            )));
        }

        let id = parts[0].to_string();
        let name = parts[1].to_string();
        let ip = parts[2].to_string();
        let raw_key = parts[3].to_string();

        let decoded = hex::decode(&raw_key)
            .map_err(|e| KeyError::InvalidHexKey(format!("{}: {}", raw_key, e)))?;

        if decoded.len() != 32 {
            return Err(KeyError::InvalidHexKey(format!(
                "Key must be 32 bytes (64 hex chars), got {} bytes",
                decoded.len()
            )));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&decoded);

        Ok(Self {
            id,
            name,
            ip,
            raw_key,
            key_bytes,
            last_counter: 0,
        })
    }

    pub fn to_client_keys_line(&self) -> String {
        format!("{} {} {} {}", self.id, self.name, self.ip, self.raw_key)
    }

    pub fn matches_ip(&self, remote_ip: &str) -> bool {
        if self.ip == "any" || self.ip == "*" {
            return true;
        }
        self.ip == remote_ip
    }
}

#[derive(Debug, Clone, Default)]
pub struct KeysDatabase {
    agents_by_id: Arc<RwLock<HashMap<String, AgentKey>>>,
    agents_by_name: Arc<RwLock<HashMap<String, String>>>, // name -> id
}

impl KeysDatabase {
    pub fn new() -> Self {
        Self {
            agents_by_id: Arc::new(RwLock::new(HashMap::new())),
            agents_by_name: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a cryptographically secure 256-bit (64 hex char) agent key
    pub fn generate_key() -> (String, [u8; 32]) {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let hex_str = hex::encode(bytes);
        (hex_str, bytes)
    }

    /// Add an agent key
    pub fn add_agent(&self, agent: AgentKey) -> Result<(), KeyError> {
        let mut by_id = self.agents_by_id.write().unwrap();
        let mut by_name = self.agents_by_name.write().unwrap();

        if by_id.contains_key(&agent.id) {
            return Err(KeyError::AgentAlreadyExists(agent.id.clone()));
        }

        by_name.insert(agent.name.clone(), agent.id.clone());
        by_id.insert(agent.id.clone(), agent);
        Ok(())
    }

    /// Lookup agent by ID
    pub fn get_by_id(&self, id: &str) -> Option<AgentKey> {
        let by_id = self.agents_by_id.read().unwrap();
        by_id.get(id).cloned()
    }

    /// Lookup agent by Name
    pub fn get_by_name(&self, name: &str) -> Option<AgentKey> {
        let by_name = self.agents_by_name.read().unwrap();
        if let Some(id) = by_name.get(name) {
            self.get_by_id(id)
        } else {
            None
        }
    }

    /// List all registered agents
    pub fn list_agents(&self) -> Vec<AgentKey> {
        let by_id = self.agents_by_id.read().unwrap();
        by_id.values().cloned().collect()
    }

    /// Verify counter and update to prevent replay attacks (mirroring netcounter.c)
    pub fn verify_and_update_counter(&self, id: &str, received_counter: u64) -> Result<(), KeyError> {
        let mut by_id = self.agents_by_id.write().unwrap();
        if let Some(agent) = by_id.get_mut(id) {
            if received_counter <= agent.last_counter && agent.last_counter > 0 {
                return Err(KeyError::ReplayAttack {
                    received: received_counter,
                    last: agent.last_counter,
                });
            }
            agent.last_counter = received_counter;
            Ok(())
        } else {
            Err(KeyError::AgentNotFound(id.to_string()))
        }
    }

    /// Next available 3-digit zero-padded agent ID (e.g. "001", "002")
    pub fn next_agent_id(&self) -> String {
        let by_id = self.agents_by_id.read().unwrap();
        let mut max_id: u32 = 0;
        for id_str in by_id.keys() {
            if let Ok(num) = id_str.parse::<u32>() {
                if num > max_id {
                    max_id = num;
                }
            }
        }
        format!("{:03}", max_id + 1)
    }

    /// Parse contents of a Wazuh client.keys file
    pub fn load_from_str(&self, content: &str) -> usize {
        let mut count = 0;
        for line in content.lines() {
            if let Ok(agent) = AgentKey::parse_line(line) {
                let _ = self.add_agent(agent);
                count += 1;
            }
        }
        count
    }

    /// Serialize current keys back to client.keys file format
    pub fn export_client_keys(&self) -> String {
        let by_id = self.agents_by_id.read().unwrap();
        let mut sorted: Vec<&AgentKey> = by_id.values().collect();
        sorted.sort_by_key(|a| &a.id);

        let mut out = String::new();
        for agent in sorted {
            out.push_str(&agent.to_client_keys_line());
            out.push('\n');
        }
        out
    }

    pub fn total_agents(&self) -> usize {
        self.agents_by_id.read().unwrap().len()
    }
}
