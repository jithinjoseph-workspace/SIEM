use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

/// Connection status matching Wazuh schema_global.sql
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Pending,
    NeverConnected,
    Active,
    Disconnected,
}

impl ConnectionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::NeverConnected => "never_connected",
            Self::Active => "active",
            Self::Disconnected => "disconnected",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "active" => Self::Active,
            "disconnected" => Self::Disconnected,
            "pending" => Self::Pending,
            _ => Self::NeverConnected,
        }
    }
}

/// Agent entity in global.db
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalAgent {
    pub id: u32,
    pub name: String,
    pub ip: Option<String>,
    pub register_ip: Option<String>,
    pub internal_key: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub os_major: Option<String>,
    pub os_minor: Option<String>,
    pub os_codename: Option<String>,
    pub os_build: Option<String>,
    pub os_platform: Option<String>,
    pub os_uname: Option<String>,
    pub os_arch: Option<String>,
    pub version: Option<String>,
    pub config_sum: Option<String>,
    pub merged_sum: Option<String>,
    pub manager_host: Option<String>,
    pub node_name: String,
    pub date_add: i64,
    pub last_keepalive: Option<i64>,
    pub group_name: String,
    pub connection_status: ConnectionStatus,
    pub disconnection_time: i64,
    pub labels: HashMap<String, String>,
}

impl GlobalAgent {
    pub fn new(id: u32, name: impl Into<String>, ip: Option<String>, key: Option<String>) -> Self {
        let now = Utc::now().timestamp();
        Self {
            id,
            name: name.into(),
            ip: ip.clone(),
            register_ip: ip,
            internal_key: key,
            os_name: None,
            os_version: None,
            os_major: None,
            os_minor: None,
            os_codename: None,
            os_build: None,
            os_platform: None,
            os_uname: None,
            os_arch: None,
            version: None,
            config_sum: None,
            merged_sum: None,
            manager_host: None,
            node_name: "master".to_string(),
            date_add: now,
            last_keepalive: None,
            group_name: "default".to_string(),
            connection_status: if id == 0 { ConnectionStatus::Active } else { ConnectionStatus::NeverConnected },
            disconnection_time: 0,
            labels: HashMap::new(),
        }
    }
}

/// Global database engine matching wdb_global.c
pub struct GlobalDb {
    agents: RwLock<HashMap<u32, GlobalAgent>>,
    groups: RwLock<HashSet<String>>,
    belongs: RwLock<HashMap<u32, Vec<String>>>, // agent_id -> list of groups in priority order
}

impl Default for GlobalDb {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalDb {
    pub fn new() -> Self {
        let mut groups = HashSet::new();
        groups.insert("default".to_string());

        let mut agents = HashMap::new();
        // Insert agent 0 (manager/localhost) as in schema_global.sql line 49
        let mut mgr = GlobalAgent::new(0, "localhost", Some("127.0.0.1".to_string()), None);
        mgr.last_keepalive = Some(253402300799);
        mgr.connection_status = ConnectionStatus::Active;
        agents.insert(0, mgr);

        Self {
            agents: RwLock::new(agents),
            groups: RwLock::new(groups),
            belongs: RwLock::new(HashMap::new()),
        }
    }

    /// Insert a new agent (wdb_insert_agent)
    pub fn insert_agent(
        &self,
        id: u32,
        name: &str,
        ip: Option<&str>,
        register_ip: Option<&str>,
        internal_key: Option<&str>,
        group: Option<&str>,
    ) -> Result<(), &'static str> {
        let mut agents = self.agents.write().unwrap();
        if agents.contains_key(&id) {
            return Err("Agent ID already exists");
        }

        let mut agent = GlobalAgent::new(
            id,
            name,
            ip.map(String::from),
            internal_key.map(String::from),
        );
        agent.register_ip = register_ip.map(String::from).or_else(|| ip.map(String::from));
        if let Some(grp) = group {
            agent.group_name = grp.to_string();
            let mut groups = self.groups.write().unwrap();
            groups.insert(grp.to_string());
        }

        agents.insert(id, agent);
        Ok(())
    }

    /// Update agent name (wdb_update_agent_name)
    pub fn update_agent_name(&self, id: u32, name: &str) -> bool {
        let mut agents = self.agents.write().unwrap();
        if let Some(agent) = agents.get_mut(&id) {
            agent.name = name.to_string();
            true
        } else {
            false
        }
    }

    /// Update agent OS and version metadata (wdb_update_agent_data)
    pub fn update_agent_data(
        &self,
        id: u32,
        os_name: Option<String>,
        os_version: Option<String>,
        os_platform: Option<String>,
        os_arch: Option<String>,
        version: Option<String>,
        config_sum: Option<String>,
        merged_sum: Option<String>,
    ) -> bool {
        let mut agents = self.agents.write().unwrap();
        if let Some(agent) = agents.get_mut(&id) {
            if os_name.is_some() { agent.os_name = os_name; }
            if os_version.is_some() { agent.os_version = os_version; }
            if os_platform.is_some() { agent.os_platform = os_platform; }
            if os_arch.is_some() { agent.os_arch = os_arch; }
            if version.is_some() { agent.version = version; }
            if config_sum.is_some() { agent.config_sum = config_sum; }
            if merged_sum.is_some() { agent.merged_sum = merged_sum; }
            true
        } else {
            false
        }
    }

    /// Update agent keepalive and connection status (wdb_update_agent_keepalive)
    pub fn update_agent_keepalive(&self, id: u32, connection_status: ConnectionStatus) -> bool {
        let mut agents = self.agents.write().unwrap();
        if let Some(agent) = agents.get_mut(&id) {
            agent.last_keepalive = Some(Utc::now().timestamp());
            agent.connection_status = connection_status;
            if connection_status == ConnectionStatus::Disconnected {
                agent.disconnection_time = Utc::now().timestamp();
            }
            true
        } else {
            false
        }
    }

    /// Update agent connection status directly (wdb_update_agent_connection_status)
    pub fn set_agent_connection_status(&self, id: u32, status: ConnectionStatus) -> bool {
        let mut agents = self.agents.write().unwrap();
        if let Some(agent) = agents.get_mut(&id) {
            agent.connection_status = status;
            if status == ConnectionStatus::Disconnected {
                agent.disconnection_time = Utc::now().timestamp();
            }
            true
        } else {
            false
        }
    }

    /// Disconnect agents whose last keepalive exceeds timeout (wdb_disconnect_agents)
    pub fn disconnect_stale_agents(&self, timeout_seconds: i64) -> usize {
        let now = Utc::now().timestamp();
        let mut count = 0;
        let mut agents = self.agents.write().unwrap();

        for (id, agent) in agents.iter_mut() {
            if *id == 0 {
                continue; // Manager never disconnects
            }
            if agent.connection_status == ConnectionStatus::Active {
                if let Some(last) = agent.last_keepalive {
                    if (now - last) > timeout_seconds {
                        agent.connection_status = ConnectionStatus::Disconnected;
                        agent.disconnection_time = now;
                        count += 1;
                    }
                }
            }
        }
        count
    }

    /// Get agent info (wdb_get_agent_info)
    pub fn get_agent_info(&self, id: u32) -> Option<GlobalAgent> {
        let agents = self.agents.read().unwrap();
        agents.get(&id).cloned()
    }

    /// Find agent by name
    pub fn find_agent_by_name(&self, name: &str) -> Option<GlobalAgent> {
        let agents = self.agents.read().unwrap();
        agents.values().find(|a| a.name.eq_ignore_ascii_case(name)).cloned()
    }

    /// Get all agents (wdb_get_all_agents)
    pub fn get_all_agents(&self) -> Vec<GlobalAgent> {
        let agents = self.agents.read().unwrap();
        agents.values().cloned().collect()
    }

    /// Get agents by connection status (wdb_get_agents_by_connection_status)
    pub fn get_agents_by_status(&self, status: ConnectionStatus) -> Vec<GlobalAgent> {
        let agents = self.agents.read().unwrap();
        agents
            .values()
            .filter(|a| a.connection_status == status)
            .cloned()
            .collect()
    }

    /// Insert or update an agent label (wdb_get_agent_labels)
    pub fn set_agent_label(&self, id: u32, key: &str, value: &str) -> bool {
        let mut agents = self.agents.write().unwrap();
        if let Some(agent) = agents.get_mut(&id) {
            agent.labels.insert(key.to_string(), value.to_string());
            true
        } else {
            false
        }
    }

    /// Group management: insert group (wdb_insert_group)
    pub fn insert_group(&self, name: &str) -> bool {
        let mut groups = self.groups.write().unwrap();
        groups.insert(name.to_string())
    }

    /// Set groups for agent (wdb_set_agent_groups)
    pub fn set_agent_groups(&self, id: u32, group_names: Vec<String>) -> bool {
        let agents = self.agents.read().unwrap();
        if !agents.contains_key(&id) {
            return false;
        }
        drop(agents);

        let mut groups = self.groups.write().unwrap();
        for g in &group_names {
            groups.insert(g.clone());
        }
        drop(groups);

        let mut belongs = self.belongs.write().unwrap();
        belongs.insert(id, group_names);
        true
    }

    /// Get groups for agent
    pub fn get_agent_groups(&self, id: u32) -> Vec<String> {
        let belongs = self.belongs.read().unwrap();
        belongs.get(&id).cloned().unwrap_or_else(|| vec!["default".to_string()])
    }

    /// Delete agent (wdb_delete_agent)
    pub fn delete_agent(&self, id: u32) -> bool {
        if id == 0 {
            return false; // Manager cannot be deleted
        }
        let mut agents = self.agents.write().unwrap();
        let removed = agents.remove(&id).is_some();
        if removed {
            let mut belongs = self.belongs.write().unwrap();
            belongs.remove(&id);
        }
        removed
    }

    /// Total registered agents count
    pub fn total_agents(&self) -> usize {
        self.agents.read().unwrap().len()
    }
}
