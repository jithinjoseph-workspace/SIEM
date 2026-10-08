use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use crate::agent_db::AgentDatabase;
use crate::global_db::GlobalDb;

#[derive(Clone)]
pub struct WazuhDbManager {
    agents: Arc<RwLock<HashMap<String, Arc<RwLock<AgentDatabase>>>>>,
    pub global: Arc<GlobalDb>,
}

impl Default for WazuhDbManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WazuhDbManager {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            global: Arc::new(GlobalDb::new()),
        }
    }

    pub fn get_or_create(&self, agent_id: &str, agent_name: &str) -> Arc<RwLock<AgentDatabase>> {
        let mut guard = self.agents.write().unwrap();
        guard
            .entry(agent_id.to_string())
            .or_insert_with(|| Arc::new(RwLock::new(AgentDatabase::new(agent_id, agent_name))))
            .clone()
    }

    pub fn get(&self, agent_id: &str) -> Option<Arc<RwLock<AgentDatabase>>> {
        let guard = self.agents.read().unwrap();
        guard.get(agent_id).cloned()
    }

    pub fn list_agent_ids(&self) -> Vec<String> {
        let guard = self.agents.read().unwrap();
        guard.keys().cloned().collect()
    }

    pub fn total_agents(&self) -> usize {
        let guard = self.agents.read().unwrap();
        guard.len()
    }
}
