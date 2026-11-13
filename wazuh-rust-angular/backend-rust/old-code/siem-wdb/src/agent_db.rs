use chrono::{DateTime, Utc};
use crate::fim_store::FimStore;
use crate::rootcheck_store::RootcheckStore;
use crate::sca_store::ScaStore;
use crate::syscollector_store::SyscollectorStore;

pub struct AgentDatabase {
    pub agent_id: String,
    pub agent_name: String,
    pub fim: FimStore,
    pub syscollector: SyscollectorStore,
    pub sca: ScaStore,
    pub rootcheck: RootcheckStore,
    pub last_sync: DateTime<Utc>,
}

impl AgentDatabase {
    pub fn new(agent_id: &str, agent_name: &str) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            agent_name: agent_name.to_string(),
            fim: FimStore::new(),
            syscollector: SyscollectorStore::new(),
            sca: ScaStore::new(),
            rootcheck: RootcheckStore::new(),
            last_sync: Utc::now(),
        }
    }

    pub fn mark_synced(&mut self) {
        self.last_sync = Utc::now();
    }
}
