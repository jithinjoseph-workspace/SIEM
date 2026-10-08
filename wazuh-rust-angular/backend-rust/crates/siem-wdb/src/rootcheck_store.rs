use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PmEventStatus {
    Outstanding,
    Resolved,
}

impl PmEventStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Outstanding => "outstanding",
            Self::Resolved => "resolved",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "resolved" => Self::Resolved,
            _ => Self::Outstanding,
        }
    }
}

/// Rootcheck / Policy Monitoring event matching schema_agents.sql pm_event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PmEvent {
    pub log: String,
    pub date_first: i64,
    pub date_last: i64,
    pub status: PmEventStatus,
    pub pci_dss: Option<String>,
    pub cis: Option<String>,
}

pub struct RootcheckStore {
    events: RwLock<HashMap<String, PmEvent>>, // keyed by log text
}

impl Default for RootcheckStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RootcheckStore {
    pub fn new() -> Self {
        Self {
            events: RwLock::new(HashMap::new()),
        }
    }

    /// Save or update a PM event (wdb_rootcheck_save)
    pub fn save_event(
        &self,
        log: &str,
        date: i64,
        pci_dss: Option<String>,
        cis: Option<String>,
    ) {
        let mut events = self.events.write().unwrap();
        if let Some(existing) = events.get_mut(log) {
            existing.date_last = date;
            existing.status = PmEventStatus::Outstanding;
            if pci_dss.is_some() { existing.pci_dss = pci_dss; }
            if cis.is_some() { existing.cis = cis; }
        } else {
            let event = PmEvent {
                log: log.to_string(),
                date_first: date,
                date_last: date,
                status: PmEventStatus::Outstanding,
                pci_dss,
                cis,
            };
            events.insert(log.to_string(), event);
        }
    }

    /// Mark an event as resolved
    pub fn resolve_event(&self, log: &str) -> bool {
        let mut events = self.events.write().unwrap();
        if let Some(event) = events.get_mut(log) {
            event.status = PmEventStatus::Resolved;
            true
        } else {
            false
        }
    }

    /// Get all events, optionally filtering by status
    pub fn get_events(&self, status_filter: Option<PmEventStatus>) -> Vec<PmEvent> {
        let events = self.events.read().unwrap();
        events
            .values()
            .filter(|e| {
                if let Some(filter) = status_filter {
                    e.status == filter
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }

    /// Total active/outstanding events
    pub fn total_outstanding(&self) -> usize {
        let events = self.events.read().unwrap();
        events.values().filter(|e| e.status == PmEventStatus::Outstanding).count()
    }

    /// Clear all rootcheck events for the agent
    pub fn clear(&self) {
        self.events.write().unwrap().clear();
    }
}
