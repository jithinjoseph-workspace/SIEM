//! Wazuh Agent Custom Labels Manager (labels_op.c)
//!
//! Handles parsing, hidden label filtering, and hierarchical JSON injection of agent labels
//! into alert events and inventory payloads.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentLabel {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub hidden: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LabelSet {
    labels: HashMap<String, AgentLabel>,
}

impl LabelSet {
    pub fn new() -> Self {
        Self {
            labels: HashMap::new(),
        }
    }

    /// Add or update a label.
    pub fn add(&mut self, key: &str, value: &str, hidden: bool) {
        self.labels.insert(
            key.to_string(),
            AgentLabel {
                key: key.to_string(),
                value: value.to_string(),
                hidden,
            },
        );
    }

    /// Retrieve a label by key.
    pub fn get(&self, key: &str) -> Option<&AgentLabel> {
        self.labels.get(key)
    }

    /// Total count of labels.
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// Convert labels into a key-value map, optionally filtering out hidden labels.
    pub fn to_map(&self, include_hidden: bool) -> HashMap<String, String> {
        self.labels
            .values()
            .filter(|lbl| include_hidden || !lbl.hidden)
            .map(|lbl| (lbl.key.clone(), lbl.value.clone()))
            .collect()
    }

    /// Merge labels into an event's JSON object under the `"agent.labels"` (or root `"labels"`) key.
    pub fn merge_into_json(&self, event: &mut serde_json::Value, include_hidden: bool) {
        if let serde_json::Value::Object(ref mut map) = event {
            let label_map = self.to_map(include_hidden);
            if !label_map.is_empty() {
                let labels_val = serde_json::to_value(label_map).unwrap_or_default();
                // Inject under "agent.labels" or root "labels"
                if let Some(serde_json::Value::Object(ref mut agent_obj)) = map.get_mut("agent") {
                    agent_obj.insert("labels".to_string(), labels_val);
                } else {
                    map.insert("labels".to_string(), labels_val);
                }
            }
        }
    }
}
