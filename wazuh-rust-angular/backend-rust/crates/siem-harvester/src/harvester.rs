use crate::wcs_model::{WcsFimDocument, WcsInventoryDocument};
use serde::{Deserialize, Serialize};

/// Policy configuration for the Harvester pipeline.
/// Ported from Wazuh src/policyHarvesterManager.hpp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvesterConfig {
    pub enabled: bool,
    pub bulk_size: usize,
    pub index_inventory_prefix: String,
    pub index_fim_prefix: String,
}

impl Default for HarvesterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bulk_size: 500,
            index_inventory_prefix: "wazuh-states-inventory-".to_string(),
            index_fim_prefix: "wazuh-states-fim-".to_string(),
        }
    }
}

/// Inventory Harvester Engine.
/// Ported from Wazuh src/inventoryHarvesterFacade.cpp.
pub struct InventoryHarvester {
    pub config: HarvesterConfig,
}

impl Default for InventoryHarvester {
    fn default() -> Self {
        Self::new(HarvesterConfig::default())
    }
}

impl InventoryHarvester {
    pub fn new(config: HarvesterConfig) -> Self {
        Self { config }
    }

    /// Formats a batch of WCS Inventory documents into standard OpenSearch / Elasticsearch bulk NDJSON.
    pub fn format_inventory_opensearch_bulk(
        &self,
        docs: &[WcsInventoryDocument],
        cluster_name: &str,
    ) -> String {
        let index_name = format!("{}{}", self.config.index_inventory_prefix, cluster_name);
        let mut bulk_payload = String::new();

        for doc in docs {
            let action = serde_json::json!({
                "index": {
                    "_index": index_name,
                    "_id": format!("{}:{}", doc.agent.id, doc.item_id)
                }
            });

            if let (Ok(action_str), Ok(doc_str)) = (serde_json::to_string(&action), serde_json::to_string(doc)) {
                bulk_payload.push_str(&action_str);
                bulk_payload.push('\n');
                bulk_payload.push_str(&doc_str);
                bulk_payload.push('\n');
            }
        }

        bulk_payload
    }

    /// Formats a batch of WCS FIM documents into standard OpenSearch / Elasticsearch bulk NDJSON.
    pub fn format_fim_opensearch_bulk(
        &self,
        docs: &[WcsFimDocument],
        cluster_name: &str,
    ) -> String {
        let index_name = format!("{}{}", self.config.index_fim_prefix, cluster_name);
        let mut bulk_payload = String::new();

        for doc in docs {
            let action = serde_json::json!({
                "index": {
                    "_index": index_name,
                    "_id": format!("{}:{}", doc.agent.id, doc.file.path)
                }
            });

            if let (Ok(action_str), Ok(doc_str)) = (serde_json::to_string(&action), serde_json::to_string(doc)) {
                bulk_payload.push_str(&action_str);
                bulk_payload.push('\n');
                bulk_payload.push_str(&doc_str);
                bulk_payload.push('\n');
            }
        }

        bulk_payload
    }
}
