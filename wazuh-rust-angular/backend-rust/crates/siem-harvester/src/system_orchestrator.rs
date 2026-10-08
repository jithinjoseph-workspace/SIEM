use crate::wcs_model::{WcsAgent, WcsHost, WcsInventoryDocument};
use chrono::Utc;
use siem_syscollector::SyncDelta;

/// System Inventory Orchestrator ported from Wazuh src/systemInventoryOrchestrator.hpp.
pub struct SystemInventoryOrchestrator;

impl SystemInventoryOrchestrator {
    /// Transforms an inventory delta into a full WCS Inventory Document.
    pub fn delta_to_wcs(
        agent: &WcsAgent,
        host: &WcsHost,
        delta: &SyncDelta,
    ) -> WcsInventoryDocument {
        let op_str = match delta.operation {
            siem_syscollector::SyncOperation::Inserted => "INSERTED",
            siem_syscollector::SyncOperation::Modified => "MODIFIED",
            siem_syscollector::SyncOperation::Deleted => "DELETED",
        };

        WcsInventoryDocument {
            timestamp: Utc::now(),
            agent: agent.clone(),
            host: host.clone(),
            data_type: delta.table.clone(),
            operation: op_str.to_string(),
            item_id: delta.item_id.clone(),
            checksum: delta.checksum.clone(),
            data: delta.data.clone(),
        }
    }

    /// Batch transforms a list of deltas.
    pub fn batch_deltas_to_wcs(
        agent: &WcsAgent,
        host: &WcsHost,
        deltas: &[SyncDelta],
    ) -> Vec<WcsInventoryDocument> {
        deltas
            .iter()
            .map(|d| Self::delta_to_wcs(agent, host, d))
            .collect()
    }
}
