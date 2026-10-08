use crate::wcs_model::{WcsAgent, WcsFile, WcsFimDocument};
use chrono::Utc;
use siem_wdb::models::FimEntry;

/// FIM Inventory Orchestrator ported from Wazuh src/fimInventoryOrchestrator.hpp.
pub struct FimInventoryOrchestrator;

impl FimInventoryOrchestrator {
    /// Transforms a FIM entry into a WCS FIM state document.
    pub fn fim_entry_to_wcs(
        agent: &WcsAgent,
        entry: &FimEntry,
        operation: &str,
    ) -> WcsFimDocument {
        WcsFimDocument {
            timestamp: Utc::now(),
            agent: agent.clone(),
            file: WcsFile {
                path: entry.full_path.clone(),
                size: entry.size,
                sha1: entry.sha1.clone(),
                sha256: entry.sha256.clone(),
                md5: entry.md5.clone(),
                perm: entry.perm.clone(),
                owner: entry.uid.clone(),
                group: entry.gid.clone(),
                mtime: Some(entry.mtime.to_string()),
            },
            operation: operation.to_string(),
            checksum: entry.sha1.clone().unwrap_or_else(|| entry.full_path.clone()),
        }
    }
}
