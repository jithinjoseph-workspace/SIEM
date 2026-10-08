pub mod fim_orchestrator;
pub mod harvester;
pub mod system_orchestrator;
pub mod wcs_model;

pub use fim_orchestrator::FimInventoryOrchestrator;
pub use harvester::{HarvesterConfig, InventoryHarvester};
pub use system_orchestrator::SystemInventoryOrchestrator;
pub use wcs_model::{
    WcsAgent, WcsFile, WcsFimDocument, WcsHost, WcsInventoryDocument, WcsPackage, WcsPort,
    WcsProcess,
};

#[cfg(test)]
mod tests {
    use super::*;
    use siem_syscollector::{SyncDelta, SyncOperation};
    use siem_wdb::models::{FimEntry, FimEntryType};

    #[test]
    fn test_system_inventory_orchestrator_wcs_transformation() {
        let agent = WcsAgent {
            id: "001".to_string(),
            name: "ubuntu-server".to_string(),
            ip: Some("192.168.1.50".to_string()),
            version: Some("4.14.7".to_string()),
            cluster: Some("wazuh-cluster".to_string()),
        };

        let host = WcsHost {
            hostname: "ubuntu-server".to_string(),
            architecture: "x86_64".to_string(),
            os_name: "Ubuntu".to_string(),
            os_version: "22.04".to_string(),
            os_platform: "linux".to_string(),
        };

        let delta = SyncDelta {
            table: "packages".to_string(),
            operation: SyncOperation::Inserted,
            item_id: "e4d909c290d0fb1ca068ffaddf22cbd0add91".to_string(),
            checksum: "a1b2c3d4e5f6".to_string(),
            data: serde_json::json!({
                "name": "nginx",
                "version": "1.24.0",
                "architecture": "x86_64"
            }),
        };

        let wcs_doc = SystemInventoryOrchestrator::delta_to_wcs(&agent, &host, &delta);
        assert_eq!(wcs_doc.agent.id, "001");
        assert_eq!(wcs_doc.data_type, "packages");
        assert_eq!(wcs_doc.operation, "INSERTED");
        assert_eq!(wcs_doc.data["name"], "nginx");

        // Test bulk exporter format
        let harvester = InventoryHarvester::default();
        let bulk_output = harvester.format_inventory_opensearch_bulk(&[wcs_doc], "default");
        assert!(bulk_output.contains("wazuh-states-inventory-default"));
        assert!(bulk_output.contains("001:e4d909c290d0fb1ca068ffaddf22cbd0add91"));
        assert!(bulk_output.contains("\"name\":\"nginx\""));
    }

    #[test]
    fn test_fim_orchestrator_wcs_transformation() {
        let agent = WcsAgent {
            id: "002".to_string(),
            name: "web-srv".to_string(),
            ip: None,
            version: None,
            cluster: None,
        };

        let entry = FimEntry {
            full_path: "/etc/shadow".to_string(),
            file_name: "shadow".to_string(),
            entry_type: FimEntryType::File,
            size: Some(1024),
            perm: Some("0640".to_string()),
            uid: Some("root".to_string()),
            gid: Some("shadow".to_string()),
            md5: Some("d41d8cd98f00b204e9800998ecf8427e".to_string()),
            sha1: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string()),
            sha256: Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()),
            mtime: 1727352000,
            inode: None,
            changes: 1,
            date: 1727352000,
        };

        let fim_doc = FimInventoryOrchestrator::fim_entry_to_wcs(&agent, &entry, "MODIFIED");
        assert_eq!(fim_doc.agent.id, "002");
        assert_eq!(fim_doc.file.path, "/etc/shadow");
        assert_eq!(fim_doc.operation, "MODIFIED");

        let harvester = InventoryHarvester::default();
        let bulk_output = harvester.format_fim_opensearch_bulk(&[fim_doc], "default");
        assert!(bulk_output.contains("wazuh-states-fim-default"));
        assert!(bulk_output.contains("/etc/shadow"));
    }
}
