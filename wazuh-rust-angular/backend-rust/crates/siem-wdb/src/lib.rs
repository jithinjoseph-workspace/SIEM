pub mod wdb;
pub mod agent_db;
pub mod fim_store;
pub mod global_db;
pub mod integrity;
pub mod manager_db;
pub mod models;
pub mod rootcheck_store;
pub mod sca_store;
pub mod syscollector_store;
pub mod wire_protocol;

pub use agent_db::AgentDatabase;
pub use fim_store::FimStore;
pub use global_db::{ConnectionStatus, GlobalAgent, GlobalDb};
pub use integrity::{IntegrityChecker, RangeChecksum};
pub use manager_db::WazuhDbManager;
pub use models::{
    FimAction, FimDelta, FimEntry, FimEntryType, ScaCheckResult, ScaStatus, SysHwInfo,
    SysNetIface, SysOsInfo, SysPort, SysProgram,
};
pub use rootcheck_store::{PmEvent, PmEventStatus, RootcheckStore};
pub use sca_store::{ScaPolicyStore, ScaStore};
pub use syscollector_store::SyscollectorStore;
pub use wire_protocol::WdbWireProtocol;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_global_db_agent_lifecycle() {
        let global = GlobalDb::new();

        // 1. Manager (Agent 0) always exists by default
        let mgr = global.get_agent_info(0).expect("Agent 0 must exist");
        assert_eq!(mgr.name, "localhost");
        assert_eq!(mgr.connection_status, ConnectionStatus::Active);

        // 2. Insert new agent
        assert!(global
            .insert_agent(1, "web-server-01", Some("192.168.1.50"), None, Some("sec-key-1"), Some("dmz"))
            .is_ok());

        let agent1 = global.get_agent_info(1).expect("Agent 1 must exist");
        assert_eq!(agent1.name, "web-server-01");
        assert_eq!(agent1.connection_status, ConnectionStatus::NeverConnected);
        assert_eq!(agent1.group_name, "dmz");

        // 3. Update keepalive -> changes to Active
        assert!(global.update_agent_keepalive(1, ConnectionStatus::Active));
        let updated = global.get_agent_info(1).unwrap();
        assert_eq!(updated.connection_status, ConnectionStatus::Active);
        assert!(updated.last_keepalive.is_some());

        // 4. Update OS and Version data
        assert!(global.update_agent_data(
            1,
            Some("Ubuntu".to_string()),
            Some("24.04".to_string()),
            Some("linux".to_string()),
            Some("x86_64".to_string()),
            Some("v4.14.7".to_string()),
            Some("cfg123".to_string()),
            Some("mrg456".to_string()),
        ));

        let with_data = global.get_agent_info(1).unwrap();
        assert_eq!(with_data.os_name.as_deref(), Some("Ubuntu"));
        assert_eq!(with_data.version.as_deref(), Some("v4.14.7"));

        // 5. Add custom label
        assert!(global.set_agent_label(1, "environment", "production"));
        let with_label = global.get_agent_info(1).unwrap();
        assert_eq!(with_label.labels.get("environment").map(|s| s.as_str()), Some("production"));

        // 6. Test multi-group assignments
        assert!(global.set_agent_groups(1, vec!["dmz".to_string(), "pci-scope".to_string()]));
        let groups = global.get_agent_groups(1);
        assert_eq!(groups, vec!["dmz".to_string(), "pci-scope".to_string()]);
    }

    #[test]
    fn test_global_db_stale_disconnect() {
        let global = GlobalDb::new();
        global.insert_agent(2, "db-node", Some("10.0.0.5"), None, None, None).unwrap();
        global.update_agent_keepalive(2, ConnectionStatus::Active);

        // Disconnect threshold test: 0 seconds timeout -> disconnects immediately
        let disconnected = global.disconnect_stale_agents(-1);
        assert_eq!(disconnected, 1);

        let agent2 = global.get_agent_info(2).unwrap();
        assert_eq!(agent2.connection_status, ConnectionStatus::Disconnected);

        // Manager (Agent 0) remains Active
        let mgr = global.get_agent_info(0).unwrap();
        assert_eq!(mgr.connection_status, ConnectionStatus::Active);
    }

    #[test]
    fn test_rootcheck_store() {
        let store = RootcheckStore::new();

        store.save_event(
            "Trojan /usr/bin/netstat modified",
            1710000000,
            Some("10.5".to_string()),
            Some("1.2.3".to_string()),
        );

        assert_eq!(store.total_outstanding(), 1);

        let events = store.get_events(None);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, PmEventStatus::Outstanding);
        assert_eq!(events[0].cis.as_deref(), Some("1.2.3"));

        // Resolve event
        assert!(store.resolve_event("Trojan /usr/bin/netstat modified"));
        assert_eq!(store.total_outstanding(), 0);

        let resolved = store.get_events(Some(PmEventStatus::Resolved));
        assert_eq!(resolved.len(), 1);
    }

    #[test]
    fn test_integrity_checksum_range() {
        let items = vec![
            ("/etc/passwd", "md5_passwd_hash"),
            ("/etc/shadow", "md5_shadow_hash"),
            ("/etc/sudoers", "md5_sudoers_hash"),
        ];

        let checksum = IntegrityChecker::compute_range_checksum(&items);
        assert!(checksum.is_some());
        let range = checksum.unwrap();
        assert_eq!(range.begin, "/etc/passwd");
        assert_eq!(range.end, "/etc/sudoers");
        assert_eq!(range.count, 3);
        assert!(!range.checksum.is_empty());

        assert!(IntegrityChecker::verify_range(&items, &range.checksum));
        assert!(!IntegrityChecker::verify_range(&items, "invalid_hash"));
    }

    #[test]
    fn test_wire_protocol_commands() {
        let manager = Arc::new(WazuhDbManager::new());
        let protocol = WdbWireProtocol::new(manager.clone());

        // Global commands
        let res1 = protocol.execute_command("global insert-agent 10 app-srv-01 192.168.1.100 key123 prod");
        assert_eq!(res1, "ok");

        let res2 = protocol.execute_command("global update-keepalive 10 active");
        assert_eq!(res2, "ok");

        let res3 = protocol.execute_command("global get-agent-info 10");
        assert!(res3.starts_with("ok "));
        assert!(res3.contains("app-srv-01"));

        // Agent FIM commands
        let fim_cmd = "agent 010 fim save /etc/hosts 1024 0644 0 0 md5_hosts sha256_hosts 1710000000 12345";
        let res_fim = protocol.execute_command(fim_cmd);
        assert!(res_fim.starts_with("ok"));

        let res_fim_get = protocol.execute_command("agent 010 fim get /etc/hosts");
        assert!(res_fim_get.starts_with("ok"));
        assert!(res_fim_get.contains("/etc/hosts"));

        // Agent Rootcheck command
        let rc_cmd = "agent 010 rootcheck save Unexpected_hidden_file 1710000000 PCI-1 CIS-2";
        let res_rc = protocol.execute_command(rc_cmd);
        assert_eq!(res_rc, "ok");

        // Agent SCA command
        let sca_cmd = "agent 010 sca save cis_ubuntu_24 100 Disable_root_ssh passed";
        let res_sca = protocol.execute_command(sca_cmd);
        assert_eq!(res_sca, "ok");
    }
}
