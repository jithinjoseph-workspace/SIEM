pub mod collector;
pub mod delta_sync;
pub mod normalizer;
pub mod provider;
pub mod tables;

pub use collector::{SyscollectorConfig, SyscollectorEngine};
pub use delta_sync::{get_item_checksum, get_item_id, SyncDelta, SyncOperation, TableSyncCache};
pub use normalizer::SysNormalizer;
pub use provider::SysInfoProvider;
pub use tables::{
    BrowserExtensionItem, GroupItem, HardwareItem, HotfixItem, NetworkAddressItem,
    NetworkIfaceItem, NetworkProtocolItem, OsItem, PackageItem, PortItem, ProcessItem,
    ServiceItem, UserItem,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscollector_engine_package_normalization_and_delta() {
        let mut engine = SyscollectorEngine::default();

        let mut packages = vec![
            PackageItem {
                name: "libldb2".to_string(),
                version: "2:2.6.2+samba4.17.9".to_string(),
                architecture: "amd64".to_string(), // will normalize to x86_64
                format: "deb".to_string(),
                vendor: Some("Debian Samba Maintainers".to_string()), // will normalize to debian
                description: Some("LDAP-like database".to_string()),
                size: Some(72000),
                install_time: None,
            },
            PackageItem {
                name: "Siri".to_string(), // will be excluded
                version: "1.0".to_string(),
                architecture: "x86_64".to_string(),
                format: "pkg".to_string(),
                vendor: Some("Apple".to_string()),
                description: None,
                size: None,
                install_time: None,
            },
        ];

        let deltas = engine.sync_packages(&mut packages);

        // Siri should be excluded, libldb2 normalized and inserted
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].operation, SyncOperation::Inserted);
        assert_eq!(deltas[0].table, "packages");

        let normalized_data = &deltas[0].data;
        assert_eq!(normalized_data["architecture"], "x86_64");
        assert_eq!(normalized_data["vendor"], "debian");
    }

    #[test]
    fn test_syscollector_ports_delta_sync() {
        let mut engine = SyscollectorEngine::default();

        // 1. Agent starts with SSH port 22 listening
        let ports_scan_1 = vec![PortItem {
            protocol: "tcp".to_string(),
            local_ip: "0.0.0.0".to_string(),
            local_port: 22,
            remote_ip: None,
            remote_port: None,
            tx_queue: None,
            rx_queue: None,
            inode: None,
            state: "listening".to_string(),
            pid: Some(1024),
            process: Some("sshd".to_string()),
        }];

        let deltas_1 = engine.sync_ports(&ports_scan_1);
        assert_eq!(deltas_1.len(), 1);
        assert_eq!(deltas_1[0].operation, SyncOperation::Inserted);

        // 2. Attacker opens reverse shell port 4444
        let ports_scan_2 = vec![
            PortItem {
                protocol: "tcp".to_string(),
                local_ip: "0.0.0.0".to_string(),
                local_port: 22,
                remote_ip: None,
                remote_port: None,
                tx_queue: None,
                rx_queue: None,
                inode: None,
                state: "listening".to_string(),
                pid: Some(1024),
                process: Some("sshd".to_string()),
            },
            PortItem {
                protocol: "tcp".to_string(),
                local_ip: "10.0.0.5".to_string(),
                local_port: 4444,
                remote_ip: Some("198.51.100.20".to_string()),
                remote_port: Some(443),
                tx_queue: None,
                rx_queue: None,
                inode: None,
                state: "established".to_string(),
                pid: Some(4096),
                process: Some("nc".to_string()),
            },
        ];

        let deltas_2 = engine.sync_ports(&ports_scan_2);
        // Only port 4444 is new! Port 22 is unchanged and NOT resent!
        assert_eq!(deltas_2.len(), 1);
        assert_eq!(deltas_2[0].operation, SyncOperation::Inserted);
        assert_eq!(deltas_2[0].data["local_port"], 4444);
    }

    #[test]
    fn test_hotfix_sync() {
        let mut engine = SyscollectorEngine::default();

        let hf_scan = vec![
            HotfixItem {
                hotfix: "KB5005565".to_string(),
                install_time: Some("2021-09-14".to_string()),
            },
        ];

        let deltas = engine.sync_hotfixes(&hf_scan);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].operation, SyncOperation::Inserted);
        assert_eq!(deltas[0].data["hotfix"], "KB5005565");
    }

    #[test]
    fn test_users_and_services_sync() {
        let mut engine = SyscollectorEngine::default();

        let users = vec![UserItem {
            user_name: "admin".to_string(),
            user_full_name: Some("System Administrator".to_string()),
            user_home: Some("/home/admin".to_string()),
            user_id: Some(1000),
            user_uid_signed: Some(1000),
            user_uuid: None,
            user_groups: Some("admin,sudo".to_string()),
            user_group_id: Some(1000),
            user_group_id_signed: Some(1000),
            user_created: None,
            user_roles: None,
            user_shell: Some("/bin/bash".to_string()),
            user_type: None,
            user_is_hidden: Some(0),
            user_is_remote: Some(0),
            user_last_login: None,
            user_auth_failed_count: Some(0),
            user_auth_failed_timestamp: None,
            user_password_last_change: None,
            user_password_expiration_date: None,
            user_password_hash_algorithm: None,
            user_password_inactive_days: None,
            user_password_max_days_between_changes: None,
            user_password_min_days_between_changes: None,
            user_password_status: Some("active".to_string()),
            user_password_warning_days_before_expiration: None,
            process_pid: None,
            host_ip: None,
            login_status: None,
            login_tty: None,
            login_type: None,
        }];

        let user_deltas = engine.sync_users(&users);
        assert_eq!(user_deltas.len(), 1);
        assert_eq!(user_deltas[0].operation, SyncOperation::Inserted);
        assert_eq!(user_deltas[0].data["user_name"], "admin");

        let services = vec![ServiceItem {
            service_id: "wazuh-agent".to_string(),
            file_path: Some("/usr/bin/wazuh-agent".to_string()),
            service_name: Some("Wazuh Agent".to_string()),
            service_description: Some("Wazuh host agent daemon".to_string()),
            service_type: Some("service".to_string()),
            service_state: Some("running".to_string()),
            service_sub_state: None,
            service_enabled: Some("enabled".to_string()),
            service_start_type: Some("auto".to_string()),
            service_restart: None,
            service_frequency: None,
            service_starts_on_mount: None,
            service_starts_on_path_modified: None,
            service_starts_on_not_empty_directory: None,
            service_inetd_compatibility: None,
            process_pid: Some(1234),
            process_executable: Some("/usr/bin/wazuh-agent".to_string()),
            process_args: None,
            process_user_name: Some("root".to_string()),
            process_group_name: Some("root".to_string()),
            process_working_dir: None,
            process_root_dir: None,
            service_address: None,
            log_file_path: None,
            error_log_file_path: None,
            service_exit_code: None,
            service_win32_exit_code: None,
            service_following: None,
            service_object_path: None,
            service_target_ephemeral_id: None,
            service_target_type: None,
            service_target_address: None,
        }];

        let service_deltas = engine.sync_services(&services);
        assert_eq!(service_deltas.len(), 1);
        assert_eq!(service_deltas[0].operation, SyncOperation::Inserted);
        assert_eq!(service_deltas[0].data["service_id"], "wazuh-agent");
    }
}

