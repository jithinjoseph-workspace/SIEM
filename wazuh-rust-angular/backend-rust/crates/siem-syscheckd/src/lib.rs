pub mod config;
pub mod diff_engine;
pub mod engine;
pub mod realtime;
pub mod registry;
pub mod syscom;
pub mod whodata;

pub use config::{
    MonitoredDirectory, SyscheckConfig, CHECK_ALL, CHECK_FOLLOW_SYMLINK, CHECK_GROUP,
    CHECK_INODE, CHECK_MD5SUM, CHECK_MTIME, CHECK_OWNER, CHECK_PERM, CHECK_REALTIME,
    CHECK_SEECHANGES, CHECK_SHA1SUM, CHECK_SHA256SUM, CHECK_SIZE, CHECK_WHODATA,
};
pub use diff_engine::DiffEngine;
pub use engine::{FimAlert, SyscheckEngine};
pub use realtime::{RealtimeEvent, RealtimeWatcher};
pub use registry::{RegistryAction, RegistryDelta, RegistryMonitor, RegistryValue};
pub use syscom::{SyscheckStatus, SyscomCommand, SyscomHandler};
pub use whodata::WhodataInfo;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_xml_parsing() {
        let xml = r#"
        <syscheck>
            <disabled>no</disabled>
            <frequency>7200</frequency>
            <scan_on_start>yes</scan_on_start>
            <max_files_per_second>500</max_files_per_second>
            <directories check_all="yes" realtime="yes" report_changes="yes">/etc,/usr/bin</directories>
            <ignore>/etc/mtab</ignore>
            <nodiff>/etc/shadow</nodiff>
        </syscheck>
        "#;

        let cfg = SyscheckConfig::parse_xml(xml).expect("Must parse valid syscheck XML");
        assert!(!cfg.disabled);
        assert_eq!(cfg.frequency, 7200);
        assert!(cfg.scan_on_start);
        assert_eq!(cfg.max_files_per_second, 500);
        assert_eq!(cfg.directories.len(), 2);

        let dir1 = &cfg.directories[0];
        assert_eq!(dir1.path, std::path::PathBuf::from("/etc"));
        assert!(dir1.has_opt(CHECK_ALL));
        assert!(dir1.has_opt(CHECK_REALTIME));
        assert!(dir1.has_opt(CHECK_SEECHANGES));

        assert!(cfg.is_ignored("/etc/mtab"));
        assert!(!cfg.is_ignored("/etc/passwd"));
        assert!(cfg.is_nodiff("/etc/shadow"));
        assert!(!cfg.is_nodiff("/etc/hosts"));
    }

    #[test]
    fn test_diff_engine_unified_diff() {
        let old_content = "server_name example.com;\nlisten 80;\n";
        let new_content = "server_name secure.example.com;\nlisten 443 ssl;\n";

        let diff = DiffEngine::compute_unified_diff(old_content, new_content, "/etc/nginx/nginx.conf");
        assert!(diff.contains("--- /etc/nginx/nginx.conf (original)"));
        assert!(diff.contains("+++ /etc/nginx/nginx.conf (current)"));
        assert!(diff.contains("-server_name example.com;"));
        assert!(diff.contains("+server_name secure.example.com;"));
        assert!(diff.contains("-listen 80;"));
        assert!(diff.contains("+listen 443 ssl;"));
    }

    #[test]
    fn test_registry_monitor() {
        let monitor = RegistryMonitor::new();

        let val1 = RegistryValue {
            key_path: r"HKLM\Software\Wazuh".to_string(),
            name: "Version".to_string(),
            val_type: "REG_SZ".to_string(),
            data: "4.14.7".to_string(),
            hash: "hash_4_14_7".to_string(),
        };

        // Added
        let delta1 = monitor.upsert_value(val1).unwrap();
        assert_eq!(delta1.action, RegistryAction::Added);

        // Unchanged -> returns None
        let val1_repeat = RegistryValue {
            key_path: r"HKLM\Software\Wazuh".to_string(),
            name: "Version".to_string(),
            val_type: "REG_SZ".to_string(),
            data: "4.14.7".to_string(),
            hash: "hash_4_14_7".to_string(),
        };
        assert!(monitor.upsert_value(val1_repeat).is_none());

        // Modified
        let val1_mod = RegistryValue {
            key_path: r"HKLM\Software\Wazuh".to_string(),
            name: "Version".to_string(),
            val_type: "REG_SZ".to_string(),
            data: "4.15.0".to_string(),
            hash: "hash_4_15_0".to_string(),
        };
        let delta2 = monitor.upsert_value(val1_mod).unwrap();
        assert_eq!(delta2.action, RegistryAction::Modified);
        assert_eq!(delta2.old_value.unwrap().data, "4.14.7");

        // Deleted
        let delta3 = monitor.delete_value(r"HKLM\Software\Wazuh", "Version").unwrap();
        assert_eq!(delta3.action, RegistryAction::Deleted);
        assert_eq!(monitor.total_entries(), 0);
    }

    #[test]
    fn test_syscom_command_parsing() {
        assert_eq!(SyscomHandler::parse_command("syscheck check_now"), Some(SyscomCommand::CheckNow));
        assert_eq!(SyscomHandler::parse_command("syscheck restart"), Some(SyscomCommand::Restart));
        assert_eq!(SyscomHandler::parse_command("syscheck status"), Some(SyscomCommand::Status));
        assert_eq!(SyscomHandler::parse_command("unknown"), None);
    }

    #[test]
    fn test_engine_scan_and_diff_generation() {
        let tmp = tempdir().unwrap();
        let mon_dir = tmp.path().join("monitored");
        let diff_dir = tmp.path().join("diffs");
        std::fs::create_dir_all(&mon_dir).unwrap();
        std::fs::create_dir_all(&diff_dir).unwrap();

        let test_file = mon_dir.join("test_config.cfg");
        std::fs::write(&test_file, "option_a=1\noption_b=2\n").unwrap();

        let mut cfg = SyscheckConfig::default();
        cfg.directories.push(MonitoredDirectory::new(
            &mon_dir,
            CHECK_ALL | CHECK_SEECHANGES,
        ));

        let engine = SyscheckEngine::new(cfg, diff_dir);

        // 1. Initial scan -> discovers new file (Added)
        let alerts1 = engine.run_integrity_scan();
        assert_eq!(alerts1.len(), 1);
        assert_eq!(alerts1[0].delta.action, siem_wdb::FimAction::Added);
        assert!(alerts1[0].diff.is_none());

        // 2. Second scan without file changes -> 0 alerts
        let alerts2 = engine.run_integrity_scan();
        assert_eq!(alerts2.len(), 0);

        // 3. Modify file content
        std::fs::write(&test_file, "option_a=1\noption_b=999\n").unwrap();

        let alerts3 = engine.run_integrity_scan();
        assert_eq!(alerts3.len(), 1);
        assert_eq!(alerts3[0].delta.action, siem_wdb::FimAction::Modified);

        // Verify diff was generated
        let diff = alerts3[0].diff.as_ref().expect("Diff must be generated for report_changes");
        assert!(diff.contains("-option_b=2"));
        assert!(diff.contains("+option_b=999"));

        // Status verification
        let status = engine.get_status();
        assert!(!status.is_scanning);
        assert!(status.last_scan_time.is_some());
        assert_eq!(status.files_monitored, 1);
    }
}
