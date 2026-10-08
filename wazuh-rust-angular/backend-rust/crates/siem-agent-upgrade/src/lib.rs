pub mod agent;
pub mod config;
pub mod manager;

pub use agent::{AgentUpgradeCommandHandler, AgentUpgradeReporter, CommandErrorCode, UpgradeResultState};
pub use config::{AgentConfigs, AgentUpgradeConfig, ManagerConfigs};
pub use manager::{
    build_response, build_wpk_file_spec, compare_wazuh_versions, parse_agent_ack_response,
    parse_message, parse_versions_content, send_wpk_to_agent, translate_arch, validate_id,
    validate_status, validate_system, validate_version, verify_sha1, AgentInfo, AgentTask,
    AgentUpgradeManager, TaskCallbacks, TaskData, UpgradeAgentStatusTask, UpgradeCommand,
    UpgradeCommander, UpgradeCustomTask, UpgradeErrorCode, UpgradeResponse, UpgradeResponseItem,
    UpgradeTask, UpgradeTransport,
};

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use sha1::Digest;
    use siem_task_manager::TaskManager;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    struct MockTransport {
        pub sent_commands: Mutex<Vec<(u32, String)>>,
        pub agent_handler: Mutex<AgentUpgradeCommandHandler>,
    }

    impl MockTransport {
        fn new(dir: std::path::PathBuf) -> Self {
            Self {
                sent_commands: Mutex::new(Vec::new()),
                agent_handler: Mutex::new(AgentUpgradeCommandHandler::new(dir)),
            }
        }
    }

    #[async_trait]
    impl UpgradeTransport for MockTransport {
        async fn send_command(&self, agent_id: u32, command_str: &str) -> Result<String, String> {
            self.sent_commands
                .lock()
                .unwrap()
                .push((agent_id, command_str.to_string()));

            let response = self
                .agent_handler
                .lock()
                .unwrap()
                .handle_raw_command(command_str);

            Ok(response)
        }
    }

    #[test]
    fn test_platform_and_system_validation() {
        // Blacklisted platform
        assert_eq!(
            validate_system("solaris", None, None, Some("x86_64")),
            Err(UpgradeErrorCode::SystemNotSupported)
        );
        assert_eq!(
            validate_system("sunos", None, None, Some("x86_64")),
            Err(UpgradeErrorCode::SystemNotSupported)
        );

        // Windows -> msi
        assert_eq!(
            validate_system("windows", None, None, Some("x86_64")).unwrap(),
            "msi"
        );

        // Darwin -> pkg
        assert_eq!(
            validate_system("darwin", None, None, Some("x86_64")).unwrap(),
            "pkg"
        );

        // Linux deb & rpm
        assert_eq!(
            validate_system("ubuntu", Some("22"), Some("04"), Some("x86_64")).unwrap(),
            "deb"
        );
        assert_eq!(
            validate_system("debian", Some("12"), None, Some("x86_64")).unwrap(),
            "deb"
        );
        assert_eq!(
            validate_system("rhel", Some("8"), None, Some("x86_64")).unwrap(),
            "rpm"
        );

        // Unsupported old Linux versions
        assert_eq!(
            validate_system("centos", Some("5"), None, Some("x86_64")),
            Err(UpgradeErrorCode::SystemNotSupported)
        );
    }

    #[test]
    fn test_version_validation() {
        let manager_ver = "v4.14.7";

        // Agent 0 is manager ID -> rejected
        assert_eq!(validate_id(0), Err(UpgradeErrorCode::InvalidActionForManager));
        assert!(validate_id(1).is_ok());

        // Inactive connection status -> rejected
        assert_eq!(validate_status("disconnected"), Err(UpgradeErrorCode::AgentIsNotActive));
        assert!(validate_status("active").is_ok());

        // Below minimal version
        assert_eq!(
            validate_version("v2.9.0", "linux", "v4.14.7", manager_ver, false),
            Err(UpgradeErrorCode::NotMinimalVersionSupported)
        );

        // Target version lower or equal than current (without force)
        assert_eq!(
            validate_version("v4.5.0", "linux", "v4.5.0", manager_ver, false),
            Err(UpgradeErrorCode::NewVersionLeesOrEqualThatCurrent)
        );

        // Target version greater than manager (without force)
        assert_eq!(
            validate_version("v4.5.0", "linux", "v4.15.0", manager_ver, false),
            Err(UpgradeErrorCode::NewVersionGreaterMaster)
        );

        // Allowed valid upgrade
        assert!(validate_version("v4.5.0", "linux", "v4.14.7", manager_ver, false).is_ok());

        // Force upgrade bypasses version restrictions
        assert!(validate_version("v4.5.0", "linux", "v4.5.0", manager_ver, true).is_ok());
        assert!(validate_version("v4.5.0", "linux", "v4.15.0", manager_ver, true).is_ok());
    }

    #[test]
    fn test_architecture_translation() {
        assert_eq!(translate_arch("darwin", "pkg", "x86_64"), "intel64");
        assert_eq!(translate_arch("darwin", "pkg", "aarch64"), "arm64");
        assert_eq!(translate_arch("ubuntu", "deb", "x86_64"), "amd64");
        assert_eq!(translate_arch("ubuntu", "deb", "aarch64"), "arm64");
        assert_eq!(translate_arch("rhel", "rpm", "x86_64"), "x86_64");
    }

    #[test]
    fn test_wpk_spec_builder() {
        let (path, file) = build_wpk_file_spec(
            "packages.wazuh.com/4.x/wpk",
            "v4.14.7",
            "linux",
            "deb",
            "x86_64",
            Some("22"),
            Some("04"),
        );
        assert_eq!(path, "https://packages.wazuh.com/4.x/wpk/linux/deb/amd64/");
        assert_eq!(file, "wazuh_agent_v4.14.7_linux_amd64.deb.wpk");

        let (win_path, win_file) = build_wpk_file_spec(
            "packages.wazuh.com/4.x/wpk",
            "v4.14.7",
            "windows",
            "msi",
            "x86_64",
            None,
            None,
        );
        assert_eq!(win_path, "https://packages.wazuh.com/4.x/wpk/windows/");
        assert_eq!(win_file, "wazuh_agent_v4.14.7_windows.wpk");
    }

    #[test]
    fn test_versions_content_parsing() {
        let versions_file = "v4.14.0 a1b2c3d4e5f6071829304152637485960718293a\nv4.14.7 b6c7d8e9f01234567890abcdef1234567890abcd\n";
        let sha1 = parse_versions_content(versions_file, "v4.14.7");
        assert_eq!(sha1, Some("b6c7d8e9f01234567890abcdef1234567890abcd".to_string()));
    }

    #[tokio::test]
    async fn test_end_to_end_upgrade_streaming() {
        let tmp = tempdir().unwrap();
        let agent_dir = tmp.path().to_path_buf();

        let transport = Arc::new(MockTransport::new(agent_dir.clone()));
        let task_manager = Arc::new(TaskManager::new());
        let callbacks = Arc::new(TaskCallbacks::new(task_manager));
        let commander = UpgradeCommander::new(
            transport.clone(),
            callbacks,
            "v4.14.7",
            128, // Small chunk size to verify multi-chunk streaming
        );

        let agent = AgentInfo {
            agent_id: 1,
            platform: "ubuntu".to_string(),
            major_version: Some("22".to_string()),
            minor_version: Some("04".to_string()),
            architecture: "x86_64".to_string(),
            wazuh_version: "v4.12.0".to_string(),
            connection_status: "active".to_string(),
            package_type: Some("deb".to_string()),
        };

        // Create dummy WPK data (500 bytes -> 4 chunks of 128 bytes)
        let dummy_wpk = vec![0xAB; 500];
        let mut hasher = sha1::Sha1::new();
        hasher.update(&dummy_wpk);
        let expected_sha1 = format!("{:02x}", hasher.finalize());

        let task = UpgradeTask {
            wpk_repository: Some("packages.wazuh.com/4.x/wpk".to_string()),
            custom_version: Some("v4.14.7".to_string()),
            use_http: false,
            force_upgrade: false,
            wpk_version: None,
            wpk_file: None,
            wpk_sha1: None,
            package_type: None,
        };

        let results = commander
            .process_upgrade(&[agent], &task, |_wpk_file| {
                Some((dummy_wpk.clone(), expected_sha1.clone()))
            })
            .await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].error, 0);
        assert_eq!(results[0].status.as_deref(), Some("In progress"));

        // Verify sent commands sequence
        let cmds = transport.sent_commands.lock().unwrap();
        assert!(cmds.iter().any(|(_, c)| c.contains("lock_restart")));
        assert!(cmds.iter().any(|(_, c)| c.contains("open")));
        assert!(cmds.iter().any(|(_, c)| c.contains("write")));
        assert!(cmds.iter().any(|(_, c)| c.contains("close")));
        assert!(cmds.iter().any(|(_, c)| c.contains("sha1")));
        assert!(cmds.iter().any(|(_, c)| c.contains("upgrade")));

        // Agent reporter checks
        let reporter = AgentUpgradeReporter::new(agent_dir);
        let res_state = reporter.check_upgrade_result();
        assert_eq!(res_state, Some(UpgradeResultState::Successful));

        let ack = reporter.build_ack_payload(res_state.unwrap());
        assert_eq!(ack.parameters.status, "Done");
        assert_eq!(ack.parameters.error_code, 0);

        // Erase result file
        assert!(reporter.clear_upgrade_result().is_ok());
        assert_eq!(reporter.check_upgrade_result(), None);
    }
}
