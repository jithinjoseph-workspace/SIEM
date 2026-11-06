pub mod config;
pub mod network_checker;
pub mod process_checker;
pub mod runner;
pub mod scanner;
pub mod signatures;

pub use config::RootcheckConfig;
pub use network_checker::NetworkChecker;
pub use process_checker::ProcessChecker;
pub use runner::{RootcheckReport, RootcheckRunner};
pub use scanner::{DetectionType, RootcheckDetection, RootcheckScanner};
pub use signatures::{RootcheckDatabase, RootkitFileSignature, TrojanSignature};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_rootcheck_end_to_end() {
        let scanner = RootcheckScanner::with_default_db();

        // Check SuckIt rootkit artifact
        let res = scanner.scan_file_path("/dev/ida/.drag-on");
        assert!(res.is_some());
        let det = res.unwrap();
        assert_eq!(det.detection_type, DetectionType::RootkitFile);
        assert!(det.title.contains("SuckIt"));
    }

    #[test]
    fn test_rootcheck_config_xml_parsing() {
        let xml = r#"
        <rootcheck>
            <disabled>no</disabled>
            <check_files>yes</check_files>
            <check_trojans>yes</check_trojans>
            <check_dev>yes</check_dev>
            <check_pids>yes</check_pids>
            <check_ports>yes</check_ports>
            <check_if>yes</check_if>
            <frequency>7200</frequency>
            <rootkit_files>/etc/custom_rk_files.txt</rootkit_files>
        </rootcheck>
        "#;

        let config = RootcheckConfig::parse_xml(xml).unwrap();
        assert!(!config.disabled);
        assert!(config.check_files);
        assert!(config.check_pids);
        assert_eq!(config.frequency_secs, 7200);
        assert!(config.rootkit_files.contains(&"/etc/custom_rk_files.txt".to_string()));
    }

    #[test]
    fn test_hidden_process_detection() {
        let checker = ProcessChecker::new();

        // PID 1337 is responding to kernel probe but missing from /proc enumeration
        let visible_pids = vec![1, 2, 500, 1024];
        let responsive_pids = vec![1, 2, 500, 1024, 1337];

        let detections = checker.detect_hidden_pids(&visible_pids, &responsive_pids);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].detection_type, DetectionType::HiddenProcess);
        assert!(detections[0].target.contains("1337"));

        // Process anomaly: deleted binary
        let anomaly = checker.inspect_process_anomaly(999, "/usr/bin/miner (deleted)", "./miner");
        assert!(anomaly.is_some());
        assert_eq!(anomaly.unwrap().detection_type, DetectionType::ProcessAnomaly);
    }

    #[test]
    fn test_promiscuous_interface_detection() {
        let checker = NetworkChecker::new();

        let det = checker.check_interface_promiscuous("eth0", true, false);
        assert!(det.is_some());
        assert_eq!(det.unwrap().detection_type, DetectionType::PromiscuousInterface);

        // Loopback should be ignored even if flagged
        let lo_det = checker.check_interface_promiscuous("lo", true, true);
        assert!(lo_det.is_none());
    }

    #[test]
    fn test_rootcheck_runner_pipeline() {
        let scanner = Arc::new(RootcheckScanner::with_default_db());
        let config = RootcheckConfig::default();
        let runner = RootcheckRunner::new(config, scanner);

        let files = vec!["/bin/safe_app", "/dev/ida/.drag-on"];
        let dev_entries = vec![(".secret_rootkit", true, false), ("sda1", false, true)];
        let visible_pids = vec![1, 100];
        let responsive_pids = vec![1, 100, 666]; // 666 hidden
        let interfaces = vec![("eth0", true, false)]; // promiscuous
        let bindable_ports = vec![8080];
        let visible_ports = vec![]; // 8080 hidden

        let report = runner.run_scan(
            &files,
            &dev_entries,
            &visible_pids,
            &responsive_pids,
            &interfaces,
            &bindable_ports,
            &visible_ports,
        );

        assert!(report.scan_completed);
        assert_eq!(report.total_alerts, 5); // 1 file + 1 dev + 1 port + 1 pid + 1 if
    }
}
