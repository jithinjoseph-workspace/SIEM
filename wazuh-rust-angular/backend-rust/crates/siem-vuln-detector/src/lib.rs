pub mod cve_model;
pub mod feed_database;
pub mod feed_importer;
pub mod hotfix_matcher;
pub mod os_scanner;
pub mod policy;
pub mod scanner;
pub mod version_matcher;

pub use cve_model::{
    CveVulnerability, CvssScore, DetectionStatus, PackageInfo, Severity, VulnerabilityDetection,
};
pub use feed_database::VulnerabilityFeed;
pub use feed_importer::{FeedImporter, JsonFeedBundle, JsonFeedEntry};
pub use hotfix_matcher::{Hotfix, HotfixDatabase};
pub use os_scanner::{OsInfo, OsScanner, OsVulnerability};
pub use policy::ScannerPolicy;
pub use scanner::{ScannerConfig, VulnerabilityScanner};
pub use version_matcher::{matches_version_range, ParsedVersion, VersionConstraint, VersionOp};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_scanner_detects_xz_backdoor() {
        let scanner = VulnerabilityScanner::with_default_feed();

        let vulnerable_pkg = PackageInfo::new("xz-utils", "5.6.0");
        let detections = scanner.scan_package(&vulnerable_pkg, "agent-001", "ubuntu-prod-srv");

        assert_eq!(detections.len(), 1);
        let det = &detections[0];
        assert_eq!(det.cve_id, "CVE-2024-3094");
        assert_eq!(det.severity, Severity::Critical);
        assert_eq!(det.fixed_version.as_deref(), Some("5.6.2"));
        assert_eq!(det.status, DetectionStatus::Active);
    }

    #[test]
    fn test_scanner_passes_patched_xz() {
        let scanner = VulnerabilityScanner::with_default_feed();

        // 5.6.2 is patched
        let patched_pkg = PackageInfo::new("xz-utils", "5.6.2");
        let detections = scanner.scan_package(&patched_pkg, "agent-001", "ubuntu-prod-srv");
        assert!(detections.is_empty());

        // 5.4.5 is earlier and not in the backdoored range (>= 5.6.0, < 5.6.2)
        let older_safe_pkg = PackageInfo::new("xz-utils", "5.4.5");
        let detections_old = scanner.scan_package(&older_safe_pkg, "agent-001", "ubuntu-prod-srv");
        assert!(detections_old.is_empty());
    }

    #[test]
    fn test_scanner_inventory_multi_cve() {
        let scanner = VulnerabilityScanner::with_default_feed();

        let inventory = vec![
            PackageInfo::new("curl", "7.74.0"),            // affected by CVE-2023-38545 (< 8.4.0)
            PackageInfo::new("sudo", "1.8.31"),            // affected by CVE-2021-3156 Baron Samedit (< 1.9.5p2)
            PackageInfo::new("openssh-server", "8.9p1"),   // affected by CVE-2024-6387 regreSSHion (< 9.8)
            PackageInfo::new("nginx", "1.24.0"),           // patched (CVE was < 1.20.1)
        ];

        let detections = scanner.scan_inventory(&inventory, "agent-002", "debian-web-01");
        assert_eq!(detections.len(), 3);

        let cves: Vec<String> = detections.into_iter().map(|d| d.cve_id).collect();
        assert!(cves.contains(&"CVE-2023-38545".to_string()));
        assert!(cves.contains(&"CVE-2021-3156".to_string()));
        assert!(cves.contains(&"CVE-2024-6387".to_string()));
    }

    #[test]
    fn test_scanner_min_severity_filter() {
        let mut config = ScannerConfig::default();
        config.min_severity = Severity::Critical;

        let scanner = VulnerabilityScanner::new(
            Arc::new(std::sync::RwLock::new(VulnerabilityFeed::new_with_builtin_feed())),
            config,
        );

        let inventory = vec![
            PackageInfo::new("sudo", "1.8.31"),          // Severity: High
            PackageInfo::new("openssh-server", "8.9p1"), // Severity: Critical
        ];

        let detections = scanner.scan_inventory(&inventory, "agent-003", "bastion-host");
        // Only openssh-server (Critical) should match, sudo (High) should be filtered out
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].cve_id, "CVE-2024-6387");
    }

    #[test]
    fn test_scanner_diff_resolved_after_upgrade() {
        let scanner = VulnerabilityScanner::with_default_feed();

        let scan_1 = scanner.scan_package(
            &PackageInfo::new("openssh-server", "8.9p1"),
            "agent-001",
            "srv-01",
        );
        assert_eq!(scan_1.len(), 1);

        // Administrator upgraded openssh-server to 9.8p1
        let scan_2 = scanner.scan_package(
            &PackageInfo::new("openssh-server", "9.8p1"),
            "agent-001",
            "srv-01",
        );
        assert_eq!(scan_2.len(), 0);

        // Diff scans tracks state change
        let (active, resolved) = VulnerabilityScanner::diff_scans(&scan_1, &scan_2);
        assert_eq!(active.len(), 0);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].cve_id, "CVE-2024-6387");
        assert_eq!(resolved[0].status, DetectionStatus::Resolved);
    }

    #[test]
    fn test_os_scanner_dirty_pipe_and_hotfix_mitigation() {
        let scanner = OsScanner::new();

        // 1. Linux Kernel 5.10 -> Dirty Pipe (CVE-2022-0847)
        let linux_os = OsInfo::new("linux", "Ubuntu", "20.04").with_kernel("5.10.0-1057-oem");
        let detections = scanner.scan_os(&linux_os, "agent-001", "ubuntu-prod");
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].cve_id, "CVE-2022-0847");

        // 2. Windows 10 without hotfix -> PrintNightmare (CVE-2021-34527)
        let win_unpatched = OsInfo::new("windows", "Microsoft Windows 10 Pro", "10.0.19044");
        let win_detections = scanner.scan_os(&win_unpatched, "agent-002", "win-desktop");
        let cves: Vec<String> = win_detections.into_iter().map(|d| d.cve_id).collect();
        assert!(cves.contains(&"CVE-2021-34527".to_string()));

        // 3. Windows 10 WITH hotfix KB5005565 -> Mitigated / suppressed
        let win_patched = OsInfo::new("windows", "Microsoft Windows 10 Pro", "10.0.19044")
            .with_hotfixes(vec![Hotfix::new("KB5005565")]);
        let win_patched_detections = scanner.scan_os(&win_patched, "agent-002", "win-desktop");
        let patched_cves: Vec<String> = win_patched_detections.into_iter().map(|d| d.cve_id).collect();
        assert!(!patched_cves.contains(&"CVE-2021-34527".to_string()));
    }

    #[test]
    fn test_policy_manager_filtering() {
        let mut policy = ScannerPolicy::default();
        policy.ignore_cve("CVE-2021-34527");
        policy.min_severity = Severity::High;

        assert!(policy.is_cve_ignored("CVE-2021-34527"));
        assert!(!policy.is_cve_ignored("CVE-2024-3094"));
        assert!(!policy.should_alert(Severity::Medium, Some(5.0)));
        assert!(policy.should_alert(Severity::Critical, Some(9.8)));
    }

    #[test]
    fn test_feed_importer_json_bundle() {
        let mut feed = VulnerabilityFeed::new();
        let json_feed = r#"{
            "version": "1.0",
            "vendor": "Canonical",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2023-4911",
                    "package_name": "glibc",
                    "version_constraint": "< 2.35-0ubuntu3.4",
                    "fixed_version": "2.35-0ubuntu3.4",
                    "severity": "HIGH",
                    "cvss_score": 7.8,
                    "title": "Looney Tunables Glibc Privilege Escalation",
                    "description": "Buffer overflow in ld.so dynamic linker",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-4911"]
                }
            ]
        }"#;

        let count = FeedImporter::import_json(&mut feed, json_feed).unwrap();
        assert_eq!(count, 1);

        let candidates = feed.find_by_package("glibc").expect("glibc found");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].cve_id, "CVE-2023-4911");
    }
}
