use siem_vuln_detector::{
    CveVulnerability, DetectionStatus, Hotfix, HotfixDatabase, OsInfo, OsScanner, OsVulnerability,
    PackageInfo, Severity, VulnerabilityFeed, VulnerabilityScanner,
};
use std::sync::Arc;

/// Integration test verifying efficacy using Wazuh QA test scenarios from:
/// wazuh/wazuh-4.14.7/src/wazuh_modules/vulnerability_scanner/qa/test_data/
#[test]
fn test_wazuh_qa_tc001_debian_bookworm_libldb2() {
    // TC-001:
    // Package: libldb2
    // CVE-2023-34966 condition: Package less than 2:2.6.2+samba4.17.10+dfsg-0+deb12u1
    let mut feed = VulnerabilityFeed::new();
    feed.add_cve(CveVulnerability {
        cve_id: "CVE-2023-34966".to_string(),
        title: "CVE-2023-34966 affects libldb2".to_string(),
        description: "An infinite loop vulnerability was found in Samba mdssvc RPC service".to_string(),
        package_name: "libldb2".to_string(),
        affected_version_range: "< 2:2.6.2+samba4.17.10+dfsg-0+deb12u1".to_string(),
        fixed_version: Some("2:2.6.2+samba4.17.10+dfsg-0+deb12u1".to_string()),
        severity: Severity::High,
        cvss: None,
        references: vec!["https://www.debian.org/security/2023/dsa-5477".to_string()],
        mitre_technique: None,
    });

    let scanner = VulnerabilityScanner::new(Arc::new(std::sync::RwLock::new(feed)), Default::default());

    // 1. Safe package from input_002.json: 2:2.6.2+samba4.17.12+dfsg-0+deb12u1 >= 2:2.6.2+samba4.17.10
    let safe_pkg = PackageInfo::new("libldb2", "2:2.6.2+samba4.17.12+dfsg-0+deb12u1");
    let safe_results = scanner.scan_package(&safe_pkg, "001", "debian-agent");
    assert!(
        safe_results.is_empty(),
        "TC-001: 2:2.6.2+samba4.17.12 must NOT be vulnerable to CVE-2023-34966"
    );

    // 2. Vulnerable package from input_003.json: 2:2.6.2+samba4.17.9+dfsg-0+deb12u1 < 2:2.6.2+samba4.17.10
    let vuln_pkg = PackageInfo::new("libldb2", "2:2.6.2+samba4.17.9+dfsg-0+deb12u1");
    let vuln_results = scanner.scan_package(&vuln_pkg, "001", "debian-agent");
    assert_eq!(vuln_results.len(), 1, "TC-001: Must detect CVE-2023-34966");
    assert_eq!(vuln_results[0].cve_id, "CVE-2023-34966");
    assert_eq!(vuln_results[0].status, DetectionStatus::Active);
}

#[test]
fn test_wazuh_qa_tc002_redhat_centos_nss() {
    // TC-002:
    // Package: nss
    // Condition: < 3.53.1-7.el7_9
    let mut feed = VulnerabilityFeed::new();
    feed.add_cve(CveVulnerability {
        cve_id: "CVE-2020-25648".to_string(),
        title: "CVE-2020-25648 affects nss".to_string(),
        description: "A flaw was found in NSS in TLS 1.3 ClientHello handling".to_string(),
        package_name: "nss".to_string(),
        affected_version_range: "< 3.53.1-7.el7_9".to_string(),
        fixed_version: Some("3.53.1-7.el7_9".to_string()),
        severity: Severity::Medium,
        cvss: None,
        references: vec![],
        mitre_technique: None,
    });

    let scanner = VulnerabilityScanner::new(Arc::new(std::sync::RwLock::new(feed)), Default::default());

    // Vulnerable version from input: 3.53.1-3.el7_9
    let pkg = PackageInfo::new("nss", "3.53.1-3.el7_9");
    let results = scanner.scan_package(&pkg, "002", "centos7-agent");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].cve_id, "CVE-2020-25648");
}

#[test]
fn test_wazuh_qa_tc003_ubuntu_networkd_dispatcher() {
    // TC-003:
    // Package: networkd-dispatcher
    // Condition from TC-003 expected_002.out: < 0:2.1-2~ubuntu20.04.2
    let mut feed = VulnerabilityFeed::new();
    feed.add_cve(CveVulnerability {
        cve_id: "CVE-2022-29800".to_string(),
        title: "CVE-2022-29800 affects networkd-dispatcher".to_string(),
        description: "A time-of-check-to-time-of-use flaw in networkd-dispatcher".to_string(),
        package_name: "networkd-dispatcher".to_string(),
        affected_version_range: "< 0:2.1-2~ubuntu20.04.2".to_string(),
        fixed_version: Some("0:2.1-2~ubuntu20.04.2".to_string()),
        severity: Severity::Medium,
        cvss: None,
        references: vec!["https://ubuntu.com/security/CVE-2022-29800".to_string()],
        mitre_technique: None,
    });

    let scanner = VulnerabilityScanner::new(Arc::new(std::sync::RwLock::new(feed)), Default::default());

    // input_002.json: 2.1-1~ubuntu20.04.3 is vulnerable
    let pkg = PackageInfo::new("networkd-dispatcher", "2.1-1~ubuntu20.04.3");
    let results = scanner.scan_package(&pkg, "003", "ubuntu-agent");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].cve_id, "CVE-2022-29800");
}

#[test]
fn test_wazuh_qa_tc004_archlinux_openssh_regresshion() {
    // TC-004:
    // Package: openssh
    // CVE-2024-6387 regreSSHion affected: >= 8.5p1, < 9.8p1
    let mut feed = VulnerabilityFeed::new();
    feed.add_cve(CveVulnerability {
        cve_id: "CVE-2024-6387".to_string(),
        title: "regreSSHion: Remote Unauthenticated Code Execution in OpenSSH".to_string(),
        description: "Signal handler race condition in OpenSSH server (sshd)".to_string(),
        package_name: "openssh".to_string(),
        affected_version_range: ">= 8.5p1, < 9.8p1".to_string(),
        fixed_version: Some("9.8p1-1".to_string()),
        severity: Severity::Critical,
        cvss: None,
        references: vec![],
        mitre_technique: None,
    });

    let scanner = VulnerabilityScanner::new(Arc::new(std::sync::RwLock::new(feed)), Default::default());

    // 1. Vulnerable version: 9.7p1-2
    let vuln_pkg = PackageInfo::new("openssh", "9.7p1-2");
    let vuln_res = scanner.scan_package(&vuln_pkg, "004", "arch-srv");
    assert_eq!(vuln_res.len(), 1);
    assert_eq!(vuln_res[0].cve_id, "CVE-2024-6387");

    // 2. Patched version: 9.8p1-1
    let safe_pkg = PackageInfo::new("openssh", "9.8p1-1");
    let safe_res = scanner.scan_package(&safe_pkg, "004", "arch-srv");
    assert!(safe_res.is_empty());

    // 3. Diff scan verifies Resolved transition
    let (active, resolved) = VulnerabilityScanner::diff_scans(&vuln_res, &safe_res);
    assert!(active.is_empty());
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].status, DetectionStatus::Resolved);
}

#[test]
fn test_wazuh_qa_tc007_macos_os_upgrade_resolution() {
    // TC-007:
    // OS Vulnerability: CVE-2024-23224 affecting macOS < 14.3
    let mut os_scanner = OsScanner::new();
    os_scanner.add_os_vulnerability(OsVulnerability {
        cve_id: "CVE-2024-23224".to_string(),
        title: "Apple macOS Kernel Memory Corruption".to_string(),
        target_platform: "darwin".to_string(),
        target_os_name: Some("macOS".to_string()),
        kernel_range: None,
        os_version_range: Some("< 14.3".to_string()),
        required_hotfix: None,
        severity: Severity::High,
        cvss_score: Some(8.2),
        description: "An issue was addressed with improved memory handling in macOS Sonoma".to_string(),
        mitre_technique: None,
    });

    // 1. macOS 14.0 is vulnerable
    let macos_14_0 = OsInfo::new("darwin", "macOS", "14.0");
    let res_14_0 = os_scanner.scan_os(&macos_14_0, "007", "macbook-pro");
    assert_eq!(res_14_0.len(), 1);
    assert_eq!(res_14_0[0].cve_id, "CVE-2024-23224");

    // 2. macOS 14.3 is upgraded and safe
    let macos_14_3 = OsInfo::new("darwin", "macOS", "14.3");
    let res_14_3 = os_scanner.scan_os(&macos_14_3, "007", "macbook-pro");
    assert!(res_14_3.is_empty());

    // 3. Diff scans verify Resolved state
    let (active, resolved) = VulnerabilityScanner::diff_scans(&res_14_0, &res_14_3);
    assert!(active.is_empty());
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].status, DetectionStatus::Resolved);
}

#[test]
fn test_wazuh_qa_tc011_windows_hotfix_remediation() {
    // TC-011:
    // Package: Skype for Business Basic 2016
    // CVE-2016-0145 remediated by hotfix KB3114948
    let mut hotfix_db = HotfixDatabase::new();
    hotfix_db.add_remediation("CVE-2016-0145", "KB3114948");

    // Agent without hotfix
    let unpatched_kbs = vec![Hotfix::new("KB4012212")];
    assert!(
        !hotfix_db.is_cve_remediated("CVE-2016-0145", &unpatched_kbs),
        "Without KB3114948, CVE-2016-0145 must remain active"
    );

    // Agent installs KB3114948
    let patched_kbs = vec![Hotfix::new("KB4012212"), Hotfix::new("KB3114948")];
    assert!(
        hotfix_db.is_cve_remediated("CVE-2016-0145", &patched_kbs),
        "With KB3114948 installed, CVE-2016-0145 must be remediated"
    );
}
