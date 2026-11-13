use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use provigil_agent::osinfo::linux_os_from;
use provigil_agent::rootcheck::linux_checks::{
    check_dev_hidden, check_ld_preload, check_promiscuous_interfaces, check_uid_zero_accounts,
};
use provigil_agent::rootcheck_signatures::{
    parse_files, parse_policies, parse_trojans, LINUX_FILES, LINUX_POLICIES, LINUX_TROJANS,
};
use provigil_agent::sca::Policy;
use provigil_agent::upgrade::{linux_helper_script, UpgradeResult};

#[test]
fn linux_cis_ruleset_policies_parse_cleanly_with_unique_ids() {
    let linux_files = [
        "ubuntu/cis_ubuntu24-04.yml",
        "ubuntu/cis_ubuntu22-04.yml",
        "ubuntu/cis_ubuntu20-04.yml",
        "ubuntu/cis_ubuntu18-04.yml",
        "ubuntu/cis_ubuntu16-04.yml",
        "ubuntu/cis_ubuntu14-04.yml",
        "debian/cis_debian13.yml",
        "debian/cis_debian12.yml",
        "debian/cis_debian11.yml",
        "debian/cis_debian10.yml",
        "debian/cis_debian9.yml",
        "debian/cis_debian8.yml",
        "debian/cis_debian7.yml",
        "rhel/10/cis_rhel10_linux.yml",
        "rhel/9/cis_rhel9_linux.yml",
        "rhel/8/cis_rhel8_linux.yml",
        "rhel/7/cis_rhel7_linux.yml",
        "rhel/6/cis_rhel6_linux.yml",
        "rhel/5/cis_rhel5_linux.yml",
        "centos/10/cis_centos10_linux.yml",
        "centos/9/cis_centos9_linux.yml",
        "centos/8/cis_centos8_linux.yml",
        "centos/7/cis_centos7_linux.yml",
        "centos/6/cis_centos6_linux.yml",
        "almalinux/cis_alma_linux_10.yml",
        "almalinux/cis_alma_linux_9.yml",
        "almalinux/cis_alma_linux_8.yml",
        "rocky/cis_rocky_linux_10.yml",
        "rocky/cis_rocky_linux_9.yml",
        "rocky/cis_rocky_linux_8.yml",
        "amazon/cis_amazon_linux_2023.yml",
        "amazon/cis_amazon_linux_2.yml",
        "amazon/cis_amazon_linux_1.yml",
        "ol/10/cis_oracle_linux_10.yml",
        "ol/9/cis_oracle_linux_9.yml",
        "sles/16/cis_sles16_linux.yml",
        "sles/15/cis_sles15_linux.yml",
        "sles/12/cis_sles12_linux.yml",
        "sles/11/cis_sles11_linux.yml",
        "generic/sca_distro_independent_linux.yml",
        "nginx/cis_nginx_1.yml",
        "mongodb/cis_mongodb_36.yml",
    ];
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ruleset/sca");
    let mut policy_ids = HashSet::new();
    for rel in linux_files {
        let yaml = fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
        let p = Policy::parse(&yaml).unwrap_or_else(|e| panic!("failed to parse {rel}: {e}"));
        assert!(policy_ids.insert(p.info.id.clone()), "duplicate policy id {} in {rel}", p.info.id);
        assert!(!p.checks.is_empty(), "empty checks in {rel}");
        let mut per_policy = HashSet::new();
        for c in &p.checks {
            assert!(per_policy.insert(c.def.id), "duplicate check id {} inside {}", c.def.id, p.info.id);
            assert!(!c.def.title.is_empty(), "empty title for check {} in {}", c.def.id, p.info.id);
        }
    }
}

#[test]
fn linux_os_release_mapping_matches_schema() {
    let ubuntu = linux_os_from(
        "NAME=\"Ubuntu\"\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n",
        "6.8.0-45-generic",
        "x86_64",
        "web-01",
    );
    assert_eq!(ubuntu["os_platform"], "ubuntu");
    assert_eq!(ubuntu["os_name"], "Ubuntu");
    assert_eq!(ubuntu["os_major"], "24");
    assert_eq!(ubuntu["os_minor"], "04");
    assert_eq!(ubuntu["os_display_version"], "24.04.1 LTS (Noble Numbat)");
    assert_eq!(ubuntu["release"], "6.8.0-45-generic");
    assert_eq!(ubuntu["architecture"], "x86_64");
    assert_eq!(ubuntu["hostname"], "web-01");

    let rocky = linux_os_from(
        "NAME=\"Rocky Linux\"\nID=\"rocky\"\nVERSION_ID=\"9.4\"\nPRETTY_NAME=\"Rocky Linux 9.4 (Blue Onyx)\"\n",
        "5.14.0-427.el9.x86_64",
        "x86_64",
        "app-02",
    );
    assert_eq!(rocky["os_platform"], "rocky");
    assert_eq!(rocky["os_major"], "9");
    assert_eq!(rocky["os_minor"], "4");
}

#[test]
fn linux_rootcheck_builtins_and_detectors_work() {
    let files = parse_files(LINUX_FILES).expect("linux files signatures");
    let trojans = parse_trojans(LINUX_TROJANS).expect("linux trojans signatures");
    let policies = parse_policies(LINUX_POLICIES).expect("linux policy signatures");
    assert!(files.len() >= 25);
    assert!(trojans.len() >= 10);
    assert!(policies.len() >= 10);

    let dir = tempfile::tempdir().unwrap();

    // 1. Hidden file in /dev (ignoring .udev allowlist)
    let dev_dir = dir.path().join("dev");
    fs::create_dir_all(&dev_dir).unwrap();
    fs::write(dev_dir.join(".udev"), b"ok").unwrap();
    fs::write(dev_dir.join(".blKb"), b"evil").unwrap();
    let dev_findings = check_dev_hidden(&dev_dir);
    assert_eq!(dev_findings.len(), 1);
    assert_eq!(dev_findings[0].rule_id, 5109);
    assert!(dev_findings[0].description.contains(".blKb"));

    // 2. /etc/ld.so.preload
    let preload = dir.path().join("ld.so.preload");
    fs::write(&preload, "# comment\n/lib/libevil.so\n").unwrap();
    let preload_findings = check_ld_preload(&preload);
    assert_eq!(preload_findings.len(), 1);
    assert_eq!(preload_findings[0].rule_id, 5110);
    assert!(preload_findings[0].description.contains("/lib/libevil.so"));

    // 3. Promiscuous NIC
    let net_dir = dir.path().join("net");
    fs::create_dir_all(net_dir.join("eth0")).unwrap();
    fs::create_dir_all(net_dir.join("lo")).unwrap();
    fs::write(net_dir.join("eth0/flags"), "0x1103\n").unwrap();
    fs::write(net_dir.join("lo/flags"), "0x109\n").unwrap();
    let nic_findings = check_promiscuous_interfaces(&net_dir);
    assert_eq!(nic_findings.len(), 1);
    assert_eq!(nic_findings[0].rule_id, 5111);
    assert!(nic_findings[0].title.contains("eth0"));

    // 4. Extra UID 0 user
    let passwd = dir.path().join("passwd");
    fs::write(&passwd, "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/tmp:/bin/sh\nuser:x:1000:1000::/home/user:/bin/bash\n").unwrap();
    let uid0_findings = check_uid_zero_accounts(&passwd);
    assert_eq!(uid0_findings.len(), 1);
    assert_eq!(uid0_findings[0].rule_id, 5112);
    assert!(uid0_findings[0].title.contains("backdoor"));
}

#[test]
fn linux_upgrade_helper_script_has_shebang_swap_and_rollback() {
    let swaps = vec![(
        PathBuf::from("/opt/provigil-agent/bin/provigil-agent-linux"),
        PathBuf::from("/opt/provigil-agent/upgrade/1.2.0/provigil-agent-linux"),
    )];
    let pending = UpgradeResult {
        status: "pending".into(),
        version: "1.2.0".into(),
        from_version: "1.1.0".into(),
        timestamp: "2026-01-01T00:00:00Z".into(),
        command_id: "cmd-42".into(),
        reason: None,
    };
    let script = linux_helper_script(&swaps, Path::new("/opt/provigil-agent/upgrade/upgrade_result.json"), &pending, 999);
    assert!(script.starts_with("#!/bin/sh\n"));
    assert!(script.contains("systemctl restart \"$SVC\""));
    assert!(script.contains("systemctl is-active --quiet \"$SVC\""));
    assert!(script.contains("rolled_back"));
    assert!(script.contains("cmd-42"));
}

#[test]
fn linux_default_config_has_realtime_fim_and_localfiles() {
    let rt = provigil_agent::config::linux_default_fim_realtime();
    let lf = provigil_agent::config::linux_default_localfiles();
    assert!(rt.contains(&"/etc".to_string()));
    assert!(rt.contains(&"/usr/local/bin".to_string()));
    assert!(rt.contains(&"/lib/systemd/system".to_string()));

    let locations: Vec<String> = lf.into_iter().map(|f| f.location).collect();
    assert!(locations.contains(&"/var/log/auth.log".to_string()));
    assert!(locations.contains(&"/var/log/secure".to_string()));
    assert!(locations.contains(&"/var/log/syslog".to_string()));
    assert!(locations.contains(&"/var/log/messages".to_string()));
}

