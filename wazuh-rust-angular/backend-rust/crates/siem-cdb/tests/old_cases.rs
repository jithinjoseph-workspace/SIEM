// Regression tests for threat intelligence indicators and live feed matching.
use siem_cdb::ThreatIntelManager;

#[test]
fn old_cases() {
    let m = ThreatIntelManager::new();
    for (l, k, v) in [
        ("malicious_ips", "185.220.101.5", "Tor Exit Node (Relay #42)"),
        ("malicious_ips", "185.220.101.0/24", "Known Tor Exit Subnet"),
        ("malicious_ips", "45.142.122.0/24", "Bulletproof Hosting Botnet Range"),
        ("malicious_hashes", "e10adc3949ba59abbe56e057f20f883e", "Mimikatz"),
        ("malicious_domains", "c2-evil-domain.org", "CobaltStrike C2 Domain"),
    ] {
        assert!(m.insert_entry(l, k, v), "{k}");
    }
    let (list, desc) = m.check_ip("185.220.101.5").unwrap();
    assert_eq!(list, "malicious_ips");
    assert!(desc.contains("Tor Exit Node"));
    assert!(m.check_ip("45.142.122.88").unwrap().1.contains("Botnet Range"));
    assert!(m.check_hash("e10adc3949ba59abbe56e057f20f883e").unwrap().1.contains("Mimikatz"));
    assert!(m.check_hash("E10ADC3949BA59ABBE56E057F20F883E").is_some());
    assert!(m.check_domain("sub.c2-evil-domain.org").unwrap().1.contains("CobaltStrike"));
    assert!(m.check_ip("127.0.0.1").is_none());
    assert!(m.check_domain("github.com").is_none());
    assert_eq!(m.get_list("malicious_ips").unwrap().total_entries(), 3);
    // what the live feeds send: Feodo IPs (port cut off by siem-api) and URLhaus hosts
    assert!(m.insert_entry("malicious_ips", "162.243.103.246", "Feodo Tracker: Emotet"));
    assert!(m.insert_entry("malicious_domains", "Malware-Host.Example.COM", "URLhaus: malware_download"));
    assert!(m.check_domain("http://malware-host.example.com/x.exe").is_some());
}
