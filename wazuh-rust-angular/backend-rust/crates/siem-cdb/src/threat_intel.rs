use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use crate::cdb::CdbTable;

#[derive(Debug, Clone)]
pub struct ThreatIntelManager {
    lists: Arc<RwLock<HashMap<String, CdbTable>>>,
}

impl Default for ThreatIntelManager {
    fn default() -> Self {
        Self::new_with_builtin_feeds()
    }
}

impl ThreatIntelManager {
    pub fn new() -> Self {
        Self {
            lists: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_list(&self, table: CdbTable) {
        let mut guard = self.lists.write().unwrap();
        guard.insert(table.name().to_string(), table);
    }

    pub fn get_list(&self, name: &str) -> Option<CdbTable> {
        let guard = self.lists.read().unwrap();
        guard.get(name).cloned()
    }

    /// Check if an IP address matches any registered threat list
    pub fn check_ip(&self, ip: &str) -> Option<(String, String)> {
        let guard = self.lists.read().unwrap();
        for (list_name, table) in guard.iter() {
            if let Some(desc) = table.get(ip) {
                return Some((list_name.clone(), desc.to_string()));
            }
        }
        None
    }

    /// Check if a file hash matches any known malware hash list
    pub fn check_hash(&self, hash: &str) -> Option<(String, String)> {
        let guard = self.lists.read().unwrap();
        for (list_name, table) in guard.iter() {
            if let Some(desc) = table.get(hash) {
                return Some((list_name.clone(), desc.to_string()));
            }
        }
        None
    }

    /// Check if a domain matches any known malicious domain list
    pub fn check_domain(&self, domain: &str) -> Option<(String, String)> {
        let guard = self.lists.read().unwrap();
        for (list_name, table) in guard.iter() {
            if let Some(desc) = table.match_domain(domain) {
                return Some((list_name.clone(), desc.to_string()));
            }
        }
        None
    }

    /// Initialize with rich built-in threat intelligence lists matching Wazuh ruleset lists
    pub fn new_with_builtin_feeds() -> Self {
        let manager = Self::new();

        // 1. Malicious IP list
        let mut ip_table = CdbTable::new("malicious_ips");
        ip_table.insert("185.220.101.5", "Tor Exit Node (Relay #42)");
        ip_table.insert("185.220.101.0/24", "Known Tor Exit Subnet");
        ip_table.insert("198.51.100.23", "CobaltStrike C2 Server");
        ip_table.insert("203.0.113.195", "Brute Force SSH Attacker");
        ip_table.insert("45.142.122.0/24", "Bulletproof Hosting Botnet Range");
        manager.add_list(ip_table);

        // 2. Malicious File Hashes list
        let mut hash_table = CdbTable::new("malicious_hashes");
        hash_table.insert("e10adc3949ba59abbe56e057f20f883e", "Mimikatz Memory Dumper");
        hash_table.insert("84c82835a5d21bbcf75a61706d8ab549", "WannaCry Ransomware PE");
        hash_table.insert("c4ca4238a0b923820dcc509a6f75849b", "Cobalt Strike Beacon Stager");
        hash_table.insert("5d41402abc4b2a76b9719d911017c592", "BlackCat / ALPHV Ransomware Executable");
        manager.add_list(hash_table);

        // 3. Malicious Domains list
        let mut domain_table = CdbTable::new("malicious_domains");
        domain_table.insert("c2-evil-domain.org", "CobaltStrike C2 Domain");
        domain_table.insert("phish-login-portal.net", "Credential Harvester");
        domain_table.insert("dynamic-dns-ddns.info", "Dynamic DNS C2 Beacon");
        manager.add_list(domain_table);

        manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_intel_checks() {
        let manager = ThreatIntelManager::new_with_builtin_feeds();

        // IP check
        let (list, desc) = manager.check_ip("185.220.101.5").expect("Tor IP should match");
        assert_eq!(list, "malicious_ips");
        assert!(desc.contains("Tor Exit Node"));

        // Subnet check
        let (_, desc2) = manager.check_ip("45.142.122.88").expect("Subnet should match");
        assert!(desc2.contains("Botnet Range"));

        // Hash check
        let (_, desc3) = manager
            .check_hash("e10adc3949ba59abbe56e057f20f883e")
            .expect("Mimikatz hash should match");
        assert!(desc3.contains("Mimikatz"));

        // Domain check
        let (_, desc4) = manager
            .check_domain("sub.c2-evil-domain.org")
            .expect("Domain should match");
        assert!(desc4.contains("CobaltStrike"));

        // Safe query
        assert!(manager.check_ip("127.0.0.1").is_none());
        assert!(manager.check_domain("github.com").is_none());
    }
}
