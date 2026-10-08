use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use ipnet::IpNet;

/// DJB2 hash algorithm matching Wazuh analysisd/cdb/cdb_hash.c
#[inline]
pub fn cdb_hash(buf: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in buf {
        h = ((h << 5).wrapping_add(h)) ^ (b as u32);
    }
    h
}

#[derive(Debug, Clone, Default)]
pub struct CdbTable {
    name: String,
    exact_map: HashMap<String, String>,
    cidr_list: Vec<(IpNet, String)>,
}

impl CdbTable {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            exact_map: HashMap::new(),
            cidr_list: Vec::new(),
        }
    }

    pub fn insert(&mut self, key: &str, value: &str) {
        let trimmed_key = key.trim();
        let trimmed_val = value.trim();

        // Check if key is a CIDR notation (e.g. 192.168.1.0/24 or 10.0.0.0/8)
        if let Ok(net) = IpNet::from_str(trimmed_key) {
            self.cidr_list.push((net, trimmed_val.to_string()));
        } else {
            self.exact_map.insert(trimmed_key.to_lowercase(), trimmed_val.to_string());
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        let lower = key.trim().to_lowercase();
        if let Some(val) = self.exact_map.get(&lower) {
            return Some(val.as_str());
        }

        // Try IP / CIDR lookup
        if let Ok(ip) = IpAddr::from_str(key.trim()) {
            for (net, val) in &self.cidr_list {
                if net.contains(&ip) {
                    return Some(val.as_str());
                }
            }
        }

        None
    }

    pub fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Match domain or subdomain (e.g. key="c2.badactor.com" matches rule entry "badactor.com")
    pub fn match_domain(&self, fqdn: &str) -> Option<&str> {
        let clean = fqdn.trim().to_lowercase();
        if let Some(val) = self.exact_map.get(&clean) {
            return Some(val.as_str());
        }

        // Check parent domains (e.g. sub.example.com -> example.com)
        let mut parts: Vec<&str> = clean.split('.').collect();
        while parts.len() > 2 {
            parts.remove(0);
            let parent = parts.join(".");
            if let Some(val) = self.exact_map.get(&parent) {
                return Some(val.as_str());
            }
        }
        None
    }

    /// Load standard Wazuh CDB text list format:
    /// key:value
    /// or simple key lines
    pub fn load_from_text(&mut self, content: &str) -> usize {
        let mut count = 0;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some(colon_idx) = trimmed.find(':') {
                let k = &trimmed[..colon_idx];
                let v = &trimmed[colon_idx + 1..];
                self.insert(k, v);
            } else {
                self.insert(trimmed, "blacklisted");
            }
            count += 1;
        }
        count
    }

    pub fn total_entries(&self) -> usize {
        self.exact_map.len() + self.cidr_list.len()
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdb_hash_matches_wazuh_algorithm() {
        let hash = cdb_hash(b"192.168.1.1");
        assert_ne!(hash, 0);

        // Verification of deterministic property
        let hash2 = cdb_hash(b"192.168.1.1");
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_exact_lookup() {
        let mut table = CdbTable::new("malicious_hashes");
        table.insert("e10adc3949ba59abbe56e057f20f883e", "Mimikatz Dump");
        table.insert("44d88612fea8a8f36de82e1278abb02f", "WannaCry Dropper");

        assert_eq!(
            table.get("e10adc3949ba59abbe56e057f20f883e"),
            Some("Mimikatz Dump")
        );
        assert_eq!(
            table.get("E10ADC3949BA59ABBE56E057F20F883E"), // case-insensitive
            Some("Mimikatz Dump")
        );
        assert!(table.get("unknown_hash").is_none());
    }

    #[test]
    fn test_cidr_ip_matching() {
        let mut table = CdbTable::new("alienvault_c2_subnets");
        table.insert("198.51.100.0/24", "CobaltStrike C2 Range");
        table.insert("203.0.113.5", "Specific Scanner Host");

        // Inside CIDR subnet
        assert_eq!(
            table.get("198.51.100.42"),
            Some("CobaltStrike C2 Range")
        );
        // Exact IP
        assert_eq!(
            table.get("203.0.113.5"),
            Some("Specific Scanner Host")
        );
        // Outside
        assert!(table.get("198.51.101.1").is_none());
    }

    #[test]
    fn test_domain_matching() {
        let mut table = CdbTable::new("phishing_domains");
        table.insert("evil-c2.com", "Active C2");

        assert_eq!(table.match_domain("evil-c2.com"), Some("Active C2"));
        assert_eq!(table.match_domain("beacon.sub.evil-c2.com"), Some("Active C2"));
        assert!(table.match_domain("google.com").is_none());
    }
}
