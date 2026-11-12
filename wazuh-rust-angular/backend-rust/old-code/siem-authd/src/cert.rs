//! X.509 Certificate Verification & Utilities (`src/os_auth/check_cert.c` & `generate_cert.c`)
//!
//! Validates Subject Alternative Names (SAN) and Common Name (CN) matching agent hostnames/IPs.

use std::net::IpAddr;

pub const VERIFY_TRUE: i32 = 1;
pub const VERIFY_FALSE: i32 = 0;
pub const VERIFY_ERROR: i32 = -1;

/// Checks if a client hostname matches a certificate pattern (supporting standard wildcards `*.domain`).
pub fn match_dns_hostname(pattern: &str, hostname: &str) -> bool {
    let p_lower = pattern.to_lowercase();
    let h_lower = hostname.to_lowercase();

    if p_lower == h_lower {
        return true;
    }

    // Check wildcard prefix `*.`
    if let Some(suffix) = p_lower.strip_prefix("*.") {
        if let Some(h_suffix) = h_lower.split_once('.') {
            return h_suffix.1 == suffix;
        }
    }

    false
}

/// Checks if an IP address matches an IP SAN pattern.
pub fn match_ip_address(cert_ip_str: &str, peer_ip: &str) -> bool {
    if cert_ip_str == peer_ip {
        return true;
    }

    match (cert_ip_str.parse::<IpAddr>(), peer_ip.parse::<IpAddr>()) {
        (Ok(ip1), Ok(ip2)) => ip1 == ip2,
        _ => false,
    }
}

/// Validates whether a given peer IP or hostname matches the certificate's SANs or CN.
pub fn verify_peer_identity(
    peer: &str,
    san_dns_names: &[String],
    san_ips: &[String],
    common_name: Option<&str>,
) -> bool {
    // 1. Try IP SANs
    for ip in san_ips {
        if match_ip_address(ip, peer) {
            return true;
        }
    }

    // 2. Try DNS SANs
    for dns in san_dns_names {
        if match_dns_hostname(dns, peer) {
            return true;
        }
    }

    // 3. Fallback to CN
    if let Some(cn) = common_name {
        if match_ip_address(cn, peer) || match_dns_hostname(cn, peer) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_dns_hostname() {
        assert!(match_dns_hostname("agent1.wazuh.com", "agent1.wazuh.com"));
        assert!(match_dns_hostname("AGENT1.WAZUH.COM", "agent1.wazuh.com"));
        assert!(match_dns_hostname("*.wazuh.com", "agent1.wazuh.com"));
        assert!(match_dns_hostname("*.wazuh.com", "node-99.wazuh.com"));
        assert!(!match_dns_hostname("*.wazuh.com", "sub.agent1.wazuh.com"));
        assert!(!match_dns_hostname("agent1.wazuh.com", "agent2.wazuh.com"));
    }

    #[test]
    fn test_match_ip_address() {
        assert!(match_ip_address("192.168.1.50", "192.168.1.50"));
        assert!(match_ip_address("::1", "0:0:0:0:0:0:0:1"));
        assert!(!match_ip_address("192.168.1.50", "192.168.1.51"));
    }

    #[test]
    fn test_verify_peer_identity() {
        let sans_dns = vec!["*.cluster.local".to_string(), "master.wazuh.com".to_string()];
        let sans_ip = vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()];
        let cn = Some("wazuh-agent");

        assert!(verify_peer_identity("10.0.0.1", &sans_dns, &sans_ip, cn));
        assert!(verify_peer_identity("node1.cluster.local", &sans_dns, &sans_ip, cn));
        assert!(verify_peer_identity("wazuh-agent", &sans_dns, &sans_ip, cn));
        assert!(!verify_peer_identity("10.0.0.99", &sans_dns, &sans_ip, cn));
    }
}
