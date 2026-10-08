//! Wazuh Input Validator (validate_op.c)
//!
//! Provides validation functions for agent IDs, names, IP addresses, CIDR ranges,
//! network ports, and path safety to prevent injection and path traversal.

use regex::Regex;
use std::net::IpAddr;
use std::path::Path;
use std::sync::LazyLock;

static AGENT_ID_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{1,8}$").unwrap());
static AGENT_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9.\-_]{1,128}$").unwrap());

/// Validate Wazuh agent ID format (numeric string, 1 to 8 digits).
pub fn is_valid_agent_id(id: &str) -> bool {
    AGENT_ID_REGEX.is_match(id.trim())
}

/// Validate Wazuh agent name format (alphanumeric with ., -, _, up to 128 chars).
pub fn is_valid_agent_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return false;
    }
    AGENT_NAME_REGEX.is_match(trimmed)
}

/// Validate if string is a valid IP address or "any".
pub fn is_valid_agent_ip(ip: &str) -> bool {
    let trimmed = ip.trim();
    if trimmed.eq_ignore_ascii_case("any") {
        return true;
    }
    // Check single IP
    if trimmed.parse::<IpAddr>().is_ok() {
        return true;
    }
    // Check CIDR format: IP/prefix
    is_valid_cidr(trimmed)
}

/// Validate CIDR notation (e.g. 192.168.1.0/24 or 10.0.0.0/8).
pub fn is_valid_cidr(cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let ip_ok = parts[0].parse::<IpAddr>().is_ok();
    if !ip_ok {
        return false;
    }
    if let Ok(prefix) = parts[1].parse::<u8>() {
        if parts[0].contains(':') {
            prefix <= 128
        } else {
            prefix <= 32
        }
    } else {
        false
    }
}

/// Validate network port (1 to 65535).
pub fn is_valid_port(port: u32) -> bool {
    (1..=65535).contains(&port)
}

/// Validate that a path does not perform directory traversal ("..").
pub fn is_safe_path(path_str: &str) -> bool {
    let p = Path::new(path_str);
    for component in p.components() {
        if component == std::path::Component::ParentDir {
            return false;
        }
    }
    true
}
