//! Agent Enrollment Protocol Parser & Logic (`src/os_auth/auth.c`)
//!
//! Handles enrollment requests: `OSSEC PASS: ... OSSEC A:'name' V:'version' G:'groups' IP:'ip' K:'key_hash'`.
//! Enforces replacement policies, duplicate checks, group checks, and client.keys registration.

use crate::config::ForceOptions;
use crate::groups::validate_groups;
use sha1::{Digest, Sha1};
use siem_crypto::keys::{ClientKey, KeyStore};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const CURRENT_MANAGER_VERSION: &str = "v4.14.7";

#[derive(Error, Debug, PartialEq, Eq)]
pub enum EnrollmentError {
    #[error("ERROR: Invalid password")]
    InvalidPassword,
    #[error("ERROR: Invalid request for new agent")]
    InvalidRequest,
    #[error("ERROR: Invalid agent name: {0}")]
    InvalidAgentName(String),
    #[error("ERROR: Incompatible version for new agent")]
    IncompatibleVersion,
    #[error("ERROR: Unterminated version field")]
    UnterminatedVersion,
    #[error("ERROR: Unterminated group field")]
    UnterminatedGroup,
    #[error("ERROR: Unterminated IP field")]
    UnterminatedIp,
    #[error("ERROR: Unterminated key field")]
    UnterminatedKey,
    #[error("ERROR: Invalid IP: {0}")]
    InvalidIp(String),
    #[error("ERROR: Duplicate IP: {0}")]
    DuplicateIp(String),
    #[error("ERROR: Duplicate agent name: {0}")]
    DuplicateAgentName(String),
    #[error("ERROR: Duplicate agent ID: {0}")]
    DuplicateAgentId(String),
    #[error("ERROR: Internal manager error adding agent: {0}")]
    InternalError(String),
    #[error("{0}")]
    Custom(String),
}

/// Parsed enrollment payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRequest {
    pub name: String,
    pub version: Option<String>,
    pub groups: Option<String>,
    pub ip: String,
    pub key_hash: Option<String>,
}

/// Agent status in database (mockable/compatible with Wazuh DB agent-info).
#[derive(Debug, Clone)]
pub struct AgentDbInfo {
    pub connection_status: String, // "active", "disconnected", "never_connected"
    pub disconnection_time: u64,
    pub date_add: u64,
}

impl Default for AgentDbInfo {
    fn default() -> Self {
        Self {
            connection_status: "disconnected".to_string(),
            disconnection_time: 0,
            date_add: 0,
        }
    }
}

/// Validates agent name according to `OS_IsValidName`.
pub fn is_valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Compares Wazuh versions: returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
pub fn compare_wazuh_versions(v1: &str, v2: &str) -> i32 {
    let clean1 = v1.trim_start_matches('v').trim_start_matches('V');
    let clean2 = v2.trim_start_matches('v').trim_start_matches('V');

    let parts1: Vec<u32> = clean1.split('.').filter_map(|p| p.parse().ok()).collect();
    let parts2: Vec<u32> = clean2.split('.').filter_map(|p| p.parse().ok()).collect();

    for (p1, p2) in parts1.iter().zip(parts2.iter()) {
        if p1 < p2 {
            return -1;
        } else if p1 > p2 {
            return 1;
        }
    }

    if parts1.len() < parts2.len() {
        -1
    } else if parts1.len() > parts2.len() {
        1
    } else {
        0
    }
}

/// Computes SHA-1 hash of a raw key string.
pub fn calculate_key_hash(raw_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(raw_key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Parses raw agent request buffer matching `w_auth_parse_data`.
pub fn parse_enrollment_data(
    buf: &str,
    authpass: Option<&str>,
    peer_ip: &str,
    use_source_ip: bool,
    allow_higher_versions: bool,
    manager_version: &str,
) -> Result<EnrollmentRequest, EnrollmentError> {
    let mut rest = buf.trim();

    // Check shared password if required
    if let Some(expected_pw) = authpass {
        if !rest.starts_with("OSSEC PASS: ") {
            return Err(EnrollmentError::InvalidPassword);
        }
        let after_pass_prefix = &rest[12..];
        if !after_pass_prefix.starts_with(expected_pw) {
            return Err(EnrollmentError::InvalidPassword);
        }
        let after_pw = &after_pass_prefix[expected_pw.len()..];
        if !after_pw.starts_with(' ') {
            return Err(EnrollmentError::InvalidPassword);
        }
        rest = after_pw.trim_start();
    }

    // Check OSSEC A:'<agentname>'
    if !rest.starts_with("OSSEC A:'") {
        return Err(EnrollmentError::InvalidRequest);
    }
    let after_a = &rest[9..];
    let end_quote = after_a.find('\'').ok_or(EnrollmentError::InvalidRequest)?;
    let agent_name = after_a[..end_quote].to_string();

    if !is_valid_name(&agent_name) {
        return Err(EnrollmentError::InvalidAgentName(agent_name));
    }

    rest = &after_a[end_quote + 1..];

    // Check optional V:'<version>'
    let mut version: Option<String> = None;
    if let Some(v_idx) = rest.find(" V:'") {
        let after_v = &rest[v_idx + 4..];
        let v_end = after_v.find('\'').ok_or(EnrollmentError::UnterminatedVersion)?;
        let ver = after_v[..v_end].to_string();

        if !allow_higher_versions && compare_wazuh_versions(manager_version, &ver) < 0 {
            return Err(EnrollmentError::IncompatibleVersion);
        }
        version = Some(ver);
        rest = &after_v[v_end + 1..];
    }

    // Check optional G:'<groups>'
    let mut groups: Option<String> = None;
    if let Some(g_idx) = rest.find(" G:'") {
        let after_g = &rest[g_idx + 4..];
        let g_end = after_g.find('\'').ok_or(EnrollmentError::UnterminatedGroup)?;
        let raw_groups = &after_g[..g_end];
        let validated = validate_groups(raw_groups).map_err(EnrollmentError::Custom)?;
        groups = Some(validated);
        rest = &after_g[g_end + 1..];
    }

    // Check optional IP:'<ip>'
    let mut ip = if use_source_ip {
        peer_ip.to_string()
    } else {
        "any".to_string()
    };

    if let Some(ip_idx) = rest.find(" IP:'") {
        let after_ip = &rest[ip_idx + 5..];
        let ip_end = after_ip.find('\'').ok_or(EnrollmentError::UnterminatedIp)?;
        let client_ip = after_ip[..ip_end].trim();

        if client_ip != "src" {
            // Validate IP format
            if client_ip != "any" && client_ip.parse::<IpAddr>().is_err() {
                return Err(EnrollmentError::InvalidIp(client_ip.to_string()));
            }
            ip = client_ip.to_string();
        }
        rest = &after_ip[ip_end + 1..];
    }

    // Check optional K:'<key_hash>'
    let mut key_hash: Option<String> = None;
    if let Some(k_idx) = rest.find(" K:'") {
        let after_k = &rest[k_idx + 4..];
        let k_end = after_k.find('\'').ok_or(EnrollmentError::UnterminatedKey)?;
        key_hash = Some(after_k[..k_end].to_string());
    }

    Ok(EnrollmentRequest {
        name: agent_name,
        version,
        groups,
        ip,
        key_hash,
    })
}

/// Evaluates if an existing agent can be replaced matching `w_auth_replace_agent`.
pub fn can_replace_agent(
    existing: &ClientKey,
    db_info: Option<&AgentDbInfo>,
    agent_key_hash: Option<&str>,
    force: &ForceOptions,
) -> Result<(), String> {
    if !force.enabled {
        return Err(format!(
            "Agent '{}' won't be removed because the force option is disabled.",
            existing.id
        ));
    }

    let default_db = AgentDbInfo::default();
    let db = db_info.unwrap_or(&default_db);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Check disconnected time
    if force.disconnected_time_enabled {
        if db.connection_status != "never_connected" {
            if db.connection_status == "disconnected" {
                if db.disconnection_time > 0 {
                    let disconnected_duration = now.saturating_sub(db.disconnection_time);
                    if disconnected_duration < force.disconnected_time {
                        return Err(format!(
                            "Agent '{}' has not been disconnected long enough to be replaced.",
                            existing.id
                        ));
                    }
                } else {
                    return Err(format!(
                        "Agent '{}' can't be replaced since it is not disconnected.",
                        existing.id
                    ));
                }
            } else if db.connection_status == "active" {
                return Err(format!(
                    "Agent '{}' can't be replaced since it is not disconnected.",
                    existing.id
                ));
            }
        }
    }

    // Check registration age
    if force.after_registration_time > 0 && db.date_add > 0 {
        let registration_age = now.saturating_sub(db.date_add);
        if registration_age < force.after_registration_time {
            return Err(format!(
                "Agent '{}' doesn't comply with the registration time to be removed.",
                existing.id
            ));
        }
    }

    // Check key mismatch
    if force.key_mismatch {
        if let Some(agent_hash) = agent_key_hash {
            let manager_hash = calculate_key_hash(&existing.raw_key);
            if manager_hash == agent_hash {
                return Err(format!(
                    "Agent '{}' key already exists on the manager.",
                    existing.id
                ));
            }
        }
    }

    Ok(())
}

/// Validates enrollment data against existing keystore and manager constraints.
pub fn validate_and_prepare(
    keystore: &mut KeyStore,
    req: &EnrollmentRequest,
    server_hostname: &str,
    force: &ForceOptions,
    db_info_lookup: Option<&dyn Fn(&str) -> Option<AgentDbInfo>>,
) -> Result<(), EnrollmentError> {
    // Agent name cannot match manager host
    if req.name == server_hostname {
        return Err(EnrollmentError::InvalidAgentName(format!(
            "{} (same as manager)",
            req.name
        )));
    }

    // Check duplicate IP (if not "any")
    if req.ip != "any" {
        if let Some(existing) = keystore.find_by_ip(&req.ip) {
            let db_info = db_info_lookup.and_then(|f| f(&existing.id));
            if let Err(reason) = can_replace_agent(existing, db_info.as_ref(), req.key_hash.as_deref(), force) {
                return Err(EnrollmentError::DuplicateIp(format!("{}. {}", req.ip, reason)));
            }
            // Allowed to replace: remove old
            let old_id = existing.id.clone();
            keystore.delete_key(&old_id);
        }
    }

    // Check duplicate Name
    if let Some(existing) = keystore.find_by_name(&req.name) {
        let db_info = db_info_lookup.and_then(|f| f(&existing.id));
        if let Err(reason) = can_replace_agent(existing, db_info.as_ref(), req.key_hash.as_deref(), force) {
            return Err(EnrollmentError::DuplicateAgentName(format!("{}. {}", req.name, reason)));
        }
        // Allowed to replace: remove old
        let old_id = existing.id.clone();
        keystore.delete_key(&old_id);
    }

    Ok(())
}

/// Enrolls a new agent into the keystore matching `w_auth_add_agent`.
pub fn add_agent_to_keystore(
    keystore: &mut KeyStore,
    name: &str,
    ip: &str,
    custom_id: Option<&str>,
    custom_raw_key: Option<&str>,
) -> ClientKey {
    let id = custom_id.map(ToString::to_string).unwrap_or_else(|| keystore.next_id());
    let raw_key = custom_raw_key.map(ToString::to_string).unwrap_or_else(KeyStore::generate_raw_key);

    let client_key = ClientKey::new(id, name.to_string(), ip.to_string(), raw_key);
    keystore.add_key(client_key.clone());
    client_key
}

/// Formats the success response: `OSSEC K:'ID NAME IP KEY'`.
pub fn format_success_response(key: &ClientKey) -> String {
    format!("OSSEC K:'{} {} {} {}'", key.id, key.name, key.ip, key.raw_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_enrollment_full() {
        let msg = "OSSEC PASS: secret123 OSSEC A:'agent-ubuntu' V:'v4.14.7' G:'linux,web' IP:'192.168.1.50' K:'d41d8cd98f00b204e9800998ecf8427e'";
        let req = parse_enrollment_data(
            msg,
            Some("secret123"),
            "192.168.1.50",
            true,
            false,
            CURRENT_MANAGER_VERSION,
        )
        .unwrap();

        assert_eq!(req.name, "agent-ubuntu");
        assert_eq!(req.version.unwrap(), "v4.14.7");
        assert_eq!(req.groups.unwrap(), "linux,web");
        assert_eq!(req.ip, "192.168.1.50");
        assert_eq!(req.key_hash.unwrap(), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_parse_enrollment_invalid_pass() {
        let msg = "OSSEC PASS: wrongpass OSSEC A:'agent1'";
        let err = parse_enrollment_data(
            msg,
            Some("secret123"),
            "192.168.1.1",
            true,
            false,
            CURRENT_MANAGER_VERSION,
        );
        assert_eq!(err, Err(EnrollmentError::InvalidPassword));
    }

    #[test]
    fn test_version_comparison() {
        assert_eq!(compare_wazuh_versions("v4.14.7", "v4.14.7"), 0);
        assert_eq!(compare_wazuh_versions("v4.14.7", "v4.14.6"), 1);
        assert_eq!(compare_wazuh_versions("v4.14.6", "v4.14.7"), -1);
        assert_eq!(compare_wazuh_versions("v5.0.0", "v4.14.7"), 1);
    }

    #[test]
    fn test_agent_enrollment_lifecycle() {
        let mut ks = KeyStore::new();
        let mut force = ForceOptions::default();
        force.enabled = true;

        let req = EnrollmentRequest {
            name: "web-server".to_string(),
            version: Some("v4.14.7".to_string()),
            groups: Some("web".to_string()),
            ip: "10.0.0.1".to_string(),
            key_hash: None,
        };

        validate_and_prepare(&mut ks, &req, "manager-node", &force, None).unwrap();
        let key = add_agent_to_keystore(&mut ks, &req.name, &req.ip, None, None);
        assert_eq!(key.id, "001");
        assert_eq!(key.name, "web-server");
        assert_eq!(key.ip, "10.0.0.1");

        let response = format_success_response(&key);
        assert!(response.starts_with("OSSEC K:'001 web-server 10.0.0.1 "));
    }
}
