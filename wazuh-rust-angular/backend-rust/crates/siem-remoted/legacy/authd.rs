use std::sync::Arc;
use thiserror::Error;
use tracing::{info, warn};

use crate::keys::{AgentKey, KeysDatabase};

#[derive(Error, Debug, PartialEq, Eq)]
pub enum AuthdError {
    #[error("Invalid request syntax: {0}")]
    InvalidSyntax(String),
    #[error("Agent name is empty or invalid")]
    InvalidAgentName,
    #[error("Agent with name '{0}' already exists and overwrite is disabled")]
    AgentAlreadyExists(String),
    #[error("Authentication failed: invalid enrollment password")]
    InvalidPassword,
}

#[derive(Debug, Clone)]
pub struct AuthdConfig {
    pub enrollment_password: Option<String>,
    pub force_overwrite: bool,
    pub default_ip: String,
}

impl Default for AuthdConfig {
    fn default() -> Self {
        Self {
            enrollment_password: None,
            force_overwrite: true,
            default_ip: "any".to_string(),
        }
    }
}

pub struct AuthdService {
    keys_db: Arc<KeysDatabase>,
    config: AuthdConfig,
}

impl AuthdService {
    pub fn new(keys_db: Arc<KeysDatabase>, config: AuthdConfig) -> Self {
        Self { keys_db, config }
    }

    /// Process a raw Wazuh enrollment message (e.g. from TCP 1515)
    /// Request format: "OSSEC A:'agent_name' [G:'group'] [P:'password']"
    pub fn handle_enrollment_request(
        &self,
        peer_ip: &str,
        request: &str,
    ) -> Result<String, AuthdError> {
        let trimmed = request.trim();

        if !trimmed.starts_with("OSSEC A:'") {
            return Err(AuthdError::InvalidSyntax(
                "Request must start with \"OSSEC A:'\"".to_string(),
            ));
        }

        // Extract agent name
        let after_prefix = &trimmed[9..];
        let name_end = after_prefix
            .find('\'')
            .ok_or_else(|| AuthdError::InvalidSyntax("Missing closing quote for agent name".into()))?;
        let agent_name = after_prefix[..name_end].trim();

        if agent_name.is_empty() {
            return Err(AuthdError::InvalidAgentName);
        }

        // Check password if configured
        if let Some(ref required_pw) = self.config.enrollment_password {
            let pw_extracted = if let Some(p_idx) = trimmed.find("P:'") {
                let rest = &trimmed[p_idx + 3..];
                if let Some(end) = rest.find('\'') {
                    Some(&rest[..end])
                } else {
                    None
                }
            } else {
                None
            };

            if pw_extracted != Some(required_pw.as_str()) {
                warn!("Authd: Invalid enrollment password attempted for agent '{}'", agent_name);
                return Err(AuthdError::InvalidPassword);
            }
        }

        // Check if agent already exists
        if let Some(existing) = self.keys_db.get_by_name(agent_name) {
            if !self.config.force_overwrite {
                return Err(AuthdError::AgentAlreadyExists(agent_name.to_string()));
            }
            // Return existing credentials
            info!("Authd: Agent '{}' re-enrolled with existing ID {}", agent_name, existing.id);
            return Ok(format!(
                "OSSEC K:'{} {} {} {}'",
                existing.id, existing.name, existing.ip, existing.raw_key
            ));
        }

        // Generate new ID and key
        let agent_id = self.keys_db.next_agent_id();
        let (raw_key, key_bytes) = KeysDatabase::generate_key();

        let agent_ip = if self.config.default_ip == "any" {
            "any".to_string()
        } else {
            peer_ip.to_string()
        };

        let new_agent = AgentKey {
            id: agent_id.clone(),
            name: agent_name.to_string(),
            ip: agent_ip.clone(),
            raw_key: raw_key.clone(),
            key_bytes,
            last_counter: 0,
        };

        let _ = self.keys_db.add_agent(new_agent);

        info!(
            "Authd: Successfully enrolled new agent '{}' with ID {} from IP {}",
            agent_name, agent_id, peer_ip
        );

        // Response format: OSSEC K:'ID NAME IP KEY'
        Ok(format!(
            "OSSEC K:'{} {} {} {}'",
            agent_id, agent_name, agent_ip, raw_key
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authd_enrollment_success() {
        let keys_db = Arc::new(KeysDatabase::new());
        let authd = AuthdService::new(keys_db.clone(), AuthdConfig::default());

        let req = "OSSEC A:'prod-server-01'";
        let res = authd.handle_enrollment_request("192.168.1.10", req).unwrap();

        assert!(res.starts_with("OSSEC K:'001 prod-server-01 any "));
        assert_eq!(keys_db.total_agents(), 1);

        let agent = keys_db.get_by_id("001").unwrap();
        assert_eq!(agent.name, "prod-server-01");
    }

    #[test]
    fn test_authd_enrollment_with_password() {
        let keys_db = Arc::new(KeysDatabase::new());
        let mut config = AuthdConfig::default();
        config.enrollment_password = Some("SuperSecretToken123".to_string());

        let authd = AuthdService::new(keys_db.clone(), config);

        // Wrong password
        let bad_req = "OSSEC A:'prod-server-02' P:'wrong'";
        let err = authd.handle_enrollment_request("192.168.1.11", bad_req);
        assert_eq!(err.unwrap_err(), AuthdError::InvalidPassword);

        // Correct password
        let good_req = "OSSEC A:'prod-server-02' P:'SuperSecretToken123'";
        let ok = authd.handle_enrollment_request("192.168.1.11", good_req);
        assert!(ok.is_ok());
        assert_eq!(keys_db.total_agents(), 1);
    }
}
