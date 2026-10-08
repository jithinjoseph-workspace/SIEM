use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("Message too short or invalid header: {0}")]
    InvalidHeader(String),
    #[error("Failed to parse counter in message: {0}")]
    InvalidCounter(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WazuhSubsystem {
    Fim,            // 1: Syscheck
    Rootcheck,      // 2: Rootcheck
    Syscollector,   // 3: Syscollector
    Sca,            // 4: SCA
    Keepalive,      // 5: Hostinfo / Heartbeat
    ActiveResponse, // 6: Active response execution / ack
    Log,            // Generic event / log
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemotedMessage {
    pub agent_id: String,
    pub counter: u64,
    pub subsystem: WazuhSubsystem,
    pub payload: String,
}

impl RemotedMessage {
    /// Parse a decrypted Wazuh agent wire message
    /// Standard format: "#!counter:subsystem_id:payload" or "#OSSEC:!counter:subsystem_id:payload"
    /// or "counter:subsystem_id:payload"
    pub fn parse(agent_id: &str, raw: &str) -> Result<Self, ProtocolError> {
        let trimmed = raw.trim();

        // Strip leading "#!" or "#OSSEC:!" or "#:"
        let content = if let Some(stripped) = trimmed.strip_prefix("#OSSEC:!") {
            stripped
        } else if let Some(stripped) = trimmed.strip_prefix("#OSSEC:") {
            stripped
        } else if let Some(stripped) = trimmed.strip_prefix("#!") {
            stripped
        } else if let Some(stripped) = trimmed.strip_prefix("#:") {
            stripped
        } else {
            trimmed
        };

        // Split by ':' to extract counter and remainder
        let parts: Vec<&str> = content.splitn(3, ':').collect();
        if parts.is_empty() {
            return Err(ProtocolError::InvalidHeader("Empty payload".to_string()));
        }

        let (counter, subsystem_token, payload) = if parts.len() >= 3 {
            let cnt = parts[0]
                .parse::<u64>()
                .map_err(|e| ProtocolError::InvalidCounter(format!("{}: {}", parts[0], e)))?;
            (cnt, parts[1], parts[2])
        } else if parts.len() == 2 {
            // counter:payload
            let cnt = parts[0].parse::<u64>().unwrap_or(0);
            (cnt, "", parts[1])
        } else {
            (0, "", parts[0])
        };

        let subsystem = match subsystem_token {
            "1" | "syscheck" => WazuhSubsystem::Fim,
            "2" | "rootcheck" => WazuhSubsystem::Rootcheck,
            "3" | "syscollector" => WazuhSubsystem::Syscollector,
            "4" | "sca" => WazuhSubsystem::Sca,
            "5" | "hostinfo" | "ping" => WazuhSubsystem::Keepalive,
            "6" | "active-response" | "ar" => WazuhSubsystem::ActiveResponse,
            _ => {
                if payload.starts_with("syscheck:") || payload.contains("File '") {
                    WazuhSubsystem::Fim
                } else if payload.starts_with("rootcheck:") {
                    WazuhSubsystem::Rootcheck
                } else if payload.starts_with("sca:") {
                    WazuhSubsystem::Sca
                } else if payload.starts_with("syscollector:") {
                    WazuhSubsystem::Syscollector
                } else if payload.starts_with("ossec: Agent started") || payload.starts_with("#ping") {
                    WazuhSubsystem::Keepalive
                } else {
                    WazuhSubsystem::Log
                }
            }
        };

        Ok(Self {
            agent_id: agent_id.to_string(),
            counter,
            subsystem,
            payload: payload.to_string(),
        })
    }

    /// Build wire string for an agent message (used by agents or tests)
    pub fn format_wire(counter: u64, subsystem_id: u8, payload: &str) -> String {
        format!("#!{}:{}:{}", counter, subsystem_id, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fim_message() {
        let raw = "#!1054:1:/etc/shadow modified md5=1234567890abcdef";
        let msg = RemotedMessage::parse("001", raw).unwrap();
        assert_eq!(msg.agent_id, "001");
        assert_eq!(msg.counter, 1054);
        assert_eq!(msg.subsystem, WazuhSubsystem::Fim);
        assert_eq!(msg.payload, "/etc/shadow modified md5=1234567890abcdef");
    }

    #[test]
    fn test_parse_syscollector_message() {
        let raw = "#!2001:3:{\"packages\": [{\"name\": \"xz-utils\", \"version\": \"5.6.0\"}]}";
        let msg = RemotedMessage::parse("002", raw).unwrap();
        assert_eq!(msg.counter, 2001);
        assert_eq!(msg.subsystem, WazuhSubsystem::Syscollector);
        assert!(msg.payload.contains("xz-utils"));
    }

    #[test]
    fn test_parse_keepalive() {
        let raw = "#!500:5:#ping";
        let msg = RemotedMessage::parse("003", raw).unwrap();
        assert_eq!(msg.counter, 500);
        assert_eq!(msg.subsystem, WazuhSubsystem::Keepalive);
    }
}
