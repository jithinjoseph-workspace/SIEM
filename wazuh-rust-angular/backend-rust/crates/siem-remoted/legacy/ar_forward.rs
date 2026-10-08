//! Active Response Message Forwarder (ar-forward.c)
//!
//! Formats, encrypts, and delivers active response mitigation commands to agents
//! (e.g. firewall-drop, host-deny, restart-ossec), reading requests from `/queue/alerts/ar`.

use crate::crypto::encrypt_aes256_cbc;
use crate::keys::AgentKey;
use crate::protocol::RemotedMessage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArLocation {
    AllAgents,
    RemoteAgent,
    SpecificAgent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArQueueMessage {
    pub rule_id: String,
    pub srcip: Option<String>,
    pub location: ArLocation,
    pub agent_id: String,
    pub command: String,
    pub is_control_only: bool,
}

impl ArQueueMessage {
    /// Parse raw line from `/queue/alerts/ar`:
    /// Format: `(rule_id) [srcip] location-flags agent_id cmd...`
    /// e.g. `(5710) [192.168.1.100] -S- 001 firewall-drop 192.168.1.100 -`
    pub fn parse_queue_line(line: &str) -> Option<Self> {
        let trimmed = line.trim();

        // 1. Extract rule_id from ( ... )
        let close_paren = trimmed.find(')')?;
        if !trimmed.starts_with('(') {
            return None;
        }
        let rule_id = trimmed[1..close_paren].trim().to_string();

        let after_rule = trimmed[close_paren + 1..].trim();

        // 2. Extract srcip from [ ... ]
        let open_bracket = after_rule.find('[')?;
        let close_bracket = after_rule.find(']')?;
        let srcip_str = after_rule[open_bracket + 1..close_bracket].trim();
        let srcip = if srcip_str.is_empty() || srcip_str == "-" {
            None
        } else {
            Some(srcip_str.to_string())
        };

        let rest = after_rule[close_bracket + 1..].trim();

        // 3. Extract location flags and agent_id
        let mut tokens = rest.split_whitespace();
        let loc_flag = tokens.next()?;
        let agent_id = tokens.next()?.to_string();
        let command = tokens.collect::<Vec<&str>>().join(" ");

        let location = if loc_flag.contains('A') {
            ArLocation::AllAgents
        } else if loc_flag.contains('R') {
            ArLocation::RemoteAgent
        } else {
            ArLocation::SpecificAgent
        };

        let is_control_only = loc_flag.contains('!');

        Some(Self {
            rule_id,
            srcip,
            location,
            agent_id,
            command,
            is_control_only,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveResponseCommand {
    pub message_id: u32,
    pub command: String,
    pub target_ip: Option<String>,
    pub extra_args: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ArForwarder;

impl ArForwarder {
    pub fn new() -> Self {
        Self
    }

    /// Format active response wire message:
    /// In Wazuh: `CONTROL_HEADER EXECD_HEADER cmd` -> `#!-execd {command}`
    pub fn format_wire_payload(cmd: &str, is_control_only: bool) -> String {
        if is_control_only {
            format!("#!-{}", cmd)
        } else {
            format!("#!-execd {}", cmd)
        }
    }

    /// Build encrypted packet ready to send over UDP/TCP socket to agent:
    /// 1. Formats AR payload.
    /// 2. Frames in RemotedMessage format: `#{counter}:AR:{payload}`.
    /// 3. Encrypts with agent key (AES-256-CBC).
    /// 4. Prepends agent routing header: `!{agent_id}:{ciphertext}`.
    pub fn build_encrypted_ar_packet(
        &self,
        agent: &AgentKey,
        counter: u64,
        command_text: &str,
        is_control_only: bool,
    ) -> Vec<u8> {
        let payload = Self::format_wire_payload(command_text, is_control_only);
        let wire_msg = RemotedMessage::format_wire(counter, 6, &payload); // subsystem 6: ActiveResponse
        let ciphertext = encrypt_aes256_cbc(&agent.key_bytes, wire_msg.as_bytes());

        let header = format!("!{}:", agent.id);
        let mut packet = header.into_bytes();
        packet.extend(ciphertext);
        packet
    }
}
