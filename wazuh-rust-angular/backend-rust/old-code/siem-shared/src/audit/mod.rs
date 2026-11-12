//! Linux Auditd Netlink Event Parser (audit_op.c)
//!
//! Parses Linux kernel audit records (`SYSCALL`, `EXECVE`, `PATH`, `CWD`, `PROCTITLE`),
//! decodes hex-encoded command arguments, and prepares structured JSON events.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditRecord {
    pub record_type: String,
    pub timestamp_epoch: f64,
    pub event_id: u64,
    pub fields: HashMap<String, String>,
}

impl AuditRecord {
    /// Parse a single audit line: `type=SYSCALL msg=audit(1633072800.123:456): key1=val1 key2="val 2" ...`
    pub fn parse_line(line: &str) -> Option<Self> {
        let trimmed = line.trim();
        if !trimmed.starts_with("type=") {
            return None;
        }

        // 1. Extract record_type
        let mut parts = trimmed.splitn(2, ' ');
        let type_part = parts.next()?;
        let rest = parts.next()?;

        let record_type = type_part.strip_prefix("type=")?.to_string();

        // 2. Extract msg=audit(epoch:id):
        let msg_idx = rest.find("msg=audit(")?;
        let after_audit = &rest[msg_idx + "msg=audit(".len()..];
        let close_paren = after_audit.find(')')?;
        let audit_header = &after_audit[..close_paren];

        let mut header_parts = audit_header.split(':');
        let epoch = header_parts.next()?.parse::<f64>().ok()?;
        let event_id = header_parts.next()?.parse::<u64>().ok()?;

        let kv_section = after_audit[close_paren + 1..].trim_start_matches(':').trim();

        // 3. Parse key-value pairs
        let mut fields = HashMap::new();
        let mut chars = kv_section.chars().peekable();

        while chars.peek().is_some() {
            // Skip spaces
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    chars.next();
                } else {
                    break;
                }
            }

            // Read key
            let mut key = String::new();
            while let Some(&c) = chars.peek() {
                if c == '=' || c.is_whitespace() {
                    break;
                }
                key.push(c);
                chars.next();
            }

            if chars.peek() != Some(&'=') {
                break;
            }
            chars.next(); // consume '='

            // Read value (quoted or unquoted)
            let mut val = String::new();
            if chars.peek() == Some(&'"') {
                chars.next(); // consume opening quote
                while let Some(c) = chars.next() {
                    if c == '"' {
                        break;
                    }
                    val.push(c);
                }
            } else {
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() {
                        break;
                    }
                    val.push(c);
                    chars.next();
                }
            }

            // Only decode hex for command argument fields (a0, a1, proctitle, cmd)
            let is_hex_field = (key.starts_with('a') && key[1..].chars().all(|c| c.is_ascii_digit()))
                || key == "proctitle"
                || key == "cmd";

            let decoded_val = if is_hex_field {
                decode_hex_audit_string(&val).unwrap_or(val)
            } else {
                val
            };

            if !key.is_empty() {
                fields.insert(key, decoded_val);
            }
        }

        Some(Self {
            record_type,
            timestamp_epoch: epoch,
            event_id,
            fields,
        })
    }
}

/// Decodes auditd hex-encoded string (e.g. "62617368" -> "bash").
fn decode_hex_audit_string(s: &str) -> Option<String> {
    if s.len() >= 2 && s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut bytes = Vec::new();
        for i in (0..s.len()).step_by(2) {
            let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
            bytes.push(byte);
        }
        String::from_utf8(bytes).ok()
    } else {
        None
    }
}
