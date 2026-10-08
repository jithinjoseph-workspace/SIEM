//! `<socket>` output targets (config/socket-config.c): `Read_AnalysisdSocket`
//! and `Read_LogCollecSocket` (identical parsers).

use crate::messages;
use crate::{ConfigError, Result};
use siem_xml::XmlNode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketMode {
    Udp,
    Tcp,
}

/// `socket_forwarder`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketForwarder {
    pub name: String,
    pub location: String,
    pub mode: SocketMode,
    pub prefix: Option<String>,
}

/// `filter_special_chars`: drop each backslash, keeping the next character.
pub fn filter_special_chars(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            i += 1;
            if i >= b.len() {
                break;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `Read_AnalysisdSocket` / `Read_LogCollecSocket`
pub fn read_socket(nodes: &[XmlNode], list: &mut Vec<SocketForwarder>) -> Result<()> {
    let mut name: Option<String> = None;
    let mut location: Option<String> = None;
    let mut mode = SocketMode::Udp;
    let mut prefix: Option<String> = None;
    for n in nodes {
        let Some(c) = n.content.as_deref() else {
            return Err(ConfigError::new(messages::xml_valuenull(&n.element)));
        };
        match n.element.as_str() {
            "name" => {
                if c == "agent" {
                    return Err(ConfigError::new("Invalid socket name 'agent'."));
                }
                name = Some(c.to_string());
            }
            "location" => location = Some(c.to_string()),
            "mode" => {
                mode = if c.eq_ignore_ascii_case("tcp") {
                    SocketMode::Tcp
                } else if c.eq_ignore_ascii_case("udp") {
                    SocketMode::Udp
                } else {
                    return Err(ConfigError::new(format!(
                        "Socket type '{c}' is not valid at <{}>. Should be 'udp' or 'tcp'.",
                        n.element
                    )));
                }
            }
            "prefix" => prefix = Some(filter_special_chars(c)),
            e => return Err(ConfigError::new(messages::xml_invelem(e))),
        }
    }
    let Some(name) = name.filter(|n| !n.is_empty()) else {
        return Err(ConfigError::new("(1954): Missing field 'name' for socket."));
    };
    let Some(location) = location.filter(|l| !l.is_empty()) else {
        return Err(ConfigError::new("(1955): Missing field 'location' for socket."));
    };
    list.push(SocketForwarder { name, location, mode, prefix });
    Ok(())
}
