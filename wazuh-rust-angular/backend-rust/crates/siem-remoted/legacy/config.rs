//! Remoted Daemon Configuration Parser (config.c)
//!
//! Parses `<remote>` XML blocks from `ossec.conf` supporting connection types (secure, syslog),
//! protocols (UDP, TCP), port bindings, allowed/denied IP lists, and buffer limits.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionType {
    Secure,
    Syslog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetProtocol {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSection {
    pub connection: ConnectionType,
    pub port: u16,
    pub protocol: NetProtocol,
    pub allow_ips: Vec<String>,
    pub deny_ips: Vec<String>,
    pub queue_size: usize,
    pub connection_overtake_time: u32,
    pub rcv_timeout_secs: u32,
    pub send_timeout_secs: u32,
}

impl Default for RemoteSection {
    fn default() -> Self {
        Self {
            connection: ConnectionType::Secure,
            port: 1514,
            protocol: NetProtocol::Tcp,
            allow_ips: Vec::new(),
            deny_ips: Vec::new(),
            queue_size: 131072,
            connection_overtake_time: 60,
            rcv_timeout_secs: 10,
            send_timeout_secs: 10,
        }
    }
}

impl RemoteSection {
    /// Parse `<remote>` XML snippet.
    pub fn parse_xml(xml: &str) -> Result<Self, String> {
        let mut section = Self::default();
        let mut reader = quick_xml::Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut current_tag = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(quick_xml::events::Event::Start(e)) => {
                    current_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                }
                Ok(quick_xml::events::Event::Text(e)) => {
                    let text = e.unescape().map_err(|err| err.to_string())?.trim().to_string();
                    match current_tag.as_str() {
                        "connection" => {
                            if text.eq_ignore_ascii_case("syslog") {
                                section.connection = ConnectionType::Syslog;
                                if section.port == 1514 {
                                    section.port = 514;
                                }
                            } else {
                                section.connection = ConnectionType::Secure;
                            }
                        }
                        "port" => {
                            if let Ok(p) = text.parse::<u16>() {
                                section.port = p;
                            }
                        }
                        "protocol" => {
                            if text.eq_ignore_ascii_case("udp") {
                                section.protocol = NetProtocol::Udp;
                            } else {
                                section.protocol = NetProtocol::Tcp;
                            }
                        }
                        "allowed-ips" | "allow_ips" => {
                            section.allow_ips.push(text);
                        }
                        "denied-ips" | "deny_ips" => {
                            section.deny_ips.push(text);
                        }
                        "queue_size" => {
                            if let Ok(qs) = text.parse::<usize>() {
                                section.queue_size = qs;
                            }
                        }
                        "connection_overtake_time" => {
                            if let Ok(cot) = text.parse::<u32>() {
                                section.connection_overtake_time = cot;
                            }
                        }
                        _ => {}
                    }
                }
                Ok(quick_xml::events::Event::End(_)) => {
                    current_tag.clear();
                }
                Ok(quick_xml::events::Event::Eof) => break,
                Err(e) => return Err(format!("XML error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        Ok(section)
    }
}
