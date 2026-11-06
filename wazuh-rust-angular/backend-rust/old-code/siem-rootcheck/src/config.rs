//! Rootcheck Configuration Parser (config.c, rootcheck-config.c)
//!
//! Parses `<rootcheck>` XML settings from `ossec.conf` controlling which anomaly passes are enabled.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootcheckConfig {
    pub disabled: bool,
    pub check_files: bool,
    pub check_trojans: bool,
    pub check_dev: bool,
    pub check_pids: bool,
    pub check_ports: bool,
    pub check_if: bool,
    pub check_sys: bool,
    pub frequency_secs: u32,
    pub rootkit_files: Vec<String>,
    pub rootkit_trojans: Vec<String>,
}

impl Default for RootcheckConfig {
    fn default() -> Self {
        Self {
            disabled: false,
            check_files: true,
            check_trojans: true,
            check_dev: true,
            check_pids: true,
            check_ports: true,
            check_if: true,
            check_sys: true,
            frequency_secs: 43200, // 12 hours
            rootkit_files: vec!["/var/ossec/etc/shared/rootkit_files.txt".to_string()],
            rootkit_trojans: vec!["/var/ossec/etc/shared/rootkit_trojans.txt".to_string()],
        }
    }
}

impl RootcheckConfig {
    /// Parse `<rootcheck>` XML block.
    pub fn parse_xml(xml: &str) -> Result<Self, String> {
        let mut config = Self::default();
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
                        "disabled" => config.disabled = parse_bool(&text),
                        "check_files" => config.check_files = parse_bool(&text),
                        "check_trojans" => config.check_trojans = parse_bool(&text),
                        "check_dev" => config.check_dev = parse_bool(&text),
                        "check_pids" => config.check_pids = parse_bool(&text),
                        "check_ports" => config.check_ports = parse_bool(&text),
                        "check_if" => config.check_if = parse_bool(&text),
                        "check_sys" => config.check_sys = parse_bool(&text),
                        "frequency" => {
                            if let Ok(freq) = text.parse::<u32>() {
                                config.frequency_secs = freq;
                            }
                        }
                        "rootkit_files" => {
                            if !config.rootkit_files.contains(&text) {
                                config.rootkit_files.push(text);
                            }
                        }
                        "rootkit_trojans" => {
                            if !config.rootkit_trojans.contains(&text) {
                                config.rootkit_trojans.push(text);
                            }
                        }
                        _ => {}
                    }
                }
                Ok(quick_xml::events::Event::End(_)) => {
                    current_tag.clear();
                }
                Ok(quick_xml::events::Event::Eof) => break,
                Err(e) => return Err(format!("XML parsing error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        Ok(config)
    }
}

fn parse_bool(text: &str) -> bool {
    matches!(text.to_lowercase().as_str(), "yes" | "true" | "1")
}
