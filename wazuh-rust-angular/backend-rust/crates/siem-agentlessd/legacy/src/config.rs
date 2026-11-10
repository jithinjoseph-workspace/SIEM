//! Agentless Configuration Engine (`src/agentlessd/agentlessd.c` & `src/config/agentlessd-config.c`)
//!
//! Parses `<agentless>` XML blocks and generates JSON configuration.

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const LESSD_STATE_CONNECTED: u8 = 0x001;
pub const LESSD_STATE_PERIODIC: u8 = 0x002;
pub const LESSD_STATE_DIFF: u8 = 0x004;

pub const DEFAULT_AGENTLESS_FREQUENCY: u64 = 86400;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentlessEntry {
    pub state: u8,
    pub frequency: u64,
    pub current_state: u64,
    pub port: u16,
    pub error_flag: u32,
    pub script_type: String,
    pub servers: Vec<String>,
    pub options: Option<String>,
    pub command: Option<String>,
}

impl Default for AgentlessEntry {
    fn default() -> Self {
        Self {
            state: LESSD_STATE_PERIODIC,
            frequency: DEFAULT_AGENTLESS_FREQUENCY,
            current_state: 0,
            port: 22,
            error_flag: 0,
            script_type: String::new(),
            servers: Vec::new(),
            options: None,
            command: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AgentlessConfig {
    pub entries: Vec<AgentlessEntry>,
}

impl AgentlessConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::from_xml(&content)
    }

    pub fn from_xml(xml: &str) -> Result<Self, String> {
        let mut config = AgentlessConfig::default();
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut in_agentless = false;
        let mut current_entry: Option<AgentlessEntry> = None;
        let mut current_tag = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    match tag.as_str() {
                        "agentless" => {
                            in_agentless = true;
                            current_entry = Some(AgentlessEntry::default());
                        }
                        _ => {
                            current_tag = tag;
                        }
                    }
                }
                Ok(Event::Text(ref e)) => {
                    if !in_agentless {
                        continue;
                    }
                    let text = e.unescape().map_err(|err| err.to_string())?.to_string();
                    if let Some(ref mut entry) = current_entry {
                        match current_tag.as_str() {
                            "type" => entry.script_type = text,
                            "frequency" => {
                                if let Ok(f) = text.parse::<u64>() {
                                    entry.frequency = f;
                                }
                            }
                            "port" => {
                                if let Ok(p) = text.parse::<u16>() {
                                    entry.port = p;
                                }
                            }
                            "host" => {
                                let formatted = if let Some(stripped) = text.strip_prefix("use_su ") {
                                    format!("s{}", stripped.trim())
                                } else if let Some(stripped) = text.strip_prefix("use_sudo ") {
                                    format!("o{}", stripped.trim())
                                } else {
                                    format!(" {}", text.trim())
                                };
                                entry.servers.push(formatted);
                            }
                            "state" => match text.as_str() {
                                "periodic" => entry.state = LESSD_STATE_PERIODIC,
                                "stay_connected" => entry.state = LESSD_STATE_CONNECTED,
                                "periodic_diff" => entry.state = LESSD_STATE_PERIODIC | LESSD_STATE_DIFF,
                                _ => {}
                            },
                            "arguments" => entry.options = Some(text),
                            "run_command" => entry.command = Some(text),
                            _ => {}
                        }
                    }
                }
                Ok(Event::End(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if tag == "agentless" {
                        in_agentless = false;
                        if let Some(entry) = current_entry.take() {
                            if !entry.script_type.is_empty() && !entry.servers.is_empty() {
                                config.entries.push(entry);
                            }
                        }
                    }
                    current_tag.clear();
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(format!("XML parse error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        Ok(config)
    }

    /// Generates JSON output matching `getAgentlessConfig` in `agentlessd.c`.
    pub fn get_agentless_config_json(&self) -> serde_json::Value {
        let mut list = Vec::new();
        for entry in &self.entries {
            let mut item = serde_json::Map::new();
            let host_arr: Vec<serde_json::Value> = entry
                .servers
                .iter()
                .map(|s| serde_json::json!(s.trim_start()))
                .collect();
            item.insert("host".to_string(), serde_json::Value::Array(host_arr));
            item.insert("port".to_string(), serde_json::json!(entry.port));
            item.insert("frequency".to_string(), serde_json::json!(entry.frequency));

            let state_str = if (entry.state & LESSD_STATE_PERIODIC != 0) && (entry.state & LESSD_STATE_DIFF != 0) {
                "periodic_diff"
            } else if entry.state & LESSD_STATE_CONNECTED != 0 {
                "stay_connected"
            } else {
                "periodic"
            };
            item.insert("state".to_string(), serde_json::json!(state_str));

            if let Some(ref opts) = entry.options {
                item.insert("arguments".to_string(), serde_json::json!(opts));
            }
            if let Some(ref cmd) = entry.command {
                item.insert("run_command".to_string(), serde_json::json!(cmd));
            }
            if !entry.script_type.is_empty() {
                item.insert("type".to_string(), serde_json::json!(entry.script_type));
            }

            list.push(serde_json::Value::Object(item));
        }

        serde_json::json!({ "agentless": list })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_agentless_xml() {
        let xml = r#"
        <ossec_config>
            <agentless>
                <type>ssh_integrity_check_linux</type>
                <frequency>3600</frequency>
                <host>use_sudo admin@192.168.1.10</host>
                <host>root@192.168.1.20</host>
                <state>periodic_diff</state>
                <arguments>/bin /sbin /etc</arguments>
            </agentless>
        </ossec_config>
        "#;

        let cfg = AgentlessConfig::from_xml(xml).unwrap();
        assert_eq!(cfg.entries.len(), 1);
        let entry = &cfg.entries[0];
        assert_eq!(entry.script_type, "ssh_integrity_check_linux");
        assert_eq!(entry.frequency, 3600);
        assert_eq!(entry.servers.len(), 2);
        assert!(entry.servers[0].starts_with('o')); // sudo flag
        assert_eq!(entry.state, LESSD_STATE_PERIODIC | LESSD_STATE_DIFF);
        assert_eq!(entry.options.as_deref(), Some("/bin /sbin /etc"));

        let json = cfg.get_agentless_config_json();
        assert_eq!(json["agentless"][0]["state"], "periodic_diff");
        assert_eq!(json["agentless"][0]["frequency"], 3600);
    }
}
