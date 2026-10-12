//! Wazuh Active Response Execution Daemon Configuration (`src/os_execd/config.c`, `src/os_execd/exec.c`)
//!
//! Handles XML parsing of `<active-response>` configurations, repeated offender timeouts,
//! command catalogs (`ar.conf`), and JSON serialization for `getARConfig` and `getExecdInternalOptions`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("XML parsing error: {0}")]
    Xml(String),
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Active Response Daemon Configuration matching `is_disabled`, `repeated_offenders_timeout`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecdConfig {
    pub disabled: bool,
    pub repeated_offenders: Vec<u32>,
    pub request_timeout: u32,
    pub max_restart_lock: u32,
}

impl Default for ExecdConfig {
    fn default() -> Self {
        Self {
            disabled: false,
            repeated_offenders: Vec::new(),
            request_timeout: 0,
            max_restart_lock: 0,
        }
    }
}

impl ExecdConfig {
    /// Produces JSON representation matching `getARConfig()` in `config.c`.
    pub fn get_ar_config(&self) -> serde_json::Value {
        let mut ar = serde_json::Map::new();
        ar.insert(
            "disabled".to_string(),
            serde_json::Value::String(if self.disabled { "yes".to_string() } else { "no".to_string() }),
        );

        if !self.repeated_offenders.is_empty() {
            let list: Vec<serde_json::Value> = self
                .repeated_offenders
                .iter()
                .map(|t| serde_json::json!(*t))
                .collect();
            ar.insert("repeated_offenders".to_string(), serde_json::Value::Array(list));
        }

        serde_json::json!({
            "active-response": ar
        })
    }

    /// Produces JSON representation matching `getExecdInternalOptions()` in `config.c`.
    pub fn get_internal_options(&self) -> serde_json::Value {
        serde_json::json!({
            "internal": {
                "execd": {
                    "request_timeout": self.request_timeout,
                    "max_restart_lock": self.max_restart_lock
                }
            }
        })
    }

    /// Reads configuration from an XML file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_xml_str(&content)
    }

    /// Parses `<active-response>` block from XML string.
    pub fn from_xml_str(xml_str: &str) -> Result<Self, ConfigError> {
        use quick_xml::events::Event;
        use quick_xml::reader::Reader;

        let mut reader = Reader::from_str(xml_str);
        reader.config_mut().trim_text(true);

        let mut config = ExecdConfig::default();
        let mut in_active_response = false;
        let mut current_tag = String::new();

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name.eq_ignore_ascii_case("active-response") {
                        in_active_response = true;
                    } else if in_active_response {
                        current_tag = name;
                    }
                }
                Ok(Event::Text(ref e)) => {
                    if in_active_response && !current_tag.is_empty() {
                        let text = e.unescape().map_err(|err| ConfigError::Xml(err.to_string()))?.to_string();
                        let tag_lower = current_tag.to_ascii_lowercase();

                        match tag_lower.as_str() {
                            "disabled" => {
                                let val = text.trim().to_ascii_lowercase();
                                if val == "yes" {
                                    config.disabled = true;
                                } else if val == "no" {
                                    config.disabled = false;
                                } else {
                                    return Err(ConfigError::Validation(format!("Invalid disabled value: {}", text)));
                                }
                            }
                            "repeated_offenders" => {
                                config.repeated_offenders.clear();
                                for part in text.split(',') {
                                    let trimmed = part.trim();
                                    if !trimmed.is_empty() {
                                        let num = trimmed.parse::<u32>().map_err(|_| {
                                            ConfigError::Validation(format!("Invalid repeated_offenders value: {}", trimmed))
                                        })?;
                                        config.repeated_offenders.push(num);
                                        if config.repeated_offenders.len() >= 6 {
                                            break;
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name.eq_ignore_ascii_case("active-response") {
                        in_active_response = false;
                    } else if in_active_response {
                        current_tag.clear();
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(ConfigError::Xml(format!("XML error: {:?}", e))),
                _ => {}
            }
            buf.clear();
        }

        Ok(config)
    }
}

/// An entry in the active response command catalog (`ReadExecConfig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandEntry {
    pub name: String,
    pub command_path: String,
    pub timeout: u32,
}

/// Catalog of configured active response commands.
#[derive(Debug, Clone, Default)]
pub struct CommandCatalog {
    pub commands: HashMap<String, CommandEntry>,
    pub bin_dir: PathBuf,
}

impl CommandCatalog {
    pub fn new(bin_dir: PathBuf) -> Self {
        Self {
            commands: HashMap::new(),
            bin_dir,
        }
    }

    /// Reads command catalog from string matching `ReadExecConfig` (`name - command - timeout`).
    pub fn parse_config(&mut self, content: &str) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('#') {
                continue;
            }

            // Expected format: name - command - timeout
            let parts: Vec<&str> = trimmed.split(" - ").collect();
            if parts.len() < 3 {
                continue;
            }

            let name = parts[0].trim().to_string();
            let cmd_file = parts[1].trim();
            let timeout = parts[2].trim().parse::<u32>().unwrap_or(0);

            // Directory traversal check
            if cmd_file.contains("..") || cmd_file.starts_with('/') || cmd_file.starts_with('\\') {
                continue;
            }

            let full_path = self.bin_dir.join(cmd_file).to_string_lossy().to_string();
            self.commands.insert(
                name.clone(),
                CommandEntry {
                    name,
                    command_path: full_path,
                    timeout,
                },
            );
        }
    }

    /// Port of `GetCommandbyName(name, &timeout)`.
    /// Returns command path and timeout for command name.
    pub fn get_command(&self, name: &str) -> Option<(String, u32)> {
        // Custom command starting with '!'
        if let Some(stripped) = name.strip_prefix('!') {
            if stripped.contains("..") || stripped.starts_with('/') || stripped.starts_with('\\') {
                return None;
            }
            let full_path = self.bin_dir.join(stripped).to_string_lossy().to_string();
            return Some((full_path, 0));
        }

        self.commands.get(name).map(|c| (c.command_path.clone(), c.timeout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execd_config_xml() {
        let xml = r#"
        <ossec_config>
            <active-response>
                <disabled>no</disabled>
                <repeated_offenders>30, 60, 120</repeated_offenders>
            </active-response>
        </ossec_config>
        "#;

        let cfg = ExecdConfig::from_xml_str(xml).unwrap();
        assert!(!cfg.disabled);
        assert_eq!(cfg.repeated_offenders, vec![30, 60, 120]);

        let ar_json = cfg.get_ar_config();
        assert_eq!(ar_json["active-response"]["disabled"], "no");
        assert_eq!(ar_json["active-response"]["repeated_offenders"], serde_json::json!([30, 60, 120]));
    }

    #[test]
    fn test_command_catalog_parse_and_lookup() {
        let content = r#"
        # Active response command catalog
        firewall-drop - firewall-drop.sh - 0
        host-deny - host-deny.sh - 600
        disable-account - disable-account.sh - 0
        !invalid - bad.sh - 100
        traversal - ../../etc/passwd - 0
        "#;

        let mut catalog = CommandCatalog::new(PathBuf::from("/var/ossec/active-response/bin"));
        catalog.parse_config(content);

        // Standard command with timeout
        let (cmd, timeout) = catalog.get_command("host-deny").unwrap();
        assert!(cmd.ends_with("host-deny.sh"));
        assert_eq!(timeout, 600);

        // Standard command without timeout
        let (cmd, timeout) = catalog.get_command("firewall-drop").unwrap();
        assert!(cmd.ends_with("firewall-drop.sh"));
        assert_eq!(timeout, 0);

        // Traversal attempt is ignored
        assert!(catalog.get_command("traversal").is_none());

        // Custom command with '!' prefix
        let (cmd, timeout) = catalog.get_command("!custom-script.sh").unwrap();
        assert!(cmd.ends_with("custom-script.sh"));
        assert_eq!(timeout, 0);

        // Custom command with directory traversal is rejected
        assert!(catalog.get_command("!..\\bad.sh").is_none());
    }
}
