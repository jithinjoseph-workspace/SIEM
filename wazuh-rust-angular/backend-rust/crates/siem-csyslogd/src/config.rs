//! Wazuh Syslog Forwarder Configuration (`src/os_csyslogd/config.c`, `src/config/csyslogd-config.c`)
//!
//! Handles XML parsing of `<syslog_output>` blocks, defaults, and JSON serialization
//! matching `getCsyslogConfig()`.

use serde::{Deserialize, Serialize};
use siem_shared::regex::OSMatch;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read configuration file: {0}")]
    Io(#[from] std::io::Error),
    #[error("XML parsing error: {0}")]
    Xml(String),
    #[error("Invalid configuration: {0}")]
    Validation(String),
}

/// Syslog output format matching `DEFAULT_CSYSLOG`, `CEF_CSYSLOG`, `JSON_CSYSLOG`, `SPLUNK_CSYSLOG`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFormat {
    Default = 0,
    Cef = 1,
    Json = 2,
    Splunk = 3,
}

impl Default for SyslogFormat {
    fn default() -> Self {
        SyslogFormat::Default
    }
}

impl SyslogFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            SyslogFormat::Default => "default",
            SyslogFormat::Cef => "cef",
            SyslogFormat::Json => "json",
            SyslogFormat::Splunk => "splunk",
        }
    }

    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "default" => Some(SyslogFormat::Default),
            "cef" => Some(SyslogFormat::Cef),
            "json" => Some(SyslogFormat::Json),
            "splunk" => Some(SyslogFormat::Splunk),
            _ => None,
        }
    }
}

/// A single `<syslog_output>` destination configuration.
#[derive(Debug, Clone)]
pub struct SyslogConfig {
    pub server: String,
    pub port: u16,
    pub level: u32,
    pub rule_ids: Vec<u32>,
    pub group: Option<OSMatch>,
    pub location: Option<OSMatch>,
    pub use_fqdn: bool,
    pub priority: u32,
    pub format: SyslogFormat,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 514,
            level: 0,
            rule_ids: Vec::new(),
            group: None,
            location: None,
            use_fqdn: false,
            // local0 facility (16) * 8 + severity 4 (warning) = 132 (matching C default)
            priority: (16 * 8) + 4,
            format: SyslogFormat::Default,
        }
    }
}

impl SyslogConfig {
    /// Produces JSON representation matching `getCsyslogConfig` in `config.c`.
    pub fn to_cjson_value(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();

        if !self.server.is_empty() {
            map.insert("server".to_string(), serde_json::Value::String(self.server.clone()));
        }
        map.insert("port".to_string(), serde_json::json!(self.port));
        map.insert("level".to_string(), serde_json::json!(self.level));

        if let Some(ref grp) = self.group {
            let patterns: Vec<serde_json::Value> = grp
                .raw_pattern()
                .split('|')
                .map(|p| serde_json::Value::String(p.trim().to_string()))
                .collect();
            map.insert("group".to_string(), serde_json::Value::Array(patterns));
        }

        if !self.rule_ids.is_empty() {
            let ids: Vec<serde_json::Value> = self
                .rule_ids
                .iter()
                .map(|id| serde_json::json!(*id))
                .collect();
            map.insert("rule_id".to_string(), serde_json::Value::Array(ids));
        }

        if let Some(ref loc) = self.location {
            let patterns: Vec<serde_json::Value> = loc
                .raw_pattern()
                .split('|')
                .map(|p| serde_json::Value::String(p.trim().to_string()))
                .collect();
            map.insert("location".to_string(), serde_json::Value::Array(patterns));
        }

        map.insert(
            "use_fqdn".to_string(),
            serde_json::Value::String(if self.use_fqdn { "yes".to_string() } else { "no".to_string() }),
        );

        map.insert(
            "format".to_string(),
            serde_json::Value::String(self.format.as_str().to_string()),
        );

        serde_json::Value::Object(map)
    }
}

/// Root container for all syslog outputs
#[derive(Debug, Clone, Default)]
pub struct SyslogConfigHolder {
    pub configs: Vec<SyslogConfig>,
}

impl SyslogConfigHolder {
    /// Produces root JSON matching `{"syslog_output": [...]}`.
    pub fn to_json_config(&self) -> serde_json::Value {
        let array: Vec<serde_json::Value> = self.configs.iter().map(|c| c.to_cjson_value()).collect();
        serde_json::json!({
            "syslog_output": array
        })
    }

    /// Reads configuration from an XML string or file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_xml_str(&content)
    }

    /// Parses `<syslog_output>` entries from XML string.
    pub fn from_xml_str(xml_str: &str) -> Result<Self, ConfigError> {
        use quick_xml::events::Event;
        use quick_xml::reader::Reader;

        let mut reader = Reader::from_str(xml_str);
        reader.config_mut().trim_text(true);

        let mut configs = Vec::new();
        let mut in_syslog_output = false;
        let mut current_tag = String::new();
        let mut current_cfg = SyslogConfig::default();

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name.eq_ignore_ascii_case("syslog_output") {
                        in_syslog_output = true;
                        current_cfg = SyslogConfig::default();
                    } else if in_syslog_output {
                        current_tag = name;
                    }
                }
                Ok(Event::Text(ref e)) => {
                    if in_syslog_output && !current_tag.is_empty() {
                        let text = e.unescape().map_err(|err| ConfigError::Xml(err.to_string()))?.to_string();
                        let tag_lower = current_tag.to_ascii_lowercase();

                        match tag_lower.as_str() {
                            "server" => {
                                current_cfg.server = text.trim().to_string();
                            }
                            "port" => {
                                current_cfg.port = text.trim().parse::<u16>().map_err(|_| {
                                    ConfigError::Validation(format!("Invalid port value: {}", text))
                                })?;
                            }
                            "level" => {
                                current_cfg.level = text.trim().parse::<u32>().map_err(|_| {
                                    ConfigError::Validation(format!("Invalid level value: {}", text))
                                })?;
                            }
                            "rule_id" => {
                                // Can be comma or space separated
                                for part in text.split(&[',', ' '][..]) {
                                    let trimmed = part.trim();
                                    if !trimmed.is_empty() {
                                        let id = trimmed.parse::<u32>().map_err(|_| {
                                            ConfigError::Validation(format!("Invalid rule_id value: {}", trimmed))
                                        })?;
                                        current_cfg.rule_ids.push(id);
                                    }
                                }
                            }
                            "group" => {
                                let pattern = text.trim();
                                if !pattern.is_empty() {
                                    let osm = OSMatch::compile(pattern, 0).map_err(|err| {
                                        ConfigError::Validation(format!("Invalid group pattern '{}': {:?}", pattern, err))
                                    })?;
                                    current_cfg.group = Some(osm);
                                }
                            }
                            "location" => {
                                let pattern = text.trim();
                                if !pattern.is_empty() {
                                    let osm = OSMatch::compile(pattern, 0).map_err(|err| {
                                        ConfigError::Validation(format!("Invalid location pattern '{}': {:?}", pattern, err))
                                    })?;
                                    current_cfg.location = Some(osm);
                                }
                            }
                            "use_fqdn" => {
                                let val = text.trim().to_ascii_lowercase();
                                if val == "yes" {
                                    current_cfg.use_fqdn = true;
                                } else if val == "no" {
                                    current_cfg.use_fqdn = false;
                                } else {
                                    return Err(ConfigError::Validation(format!("Invalid use_fqdn value: {}", text)));
                                }
                            }
                            "format" => {
                                current_cfg.format = SyslogFormat::from_str_name(text.trim()).ok_or_else(|| {
                                    ConfigError::Validation(format!("Invalid format value: {}", text))
                                })?;
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name.eq_ignore_ascii_case("syslog_output") {
                        if current_cfg.server.is_empty() {
                            return Err(ConfigError::Validation(
                                "syslog_output block must have a 'server' specified".to_string(),
                            ));
                        }
                        configs.push(current_cfg.clone());
                        in_syslog_output = false;
                    } else if in_syslog_output {
                        current_tag.clear();
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(ConfigError::Xml(format!("XML parse error at position {}: {:?}", reader.buffer_position(), e))),
                _ => {}
            }
            buf.clear();
        }

        Ok(SyslogConfigHolder { configs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_syslog_output() {
        let xml = r#"
        <ossec_config>
            <syslog_output>
                <server>192.168.1.100</server>
                <port>514</port>
                <format>cef</format>
                <level>7</level>
                <rule_id>100, 200, 300</rule_id>
                <group>syscheck|authentication</group>
                <location>/var/log/*</location>
                <use_fqdn>yes</use_fqdn>
            </syslog_output>
        </ossec_config>
        "#;

        let holder = SyslogConfigHolder::from_xml_str(xml).unwrap();
        assert_eq!(holder.configs.len(), 1);

        let cfg = &holder.configs[0];
        assert_eq!(cfg.server, "192.168.1.100");
        assert_eq!(cfg.port, 514);
        assert_eq!(cfg.format, SyslogFormat::Cef);
        assert_eq!(cfg.level, 7);
        assert_eq!(cfg.rule_ids, vec![100, 200, 300]);
        assert!(cfg.use_fqdn);
        assert!(cfg.group.is_some());
        assert!(cfg.location.is_some());

        // Verify JSON representation
        let json = holder.to_json_config();
        let arr = json["syslog_output"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["server"], "192.168.1.100");
        assert_eq!(arr[0]["port"], 514);
        assert_eq!(arr[0]["format"], "cef");
        assert_eq!(arr[0]["use_fqdn"], "yes");
    }

    #[test]
    fn test_parse_multiple_syslog_outputs() {
        let xml = r#"
        <ossec_config>
            <syslog_output>
                <server>syslog.corp.net</server>
                <port>1514</port>
                <format>json</format>
            </syslog_output>
            <syslog_output>
                <server>splunk.corp.net</server>
                <format>splunk</format>
                <level>10</level>
            </syslog_output>
        </ossec_config>
        "#;

        let holder = SyslogConfigHolder::from_xml_str(xml).unwrap();
        assert_eq!(holder.configs.len(), 2);

        assert_eq!(holder.configs[0].server, "syslog.corp.net");
        assert_eq!(holder.configs[0].port, 1514);
        assert_eq!(holder.configs[0].format, SyslogFormat::Json);

        assert_eq!(holder.configs[1].server, "splunk.corp.net");
        assert_eq!(holder.configs[1].port, 514); // Default port
        assert_eq!(holder.configs[1].format, SyslogFormat::Splunk);
        assert_eq!(holder.configs[1].level, 10);
    }

    #[test]
    fn test_missing_server_fails() {
        let xml = r#"
        <ossec_config>
            <syslog_output>
                <port>514</port>
            </syslog_output>
        </ossec_config>
        "#;

        let res = SyslogConfigHolder::from_xml_str(xml);
        assert!(res.is_err());
    }
}
