//! Authd Configuration Manager (`src/os_auth/config.c` & `src/config/authd-config.c`)
//!
//! Parses `<auth>` blocks from `ossec.conf` and generates configuration JSON.

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const DEFAULT_PORT: u16 = 1515;
pub const DEFAULT_CIPHERS: &str = "HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH";
pub const DEFAULT_CENTRALIZED_GROUP: &str = "default";
pub const DEFAULT_MANAGER_CERT: &str = "etc/sslmanager.cert";
pub const DEFAULT_MANAGER_KEY: &str = "etc/sslmanager.key";
pub const AUTHD_PASS: &str = "etc/authd.pass";
pub const KEYS_FILE: &str = "etc/client.keys";

/// Force options for replacing duplicate agents matching `authd_force_options_t`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForceOptions {
    pub enabled: bool,
    pub key_mismatch: bool,
    pub disconnected_time_enabled: bool,
    pub disconnected_time: u64,
    pub after_registration_time: u64,
}

impl Default for ForceOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            key_mismatch: true,
            disconnected_time_enabled: true,
            disconnected_time: 3600,
            after_registration_time: 3600,
        }
    }
}

/// Agent key request integration configuration matching `authd_key_request_t`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct KeyRequestConfig {
    pub enabled: bool,
    pub exec_path: Option<String>,
    pub socket: Option<String>,
    pub timeout: u32,
    pub threads: u32,
    pub queue_size: u32,
    pub compatibility_flag: bool,
}

/// Complete Authd configuration matching `authd_config_t`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthdConfig {
    pub port: u16,
    pub disabled: bool,
    pub remote_enrollment: bool,
    pub ipv6: bool,
    pub use_source_ip: bool,
    pub purge: bool,
    pub use_password: bool,
    pub password: Option<String>,
    pub verify_host: bool,
    pub auto_negotiate: bool,
    pub ciphers: String,
    pub agent_ca: Option<String>,
    pub manager_cert: String,
    pub manager_key: String,
    pub timeout_sec: u64,
    pub timeout_usec: u64,
    pub worker_node: bool,
    pub allow_higher_versions: bool,
    pub force_options: ForceOptions,
    pub key_request: KeyRequestConfig,
}

impl Default for AuthdConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            disabled: false,
            remote_enrollment: true,
            ipv6: false,
            use_source_ip: false,
            purge: false,
            use_password: false,
            password: None,
            verify_host: false,
            auto_negotiate: false,
            ciphers: DEFAULT_CIPHERS.to_string(),
            agent_ca: None,
            manager_cert: DEFAULT_MANAGER_CERT.to_string(),
            manager_key: DEFAULT_MANAGER_KEY.to_string(),
            timeout_sec: 0,
            timeout_usec: 0,
            worker_node: false,
            allow_higher_versions: false,
            force_options: ForceOptions::default(),
            key_request: KeyRequestConfig::default(),
        }
    }
}

/// Parses time interval strings with units (`s`, `m`, `h`, `d`) matching `get_time_interval`.
pub fn parse_time_interval(source: &str) -> Option<u64> {
    let trimmed = source.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (num_str, multiplier) = if let Some(stripped) = trimmed.strip_suffix('d') {
        (stripped, 86400u64)
    } else if let Some(stripped) = trimmed.strip_suffix('h') {
        (stripped, 3600u64)
    } else if let Some(stripped) = trimmed.strip_suffix('m') {
        (stripped, 60u64)
    } else if let Some(stripped) = trimmed.strip_suffix('s') {
        (stripped, 1u64)
    } else {
        (trimmed, 1u64)
    };

    num_str.parse::<u64>().ok().map(|val| val * multiplier)
}

fn eval_bool(s: &str) -> Option<bool> {
    match s.trim().to_lowercase().as_str() {
        "yes" | "true" | "1" => Some(true),
        "no" | "false" | "0" => Some(false),
        _ => None,
    }
}

impl AuthdConfig {
    /// Loads configuration from an XML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::from_xml(&content)
    }

    /// Parses configuration from XML string containing `<auth>...</auth>`.
    pub fn from_xml(xml: &str) -> Result<Self, String> {
        let mut config = AuthdConfig::default();
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut in_auth = false;
        let mut in_force = false;
        let mut in_disconnected_time = false;
        let mut disconnected_time_enabled_attr: Option<bool> = None;
        let mut in_key_request = false;
        let mut in_agents = false;
        let mut current_tag = String::new();

        let mut legacy_force_insert: Option<bool> = None;
        let mut legacy_force_time: Option<u64> = None;
        let mut new_force_read = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    match tag.as_str() {
                        "auth" => in_auth = true,
                        "force" if in_auth => {
                            in_force = true;
                            new_force_read = true;
                        }
                        "disconnected_time" if in_force => {
                            in_disconnected_time = true;
                            // Check attribute `enabled`
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                if key == "enabled" {
                                    let val = String::from_utf8_lossy(&attr.value).to_string();
                                    disconnected_time_enabled_attr = eval_bool(&val);
                                }
                            }
                        }
                        "key_request" if in_auth => in_key_request = true,
                        "agents" if in_auth => in_agents = true,
                        _ => {
                            if in_auth {
                                current_tag = tag;
                            }
                        }
                    }
                }
                Ok(Event::Text(ref e)) => {
                    if !in_auth {
                        continue;
                    }
                    let text = e.unescape().map_err(|err| err.to_string())?.to_string();

                    if in_disconnected_time {
                        if let Some(interval) = parse_time_interval(&text) {
                            config.force_options.disconnected_time = interval;
                        }
                        if let Some(enabled) = disconnected_time_enabled_attr {
                            config.force_options.disconnected_time_enabled = enabled;
                        }
                    } else if in_force {
                        match current_tag.as_str() {
                            "enabled" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.force_options.enabled = b;
                                }
                            }
                            "key_mismatch" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.force_options.key_mismatch = b;
                                }
                            }
                            "after_registration_time" => {
                                if let Some(interval) = parse_time_interval(&text) {
                                    config.force_options.after_registration_time = interval;
                                }
                            }
                            _ => {}
                        }
                    } else if in_key_request {
                        match current_tag.as_str() {
                            "enabled" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.key_request.enabled = b;
                                }
                            }
                            "exec_path" => config.key_request.exec_path = Some(text),
                            "socket" => config.key_request.socket = Some(text),
                            "timeout" => {
                                if let Ok(n) = text.parse::<u32>() {
                                    config.key_request.timeout = n;
                                }
                            }
                            "threads" => {
                                if let Ok(n) = text.parse::<u32>() {
                                    config.key_request.threads = n;
                                }
                            }
                            "queue_size" => {
                                if let Ok(n) = text.parse::<u32>() {
                                    config.key_request.queue_size = n;
                                }
                            }
                            _ => {}
                        }
                    } else if in_agents {
                        if current_tag == "allow_higher_versions" {
                            if let Some(b) = eval_bool(&text) {
                                config.allow_higher_versions = b;
                            }
                        }
                    } else {
                        match current_tag.as_str() {
                            "disabled" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.disabled = b;
                                }
                            }
                            "port" => {
                                if let Ok(p) = text.parse::<u16>() {
                                    config.port = p;
                                }
                            }
                            "ipv6" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.ipv6 = b;
                                }
                            }
                            "use_source_ip" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.use_source_ip = b;
                                }
                            }
                            "purge" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.purge = b;
                                }
                            }
                            "use_password" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.use_password = b;
                                }
                            }
                            "ciphers" => config.ciphers = text,
                            "ssl_verify_host" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.verify_host = b;
                                }
                            }
                            "ssl_agent_ca" => config.agent_ca = Some(text),
                            "ssl_manager_cert" => config.manager_cert = text,
                            "ssl_manager_key" => config.manager_key = text,
                            "ssl_auto_negotiate" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.auto_negotiate = b;
                                }
                            }
                            "remote_enrollment" => {
                                if let Some(b) = eval_bool(&text) {
                                    config.remote_enrollment = b;
                                }
                            }
                            "force_insert" => {
                                legacy_force_insert = eval_bool(&text);
                            }
                            "force_time" => {
                                legacy_force_time = parse_time_interval(&text);
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Event::End(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    match tag.as_str() {
                        "auth" => in_auth = false,
                        "force" => in_force = false,
                        "disconnected_time" => {
                            in_disconnected_time = false;
                            disconnected_time_enabled_attr = None;
                        }
                        "key_request" => in_key_request = false,
                        "agents" => in_agents = false,
                        _ => {}
                    }
                    current_tag.clear();
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(format!("XML parse error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        // Apply legacy force options if new <force> block wasn't present
        if !new_force_read {
            if let Some(enabled) = legacy_force_insert {
                config.force_options.enabled = enabled;
            }
            if let Some(time) = legacy_force_time {
                if time == 0 {
                    config.force_options.disconnected_time_enabled = false;
                }
                config.force_options.disconnected_time = time;
            }
        }

        Ok(config)
    }

    /// Generates JSON output matching `getAuthdConfig()` in `config.c`.
    pub fn get_authd_config_json(&self) -> serde_json::Value {
        let mut auth = serde_json::Map::new();
        auth.insert("port".to_string(), serde_json::json!(self.port));
        auth.insert("disabled".to_string(), serde_json::json!(if self.disabled { "yes" } else { "no" }));
        auth.insert("remote_enrollment".to_string(), serde_json::json!(if self.remote_enrollment { "yes" } else { "no" }));
        auth.insert("ipv6".to_string(), serde_json::json!(if self.ipv6 { "yes" } else { "no" }));
        auth.insert("use_source_ip".to_string(), serde_json::json!(if self.use_source_ip { "yes" } else { "no" }));
        auth.insert("purge".to_string(), serde_json::json!(if self.purge { "yes" } else { "no" }));
        auth.insert("use_password".to_string(), serde_json::json!(if self.use_password { "yes" } else { "no" }));
        auth.insert("ssl_verify_host".to_string(), serde_json::json!(if self.verify_host { "yes" } else { "no" }));
        auth.insert("ssl_auto_negotiate".to_string(), serde_json::json!(if self.auto_negotiate { "yes" } else { "no" }));
        auth.insert("ciphers".to_string(), serde_json::json!(self.ciphers));
        if let Some(ref ca) = self.agent_ca {
            auth.insert("ssl_agent_ca".to_string(), serde_json::json!(ca));
        }
        auth.insert("ssl_manager_cert".to_string(), serde_json::json!(self.manager_cert));
        auth.insert("ssl_manager_key".to_string(), serde_json::json!(self.manager_key));

        // key_request
        let mut kr = serde_json::Map::new();
        kr.insert("enabled".to_string(), serde_json::json!(if self.key_request.enabled { "yes" } else { "no" }));
        if let Some(ref ep) = self.key_request.exec_path {
            kr.insert("exec_path".to_string(), serde_json::json!(ep));
        }
        if let Some(ref sk) = self.key_request.socket {
            kr.insert("socket".to_string(), serde_json::json!(sk));
        }
        if self.key_request.timeout > 0 {
            kr.insert("timeout".to_string(), serde_json::json!(self.key_request.timeout));
        }
        if self.key_request.threads > 0 {
            kr.insert("threads".to_string(), serde_json::json!(self.key_request.threads));
        }
        if self.key_request.queue_size > 0 {
            kr.insert("queue_size".to_string(), serde_json::json!(self.key_request.queue_size));
        }
        auth.insert("key_request".to_string(), serde_json::Value::Object(kr));

        // force
        let mut force = serde_json::Map::new();
        force.insert("enabled".to_string(), serde_json::json!(if self.force_options.enabled { "yes" } else { "no" }));
        force.insert("key_mismatch".to_string(), serde_json::json!(if self.force_options.key_mismatch { "yes" } else { "no" }));

        let mut disc = serde_json::Map::new();
        disc.insert("enabled".to_string(), serde_json::json!(if self.force_options.disconnected_time_enabled { "yes" } else { "no" }));
        disc.insert("value".to_string(), serde_json::json!(self.force_options.disconnected_time));
        force.insert("disconnected_time".to_string(), serde_json::Value::Object(disc));
        force.insert("after_registration_time".to_string(), serde_json::json!(self.force_options.after_registration_time));
        auth.insert("force".to_string(), serde_json::Value::Object(force));

        // agents
        let mut agents = serde_json::Map::new();
        agents.insert("allow_higher_versions".to_string(), serde_json::json!(if self.allow_higher_versions { "yes" } else { "no" }));
        auth.insert("agents".to_string(), serde_json::Value::Object(agents));

        serde_json::json!({ "auth": auth })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_time_intervals() {
        assert_eq!(parse_time_interval("30"), Some(30));
        assert_eq!(parse_time_interval("30s"), Some(30));
        assert_eq!(parse_time_interval("5m"), Some(300));
        assert_eq!(parse_time_interval("2h"), Some(7200));
        assert_eq!(parse_time_interval("1d"), Some(86400));
        assert_eq!(parse_time_interval("invalid"), None);
    }

    #[test]
    fn test_xml_config_parse() {
        let xml = r#"
        <auth>
            <port>1515</port>
            <disabled>no</disabled>
            <use_source_ip>yes</use_source_ip>
            <purge>yes</purge>
            <use_password>yes</use_password>
            <force>
                <enabled>yes</enabled>
                <key_mismatch>no</key_mismatch>
                <disconnected_time enabled="yes">2h</disconnected_time>
                <after_registration_time>30m</after_registration_time>
            </force>
            <agents>
                <allow_higher_versions>yes</allow_higher_versions>
            </agents>
        </auth>
        "#;

        let cfg = AuthdConfig::from_xml(xml).unwrap();
        assert_eq!(cfg.port, 1515);
        assert!(!cfg.disabled);
        assert!(cfg.use_source_ip);
        assert!(cfg.purge);
        assert!(cfg.use_password);
        assert!(cfg.force_options.enabled);
        assert!(!cfg.force_options.key_mismatch);
        assert_eq!(cfg.force_options.disconnected_time, 7200);
        assert_eq!(cfg.force_options.after_registration_time, 1800);
        assert!(cfg.allow_higher_versions);

        let json = cfg.get_authd_config_json();
        assert_eq!(json["auth"]["port"], 1515);
        assert_eq!(json["auth"]["use_source_ip"], "yes");
        assert_eq!(json["auth"]["force"]["disconnected_time"]["value"], 7200);
    }
}
