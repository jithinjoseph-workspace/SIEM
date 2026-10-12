//! Wazuh Logcollector Configuration Parser (src/logcollector/config.c, localfile-config.h)
//!
//! Parses `<localfile>` and `<socket>` blocks from `ossec.conf`.
//! Supports 20+ log formats, multiline regex configurations, ignore/restrict regexes,
//! out_format formatting, command execution, and query filtering.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Supported log formats matching `localfile-config.h`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Syslog,
    Json,
    SnortFull,
    SnortFast,
    Nmapg,
    MysqlLog,
    MssqlLog,
    PostgresqlLog,
    DjbMultilog,
    Command,
    FullCommand,
    Audit,
    Journald,
    Macos,
    EventChannel,
    EventLog,
    MultiLine,
    MultiLineRegex,
    Ucs2Le,
    Ucs2Be,
    OssecAlert,
}

impl Default for LogFormat {
    fn default() -> Self {
        LogFormat::Syslog
    }
}

impl LogFormat {
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "syslog" => Some(LogFormat::Syslog),
            "json" => Some(LogFormat::Json),
            "snort-full" => Some(LogFormat::SnortFull),
            "snort-fast" => Some(LogFormat::SnortFast),
            "nmapg" => Some(LogFormat::Nmapg),
            "mysql_log" | "mysql" => Some(LogFormat::MysqlLog),
            "mssql_log" | "mssql" => Some(LogFormat::MssqlLog),
            "postgresql_log" | "postgresql" => Some(LogFormat::PostgresqlLog),
            "djb-multilog" => Some(LogFormat::DjbMultilog),
            "command" => Some(LogFormat::Command),
            "full_command" => Some(LogFormat::FullCommand),
            "audit" => Some(LogFormat::Audit),
            "journald" => Some(LogFormat::Journald),
            "macos" => Some(LogFormat::Macos),
            "eventchannel" => Some(LogFormat::EventChannel),
            "eventlog" => Some(LogFormat::EventLog),
            "multi-line" => Some(LogFormat::MultiLine),
            "multi-line-regex" => Some(LogFormat::MultiLineRegex),
            "ucs2-le" | "ucs2_le" => Some(LogFormat::Ucs2Le),
            "ucs2-be" | "ucs2_be" => Some(LogFormat::Ucs2Be),
            "ossecalert" => Some(LogFormat::OssecAlert),
            _ => None,
        }
    }

    pub fn as_str_name(&self) -> &'static str {
        match self {
            LogFormat::Syslog => "syslog",
            LogFormat::Json => "json",
            LogFormat::SnortFull => "snort-full",
            LogFormat::SnortFast => "snort-fast",
            LogFormat::Nmapg => "nmapg",
            LogFormat::MysqlLog => "mysql_log",
            LogFormat::MssqlLog => "mssql_log",
            LogFormat::PostgresqlLog => "postgresql_log",
            LogFormat::DjbMultilog => "djb-multilog",
            LogFormat::Command => "command",
            LogFormat::FullCommand => "full_command",
            LogFormat::Audit => "audit",
            LogFormat::Journald => "journald",
            LogFormat::Macos => "macos",
            LogFormat::EventChannel => "eventchannel",
            LogFormat::EventLog => "eventlog",
            LogFormat::MultiLine => "multi-line",
            LogFormat::MultiLineRegex => "multi-line-regex",
            LogFormat::Ucs2Le => "ucs2-le",
            LogFormat::Ucs2Be => "ucs2-be",
            LogFormat::OssecAlert => "ossecalert",
        }
    }
}

/// End-of-line replacement strategy for multiline logs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MultilineReplaceType {
    NoReplace,
    None,
    Wspace,
    Tab,
}

impl Default for MultilineReplaceType {
    fn default() -> Self {
        MultilineReplaceType::NoReplace
    }
}

/// Multiline matching type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MultilineMatchType {
    Start,
    All,
    End,
}

impl Default for MultilineMatchType {
    fn default() -> Self {
        MultilineMatchType::Start
    }
}

/// Configuration for multiline-regex format
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultilineConfig {
    pub regex: String,
    pub match_type: MultilineMatchType,
    pub replace_type: MultilineReplaceType,
    pub timeout: u32,
}

impl Default for MultilineConfig {
    fn default() -> Self {
        Self {
            regex: String::new(),
            match_type: MultilineMatchType::Start,
            replace_type: MultilineReplaceType::NoReplace,
            timeout: 5,
        }
    }
}

/// Out-format specification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutFormat {
    pub target: Option<String>,
    pub format: String,
}

/// Individual `<localfile>` configuration entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalFileConfig {
    pub location: Option<String>,
    pub log_format: LogFormat,
    pub command: Option<String>,
    pub alias: Option<String>,
    pub frequency: Option<u32>,
    pub query: Option<String>,
    pub query_type: Option<String>,
    pub query_level: Option<String>,
    pub reconnect_time: u32,
    pub only_future_events: bool,
    pub ignore: Vec<String>,
    pub restrict: Vec<String>,
    pub target: Vec<String>,
    pub out_format: Vec<OutFormat>,
    pub multiline: Option<MultilineConfig>,
    pub age: Option<String>,
    pub exclude: Option<String>,
}

impl Default for LocalFileConfig {
    fn default() -> Self {
        Self {
            location: None,
            log_format: LogFormat::Syslog,
            command: None,
            alias: None,
            frequency: None,
            query: None,
            query_type: None,
            query_level: None,
            reconnect_time: 5,
            only_future_events: false,
            ignore: Vec::new(),
            restrict: Vec::new(),
            target: Vec::new(),
            out_format: Vec::new(),
            multiline: None,
            age: None,
            exclude: None,
        }
    }
}

/// Forwarder socket configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketForwarderConfig {
    pub name: String,
    pub location: String,
    pub mode: String,
    pub prefix: Option<String>,
}

/// Global LogCollector Configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogCollectorConfig {
    pub localfiles: Vec<LocalFileConfig>,
    pub sockets: Vec<SocketForwarderConfig>,
    pub loop_timeout: u32,
    pub open_file_attempts: u32,
    pub vcheck_files: u32,
    pub maximum_lines: u32,
    pub force_reload: bool,
    pub reload_interval: u32,
    pub reload_delay: u32,
    pub free_excluded_files_interval: u32,
    pub state_interval: u32,
    pub sample_log_length: usize,
    pub accept_remote: bool,
}

impl Default for LogCollectorConfig {
    fn default() -> Self {
        Self {
            localfiles: Vec::new(),
            sockets: Vec::new(),
            loop_timeout: 2,
            open_file_attempts: 2,
            vcheck_files: 64,
            maximum_lines: 10000,
            force_reload: false,
            reload_interval: 30,
            reload_delay: 2,
            free_excluded_files_interval: 60,
            state_interval: 10,
            sample_log_length: 1024,
            accept_remote: true,
        }
    }
}

impl LogCollectorConfig {
    /// Parse `<localfile>` and `<socket>` blocks from XML configuration
    pub fn parse_xml(xml: &str) -> Result<Self, String> {
        let os_xml = siem_shared::xml::OsXml::parse_str(xml)?;
        let mut config = LogCollectorConfig::default();

        // 1. Parse localfiles
        let lf_nodes = os_xml.get_elements_by_path(&["ossec_config", "localfile"]);
        for elem in lf_nodes {
            let mut lf = LocalFileConfig::default();

            if let Some(loc) = elem.get_child("location") {
                lf.location = Some(loc.content.clone());
            }
            if let Some(fmt) = elem.get_child("log_format") {
                if let Some(parsed_fmt) = LogFormat::from_str_name(&fmt.content) {
                    lf.log_format = parsed_fmt;
                }
            }
            if let Some(cmd) = elem.get_child("command") {
                lf.command = Some(cmd.content.clone());
            }
            if let Some(alias) = elem.get_child("alias") {
                lf.alias = Some(alias.content.clone());
            }
            if let Some(freq) = elem.get_child("frequency") {
                if let Ok(val) = freq.content.parse::<u32>() {
                    lf.frequency = Some(val);
                }
            }
            if let Some(q) = elem.get_child("query") {
                lf.query = Some(q.content.clone());
            }
            if let Some(rec) = elem.get_child("reconnect_time") {
                if let Ok(val) = rec.content.parse::<u32>() {
                    lf.reconnect_time = val;
                }
            }
            if let Some(ofe) = elem.get_child("only-future-events") {
                lf.only_future_events = ofe.content.eq_ignore_ascii_case("yes") || ofe.content.eq_ignore_ascii_case("true");
            }
            if let Some(ign) = elem.get_child("ignore") {
                lf.ignore.push(ign.content.clone());
            }
            if let Some(rest) = elem.get_child("restrict") {
                lf.restrict.push(rest.content.clone());
            }
            if let Some(tgt) = elem.get_child("target") {
                lf.target.push(tgt.content.clone());
            }
            if let Some(excl) = elem.get_child("exclude") {
                lf.exclude = Some(excl.content.clone());
            }
            if let Some(age) = elem.get_child("age") {
                lf.age = Some(age.content.clone());
            }

            // Multiline regex
            if let Some(ml_elem) = elem.get_child("multiline_regex") {
                let mut ml = MultilineConfig::default();
                ml.regex = ml_elem.content.clone();

                if let Some(attr) = ml_elem.attributes.get("match") {
                    match attr.to_ascii_lowercase().as_str() {
                        "all" => ml.match_type = MultilineMatchType::All,
                        "end" => ml.match_type = MultilineMatchType::End,
                        _ => ml.match_type = MultilineMatchType::Start,
                    }
                }
                if let Some(attr) = ml_elem.attributes.get("replace") {
                    match attr.to_ascii_lowercase().as_str() {
                        "none" => ml.replace_type = MultilineReplaceType::None,
                        "wspace" => ml.replace_type = MultilineReplaceType::Wspace,
                        "tab" => ml.replace_type = MultilineReplaceType::Tab,
                        _ => ml.replace_type = MultilineReplaceType::NoReplace,
                    }
                }
                if let Some(attr) = ml_elem.attributes.get("timeout") {
                    if let Ok(val) = attr.parse::<u32>() {
                        ml.timeout = val;
                    }
                }

                lf.multiline = Some(ml);
            }

            // Out format
            if let Some(out_elem) = elem.get_child("out_format") {
                let target = out_elem.attributes.get("target").cloned();
                lf.out_format.push(OutFormat {
                    target,
                    format: out_elem.content.clone(),
                });
            }

            config.localfiles.push(lf);
        }

        // 2. Parse sockets
        let sock_nodes = os_xml.get_elements_by_path(&["ossec_config", "socket"]);
        for elem in sock_nodes {
            let name = elem.get_child("name").map(|e| e.content.clone()).unwrap_or_default();
            let location = elem.get_child("location").map(|e| e.content.clone()).unwrap_or_default();
            let mode = elem.get_child("mode").map(|e| e.content.clone()).unwrap_or_else(|| "udp".to_string());
            let prefix = elem.get_child("prefix").map(|e| e.content.clone());

            config.sockets.push(SocketForwarderConfig {
                name,
                location,
                mode,
                prefix,
            });
        }

        Ok(config)
    }

    /// Read configuration from file
    pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::parse_xml(&content)
    }

    /// JSON generator matching `getLocalfileConfig(void)` in `src/logcollector/config.c`
    pub fn get_localfile_config_json(&self) -> serde_json::Value {
        let files: Vec<serde_json::Value> = self.localfiles.iter().map(|lf| {
            let mut obj = serde_json::Map::new();
            if let Some(ref loc) = lf.location {
                obj.insert("file".to_string(), serde_json::Value::String(loc.clone()));
            }
            obj.insert("logformat".to_string(), serde_json::Value::String(lf.log_format.as_str_name().to_string()));
            if let Some(ref cmd) = lf.command {
                obj.insert("command".to_string(), serde_json::Value::String(cmd.clone()));
            }
            if let Some(ref alias) = lf.alias {
                obj.insert("alias".to_string(), serde_json::Value::String(alias.clone()));
            }
            if let Some(freq) = lf.frequency {
                obj.insert("frequency".to_string(), serde_json::json!(freq));
            }
            if let Some(ref q) = lf.query {
                obj.insert("query".to_string(), serde_json::Value::String(q.clone()));
            }
            if !lf.ignore.is_empty() {
                obj.insert("ignore".to_string(), serde_json::json!(lf.ignore));
            }
            if !lf.restrict.is_empty() {
                obj.insert("restrict".to_string(), serde_json::json!(lf.restrict));
            }
            if !lf.target.is_empty() {
                obj.insert("target".to_string(), serde_json::json!(lf.target));
            }
            serde_json::Value::Object(obj)
        }).collect();

        serde_json::json!({
            "localfile": files
        })
    }

    /// JSON generator matching `getSocketConfig(void)` in `src/logcollector/config.c`
    pub fn get_socket_config_json(&self) -> serde_json::Value {
        let socks: Vec<serde_json::Value> = self.sockets.iter().map(|s| {
            serde_json::json!({
                "name": s.name,
                "location": s.location,
                "mode": s.mode,
                "prefix": s.prefix,
            })
        }).collect();

        serde_json::json!({
            "socket": socks
        })
    }

    /// JSON generator matching `getLogcollectorInternalOptions(void)` in `src/logcollector/config.c`
    pub fn get_internal_options_json(&self) -> serde_json::Value {
        serde_json::json!({
            "logcollector": {
                "loop_timeout": self.loop_timeout,
                "open_file_attempts": self.open_file_attempts,
                "vcheck_files": self.vcheck_files,
                "max_lines": self.maximum_lines,
                "reload_interval": self.reload_interval,
                "reload_delay": self.reload_delay,
                "state_interval": self.state_interval,
                "sample_log_length": self.sample_log_length
            }
        })
    }
}
