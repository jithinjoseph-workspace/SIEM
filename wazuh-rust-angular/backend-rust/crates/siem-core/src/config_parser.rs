use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Root Wazuh Configuration (mirroring src/config/config.c ReadConfig)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename = "ossec_config")]
pub struct OssecConfig {
    // Agent configuration sections
    #[serde(default)]
    pub client: Option<ClientConfig>,

    #[serde(default)]
    pub client_buffer: Option<ClientBufferConfig>,

    #[serde(default)]
    pub syscheck: Option<SyscheckConfig>,

    #[serde(default)]
    pub rootcheck: Option<RootcheckConfig>,

    #[serde(default, rename = "wodle")]
    pub wodles: Vec<WodleConfig>,

    #[serde(default, rename = "localfile")]
    pub localfiles: Vec<LocalfileConfig>,

    #[serde(default, rename = "active-response")]
    pub active_responses: Vec<ActiveResponseConfig>,

    // Manager / Server configuration sections (src/config/)
    #[serde(default)]
    pub global: Option<GlobalConfig>,

    #[serde(default)]
    pub alerts: Option<AlertsConfig>,

    #[serde(default)]
    pub ruleset: Option<RulesetConfig>,

    #[serde(default, rename = "remote")]
    pub remotes: Vec<RemoteConfig>,

    #[serde(default)]
    pub auth: Option<AuthServerConfig>,

    #[serde(default, rename = "integration")]
    pub integrations: Vec<IntegrationConfig>,

    #[serde(default, rename = "syslog_output")]
    pub syslog_outputs: Vec<SyslogOutputConfig>,

    #[serde(default)]
    pub cluster: Option<ClusterConfig>,

    #[serde(default)]
    pub indexer: Option<IndexerConfig>,

    #[serde(default, rename = "vulnerability-detection")]
    pub vulnerability_detection: Option<VulnerabilityDetectionConfig>,
}

/// `<global>` block (src/config/global-config.c)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalConfig {
    #[serde(default)]
    pub email_notification: Option<String>,
    #[serde(default)]
    pub email_to: Vec<String>,
    #[serde(default)]
    pub smtp_server: Option<String>,
    #[serde(default)]
    pub email_from: Option<String>,
    #[serde(default)]
    pub email_maxperhour: Option<u32>,
    #[serde(default)]
    pub custom_alert_output: Option<String>,
    #[serde(default)]
    pub alerts_log: Option<String>,
    #[serde(default)]
    pub jsonout_output: Option<String>,
    #[serde(default)]
    pub logall: Option<String>,
    #[serde(default)]
    pub logall_json: Option<String>,
    #[serde(default, rename = "white_list")]
    pub white_list: Vec<String>,
}

/// `<alerts>` block (src/config/alerts-config.c)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlertsConfig {
    #[serde(default)]
    pub log_alert_level: Option<u32>,
    #[serde(default)]
    pub email_alert_level: Option<u32>,
}

/// `<ruleset>` block (src/config/rules-config.c)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesetConfig {
    #[serde(default, rename = "decoder_dir")]
    pub decoder_dirs: Vec<String>,
    #[serde(default, rename = "rule_dir")]
    pub rule_dirs: Vec<String>,
    #[serde(default, rename = "rule_include")]
    pub rule_includes: Vec<String>,
    #[serde(default, rename = "rule_exclude")]
    pub rule_excludes: Vec<String>,
    #[serde(default, rename = "list")]
    pub lists: Vec<String>,
}

/// `<remote>` block (src/config/remote-config.c)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RemoteConfig {
    #[serde(default)]
    pub connection: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default, rename = "allowed-ips")]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub local_ip: Option<String>,
    #[serde(default)]
    pub queue_size: Option<usize>,
}

/// `<auth>` block (src/config/authd-config.c)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthServerConfig {
    #[serde(default = "default_no")]
    pub disabled: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub use_source_ip: Option<String>,
    #[serde(default)]
    pub force_insert: Option<String>,
    #[serde(default)]
    pub force_time: Option<u64>,
    #[serde(default)]
    pub purge: Option<String>,
    #[serde(default)]
    pub use_password: Option<String>,
    #[serde(default)]
    pub ssl_verify_host: Option<String>,
}

/// `<integration>` block (src/config/integrator-config.c)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntegrationConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub hook_url: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub level: Option<u32>,
    #[serde(default)]
    pub rule_id: Vec<u32>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub event_location: Option<String>,
    #[serde(default)]
    pub alert_format: Option<String>,
}

/// `<syslog_output>` block (src/config/csyslogd-config.c)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyslogOutputConfig {
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub level: Option<u32>,
}

/// `<cluster>` block (src/config/cluster-config.c)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClusterConfig {
    #[serde(default = "default_no")]
    pub disabled: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub node_name: Option<String>,
    #[serde(default)]
    pub node_type: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub bind_addr: Option<String>,
    #[serde(default, rename = "node")]
    pub nodes: Vec<String>,
}

/// `<indexer>` block (src/config/indexer-config.c)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IndexerConfig {
    #[serde(default = "default_yes")]
    pub enabled: String,
    #[serde(default, rename = "hosts")]
    pub hosts: Vec<String>,
}

/// `<vulnerability-detection>` block (src/config/wmodules-vulnerability-detection.c)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnerabilityDetectionConfig {
    #[serde(default = "default_yes")]
    pub enabled: String,
    #[serde(default)]
    pub index_status: Option<String>,
    #[serde(default)]
    pub feed_update_interval: Option<String>,
}


/// `<client>` block in ossec.conf
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientConfig {
    #[serde(default)]
    pub server: Option<ServerConfig>,

    #[serde(default)]
    pub address: Option<String>,

    #[serde(default)]
    pub port: Option<u16>,

    #[serde(default)]
    pub protocol: Option<String>,

    #[serde(default)]
    pub crypto_method: Option<String>,

    #[serde(default, rename = "config-profile")]
    pub config_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerConfig {
    #[serde(default)]
    pub address: Option<String>,

    #[serde(default)]
    pub port: Option<u16>,

    #[serde(default)]
    pub protocol: Option<String>,
}

/// `<client_buffer>` block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientBufferConfig {
    #[serde(default = "default_no")]
    pub disabled: String,

    #[serde(default = "default_queue_size")]
    pub queue_size: usize,

    #[serde(default = "default_eps")]
    pub events_per_second: usize,
}

impl Default for ClientBufferConfig {
    fn default() -> Self {
        Self {
            disabled: "no".into(),
            queue_size: 5000,
            events_per_second: 500,
        }
    }
}

/// `<syscheck>` (FIM) block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscheckConfig {
    #[serde(default = "default_no")]
    pub disabled: String,

    #[serde(default = "default_frequency")]
    pub frequency: u64,

    #[serde(default = "default_yes")]
    pub scan_on_start: String,

    #[serde(default, rename = "directories")]
    pub directories: Vec<String>,

    #[serde(default, rename = "ignore")]
    pub ignores: Vec<String>,

    #[serde(default, rename = "windows_registry")]
    pub windows_registry: Vec<String>,
}

impl Default for SyscheckConfig {
    fn default() -> Self {
        Self {
            disabled: "no".into(),
            frequency: 43200,
            scan_on_start: "yes".into(),
            directories: vec!["/etc".into(), "/usr/bin".into(), "/usr/sbin".into(), "/bin".into()],
            ignores: vec!["/etc/mtab".into(), "/etc/hosts.deny".into()],
            windows_registry: Vec::new(),
        }
    }
}

/// `<rootcheck>` block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootcheckConfig {
    #[serde(default = "default_no")]
    pub disabled: String,

    #[serde(default = "default_frequency")]
    pub frequency: u64,

    #[serde(default)]
    pub rootkit_files: Option<String>,

    #[serde(default)]
    pub rootkit_trojans: Option<String>,
}

impl Default for RootcheckConfig {
    fn default() -> Self {
        Self {
            disabled: "no".into(),
            frequency: 43200,
            rootkit_files: None,
            rootkit_trojans: None,
        }
    }
}

/// `<wodle name="...">` block
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WodleConfig {
    #[serde(default, rename = "@name")]
    pub name: String,

    #[serde(default = "default_no")]
    pub disabled: String,

    #[serde(default)]
    pub interval: Option<String>,

    #[serde(default)]
    pub scan_on_start: Option<String>,

    #[serde(default)]
    pub hardware: Option<String>,

    #[serde(default)]
    pub os: Option<String>,

    #[serde(default)]
    pub network: Option<String>,

    #[serde(default)]
    pub packages: Option<String>,

    #[serde(default)]
    pub ports: Option<String>,

    #[serde(default)]
    pub processes: Option<String>,

    #[serde(default, rename = "policy")]
    pub policies: Vec<String>,
}

/// `<localfile>` block
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalfileConfig {
    #[serde(default)]
    pub log_format: String,

    #[serde(default)]
    pub location: String,
}

/// `<active-response>` block
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActiveResponseConfig {
    #[serde(default = "default_no")]
    pub disabled: String,

    #[serde(default)]
    pub command: String,

    #[serde(default)]
    pub location: String,

    #[serde(default)]
    pub timeout: Option<u64>,
}

fn default_no() -> String {
    "no".to_string()
}
fn default_yes() -> String {
    "yes".to_string()
}
fn default_queue_size() -> usize {
    5000
}
fn default_eps() -> usize {
    500
}
fn default_frequency() -> u64 {
    43200
}

impl OssecConfig {
    /// Parse from an XML string
    pub fn from_xml_str(xml: &str) -> Result<Self, String> {
        quick_xml::de::from_str(xml).map_err(|e| format!("Failed to parse ossec.conf XML: {}", e))
    }

    /// Load from a file path
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| format!("Failed to read {}: {}", path.as_ref().display(), e))?;
        Self::from_xml_str(&content)
    }

    /// Resolve manager IP/URL from `<client>`
    pub fn get_manager_address(&self) -> String {
        if let Some(client) = &self.client {
            if let Some(server) = &client.server {
                if let Some(addr) = &server.address {
                    let port = server.port.unwrap_or(8088);
                    return if addr.starts_with("http") {
                        addr.clone()
                    } else {
                        format!("http://{}:{}", addr, port)
                    };
                }
            }
            if let Some(addr) = &client.address {
                let port = client.port.unwrap_or(8088);
                return if addr.starts_with("http") {
                    addr.clone()
                } else {
                    format!("http://{}:{}", addr, port)
                };
            }
        }
        "http://127.0.0.1:8088".to_string()
    }

    /// Helper to find standard ossec.conf locations across operating systems
    pub fn find_and_load() -> Self {
        let candidates = [
            PathBuf::from("ossec.conf"),
            PathBuf::from("/var/ossec/etc/ossec.conf"),
            PathBuf::from("/etc/wazuh-agent/ossec.conf"),
            PathBuf::from(r"C:\Program Files (x86)\ossec-agent\ossec.conf"),
            PathBuf::from(r"C:\Program Files\ossec-agent\ossec.conf"),
        ];

        for path in &candidates {
            if path.exists() {
                if let Ok(cfg) = Self::from_file(path) {
                    return cfg;
                }
            }
        }

        Self::default()
    }
}

/// Helper to parse standard Wazuh `client.keys` (Format: `ID NAME IP KEY`)
pub fn parse_client_keys<P: AsRef<Path>>(path: P) -> Option<(String, String, String, String)> {
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 4 {
                    return Some((
                        parts[0].to_string(),
                        parts[1].to_string(),
                        parts[2].to_string(),
                        parts[3].to_string(),
                    ));
                } else if parts.len() >= 2 {
                    return Some((
                        parts[0].to_string(),
                        parts[1].to_string(),
                        "any".to_string(),
                        "".to_string(),
                    ));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sample_ossec_conf() {
        let xml = r#"
<ossec_config>
  <client>
    <server>
      <address>192.168.1.100</address>
      <port>8088</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>debian, debian8</config-profile>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories>/etc,/usr/bin</directories>
    <ignore>/etc/mtab</ignore>
  </syscheck>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
  </wodle>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <timeout>600</timeout>
  </active-response>
</ossec_config>
        "#;

        let config = OssecConfig::from_xml_str(xml).expect("Failed to parse XML");
        assert_eq!(config.get_manager_address(), "http://192.168.1.100:8088");
        assert!(config.client.is_some());
        assert_eq!(config.client.as_ref().unwrap().crypto_method.as_deref(), Some("aes"));
        assert_eq!(config.client_buffer.as_ref().unwrap().queue_size, 5000);
        assert_eq!(config.syscheck.as_ref().unwrap().disabled, "no");
        assert_eq!(config.wodles.len(), 1);
        assert_eq!(config.wodles[0].name, "syscollector");
        assert_eq!(config.localfiles.len(), 1);
        assert_eq!(config.localfiles[0].location, "/var/log/auth.log");
        assert_eq!(config.active_responses.len(), 1);
        assert_eq!(config.active_responses[0].command, "firewall-drop");
    }

    #[test]
    fn test_parse_full_manager_ossec_conf() {
        let xml = r#"
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>127.0.0.1</smtp_server>
    <email_from>ossecm@localhost</email_from>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
  </auth>

  <integration>
    <name>slack</name>
    <hook_url>https://hooks.slack.com/services/XXX</hook_url>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>

  <syslog_output>
    <server>10.0.0.50</server>
    <port>514</port>
    <format>cef</format>
    <level>5</level>
  </syslog_output>

  <cluster>
    <name>wazuh-cluster</name>
    <node_name>node01</node_name>
    <node_type>master</node_type>
    <key>9876543210abcdef9876543210abcdef</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <disabled>no</disabled>
  </cluster>
</ossec_config>
        "#;

        let config = OssecConfig::from_xml_str(xml).expect("Failed to parse Manager XML");
        assert!(config.global.is_some());
        assert_eq!(config.global.as_ref().unwrap().jsonout_output.as_deref(), Some("yes"));
        assert!(config.alerts.is_some());
        assert_eq!(config.alerts.as_ref().unwrap().log_alert_level, Some(3));
        assert_eq!(config.remotes.len(), 1);
        assert_eq!(config.remotes[0].port, Some(1514));
        assert!(config.auth.is_some());
        assert_eq!(config.auth.as_ref().unwrap().port, Some(1515));
        assert_eq!(config.integrations.len(), 1);
        assert_eq!(config.integrations[0].name, "slack");
        assert_eq!(config.syslog_outputs.len(), 1);
        assert_eq!(config.syslog_outputs[0].server, "10.0.0.50");
        assert!(config.cluster.is_some());
        assert_eq!(config.cluster.as_ref().unwrap().node_type.as_deref(), Some("master"));
    }
}

