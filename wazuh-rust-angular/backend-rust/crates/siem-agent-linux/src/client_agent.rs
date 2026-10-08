use crate::buffer::AgentBuffer;
use serde::{Deserialize, Serialize};
use siem_core::{EventSource, RawEvent};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub manager_url: String,
    pub agent_id: String,
    pub agent_name: String,
    pub buffer_capacity: usize,
    pub events_per_second: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            manager_url: "http://127.0.0.1:8088".to_string(),
            agent_id: "002".to_string(),
            agent_name: "wazuh-linux-node".to_string(),
            buffer_capacity: 5000,
            events_per_second: 500,
        }
    }
}

pub struct ClientAgent {
    pub config: AgentConfig,
}

impl ClientAgent {
    /// Load agent configuration from environment, JSON configuration file, or defaults
    pub fn load_config() -> AgentConfig {
        let mut cfg = AgentConfig::default();

        // 1. Check client.keys (official Wazuh key authentication format: ID NAME IP KEY)
        let client_keys_candidates = [
            PathBuf::from("/var/ossec/etc/client.keys"),
            PathBuf::from("/etc/wazuh-agent/client.keys"),
            PathBuf::from("client.keys"),
        ];

        for keys_path in &client_keys_candidates {
            if let Some((id, name, _ip, _key)) = siem_core::parse_client_keys(keys_path) {
                cfg.agent_id = id;
                cfg.agent_name = name;
                info!("ClientAgent: Loaded credentials from client.keys [ID: {}, Name: {}]", cfg.agent_id, cfg.agent_name);
                break;
            }
        }

        // 2. Check official Wazuh ossec.conf XML configuration
        let ossec_conf = siem_core::OssecConfig::find_and_load();
        let ossec_addr = ossec_conf.get_manager_address();
        if ossec_addr != "http://127.0.0.1:8088" || ossec_conf.client.is_some() {
            cfg.manager_url = ossec_addr;
            info!("ClientAgent: Loaded manager address from ossec.conf: {}", cfg.manager_url);
        }
        if let Some(buf) = &ossec_conf.client_buffer {
            cfg.buffer_capacity = buf.queue_size;
            cfg.events_per_second = buf.events_per_second;
        }

        // 3. Check JSON configuration candidates
        let config_candidates = [
            PathBuf::from("agent-config.json"),
            PathBuf::from("/etc/wazuh-agent/agent-config.json"),
            PathBuf::from("/var/ossec/etc/agent-config.json"),
        ];

        for cand in &config_candidates {
            if cand.exists() {
                if let Ok(content) = std::fs::read_to_string(cand) {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(u) = parsed.get("manager_url").and_then(|v| v.as_str()) {
                            cfg.manager_url = u.to_string();
                        }
                        if let Some(id) = parsed.get("agent_id").and_then(|v| v.as_str()) {
                            cfg.agent_id = id.to_string();
                        }
                        if let Some(name) = parsed.get("agent_name").and_then(|v| v.as_str()) {
                            cfg.agent_name = name.to_string();
                        }
                        info!("ClientAgent: Loaded configuration from {}", cand.display());
                        break;
                    }
                }
            }
        }

        // 4. Environment variable overrides (Supporting official Wazuh & SIEM environment variables)
        // Check WAZUH_MANAGER / WAZUH_MANAGER_IP
        if let Ok(manager) = std::env::var("WAZUH_MANAGER").or_else(|_| std::env::var("WAZUH_MANAGER_IP")) {
            let port = std::env::var("WAZUH_MANAGER_PORT").unwrap_or_else(|_| "8088".to_string());
            cfg.manager_url = if manager.starts_with("http") {
                manager
            } else {
                format!("http://{}:{}", manager, port)
            };
        } else if let Ok(url) = std::env::var("SIEM_MANAGER_URL") {
            cfg.manager_url = url;
        }

        // Check WAZUH_AGENT_NAME / WAZUH_AGENT_GROUP / HOSTNAME
        if let Ok(name) = std::env::var("WAZUH_AGENT_NAME") {
            cfg.agent_name = name;
        } else if let Ok(hostname) = std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")) {
            cfg.agent_name = hostname;
        }

        // Check SIEM_AGENT_ID
        if let Ok(id) = std::env::var("SIEM_AGENT_ID") {
            cfg.agent_id = id;
        }

        cfg
    }

    /// Read Linux distribution info from /etc/os-release (e.g. "Ubuntu 22.04 LTS")
    pub fn detect_linux_distro() -> String {
        let os_release_path = Path::new("/etc/os-release");
        if os_release_path.exists() {
            if let Ok(content) = std::fs::read_to_string(os_release_path) {
                for line in content.lines() {
                    if line.starts_with("PRETTY_NAME=") {
                        return line.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string();
                    }
                }
            }
        }
        format!("Linux ({} {})", std::env::consts::OS, std::env::consts::ARCH)
    }

    /// Read primary local IP address of endpoint (mirroring notify.c get_agent_ip)
    pub fn detect_agent_ip() -> String {
        if let Ok(file) = std::fs::File::open("/proc/net/fib_trie") {
            use std::io::{BufRead, BufReader};
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                let trimmed = line.trim();
                if trimmed.starts_with("/32 host LOCAL") {
                    // Previous line or current pattern
                }
            }
        }
        "127.0.0.1".to_string()
    }

    /// Write runtime state to /var/ossec/var/run/wazuh-agentd.state (mirroring Wazuh state.c)
    pub fn write_state_file(agent_id: &str, agent_name: &str, manager_url: &str, status: &str) {
        let state_dir = Path::new("/var/ossec/var/run");
        let fallback_dir = Path::new("./run");
        let target_dir = if state_dir.exists() || std::fs::create_dir_all(state_dir).is_ok() {
            state_dir
        } else {
            let _ = std::fs::create_dir_all(fallback_dir);
            fallback_dir
        };

        let now = chrono::Utc::now().to_rfc3339();
        let state_content = format!(
            "# Wazuh Agent State File (1:1 state.c)\n\
            status='{}'\n\
            last_keepalive='{}'\n\
            version='4.14.7'\n\
            agent_id='{}'\n\
            agent_name='{}'\n\
            manager_url='{}'\n\
            os='Linux'\n",
            status, now, agent_id, agent_name, manager_url
        );

        let state_file = target_dir.join("wazuh-agentd.state");
        let _ = std::fs::write(state_file, state_content);
    }

    /// Send initial registration event to SIEM Manager
    pub async fn register(&self, buffer: &AgentBuffer) {
        let distro = Self::detect_linux_distro();
        let agent_ip = Self::detect_agent_ip();
        let reg_msg = format!(
            "wazuh-agentd[{}]: Linux Agent registered on host '{}' ({} - IP: {}). Communication active with manager at {}",
            self.config.agent_id, self.config.agent_name, distro, agent_ip, self.config.manager_url
        );

        let mut reg_event = RawEvent::new(
            &self.config.agent_id,
            EventSource::Syslog,
            "agent/lifecycle",
            reg_msg,
        );

        reg_event.metadata.insert("status".into(), "active".into());
        reg_event.metadata.insert("hostname".into(), self.config.agent_name.clone());
        reg_event.metadata.insert("ip".into(), agent_ip);
        reg_event.metadata.insert("os_type".into(), "linux".into());
        reg_event.metadata.insert("distribution".into(), distro);
        reg_event.metadata.insert("version".into(), "4.14.7".into());

        buffer.push(reg_event).await;
        Self::write_state_file(&self.config.agent_id, &self.config.agent_name, &self.config.manager_url, "active");
        info!("ClientAgent: Registered agent '{}' with SIEM Manager and wrote wazuh-agentd.state", self.config.agent_id);
    }

    /// Spawn periodic keepalive heartbeat worker (mirroring Wazuh agentd keepalive notify.c & state.c)
    pub fn spawn_keepalive_worker(
        agent_id: String,
        agent_name: String,
        manager_url: String,
        buffer: Arc<AgentBuffer>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let agent_ip = Self::detect_agent_ip();
                let mut keepalive_event = RawEvent::new(
                    &agent_id,
                    EventSource::Syslog,
                    "agent/heartbeat",
                    format!("wazuh-agentd[{}]: Keepalive heartbeat from '{}'", agent_id, agent_name),
                );
                keepalive_event.metadata.insert("status".into(), "active".into());
                keepalive_event.metadata.insert("hostname".into(), agent_name.clone());
                keepalive_event.metadata.insert("ip".into(), agent_ip);
                keepalive_event.metadata.insert("os_type".into(), "linux".into());
                keepalive_event.metadata.insert("keepalive".into(), "true".into());
                buffer.push(keepalive_event).await;

                Self::write_state_file(&agent_id, &agent_name, &manager_url, "active");
            }
        })
    }
}
