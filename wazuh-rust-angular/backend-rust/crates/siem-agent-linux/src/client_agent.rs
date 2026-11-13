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
    /// Empty until the agent is enrolled (client.keys / SIEM_AGENT_ID / enrollment).
    pub agent_id: String,
    pub agent_name: String,
    /// Raw agent key used for authentication (`X-Agent-Key`)
    #[serde(default)]
    pub agent_key: String,
    /// Agent group sent at enrollment (`SIEM_AGENT_GROUP` / `PROVIGIL_AGENT_GROUP`).
    pub agent_group: String,
    /// Tenant agent key (`X-Tenant-Key`), see enroll.rs.
    pub tenant_key: Option<String>,
    pub buffer_capacity: usize,
    pub events_per_second: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            manager_url: "https://127.0.0.1:8443".to_string(),
            agent_id: String::new(),
            agent_name: "provigil-linux-node".to_string(),
            agent_key: String::new(),
            agent_group: "default".to_string(),
            tenant_key: None,
            buffer_capacity: 5000,
            events_per_second: 500,
        }
    }
}

pub struct ClientAgent {
    pub config: AgentConfig,
}

impl ClientAgent {
    /// Load agent configuration from environment, JSON configuration file, or defaults.
    pub fn load_config() -> AgentConfig {
        let mut cfg = AgentConfig::default();
        let mut name_from_keys = false;
        let mut config_json: Option<serde_json::Value> = None;

        // Check client.keys (ID NAME IP KEY)
        let client_keys_candidates = [
            PathBuf::from("/opt/provigil-agent/etc/client.keys"),
            PathBuf::from("/etc/provigil-agent/client.keys"),
            PathBuf::from("client.keys"),
        ];

        for keys_path in &client_keys_candidates {
            if let Some((id, name, _ip, key)) = crate::config_parser::parse_client_keys(keys_path) {
                crate::enroll::export_agent_key(&key);
                cfg.agent_id = id;
                cfg.agent_name = name;
                cfg.agent_key = key;
                name_from_keys = true;
                info!("ClientAgent: Loaded credentials from client.keys [ID: {}, Name: {}]", cfg.agent_id, cfg.agent_name);
                break;
            }
        }

        // Check XML configuration if present
        let xml_conf = crate::config_parser::AgentXmlConfig::find_and_load();
        let mut xml_addr = xml_conf.get_manager_address();
        if xml_addr.ends_with(":1514") {
            xml_addr = format!("{}:8443", &xml_addr[..xml_addr.len() - 5]);
            if !xml_addr.starts_with("https://") {
                xml_addr = xml_addr.replace("http://", "https://");
            }
        }
        if xml_addr != "http://127.0.0.1:8088" || xml_conf.client.is_some() {
            cfg.manager_url = xml_addr;
            info!("ClientAgent: Loaded manager address from agent.conf: {}", cfg.manager_url);
        }
        if let Some(buf) = &xml_conf.client_buffer {
            cfg.buffer_capacity = buf.queue_size;
            cfg.events_per_second = buf.events_per_second;
        }

        // Check JSON configuration candidates
        let config_candidates = [
            PathBuf::from("agent-config.json"),
            PathBuf::from("/etc/provigil-agent/agent-config.json"),
            PathBuf::from("/opt/provigil-agent/etc/agent-config.json"),
        ];

        for cand in &config_candidates {
            if cand.exists() {
                if let Ok(content) = std::fs::read_to_string(cand) {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(u) = parsed.get("manager_url").and_then(|v| v.as_str()) {
                            cfg.manager_url = u.to_string();
                        }
                        // client.keys (written at enrollment) wins over the config file.
                        if cfg.agent_id.is_empty() {
                            if let Some(id) = parsed.get("agent_id").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                                cfg.agent_id = id.to_string();
                            }
                        }
                        if !name_from_keys {
                            if let Some(name) = parsed.get("agent_name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                                cfg.agent_name = name.to_string();
                            }
                        }
                        if let Some(g) = parsed.get("agent_group").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                            cfg.agent_group = g.to_string();
                        }
                        config_json = Some(parsed.clone());
                        info!("ClientAgent: Loaded configuration from {}", cand.display());
                        break;
                    }
                }
            }
        }

        // Environment variable overrides
        if let Ok(manager) = std::env::var("PROVIGIL_MANAGER").or_else(|_| std::env::var("PROVIGIL_MANAGER_IP")) {
            let port = std::env::var("PROVIGIL_MANAGER_PORT")
                .or_else(|_| std::env::var("SIEM_MANAGER_PORT"))
                .unwrap_or_else(|_| "8443".to_string());
            let proto = if port == "8443" || port == "443" { "https" } else { "http" };
            cfg.manager_url = if manager.starts_with("http") {
                manager
            } else {
                format!("{}://{}:{}", proto, manager, port)
            };
        } else if let Ok(url) = std::env::var("SIEM_MANAGER_URL") {
            cfg.manager_url = url;
        }

        // Enrolled agent keeps name in client.keys; otherwise env var, config file, or hostname.
        if !name_from_keys {
            if let Ok(name) = std::env::var("SIEM_AGENT_NAME").or_else(|_| std::env::var("PROVIGIL_AGENT_NAME")) {
                if !name.trim().is_empty() {
                    cfg.agent_name = name.trim().to_string();
                }
            } else if cfg.agent_name == "provigil-linux-node" {
                if let Some(h) = Self::host_name() {
                    cfg.agent_name = h;
                }
            }
        }
        if let Ok(g) = std::env::var("SIEM_AGENT_GROUP").or_else(|_| std::env::var("PROVIGIL_AGENT_GROUP")) {
            if !g.trim().is_empty() {
                cfg.agent_group = g.trim().to_string();
            }
        }

        // Explicit id override, only for manual setups without an identity
        // (an enrolled agent keeps the id in client.keys / its config).
        if cfg.agent_id.is_empty() && config_json.is_none() {
            if let Ok(id) = std::env::var("SIEM_AGENT_ID") {
                if !id.trim().is_empty() {
                    cfg.agent_id = id.trim().to_string();
                }
            }
        }

        cfg.tenant_key = crate::enroll::tenant_key(config_json.as_ref());

        cfg
    }

/// Host name: $HOSTNAME, else /etc/hostname, else gethostname via `hostname`.
    pub fn host_name() -> Option<String> {
        if let Ok(h) = std::env::var("HOSTNAME") {
            if !h.trim().is_empty() {
                return Some(h.trim().to_string());
            }
        }
        if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
            if !h.trim().is_empty() {
                return Some(h.trim().to_string());
            }
        }
        std::process::Command::new("hostname")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
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

    /// Dynamically discover the actual primary IP address of this host that communicates
    /// with the SIEM manager using kernel routing lookup (zero packets transmitted).
    pub fn detect_agent_ip(manager_url: &str) -> String {
        // 1. Try UDP routing socket to manager host (pure kernel routing lookup, no packets sent)
        if let Ok(url) = reqwest::Url::parse(manager_url) {
            if let Some(host) = url.host_str() {
                let port = url.port().unwrap_or(8088);
                let target = format!("{}:{}", host, port);
                if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
                    if sock.connect(&target).is_ok() {
                        if let Ok(local_addr) = sock.local_addr() {
                            let ip = local_addr.ip();
                            if !ip.is_loopback() && !ip.is_unspecified() {
                                return ip.to_string();
                            }
                        }
                    }
                }
            }
        }

        // 2. Fallback to route probe socket
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if sock.connect("8.8.8.8:80").is_ok() {
                if let Ok(local_addr) = sock.local_addr() {
                    let ip = local_addr.ip();
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        return ip.to_string();
                    }
                }
            }
        }

        // 3. Fallback: Parse hostname -I
        if let Ok(out) = std::process::Command::new("hostname").arg("-I").output() {
            let text = String::from_utf8_lossy(&out.stdout);
            for ip_cand in text.split_whitespace() {
                if let Ok(parsed) = ip_cand.parse::<std::net::IpAddr>() {
                    if !parsed.is_loopback() {
                        return parsed.to_string();
                    }
                }
            }
        }

        "127.0.0.1".to_string()
    }

    /// Write runtime state to /opt/provigil-agent/var/run/provigil-agent.state
    pub fn write_state_file(agent_id: &str, agent_name: &str, manager_url: &str, status: &str) {
        let state_dir = Path::new("/opt/provigil-agent/var/run");
        let fallback_dir = Path::new("./run");
        let target_dir = if state_dir.exists() || std::fs::create_dir_all(state_dir).is_ok() {
            state_dir
        } else {
            let _ = std::fs::create_dir_all(fallback_dir);
            fallback_dir
        };

        let now = chrono::Utc::now().to_rfc3339();
        let state_content = format!(
            "# ProVigil Agent Runtime State\n\
            status='{}'\n\
            last_keepalive='{}'\n\
            version='1.0.0'\n\
            agent_id='{}'\n\
            agent_name='{}'\n\
            manager_url='{}'\n\
            os='Linux'\n",
            status, now, agent_id, agent_name, manager_url
        );

        let state_file = target_dir.join("provigil-agent.state");
        let _ = std::fs::write(state_file, state_content);
    }

    /// Send initial registration event to SIEM Manager
    pub async fn register(&self, buffer: &AgentBuffer) {
        let distro = Self::detect_linux_distro();
        let agent_ip = Self::detect_agent_ip(&self.config.manager_url);
        let reg_msg = format!(
            "provigil-agentd[{}]: Linux Agent registered on host '{}' ({} - IP: {}). Connected to manager at {}",
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
        reg_event.metadata.insert("ip".into(), agent_ip.clone());
        reg_event.metadata.insert("os_type".into(), "linux".into());
        reg_event.metadata.insert("distribution".into(), distro);
        reg_event.metadata.insert("version".into(), "1.0.0".into());

        buffer.push(reg_event).await;
        let _ = Self::send_keepalive_http(&self.config.manager_url, &self.config.agent_id, &self.config.agent_name, &agent_ip).await;
        Self::write_state_file(&self.config.agent_id, &self.config.agent_name, &self.config.manager_url, "active");
        info!("ClientAgent: Registered agent '{}' with manager and wrote provigil-agent.state", self.config.agent_id);
    }

    /// Send direct HTTP keepalive heartbeat to manager / gateway (`POST /api/v1/agents/{id}/keepalive`)
    /// Returns `(Some(status_code), returned_commands)`.
    pub async fn send_keepalive_http(manager_url: &str, agent_id: &str, agent_name: &str, agent_ip: &str) -> (Option<u16>, Vec<serde_json::Value>) {
        let client = crate::enroll::http_builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        let endpoint = format!("{}/api/v1/agents/{}/keepalive", manager_url.trim_end_matches('/'), agent_id);
        let key = std::env::var("SIEM_AGENT_KEY").unwrap_or_default();
        let payload = serde_json::json!({
            "agent_id": agent_id,
            "agent_name": agent_name,
            "status": "active",
            "agent_ip": agent_ip,
            "version": "1.0.0",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        let mut req = client.post(&endpoint).json(&payload);
        if !agent_id.trim().is_empty() {
            req = req.header("x-agent-id", agent_id.trim());
        }
        let key_trim = key.trim();
        if !key_trim.is_empty() {
            req = req.header("x-agent-key", key_trim)
                .header("authorization", format!("Bearer {}", key_trim));
        }
        match req.send().await {
            Ok(res) if res.status().is_success() => {
                let code = res.status().as_u16();
                let body: serde_json::Value = res.json().await.unwrap_or_default();
                let cmds = body
                    .get("commands")
                    .and_then(|c| c.as_array())
                    .cloned()
                    .unwrap_or_default();
                (Some(code), cmds)
            }
            Ok(res) => {
                let code = res.status().as_u16();
                tracing::warn!("ClientAgent: Keepalive {} returned HTTP {}", endpoint, res.status());
                (Some(code), Vec::new())
            }
            Err(err) => {
                tracing::warn!("ClientAgent: Keepalive {} failed: {}", endpoint, err);
                (None, Vec::new())
            }
        }
    }

    /// Spawn periodic keepalive heartbeat worker.
    pub fn spawn_keepalive_worker(
        agent_id: String,
        agent_name: String,
        manager_url: String,
        buffer: Arc<AgentBuffer>,
        lifecycle: Arc<crate::lifecycle::LifecycleCoordinator>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let handler = crate::execd::LinuxActiveResponseHandler::new(agent_id.clone());
            let mut was_dormant = false;
            loop {
                if !lifecycle.is_active() {
                    was_dormant = true;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    if lifecycle.is_terminated() {
                        break;
                    }
                    continue;
                }
                if !was_dormant {
                    tokio::time::sleep(interval).await;
                }
                was_dormant = false;
                if lifecycle.is_terminated() {
                    break;
                }
                if !lifecycle.is_active() {
                    was_dormant = true;
                    continue;
                }
                let agent_ip = Self::detect_agent_ip(&manager_url);
                let (status_code, cmds) = Self::send_keepalive_http(&manager_url, &agent_id, &agent_name, &agent_ip).await;
                if matches!(status_code, Some(404 | 410)) {
                    if let Some(st) = lifecycle.fetch_state().await {
                        lifecycle.set_state(st);
                    }
                    continue;
                }
                if !cmds.is_empty() {
                    crate::execd::dispatch_commands(&cmds, &agent_id, &handler, &buffer, &lifecycle).await;
                }

                let mut keepalive_event = RawEvent::new(
                    &agent_id,
                    EventSource::Syslog,
                    "agent/heartbeat",
                    format!("provigil-agentd[{}]: Keepalive heartbeat from '{}'", agent_id, agent_name),
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
