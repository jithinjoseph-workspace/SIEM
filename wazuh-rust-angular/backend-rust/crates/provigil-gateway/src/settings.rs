//! Settings from the environment, each checked against its range at start.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Settings {
    pub grpc_port: u16,
    pub tls_port: u16,
    /// `None`: all addresses, IPv4 and IPv6.
    pub bind: Option<IpAddr>,
    pub id: String,
    /// Gateways on this engine: each gives its share of a tenant's baseline slots.
    pub count: usize,
    pub public_hosts: Vec<String>,
    pub stats_addr: SocketAddr,
    pub internal_token: String,
    pub api_url: String,
    pub max_connections: usize,
    pub agent_max_eps: f64,
    pub plain_loopback: bool,
    pub plain_port: u16,
    pub home: PathBuf,
    /// The published agent package (`<dist>/windows/...`).
    pub dist: PathBuf,
    /// The install CA.
    pub tls_dir: PathBuf,
    pub tls_files: Option<(String, String)>,
    pub clickhouse_url: String,
    pub clickhouse_user: String,
    pub clickhouse_password: String,
    pub keys_secret: String,
    pub disconnection_secs: u64,
    pub enroll_per_minute: u32,
    pub enroll_per_second: u32,
    pub handshakes_per_addr: u32,
    /// Reads the engine's response and dump queues; off while the old gateway owns them.
    pub engine_queues: bool,
    pub node_name: String,
}

fn range<T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy>(get: &dyn Fn(&str) -> Option<String>, k: &str, default: T, min: T, max: T) -> Result<T, String> {
    let Some(v) = get(k) else { return Ok(default) };
    let n: T = v.parse().map_err(|_| format!("{k}: not a number: {v}"))?;
    if n < min || n > max {
        return Err(format!("{k}: {n} is outside {min}..{max}"));
    }
    Ok(n)
}

fn flag(get: &dyn Fn(&str) -> Option<String>, k: &str) -> bool {
    matches!(get(k).as_deref(), Some("1" | "true" | "yes"))
}

impl Settings {
    pub fn from_env() -> Result<Self, String> {
        Self::read(&|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
    }

    pub fn read(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        let host = sysinfo::System::host_name().unwrap_or_else(|| "localhost".into());
        let grpc_port = range(get, "GATEWAY_GRPC_PORT", 8089u16, 1, 65535)?;
        let tls_port = range(get, "GATEWAY_TLS_PORT", 8443u16, 1, 65535)?;
        if grpc_port == tls_port {
            return Err("GATEWAY_GRPC_PORT and GATEWAY_TLS_PORT are the same".into());
        }
        let bind = get("GATEWAY_BIND").map(|b| b.parse().map_err(|_| format!("GATEWAY_BIND: not an address: {b}"))).transpose()?;
        let stats = get("GATEWAY_STATS_ADDR").unwrap_or_else(|| "127.0.0.1:9101".into());
        let stats_addr: SocketAddr = stats.parse().map_err(|_| format!("GATEWAY_STATS_ADDR: not an address: {stats}"))?;
        let internal_token = get("GATEWAY_INTERNAL_TOKEN").unwrap_or_default();
        if !stats_addr.ip().is_loopback() && internal_token.is_empty() {
            return Err("GATEWAY_STATS_ADDR is not loopback: GATEWAY_INTERNAL_TOKEN is required".into());
        }
        let keys_secret = get("AGENT_KEYS_SECRET").ok_or("AGENT_KEYS_SECRET is required: agent keys are stored encrypted with it")?;
        let tls_files = match (get("SIEM_GRPC_TLS_CERT"), get("SIEM_GRPC_TLS_KEY")) {
            (Some(c), Some(k)) => Some((c, k)),
            (None, None) => None,
            _ => return Err("SIEM_GRPC_TLS_CERT and SIEM_GRPC_TLS_KEY go together".into()),
        };
        let base = || if std::path::Path::new("data").exists() { PathBuf::from("data") } else { PathBuf::from("backend-rust/data") };
        let path = |k: &str, sub: &str| get(k).map_or_else(|| base().join(sub), PathBuf::from);
        Ok(Self {
            grpc_port,
            tls_port,
            bind,
            id: get("GATEWAY_ID").unwrap_or_else(|| format!("{host}:{grpc_port}")),
            count: range(get, "GATEWAY_COUNT", 1usize, 1, 64)?,
            public_hosts: get("GATEWAY_PUBLIC_HOSTS").map(|h| h.split(',').map(|x| x.trim().to_string()).collect()).unwrap_or_default(),
            stats_addr,
            internal_token,
            api_url: get("SIEM_API_INTERNAL_URL").unwrap_or_default().trim_end_matches('/').to_string(),
            max_connections: range(get, "GATEWAY_MAX_CONNECTIONS", 25_000usize, 1, 1_000_000)?,
            agent_max_eps: range(get, "GATEWAY_AGENT_MAX_EPS", 2_000f64, 1.0, 1_000_000.0)?,
            plain_loopback: flag(get, "GATEWAY_PLAIN_LOOPBACK"),
            plain_port: range(get, "GATEWAY_PLAIN_PORT", 9088u16, 1, 65535)?,
            home: get("PROVIGIL_MANAGER_HOME").map_or_else(|| base().join("manager"), PathBuf::from),
            dist: path("GATEWAY_AGENT_DIST", "agent-dist"),
            tls_dir: path("GATEWAY_CA_DIR", "tls"),
            tls_files,
            clickhouse_url: get("CLICKHOUSE_URL").unwrap_or_else(|| "http://localhost:8123".into()),
            clickhouse_user: get("CLICKHOUSE_USER").unwrap_or_else(|| "default".into()),
            clickhouse_password: get("CLICKHOUSE_PASSWORD").unwrap_or_default(),
            keys_secret,
            disconnection_secs: range(get, "GATEWAY_DISCONNECTION_SECS", 600u64, 30, 86_400)?,
            enroll_per_minute: range(get, "GATEWAY_ENROLL_PER_MINUTE", 5u32, 1, 1_000_000)?,
            enroll_per_second: range(get, "GATEWAY_ENROLL_PER_SECOND", 100u32, 1, 100_000)?,
            handshakes_per_addr: range(get, "GATEWAY_HANDSHAKES_PER_ADDR", 50u32, 1, 1_000_000)?,
            engine_queues: flag(get, "GATEWAY_ENGINE_QUEUES"),
            node_name: get("GATEWAY_NODE_NAME").unwrap_or(host),
        })
    }

    /// The tenant's baseline slots on this gateway.
    pub fn fim_slots(&self) -> usize {
        (provigil_agent_server::agent_state::FIM_SLOTS / self.count).max(1)
    }

    /// What `/state` shows: no secret.
    pub fn public(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id, "grpc_port": self.grpc_port, "tls_port": self.tls_port, "bind": self.bind.map(|b| b.to_string()),
            "count": self.count, "public_hosts": self.public_hosts, "stats_addr": self.stats_addr.to_string(),
            "api_url": self.api_url, "max_connections": self.max_connections, "agent_max_eps": self.agent_max_eps,
            "plain_loopback": self.plain_loopback, "home": self.home, "dist": self.dist, "tls_dir": self.tls_dir,
            "clickhouse_url": self.clickhouse_url, "disconnection_secs": self.disconnection_secs,
            "enroll_per_minute": self.enroll_per_minute, "enroll_per_second": self.enroll_per_second,
            "handshakes_per_addr": self.handshakes_per_addr, "engine_queues": self.engine_queues,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(vars: &[(&str, &str)]) -> Result<Settings, String> {
        Settings::read(&|k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string()))
    }

    #[test]
    fn ranges_and_required() {
        let secret = ("AGENT_KEYS_SECRET", "s");
        assert!(read(&[]).unwrap_err().contains("AGENT_KEYS_SECRET"));
        let ok = read(&[secret]).unwrap();
        assert_eq!((ok.grpc_port, ok.tls_port, ok.fim_slots()), (8089, 8443, 20));
        assert_eq!(read(&[secret, ("GATEWAY_COUNT", "4")]).unwrap().fim_slots(), 5);
        assert!(read(&[secret, ("GATEWAY_GRPC_PORT", "0")]).is_err());
        assert!(read(&[secret, ("GATEWAY_GRPC_PORT", "x")]).is_err());
        assert!(read(&[secret, ("GATEWAY_GRPC_PORT", "8443")]).is_err());
        assert!(read(&[secret, ("GATEWAY_STATS_ADDR", "0.0.0.0:9101")]).is_err(), "not loopback needs a token");
        assert!(read(&[secret, ("SIEM_GRPC_TLS_CERT", "c")]).is_err());
        assert!(!read(&[secret, ("GATEWAY_INTERNAL_TOKEN", "t")]).unwrap().public().to_string().contains("\"t\""));
    }
}
