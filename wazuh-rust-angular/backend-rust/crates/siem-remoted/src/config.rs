//! Port of `src/remoted/config.c` (`RemotedConfig`, `getRemoteConfig`,
//! `getRemoteInternalConfig`, `getRemoteGlobalConfig`): reads `<remote>` and
//! `<global>` from `ossec.conf` plus every remoted internal option.

use serde_json::{json, Value};
use siem_config::global::{read_global, GlobalConfig};
use siem_config::internal_options::InternalOptions;
use siem_config::remote::*;
use siem_config::{modules, read_config, ConfigContext, ConfigError, ConfigHandler, Platform, Section};
use siem_xml::{OsXml, XmlNode};
use std::path::{Path, PathBuf};

/// `__ossec_version`
pub const OSSEC_VERSION: &str = "v4.14.7";
pub const OSSEC_NAME: &str = "Wazuh";

/// Internal options read by `RemotedConfig()` (names and ranges as in C).
#[derive(Debug, Clone)]
pub struct InternalRemoted {
    pub receive_chunk: u32,
    pub send_chunk: u32,
    pub buffer_relax: i32,
    pub send_buffer_size: u32,
    pub send_timeout_to_retry: i32,
    pub recv_timeout: i32,
    pub tcp_keepidle: i32,
    pub tcp_keepintvl: i32,
    pub tcp_keepcnt: i32,
    pub worker_pool: i32,
    pub merge_shared: i32,
    pub pass_empty_keyfile: i32,
    pub ctrl_msg_queue_size: usize,
    pub keyupdate_interval: i32,
    pub router_forwarding_disabled: i32,
    pub state_interval: i32,
    pub rlimit_nofile: i32,
    pub sender_pool: i32,
    pub request_pool: i32,
    pub request_timeout: i32,
    pub response_timeout: i32,
    pub rto_sec: i32,
    pub rto_msec: i32,
    pub max_attempts: i32,
    pub guess_agent_group: i32,
    pub shared_reload: i32,
    pub disk_storage: i32,
    pub verify_msg_id: i32,
    /// Read by `OS_StartCounter`.
    pub recv_counter_flush: i32,
    pub comp_average_printout: i32,
    pub debug: i32,
}

impl InternalRemoted {
    pub fn load(o: &InternalOptions) -> Result<Self, ConfigError> {
        let g = |n: &str, min, max| o.get_int("remoted", n, min, max);
        Ok(Self {
            receive_chunk: g("receive_chunk", 1024, 16384)? as u32,
            send_chunk: g("send_chunk", 512, 16384)? as u32,
            buffer_relax: g("buffer_relax", 0, 2)?,
            send_buffer_size: g("send_buffer_size", 65536, 1048576)? as u32,
            send_timeout_to_retry: g("send_timeout_to_retry", 1, 60)?,
            recv_timeout: g("recv_timeout", 1, 60)?,
            tcp_keepidle: g("tcp_keepidle", 1, 7200)?,
            tcp_keepintvl: g("tcp_keepintvl", 1, 100)?,
            tcp_keepcnt: g("tcp_keepcnt", 1, 50)?,
            worker_pool: g("worker_pool", 1, 16)?,
            merge_shared: g("merge_shared", 0, 1)?,
            pass_empty_keyfile: g("pass_empty_keyfile", 0, 1)?,
            ctrl_msg_queue_size: g("control_msg_queue_size", 4096, 1 << 20)? as usize,
            keyupdate_interval: g("keyupdate_interval", 1, 3600)?,
            router_forwarding_disabled: g("router_forwarding_disabled", 0, 1)?,
            state_interval: g("state_interval", 0, 86400)?,
            rlimit_nofile: g("rlimit_nofile", 1024, 1048576)?,
            sender_pool: g("sender_pool", 1, 64)?,
            request_pool: g("request_pool", 1, 4096)?,
            request_timeout: g("request_timeout", 1, 600)?,
            response_timeout: g("response_timeout", 1, 3600)?,
            rto_sec: g("request_rto_sec", 0, 60)?,
            rto_msec: g("request_rto_msec", 0, 999)?,
            max_attempts: g("max_attempts", 1, 16)?,
            guess_agent_group: g("guess_agent_group", 0, 1)?,
            shared_reload: g("shared_reload", 1, 18000)?,
            disk_storage: g("disk_storage", 0, 1)?,
            verify_msg_id: g("verify_msg_id", 0, 1)?,
            recv_counter_flush: g("recv_counter_flush", 10, 999999)?,
            comp_average_printout: g("comp_average_printout", 10, 999999)?,
            debug: g("debug", 0, 2)?,
        })
    }
}

/// Paths derived from the Wazuh home directory (chroot-relative in C).
#[derive(Debug, Clone)]
pub struct Paths {
    pub home: PathBuf,
}

impl Paths {
    pub fn new(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into() }
    }
    fn j(&self, rel: &str) -> String {
        self.home.join(rel).to_string_lossy().replace('\\', "/")
    }
    pub fn ossec_conf(&self) -> String { self.j("etc/ossec.conf") }
    pub fn keys_file(&self) -> String { self.j("etc/client.keys") }
    pub fn rids_dir(&self) -> String { self.j("queue/rids") }
    pub fn shared_dir(&self) -> String { self.j("etc/shared") }
    pub fn multigroups_dir(&self) -> String { self.j("var/multigroups") }
    pub fn download_dir(&self) -> String { self.j("var/download") }
    pub fn default_ar(&self) -> String { self.j("etc/shared/ar.conf") }
    pub fn queue(&self) -> String { self.j("queue/sockets/queue") }
    pub fn ar_queue(&self) -> String { self.j("queue/alerts/ar") }
    pub fn cfga_queue(&self) -> String { self.j("queue/alerts/cfgarq") }
    pub fn remote_local_sock(&self) -> String { self.j("queue/sockets/remote") }
    pub fn key_request_sock(&self) -> String { self.j("queue/sockets/krequest") }
    pub fn wdb_sock(&self) -> String { self.j("queue/db/wdb") }
    pub fn state_file(&self) -> String { self.j("var/run/wazuh-remoted.state") }
}

/// Everything remoted reads at startup.
#[derive(Debug, Clone)]
pub struct RemotedSettings {
    pub remote: RemotedConfig,
    pub internal: InternalRemoted,
    pub node_name: String,
    pub worker_node: bool,
    pub paths: Paths,
    pub warnings: Vec<String>,
}

struct Handler<'a> {
    remote: &'a mut RemotedConfig,
    global: GlobalConfig,
}

impl ConfigHandler for Handler<'_> {
    fn section(
        &mut self,
        ctx: &mut ConfigContext,
        xml: &OsXml,
        s: Section,
        _node: &XmlNode,
        ch: Option<&[XmlNode]>,
    ) -> siem_config::Result<()> {
        match s {
            Section::Remote => read_remote(ctx, xml, ch.unwrap_or(&[]), self.remote),
            Section::Global => {
                read_global(ctx, xml, ch.unwrap_or(&[]), Some(&mut self.global), None, false, cfg!(windows))
            }
            _ => Ok(()),
        }
    }
}

impl RemotedSettings {
    /// `RemotedConfig()` + the checks done in remoted's `main()`.
    pub fn load(home: impl AsRef<Path>, cfgfile: Option<&str>, nocmerged: bool) -> Result<Self, ConfigError> {
        let paths = Paths::new(home.as_ref());
        let opts = InternalOptions::from_home(home.as_ref());
        let mut internal = InternalRemoted::load(&opts)?;
        let mut remote = RemotedConfig::default();
        let cfg = cfgfile.map(String::from).unwrap_or_else(|| paths.ossec_conf());

        let mut ctx = ConfigContext::new(Platform::MANAGER);
        // Read_Global needs a _Config preloaded with remoted's defaults.
        let mut h = Handler { remote: &mut remote, global: GlobalConfig::default() };
        h.global.agents_disconnection_time = 900;
        h.global.agents_disconnection_alert_time = 0;
        read_config(&mut ctx, modules::CREMOTE | modules::CGLOBAL, &cfg, None, &mut h)?;
        let gt = h.global.agents_disconnection_time;
        let gat = h.global.agents_disconnection_alert_time;
        remote.agents_disconnection_time = gt;
        remote.agents_disconnection_alert_time = gat;

        if remote.queue_size < 1 {
            return Err(ConfigError::new("Queue size is invalid. Review configuration."));
        }
        if remote.queue_size > 262144 {
            ctx.warn("Queue size is very high. The application may run out of memory.");
        }
        if internal.worker_pool > 1 && internal.verify_msg_id == 1 {
            return Err(ConfigError::new("Message id verification can't be guaranteed when worker_pool is greater than 1."));
        }
        if nocmerged {
            internal.merge_shared = 0;
        }
        let worker_node = siem_config::cluster::is_worker(Path::new(&cfg)) == Some(true);
        if worker_node {
            tracing::debug!("Cluster worker node: Disabling the merged.mg creation");
            internal.merge_shared = 0;
        }
        if remote.connections.is_empty() {
            return Err(ConfigError::new("Remoted connection is not configured."));
        }
        let node_name = siem_config::cluster::node_name(Path::new(&cfg));
        Ok(Self { remote, internal, node_name, worker_node, paths, warnings: ctx.warnings })
    }

    /// `getRemoteConfig`
    pub fn remote_json(&self, position: usize) -> Value {
        let mut arr = Vec::new();
        for (i, c) in self.remote.connections.iter().enumerate() {
            let mut o = serde_json::Map::new();
            if c.conn == SYSLOG_CONN {
                o.insert("connection".into(), json!("syslog"));
            } else if c.conn == SECURE_CONN {
                o.insert("connection".into(), json!("secure"));
            }
            o.insert("ipv6".into(), json!(if c.ipv6 { "yes" } else { "no" }));
            if let Some(l) = &c.lip {
                o.insert("local_ip".into(), json!(l));
            }
            let mut proto = Vec::new();
            if c.proto & REMOTED_NET_PROTOCOL_TCP != 0 {
                proto.push(json!("TCP"));
            }
            if c.proto & REMOTED_NET_PROTOCOL_UDP != 0 {
                proto.push(json!("UDP"));
            }
            o.insert("protocol".into(), Value::Array(proto));
            if c.port != 0 {
                o.insert("port".into(), json!(c.port.to_string()));
            }
            if c.conn == SECURE_CONN {
                o.insert("queue_size".into(), json!(self.remote.queue_size.to_string()));
                o.insert(
                    "agents".into(),
                    json!({"allow_higher_versions": if self.remote.allow_higher_versions { "yes" } else { "no" }}),
                );
            }
            if !self.remote.allowips.is_empty() && i != position {
                o.insert("allowed-ips".into(), json!(self.remote.allowips.iter().map(|ip| ip.ip.clone()).collect::<Vec<_>>()));
            }
            if !self.remote.denyips.is_empty() && i != position {
                o.insert("denied-ips".into(), json!(self.remote.denyips.iter().map(|ip| ip.ip.clone()).collect::<Vec<_>>()));
            }
            o.insert("connection_overtake_time".into(), json!(self.remote.connection_overtake_time));
            arr.push(Value::Object(o));
        }
        json!({ "remote": arr })
    }

    /// `getRemoteInternalConfig`
    pub fn internal_json(&self) -> Value {
        let i = &self.internal;
        json!({"internal": {"remoted": {
            "recv_counter_flush": i.recv_counter_flush,
            "comp_average_printout": i.comp_average_printout,
            "verify_msg_id": i.verify_msg_id,
            "recv_timeout": i.recv_timeout,
            "pass_empty_keyfile": i.pass_empty_keyfile,
            "sender_pool": i.sender_pool,
            "request_pool": i.request_pool,
            "request_rto_sec": i.rto_sec,
            "request_rto_msec": i.rto_msec,
            "max_attempts": i.max_attempts,
            "request_timeout": i.request_timeout,
            "response_timeout": i.response_timeout,
            "shared_reload": i.shared_reload,
            "disk_storage": i.disk_storage,
            "rlimit_nofile": i.rlimit_nofile,
            "merge_shared": i.merge_shared,
            "guess_agent_group": i.guess_agent_group,
            "receive_chunk": i.receive_chunk,
            "send_chunk": i.send_chunk,
            "buffer_relax": i.buffer_relax,
            "send_buffer_size": i.send_buffer_size,
            "send_timeout_to_retry": i.send_timeout_to_retry,
            "tcp_keepidle": i.tcp_keepidle,
            "tcp_keepintvl": i.tcp_keepintvl,
            "tcp_keepcnt": i.tcp_keepcnt,
            "debug": i.debug,
            "worker_pool": i.worker_pool,
            "control_msg_queue_size": i.ctrl_msg_queue_size,
            "keyupdate_interval": i.keyupdate_interval,
            "router_forwarding_disabled": i.router_forwarding_disabled,
            "state_interval": i.state_interval
        }}})
    }

    /// `getRemoteGlobalConfig`
    pub fn global_json(&self) -> Value {
        json!({"global": {"remoted": {
            "agents_disconnection_alert_time": self.remote.agents_disconnection_alert_time,
            "agents_disconnection_time": self.remote.agents_disconnection_time
        }}})
    }
}

/// `compare_wazuh_versions(v1, v2, compare_patch)`
pub fn compare_wazuh_versions(v1: Option<&str>, v2: Option<&str>, compare_patch: bool) -> i32 {
    fn parse(v: Option<&str>) -> (i32, i32, i32) {
        let Some(v) = v else { return (0, 0, 0) };
        // strncpy(ver, version, 9)
        let mut s: String = v.chars().take(9).collect();
        if let Some(p) = s.find('v') {
            s = s[p + 1..].to_string();
        }
        let mut it = s.split('.').filter(|t| !t.is_empty());
        let a = it.next().map(siem_config::util::atoi).unwrap_or(0);
        let b = it.next().map(siem_config::util::atoi).unwrap_or(0);
        let c = it.next().map(siem_config::util::atoi).unwrap_or(0);
        (a, b, c)
    }
    let (a1, b1, c1) = parse(v1);
    let (a2, b2, c2) = parse(v2);
    use std::cmp::Ordering::*;
    let ord = a1.cmp(&a2).then(b1.cmp(&b2)).then(if compare_patch { c1.cmp(&c2) } else { Equal });
    match ord {
        Less => -1,
        Equal => 0,
        Greater => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(compare_wazuh_versions(Some("v4.14.7"), Some("v4.15.0"), false), -1);
        assert_eq!(compare_wazuh_versions(Some("v4.14.7"), Some("v4.14.9"), false), 0);
        assert_eq!(compare_wazuh_versions(Some("v4.14.7"), Some("v4.14.9"), true), -1);
        assert_eq!(compare_wazuh_versions(Some("v4.14.7"), Some("Wazuh v3.13.0"), false), 1);
        assert_eq!(compare_wazuh_versions(Some("v4.14.7"), None, false), 1);
    }
}
