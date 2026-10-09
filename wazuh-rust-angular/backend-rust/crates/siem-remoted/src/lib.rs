//! `siem-remoted`: port of Wazuh's `wazuh-remoted` (`src/remoted/`).
//!
//! Speaks the real Wazuh agent protocol on 1514/TCP+UDP: framed TCP
//! (`OS_SendSecureTCP`), `!<id>!` dynamic-IP prefixes, AES/Blowfish
//! `ReadSecMSG`/`CreateSecMSG` (via `siem-crypto`), control messages
//! (startup/shutdown/keepalive/requests), shared-file (`merged.mg`)
//! distribution, active-response forwarding, the `queue/sockets/remote` API
//! socket, remote syslog, and the wazuh-db updates a C remoted performs.

pub mod agent_info;
pub mod config;
pub mod forwarders;
pub mod keystore;
pub mod manager;
pub mod mq;
pub mod request;
pub mod router;
pub mod server;
pub mod shared_download;
pub mod state;
pub mod syslog;
pub mod wdb;

use config::RemotedSettings;
use keystore::KeyStore;
use manager::{CtrlQueue, Files, PendingData};
use siem_config::remote::{REMOTED_NET_PROTOCOL_TCP, REMOTED_NET_PROTOCOL_UDP, SECURE_CONN, SYSLOG_CONN};
use siem_crypto::msgs::{CounterStore, SenderCounter};
use siem_ipc::wdbc::WdbQuery;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

/// Seconds since the epoch (`time(NULL)`).
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Truncate to at most `max` bytes on a char boundary (`snprintf` limits).
pub fn truncate_bytes(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

/// Worker nodes ask the master to assign groups (`assign_group_to_agent_worker`
/// via the cluster's `sendsync`).
#[async_trait::async_trait]
pub trait ClusterClient: Send + Sync {
    async fn assign_group(&self, agent_id: &str, md5: &str) -> Option<String>;
}

/// No cluster daemon available.
pub struct NoCluster;

#[async_trait::async_trait]
impl ClusterClient for NoCluster {
    async fn assign_group(&self, _agent_id: &str, _md5: &str) -> Option<String> {
        tracing::error!("Cluster communication is not available to assign agent groups from a worker node.");
        None
    }
}

/// Shared state of the daemon (the globals of the C remoted).
pub struct Remoted {
    pub settings: RemotedSettings,
    pub keys: RwLock<KeyStore>,
    pub counters: Mutex<CounterStore>,
    pub sender_counter: Mutex<SenderCounter>,
    pub conns: server::ConnTable,
    pub next_sock: AtomicI64,
    pub udp: OnceLock<Arc<tokio::net::UdpSocket>>,
    pub msgq: server::MsgQueue,
    pub global_counter: AtomicU64,
    pub netcounter: Mutex<HashMap<i64, u64>>,
    pub ctrl_queue: CtrlQueue,
    pub state: state::State,
    pub mq: mq::Mq,
    pub wdb: Arc<dyn WdbQuery>,
    pub router: Box<dyn router::Router>,
    pub cluster: Box<dyn ClusterClient>,
    pub krequest_tx: tokio::sync::mpsc::Sender<String>,
    krequest_rx: Mutex<Option<tokio::sync::mpsc::Receiver<String>>>,
    pub key_request_available: AtomicBool,
    pub agent_versions: Mutex<HashMap<String, String>>,
    pub current_ts: AtomicI64,
    pub files: Mutex<Files>,
    pub pending: Mutex<HashMap<String, PendingData>>,
    pub pending_queue: manager::PendingQueue,
    pub pending_notify: tokio::sync::Notify,
    pub shared_download: shared_download::SharedDownload,
    pub requests: request::Requests,
    self_ref: OnceLock<Weak<Remoted>>,
}

/// External collaborators (all have defaults suitable for a standalone manager).
pub struct Deps {
    pub wdb: Arc<dyn WdbQuery>,
    pub sink: Box<dyn mq::EventSink>,
    pub router: Box<dyn router::Router>,
    pub cluster: Box<dyn ClusterClient>,
    pub downloader: Box<dyn shared_download::Downloader>,
}

impl Deps {
    /// Talk to the other daemons through their Wazuh sockets.
    pub fn sockets(settings: &RemotedSettings) -> Self {
        Self {
            wdb: Arc::new(siem_ipc::wdbc::WdbcSocket::new(settings.paths.wdb_sock())),
            sink: Box::new(mq::QueueSocket::new(settings.paths.queue())),
            #[cfg(target_os = "linux")]
            router: Box::new(router::WazuhRouter::new()),
            #[cfg(not(target_os = "linux"))]
            router: Box::new(router::NoRouter),
            cluster: Box::new(NoCluster),
            downloader: Box::new(shared_download::HttpDownloader),
        }
    }
}

impl Remoted {
    /// Build the daemon state: read keys and counters (`OS_ReadKeys`,
    /// `OS_StartCounter`) and initialise every queue.
    pub fn new(settings: RemotedSettings, deps: Deps) -> Result<Arc<Self>, keystore::KeysError> {
        let i = &settings.internal;
        let keys = KeyStore::read(&settings.paths.keys_file(), i.pass_empty_keyfile == 1, false)?;
        let counters = CounterStore::new(settings.paths.rids_dir(), i.recv_counter_flush as u32);
        for e in &keys.entries {
            let mut st = e.state.lock().unwrap();
            counters.start_agent(&mut st.key);
        }
        let sender = counters.load_sender();
        let (ktx, krx) = tokio::sync::mpsc::channel(1024);
        let sd = shared_download::SharedDownload::new(&settings.paths.shared_dir(), &settings.paths.download_dir(), deps.downloader);
        let r = Arc::new(Self {
            msgq: server::MsgQueue::new(settings.remote.queue_size as usize),
            ctrl_queue: CtrlQueue::new(i.ctrl_msg_queue_size),
            requests: request::Requests::new(i.request_pool as usize),
            keys: RwLock::new(keys),
            counters: Mutex::new(counters),
            sender_counter: Mutex::new(sender),
            conns: Mutex::new(HashMap::new()),
            next_sock: server::new_sock_counter(),
            udp: OnceLock::new(),
            global_counter: AtomicU64::new(0),
            netcounter: Mutex::new(HashMap::new()),
            state: state::State::new(),
            mq: mq::Mq { sink: deps.sink },
            wdb: deps.wdb,
            router: deps.router,
            cluster: deps.cluster,
            krequest_tx: ktx,
            krequest_rx: Mutex::new(Some(krx)),
            key_request_available: AtomicBool::new(false),
            agent_versions: Mutex::new(HashMap::new()),
            current_ts: AtomicI64::new(now()),
            files: Mutex::new(Files::default()),
            pending: Mutex::new(HashMap::new()),
            pending_queue: Mutex::new(VecDeque::new()),
            pending_notify: tokio::sync::Notify::new(),
            shared_download: sd,
            self_ref: OnceLock::new(),
            settings,
        });
        let _ = r.self_ref.set(Arc::downgrade(&r));
        Ok(r)
    }

    /// `HandleSecure` + `HandleSyslog*`: bind every configured connection and
    /// start all threads. Returns when the listeners are up.
    pub async fn start(self: &Arc<Self>) -> std::io::Result<()> {
        // manager_init: initial groups scan
        self.c_files(true).await;
        self.shared_download.create_groups(&self.settings.paths.shared_dir());

        let i = &self.settings.internal;
        tokio::spawn(self.clone().timestamp_loop());
        tokio::spawn(self.clone().update_shared_files_loop());
        tokio::spawn(self.clone().ar_forward_loop());
        tokio::spawn(self.clone().cfga_forward_loop());
        tokio::spawn(self.clone().remcom_loop());
        tokio::spawn(self.clone().state_loop());
        if let Some(rx) = self.krequest_rx.lock().unwrap().take() {
            tokio::spawn(self.clone().key_request_loop(rx));
        }
        for _ in 0..i.sender_pool {
            tokio::spawn(self.clone().sender_worker());
        }
        if !wdb::reset_agents_connection(self.wdb.as_ref(), "synced").await {
            tracing::warn!("Unable to reset the agents' connection status. Possible incorrect statuses until the agents get connected to the manager.");
        }
        tokio::spawn(self.clone().save_control_worker());
        for _ in 0..i.worker_pool {
            tokio::spawn(self.clone().handler_worker());
        }
        tokio::spawn(self.clone().key_update_loop());

        for c in &self.settings.remote.connections {
            let ip = c.lip.clone().unwrap_or_else(|| if c.ipv6 { "::".into() } else { "0.0.0.0".into() });
            let addr = format!("{}:{}", if ip.contains(':') { format!("[{ip}]") } else { ip.clone() }, c.port);
            if c.conn == SECURE_CONN {
                let mut protos = Vec::new();
                if c.proto & REMOTED_NET_PROTOCOL_TCP != 0 {
                    let l = tokio::net::TcpListener::bind(&addr).await?;
                    tokio::spawn(self.clone().tcp_listener(l));
                    protos.push("TCP");
                }
                if c.proto & REMOTED_NET_PROTOCOL_UDP != 0 {
                    let u = Arc::new(tokio::net::UdpSocket::bind(&addr).await?);
                    let _ = self.udp.set(u.clone());
                    tokio::spawn(self.clone().udp_loop(u));
                    protos.push("UDP");
                }
                tracing::info!("Started (pid: {}). Listening on port {}/{} (secure).", std::process::id(), c.port, protos.join(","));
            } else if c.conn == SYSLOG_CONN {
                if self.settings.remote.allowips.is_empty() {
                    tracing::info!("(1218): Remote syslog allowed IPs not set: ignoring syslog connection.");
                    continue;
                }
                for ip in &self.settings.remote.allowips {
                    tracing::info!("Remote syslog allowed from: '{}'", ip.ip);
                }
                if c.proto & REMOTED_NET_PROTOCOL_TCP != 0 && c.proto & REMOTED_NET_PROTOCOL_UDP == 0 {
                    let l = tokio::net::TcpListener::bind(&addr).await?;
                    tokio::spawn(self.clone().syslog_tcp(l, c.port));
                } else {
                    let u = tokio::net::UdpSocket::bind(&addr).await?;
                    tokio::spawn(self.clone().syslog_udp(u, c.port));
                }
            }
        }
        tracing::info!("(1410): Reading authentication keys file.");
        Ok(())
    }
}
