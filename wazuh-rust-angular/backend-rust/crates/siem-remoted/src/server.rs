//! The secure (agent) server: port of `src/remoted/secure.c`,
//! `netbuffer.c`, `queue.c`, `netcounter.c` and `sendmsg.c`.

use crate::keystore::{KeyEntry, KeySnapshot, KeyStore, NetProtocol, UDP_SOCK};
use crate::state::Counter;
use crate::Remoted;
use siem_crypto::msgs::{create_sec_msg, read_sec_msg, CreateOptions, KeyState as KS, ReadOptions};
use siem_ipc::framing::FrameDecoder;
use siem_ipc::mq::queues::SECURE_MQ;
use siem_ipc::OS_MAXSTR;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Notify};

pub const CONTROL_HEADER: &str = "#!-";
pub const HC_STARTUP: &str = "agent startup ";
pub const HC_SHUTDOWN: &str = "agent shutdown ";
pub const HC_ACK: &str = "agent ack ";
pub const HC_REQUEST: &str = "req ";
pub const HC_ERROR: &str = "err ";
pub const HC_INVALID_VERSION: &str = "Incompatible version";
pub const HC_INVALID_VERSION_RESPONSE: &str = "Agent version must be lower or equal to manager version";
pub const HC_RETRIEVE_VERSION: &str = "Couldn't retrieve version";
pub const FILE_UPDATE_HEADER: &str = "up file ";
pub const FILE_CLOSE_HEADER: &str = "close file ";
pub const EXECD_HEADER: &str = "execd ";

/// A message received from an agent (`message_t`).
#[derive(Debug)]
pub struct Message {
    pub buffer: Vec<u8>,
    pub addr: SocketAddr,
    /// TCP connection id or [`UDP_SOCK`].
    pub sock: i64,
    pub counter: u64,
}

/// Write side of a TCP connection (`sockbuffer_t` + its `bqueue`).
pub struct Conn {
    pub peer: SocketAddr,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    queued: Arc<AtomicUsize>,
    close: Arc<Notify>,
}

/// The receive queue (`rem_msgpush` / `rem_msgpop`).
pub struct MsgQueue {
    tx: mpsc::Sender<Message>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Message>>,
    pub size: usize,
    used: AtomicUsize,
    reported: std::sync::atomic::AtomicBool,
}

impl MsgQueue {
    pub fn new(size: usize) -> Self {
        let (tx, rx) = mpsc::channel(size.max(1));
        Self { tx, rx: tokio::sync::Mutex::new(rx), size, used: AtomicUsize::new(0), reported: Default::default() }
    }

    pub fn usage(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }
}

impl Remoted {
    // ---------------------------------------------------------------- queue

    /// `rem_msgpush`
    pub(crate) fn msg_push(&self, buffer: Vec<u8>, addr: SocketAddr, sock: i64) {
        let counter = self.global_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let m = Message { buffer, addr, sock, counter };
        match self.msgq.tx.try_send(m) {
            Ok(()) => {
                self.msgq.used.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                tracing::debug!("Discarding event from host.");
                self.state.inc(Counter::RecvDiscarded, None);
                if !self.msgq.reported.swap(true, Ordering::Relaxed) {
                    tracing::warn!("Message queue is full ({}). Events may be lost.", self.msgq.size);
                }
            }
        }
    }

    /// `rem_handler_main`: one worker of the pool.
    pub(crate) async fn handler_worker(self: Arc<Self>) {
        loop {
            let msg = {
                let mut rx = self.msgq.rx.lock().await;
                rx.recv().await
            };
            let Some(msg) = msg else { return };
            self.msgq.used.fetch_sub(1, Ordering::Relaxed);
            self.handle_secure_message(msg).await;
        }
    }

    // ------------------------------------------------------- net counters

    /// `rem_setCounter`
    fn set_counter(&self, sock: i64, c: u64) {
        self.netcounter.lock().unwrap().insert(sock, c);
    }

    /// `rem_getCounter`
    fn get_counter(&self, sock: i64) -> u64 {
        *self.netcounter.lock().unwrap().get(&sock).unwrap_or(&0)
    }

    // --------------------------------------------------------------- TCP

    /// Accept loop for the secure TCP port.
    pub(crate) async fn tcp_listener(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    let sock = self.next_sock.fetch_add(1, Ordering::SeqCst);
                    self.state.tcp(1);
                    tracing::debug!("New TCP connection [{sock}]");
                    let (rd, mut wr) = stream.into_split();
                    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    let queued = Arc::new(AtomicUsize::new(0));
                    let close = Arc::new(Notify::new());
                    self.conns.lock().unwrap().insert(sock, Conn { peer, tx, queued: queued.clone(), close: close.clone() });

                    // Writer (`nb_send`): drains the per-socket queue.
                    let me = self.clone();
                    let q2 = queued.clone();
                    tokio::spawn(async move {
                        while let Some(data) = rx.recv().await {
                            let n = data.len();
                            if let Err(e) = wr.write_all(&data).await {
                                tracing::debug!("TCP peer [{sock}]: {e}");
                                me.close_sock(sock);
                                break;
                            }
                            q2.fetch_sub(n, Ordering::Relaxed);
                            me.state.add_send(n as u64);
                        }
                    });

                    // Reader (`nb_recv`)
                    let me = self.clone();
                    tokio::spawn(async move { me.tcp_reader(sock, peer, rd, close).await });
                }
                Err(e) => tracing::error!("(1242): Couldn't accept TCP connections: {e}"),
            }
        }
    }

    async fn tcp_reader(self: Arc<Self>, sock: i64, peer: SocketAddr, mut rd: tokio::net::tcp::OwnedReadHalf, close: Arc<Notify>) {
        let chunk = self.settings.internal.receive_chunk as usize;
        let recv_timeout = Duration::from_secs(self.settings.internal.recv_timeout.max(1) as u64);
        let mut dec = FrameDecoder::new();
        let mut buf = vec![0u8; chunk];
        loop {
            let n = tokio::select! {
                _ = close.notified() => break,
                r = rd.read(&mut buf) => match r {
                    Ok(0) => { tracing::debug!("handle incoming close socket [{sock}]."); break; }
                    Ok(n) => n,
                    Err(e) => { tracing::debug!("TCP peer [{sock}]: {e}"); break; }
                },
            };
            let _ = recv_timeout;
            dec.extend(&buf[..n]);
            self.state.add_recv(n as u64);
            loop {
                match dec.next_frame(OS_MAXSTR) {
                    Ok(Some(frame)) => self.msg_push(frame, peer, sock),
                    Ok(None) => break,
                    Err(_) => {
                        tracing::warn!("Too big message size from socket [{sock}].");
                        self.close_sock(sock);
                        return;
                    }
                }
            }
        }
        self.close_sock(sock);
    }

    /// `_close_sock`
    pub(crate) fn close_sock(&self, sock: i64) {
        self.set_counter(sock, self.global_counter.load(Ordering::SeqCst));
        self.keys.read().unwrap().delete_socket(sock);
        if let Some(c) = self.conns.lock().unwrap().remove(&sock) {
            c.close.notify_one();
            self.state.tcp(-1);
        }
        tracing::debug!("TCP peer disconnected [{sock}]");
    }

    /// `nb_queue`: frame and enqueue; waits `send_timeout_to_retry` once when
    /// the per-socket buffer is full, then drops the packet.
    async fn nb_queue(&self, sock: i64, crypt: &[u8], agent_id: &str) -> bool {
        let frame = siem_ipc::framing::encode(crypt);
        let limit = self.settings.internal.send_buffer_size as usize;
        for attempt in 0..2 {
            let ok = {
                let conns = self.conns.lock().unwrap();
                match conns.get(&sock) {
                    None => return self.drop_packet(agent_id),
                    Some(c) => {
                        if c.queued.load(Ordering::Relaxed) + frame.len() <= limit {
                            c.queued.fetch_add(frame.len(), Ordering::Relaxed);
                            c.tx.send(frame.clone()).is_ok()
                        } else {
                            false
                        }
                    }
                }
            };
            if ok {
                return true;
            }
            if attempt == 0 {
                tracing::debug!("Not enough buffer space. Retrying...");
                tokio::time::sleep(Duration::from_secs(self.settings.internal.send_timeout_to_retry as u64)).await;
            }
        }
        self.drop_packet(agent_id)
    }

    fn drop_packet(&self, agent_id: &str) -> bool {
        self.state.inc(Counter::SendDiscarded, Some(agent_id));
        tracing::warn!("Package dropped. Could not append data into buffer.");
        false
    }

    // --------------------------------------------------------------- UDP

    /// `handle_incoming_data_from_udp_socket`
    pub(crate) async fn udp_loop(self: Arc<Self>, sock: Arc<UdpSocket>) {
        let mut buf = vec![0u8; OS_MAXSTR];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, peer)) if n > 0 => {
                    self.msg_push(buf[..n].to_vec(), peer, UDP_SOCK);
                    self.state.add_recv(n as u64);
                }
                Ok(_) => {}
                Err(e) => tracing::debug!("UDP recv error: {e}"),
            }
        }
    }

    // ------------------------------------------------------- send_msg

    /// `send_msg` / `send_msg_with_key_control`: encrypt for the agent and send
    /// through its current transport. Returns false on any failure.
    pub async fn send_msg(&self, agent_id: &str, msg: &[u8]) -> bool {
        let entry = {
            let ks = self.keys.read().unwrap();
            ks.allowed_id(agent_id)
        };
        let Some(entry) = entry else {
            tracing::error!("(1320): Agent '{agent_id}' not found.");
            return false;
        };
        let now = crate::now();
        let (crypt, proto, sock, peer) = {
            let st = entry.state.lock().unwrap();
            if st.rcvd < now - self.settings.remote.agents_disconnection_time {
                tracing::debug!("(1245): Sending message to disconnected agent '{}'.", entry.id);
                return false;
            }
            let mut ctr = self.sender_counter.lock().unwrap();
            let r = create_sec_msg(&st.key, &mut ctr, msg, CreateOptions { dynamic_prefix: false, random: None });
            let _ = self.counters.lock().unwrap().store_sender(&ctr);
            match r {
                Ok(c) => (c, st.net_protocol, st.sock, st.peer),
                Err(_) => {
                    tracing::error!("(1403): Incorrectly formatted message from agent.");
                    return false;
                }
            }
        };
        if proto == NetProtocol::Udp {
            let (Some(udp), Some(peer)) = (self.udp.get(), peer) else { return false };
            match udp.send_to(&crypt, peer).await {
                Ok(n) if n == crypt.len() => {
                    self.state.add_send(n as u64);
                    true
                }
                _ => {
                    tracing::warn!("(1218): Unable to send message to '{agent_id}': A message could not be delivered completely.");
                    false
                }
            }
        } else if sock >= 0 {
            self.nb_queue(sock, &crypt, &entry.id).await
        } else {
            tracing::debug!("Send operation cancelled due to closed socket.");
            false
        }
    }

    // ----------------------------------------------- HandleSecureMessage

    /// `HandleSecureMessage`
    pub(crate) async fn handle_secure_message(self: &Arc<Self>, message: Message) {
        let protocol = if message.sock == UDP_SOCK { NetProtocol::Udp } else { NetProtocol::Tcp };
        let srcip = match message.addr {
            SocketAddr::V4(a) => a.ip().to_string(),
            SocketAddr::V6(a) => a.ip().to_string(),
        };
        let buffer = &message.buffer;
        let mut sock_idle: i64 = -1;
        let ip_found;
        let entry: Arc<KeyEntry>;
        let body: &[u8];
        let now = self.current_ts.load(Ordering::Relaxed);
        let overtake = self.settings.remote.connection_overtake_time as i64;

        if buffer.first() == Some(&b'!') {
            // "!<id>!" dynamic IP agents
            let digits = buffer[1..].iter().take_while(|c| c.is_ascii_digit()).count();
            if buffer.get(1 + digits) != Some(&b'!') {
                tracing::error!("(1403): Incorrectly formatted message from agent '(unknown)' at '{srcip}'.");
                if message.sock >= 0 {
                    self.close_sock(message.sock);
                }
                self.state.inc(Counter::RecvUnknown, None);
                return;
            }
            let id = String::from_utf8_lossy(&buffer[1..1 + digits]).into_owned();
            body = &buffer[2 + digits..];
            let found = self.keys.read().unwrap().allowed_dynamic_id(&id, &srcip);
            match found {
                None => {
                    let name = self.keys.read().unwrap().allowed_id(&id).map(|e| e.name.clone()).unwrap_or_else(|| "unknown".into());
                    tracing::warn!("(1408): Invalid ID {id} for the source ip: '{srcip}' (name '{name}').");
                    self.push_request(&id, "id");
                    if message.sock >= 0 {
                        self.close_sock(message.sock);
                    }
                    self.state.inc(Counter::RecvUnknown, None);
                    return;
                }
                Some(e) => {
                    if !self.check_overtake(&e, message.sock, now, overtake, &mut sock_idle) {
                        return;
                    }
                    entry = e;
                }
            }
            ip_found = false;
        } else if buffer.starts_with(b"#ping") {
            let pong = b"#pong";
            let ok = if protocol == NetProtocol::Udp {
                match self.udp.get() {
                    Some(u) => u.send_to(pong, message.addr).await.map(|n| n == pong.len()).unwrap_or(false),
                    None => false,
                }
            } else {
                // OS_SendSecureTCP straight on the socket
                let conns = self.conns.lock().unwrap();
                conns.get(&message.sock).map(|c| c.tx.send(siem_ipc::framing::encode(pong)).is_ok()).unwrap_or(false)
            };
            if !ok {
                tracing::warn!("Ping operation could not be delivered completely (-1)");
            }
            self.state.inc(Counter::RecvPing, None);
            return;
        } else {
            let found = self.keys.read().unwrap().allowed_ip(&srcip);
            match found {
                None => {
                    tracing::warn!("(1213): Message from '{srcip}' not allowed. Cannot find the ID of the agent. Source agent ID is unknown.");
                    self.push_request(&srcip, "ip");
                    if message.sock >= 0 {
                        self.close_sock(message.sock);
                    }
                    self.state.inc(Counter::RecvUnknown, None);
                    return;
                }
                Some(e) => {
                    if !self.check_overtake(&e, message.sock, now, overtake, &mut sock_idle) {
                        return;
                    }
                    entry = e;
                }
            }
            ip_found = true;
            body = &buffer[..];
        }

        if body.is_empty() {
            tracing::warn!("Received message is empty");
            if message.sock >= 0 {
                self.close_sock(message.sock);
            }
            if sock_idle >= 0 {
                self.close_sock(sock_idle);
            }
            self.state.inc(Counter::RecvUnknown, None);
            return;
        }

        // ReadSecMSG
        let verify = self.settings.internal.verify_msg_id == 1;
        let result = {
            let mut st = entry.state.lock().unwrap();
            read_sec_msg(&mut st.key, body, ReadOptions { verify_counter: verify })
        };
        let payload = match result {
            Ok(r) => {
                let st = entry.state.lock().unwrap();
                let _ = self.counters.lock().unwrap().on_received(&st.key);
                r.payload
            }
            Err(e) => {
                match e.key_state() {
                    Some(KS::EncKey) => {
                        tracing::warn!("(1404): Authentication error. Wrong key or corrupt payload. Message received from agent '{}' at '{srcip}'.", entry.id);
                        if ip_found {
                            self.push_request(&srcip, "ip");
                        } else {
                            self.push_request(&entry.id, "id");
                        }
                    }
                    Some(KS::Corrupt) => tracing::error!("(1403): Incorrectly formatted message from agent '{}' at '{srcip}'.", entry.id),
                    Some(KS::Rids) => tracing::error!("(1407): Duplicated counter for '{}'.", entry.name),
                    _ => {}
                }
                if message.sock >= 0 {
                    tracing::warn!("Decrypt the message fail, socket {}", message.sock);
                    self.close_sock(message.sock);
                }
                if sock_idle >= 0 {
                    self.close_sock(sock_idle);
                }
                self.state.inc(Counter::RecvUnknown, None);
                return;
            }
        };

        if payload.len() > OS_MAXSTR {
            tracing::warn!("Message length ({}) exceeds maximum allowed size ({OS_MAXSTR}) from agent '{}'", payload.len(), entry.id);
            if message.sock >= 0 {
                self.close_sock(message.sock);
            }
            if sock_idle >= 0 {
                self.close_sock(sock_idle);
            }
            self.state.inc(Counter::RecvUnknown, None);
            return;
        }

        entry.state.lock().unwrap().rcvd = now;

        // The C code works on a NUL-terminated string from here on.
        let cstr_len = payload.iter().position(|&b| b == 0).unwrap_or(payload.len());
        let text = &payload[..cstr_len];

        if text.starts_with(CONTROL_HEADER.as_bytes()) {
            let tmp = &text[3..];
            let is_shutdown_msg = tmp.starts_with(HC_SHUTDOWN.as_bytes());
            if message.sock == UDP_SOCK || message.counter > self.get_counter(message.sock) || is_shutdown_msg {
                let key: KeySnapshot;
                {
                    let mut st = entry.state.lock().unwrap();
                    st.net_protocol = protocol;
                    st.peer = Some(message.addr);
                    if protocol == NetProtocol::Tcp {
                        if sock_idle >= 0 || message.counter > self.get_counter(message.sock) {
                            st.sock = message.sock;
                        }
                    } else {
                        st.sock = UDP_SOCK;
                    }
                }
                key = entry.snapshot();
                if protocol == NetProtocol::Tcp && !is_shutdown_msg {
                    let added = self.keys.read().unwrap().add_socket(entry.keyid, message.sock);
                    tracing::trace!("TCP socket {} {} keystore.", message.sock, if added { "added to" } else { "already in" });
                }

                let tmp_str = String::from_utf8_lossy(tmp).into_owned();
                let v = self.validate_control_msg(&key, &tmp_str, &payload[3..]).await;
                if v.is_startup {
                    entry.state.lock().unwrap().post_startup = true;
                }
                let post_startup = entry.state.lock().unwrap().post_startup;
                if sock_idle >= 0 {
                    self.close_sock(sock_idle);
                }
                self.state.inc(Counter::RecvCtrl, Some(&key.id));
                match v.result {
                    1 => {
                        let data = crate::manager::CtrlMsg {
                            key,
                            message: v.cleaned.unwrap_or(tmp_str),
                            is_startup: v.is_startup,
                            is_shutdown: v.is_shutdown,
                            post_startup,
                        };
                        match self.ctrl_queue.upsert(data) {
                            Some(false) => self.state.inc(Counter::CtrlQueueInserted, None),
                            Some(true) => self.state.inc(Counter::CtrlQueueReplaced, None),
                            None => {}
                        }
                    }
                    0 => tracing::debug!("Control message processed directly, not queued."),
                    _ => tracing::warn!("Error validating control message from agent ID '{}'.", key.id),
                }
            } else {
                self.state.inc(Counter::RecvDequeued, None);
            }
            return;
        }

        // Event: srcmsg = "[id] (name) ip"
        let (id, name, mut agent_ip) = (entry.id.clone(), entry.name.clone(), entry.ip_str.clone());
        let mut srcmsg = format!("[{}] ({}) {}", id, name, entry.ip_str);
        crate::truncate_bytes(&mut srcmsg, siem_ipc_flsize());
        if agent_ip == "any" && !srcip.is_empty() {
            agent_ip = srcip.clone();
        }
        if sock_idle >= 0 {
            self.close_sock(sock_idle);
        }
        if self.mq.send_msg(text, &srcmsg, SECURE_MQ).await {
            self.state.inc(Counter::RecvEvt, Some(&id));
        }
        if self.settings.internal.router_forwarding_disabled == 1 {
            tracing::trace!("Router forwarding is disabled, not forwarding message from agent '{id}'.");
            return;
        }
        let version = self.agent_versions.lock().unwrap().get(&id).cloned();
        crate::router::router_message_forward(self.router.as_ref(), text, &id, &agent_ip, &name, version.as_deref());
    }

    /// Connection overtake check shared by both lookup paths. Returns false
    /// when the message must be dropped ("Agent key already in use").
    fn check_overtake(&self, e: &Arc<KeyEntry>, sock: i64, now: i64, overtake: i64, sock_idle: &mut i64) -> bool {
        let mut st = e.state.lock().unwrap();
        if st.sock >= 0 && st.sock != sock {
            if overtake > 0 && now - st.rcvd > overtake {
                *sock_idle = st.sock;
                tracing::debug!("Idle socket [{}] from agent ID '{}' will be closed.", st.sock, e.id);
                st.rcvd = now;
            } else {
                tracing::warn!("Agent key already in use: agent ID '{}'", e.id);
                drop(st);
                if sock >= 0 {
                    self.close_sock(sock);
                }
                self.state.inc(Counter::RecvUnknown, None);
                return false;
            }
        }
        true
    }

    /// `push_request`: queue a key request for authd (`"<type>:<value>"`).
    pub(crate) fn push_request(&self, request: &str, kind: &str) {
        if !self.key_request_available.load(Ordering::Relaxed) {
            return;
        }
        let _ = self.krequest_tx.try_send(format!("{kind}:{request}"));
    }
}

/// `snprintf(srcmsg, OS_FLSIZE, ...)` keeps at most OS_FLSIZE - 1 bytes.
fn siem_ipc_flsize() -> usize {
    256 - 1
}

/// Map of live TCP connections.
pub type ConnTable = Mutex<HashMap<i64, Conn>>;

/// Monotonic socket ids handed to TCP connections.
pub fn new_sock_counter() -> AtomicI64 {
    AtomicI64::new(0)
}

/// Read the full keystore under the key lock (`key_lock_read`).
pub fn keys_snapshot(ks: &std::sync::RwLock<KeyStore>) -> Vec<Arc<KeyEntry>> {
    ks.read().unwrap().entries.clone()
}
