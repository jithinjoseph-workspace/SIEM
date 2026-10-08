//! Port of `src/remoted/manager.c`: agent control messages (startup,
//! shutdown, keepalive, requests), group assignment, `merged.mg` generation
//! for groups and multigroups, and shared-file distribution.

use crate::config::{compare_wazuh_versions, OSSEC_NAME, OSSEC_VERSION};
use crate::keystore::{KeySnapshot, NetProtocol};
use crate::server::*;
use crate::state::Counter;
use crate::wdb::{self, AgentStatusCode, AGENT_CS_ACTIVE, AGENT_CS_DISCONNECTED, AGENT_CS_PENDING, WDB_GROUP_MODE_EMPTY_ONLY};
use crate::Remoted;
use sha2::{Digest, Sha256};
use siem_fileop as fo;
use siem_ipc::mq::queues::SECURE_MQ;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

pub const SHAREDCFG_FILENAME: &str = "merged.mg";
pub const DEFAULTAR_FILE: &str = "ar.conf";
pub const MULTIGROUP_SEPARATOR: char = ',';
pub const MAX_GROUPS_PER_MULTIGROUP: usize = 128;
/// `MAX_SHARED_PATH`
pub const MAX_SHARED_PATH: usize = 200;

/// `w_ctrl_msg_data_t`
#[derive(Debug, Clone)]
pub struct CtrlMsg {
    pub key: KeySnapshot,
    pub message: String,
    pub is_startup: bool,
    pub is_shutdown: bool,
    pub post_startup: bool,
}

/// `w_indexed_queue_t` keyed by agent id: a newer control message from the
/// same agent replaces the queued one.
pub struct CtrlQueue {
    inner: Mutex<(VecDeque<String>, HashMap<String, CtrlMsg>)>,
    cap: usize,
    notify: Notify,
}

impl CtrlQueue {
    pub fn new(cap: usize) -> Self {
        Self { inner: Mutex::new((VecDeque::new(), HashMap::new())), cap, notify: Notify::new() }
    }

    /// `indexed_queue_upsert_ex`: `Some(false)` inserted, `Some(true)` replaced,
    /// `None` when full.
    pub fn upsert(&self, m: CtrlMsg) -> Option<bool> {
        let mut g = self.inner.lock().unwrap();
        let id = m.key.id.clone();
        if g.1.contains_key(&id) {
            g.1.insert(id, m);
            return Some(true);
        }
        if g.0.len() >= self.cap {
            return None;
        }
        g.0.push_back(id.clone());
        g.1.insert(id, m);
        drop(g);
        self.notify.notify_one();
        Some(false)
    }

    pub async fn pop(&self) -> CtrlMsg {
        loop {
            {
                let mut g = self.inner.lock().unwrap();
                while let Some(id) = g.0.pop_front() {
                    if let Some(m) = g.1.remove(&id) {
                        return m;
                    }
                }
            }
            self.notify.notified().await;
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// `pending_data_t`
#[derive(Debug, Default, Clone)]
pub struct PendingData {
    pub message: Option<String>,
    pub group: Option<String>,
    pub merged_sum: String,
    pub last_reported_merged_sum: String,
    pub changed: bool,
}

/// `group_t`
#[derive(Debug, Clone, Default)]
pub struct Group {
    pub name: String,
    pub f_time: Option<HashMap<String, i64>>,
    pub merged_sum: String,
    pub has_changed: bool,
    pub exists: bool,
}

/// State protected by `files_mutex` in C.
#[derive(Debug, Default)]
pub struct Files {
    pub groups: HashMap<String, Group>,
    pub multi_groups: HashMap<String, Group>,
    /// multigroup csv -> directory hash (`m_hash`)
    pub m_hash: HashMap<String, String>,
    pub invalid_files: HashMap<String, i64>,
    pub reported_path_size_exceeded: bool,
}

/// Result of `validate_control_msg`.
pub struct Validation {
    /// 1 queue it, 0 handled, -1 error.
    pub result: i32,
    pub cleaned: Option<String>,
    pub is_startup: bool,
    pub is_shutdown: bool,
}

/// `w_utf8_filter(string, true)`
pub fn utf8_filter(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() && b[i] != 0 {
        let s = &b[i..];
        let len = if s[0] & 0x80 == 0 {
            1
        } else if s.len() >= 2 && (s[0] & 0xE0) == 0xC0 && s[0] >= 0xC2 && (s[1] & 0xC0) == 0x80 {
            2
        } else if s.len() >= 3
            && (s[0] & 0xF0) == 0xE0
            && (s[1] & 0xC0) == 0x80
            && (s[2] & 0xC0) == 0x80
            && (s[0] != 0xE0 || s[1] >= 0xA0)
            && (s[0] != 0xED || s[1] < 0xA0)
            && (s[0] != 0xEF || s[1] <= 0xBF)
        {
            3
        } else if s.len() >= 4
            && (s[0] & 0xF8) == 0xF0
            && s[0] <= 0xF4
            && (s[1] & 0xC0) == 0x80
            && (s[2] & 0xC0) == 0x80
            && (s[3] & 0xC0) == 0x80
            && (s[0] != 0xF0 || s[1] >= 0x90)
            && (s[0] != 0xF4 || s[1] <= 0x8F)
        {
            4
        } else {
            0
        };
        if len == 0 {
            out.push('\u{FFFD}');
            i += 1;
        } else {
            out.push_str(std::str::from_utf8(&s[..len]).unwrap_or("\u{FFFD}"));
            i += len;
        }
    }
    out
}

/// Keep the message up to and including its last `\n` (drops the trailing
/// random string of keepalives). `None` when there is no newline.
fn cut_after_last_newline(s: &str) -> Option<String> {
    let first = s.find('\n')?;
    let last = s.rfind('\n').unwrap_or(first);
    Some(s[..=last].to_string())
}

/// `OS_SHA256_String(group)` truncated to 8 hex chars (multigroup dir name).
pub fn multigroup_hash(group: &str) -> String {
    let d = Sha256::digest(group.as_bytes());
    d.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

fn hostname() -> Option<String> {
    #[cfg(unix)]
    {
        std::fs::read_to_string("/proc/sys/kernel/hostname").ok().map(|s| s.trim().to_string()).or_else(|| std::env::var("HOSTNAME").ok())
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").ok()
    }
}

/// `wm_strcat(&dst, src, sep)`
fn strcat(dst: &mut Option<String>, src: &str, sep: Option<char>) {
    match dst {
        Some(d) => {
            if let Some(c) = sep {
                d.push(c);
            }
            d.push_str(src);
        }
        None => *dst = Some(src.to_string()),
    }
}

impl Remoted {
    /// `validate_control_msg`. `r_msg` is the text after `#!-`; `raw` the bytes
    /// (used for `req` payloads, which may be binary).
    pub(crate) async fn validate_control_msg(&self, key: &KeySnapshot, r_msg: &str, raw: &[u8]) -> Validation {
        let mut v = Validation { result: 1, cleaned: None, is_startup: false, is_shutdown: false };

        if r_msg.starts_with(HC_REQUEST) {
            let counter_and_rest = &r_msg[HC_REQUEST.len()..];
            let Some(sp) = counter_and_rest.find(' ') else {
                tracing::error!("Request control format error.");
                v.result = -1;
                return v;
            };
            let counter = &counter_and_rest[..sp];
            let off = HC_REQUEST.len() + sp + 1;
            let payload = raw.get(off..).unwrap_or(&[]);
            self.req_save(counter, payload);
            self.state.inc(Counter::CtrlRequest, Some(&key.id));
            v.result = 0;
            return v;
        }

        let clean = utf8_filter(r_msg.as_bytes());
        if clean.starts_with(HC_STARTUP) || clean == HC_SHUTDOWN {
            let aux_ip = key.peer.map(|p| p.ip().to_string()).unwrap_or_default();
            if clean.starts_with(HC_STARTUP) {
                tracing::debug!("Agent {} sent HC_STARTUP from '{aux_ip}'", key.name);
                if let Some(p) = clean.find('{') {
                    if let Ok(info) = serde_json::from_str::<serde_json::Value>(&clean[p..]) {
                        match info.get("version").and_then(|x| x.as_str()) {
                            Some(ver) => {
                                self.agent_versions.lock().unwrap().insert(key.id.clone(), ver.to_string());
                                if !self.settings.remote.allow_higher_versions
                                    && compare_wazuh_versions(Some(OSSEC_VERSION), Some(ver), false) < 0
                                {
                                    v.is_startup = true;
                                    v.cleaned = Some(clean);
                                    self.state.inc(Counter::CtrlStartup, Some(&key.id));
                                    return v;
                                }
                            }
                            None => {
                                v.is_startup = true;
                                v.cleaned = Some(clean);
                                self.state.inc(Counter::CtrlStartup, Some(&key.id));
                                return v;
                            }
                        }
                    }
                }
                v.is_startup = true;
                self.state.inc(Counter::CtrlStartup, Some(&key.id));
            } else {
                tracing::debug!("Agent {} sent HC_SHUTDOWN from '{aux_ip}'", key.name);
                v.is_shutdown = true;
                self.state.inc(Counter::CtrlShutdown, Some(&key.id));
                self.agent_versions.lock().unwrap().remove(&key.id);
                let mut srcmsg = format!("[{}] ({}) {}", key.id, key.name, key.ip);
                crate::truncate_bytes(&mut srcmsg, 255);
                let mut msg = format!("1:wazuh-remoted:ossec: Agent stopped: '{}->{}'.", key.name, key.ip);
                crate::truncate_bytes(&mut msg, 1023);
                self.mq.send_msg(msg.as_bytes(), &srcmsg, SECURE_MQ).await;
            }
            v.cleaned = Some(clean);
        } else {
            match cut_after_last_newline(&clean) {
                Some(c) => v.cleaned = Some(c),
                None => {
                    tracing::warn!("Invalid message from agent: '{}' ({})", key.name, key.id);
                    v.result = -1;
                    return v;
                }
            }
            self.state.inc(Counter::CtrlKeepalive, Some(&key.id));
        }

        if !v.is_shutdown {
            let ack = format!("{CONTROL_HEADER}{HC_ACK}");
            if self.send_msg(&key.id, ack.as_bytes()).await {
                self.state.inc(Counter::SendAck, Some(&key.id));
            }
        }
        v
    }

    /// `save_control_thread`
    pub(crate) async fn save_control_worker(self: Arc<Self>) {
        loop {
            let m = self.ctrl_queue.pop().await;
            self.state.inc(Counter::CtrlQueueProcessed, None);
            let mut post_startup = m.post_startup;
            self.save_controlmsg(&m.key, &m.message, &mut post_startup, m.is_startup, m.is_shutdown).await;
            if post_startup != m.post_startup {
                let e = self.keys.read().unwrap().allowed_id(&m.key.id);
                if let Some(e) = e {
                    e.state.lock().unwrap().post_startup = post_startup;
                }
            }
        }
    }

    fn sync_status(&self, worker: &str, master: &'static str) -> String {
        if self.settings.worker_node { worker.to_string() } else { master.to_string() }
    }

    /// `save_controlmsg`
    pub(crate) async fn save_controlmsg(&self, key: &KeySnapshot, r_msg: &str, post_startup: &mut bool, is_startup: bool, is_shutdown: bool) {
        let db = self.wdb.as_ref();
        let id: i64 = key.id.parse().unwrap_or(0);
        let mut msg: Option<String> = None;

        if is_startup {
            if r_msg.starts_with(HC_STARTUP) {
                if let Some(p) = r_msg.find('{') {
                    if let Ok(info) = serde_json::from_str::<serde_json::Value>(&r_msg[p..]) {
                        match info.get("version").and_then(|x| x.as_str()) {
                            Some(ver) => {
                                if !self.settings.remote.allow_higher_versions
                                    && compare_wazuh_versions(Some(OSSEC_VERSION), Some(ver), false) < 0
                                {
                                    self.send_wrong_version_response(&key.id, HC_INVALID_VERSION, AgentStatusCode::InvalidVersion, Some(ver)).await;
                                    return;
                                }
                            }
                            None => {
                                tracing::warn!("Unable to get version from agent '{}' on startup message", key.id);
                                self.send_wrong_version_response(&key.id, HC_RETRIEVE_VERSION, AgentStatusCode::ErrVersionRecv, None).await;
                                return;
                            }
                        }
                    }
                }
            }
        } else if !is_shutdown {
            match cut_after_last_newline(r_msg) {
                Some(m) => msg = Some(m),
                None => {
                    tracing::warn!("Invalid message from agent: '{}' ({})", key.name, key.id);
                    return;
                }
            }
        }

        // Unchanged keepalive while a shared-file push is pending.
        let unchanged = {
            let pd = self.pending.lock().unwrap();
            match (pd.get(&key.id), &msg) {
                (Some(d), Some(m)) => d.changed && d.message.as_deref() == Some(m.as_str()),
                _ => false,
            }
        };
        if unchanged {
            let ss = if self.settings.worker_node { if *post_startup { "syncreq" } else { "syncreq_keepalive" } } else { "synced" };
            *post_startup = false;
            if !wdb::update_agent_keepalive(db, id, AGENT_CS_ACTIVE, ss).await {
                tracing::warn!("Unable to save last keepalive and set connection status as active for agent: {}", key.id);
            }
            return;
        }

        self.pending.lock().unwrap().entry(key.id.clone()).or_default();

        if is_startup {
            *post_startup = true;
            let ss = self.sync_status("syncreq_status", "synced");
            if !wdb::update_agent_keepalive(db, id, AGENT_CS_PENDING, &ss).await {
                tracing::warn!("Unable to save last keepalive and set connection status as pending for agent: {}", key.id);
            }
            return;
        }
        if is_shutdown {
            let ss = self.sync_status("syncreq_status", "synced");
            if !wdb::update_agent_connection_status(db, id, AGENT_CS_DISCONNECTED, &ss, AgentStatusCode::HcShutdownRecv).await {
                tracing::warn!("Unable to set connection status as disconnected for agent: {}", key.id);
            }
            return;
        }

        let msg = msg.unwrap_or_default();
        tracing::trace!("save_controlmsg(): inserting '{msg}'");
        let prev_reported = {
            let mut pd = self.pending.lock().unwrap();
            let d = pd.get_mut(&key.id).unwrap();
            d.message = Some(msg.clone());
            d.group = None;
            d.merged_sum.clear();
            d.last_reported_merged_sum.clone()
        };

        match self.lookfor_agent_group(&key.id, &msg).await {
            Some(group) => {
                let sum = {
                    let f = self.files.lock().unwrap();
                    let aux = f.groups.get(&group).or_else(|| f.multi_groups.get(&group));
                    if aux.is_none() {
                        tracing::debug!("No such group '{group}' for agent '{}'", key.id);
                    }
                    aux.map(|g| g.merged_sum.clone()).unwrap_or_default()
                };
                let mut pd = self.pending.lock().unwrap();
                let d = pd.get_mut(&key.id).unwrap();
                d.group = Some(group);
                if !sum.is_empty() {
                    d.merged_sum = sum;
                }
            }
            None => tracing::error!("Error getting group for agent '{}'", key.id),
        }

        let mut ad = crate::agent_info::parse_agent_update_msg(&msg, OSSEC_NAME);
        match hostname() {
            Some(h) => {
                strcat(&mut ad.labels, "#\"_manager_hostname\":", Some('\n'));
                strcat(&mut ad.labels, &h, None);
                ad.manager_host = Some(h);
            }
            None => tracing::warn!("Unable to get hostname"),
        }
        if let Some(ip) = ad.agent_ip.clone() {
            strcat(&mut ad.labels, "#\"_agent_ip\":", Some('\n'));
            strcat(&mut ad.labels, &ip, None);
        }
        let node = self.settings.node_name.clone();
        strcat(&mut ad.labels, "#\"_node_name\":", Some('\n'));
        strcat(&mut ad.labels, &node, None);
        ad.node_name = Some(node);
        if let Some(v) = ad.version.clone() {
            strcat(&mut ad.labels, "#\"_wazuh_version\":", Some('\n'));
            strcat(&mut ad.labels, &v, None);
        }

        let agent_sum = ad.merged_sum.clone().unwrap_or_default();
        let merged_changed = !agent_sum.is_empty() && !prev_reported.is_empty() && prev_reported != agent_sum;
        ad.id = id;
        ad.connection_status = Some(AGENT_CS_ACTIVE.into());
        ad.sync_status = Some(if self.settings.worker_node {
            if *post_startup || merged_changed { "syncreq".into() } else { "syncreq_keepalive".into() }
        } else {
            "synced".into()
        });
        *post_startup = false;

        let push_id = {
            let mut pd = self.pending.lock().unwrap();
            let d = pd.get_mut(&key.id).unwrap();
            if !agent_sum.is_empty() {
                d.last_reported_merged_sum = agent_sum.chars().take(32).collect();
            }
            if !d.merged_sum.is_empty() && (ad.merged_sum.is_none() || d.merged_sum != agent_sum) {
                ad.group_config_status = Some("not synced".into());
                if !d.changed {
                    d.changed = true;
                    true
                } else {
                    false
                }
            } else {
                ad.group_config_status = Some("synced".into());
                false
            }
        };
        if push_id {
            self.pending_queue.lock().unwrap().push_back(key.id.clone());
            self.pending_notify.notify_one();
        }

        if !wdb::update_agent_data(db, &ad).await {
            tracing::debug!("Unable to update information in global.db for agent: {}", key.id);
        }
    }

    /// `send_wrong_version_response`
    async fn send_wrong_version_response(&self, agent_id: &str, msg: &str, code: AgentStatusCode, version: Option<&str>) {
        let text = if msg.starts_with(HC_INVALID_VERSION) { HC_INVALID_VERSION_RESPONSE } else { msg };
        let err = serde_json::json!({ "message": text }).to_string();
        let mut out = format!("{CONTROL_HEADER}{HC_ERROR}{err}");
        crate::truncate_bytes(&mut out, 255);
        if self.send_msg(agent_id, out.as_bytes()).await {
            self.state.inc(Counter::SendAck, Some(agent_id));
        }
        tracing::debug!("Unable to connect agent: '{agent_id}': '{msg}'");
        let ss = self.sync_status("syncreq_status", "synced");
        if !wdb::update_agent_status_code(self.wdb.as_ref(), agent_id.parse().unwrap_or(0), code, version, &ss).await {
            tracing::warn!("Unable to set status code for agent: '{agent_id}'");
        }
    }

    /// `lookfor_agent_group`
    async fn lookfor_agent_group(&self, agent_id: &str, msg: &str) -> Option<String> {
        let id: i64 = agent_id.parse().unwrap_or(0);
        if let Some(g) = wdb::get_agent_group(self.wdb.as_ref(), id).await {
            tracing::trace!("Agent '{agent_id}' group is '{g}'");
            return Some(g);
        }
        let Some(nl) = msg.find('\n') else {
            tracing::error!("Invalid message from agent ID '{agent_id}' (strchr \\n)");
            return None;
        };
        let mut rest = &msg[nl + 1..];
        // Skip label lines
        while rest.starts_with('"') || rest.starts_with('!') || rest.starts_with('#') {
            match rest.find('\n') {
                Some(e) => rest = &rest[e + 1..],
                None => break,
            }
        }
        while !rest.is_empty() {
            let Some(e) = rest.find('\n') else {
                tracing::error!("Invalid message from agent ID '{agent_id}' (strchr \\n)");
                break;
            };
            let line = &rest[..e];
            rest = &rest[e + 1..];
            if line.starts_with('"') || line.starts_with('!') || line.starts_with('#') {
                continue;
            }
            let Some(sp) = line.find(' ') else {
                tracing::error!("Invalid message from agent ID '{agent_id}' (strchr ' ')");
                break;
            };
            let (md5, file) = (&line[..sp], &line[sp + 1..]);
            if file == SHAREDCFG_FILENAME {
                let group = if !self.settings.worker_node {
                    Some(self.assign_group_to_agent(agent_id, md5).await)
                } else {
                    self.cluster.assign_group(agent_id, md5).await
                };
                return match group {
                    Some(g) if !g.is_empty() => Some(g),
                    _ => {
                        tracing::error!("Agent '{agent_id}' invalid or empty group assigned.");
                        None
                    }
                };
            }
        }
        None
    }

    /// `assign_group_to_agent` (also the `assigngroup` remcom command).
    pub async fn assign_group_to_agent(&self, agent_id: &str, md5: &str) -> String {
        tracing::trace!("Agent '{agent_id}' with file '{SHAREDCFG_FILENAME}' MD5 '{md5}'");
        let group = {
            let f = self.files.lock().unwrap();
            let guessed = if self.settings.internal.guess_agent_group == 1 {
                f.groups.values().find(|g| g.merged_sum == md5).or_else(|| f.multi_groups.values().find(|g| g.merged_sum == md5)).map(|g| g.name.clone())
            } else {
                None
            };
            guessed.unwrap_or_else(|| "default".to_string())
        };
        let single = siem_config::cluster::is_single_node(std::path::Path::new(&self.settings.paths.ossec_conf())).0 == Some(true);
        wdb::set_agent_groups_csv(self.wdb.as_ref(), agent_id.parse().unwrap_or(0), &group, WDB_GROUP_MODE_EMPTY_ONLY, Some(if single { "synced" } else { "syncreq" })).await;
        tracing::trace!("Group assigned: '{group}'");
        group
    }

    /// `send_file_toagent`
    async fn send_file_toagent(&self, agent_id: &str, group: &str, name: &str, sum: &str, dir: &str) -> bool {
        let file = if group.contains(MULTIGROUP_SEPARATOR) {
            format!("{dir}/{}/{name}", multigroup_hash(group))
        } else {
            format!("{dir}/{group}/{name}")
        };
        let data = match std::fs::read(&file) {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!("(1103): Could not open file '{file}' due to [{e}].");
                return false;
            }
        };
        let header = format!("{CONTROL_HEADER}{FILE_UPDATE_HEADER}{sum} {name}\n");
        if !self.send_msg(agent_id, header.as_bytes()).await {
            return false;
        }
        self.state.inc(Counter::SendShared, Some(agent_id));
        let proto = self.keys.read().unwrap().net_protocol(agent_id);
        let Some(proto) = proto else {
            tracing::error!("(1320): Agent '{agent_id}' not found.");
            return false;
        };
        let mut i = 0;
        for chunk in data.chunks(900) {
            // send_msg(agent_id, buf, -1) uses strlen(buf)
            let n = chunk.iter().position(|&b| b == 0).unwrap_or(chunk.len());
            if !self.send_msg(agent_id, &chunk[..n]).await {
                return false;
            }
            self.state.inc(Counter::SendShared, Some(agent_id));
            if proto == NetProtocol::Udp {
                if i > 30 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    i = 0;
                }
                i += 1;
            }
        }
        let close = format!("{CONTROL_HEADER}{FILE_CLOSE_HEADER}");
        if !self.send_msg(agent_id, close.as_bytes()).await {
            return false;
        }
        self.state.inc(Counter::SendShared, Some(agent_id));
        true
    }

    /// `wait_for_msgs`: one shared-file sender of the pool.
    pub(crate) async fn sender_worker(self: Arc<Self>) {
        loop {
            let agent_id = loop {
                if let Some(id) = self.pending_queue.lock().unwrap().pop_front() {
                    break id;
                }
                self.pending_notify.notified().await;
            };
            let (group, sum) = {
                let pd = self.pending.lock().unwrap();
                match pd.get(&agent_id) {
                    Some(d) => (d.group.clone(), d.merged_sum.clone()),
                    None => {
                        tracing::error!("Couldn't get pending data from hash table for agent ID '{agent_id}'.");
                        (None, String::new())
                    }
                }
            };
            if let Some(g) = &group {
                if !sum.is_empty() {
                    tracing::debug!("Sending file '{g}/{SHAREDCFG_FILENAME}' to agent '{agent_id}'.");
                    let dir = if g.contains(MULTIGROUP_SEPARATOR) { self.settings.paths.multigroups_dir() } else { self.settings.paths.shared_dir() };
                    if !self.send_file_toagent(&agent_id, g, SHAREDCFG_FILENAME, &sum, &dir).await {
                        tracing::warn!("(1246): Unable to send file '{SHAREDCFG_FILENAME}' to agent ID '{agent_id}'.");
                    }
                }
            }
            if let Some(d) = self.pending.lock().unwrap().get_mut(&agent_id) {
                d.changed = false;
            }
        }
    }

    // ---------------------------------------------------- shared files

    /// `update_shared_files`
    pub(crate) async fn update_shared_files_loop(self: Arc<Self>) {
        let interval = self.settings.internal.shared_reload as i64;
        let mut stime = crate::now();
        loop {
            let now = crate::now();
            if now - stime >= interval {
                if self.shared_download.has_changed() {
                    self.shared_download.update_structs();
                    self.shared_download.create_groups(&self.settings.paths.shared_dir());
                }
                self.c_files(false).await;
                stime = now;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// `c_files`
    pub(crate) async fn c_files(&self, initial_scan: bool) {
        tracing::trace!("Updating shared files.");
        let distinct = wdb::get_distinct_agent_groups(self.wdb.as_ref()).await;
        let me = self.clone_for_files();
        let _ = tokio::task::spawn_blocking(move || {
            let mut f = me.files.lock().unwrap();
            me.process_groups(&mut f);
            me.process_multi_groups(&mut f, distinct);
            process_deleted_groups(&mut f);
            me.process_deleted_multi_groups(&mut f, initial_scan);
            f.reported_path_size_exceeded = true;
        })
        .await;
        tracing::trace!("End updating shared files.");
    }

    fn merge_shared(&self) -> bool {
        self.settings.internal.merge_shared == 1
    }

    fn process_groups(&self, f: &mut Files) {
        let shared = self.settings.paths.shared_dir();
        let Ok(rd) = std::fs::read_dir(&shared) else {
            tracing::debug!("Opening directory: '{shared}'");
            return;
        };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = format!("{shared}/{name}");
            if fo::wreaddir(&path).is_none() || !std::path::Path::new(&path).is_dir() {
                continue;
            }
            if !f.groups.contains_key(&name) {
                let mut g = Group { name: name.clone(), ..Default::default() };
                self.c_group(f, &name, &mut g.f_time, &mut g.merged_sum, &shared, self.merge_shared(), false);
                g.has_changed = true;
                g.exists = true;
                f.groups.insert(name, g);
            } else {
                let mut g = f.groups.remove(&name).unwrap();
                let old = g.f_time.take();
                self.c_group(f, &name, &mut g.f_time, &mut g.merged_sum, &shared, false, false);
                if ftime_changed(old.as_ref(), g.f_time.as_ref()) {
                    if self.merge_shared() {
                        self.c_group(f, &name, &mut g.f_time, &mut g.merged_sum, &shared, true, false);
                    }
                    g.has_changed = true;
                    tracing::trace!("Group '{name}' has changed.");
                } else {
                    g.has_changed = false;
                }
                g.exists = true;
                f.groups.insert(name, g);
            }
        }
    }

    fn process_multi_groups(&self, f: &mut Files, distinct: Option<Vec<serde_json::Value>>) {
        if let Some(rows) = distinct {
            for r in rows {
                let group = r.get("group").and_then(|x| x.as_str());
                let hash = r.get("group_hash").and_then(|x| x.as_str());
                if let (Some(g), Some(h)) = (group, hash) {
                    if g.contains(',') && !f.m_hash.contains_key(g) {
                        f.m_hash.insert(g.to_string(), h.to_string());
                    }
                }
            }
        }
        let mdir = self.settings.paths.multigroups_dir();
        let entries: Vec<(String, String)> = f.m_hash.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        for (key, data) in entries {
            let path = format!("{mdir}/{data}");
            if fo::wreaddir(&path).is_none() {
                if let Err(e) = std::fs::create_dir_all(&path) {
                    tracing::error!("Cannot create multigroup directory '{path}': {e}");
                    continue;
                }
            }
            if !f.multi_groups.contains_key(&key) {
                let mut g = Group { name: key.clone(), ..Default::default() };
                self.c_multi_group(f, &key, &mut g.f_time, &mut g.merged_sum, &data, self.merge_shared());
                g.exists = true;
                f.multi_groups.insert(key, g);
            } else if group_changed(f, &key) {
                let mut g = f.multi_groups.remove(&key).unwrap();
                g.f_time = None;
                self.c_multi_group(f, &key, &mut g.f_time, &mut g.merged_sum, &data, self.merge_shared());
                tracing::trace!("Multigroup '{key}' has changed.");
                g.exists = true;
                f.multi_groups.insert(key, g);
            } else {
                let mut g = f.multi_groups.remove(&key).unwrap();
                let old = g.f_time.take();
                self.c_multi_group(f, &key, &mut g.f_time, &mut g.merged_sum, &data, false);
                if ftime_changed(old.as_ref(), g.f_time.as_ref()) {
                    if self.merge_shared() {
                        self.c_multi_group(f, &key, &mut g.f_time, &mut g.merged_sum, &data, true);
                        tracing::warn!("Multigroup '{key}' was modified from outside, so it was regenerated.");
                    } else {
                        tracing::trace!("Multigroup '{key}' was modified from outside.");
                    }
                }
                g.exists = true;
                f.multi_groups.insert(key, g);
            }
        }
    }

    fn process_deleted_multi_groups(&self, f: &mut Files, initial_scan: bool) {
        let mdir = self.settings.paths.multigroups_dir();
        if initial_scan {
            let keep: Vec<&str> = f.m_hash.values().map(String::as_str).collect();
            let _ = fo::cldir_ex_ignore(&mdir, &keep);
        }
        f.m_hash.clear();
        let names: Vec<String> = f.multi_groups.keys().cloned().collect();
        for n in names {
            let exists = f.multi_groups.get(&n).map(|g| g.exists).unwrap_or(false);
            if exists {
                f.multi_groups.get_mut(&n).unwrap().exists = false;
            } else {
                let _ = fo::rmdir_ex(&format!("{mdir}/{}", multigroup_hash(&n)));
                f.multi_groups.remove(&n);
            }
        }
    }

    /// `c_multi_group`
    fn c_multi_group(&self, f: &mut Files, multi_group: &str, f_time: &mut Option<HashMap<String, i64>>, sum: &mut String, hash: &str, create_merged: bool) {
        let mdir = self.settings.paths.multigroups_dir();
        let multi_path = format!("{mdir}/{hash}");
        let _ = fo::cldir_ex_ignore(&multi_path, &[SHAREDCFG_FILENAME]);
        if create_merged {
            let shared = self.settings.paths.shared_dir();
            for group in multi_group.split(MULTIGROUP_SEPARATOR).filter(|g| !g.is_empty()) {
                if std::fs::read_dir(&shared).is_err() {
                    tracing::debug!("Opening directory: '{shared}'");
                    return;
                }
                self.copy_directory(f, &format!("{shared}/{group}"), &multi_path, group);
            }
        }
        if std::fs::read_dir(&mdir).is_err() {
            tracing::debug!("Opening directory: '{mdir}'");
            return;
        }
        self.c_group(f, hash, f_time, sum, &mdir, create_merged, true);
        if create_merged {
            let _ = fo::cldir_ex_ignore(&multi_path, &[SHAREDCFG_FILENAME]);
        }
    }

    /// `copy_directory`
    fn copy_directory(&self, f: &mut Files, src: &str, dst: &str, group: &str) {
        let Some(files) = fo::wreaddir(src) else {
            if std::path::Path::new(src).exists() {
                tracing::warn!("Could not open directory '{src}'. Group folder was deleted.");
            }
            return;
        };
        for name in files {
            if name.starts_with('.') || name.starts_with(SHAREDCFG_FILENAME) {
                continue;
            }
            let s = format!("{src}/{name}");
            let d = format!("{dst}/{name}");
            if s.len() > MAX_SHARED_PATH {
                self.path_too_long(f, "Source path too long", &s);
                continue;
            }
            if d.len() > MAX_SHARED_PATH {
                self.path_too_long(f, "Destination path too long", &d);
                continue;
            }
            if !std::path::Path::new(&s).is_dir() {
                if f.invalid_files.contains_key(&s) {
                    continue;
                }
                let r = if name == "agent.conf" {
                    fo::copy_file(&s, &d, 'a', Some(&format!("<!-- Source file: {group}/agent.conf -->\n")))
                } else {
                    fo::copy_file(&s, &d, 'c', None)
                };
                let _ = r;
            } else {
                if let Err(e) = std::fs::create_dir(&d) {
                    if e.kind() != std::io::ErrorKind::AlreadyExists {
                        tracing::error!("Cannot create directory '{d}': {e}");
                        continue;
                    }
                }
                self.copy_directory(f, &s, &d, group);
            }
        }
    }

    fn path_too_long(&self, f: &Files, what: &str, p: &str) {
        if !f.reported_path_size_exceeded {
            tracing::warn!("{what} '{p}'");
        } else {
            tracing::debug!("{what} '{p}'");
        }
    }

    /// `c_group`
    #[allow(clippy::too_many_arguments)]
    fn c_group(&self, f: &mut Files, group: &str, f_time: &mut Option<HashMap<String, i64>>, merged_sum: &mut String, dir: &str, create_merged: bool, is_multigroup: bool) {
        let mut ft: HashMap<String, i64> = HashMap::new();
        let merged = format!("{dir}/{group}/{SHAREDCFG_FILENAME}");

        let r_group = if create_merged { self.shared_download.get_group(group) } else { None };
        let mut merged_is_downloaded = false;
        if let Some(rg) = &r_group {
            merged_is_downloaded = self.shared_download.poll_group(rg, &merged, dir, group, self.settings.internal.shared_reload);
        }

        if !merged_is_downloaded && (!is_multigroup || create_merged) {
            let mut buf: Vec<u8> = Vec::new();
            if create_merged {
                buf.extend_from_slice(format!("#{group}\n").as_bytes());
            }
            let ar = self.settings.paths.default_ar();
            if let Some(mt) = fo::mtime(&ar) {
                if create_merged && !fo::merge_append_file(&mut buf, &ar, None) {
                    return;
                }
                if !is_multigroup {
                    ft.insert(DEFAULTAR_FILE.to_string(), mt);
                }
            }
            let gpath = format!("{dir}/{group}");
            let ok = self.validate_shared_files(f, &gpath, &mut buf, &mut ft, create_merged, is_multigroup, None);
            if create_merged && !ok {
                return;
            }
            if create_merged {
                let new_sum = fo::md5_hex(&buf);
                if fo::md5_file(&merged).as_deref() != Some(new_sum.as_str()) {
                    if self.settings.internal.disk_storage == 1 {
                        let tmp = format!("{merged}.tmp");
                        if std::fs::write(&tmp, &buf).is_err() || std::fs::rename(&tmp, &merged).is_err() {
                            tracing::error!("Unable to create merged file: '{tmp}'.");
                            return;
                        }
                    } else if let Err(e) = std::fs::write(&merged, &buf) {
                        tracing::error!("Unable to open file: '{merged}' due to [{e}].");
                        return;
                    }
                }
            }
        }

        match fo::md5_file(&merged) {
            Some(s) => {
                *merged_sum = s;
                match fo::mtime(&merged) {
                    Some(mt) => {
                        ft.insert(SHAREDCFG_FILENAME.to_string(), mt);
                    }
                    None => tracing::error!("Unable to get entry attributes '{merged}'"),
                }
            }
            None => {
                if create_merged {
                    tracing::error!("Accessing file '{merged}'");
                }
            }
        }
        *f_time = Some(ft);
    }

    /// `validate_shared_files`
    #[allow(clippy::too_many_arguments)]
    fn validate_shared_files(
        &self,
        f: &mut Files,
        src: &str,
        out: &mut Vec<u8>,
        ft: &mut HashMap<String, i64>,
        create_merged: bool,
        is_multigroup: bool,
        mut path_offset: Option<usize>,
    ) -> bool {
        let Some(files) = fo::wreaddir(src) else { return true };
        for name in files {
            if name.starts_with('.') || name.starts_with(SHAREDCFG_FILENAME) {
                continue;
            }
            let file = format!("{src}/{name}");
            if file.len() > MAX_SHARED_PATH {
                self.path_too_long(f, "Path too long", &file);
                continue;
            }
            if path_offset.is_none() {
                path_offset = Some(fo::default_path_offset(&file));
            }
            let Ok(meta) = std::fs::metadata(&file) else {
                tracing::error!("Unable to get entry attributes '{file}'");
                continue;
            };
            if meta.is_dir() {
                if !self.validate_shared_files(f, &file, out, ft, create_merged, is_multigroup, path_offset) {
                    return false;
                }
                continue;
            }
            let mt = fo::mtime(&file).unwrap_or(0);
            let mut ignored = false;
            if let Some(&old) = f.invalid_files.get(&file) {
                ignored = true;
                if old != mt {
                    if fo::check_binary_file(&file) {
                        f.invalid_files.insert(file.clone(), mt);
                        tracing::debug!("File '{file}' modified but still invalid.");
                    } else {
                        f.invalid_files.remove(&file);
                        tracing::info!("File '{file}' is valid after last modification.");
                        ignored = false;
                    }
                }
            } else if fo::check_binary_file(&file) {
                ignored = true;
                f.invalid_files.insert(file.clone(), mt);
                tracing::error!("Invalid shared file '{file}'. Ignoring it.");
            }
            if !ignored {
                if create_merged && !fo::merge_append_file(out, &file, path_offset) {
                    return false;
                }
                if !is_multigroup {
                    ft.insert(file, mt);
                }
            }
        }
        true
    }

    /// Cheap handle with the pieces `c_files` needs inside `spawn_blocking`.
    fn clone_for_files(&self) -> Arc<Remoted> {
        self.self_ref.get().and_then(|w| w.upgrade()).expect("remoted self reference")
    }
}

/// `process_deleted_groups`
fn process_deleted_groups(f: &mut Files) {
    let names: Vec<String> = f.groups.keys().cloned().collect();
    for n in names {
        let g = f.groups.get_mut(&n).unwrap();
        if g.exists {
            g.has_changed = false;
            g.exists = false;
        } else {
            f.groups.remove(&n);
        }
    }
}

/// `ftime_changed`
fn ftime_changed(old: Option<&HashMap<String, i64>>, new: Option<&HashMap<String, i64>>) -> bool {
    match (old, new) {
        (None, None) => false,
        (Some(o), Some(n)) => o.len() != n.len() || o.iter().any(|(k, v)| n.get(k) != Some(v)),
        _ => true,
    }
}

/// `group_changed`
fn group_changed(f: &Files, multi_group: &str) -> bool {
    let parts = siem_regex::str_break(MULTIGROUP_SEPARATOR, multi_group, MAX_GROUPS_PER_MULTIGROUP).unwrap_or_default();
    parts.iter().any(|g| match f.groups.get(g) {
        Some(gr) => !gr.exists || gr.has_changed,
        None => true,
    })
}

/// Pending shared-file pushes (`pending_queue`).
pub type PendingQueue = Mutex<VecDeque<String>>;

/// Kept for parity with `IGNORE_LIST`.
pub fn ignore_list() -> HashSet<&'static str> {
    [SHAREDCFG_FILENAME].into_iter().collect()
}

impl Remoted {
    /// `wait_for_msgs` notification counterpart used in tests.
    pub fn pending_len(&self) -> usize {
        self.pending_queue.lock().unwrap().len()
    }

    pub fn current_counter(&self) -> u64 {
        self.global_counter.load(Ordering::SeqCst)
    }
}
