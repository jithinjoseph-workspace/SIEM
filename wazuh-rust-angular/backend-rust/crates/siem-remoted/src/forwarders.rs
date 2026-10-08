//! Background tasks of remoted: `AR_Forward` (ar-forward.c), `SCFGA_Forward`
//! (cfga-forward.c), the key-request sender, the key reloader, the timestamp
//! updater and the state writer (secure.c / state.c).

use crate::server::{CONTROL_HEADER, EXECD_HEADER};
use crate::state::{refresh_text, Counter};
use crate::Remoted;
use siem_ipc::local::{DatagramReceiver, DatagramSender};
use siem_ipc::OS_MAXSTR;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

pub const ALL_AGENTS: u32 = 0o1;
pub const REMOTE_AGENT: u32 = 0o2;
pub const SPECIFIC_AGENT: u32 = 0o4;
pub const NO_AR_MSG: u32 = 0o20;
pub const CFGA_DB_DUMP: &str = "sca-dump";

/// Parsed active-response request from analysisd/execq.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArRequest {
    pub location: u32,
    pub agent_id: String,
    pub message: String,
}

/// Parse an `queue/alerts/ar` message as `AR_Forward` does:
/// `"(<srcip>) <user?>[...] <A|N><R|!|N><S|N> <agent_id> <command...>"`.
pub fn parse_ar(msg: &str) -> Option<ArRequest> {
    let b = msg.as_bytes();
    let mut i = msg.find(')')? + 2;
    i = i + msg.get(i..)?.find(']')? + 2;
    let mut loc = 0;
    if b.get(i) == Some(&b'A') {
        loc |= ALL_AGENTS;
    }
    i += 1;
    match b.get(i) {
        Some(b'R') => loc |= REMOTE_AGENT,
        Some(b'!') => loc |= NO_AR_MSG,
        _ => {}
    }
    i += 1;
    if b.get(i) == Some(&b'S') {
        loc |= SPECIFIC_AGENT;
    }
    i += 2;
    let rest = msg.get(i..)?;
    let sp = rest.find(' ')?;
    Some(ArRequest { location: loc, agent_id: rest[..sp].to_string(), message: rest[sp + 1..].to_string() })
}

impl Remoted {
    /// `AR_Forward`
    pub(crate) async fn ar_forward_loop(self: Arc<Self>) {
        let path = self.settings.paths.ar_queue();
        let rx = match DatagramReceiver::bind(&path).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("(1210): Queue '{path}' not accessible: {e}");
                return;
            }
        };
        loop {
            let Ok(raw) = rx.recv(OS_MAXSTR - 1).await else { continue };
            let msg = String::from_utf8_lossy(&raw).trim_end_matches('\0').to_string();
            tracing::trace!("Active response request received: {msg}");
            let Some(ar) = parse_ar(&msg) else {
                tracing::warn!("(1310): Invalid active response (execd) message '{msg}'.");
                continue;
            };
            let mut out = if ar.location & NO_AR_MSG != 0 {
                format!("{CONTROL_HEADER}{}", ar.message)
            } else {
                format!("{CONTROL_HEADER}{EXECD_HEADER}{}", ar.message)
            };
            crate::truncate_bytes(&mut out, OS_MAXSTR - 1);
            tracing::trace!("Active response sent: {out}");
            if ar.location & ALL_AGENTS != 0 {
                let entries = crate::server::keys_snapshot(&self.keys);
                let now = crate::now();
                for e in entries {
                    let rcvd = e.state.lock().unwrap().rcvd;
                    if rcvd >= now - self.settings.remote.agents_disconnection_time && self.send_msg(&e.id, out.as_bytes()).await {
                        self.state.inc(Counter::SendAr, Some(&e.id));
                    }
                }
            } else if ar.location & (REMOTE_AGENT | SPECIFIC_AGENT) != 0 && self.send_msg(&ar.agent_id, out.as_bytes()).await {
                self.state.inc(Counter::SendAr, Some(&ar.agent_id));
            }
        }
    }

    /// `SCFGA_Forward`: `"<agent_id>:sca-dump..."` -> `#!-sca-dump...`
    pub(crate) async fn cfga_forward_loop(self: Arc<Self>) {
        let path = self.settings.paths.cfga_queue();
        let rx = match DatagramReceiver::bind(&path).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("(1210): Queue '{path}' not accessible: {e}");
                return;
            }
        };
        loop {
            let Ok(raw) = rx.recv(4096).await else { continue };
            let msg = String::from_utf8_lossy(&raw).into_owned();
            let Some(p) = msg.find(':') else { continue };
            let (agent_id, dump) = (&msg[..p], &msg[p + 1..]);
            if dump.starts_with(CFGA_DB_DUMP) {
                let mut out = format!("{CONTROL_HEADER}{dump}");
                crate::truncate_bytes(&mut out, 4095);
                if self.send_msg(agent_id, out.as_bytes()).await {
                    self.state.inc(Counter::SendCfga, Some(agent_id));
                }
            }
        }
    }

    /// `key_request_thread`: forward `"<type>:<value>"` to authd's krequest socket.
    pub(crate) async fn key_request_loop(self: Arc<Self>, mut rx: tokio::sync::mpsc::Receiver<String>) {
        let path = self.settings.paths.key_request_sock();
        let mut sock: Option<DatagramSender> = None;
        let mut pending: Option<String> = None;
        loop {
            if sock.is_none() {
                sock = loop {
                    let mut got = None;
                    for _ in 0..4 {
                        match DatagramSender::connect(&path).await {
                            Ok(s) => {
                                got = Some(s);
                                break;
                            }
                            Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
                        }
                    }
                    if got.is_some() {
                        self.key_request_available.store(true, Ordering::Relaxed);
                        break got;
                    }
                    tracing::debug!("Key-request feature is not available. Retrying connection in 300 seconds.");
                    tokio::time::sleep(Duration::from_secs(300)).await;
                };
            }
            let msg = match pending.take() {
                Some(m) => m,
                None => match rx.recv().await {
                    Some(m) => m,
                    None => return,
                },
            };
            if let Err(e) = sock.as_ref().unwrap().send(msg.as_bytes()).await {
                tracing::error!("Could not communicate with key request queue ({e}). Is the module running?");
                self.key_request_available.store(false, Ordering::Relaxed);
                sock = None;
                pending = Some(msg);
            }
        }
    }

    /// `rem_keyupdate_main`
    pub(crate) async fn key_update_loop(self: Arc<Self>) {
        let every = Duration::from_secs(self.settings.internal.keyupdate_interval as u64);
        loop {
            tokio::time::sleep(every).await;
            let needs = self.keys.read().unwrap().needs_reload();
            if !needs {
                continue;
            }
            tracing::info!("(1752): File client.keys changed. Reloading.");
            let reloaded = self.keys.read().unwrap().reload(self.settings.internal.pass_empty_keyfile == 1);
            match reloaded {
                Ok(ks) => {
                    {
                        let counters = self.counters.lock().unwrap();
                        for e in &ks.entries {
                            let mut st = e.state.lock().unwrap();
                            counters.start_agent(&mut st.key);
                        }
                    }
                    *self.keys.write().unwrap() = ks;
                    self.state.inc(Counter::KeysReload, None);
                }
                Err(e) => tracing::error!("{e}"),
            }
        }
    }

    /// `current_timestamp`
    pub(crate) async fn timestamp_loop(self: Arc<Self>) {
        loop {
            self.current_ts.store(crate::now(), Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// `rem_state_main`
    pub(crate) async fn state_loop(self: Arc<Self>) {
        let interval = self.settings.internal.state_interval as i64;
        if interval == 0 {
            tracing::info!("State file is disabled.");
            return;
        }
        let refresh = refresh_text(interval);
        loop {
            let text = self.state.state_file_text(&refresh, self.msgq.usage(), self.msgq.size, self.ctrl_queue.len());
            let path = self.settings.paths.state_file();
            let tmp = format!("{path}.temp");
            if let Some(p) = std::path::Path::new(&path).parent() {
                let _ = std::fs::create_dir_all(p);
            }
            if std::fs::write(&tmp, text).is_ok() {
                if let Err(e) = std::fs::rename(&tmp, &path) {
                    tracing::error!("Renaming {tmp} to {path}: {e}");
                    let _ = std::fs::remove_file(&tmp);
                }
            }
            tokio::time::sleep(Duration::from_secs(interval as u64)).await;
            if self.state.has_agents() {
                if let Some(ids) = crate::wdb::get_agents_ids_of_current_node(
                    self.wdb.as_ref(),
                    crate::wdb::AGENT_CS_ACTIVE,
                    &self.settings.node_name,
                    0,
                    -1,
                )
                .await
                {
                    self.state.retain_agents(&ids);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ar_messages() {
        let a = parse_ar("(local_source) [] NRN 001 {\"version\":1,\"command\":\"add\"}").unwrap();
        assert_eq!(a, ArRequest { location: REMOTE_AGENT, agent_id: "001".into(), message: "{\"version\":1,\"command\":\"add\"}".into() });
        let b = parse_ar("(1.2.3.4) [user] ANN (null) restart-wazuh0 - - 123 1 /var/log").unwrap();
        assert_eq!(b.location, ALL_AGENTS);
        assert_eq!(b.agent_id, "(null)");
        let c = parse_ar("(x) [] N!S 004 msg").unwrap();
        assert_eq!(c.location, NO_AR_MSG | SPECIFIC_AGENT);
        assert!(parse_ar("garbage").is_none());
    }
}
