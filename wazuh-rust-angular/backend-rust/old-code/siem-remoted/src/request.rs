//! Port of `src/remoted/request.c` and `remcom.c`: the local socket
//! `queue/sockets/remote`. JSON commands (`getstats`, `getagentsstats`,
//! `getconfig`, `assigngroup`) are answered directly; anything else is an
//! `"<agent_id> <payload>"` request relayed to the agent as `#!-req <counter> ...`.

use crate::server::{CONTROL_HEADER, HC_REQUEST};
use crate::state::{Counter, REM_MAX_NUM_AGENTS_STATS};
use crate::keystore::NetProtocol;
use crate::Remoted;
use serde_json::{json, Value};
use siem_ipc::framing;
use siem_ipc::local::{LocalStream, StreamListener};
use siem_ipc::OS_MAXSTR;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore};

const WR_INTERNAL_ERROR: &str = "err Internal error";
const WR_SEND_ERROR: &str = "err Cannot send request";
const WR_ATTEMPT_ERROR: &str = "err Maximum attempts exceeded";
const WR_TIMEOUT_ERROR: &str = "err Response timeout";

/// `req_node_t`
#[derive(Default)]
pub struct ReqNode {
    response: Mutex<Option<Vec<u8>>>,
    notify: Notify,
}

pub struct Requests {
    table: Mutex<HashMap<String, Arc<ReqNode>>>,
    pool: Semaphore,
}

impl Requests {
    pub fn new(pool: usize) -> Self {
        Self { table: Mutex::new(HashMap::new()), pool: Semaphore::new(pool) }
    }
}

fn is_ack(b: &[u8]) -> bool {
    b == b"ack"
}

/// remcom error codes
const ERRORS: &[&str] = &[
    "ok",
    "due",
    "Invalid JSON input",
    "Empty command",
    "Unrecognized command",
    "Empty parameters",
    "Empty section",
    "Unrecognized or not configured section",
    "Invalid agents parameter",
    "Error getting agents from DB",
    "Empty last id",
    "Too many agents",
    "Invalid agent or md5 parameter",
];

/// `remcom_output_builder`
fn output(code: usize, data: Option<Value>) -> String {
    json!({"error": code, "message": ERRORS[code], "data": data.unwrap_or_else(|| json!({}))}).to_string()
}

impl Remoted {
    /// `req_save`: an agent answered (ack or response) request `counter`.
    pub(crate) fn req_save(&self, counter: &str, payload: &[u8]) -> bool {
        tracing::trace!("Saving '{counter}:{}'", String::from_utf8_lossy(payload));
        let node = self.requests.table.lock().unwrap().get(counter).cloned();
        match node {
            Some(n) => {
                *n.response.lock().unwrap() = Some(payload.to_vec());
                n.notify.notify_waiters();
                n.notify.notify_one();
                true
            }
            None => {
                tracing::debug!("Request counter ({counter}) not found. Duplicated message?");
                false
            }
        }
    }

    /// `remcom_main`
    pub(crate) async fn remcom_loop(self: Arc<Self>) {
        let path = self.settings.paths.remote_local_sock();
        let l = match StreamListener::bind(&path).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Unable to bind to socket '{path}': {e}");
                return;
            }
        };
        tracing::debug!("Local requests thread ready");
        loop {
            let Ok(mut peer) = l.accept().await else { continue };
            let me = self.clone();
            tokio::spawn(async move {
                match framing::recv(&mut peer, OS_MAXSTR).await {
                    Ok(buf) if buf.is_empty() => tracing::debug!("Empty message from local client"),
                    Ok(buf) => {
                        if buf.first() == Some(&b'{') {
                            let out = me.remcom_dispatch(&buf).await;
                            let _ = framing::send(&mut peer, out.as_bytes()).await;
                        } else {
                            me.req_sender(peer, buf).await;
                        }
                    }
                    Err(e) => tracing::error!("At OS_RecvSecureTCP(): {e}"),
                }
            });
        }
    }

    /// `remcom_dispatch`
    pub async fn remcom_dispatch(&self, request: &[u8]) -> String {
        let Ok(req) = serde_json::from_slice::<Value>(request) else { return output(2, None) };
        let Some(cmd) = req.get("command").and_then(|c| c.as_str()) else { return output(3, None) };
        let params = req.get("parameters");
        match cmd {
            "getstats" => output(0, Some(self.state.state_json(self.msgq.size, self.msgq.usage(), self.ctrl_queue.len()))),
            "getagentsstats" => {
                let Some(p) = params.filter(|p| p.is_object()) else { return output(5, None) };
                match p.get("agents") {
                    Some(Value::Array(a)) => {
                        if a.len() >= REM_MAX_NUM_AGENTS_STATS {
                            return output(11, None);
                        }
                        let ids: Vec<i64> = a.iter().filter_map(|x| x.as_i64()).collect();
                        if ids.len() != a.len() {
                            return output(9, None);
                        }
                        output(0, Some(self.state.agents_state_json(&ids)))
                    }
                    Some(Value::String(s)) if s == "all" => match p.get("last_id").and_then(|x| x.as_i64()) {
                        Some(last) if last >= 0 => {
                            let ids = crate::wdb::get_agents_ids_of_current_node(
                                self.wdb.as_ref(),
                                crate::wdb::AGENT_CS_ACTIVE,
                                &self.settings.node_name,
                                last,
                                REM_MAX_NUM_AGENTS_STATS as i64,
                            )
                            .await;
                            match ids {
                                Some(ids) => {
                                    let code = if ids.len() < REM_MAX_NUM_AGENTS_STATS { 0 } else { 1 };
                                    output(code, Some(self.state.agents_state_json(&ids)))
                                }
                                None => output(9, None),
                            }
                        }
                        _ => output(10, None),
                    },
                    _ => output(8, None),
                }
            }
            "getconfig" => {
                let Some(p) = params.filter(|p| p.is_object()) else { return output(5, None) };
                let Some(section) = p.get("section").and_then(|s| s.as_str()) else { return output(6, None) };
                let cfg = match section {
                    "remote" => Some(self.settings.remote_json(0)),
                    "internal" => Some(self.settings.internal_json()),
                    "global" => Some(self.settings.global_json()),
                    _ => None,
                };
                match cfg {
                    Some(c) => output(0, Some(c)),
                    None => output(7, None),
                }
            }
            "assigngroup" => {
                let Some(p) = params.filter(|p| p.is_object()) else { return output(5, None) };
                match (p.get("agent").and_then(|x| x.as_str()), p.get("md5").and_then(|x| x.as_str())) {
                    (Some(a), Some(m)) => {
                        let g = self.assign_group_to_agent(a, m).await;
                        output(0, Some(json!({ "group": g })))
                    }
                    _ => output(12, None),
                }
            }
            _ => output(4, None),
        }
    }

    /// `req_sender` + `req_dispatch`
    async fn req_sender(self: Arc<Self>, mut peer: LocalStream, buffer: Vec<u8>) {
        let counter = format!("{:x}", rand::random::<u32>());
        let node = Arc::new(ReqNode::default());
        let duplicated = {
            let mut t = self.requests.table.lock().unwrap();
            if t.contains_key(&counter) {
                true
            } else {
                t.insert(counter.clone(), node.clone());
                false
            }
        };
        if duplicated {
            tracing::error!("At OSHash_Add(): Duplicated counter.");
            let _ = framing::send(&mut peer, WR_INTERNAL_ERROR.as_bytes()).await;
            return;
        }
        let timeout = Duration::from_secs(self.settings.internal.request_timeout as u64);
        let permit = match tokio::time::timeout(timeout, self.requests.pool.acquire()).await {
            Ok(Ok(p)) => p,
            _ => {
                tracing::error!("Request pool is full. Rejecting request.");
                self.requests.table.lock().unwrap().remove(&counter);
                let _ = framing::send(&mut peer, WR_INTERNAL_ERROR.as_bytes()).await;
                return;
            }
        };
        self.req_dispatch(&counter, &node, &mut peer, &buffer).await;
        drop(permit);
        self.requests.table.lock().unwrap().remove(&counter);
    }

    async fn req_dispatch(&self, counter: &str, node: &ReqNode, peer: &mut LocalStream, buffer: &[u8]) {
        let Some(sp) = buffer.iter().position(|&b| b == b' ') else {
            tracing::error!("Request has no agent id.");
            return;
        };
        let agent_id = String::from_utf8_lossy(&buffer[..sp]).into_owned();
        let mut payload = format!("{CONTROL_HEADER}{HC_REQUEST}{counter} ").into_bytes();
        payload.extend_from_slice(&buffer[sp + 1..]);

        let proto = self.keys.read().unwrap().net_protocol(&agent_id);
        let Some(proto) = proto else {
            tracing::error!("(1320): Agent '{agent_id}' not found.");
            return;
        };
        let max = self.settings.internal.max_attempts;
        let rto = Duration::from_secs(self.settings.internal.rto_sec as u64) + Duration::from_millis(self.settings.internal.rto_msec as u64);
        let mut attempts = 0;
        while attempts < max {
            if !self.send_msg(&agent_id, &payload).await {
                tracing::error!("Cannot send request to agent '{agent_id}'");
                let _ = framing::send(peer, WR_SEND_ERROR.as_bytes()).await;
                return;
            }
            self.state.inc(Counter::SendRequest, Some(&agent_id));
            if proto == NetProtocol::Udp {
                let got = tokio::time::timeout(rto, node.notify.notified()).await.is_ok();
                if got && node.response.lock().unwrap().is_some() {
                    break;
                }
            } else {
                break;
            }
            tracing::trace!("Timeout for waiting ACK from agent '{agent_id}', resending.");
            attempts += 1;
        }
        if attempts == max {
            tracing::error!("Couldn't send request to agent '{agent_id}': number of attempts exceeded.");
            let _ = framing::send(peer, WR_ATTEMPT_ERROR.as_bytes()).await;
            return;
        }
        let resp_timeout = Duration::from_secs(self.settings.internal.response_timeout as u64);
        let mut attempts = 0;
        loop {
            let pending = {
                let r = node.response.lock().unwrap();
                r.as_deref().map(is_ack).unwrap_or(true)
            };
            if !pending || attempts >= max {
                break;
            }
            if tokio::time::timeout(resp_timeout, node.notify.notified()).await.is_err() {
                tracing::error!("Response timeout for request counter '{counter}'");
                let _ = framing::send(peer, WR_TIMEOUT_ERROR.as_bytes()).await;
                return;
            }
            attempts += 1;
        }
        if attempts == max {
            tracing::error!("Couldn't get response from agent '{agent_id}': number of attempts exceeded.");
            let _ = framing::send(peer, WR_ATTEMPT_ERROR.as_bytes()).await;
            return;
        }
        if proto == NetProtocol::Udp {
            let ack = format!("{CONTROL_HEADER}{HC_REQUEST}{counter} ack");
            if self.send_msg(&agent_id, ack.as_bytes()).await {
                self.state.inc(Counter::SendRequest, Some(&agent_id));
            }
        }
        let resp = node.response.lock().unwrap().clone().unwrap_or_default();
        if let Err(e) = framing::send(peer, &resp).await {
            tracing::warn!("At OS_SendSecureTCP(): {e}");
        }
        let _ = Ordering::Relaxed;
    }
}
