//! Port of `src/remoted/state.c`: global and per-agent counters, the JSON
//! returned by the `getstats` / `getagentsstats` remcom commands, and the
//! `var/run/wazuh-remoted.state` file.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

pub const ARGV0: &str = "wazuh-remoted";
/// `REM_MAX_NUM_AGENTS_STATS`
pub const REM_MAX_NUM_AGENTS_STATS: usize = 150;

#[derive(Debug, Default, Clone)]
pub struct CtrlBreakdown {
    pub keepalive: u64,
    pub startup: u64,
    pub shutdown: u64,
    pub request: u64,
}

#[derive(Debug, Default, Clone)]
pub struct SentBreakdown {
    pub ack: u64,
    pub shared: u64,
    pub ar: u64,
    pub sca: u64,
    pub request: u64,
    pub discarded: u64,
}

#[derive(Debug, Default, Clone)]
pub struct RemotedStats {
    pub uptime: i64,
    pub tcp_sessions: u64,
    pub recv_bytes: u64,
    pub sent_bytes: u64,
    pub keys_reload_count: u64,
    pub evt: u64,
    pub ctrl: u64,
    pub ping: u64,
    pub unknown: u64,
    pub dequeued: u64,
    pub discarded: u64,
    pub ctrl_breakdown: CtrlBreakdown,
    pub sent: SentBreakdown,
    pub ctrl_queue_inserted: u64,
    pub ctrl_queue_replaced: u64,
    pub ctrl_queue_processed: u64,
}

#[derive(Debug, Default, Clone)]
pub struct AgentStats {
    pub uptime: i64,
    pub recv_evt: u64,
    pub recv_ctrl: u64,
    pub ctrl_breakdown: CtrlBreakdown,
    pub sent: SentBreakdown,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// What a counter increment applies to.
#[derive(Debug, Clone, Copy)]
pub enum Counter {
    RecvEvt,
    RecvCtrl,
    RecvPing,
    RecvUnknown,
    RecvDequeued,
    RecvDiscarded,
    CtrlKeepalive,
    CtrlStartup,
    CtrlShutdown,
    CtrlRequest,
    SendAck,
    SendShared,
    SendAr,
    SendCfga,
    SendRequest,
    SendDiscarded,
    KeysReload,
    CtrlQueueInserted,
    CtrlQueueReplaced,
    CtrlQueueProcessed,
}

#[derive(Debug, Default)]
pub struct State {
    global: Mutex<RemotedStats>,
    agents: Mutex<HashMap<String, AgentStats>>,
}

impl State {
    pub fn new() -> Self {
        let s = Self::default();
        s.global.lock().unwrap().uptime = now();
        s
    }

    pub fn snapshot(&self) -> RemotedStats {
        self.global.lock().unwrap().clone()
    }

    pub fn tcp(&self, delta: i64) {
        let mut g = self.global.lock().unwrap();
        g.tcp_sessions = (g.tcp_sessions as i64 + delta).max(0) as u64;
    }

    pub fn add_recv(&self, bytes: u64) {
        self.global.lock().unwrap().recv_bytes += bytes;
    }

    pub fn add_send(&self, bytes: u64) {
        self.global.lock().unwrap().sent_bytes += bytes;
    }

    /// `rem_inc_*`: global counter plus, when `agent` is given, the per-agent one.
    pub fn inc(&self, c: Counter, agent: Option<&str>) {
        {
            let mut g = self.global.lock().unwrap();
            match c {
                Counter::RecvEvt => g.evt += 1,
                Counter::RecvCtrl => g.ctrl += 1,
                Counter::RecvPing => g.ping += 1,
                Counter::RecvUnknown => g.unknown += 1,
                Counter::RecvDequeued => g.dequeued += 1,
                Counter::RecvDiscarded => g.discarded += 1,
                Counter::CtrlKeepalive => g.ctrl_breakdown.keepalive += 1,
                Counter::CtrlStartup => g.ctrl_breakdown.startup += 1,
                Counter::CtrlShutdown => g.ctrl_breakdown.shutdown += 1,
                Counter::CtrlRequest => g.ctrl_breakdown.request += 1,
                Counter::SendAck => g.sent.ack += 1,
                Counter::SendShared => g.sent.shared += 1,
                Counter::SendAr => g.sent.ar += 1,
                Counter::SendCfga => g.sent.sca += 1,
                Counter::SendRequest => g.sent.request += 1,
                Counter::SendDiscarded => g.sent.discarded += 1,
                Counter::KeysReload => g.keys_reload_count += 1,
                Counter::CtrlQueueInserted => g.ctrl_queue_inserted += 1,
                Counter::CtrlQueueReplaced => g.ctrl_queue_replaced += 1,
                Counter::CtrlQueueProcessed => g.ctrl_queue_processed += 1,
            }
        }
        let Some(id) = agent else { return };
        let mut agents = self.agents.lock().unwrap();
        let a = agents.entry(id.to_string()).or_insert_with(|| AgentStats { uptime: now(), ..Default::default() });
        match c {
            Counter::RecvEvt => a.recv_evt += 1,
            Counter::RecvCtrl => a.recv_ctrl += 1,
            Counter::CtrlKeepalive => a.ctrl_breakdown.keepalive += 1,
            Counter::CtrlStartup => a.ctrl_breakdown.startup += 1,
            Counter::CtrlShutdown => a.ctrl_breakdown.shutdown += 1,
            Counter::CtrlRequest => a.ctrl_breakdown.request += 1,
            Counter::SendAck => a.sent.ack += 1,
            Counter::SendShared => a.sent.shared += 1,
            Counter::SendAr => a.sent.ar += 1,
            Counter::SendCfga => a.sent.sca += 1,
            Counter::SendRequest => a.sent.request += 1,
            Counter::SendDiscarded => a.sent.discarded += 1,
            _ => {}
        }
    }

    /// `w_remoted_clean_agents_state`: keep only active agents.
    pub fn retain_agents(&self, active_ids: &[i64]) {
        self.agents
            .lock()
            .unwrap()
            .retain(|id, _| id.parse::<i64>().map(|n| active_ids.contains(&n)).unwrap_or(false));
    }

    pub fn has_agents(&self) -> bool {
        !self.agents.lock().unwrap().is_empty()
    }

    /// `rem_create_state_json`
    pub fn state_json(&self, queue_size: usize, queue_usage: usize, ctrl_queue_usage: usize) -> Value {
        let s = self.snapshot();
        json!({
            "uptime": s.uptime,
            "timestamp": now(),
            "name": ARGV0,
            "metrics": {
                "bytes": {"received": s.recv_bytes, "sent": s.sent_bytes},
                "keys_reload_count": s.keys_reload_count,
                "messages": {
                    "received_breakdown": {
                        "control": s.ctrl,
                        "control_breakdown": {
                            "keepalive": s.ctrl_breakdown.keepalive,
                            "request": s.ctrl_breakdown.request,
                            "shutdown": s.ctrl_breakdown.shutdown,
                            "startup": s.ctrl_breakdown.startup
                        },
                        "dequeued_after": s.dequeued,
                        "discarded": s.discarded,
                        "event": s.evt,
                        "ping": s.ping,
                        "unknown": s.unknown
                    },
                    "sent_breakdown": {
                        "ack": s.sent.ack,
                        "ar": s.sent.ar,
                        "discarded": s.sent.discarded,
                        "request": s.sent.request,
                        "sca": s.sent.sca,
                        "shared": s.sent.shared
                    }
                },
                "queues": {"received": {"size": queue_size, "usage": queue_usage}},
                "tcp_sessions": s.tcp_sessions,
                "control_messages_queue_usage": ctrl_queue_usage,
                "control_messages_queue_breakdown": {
                    "inserted": s.ctrl_queue_inserted,
                    "replaced": s.ctrl_queue_replaced,
                    "processed": s.ctrl_queue_processed
                }
            }
        })
    }

    /// `rem_create_agents_state_json`
    pub fn agents_state_json(&self, ids: &[i64]) -> Value {
        let agents = self.agents.lock().unwrap();
        let mut arr = Vec::new();
        for &id in ids {
            let key = format!("{id:03}");
            if let Some(a) = agents.get(&key) {
                arr.push(json!({
                    "uptime": a.uptime,
                    "id": id,
                    "metrics": {
                        "messages": {
                            "received_breakdown": {
                                "control": a.recv_ctrl,
                                "control_breakdown": {
                                    "keepalive": a.ctrl_breakdown.keepalive,
                                    "request": a.ctrl_breakdown.request,
                                    "shutdown": a.ctrl_breakdown.shutdown,
                                    "startup": a.ctrl_breakdown.startup
                                },
                                "event": a.recv_evt
                            },
                            "sent_breakdown": {
                                "ack": a.sent.ack,
                                "ar": a.sent.ar,
                                "discarded": a.sent.discarded,
                                "request": a.sent.request,
                                "sca": a.sent.sca,
                                "shared": a.sent.shared
                            }
                        }
                    }
                }));
            }
        }
        json!({"timestamp": now(), "name": ARGV0, "agents": arr})
    }

    /// `rem_write_state`: the legacy key=value state file.
    pub fn state_file_text(&self, refresh: &str, queue_size: usize, total: usize, ctrl_queue_usage: usize) -> String {
        let s = self.snapshot();
        format!(
            "# State file for {ARGV0}\n# THIS FILE WILL BE DEPRECATED IN FUTURE VERSIONS\n# {refresh}\n\n\
             # Queue size\nqueue_size='{queue_size}'\n\n# Total queue size\ntotal_queue_size='{total}'\n\n\
             # TCP sessions\ntcp_sessions='{}'\n\n# Events sent to Analysisd\nevt_count='{}'\n\n\
             # Control messages received\nctrl_msg_count='{}'\n\n# Discarded messages\ndiscarded_count='{}'\n\n\
             # Total number of bytes sent\nsent_bytes='{}'\n\n# Total number of bytes received\nrecv_bytes='{}'\n\n\
             # Messages dequeued after the agent closes the connection\ndequeued_after_close='{}'\n\n\
             # Control messages queue usage\nctrl_msg_queue_usage='{ctrl_queue_usage}'\n\n\
             # Control messages queue breakdown\nctrl_msg_queue_inserted='{}'\nctrl_msg_queue_replaced='{}'\nctrl_msg_queue_processed='{}'\n\n",
            s.tcp_sessions, s.evt, s.ctrl, s.discarded, s.sent_bytes, s.recv_bytes, s.dequeued,
            s.ctrl_queue_inserted, s.ctrl_queue_replaced, s.ctrl_queue_processed
        )
    }
}

/// The "Updated every ..." line of the state file.
pub fn refresh_text(interval: i64) -> String {
    if interval < 60 {
        format!("Updated every {interval} seconds.")
    } else if interval < 3600 {
        format!("Updated every {} minutes.", interval / 60)
    } else {
        format!("Updated every {} hours.", interval / 3600)
    }
}
