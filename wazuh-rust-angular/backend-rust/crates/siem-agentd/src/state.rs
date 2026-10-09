//! `client-agent/state.c`: the agent state counters, the
//! `var/run/wazuh-agentd.state` file and the `getstate` JSON.

use std::io::Write;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use siem_cjson::Json;

use crate::*;

/// `agent_state_t`
#[derive(Debug, Clone, Copy)]
pub struct AgentState {
    pub status: AgentStatus,
    pub last_keepalive: i64,
    pub last_ack: i64,
    pub msg_count: u32,
    pub msg_sent: u32,
}

impl Default for AgentState {
    fn default() -> Self {
        Self { status: AgentStatus::Pending, last_keepalive: 0, last_ack: 0, msg_count: 0, msg_sent: 0 }
    }
}

/// `w_agentd_state_update_t`
pub enum Update {
    Status(AgentStatus),
    Keepalive(i64),
    Ack(i64),
    IncrementMsgCount,
    IncrementMsgSend,
    ResetMsgCountOnShrink(u32),
}

#[derive(Default)]
pub struct State {
    inner: Mutex<AgentState>,
}

/// `W_AGENTD_STATE_TIME_FORMAT` of a local time.
fn fmt_time(t: i64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_opt(t, 0) {
        chrono::LocalResult::Single(d) | chrono::LocalResult::Ambiguous(d, _) => d.format("%Y-%m-%d %H:%M:%S").to_string(),
        chrono::LocalResult::None => String::new(),
    }
}

/// `get_str_status`
fn str_status(s: AgentStatus) -> &'static str {
    match s {
        AgentStatus::Pending => "pending",
        AgentStatus::Active => "connected",
        AgentStatus::NActive => "disconnected",
    }
}

impl State {
    /// `w_agentd_state_update`
    pub fn update(&self, u: Update) {
        let mut s = self.inner.lock().unwrap();
        match u {
            Update::Status(st) => s.status = st,
            Update::Keepalive(t) => s.last_keepalive = t,
            Update::Ack(t) => s.last_ack = t,
            Update::IncrementMsgCount => s.msg_count = s.msg_count.wrapping_add(1),
            Update::IncrementMsgSend => s.msg_sent = s.msg_sent.wrapping_add(1),
            Update::ResetMsgCountOnShrink(n) => s.msg_count = n,
        }
    }

    pub fn snapshot(&self) -> AgentState {
        *self.inner.lock().unwrap()
    }
}

/// `w_agentd_state_init`
pub fn init(ag: &Agentd) {
    let v = ag.define_int("agent", "state_interval", 0, 86400);
    ag.ints.interval.store(v, Ordering::SeqCst);
}

/// `state_main`
pub fn state_main(ag: &Agentd) {
    let interval = ag.ints.interval.load(Ordering::SeqCst);
    if interval == 0 {
        ag.log.info("State file is disabled.");
        return;
    }
    ag.log.debug1("State file updating thread started.");
    loop {
        let _ = write_state(ag);
        sleep_secs(interval as i64);
    }
}

/// `write_state`
pub fn write_state(ag: &Agentd) -> Result<(), ()> {
    ag.log.debug2("Updating state file.");
    let buffered = crate::buffer::get_buffer_length(ag);
    let st = ag.state.inner.lock().unwrap();
    let path = format!("{OS_PIDFILE}/{ARGV0}.state");
    let path_temp = format!("{path}.temp");
    let mut fp = match std::fs::File::create(&path_temp) {
        Ok(f) => f,
        Err(e) => {
            ag.log.error(fopen_error(&path_temp, e.raw_os_error().unwrap_or(0)));
            return Err(());
        }
    };
    let (notify_time, max_reconnect) = {
        let c = ag.cfg.read().unwrap();
        (c.notify_time, c.max_time_reconnect_try)
    };
    let last_keepalive = if st.last_keepalive != 0 { fmt_time(st.last_keepalive) } else { String::new() };
    let last_ack = if st.last_ack != 0 { fmt_time(st.last_ack) } else { String::new() };
    let mut out = format!(
        "# State file for {ARGV0}\n\
         \n\
         # Agent status:\n\
         # - pending:      waiting to get connected.\n\
         # - connected:    connection established with manager in the last {notify_time} seconds.\n\
         # - disconnected: connection lost or no ACK received in the last {max_reconnect} seconds.\n\
         status='{}'\n\
         \n\
         # Last time a keepalive was sent\n\
         last_keepalive='{last_keepalive}'\n\
         \n\
         # Last time a control message was received\n\
         last_ack='{last_ack}'\n\
         \n\
         # Number of generated events\n\
         msg_count='{}'\n\
         \n\
         # Number of messages (events + control messages) sent to the manager\n\
         msg_sent='{}'\n\
         \n\
         # Number of events currently buffered\n\
         # Empty if anti-flooding mechanism is disabled\n",
        str_status(st.status),
        st.msg_count,
        st.msg_sent
    );
    if buffered >= 0 {
        out.push_str(&format!("msg_buffer='{buffered}'\n"));
    } else {
        out.push_str("msg_buffer=''\n");
    }
    let _ = fp.write_all(out.as_bytes());
    drop(fp);
    if let Err(e) = std::fs::rename(&path_temp, &path) {
        ag.log.error(format!("Renaming {path_temp} to {path}: {}", strerror(e.raw_os_error().unwrap_or(0))));
        if let Err(e) = std::fs::remove_file(&path_temp) {
            ag.log.error(format!("Deleting {path_temp}: {}", strerror(e.raw_os_error().unwrap_or(0))));
        }
        return Err(());
    }
    Ok(())
}

/// `w_agentd_state_get`
pub fn state_get(ag: &Agentd) -> String {
    let st = ag.state.snapshot();
    let last_keepalive = if st.last_keepalive != 0 { fmt_time(st.last_keepalive) } else { String::new() };
    let last_ack = if st.last_ack != 0 { fmt_time(st.last_ack) } else { String::new() };
    let (mut buffered, mut enabled) = (crate::buffer::get_buffer_length(ag), true);
    if buffered < 0 {
        enabled = false;
        buffered = 0;
    }
    let mut data = Json::object();
    data.add("status", Json::string(str_status(st.status)));
    data.add("last_keepalive", Json::string(&last_keepalive));
    data.add("last_ack", Json::string(&last_ack));
    data.add("msg_count", Json::number(st.msg_count as f64));
    data.add("msg_sent", Json::number(st.msg_sent as f64));
    data.add("msg_buffer", Json::number(buffered as f64));
    data.add("buffer_enabled", Json::bool(enabled));
    let mut root = Json::object();
    root.add("error", Json::number(0.0));
    root.add("data", data);
    root.to_string_unformatted()
}
