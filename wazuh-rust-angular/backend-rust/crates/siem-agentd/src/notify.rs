//! `client-agent/notify.c`: the periodic keep-alive (`run_notify`), the
//! server-unavailable and force-reconnect checks, the `merged.mg` hash
//! cache and the agent IP label.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use siem_ipc::mq_op::{os_delwait, os_setwait};
use siem_ipc::os_net;

use crate::sendmsg::send_msg;
use crate::state::Update;
use crate::*;

/// The statics of notify.c.
#[derive(Default)]
pub struct NotifyState {
    /// `g_shared_mg_file_hash`
    shared_hash: Option<String>,
    /// `g_saved_time`
    saved_time: i64,
    /// `tmp_labels` / `last_labels_ptr`
    tmp_labels: String,
    last_labels_ptr: usize,
    /// `agent_ip` / `last_update`
    agent_ip: String,
    last_update: i64,
}

/// `getsharedfiles`
pub fn getsharedfiles() -> String {
    let md5 = siem_fileop::md5_file(SHAREDCFG_FILE).unwrap_or_else(|| "x".to_string());
    format!("{md5} merged.mg\n")
}

/// `get_agent_ip`: the local address of the manager connection.
pub fn get_agent_ip(ag: &Agentd) -> String {
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: valid sockaddr_storage buffer and length.
    let err = unsafe { libc::getsockname(ag.sock(), (&mut ss as *mut libc::sockaddr_storage).cast(), &mut len) };
    if err != 0 {
        ag.log.debug2(format!("getsockname() failed: {}", strerror(errno())));
        return String::new();
    }
    match ss.ss_family as i32 {
        libc::AF_INET => {
            // SAFETY: the family says this is a sockaddr_in.
            let a: libc::sockaddr_in = unsafe { std::ptr::read((&ss as *const libc::sockaddr_storage).cast()) };
            os_net::get_ipv4_string(a.sin_addr, IPSIZE).unwrap_or_default()
        }
        libc::AF_INET6 => {
            // SAFETY: the family says this is a sockaddr_in6.
            let a: libc::sockaddr_in6 = unsafe { std::ptr::read((&ss as *const libc::sockaddr_storage).cast()) };
            os_net::get_ipv6_string(a.sin6_addr, IPSIZE).unwrap_or_default()
        }
        f => {
            ag.log.debug2(format!("Unknown address family: {f}"));
            String::new()
        }
    }
}

/// `clear_merged_hash_cache`
pub fn clear_merged_hash_cache(ag: &Agentd) {
    ag.notify.lock().unwrap().shared_hash = None;
}

/// Reconnect under the global lock (`os_setwait` ... `os_delwait`).
fn reconnect(ag: &Agentd, server_up: bool) {
    os_setwait();
    ag.state.update(Update::Status(AgentStatus::NActive));
    crate::start_agent::start_agent(ag, false);
    if server_up {
        ag.log.info(SERVER_UP);
    }
    os_delwait();
    ag.state.update(Update::Status(AgentStatus::Active));
}

/// `run_notify`
pub fn run_notify(ag: &Agentd) {
    let mono_now = monotonic();
    let curr_time = now();
    {
        let mut n = ag.notify.lock().unwrap();
        if n.saved_time == 0 {
            n.saved_time = mono_now;
        }
    }
    let (max_reconnect, force_interval, notify_time, ip_interval) = {
        let c = ag.cfg.read().unwrap();
        (c.max_time_reconnect_try as i64, c.force_reconnect_interval, c.notify_time as i64, c.main_ip_update_interval as i64)
    };

    if curr_time - ag.available_server.load(Ordering::SeqCst) > max_reconnect {
        ag.log.warn(SERVER_UNAV);
        reconnect(ag, true);
    }

    if force_interval != 0 && curr_time - ag.last_connection_time.load(Ordering::SeqCst) >= force_interval {
        ag.log.info("Wazuh Agent will be reconnected because of force reconnect interval");
        reconnect(ag, false);
    }

    let mut n = ag.notify.lock().unwrap();
    if mono_now - n.saved_time < notify_time {
        return;
    }
    n.saved_time = mono_now;
    ag.log.debug1("Sending agent notification.");

    let uname = siem_fileop::version_op::getuname();

    let labels = ag.labels.read().unwrap().clone();
    let ptr = Arc::as_ptr(&labels) as usize;
    if ptr != n.last_labels_ptr {
        let (text, ok) = siem_config::labels::labels_format(&labels, OS_MAXSTR - OS_SIZE_2048);
        n.tmp_labels = text;
        if !ok {
            ag.log.warn("Too large labeled data. Not all labels will be shown in the keep-alive messages.");
        }
        n.last_labels_ptr = ptr;
    }

    if n.shared_hash.is_none() {
        n.shared_hash = Some(getsharedfiles());
    } else if let Err(e) = std::fs::metadata(SHAREDCFG_FILE) {
        if e.kind() == std::io::ErrorKind::NotFound {
            n.shared_hash = None;
        }
    }

    if mono_now - n.last_update >= ip_interval {
        n.last_update = mono_now;
        let ip = get_agent_ip(ag);
        n.agent_ip = ip.chars().take(IPSIZE).collect();
    }

    let hash = n.shared_hash.clone().unwrap_or_else(|| "x merged.mg\n".to_string());
    let agent_md5 = agent_conf_md5();
    let mut msg = format!("{CONTROL_HEADER}{uname}");
    if let Some(md5) = &agent_md5 {
        msg.push_str(&format!(" / {md5}"));
    }
    msg.push('\n');
    msg.push_str(&n.tmp_labels);
    msg.push_str(&hash);
    if !n.agent_ip.is_empty() {
        // snprintf(label_ip, 60, ...)
        let mut label_ip = format!("#\"_agent_ip\":{}", n.agent_ip);
        label_ip.truncate(59);
        msg.push_str(&label_ip);
    }
    msg.push('\n');
    drop(n);

    // snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, ...)
    let msg = trunc_bytes(msg.into_bytes(), OS_MAXSTR - OS_HEADER_SIZE);
    ag.log.debug2(format!("Sending keep alive: {}", String::from_utf8_lossy(&msg)));
    send_msg(ag, &msg);
    ag.state.update(Update::Keepalive(curr_time));
}

/// `File_DateofChange(AGENTCONFIG) > 0 && OS_MD5_File(AGENTCONFIG) == 0`
fn agent_conf_md5() -> Option<String> {
    let m = std::fs::metadata(AGENTCONFIG).ok()?;
    let mtime = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    if mtime == 0 {
        return None;
    }
    siem_fileop::md5_file(AGENTCONFIG)
}
