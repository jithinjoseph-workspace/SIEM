//! `client-agent/receiver.c` (`receive_msg`): what the manager sends to
//! the agent. Active responses go to execd, FIM/syscollector sync messages
//! to their sockets, requests to the request module, `sca-dump` to the
//! SCA queue, and shared files (`up file` / `close file`) are written to
//! `etc/shared`, with `merged.mg` unmerged and the remote configuration
//! checked.

use std::io::Write;
use std::sync::atomic::Ordering;

use siem_ipc::mq_op::{os_delwait, os_setwait};
#[cfg(unix)]
use siem_ipc::mq_op::{start_mq, WRITE};
use siem_ipc::os_net;

use crate::sendmsg::send_msg;
use crate::start_agent::valid_header;
use crate::state::Update;
use crate::*;

/// The statics of receiver.c.
#[derive(Default)]
pub struct RecvState {
    fp: Option<siem_fileop::crt::TextFile>,
    file_sum: String,
    file: String,
    undefined_msg_logged: bool,
}

/// `ag_send_syscheck` (Windows): `syscom_dispatch(message, &response)`.
#[cfg(windows)]
pub fn ag_send_syscheck(ag: &Agentd, message: &[u8]) {
    if let Some(d) = ag.hooks.get().and_then(|h| h.find(b"syscheck")) {
        d(message);
    }
}

/// `wmcom_send` (Windows): `wmcom_sync(message)`.
#[cfg(windows)]
pub fn wmcom_send(ag: &Agentd, message: &[u8]) {
    if let Some(f) = ag.hooks.get().and_then(|h| h.wmcom_sync.as_ref()) {
        f(message);
    }
}

/// `ag_send_syscheck` (shared/syscheck_op.c)
#[cfg(unix)]
pub fn ag_send_syscheck(ag: &Agentd, message: &[u8]) {
    let sock = os_net::connect_unix_domain(SYS_LOCAL_SOCK, os_net::SOCK_STREAM, os_net::OS_MAXSTR);
    if sock < 0 {
        let e = errno();
        ag.log.warn(format!("dbsync: cannot connect to syscheck: {} ({e})", strerror(e)));
        return;
    }
    if os_net::send_secure_tcp(sock, message) < 0 {
        let e = errno();
        ag.log.warn(format!("Cannot send message to syscheck: {} ({e})", strerror(e)));
    }
    os_net::close_fd(sock);
}

/// `wmcom_send` (wazuh_modules/wmcom.c)
#[cfg(unix)]
pub fn wmcom_send(ag: &Agentd, message: &[u8]) {
    let sock = os_net::connect_unix_domain(WM_LOCAL_SOCK, os_net::SOCK_STREAM, os_net::OS_MAXSTR);
    if sock < 0 {
        let e = errno();
        if e == os_net::ECONNREFUSED {
            ag.log.debug1("Target wmodules refused connection. The component might be disabled");
        } else {
            ag.log.debug1(format!("Could not connect to socket wmodules: {} ({e}).", strerror(e)));
        }
        return;
    }
    os_net::send_secure_tcp(sock, message);
    os_net::close_fd(sock);
}

#[cfg(unix)]
fn sca_unavailable(ag: &Agentd) {
    ag.log.debug1("Unable to connect to the Security configuration assessment queue (disabled).");
    ag.cfgadq.store(-1, Ordering::SeqCst);
}

#[cfg(unix)]
fn sca_error(ag: &Agentd, q: i32) {
    ag.log.debug1("Error communicating with Security configuration assessment");
    os_net::close_fd(q);
}

/// The `sca-dump` branch of `receive_msg` (Windows):
/// `wm_sca_push_request_win(msg)`.
#[cfg(windows)]
fn send_sca(ag: &Agentd, msg: &[u8]) {
    if let Some(f) = ag.hooks.get().and_then(|h| h.sca_push.as_ref()) {
        f(msg);
    }
}

/// The `sca-dump` branch of `receive_msg`.
#[cfg(unix)]
fn send_sca(ag: &Agentd, msg: &[u8]) {
    let q = ag.cfgadq.load(Ordering::SeqCst);
    if q >= 0 {
        if os_net::send_unix(q, msg, 0) < 0 {
            sca_error(ag, q);
            let q = start_mq(CFGAQUEUE, WRITE, 1);
            if q < 0 {
                sca_unavailable(ag);
            } else {
                ag.cfgadq.store(q, Ordering::SeqCst);
                if os_net::send_unix(q, msg, 0) < 0 {
                    sca_error(ag, q);
                    ag.cfgadq.store(-1, Ordering::SeqCst);
                }
            }
        }
    } else {
        let q = start_mq(CFGAQUEUE, WRITE, 1);
        if q < 0 {
            sca_unavailable(ag);
        } else {
            ag.cfgadq.store(q, Ordering::SeqCst);
            if os_net::send_unix(q, msg, 0) < 0 {
                sca_error(ag, q);
                ag.cfgadq.store(-1, Ordering::SeqCst);
            }
        }
    }
}

/// `receive_msg`: -1 when the connection must be re-established.
pub fn receive_msg(ag: &Agentd) -> i32 {
    let mut reads = 0;
    loop {
        let sock = ag.sock();
        let mut buffer = vec![0u8; OS_MAXSTR + 1];
        let recv_b: isize = if !ag.is_udp() {
            // Only one read per call
            reads += 1;
            if reads > 1 {
                break;
            }
            let r = os_net::recv_secure_tcp(sock, &mut buffer, OS_MAXSTR as u32);
            if r <= 0 {
                let e = errno();
                if r == os_net::OS_SOCKTERR as isize {
                    ag.log.error("Corrupt payload (exceeding size) received.");
                } else if r == -1 {
                    #[cfg(unix)]
                    if e == os_net::ENOTCONN {
                        ag.log.debug1("Manager disconnected (ENOTCONN).");
                    } else {
                        ag.log.error(format!("Connection socket: {} ({e})", strerror(e)));
                    }
                    #[cfg(windows)]
                    {
                        let _ = e;
                        ag.log.error(format!("Connection socket: {} ({})", win_strerror_last(), os_net::wsa_errno()));
                    }
                } else if r == 0 {
                    ag.log.debug1("Manager disconnected.");
                }
                return -1;
            }
            r
        } else {
            let r = os_net::recv_flags(sock, &mut buffer[..OS_MAXSTR], true);
            if r <= 0 {
                break;
            }
            r
        };
        buffer.truncate(recv_b as usize);

        let Some(payload) = crate::keys::read_msg(ag, &buffer, &ag.current_server().rip) else {
            ag.log.warn(format!("(1214): Problem receiving message from '{}'.", ag.current_server().rip));
            continue;
        };
        handle_message(ag, &payload);
    }
    0
}

/// One decrypted message (the body of the `receive_msg` loop).
pub fn handle_message(ag: &Agentd, payload: &[u8]) {
    let tmp_msg = crate::keys::cstr(payload);
    ag.log.debug2(format!("Received message: '{}'", String::from_utf8_lossy(tmp_msg)));

    let Some(msg) = valid_header(tmp_msg) else {
        let mut st = ag.recv.lock().unwrap();
        if let Some(fp) = st.fp.as_mut() {
            let t = now();
            ag.available_server.store(t, Ordering::SeqCst);
            ag.state.update(Update::Ack(t));
            let _ = fp.write_all(tmp_msg);
        } else if !st.undefined_msg_logged {
            ag.log.warn("Unknown message received. No action defined.");
            st.undefined_msg_logged = true;
        }
        return;
    };

    ag.recv.lock().unwrap().undefined_msg_logged = false;
    let t = now();
    ag.available_server.store(t, Ordering::SeqCst);
    ag.state.update(Update::Ack(t));

    let starts = |p: &str| msg.starts_with(p.as_bytes());

    // Active response
    if starts(EXECD_HEADER) {
        let rest = &msg[EXECD_HEADER.len()..];
        let q = ag.execdq.load(Ordering::SeqCst);
        #[cfg(unix)]
        if q >= 0 && os_net::send_unix(q, rest, 0) < 0 {
            ag.log.debug1("Error communicating with execd");
        }
        // queue_push_ex(winexec_queue, strdup(tmp_msg))
        #[cfg(windows)]
        if q >= 0 {
            if let Some(f) = ag.hooks.get().and_then(|h| h.execd_push.as_ref()) {
                f(rest);
            }
        }
        return;
    }
    // Force reconnect
    if starts(HC_FORCE_RECONNECT) {
        ag.log.info("Wazuh Agent will be reconnected because a reconnect message was received");
        os_setwait();
        ag.state.update(Update::Status(AgentStatus::NActive));
        crate::start_agent::start_agent(ag, false);
        os_delwait();
        ag.state.update(Update::Status(AgentStatus::Active));
        return;
    }
    // Syscheck
    if starts(HC_SK)
        || starts(HC_FIM_FILE)
        || starts(HC_FIM_REGISTRY)
        || starts(HC_FIM_REGISTRY_KEY)
        || starts(HC_FIM_REGISTRY_VALUE)
    {
        ag_send_syscheck(ag, msg);
        return;
    }
    // Syscollector
    if starts(HC_SYSCOLLECTOR) {
        wmcom_send(ag, msg);
        return;
    }
    // Ack from server
    if msg == HC_ACK.as_bytes() {
        return;
    }
    // Request from manager (or request ack): IS_REQ
    if msg.len() > 3 && &msg[..3] == b"req" {
        // req_push(tmp_msg + strlen(HC_REQUEST), msg_length - strlen(HC_REQUEST) - 3)
        let start = CONTROL_HEADER.len() + HC_REQUEST.len();
        let body = payload.get(start..).unwrap_or(&[]);
        crate::request::req_push(ag, body);
        return;
    }
    // Security configuration assessment DB request
    if starts(CFGA_DB_DUMP) {
        send_sca(ag, msg);
        return;
    }

    let mut st = ag.recv.lock().unwrap();
    // Close any open file pointer if it was being written to
    st.fp = None;

    if starts(FILE_UPDATE_HEADER) {
        let rest = &msg[FILE_UPDATE_HEADER.len()..];
        let Some(sp) = rest.iter().position(|&c| c == b' ') else { return };
        let validate_file = String::from_utf8_lossy(&rest[sp..]).into_owned();
        if siem_fileop::ref_parent_folder(&validate_file) {
            ag.log.warn(format!(
                "Invalid file '{validate_file}', vulnerable to directory traversal attack. Ignoring."
            ));
            return;
        }
        // strncpy(file_sum, tmp_msg, 33)
        st.file_sum = String::from_utf8_lossy(&rest[..sp.min(33)]).into_owned();
        let mut name = rest[sp + 1..].to_vec();
        if let Some(nl) = name.iter().position(|&c| c == b'\n') {
            name.truncate(nl);
        }
        for c in name.iter_mut() {
            if *c == b'/' {
                *c = b'-';
            }
        }
        if name.first() == Some(&b'.') {
            name[0] = b'-';
        }
        let file = format!("{SHAREDCFG_DIR}/{}", String::from_utf8_lossy(&name));
        st.file = String::from_utf8_lossy(&trunc_bytes(file.into_bytes(), OS_SIZE_1024)).into_owned();
        match siem_fileop::crt::TextFile::create(&st.file) {
            Ok(f) => st.fp = Some(f),
            Err(e) => ag.log.error(fopen_error(&st.file, e.raw_os_error().unwrap_or(0))),
        }
        return;
    }

    if starts(FILE_CLOSE_HEADER) {
        if st.file.is_empty() {
            return;
        }
        let file = st.file.clone();
        match siem_fileop::md5_file(&file) {
            None => {
                let _ = std::fs::remove_file(&file);
                st.file.clear();
            }
            Some(md5) => {
                let sum = std::mem::take(&mut st.file_sum);
                st.file.clear();
                drop(st);
                if md5 != sum {
                    ag.log.debug1(format!("Failed md5 for: {file} -- deleting."));
                    let _ = std::fs::remove_file(&file);
                } else {
                    shared_file_received(ag, &file);
                }
            }
        }
        return;
    }

    ag.log.warn("Unknown message received from server.");
}

/// A shared file passed its checksum: unmerge `merged.mg` and apply it.
fn shared_file_received(ag: &Agentd, file: &str) {
    let Some(slash) = file.rfind('/') else {
        let _ = std::fs::remove_file(file);
        return;
    };
    if &file[slash + 1..] != SHAREDCFG_FILENAME {
        return;
    }
    let (ok, names) = siem_fileop::unmerge_files(file, Some(SHAREDCFG_DIR));
    if !ok {
        send_msg(ag, agent_event(AG_IN_UNMERGE).as_bytes());
        return;
    }
    let mut ignore: Vec<&str> = vec![SHAREDCFG_FILENAME];
    ignore.extend(names.iter().map(String::as_str));
    if siem_fileop::cldir_ex_ignore(SHAREDCFG_DIR, &ignore).is_err() {
        ag.log.warn("Could not clean up shared directory.");
    }
    crate::notify::clear_merged_hash_cache(ag);
    if ag.remote_conf_flag.load(Ordering::SeqCst) && crate::reload::verify_remote_conf(ag) == 0 {
        if ag.cfg.read().unwrap().auto_restart {
            ag.log.info("Agent is reloading due to shared configuration changes.");
            crate::reload::reload_agent(ag);
        } else {
            ag.log.info("Shared agent configuration has been updated.");
        }
    }
}
