//! `client-agent/sendmsg.c` (`send_msg`) and `event-forward.c`
//! (`EventForward`).

use siem_ipc::os_net;

use crate::state::Update;
use crate::*;

/// `send_msg(msg, -1)`: encrypt and send one message (up to its first NUL)
/// to the manager. Returns 0 on success (the C `retval`).
pub fn send_msg(ag: &Agentd, msg: &[u8]) -> i32 {
    send_msg_len(ag, crate::keys::cstr(msg))
}

/// `send_msg(msg, length)`
pub fn send_msg_len(ag: &Agentd, msg: &[u8]) -> i32 {
    let Some(crypt) = crate::keys::create_msg(ag, msg) else {
        ag.log.error(SEC_ERROR);
        return -1;
    };
    let sock = ag.sock();
    let (retval, error) = if ag.is_udp() {
        let r = os_net::send_udp_by_size(sock, &crypt);
        (r, errno())
    } else {
        let _g = ag.send_mutex.lock().unwrap();
        let r = os_net::send_secure_tcp(sock, &crypt);
        (r, errno())
    };
    if retval == 0 {
        ag.state.update(Update::IncrementMsgSend);
    } else {
        match error {
            libc::EPIPE => ag.log.debug2(TCP_EPIPE),
            libc::ECONNREFUSED => ag.log.debug2(CONN_REF),
            e => ag.log.warn(format!("(1218): Unable to send message to 'server': {}", strerror(e))),
        }
        sleep_secs(1);
    }
    retval
}

/// `EventForward`: drain the local queue into the buffer (or straight to
/// the manager when the buffer is disabled).
pub fn event_forward(ag: &Agentd) {
    let q = ag.m_queue.load(std::sync::atomic::Ordering::SeqCst);
    let mut msg = vec![0u8; OS_MAXSTR + 1];
    loop {
        // SAFETY: recv into a buffer of OS_MAXSTR + 1 bytes.
        let r = unsafe { libc::recv(q, msg.as_mut_ptr().cast(), OS_MAXSTR, libc::MSG_DONTWAIT) };
        if r <= 0 {
            break;
        }
        let m = crate::keys::cstr(&msg[..r as usize]).to_vec();
        if ag.buffer_enabled() {
            if crate::buffer::buffer_append(ag, &m) < 0 {
                break;
            }
        } else {
            ag.state.update(Update::IncrementMsgCount);
            if send_msg(ag, &m) < 0 {
                break;
            }
        }
    }
}
