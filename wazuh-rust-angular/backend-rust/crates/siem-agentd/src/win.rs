//! The agentd parts of `win32/win_utils.c` (`SendMSGAction` for Windows,
//! where events go straight to the buffer or the manager under `hMutex`)
//! and `client-agent/receiver.c` (`receiver_messages`, the main loop of
//! `wazuh-agent.exe`).

use std::sync::atomic::Ordering;
use std::sync::Mutex;

use siem_ipc::os_net;

use crate::state::Update;
use crate::*;

/// `hMutex`
static H_MUTEX: Mutex<()> = Mutex::new(());

/// `OS_SIZE_8192 + 1`: the escaped location buffer.
const LOC_BUFF_SIZE: usize = 8192 + 1;

/// `SendMSGAction` for Windows: `"<loc>:<escaped location>:<message>"`
/// (at most `OS_MAXSTR - 1` bytes) into the buffer, or to the manager when
/// the buffer is disabled. 0, or -1 when the manager send failed.
pub fn send_msg_action(ag: &Agentd, message: &[u8], locmsg: &str, loc: u8) -> i32 {
    let _g = H_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let loc_buff = siem_ipc::mq::wstr_escape(locmsg.as_bytes(), b'|', b':', LOC_BUFF_SIZE);
    // snprintf(tmpstr, OS_MAXSTR, "%c:%s:%s", loc, loc_buff, message)
    let mut tmpstr = vec![loc, b':'];
    tmpstr.extend_from_slice(crate::keys::cstr(&loc_buff));
    tmpstr.push(b':');
    tmpstr.extend_from_slice(crate::keys::cstr(message));
    tmpstr.truncate(OS_MAXSTR - 1);
    if !ag.buffer_enabled() {
        ag.state.update(Update::IncrementMsgCount);
        if crate::sendmsg::send_msg(ag, &tmpstr) >= 0 {
            0
        } else {
            -1
        }
    } else {
        crate::buffer::buffer_append(ag, &tmpstr);
        0
    }
}

/// `receiver_messages`: run the timed responses, the keep-alive and the
/// messages from the manager, reconnecting when the connection is lost.
pub fn receiver_messages(ag: &Agentd) -> ! {
    loop {
        // Run timeout commands
        if ag.execdq.load(Ordering::SeqCst) >= 0 {
            if let Some(f) = ag.hooks.get().and_then(|h| h.execd_timeout_run.as_ref()) {
                f();
            }
        }
        // sock must be set
        let sock = ag.sock();
        if sock == -1 {
            sleep_secs(5);
            continue;
        }
        crate::notify::run_notify(ag);
        // Wait for 1 second
        let rc = os_net::select_read(ag.sock(), 1, 0);
        if rc == -1 {
            let e = os_net::wsa_errno();
            ag.log.error(format!("(1114): Error during select()-call due to [({e})-({})].", os_net::win_strerror(e as u32)));
            sleep_secs(30);
            continue;
        } else if rc == 0 {
            continue;
        }
        if crate::receiver::receive_msg(ag) < 0 {
            ag.state.update(Update::Status(AgentStatus::NActive));
            ag.log.error(LOST_ERROR);
            siem_ipc::mq_op::os_setwait();
            crate::start_agent::start_agent(ag, false);
            ag.log.info(SERVER_UP);
            siem_ipc::mq_op::os_delwait();
            ag.state.update(Update::Status(AgentStatus::Active));
        }
    }
}
