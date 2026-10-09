//! Blocking port of `shared/mq_op.c` (`StartMQ`, `MQReconnectPredicated`,
//! `SendMSG`) and `shared/wait_op.c` (the agent's global "wait" lock that
//! pauses senders while the manager is unreachable). Unix only.
//!
//! Paths are relative to the Wazuh home: the daemons `chdir` there at startup,
//! as the C daemons do.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::Duration;

use crate::mq::{format_msg, queues};
use crate::os_net::{self, errno, logger, strerror, OS_INVALID, OS_MAXSTR, OS_SOCKTERR};

/// `READ` (`defs.h`): bind the queue.
pub const READ: i16 = 1;
/// `WRITE` (`defs.h`): connect to the queue.
pub const WRITE: i16 = 2;
/// `INFINITE_OPENQ_ATTEMPTS`
pub const INFINITE_OPENQ_ATTEMPTS: i16 = 0;
/// `WAIT_FILE` (Unix)
pub const WAIT_FILE: &str = "queue/sockets/.wait";
/// `LOCK_LOOP`
const LOCK_LOOP: u64 = 5;

pub const FORMAT_ERROR: &str = "(1106): String not correctly formatted.";
pub const FIM_SHUTDOWN_DETECTED: &str = "(6220): Reconnection attempts terminated due to the shutdown of FIM.";
pub const WAITING_MSG: &str = "Process locked due to agent is offline. Waiting for connection...";
pub const WAITING_FREE: &str = "Agent is now online. Process unlocked, continuing...";

/// A shutdown predicate (`bool (*fn_ptr)()`).
pub type Predicate<'a> = &'a dyn Fn() -> bool;

fn debug1(msg: String) {
    if let Some(l) = logger() {
        l.debug1(msg);
    }
}

fn debug2(msg: String) {
    if let Some(l) = logger() {
        l.debug2(msg);
    }
}

fn connect_attempts(path: &str, n_attempts: i16, stop: Option<Predicate<'_>>) -> i32 {
    let mut sleep_time = 5u64;
    let mut attempt: i16 = 0;
    let rc = loop {
        let rc = os_net::connect_unix_domain(path, libc::SOCK_DGRAM, OS_MAXSTR + 256);
        if rc >= 0 {
            break rc;
        }
        let e = errno();
        if let Some(f) = stop {
            if f() {
                debug2(FIM_SHUTDOWN_DETECTED.to_string());
                return OS_INVALID;
            }
        }
        attempt = attempt.wrapping_add(1);
        debug1(format!("Can't connect to '{}': {} ({}). Attempt: {}", path, strerror(e), e, attempt));
        if n_attempts != INFINITE_OPENQ_ATTEMPTS && attempt == n_attempts {
            break rc;
        }
        sleep_time += 5;
        sleep(Duration::from_secs(sleep_time));
    };
    if rc < 0 {
        return OS_INVALID;
    }
    debug1(format!("Connected succesfully to '{}' after {} attempts", path, attempt));
    debug1(format!("(unix_domain) Maximum send buffer set to: '{}'.", os_net::get_socket_size(rc)));
    rc
}

/// `StartMQWithSpecificOwnerAndPerms`
pub fn start_mq_with_perms(path: &str, ty: i16, n_attempts: i16, uid: u32, gid: u32, mode: u32) -> i32 {
    if ty == READ {
        return os_net::bind_unix_domain_with_perms(path, libc::SOCK_DGRAM, OS_MAXSTR + 512, uid, gid, mode);
    }
    connect_attempts(path, n_attempts, None)
}

/// `StartMQ`
pub fn start_mq(path: &str, ty: i16, n_attempts: i16) -> i32 {
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    start_mq_with_perms(path, ty, n_attempts, uid, gid, 0o660)
}

/// `StartMQPredicated`
pub fn start_mq_predicated(path: &str, ty: i16, n_attempts: i16, stop: Predicate<'_>) -> i32 {
    if ty == READ {
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        return os_net::bind_unix_domain_with_perms(path, libc::SOCK_DGRAM, OS_MAXSTR + 512, uid, gid, 0o660);
    }
    connect_attempts(path, n_attempts, Some(stop))
}

/// `MQReconnectPredicated`: retries every 5 s until connected or `stop()`.
pub fn mq_reconnect_predicated(path: &str, stop: Predicate<'_>) -> i32 {
    let rc = loop {
        let rc = os_net::connect_unix_domain(path, libc::SOCK_DGRAM, OS_MAXSTR + 256);
        if rc >= 0 {
            break rc;
        }
        let e = errno();
        if stop() {
            return OS_INVALID;
        }
        debug1(format!("(1278): Unable to reconnect to '{}': {} ({}).", path, strerror(e), e));
        sleep(Duration::from_secs(5));
    };
    debug1(format!("(8300): Successfully reconnected to '{}'", path));
    debug1(format!("(unix_domain) Maximum send buffer set to: '{}'.", os_net::get_socket_size(rc)));
    rc
}

/// `static int reported` in `SendMSGAction`.
static REPORTED: AtomicBool = AtomicBool::new(false);

fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// `SendMSGAction`. Returns 0 (sent, dropped or busy) or -1 (queue
/// unavailable; on a socket error the queue is closed and must be reopened).
pub fn send_msg_action(queue: i32, message: &[u8], locmsg: &str, loc: u8) -> i32 {
    let message = cstr(message);
    let locmsg = locmsg.split('\0').next().unwrap_or("");
    let tmpstr = match format_msg(message, locmsg, loc) {
        Some(m) => m,
        None => {
            // keepalive locations are dropped silently; anything else is malformed.
            let keepalive = loc == queues::SECURE_MQ
                && message.len() >= 2
                && message[1] == b':'
                && message[2..].starts_with(b"keepalive");
            if !keepalive {
                if let Some(l) = logger() {
                    l.error(FORMAT_ERROR);
                }
            }
            return 0;
        }
    };

    if queue < 0 {
        return -1;
    }

    let rc = os_net::send_unix(queue, &tmpstr, tmpstr.len() + 1);
    if rc < 0 {
        if rc == OS_SOCKTERR {
            debug1("socketerr (not available).".to_string());
            unsafe { libc::close(queue) };
            return -1;
        }
        debug2("Socket busy, discarding message.".to_string());
        if !REPORTED.swap(true, Ordering::Relaxed) {
            if let Some(l) = logger() {
                l.warn("Socket busy, discarding message.");
            }
        }
    }
    0
}

/// `SendMSG`: waits while the agent is locked, then sends.
pub fn send_msg(queue: i32, message: &[u8], locmsg: &str, loc: u8) -> i32 {
    os_wait();
    send_msg_action(queue, message, locmsg, loc)
}

/// `SendMSGPredicated`
pub fn send_msg_predicated(queue: i32, message: &[u8], locmsg: &str, loc: u8, stop: Predicate<'_>) -> i32 {
    os_wait_predicate(stop);
    send_msg_action(queue, message, locmsg, loc)
}

// ---------------------------------------------------------------- wait_op.c

/// `static int __wait_lock`
static WAIT_LOCK: AtomicBool = AtomicBool::new(false);
/// `static atomic_int_t just_unlocked` in `os_wait_primitive`.
static JUST_UNLOCKED: AtomicBool = AtomicBool::new(false);

/// `os_setwait`: creates the global lock file (content `l`).
pub fn os_setwait() {
    WAIT_LOCK.store(true, Ordering::SeqCst);
    let _ = std::fs::write(WAIT_FILE, b"l");
}

/// `os_delwait`
pub fn os_delwait() {
    WAIT_LOCK.store(false, Ordering::SeqCst);
    let _ = std::fs::remove_file(WAIT_FILE);
}

fn wait_file_present() -> bool {
    // w_stat == 0
    std::fs::metadata(WAIT_FILE).is_ok()
}

fn os_wait_primitive(stop: Option<Predicate<'_>>) {
    if !wait_file_present() {
        JUST_UNLOCKED.store(true, Ordering::SeqCst);
        return;
    }
    let loud = JUST_UNLOCKED.load(Ordering::SeqCst);
    if let Some(l) = logger() {
        if loud {
            l.warn(WAITING_MSG);
        } else {
            l.debug1(WAITING_MSG);
        }
    }
    // loop_check
    loop {
        if !wait_file_present() || stop.map_or(false, |f| f()) {
            break;
        }
        sleep(Duration::from_secs(LOCK_LOOP));
    }
    let loud = JUST_UNLOCKED.load(Ordering::SeqCst);
    if let Some(l) = logger() {
        if loud {
            l.info(WAITING_FREE);
        } else {
            l.debug1(WAITING_FREE);
        }
    }
    JUST_UNLOCKED.store(true, Ordering::SeqCst);
}

/// `os_wait`: blocks while `queue/sockets/.wait` exists.
pub fn os_wait() {
    os_wait_primitive(None);
}

/// `os_wait_predicate`
pub fn os_wait_predicate(stop: Predicate<'_>) {
    os_wait_primitive(Some(stop));
}

/// `os_iswait`: the agent is disconnected from the manager.
pub fn os_iswait() -> bool {
    // IsFile(): a regular file
    std::fs::metadata(WAIT_FILE).map(|m| m.is_file()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_formats_like_c() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue");
        let p = path.to_str().unwrap();
        let rx = start_mq(p, READ, 0);
        assert!(rx >= 0);
        let tx = start_mq(p, WRITE, 1);
        assert!(tx >= 0);
        assert_eq!(send_msg_action(tx, b"hello", "wazuh-agent", queues::LOCALFILE_MQ), 0);
        assert_eq!(send_msg_action(tx, b"1:keepalive:x", "w", queues::SECURE_MQ), 0);
        assert_eq!(send_msg_action(tx, b"1:/var/log:m", "[001] (a) any", queues::SECURE_MQ), 0);
        let mut buf = Vec::new();
        os_net::recv_unix(rx, 70000, &mut buf);
        assert_eq!(cstr(&buf), b"1:wazuh-agent:hello");
        os_net::recv_unix(rx, 70000, &mut buf);
        assert_eq!(cstr(&buf), b"1:[001] (a) any->/var/log:m");
        assert_eq!(send_msg_action(-1, b"x", "y", queues::LOCALFILE_MQ), -1);
    }
}
