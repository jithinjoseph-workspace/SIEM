//! The output side of `logcollector.c` (`w_msg_hash_queues_*`,
//! `w_msg_queue_push/pop`, `w_output_thread`, `w_create_output_threads`)
//! and `SendMSGtoSCK` of `shared/mq_op.c`.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};

#[cfg(unix)]
use siem_config::socket::SocketMode;
use siem_ipc::mq_op::{self, start_mq, INFINITE_OPENQ_ATTEMPTS, WRITE};
#[cfg(unix)]
use siem_ipc::os_net;

use crate::*;

/// `w_message_t`
pub struct Message {
    pub file: String,
    pub buffer: Vec<u8>,
    pub queue_mq: u8,
    pub size: usize,
    pub log_target: LogTarget,
}

/// `w_msg_queue_t` (a `w_queue_t` of `size` slots holds `size - 1`).
pub struct MsgQueue {
    pub size: usize,
    q: Mutex<VecDeque<Message>>,
    available: Condvar,
}

/// `msg_queues_table`, keeping the insertion order for the output threads.
#[derive(Default)]
pub struct Queues {
    pub table: Mutex<Vec<(String, Arc<MsgQueue>)>>,
}

impl Queues {
    fn get(&self, name: &str) -> Option<Arc<MsgQueue>> {
        self.table.lock().unwrap().iter().find(|(n, _)| n == name).map(|(_, q)| Arc::clone(q))
    }
}

/// `w_msg_hash_queues_init`
pub fn hash_queues_init(lc: &Lc) {
    let v = lc.define_int("logcollector", "queue_size", OUTPUT_MIN_QUEUE_SIZE, 220000);
    lc.ints.output_queue_size.store(v, Ordering::SeqCst);
}

/// `w_msg_hash_queues_add_entry`
pub fn hash_queues_add_entry(lc: &Lc, key: &str) {
    let mut t = lc.queues.table.lock().unwrap();
    if t.iter().any(|(n, _)| n == key) {
        return;
    }
    let size = get(&lc.ints.output_queue_size).max(1) as usize;
    t.push((key.to_string(), Arc::new(MsgQueue { size, q: Mutex::new(VecDeque::new()), available: Condvar::new() })));
}

/// `w_msg_hash_queues_push(str, file, size, targets, queue_mq)`
pub fn push(lc: &Lc, s: &[u8], file: &str, size: usize, targets: &[LogTarget], queue_mq: u8) {
    crate::state::update_file(lc, file, size as u64);
    for t in targets {
        if let Some(q) = lc.queues.get(&t.socket.name) {
            if queue_push(lc, &q, s, file, size, t, queue_mq) < 0 {
                crate::state::update_target(lc, file, &t.socket.name, true);
            }
        }
    }
}

/// `w_msg_queue_push`: the message is `size` bytes of `buffer` (`memcpy`).
fn queue_push(lc: &Lc, q: &MsgQueue, buffer: &[u8], file: &str, size: usize, t: &LogTarget, queue_mq: u8) -> i32 {
    let mut b = vec![0u8; size];
    let n = size.min(buffer.len());
    b[..n].copy_from_slice(&buffer[..n]);
    let mut g = q.q.lock().unwrap();
    let result = if g.len() + 1 >= q.size {
        -1
    } else {
        g.push_back(Message { file: file.to_string(), buffer: b, queue_mq, size, log_target: t.clone() });
        q.available.notify_one();
        0
    };
    if result < 0 && !lc.reported_queue_full.swap(true, Ordering::SeqCst) {
        lc.log.warn(format!(
            "Target '{}' message queue is full ({}). Log lines may be lost.",
            t.socket.name, q.size
        ));
    }
    drop(g);
    if result < 0 {
        lc.log.debug2(format!("Discarding log line for target '{}'", t.socket.name));
    }
    result
}

fn queue_pop(q: &MsgQueue) -> Message {
    let mut g = q.q.lock().unwrap();
    loop {
        if let Some(m) = g.pop_front() {
            return m;
        }
        g = q.available.wait(g).unwrap();
    }
}

/// `SendMSGtoSCK` (Windows): no socket forwarding, every target goes to
/// the manager through `SendMSG` with its output format.
#[cfg(windows)]
pub fn send_msg_to_sck(lc: &Lc, queue: i32, message: &[u8], locmsg: &str, loc: u8, target: &LogTarget) -> i32 {
    let msg = crate::logbuilder::build(lc, target.format.as_deref(), message, locmsg.as_bytes());
    mq_op::send_msg(queue, &msg, locmsg, loc)
}

/// `SendMSGtoSCK`: 0 sent, 1 discarded, -1 error.
#[cfg(unix)]
pub fn send_msg_to_sck(lc: &Lc, queue: i32, message: &[u8], locmsg: &str, loc: u8, target: &LogTarget) -> i32 {
    let msg = crate::logbuilder::build(lc, target.format.as_deref(), message, locmsg.as_bytes());
    let sk = &target.socket;
    if sk.name == "agent" {
        if mq_op::send_msg(queue, &msg, locmsg, loc) != 0 {
            return -1;
        }
        return 0;
    }
    let (sock_type, strmode) = match sk.mode {
        SocketMode::Udp => (os_net::SOCK_DGRAM, "udp"),
        SocketMode::Tcp => (os_net::SOCK_STREAM, "tcp"),
    };
    // snprintf(tmpstr, OS_MAXSTR, "%s%s", prefix, msg)
    let mut tmp = sk.prefix.clone().unwrap_or_default().into_bytes();
    tmp.extend_from_slice(cstr(&msg));
    tmp.truncate(OS_MAXSTR - 1);
    let fail_time = get(&lc.ints.sock_fail_time) as i64;
    let mut conn = sk.conn.lock().unwrap();
    if conn.0 < 0 {
        let mtime = now();
        if mtime > conn.1 + fail_time {
            conn.0 = os_net::connect_unix_domain(&sk.location, sock_type, (OS_MAXSTR + 256) as i32);
            if conn.0 < 0 {
                conn.1 = mtime;
                lc.log.error(format!("Unable to connect to socket '{}': {} ({strmode})", sk.name, sk.location));
                return -1;
            }
            lc.log.debug1(format!("Connected to socket '{}' ({})", sk.name, sk.location));
        } else {
            lc.log.debug2(format!(
                "Discarding event from '{locmsg}' due to connection issue with '{}'",
                sk.name
            ));
            return 1;
        }
    }
    let mut retval = 0;
    let rc = os_net::send_unix(conn.0, &tmp, tmp.len());
    if rc < 0 {
        if rc == os_net::OS_SOCKTERR {
            let mtime = now();
            if mtime > conn.1 + fail_time {
                os_net::close_fd(conn.0);
                conn.0 = os_net::connect_unix_domain(&sk.location, sock_type, (OS_MAXSTR + 256) as i32);
                if conn.0 < 0 {
                    lc.log.error(format!("Unable to connect to socket '{}': {} ({strmode})", sk.name, sk.location));
                    conn.1 = mtime;
                } else {
                    lc.log.debug1(format!("Connected to socket '{}' ({})", sk.name, sk.location));
                    // C checks the previous return code here, so this always "fails"
                    os_net::send_unix(conn.0, &tmp, tmp.len());
                    lc.log.error(format!("Cannot send message to socket '{}'. (Retry)", sk.name));
                    mq_op::send_msg(queue, b"Cannot send message to socket.", "logcollector", LOCALFILE_MQ);
                    conn.1 = mtime;
                }
            } else {
                lc.log.debug2(format!(
                    "Discarding event from '{locmsg}' due to connection issue with '{}'",
                    sk.name
                ));
            }
        } else {
            lc.log.error(format!("Cannot send message to socket '{}'. (Retry)", sk.name));
            mq_op::send_msg(queue, b"Cannot send message to socket.", "logcollector", LOCALFILE_MQ);
        }
        retval = 1;
    }
    retval
}

/// `w_output_thread`
pub fn output_thread(lc: &Lc, queue_name: &str) {
    let Some(q) = lc.queues.get(queue_name) else {
        lc.log.warn(format!("Could not found the '{queue_name}'."));
        #[cfg(windows)]
        std::process::exit(1);
        #[cfg(unix)]
        return;
    };
    loop {
        let mut sleep_time = 5;
        let m = queue_pop(&q);
        let q_fd = lc.logr_queue.load(Ordering::SeqCst);
        if m.log_target.socket.name == "agent" {
            let mut result = send_msg_to_sck(lc, q_fd, &m.buffer, &m.file, m.queue_mq, &m.log_target);
            if result != 0 {
                if result != 1 {
                    lc.log.debug1(format!(
                        "Unable to send message to '{DEFAULTQUEUE}' (wazuh-agentd might be down). Attempting to reconnect."
                    ));
                }
                let nq = start_mq(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);
                lc.logr_queue.store(nq, Ordering::SeqCst);
                lc.log.info(format!("Successfully reconnected to '{DEFAULTQUEUE}'"));
                result = send_msg_to_sck(lc, nq, &m.buffer, &m.file, m.queue_mq, &m.log_target);
                if result != 0 {
                    if result != 1 {
                        lc.log.debug1(format!(
                            "Unable to send message to '{DEFAULTQUEUE}' after a successfull reconnection..."
                        ));
                    }
                    result = 1;
                }
            }
            crate::state::update_target(lc, &m.file, &m.log_target.socket.name, result == 1);
        } else {
            let mut retries = 0;
            let mut result = 1;
            while retries < 3 {
                result = send_msg_to_sck(lc, q_fd, &m.buffer, &m.file, m.queue_mq, &m.log_target);
                if result < 0 {
                    lc.log.debug1("(1224): Error sending message to queue.");
                    sleep_secs(sleep_time);
                    sleep_time += 5;
                    retries += 1;
                } else {
                    break;
                }
            }
            crate::state::update_target(lc, &m.file, &m.log_target.socket.name, result == 1);
            if retries == 3 {
                lc.log.error(format!(
                    "(1218): Unable to send message to '{}': {}",
                    m.log_target.socket.location,
                    String::from_utf8_lossy(cstr(&m.buffer))
                ));
            }
        }
    }
}
