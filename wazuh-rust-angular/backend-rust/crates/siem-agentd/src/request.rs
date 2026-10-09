//! `client-agent/request.c` and `shared/request_op.c`: requests from the
//! manager (`#!-req <counter> <target> <payload>`), forwarded to a local
//! component socket (or answered by agentd itself for `agent`), with
//! the UDP ACK / retransmission handshake.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use siem_ipc::os_net;

use crate::sendmsg::{send_msg, send_msg_len};
use crate::*;

/// `req_node_t`
pub struct ReqNode {
    sock: i32,
    counter: String,
    target: String,
    data: Mutex<NodeData>,
    available: Condvar,
}

struct NodeData {
    buffer: Vec<u8>,
    signaled: bool,
}

impl Drop for ReqNode {
    /// `req_free`
    fn drop(&mut self) {
        if self.sock >= 0 {
            // SAFETY: closing the node's own socket.
            unsafe { libc::close(self.sock) };
        }
    }
}

#[derive(Default)]
pub struct Requests {
    table: Mutex<HashMap<String, Arc<ReqNode>>>,
    pool: Mutex<VecDeque<Arc<ReqNode>>>,
    pool_available: Condvar,
}

/// `IS_ACK`
fn is_ack(x: &[u8]) -> bool {
    crate::keys::cstr(x) == b"ack"
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(crate::keys::cstr(b)).into_owned()
}

/// `snprintf(response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST ...)`
fn response(rest: &str) -> Vec<u8> {
    trunc_bytes(format!("{CONTROL_HEADER}{HC_REQUEST}{rest}").into_bytes(), REQ_RESPONSE_LENGTH)
}

/// `req_init`
pub fn req_init(ag: &Agentd) {
    let i = &ag.ints;
    i.request_pool.store(ag.define_int("remoted", "request_pool", 1, 4096), Ordering::SeqCst);
    i.rto_sec.store(ag.define_int("remoted", "request_rto_sec", 0, 60), Ordering::SeqCst);
    i.rto_msec.store(ag.define_int("remoted", "request_rto_msec", 0, 999), Ordering::SeqCst);
    i.max_attempts.store(ag.define_int("remoted", "max_attempts", 1, 16), Ordering::SeqCst);
}

/// `req_push(buffer, length)`
pub fn req_push(ag: &Agentd, buffer: &[u8]) -> i32 {
    let Some(sp) = buffer.iter().position(|&c| c == b' ') else {
        ag.log.error("Request format is incorrect [target].");
        ag.log.debug2(format!("buffer = \"{}\"", lossy(buffer)));
        return -1;
    };
    let counter = lossy(&buffer[..sp]);
    let target_raw = &buffer[sp + 1..];

    if is_ack(target_raw) {
        let t = ag.req.table.lock().unwrap();
        match t.get(&counter) {
            Some(node) => {
                // req_update(node, target, length)
                let mut d = node.data.lock().unwrap();
                d.buffer = target_raw.to_vec();
                d.signaled = true;
                node.available.notify_one();
            }
            None => ag.log.debug1(format!("Request counter ({counter}) not found. Duplicated ACK?")),
        }
        return 0;
    }

    let target_c = crate::keys::cstr(target_raw);
    let Some(sp2) = target_c.iter().position(|&c| c == b' ') else {
        ag.log.error("Request format is incorrect [payload].");
        ag.log.debug2(format!("target = \"{}\"", lossy(target_raw)));
        return -1;
    };
    let target = String::from_utf8_lossy(&target_c[..sp2]).into_owned();
    let payload = &target_raw[sp2 + 1..];

    let mut sock = -1;
    if target != "agent" {
        let sockname = format!("queue/sockets/{target}");
        sock = os_net::connect_unix_domain(&sockname, libc::SOCK_STREAM, os_net::OS_MAXSTR);
        if sock < 0 {
            let e = errno();
            if e == libc::ECONNREFUSED {
                ag.log.debug1(format!(
                    "At req_push(): Target '{target}' refused connection. The component might be disabled"
                ));
            } else {
                ag.log.debug1(format!(
                    "At req_push(): Could not connect to socket '{target}': {} ({e}).",
                    strerror(e)
                ));
            }
            send_msg(ag, &response(&format!("{counter} err {}", strerror(e))));
            return -1;
        }
    }

    if ag.is_udp() {
        ag.log.debug2(format!("req_push(): Sending ack ({counter})."));
        send_msg(ag, &response(&format!("{counter} ack")));
    }

    let node = Arc::new(ReqNode {
        sock,
        counter: counter.clone(),
        target,
        data: Mutex::new(NodeData { buffer: payload.to_vec(), signaled: false }),
        available: Condvar::new(),
    });
    {
        let mut t = ag.req.table.lock().unwrap();
        if t.contains_key(&counter) {
            drop(t);
            ag.log.debug1("Duplicated counter. RTO too short?");
            return 0;
        }
        t.insert(counter.clone(), node.clone());
    }
    let pool_size = ag.ints.request_pool.load(Ordering::SeqCst).max(1) as usize;
    let mut pool = ag.req.pool.lock().unwrap();
    // full(pool_i, pool_j, request_pool): the ring holds request_pool - 1 nodes
    if pool.len() + 1 >= pool_size {
        drop(pool);
        ag.log.error(format!("Too many requests. Rejecting counter {counter}."));
        ag.req.table.lock().unwrap().remove(&counter);
        send_msg(ag, &response(&format!("{counter} err Too many requests")));
        return -1;
    }
    pool.push_back(node);
    ag.req.pool_available.notify_one();
    0
}

/// `req_receiver` thread.
pub fn req_receiver(ag: &Agentd) {
    loop {
        let node = {
            let mut pool = ag.req.pool.lock().unwrap();
            loop {
                if let Some(n) = pool.pop_front() {
                    break n;
                }
                pool = ag.req.pool_available.wait(pool).unwrap();
            }
        };
        let mut d = node.data.lock().unwrap();

        let mut buffer: Vec<u8> = if node.target.starts_with("agent") {
            crate::agcom::agcom_dispatch(ag, crate::keys::cstr(&d.buffer))
        } else {
            ag.log.debug2(format!("req_receiver(): sending '{}' to socket", lossy(&d.buffer)));
            if os_net::send_secure_tcp(node.sock, &d.buffer) != 0 {
                ag.log.error(format!("OS_SendSecureTCP(): {}", strerror(errno())));
                b"err Send data".to_vec()
            } else {
                let mut out = Vec::new();
                match os_net::recv_secure_tcp(node.sock, &mut out, OS_MAXSTR as u32) {
                    -1 => {
                        ag.log.error(format!("recv(): {}", strerror(errno())));
                        b"err Receive data".to_vec()
                    }
                    0 => {
                        ag.log.debug1("Empty message from local client.");
                        b"err Empty response".to_vec()
                    }
                    r if r == os_net::OS_SOCKTERR as isize => {
                        ag.log.debug1("Maximum buffer length reached.");
                        b"err Maximum buffer length reached".to_vec()
                    }
                    _ => out,
                }
            }
        };
        if buffer.is_empty() {
            buffer = b"err Disconnected".to_vec();
        }

        let mut full = response(&format!("{} ", node.counter));
        full.extend_from_slice(&buffer);
        ag.log.debug2(format!("req_receiver(): sending '{}' to server", lossy(&full)));

        let max_attempts = ag.ints.max_attempts.load(Ordering::SeqCst);
        let mut attempts = 0;
        while attempts < max_attempts {
            if send_msg_len(ag, &full) != 0 {
                ag.log.error("Sending response to manager.");
                break;
            }
            if ag.is_udp() {
                let rto = Duration::from_secs(ag.ints.rto_sec.load(Ordering::SeqCst) as u64)
                    + Duration::from_millis(ag.ints.rto_msec.load(Ordering::SeqCst) as u64);
                d.signaled = false;
                let (g, _) = node.available.wait_timeout_while(d, rto, |x| !x.signaled).unwrap();
                d = g;
                if d.signaled && is_ack(&d.buffer) {
                    break;
                }
            } else {
                // TCP handles ACK by itself
                break;
            }
            ag.log.debug2("Timeout for waiting ACK from manager, resending.");
            attempts += 1;
        }
        if attempts == max_attempts {
            ag.log.error("Couldn't send response to manager: number of attempts exceeded.");
        }
        drop(d);
        ag.req.table.lock().unwrap().remove(&node.counter);
    }
}
