//! `client-agent/start_agent.c`: connecting to a manager, the startup
//! handshake (`#!-agent startup` / `#!-agent ack`), server failover, key
//! initialisation (with auto-enrollment) and the start/stop messages.

use std::sync::atomic::Ordering;

use siem_config::client::{IPPROTO_UDP, W_METH_AES, W_METH_BLOWFISH};
use siem_ipc::os_net;

use crate::sendmsg::send_msg;
use crate::*;

/// `ENROLLMENT_RETRY_TIME_MAX` / `ENROLLMENT_RETRY_TIME_DELTA`
const ENROLLMENT_RETRY_TIME_MAX: i64 = 60;
const ENROLLMENT_RETRY_TIME_DELTA: i64 = 5;

fn proto_str(p: i32) -> &'static str {
    if p == IPPROTO_UDP {
        "udp"
    } else {
        "tcp"
    }
}

/// `'%.*s'` of a server address without its trailing '/'.
fn rip_shown(rip: &str) -> &str {
    rip.strip_suffix('/').unwrap_or(rip)
}

/// `connect_server(server_id, verbose)`
pub fn connect_server(ag: &Agentd, server_id: usize, verbose: bool) -> bool {
    let timeout = ag.define_int("agent", "recv_timeout", 1, 600);
    ag.ints.timeout.store(timeout, Ordering::SeqCst);

    let sock = ag.sock();
    if sock >= 0 {
        os_net::close_socket(sock);
        ag.sock.store(-1, Ordering::SeqCst);
        if let Some(s) = ag.server(ag.rip_id()) {
            if verbose {
                ag.log.info(format!("Closing connection to server ([{}]:{}/{}).", s.rip, s.port, proto_str(s.protocol)));
            }
        }
    }

    let Some(server) = ag.server(server_id) else { return false };
    let ip_address = match server.rip.find('/') {
        // server address comes in {hostname}/{ip} format
        Some(p) => Some(server.rip[p + 1..].to_string()),
        None => os_net::get_host(&server.rip, 3),
    };
    let ip_address = match ip_address {
        Some(ip) if !ip.is_empty() => ip,
        _ => {
            ag.log.info(format!("Could not resolve hostname '{}'", rip_shown(&server.rip)));
            return false;
        }
    };

    if verbose {
        ag.log.info(format!(
            "Trying to connect to server ([{}]:{}/{}).",
            server.rip,
            server.port,
            proto_str(server.protocol)
        ));
    }

    let ipv6 = ip_address.contains(':');
    let s = if server.protocol == IPPROTO_UDP {
        os_net::connect_udp(server.port as u16, &ip_address, ipv6, server.network_interface)
    } else {
        os_net::connect_tcp(server.port as u16, &ip_address, ipv6, server.network_interface)
    };
    if s < 0 {
        let e = errno();
        ag.sock.store(-1, Ordering::SeqCst);
        if verbose {
            ag.log.error(format!(
                "(1216): Unable to connect to '[{}]:{}/{}': '{}'.",
                ip_address,
                server.port,
                proto_str(server.protocol),
                strerror(e)
            ));
        }
        return false;
    }
    ag.sock.store(s, Ordering::SeqCst);
    ag.rip_id.store(server_id, Ordering::SeqCst);
    ag.last_connection_time.store(now(), Ordering::SeqCst);
    true
}

/// `start_agent(is_startup)`: block until a manager acknowledges us.
pub fn start_agent(ag: &Agentd, is_startup: bool) {
    if is_startup {
        keys_init(ag);
    }
    let mut current = ag.rip_id();
    loop {
        let server = ag.server(current).unwrap_or_default();
        for _ in 0..(server.max_retries - 1).max(0) {
            if handshake_to_server(ag, current, is_startup) {
                return;
            }
            sleep_secs(server.retry_interval as i64);
        }
        // Last attempt
        if handshake_to_server(ag, current, is_startup) {
            return;
        }
        // Try to enroll and extra attempt
        if ag.cfg.read().unwrap().enrollment.enabled
            && try_enroll_to_server(ag, &server.rip, server.network_interface) == 0
            && handshake_to_server(ag, current, is_startup)
        {
            return;
        }
        sleep_secs(server.retry_interval as i64);
        ag.log.warn(format!(
            "(4101): Waiting for server reply (not started). Tried: '{}'. Ensure that the manager version is '{}' or higher.",
            server.rip, OSSEC_VERSION
        ));
        if let Some(next) = ag.server(current + 1) {
            current += 1;
            ag.log.info(format!("Trying next server ip in the line: '{}'.", next.rip));
        } else {
            current = 0;
            ag.log.warn("Unable to connect to any server.");
        }
    }
}

/// `w_agentd_keys_init`
fn keys_init(ag: &Agentd) {
    if ag.keys.lock().unwrap().keysize() == 0 {
        let (enabled, manager_name, iface) = {
            let c = ag.cfg.read().unwrap();
            (c.enrollment.enabled, c.enrollment.target.manager_name.clone(), c.enrollment.target.network_interface)
        };
        if !enabled {
            ag.exit_critical(AG_NOKEYS_EXIT);
        }
        let mut registration_status = -1;
        let mut delay_sleep: i64 = 0;
        while registration_status != 0 {
            if let Some(m) = &manager_name {
                registration_status = try_enroll_to_server(ag, m, iface);
            }
            let mut rc = 0;
            while registration_status != 0 {
                let Some(s) = ag.server(rc) else { break };
                registration_status = try_enroll_to_server(ag, &s.rip, s.network_interface);
                rc += 1;
            }
            if registration_status != 0 {
                if delay_sleep < ENROLLMENT_RETRY_TIME_MAX {
                    delay_sleep += ENROLLMENT_RETRY_TIME_DELTA;
                }
                ag.log.debug1(format!("Sleeping {delay_sleep} seconds before trying to enroll again"));
                sleep_secs(delay_sleep);
            }
        }
    } else {
        // When the key store was empty, enrollment already started the counters.
        crate::keys::start_counter(ag);
    }

    let (name, id) = {
        let k = ag.keys.lock().unwrap();
        let e = k.entry.as_ref().expect("agent key");
        (e.name.clone(), e.id.clone())
    };
    let (profile, method) = {
        let c = ag.cfg.read().unwrap();
        (c.profile.clone(), c.crypto_method)
    };
    crate::keys::write_agent_info(ag, &name, &id, profile.as_deref());
    crate::keys::set_crypto_method(ag, method);
    match method {
        W_METH_AES => ag.log.info("Using AES as encryption method."),
        W_METH_BLOWFISH => ag.log.info("Using Blowfish as encryption method."),
        _ => ag.log.error("Invalid encryption method."),
    }
}

/// `receive_message`: the reply of the manager, or `None` on timeout/error.
fn receive_message(ag: &Agentd, max_length: usize) -> Option<Vec<u8>> {
    let sock = ag.sock();
    let timeout = ag.ints.timeout.load(Ordering::SeqCst) as i64;
    match os_net::wnet_select(sock, timeout) {
        -1 => {
            ag.log.error(select_error(errno()));
            None
        }
        0 => None,
        _ => {
            let mut buf = vec![0u8; max_length];
            let recv_b: isize = if ag.is_udp() {
                // SAFETY: recv into a buffer of max_length bytes.
                unsafe { libc::recv(sock, buf.as_mut_ptr().cast(), max_length, libc::MSG_DONTWAIT) }
            } else {
                os_net::recv_secure_tcp(sock, &mut buf, max_length as u32)
            };
            if recv_b > 0 {
                buf.truncate(recv_b as usize);
                return Some(buf);
            }
            let e = errno();
            if recv_b == os_net::OS_SOCKTERR as isize {
                ag.log.error("Corrupt payload (exceeding size) received.");
            } else if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                ag.log.info("Unable to receive start response: Timeout reached");
            } else {
                ag.log.debug1(format!("Connection socket: {} ({e})", strerror(e)));
            }
            None
        }
    }
}

/// `try_enroll_to_server`
pub fn try_enroll_to_server(ag: &Agentd, server_rip: &str, network_interface: u32) -> i32 {
    let r = crate::enrollment::request_key(ag, server_rip, network_interface);
    if r == 0 {
        let delay = ag.cfg.read().unwrap().enrollment.delay_after_enrollment;
        ag.log.info(format!("Waiting {delay} seconds before server connection"));
        sleep_secs(delay);
        crate::keys::update_keys(ag);
        let method = ag.cfg.read().unwrap().crypto_method;
        crate::keys::set_crypto_method(ag, method);
    }
    r
}

/// `IsValidHeader`: the message after `#!-`.
pub fn valid_header(m: &[u8]) -> Option<&[u8]> {
    m.strip_prefix(CONTROL_HEADER.as_bytes())
}

/// `agent_handshake_to_server`
pub fn handshake_to_server(ag: &Agentd, server_id: usize, is_startup: bool) -> bool {
    let mut info = siem_cjson::Json::object();
    info.add("version", siem_cjson::Json::string(OSSEC_VERSION));
    let msg = format!("{CONTROL_HEADER}{HC_STARTUP}{}", info.to_string_unformatted());

    if !connect_server(ag, server_id, true) {
        return false;
    }
    let server = ag.server(server_id).unwrap_or_default();
    send_msg(ag, msg.as_bytes());
    let Some(buffer) = receive_message(ag, OS_MAXSTR) else { return false };
    let Some(payload) = crate::keys::read_msg(ag, &buffer) else {
        ag.log.warn(format!("(1214): Problem receiving message from '{}'.", server.rip));
        return false;
    };
    let tmp = crate::keys::cstr(&payload);
    let Some(tmp) = valid_header(tmp) else { return false };
    if tmp == HC_ACK.as_bytes() {
        ag.available_server.store(now(), Ordering::SeqCst);
        ag.log.info(format!(
            "(4102): Connected to the server ([{}]:{}/{}).",
            server.rip,
            server.port,
            proto_str(server.protocol)
        ));
        if is_startup {
            send_msg_on_startup(ag);
        }
        return true;
    }
    if tmp.starts_with(HC_ERROR.as_bytes()) {
        let parsed = tmp.iter().position(|&c| c == b'{').and_then(|p| siem_cjson::parse(&tmp[p..]));
        match parsed.as_ref().and_then(|j| j.get("message")).filter(|m| m.is_string()) {
            Some(m) => ag.log.warn(format!(
                "Couldn't connect to server '{}': '{}'",
                server.rip,
                m.as_str().unwrap_or_default()
            )),
            None => ag.log.error(format!("Error getting message from server '{}'", server.rip)),
        }
    }
    false
}

/// `send_msg_on_startup`
fn send_msg_on_startup(ag: &Agentd) {
    let (name, ip) = {
        let k = ag.keys.lock().unwrap();
        let e = k.entry.as_ref().expect("agent key");
        (e.name.clone(), e.ip.clone())
    };
    let msg = format!("ossec: Agent started: '{name}->{ip}'.");
    send_msg(ag, agent_event(&msg).as_bytes());
}

/// `send_agent_stopped_message`
pub fn send_agent_stopped_message(ag: &Agentd) {
    // snprintf(msg, OS_SIZE_32, ...)
    let msg = format!("{CONTROL_HEADER}{HC_SHUTDOWN}");
    send_msg(ag, &msg.as_bytes()[..msg.len().min(31)]);
}
