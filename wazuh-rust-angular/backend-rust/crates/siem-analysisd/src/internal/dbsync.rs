//! Database synchronization dispatcher (analysisd/decoders/dbsync.c): agent
//! `dbsync` messages are turned into wazuh-db queries; integrity check
//! answers are sent back to the agent (through remoted) or to the local
//! syscheck / wazuh-modules socket.

use siem_cjson::Json;

use crate::daemon::Env;

const OS_MAXSTR: usize = 65536;
/// `SYS_LOCAL_SOCK`
pub const SYS_LOCAL_SOCK: &str = "queue/sockets/syscheck";
/// `WM_LOCAL_SOCK`
pub const WM_LOCAL_SOCK: &str = "queue/sockets/wmodules";

/// `WDBC_VALID_COMPONENTS`
const VALID_COMPONENTS: &[&[u8]] = &[
    b"syscollector_processes",
    b"syscollector_packages",
    b"syscollector_hotfixes",
    b"syscollector_ports",
    b"syscollector_network_protocol",
    b"syscollector_network_address",
    b"syscollector_network_iface",
    b"syscollector_hwinfo",
    b"syscollector_osinfo",
    b"syscollector_users",
    b"syscollector_groups",
    b"syscollector_browser_extensions",
    b"syscollector_services",
    b"syscheck",
    b"fim_file",
    b"fim_registry",
    b"fim_registry_key",
    b"fim_registry_value",
];

fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `dispatch_send_local`
fn send_local(env: &mut dyn Env, component: &[u8], query: &[u8]) {
    let path = if component.starts_with(b"syscheck") || component.starts_with(b"fim_file") {
        SYS_LOCAL_SOCK
    } else if component.starts_with(b"syscollector") {
        WM_LOCAL_SOCK
    } else {
        env.log("ERROR", &cat(&[b"dbsync: unknown location '", component, b"'"]));
        return;
    };
    let request = cat(&[component, b" ", query]);
    if let Err((n, t)) = env.send_local(path, &request) {
        env.log("ERROR", &cat(&[b"dbsync: cannot connect to ", component, format!(": {t} ({n})").as_bytes()]));
    }
}

/// `dispatch_send_remote` + `send_msg_to_agent(sock, buffer, agent_id, NULL)`
fn send_remote(env: &mut dyn Env, component: &[u8], agent: &[u8], query: &[u8]) {
    let mut buffer = cat(&[component, b" ", query]);
    buffer.truncate(OS_MAXSTR - 1);
    let mut msg = cat(&[b"(msg_to_agent) [] N!S ", agent, b" ", &buffer]);
    msg.truncate(OS_MAXSTR - 1);
    env.ar().send_ar(&msg);
}

/// `dispatch_answer`
fn answer(env: &mut dyn Env, component: &[u8], agent: &[u8], data: &mut Json, result: &[u8]) {
    data.remove("tail");
    data.remove("checksum");
    let plain = data.print_unformatted();
    let query = cat(&[b"dbsync ", result, b" ", &plain]);
    if query.len() >= OS_MAXSTR {
        env.log("ERROR", b"dbsync: Cannot build query for agent: query is too long.");
        return;
    }
    if agent == b"000" {
        send_local(env, component, &query);
    } else {
        send_remote(env, component, agent, &query);
    }
}

/// The query / reply part shared by `dispatch_check`, `dispatch_state` and
/// `dispatch_clear`: the reply payload of an `ok` answer.
fn query(env: &mut dyn Env, q: Vec<u8>, too_long: &[u8]) -> Option<Vec<u8>> {
    if q.len() >= OS_MAXSTR {
        env.log("ERROR", too_long);
        return None;
    }
    let response = match env.wdb_query_ex(&q, OS_MAXSTR) {
        Ok(r) => r,
        Err(-2) => {
            env.log("ERROR", b"dbsync: Cannot communicate with database.");
            return None;
        }
        Err(_) => {
            env.log("ERROR", b"dbsync: Cannot get response from database.");
            return None;
        }
    };
    // wdbc_parse_result
    let (head, arg) = match response.iter().position(|&c| c == b' ') {
        Some(p) => (&response[..p], &response[p + 1..]),
        None => (&response[..], &response[..]),
    };
    match head {
        b"ok" => Some(arg.to_vec()),
        b"err" => {
            if arg != b"Agent not found" {
                env.log("ERROR", &cat(&[b"dbsync: Bad response from database: ", arg]));
            }
            None
        }
        _ => None,
    }
}

/// `DispatchDBSync`
pub fn dispatch(env: &mut dyn Env, agent: &[u8], log: &[u8]) {
    let Ok((mut root, _)) = siem_cjson::parse_with_opts(log, false) else {
        env.log("ERROR", &cat(&[b"dbsync: Cannot parse JSON: ", log]));
        return;
    };
    let component = match root.get("component") {
        Some(Json::String(s)) => cstr(s).to_vec(),
        _ => {
            env.log("ERROR", b"dbsync: Corrupt message: cannot get component member.");
            return;
        }
    };
    let mtype = match root.get("type") {
        Some(Json::String(s)) => cstr(s).to_vec(),
        _ => {
            env.log("ERROR", b"dbsync: Corrupt message: cannot get type member.");
            return;
        }
    };
    if !VALID_COMPONENTS.contains(&&component[..]) {
        env.log("ERROR", b"dbsync: Invalid component specified.");
        return;
    }
    let is_check = mtype.starts_with(b"integrity_check_");
    if !is_check && mtype != b"state" && mtype != b"integrity_clear" {
        env.log("ERROR", &cat(&[b"dbsync: Wrong message type '", &mtype, b"' received from agent ", agent, b"."]));
        return;
    }
    let Some(data) = root.get_mut("data") else {
        env.log("ERROR", b"dbsync: Corrupt message: cannot get data member.");
        return;
    };
    let plain = data.print_unformatted();
    if is_check {
        let q = cat(&[b"agent ", agent, b" ", &component, b" ", &mtype, b" ", &plain]);
        if let Some(arg) = query(env, q, b"dbsync: Cannot build check query: input is too long.") {
            if !arg.is_empty() {
                answer(env, &component, agent, data, &arg);
            }
        }
    } else if mtype == b"state" {
        let q = cat(&[b"agent ", agent, b" ", &component, b" save2 ", &plain]);
        query(env, q, b"dbsync: Cannot build save query: input is too long.");
    } else {
        let q = cat(&[b"agent ", agent, b" ", &component, b" integrity_clear ", &plain]);
        query(env, q, b"dbsync: Cannot build clear query: input is too long.");
    }
}
