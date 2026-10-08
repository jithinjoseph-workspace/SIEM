//! Active response execution (analysisd/alerts/exec.c and ar_json.c):
//! `OS_Exec`, `getActiveResponseInJSON`, `getActiveResponseInString`,
//! `get_exec_msg`.

use siem_cjson::Json;
use siem_config::active_response::{
    ActiveResponse, ArCommand, ALL_AGENTS, AS_ONLY, LOCAL_AR, NONE_C, REMOTE_AGENT, REMOTE_AGENT_C, REMOTE_AR,
    SPECIFIC_AGENT, SPECIFIC_AGENT_C,
};
use siem_regex::{OsIp, OsMatch};

use crate::engine::Engine;
use crate::logmsg::LogList;
use crate::event::*;

const OS_MAXSTR: usize = 65536;
const OS_SIZE_1024: usize = 1024;

/// Result of looking up an agent's version for `OS_Exec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentVersion {
    Found(String),
    /// `wdb_get_agent_info` failed (logged as an error).
    NoInfo,
    /// The agent info has no string `version` (debug message only).
    NoVersion,
}

/// What `OS_Exec` needs from the outside world.
pub trait ArBackend {
    /// `labels_get(labels_find(id), "_wazuh_version")`, else the version
    /// reported by wazuh-db (`global get-agent-info`).
    fn agent_version(&mut self, agent_id: i32) -> AgentVersion;
    /// `wdb_get_agents_by_connection_status("active")`
    fn active_agents(&mut self) -> Option<Vec<i32>>;
    /// `get_node_name()` (`ossec.conf` cluster node name or "undefined").
    fn node_name(&mut self) -> String;
    /// Send to `queue/alerts/execq` (local) or `queue/alerts/ar` (remote).
    fn send_exec(&mut self, msg: &[u8]);
    fn send_ar(&mut self, msg: &[u8]);
}

/// AR whitelists (`Config.white_list`, `Config.hostname_white_list`).
#[derive(Debug, Clone, Default)]
pub struct ArWhitelist {
    pub ips: Vec<OsIp>,
    pub hostnames: Vec<OsMatch>,
}

/// `os_shell_escape`
pub fn os_shell_escape(src: &[u8]) -> Vec<u8> {
    const ESC: &[u8] = b"\\\"'\t;`><|#*[]{}&$!:()";
    let mut out = Vec::with_capacity(src.len() * 2);
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        if ESC.contains(&c) {
            if c == b'\\' && i + 1 < src.len() && ESC.contains(&src[i + 1]) {
                // already escaped
                out.push(c);
                i += 1;
            } else {
                out.push(b'\\');
            }
        }
        if i < src.len() {
            out.push(src[i]);
        }
        i += 1;
    }
    out
}

/// `get_ip`: strip `::ffff:` and apply the whitelists.
fn get_ip(srcip: &[u8], wl: &ArWhitelist) -> Option<Vec<u8>> {
    let ip = srcip.strip_prefix(b"::ffff:").unwrap_or(srcip);
    let s = String::from_utf8_lossy(ip);
    if !wl.ips.is_empty() && siem_regex::ip_found_list(&s, &wl.ips) {
        return None;
    }
    for m in &wl.hostnames {
        if m.is_match_bytes(ip) {
            return None;
        }
    }
    Some(ip.to_vec())
}

/// `wstr_replace`
fn replace_all(s: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    crate::output::search_and_replace(s, from, to)
}

/// `getActiveResponseInJSON`
pub fn ar_json(
    eng: &Engine,
    ev: &Event,
    ar: &ActiveResponse,
    extra_args: Option<&str>,
    node_name: &str,
    escape: bool,
    log: &mut LogList,
) -> Vec<u8> {
    let mut msg = Json::object();
    msg.add("version", Json::number(1.0));
    let mut origin = Json::object();
    origin.add("name", Json::string(node_name));
    origin.add("module", Json::string("wazuh-analysisd"));
    msg.add("origin", origin);
    msg.add("command", Json::string(&ar.name));
    let mut params = Json::object();
    let mut args = Vec::new();
    if let Some(ea) = extra_args {
        let b = ea.as_bytes();
        let b = &b[..b.len().min(2047)];
        for t in b.split(|&c| c == b' ').filter(|t| !t.is_empty()) {
            args.push(Json::String(t.to_vec()));
        }
    }
    params.add("extra_args", Json::Array(args));
    let alert = crate::to_json::eventinfo_to_json(eng, ev, false, log);
    if let Some(a) = siem_cjson::parse(&alert) {
        params.add("alert", a);
    }
    msg.add("parameters", params);
    let mut s = msg.print_unformatted();
    if escape {
        s = replace_all(&s, b"!", b"\\\\x21");
        s = replace_all(&s, b"$", b"\\\\x24");
        s = replace_all(&s, b"'", b"\\\\x27");
        s = replace_all(&s, b"`", b"\\\\x60");
    }
    s.truncate(OS_MAXSTR);
    s
}

/// `getActiveResponseInString`
#[allow(clippy::too_many_arguments)]
fn ar_string(
    ev: &Event,
    ar: &ActiveResponse,
    alert_second_id: i64,
    sigid: i32,
    ip: &[u8],
    user: &[u8],
    filename: Option<&[u8]>,
    extra_args: Option<&[u8]>,
) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(ar.name.as_bytes());
    o.push(b' ');
    o.extend_from_slice(user);
    o.push(b' ');
    o.extend_from_slice(ip);
    o.extend_from_slice(format!(" {}.{} {} ", ev.time.sec, alert_second_id, sigid).as_bytes());
    o.extend_from_slice(ev.f[F_LOCATION].as_deref().unwrap_or(b"(null)"));
    o.push(b' ');
    o.extend_from_slice(filename.unwrap_or(b"-"));
    o.push(b' ');
    o.extend_from_slice(extra_args.unwrap_or(b"-"));
    o.truncate(OS_SIZE_1024 - 1);
    o
}

/// `get_exec_msg`
fn exec_msg(ar: &ActiveResponse, agent_id: &str, msg: &[u8]) -> Vec<u8> {
    let mut head = format!(
        "(local_source) [] {}{}{} {}",
        NONE_C as char,
        if ar.location & REMOTE_AGENT != 0 { REMOTE_AGENT_C } else { NONE_C } as char,
        if ar.location & SPECIFIC_AGENT != 0 || ar.location & ALL_AGENTS != 0 { SPECIFIC_AGENT_C } else { NONE_C } as char,
        agent_id
    )
    .into_bytes();
    head.truncate(OS_SIZE_1024 - 1);
    let mut out = head;
    out.push(b' ');
    out.extend_from_slice(msg);
    out.truncate(OS_MAXSTR);
    out
}

/// Parse "Wazuh vX.Y.Z" like the `strtok_r(v / .)` sequence of `OS_Exec`.
pub fn parse_agent_version(v: &str) -> Option<(i32, i32, i32)> {
    let b = v.as_bytes();
    // strtok_r(agt_version, "v"): skip leading 'v's, the first token ends at the next 'v'
    let mut i = 0;
    while i < b.len() && b[i] == b'v' {
        i += 1;
    }
    if i >= b.len() {
        return None;
    }
    while i < b.len() && b[i] != b'v' {
        i += 1;
    }
    if i < b.len() {
        i += 1;
    }
    let rest = &v[i.min(v.len())..];
    let mut it = rest.split('.').filter(|t| !t.is_empty());
    let major = it.next()?;
    let minor = it.next()?;
    let patch = it.next()?;
    let a = |s: &str| crate::rules::atoi(s);
    Some((a(major), a(minor), a(patch)))
}

/// `OS_Exec`. `ar_flags` is `Config.ar`.
#[allow(clippy::too_many_arguments)]
pub fn os_exec(
    eng: &Engine,
    ev: &Event,
    ar: &ActiveResponse,
    cmd: &ArCommand,
    ar_flags: i32,
    wl: &ArWhitelist,
    backend: &mut dyn ArBackend,
    log: &mut LogList,
) {
    let ip: Vec<u8> = match &ev.f[F_SRCIP] {
        Some(s) => match get_ip(s, wl) {
            Some(i) => i,
            None => return,
        },
        None => b"-".to_vec(),
    };
    let user: Vec<u8> = ev.f[F_DSTUSER].clone().unwrap_or_else(|| b"-".to_vec());
    let dec = &eng.decoders.infos[ev.decoder];
    let filename: Option<Vec<u8>> = if dec.name.as_deref().map_or(false, |n| n.starts_with("syscheck_")) {
        ev.fields.get(crate::syscheck_json::fim::FILE).and_then(|f| f.value.as_deref()).map(os_shell_escape)
    } else {
        None
    };
    let extra_args = cmd.extra_args.as_deref().map(|e| os_shell_escape(e.as_bytes()));
    let sigid = ev.generated_rule.map(|r| eng.rules.infos[r].sigid).unwrap_or(0);
    let agent_id = ev.agent_id.as_deref().unwrap_or(b"");

    if ar.location & AS_ONLY != 0 || (ar.location & REMOTE_AGENT != 0 && agent_id == b"000") {
        if ar_flags & LOCAL_AR == 0 {
            return;
        }
        let node = backend.node_name();
        let m = ar_json(eng, ev, ar, cmd.extra_args.as_deref(), &node, false, log);
        backend.send_exec(&m);
    } else if ar_flags & REMOTE_AR != 0 {
        let send_to = |backend: &mut dyn ArBackend, id: i32, log: &mut LogList| {
            let c_id = format!("{:03}", id);
            let ver = match backend.agent_version(id) {
                AgentVersion::Found(v) => v,
                AgentVersion::NoInfo => {
                    log.error(format!("Failed to get agent '{id}' information from Wazuh DB."));
                    return;
                }
                AgentVersion::NoVersion => return,
            };
            let msg = match parse_agent_version(&ver) {
                None => {
                    log.error("Unable to read agent version.");
                    return;
                }
                Some((major, minor, patch)) => {
                    if major < 4 || (major == 4 && minor < 2) {
                        ar_string(ev, ar, eng.alert_second_id, sigid, &ip, &user, filename.as_deref(), extra_args.as_deref())
                    } else {
                        let escape = major == 4 && minor == 2 && patch < 5;
                        let node = backend.node_name();
                        ar_json(eng, ev, ar, cmd.extra_args.as_deref(), &node, escape, log)
                    }
                }
            };
            let m = exec_msg(ar, &c_id, &msg);
            backend.send_ar(&m);
        };
        if ar.location & ALL_AGENTS != 0 {
            match backend.active_agents() {
                None => log.error("Unable to get agent's ID array."),
                Some(ids) => {
                    for id in ids {
                        send_to(backend, id, log);
                    }
                }
            }
        } else {
            let id = if ar.location & SPECIFIC_AGENT != 0 {
                crate::rules::atoi(ar.agent_id.as_deref().unwrap_or(""))
            } else if ar.location & REMOTE_AGENT != 0 {
                crate::rules::atoi(&String::from_utf8_lossy(agent_id))
            } else {
                -1
            };
            if id == -1 {
                log.error("Unable to get agent ID.");
                return;
            }
            send_to(backend, id, log);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_escape() {
        assert_eq!(os_shell_escape(b"a;b"), b"a\\;b");
        assert_eq!(os_shell_escape(b"a\\;b"), b"a\\;b");
        assert_eq!(os_shell_escape(b"x\\"), b"x\\\\");
    }

    #[test]
    fn versions() {
        assert_eq!(parse_agent_version("Wazuh v4.7.1"), Some((4, 7, 1)));
        assert_eq!(parse_agent_version("v4.7.1"), None);
        assert_eq!(parse_agent_version("Wazuh v4.2"), None);
    }
}
