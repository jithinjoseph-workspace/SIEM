//! Running active responses (spec section 2.11): the message for the manager or each agent
//! (JSON for current agents, the older one-line text for agents before 4.2), the address
//! white lists and the shell escaping of values.

use provigil_json::Json;
use provigil_regex::{OsIp, OsMatch};

use crate::config::{Command, Response, ALL_AGENTS, AS_ONLY, LOCAL_AR, REMOTE_AGENT, REMOTE_AR, SPECIFIC_AGENT};
use crate::engine::Engine;
use crate::event::*;
use crate::messages::Messages;

const MAX_MESSAGE: usize = 65536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentVersion {
    Found(String),
    /// provigil-db had no answer (an error is logged)
    NoInfo,
    /// the agent has no version (nothing is sent)
    NoVersion,
}

/// What running a response needs from outside.
pub trait ResponseSink {
    /// The agent's version label, else what provigil-db knows.
    fn agent_version(&mut self, agent: i32) -> AgentVersion;
    fn active_agents(&mut self) -> Option<Vec<i32>>;
    /// The cluster node name (or "undefined").
    fn node_name(&mut self) -> String;
    /// To the local response service.
    fn send_exec(&mut self, msg: &[u8]);
    /// To the agents' response queue.
    fn send_ar(&mut self, msg: &[u8]);
    /// To ProVigil agents (through siem-api).
    fn send_provigil_ar(&mut self, msg: &[u8]) {
        self.send_ar(msg)
    }
}

/// Addresses and host patterns never responded to.
#[derive(Debug, Clone, Default)]
pub struct WhiteList {
    pub ips: Vec<OsIp>,
    pub hostnames: Vec<OsMatch>,
}

/// A backslash before each shell special character, unless one is there already.
pub fn shell_escape(src: &[u8]) -> Vec<u8> {
    const SPECIAL: &[u8] = b"\\\"'\t;`><|#*[]{}&$!:()";
    let mut out = Vec::with_capacity(src.len() * 2);
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        if SPECIAL.contains(&c) {
            if c == b'\\' && src.get(i + 1).is_some_and(|n| SPECIAL.contains(n)) {
                out.push(c);
                i += 1;
            } else {
                out.push(b'\\');
            }
        }
        if let Some(&x) = src.get(i) {
            out.push(x);
        }
        i += 1;
    }
    out
}

/// The source address (without `::ffff:`), unless white-listed.
fn source_ip(ip: &[u8], wl: &WhiteList) -> Option<Vec<u8>> {
    let ip = ip.strip_prefix(b"::ffff:").unwrap_or(ip);
    if !wl.ips.is_empty() && provigil_regex::ip_found_list(&String::from_utf8_lossy(ip), &wl.ips) {
        return None;
    }
    if wl.hostnames.iter().any(|m| m.is_match_bytes(ip)) {
        return None;
    }
    Some(ip.to_vec())
}

/// The JSON response message (with the alert); `escape` hides `! $ ' `` ` for agents 4.2.0-4.2.4.
pub fn json_message(eng: &Engine, ev: &Event, r: &Response, extra_args: Option<&str>, node: &str, escape: bool, msgs: &mut Messages) -> Vec<u8> {
    let mut m = Json::object();
    m.add("version", Json::number(1.0));
    let mut origin = Json::object();
    origin.add("name", Json::string(node));
    origin.add("module", Json::string("provigil-analysisd"));
    m.add("origin", origin);
    m.add("command", Json::string(&r.name));
    let mut p = Json::object();
    let args = extra_args.map(|a| &a.as_bytes()[..a.len().min(2047)]).unwrap_or(b"");
    p.add("extra_args", Json::Array(args.split(|&c| c == b' ').filter(|t| !t.is_empty()).map(|t| Json::String(t.to_vec())).collect()));
    if let Some(a) = provigil_json::parse(&crate::alert_json::alert(eng, ev, false, msgs)) {
        p.add("alert", a);
    }
    m.add("parameters", p);
    let mut s = m.print_unformatted();
    if escape {
        for (from, to) in [(&b"!"[..], &b"\\\\x21"[..]), (b"$", b"\\\\x24"), (b"'", b"\\\\x27"), (b"`", b"\\\\x60")] {
            s = crate::text_logs::replace_all(&s, from, to);
        }
    }
    s.truncate(MAX_MESSAGE);
    s
}

/// The one-line message of agents before 4.2:
/// `name user ip time.id rule location file extra-args` (1,023 bytes at most).
#[allow(clippy::too_many_arguments)]
fn line_message(ev: &Event, r: &Response, counter: i64, rule: i32, ip: &[u8], user: &[u8], file: Option<&[u8]>, extra: Option<&[u8]>) -> Vec<u8> {
    let mut o = [r.name.as_bytes(), b" ", user, b" ", ip].concat();
    o.extend_from_slice(format!(" {}.{} {} ", ev.time.sec, counter, rule).as_bytes());
    o.extend_from_slice(&[ev.f[F_LOCATION].as_deref().unwrap_or(b"(null)"), b" ", file.unwrap_or(b"-"), b" ", extra.unwrap_or(b"-")].concat());
    o.truncate(1023);
    o
}

/// `(local_source) [] N<R|N><S|N> <agent> <message>`
fn queue_message(r: &Response, agent: &str, msg: &[u8]) -> Vec<u8> {
    let mut o = format!(
        "(local_source) [] N{}{} {agent}",
        if r.location & REMOTE_AGENT != 0 { 'R' } else { 'N' },
        if r.location & (SPECIFIC_AGENT | ALL_AGENTS) != 0 { 'S' } else { 'N' }
    )
    .into_bytes();
    o.truncate(1023);
    o.push(b' ');
    o.extend_from_slice(msg);
    o.truncate(MAX_MESSAGE);
    o
}

/// "<product> vX.Y.Z" as numbers: the text after the first `v` that follows something, in
/// dot-separated parts.
pub fn agent_version(v: &str) -> Option<(i32, i32, i32)> {
    let b = v.as_bytes();
    let mut i = b.iter().take_while(|&&c| c == b'v').count();
    if i >= b.len() {
        return None;
    }
    while i < b.len() && b[i] != b'v' {
        i += 1;
    }
    let rest = &v[(i + 1).min(v.len())..];
    let mut parts = rest.split('.').filter(|t| !t.is_empty()).map(crate::rules::atoi);
    Some((parts.next()?, parts.next()?, parts.next()?))
}

/// Runs response `r` (command `cmd`) for `ev`; `flags` says where responses may run.
#[allow(clippy::too_many_arguments)]
pub fn run(eng: &Engine, ev: &Event, r: &Response, cmd: &Command, flags: i32, wl: &WhiteList, sink: &mut dyn ResponseSink, msgs: &mut Messages) {
    let ip = match &ev.f[F_SRCIP] {
        Some(s) => match source_ip(s, wl) {
            Some(i) => i,
            None => return,
        },
        None => b"-".to_vec(),
    };
    let user = ev.f[F_DSTUSER].clone().unwrap_or_else(|| b"-".to_vec());
    let d = &eng.decoders.decoders[ev.decoder];
    let file = d
        .name
        .as_deref()
        .filter(|n| n.starts_with("syscheck_"))
        .and_then(|_| ev.fields.get(crate::alert_json::fim::FILE))
        .and_then(|f| f.value.as_deref())
        .map(shell_escape);
    let extra = cmd.extra_args.as_deref().map(|e| shell_escape(e.as_bytes()));
    let rule = ev.generated_rule.map_or(0, |x| eng.rules.rules[x].sigid);
    let agent = ev.agent_id.as_deref().unwrap_or(b"");

    if r.location & AS_ONLY != 0 || (r.location & REMOTE_AGENT != 0 && agent == b"000") {
        if flags & LOCAL_AR != 0 {
            let node = sink.node_name();
            let m = json_message(eng, ev, r, cmd.extra_args.as_deref(), &node, false, msgs);
            sink.send_exec(&m);
        }
        return;
    }
    if flags & REMOTE_AR == 0 {
        return;
    }
    let send = |sink: &mut dyn ResponseSink, id: i32, msgs: &mut Messages| {
        let to = format!("{id:03}");
        let version = match sink.agent_version(id) {
            AgentVersion::Found(v) => v,
            AgentVersion::NoInfo => {
                msgs.error(format!("Failed to get agent '{id}' information from provigil-db."));
                return;
            }
            AgentVersion::NoVersion => return,
        };
        // ProVigil agents number their own versions: always JSON, through siem-api
        if version.starts_with("ProVigil") {
            let node = sink.node_name();
            let m = json_message(eng, ev, r, cmd.extra_args.as_deref(), &node, false, msgs);
            sink.send_provigil_ar(&queue_message(r, &to, &m));
            return;
        }
        let Some((major, minor, patch)) = agent_version(&version) else {
            msgs.error("Unable to read agent version.");
            return;
        };
        let m = if major < 4 || (major == 4 && minor < 2) {
            line_message(ev, r, eng.alert_counter, rule, &ip, &user, file.as_deref(), extra.as_deref())
        } else {
            let node = sink.node_name();
            json_message(eng, ev, r, cmd.extra_args.as_deref(), &node, major == 4 && minor == 2 && patch < 5, msgs)
        };
        sink.send_ar(&queue_message(r, &to, &m));
    };
    if r.location & ALL_AGENTS != 0 {
        match sink.active_agents() {
            Some(ids) => {
                for id in ids {
                    send(sink, id, msgs);
                }
            }
            None => msgs.error("Unable to get agent's ID array."),
        }
        return;
    }
    let id = if r.location & SPECIFIC_AGENT != 0 {
        crate::rules::atoi(r.agent_id.as_deref().unwrap_or(""))
    } else if r.location & REMOTE_AGENT != 0 {
        crate::rules::atoi(&String::from_utf8_lossy(agent))
    } else {
        -1
    };
    if id == -1 {
        msgs.error("Unable to get agent ID.");
        return;
    }
    send(sink, id, msgs);
}
