//! The small built-in decoders (spec section 2.26): agent upgrade messages, host
//! information, CIS-CAT results, rootcheck results and database sync messages.

use std::io::Write;
use std::path::{Path, PathBuf};

use provigil_json::Json;

use crate::decoders::DecoderSet;
use crate::event::*;
use crate::host::Host;

fn cut(b: &[u8]) -> &[u8] {
    text_at(b, 0)
}

// ---------------------------------------------------------------- upgrade

pub const UPGRADE_SOCKET: &str = "queue/tasks/upgrade";

/// Forwards an agent upgrade message with `"agents":[<id>]` added to its parameters.
pub fn upgrade(host: &mut dyn Host, agent: &[u8], log: &[u8]) {
    let Ok((mut root, _)) = provigil_json::parse_with_opts(log, false) else {
        host.log("ERROR", &[&b"Could not parse upgrade message: "[..], log].concat());
        return;
    };
    let id = crate::rules::atoi(&String::from_utf8_lossy(agent));
    let Some(params) = root.get_mut("parameters") else {
        host.log("ERROR", &[&b"Could not get parameters from upgrade message: "[..], log].concat());
        return;
    };
    let agents = Json::Array(vec![Json::number(f64::from(id))]);
    // an object gets the member, an array the list as an element, other values nothing
    match params {
        Json::Object(_) => {
            params.add("agents", agents);
        }
        Json::Array(a) => a.push(agents),
        _ => {}
    }
    let msg = root.print_unformatted();
    if let Err((_, t)) = host.send_local(UPGRADE_SOCKET, cut(&msg)) {
        host.log("ERROR", format!("Could not connect to upgrade module socket at '{UPGRADE_SOCKET}'. Error: {t}").as_bytes());
    }
}

// ---------------------------------------------------------------- host information

pub const HOSTINFO_NAME: &str = "hostinfo";
pub const HOSTINFO_NEW: &str = "hostinfo_new";
pub const HOSTINFO_CHANGED: &str = "hostinfo_modified";
pub const HOSTINFO_FILE: &str = "queue/fts/hostinfo";
const HOSTINFO_ERROR: &[u8] = b"Error handling host information database.";

/// The open ports seen per address, in `queue/fts/hostinfo`.
#[derive(Debug)]
pub struct HostInfo {
    errors: i32,
    file: Option<PathBuf>,
}

impl HostInfo {
    /// Opens (or creates) the file.
    pub fn open(home: &Path, host: &mut dyn Host) -> HostInfo {
        let path = home.join(HOSTINFO_FILE);
        let ok = std::fs::OpenOptions::new().read(true).write(true).open(&path).or_else(|_| {
            std::fs::File::create(&path)?;
            std::fs::OpenOptions::new().read(true).write(true).open(&path)
        });
        match ok {
            Ok(_) => HostInfo { errors: 0, file: Some(path) },
            Err(e) => {
                let (n, t) = crate::messages::os_error(&e);
                host.log("ERROR", format!("(1103): Could not open file '{HOSTINFO_FILE}' due to [({n})-({t})].").as_bytes());
                HostInfo { errors: 0, file: None }
            }
        }
    }

    fn fail(&mut self, host: &mut dyn Host) -> bool {
        host.log("ERROR", HOSTINFO_ERROR);
        self.errors += 1;
        false
    }

    /// `Host: <ip>[ ...],<ports>`: new or changed ports are recorded and decoded as
    /// hostinfo_new / hostinfo_modified; unchanged ones go no further.
    pub fn decode(&mut self, host: &mut dyn Host, decoders: &mut DecoderSet, decoder: DecoderId, new_id: u16, changed_id: u16, ev: &mut Event) -> bool {
        if self.errors > 30 {
            host.log("ERROR", b"Too many errors handling host information db. Ignoring it.");
            return false;
        }
        let Some(path) = self.file.clone() else { return self.fail(host) };
        let log = ev.log();
        let text = &log[..log.len().min(65536)];
        let Some(rest) = text.strip_prefix(b"Host: ").filter(|r| !r.is_empty()) else { return self.fail(host) };
        let Some(comma) = rest.iter().position(|&c| c == b',') else { return self.fail(host) };
        let ports = rest[comma + 1..].to_vec();
        let ip = &rest[..comma];
        let ip = ip[..ip.iter().position(|&c| c == b' ').unwrap_or(ip.len())].to_vec();
        let data = std::fs::read(&path).unwrap_or_default();
        let mut seen = false;
        // the file is read in pieces of 65,534 bytes
        let mut at = 0;
        while at < data.len() {
            let end = data[at..].iter().take(65534).position(|&c| c == b'\n').map_or((at + 65534).min(data.len()), |p| at + p + 1);
            let piece = cut(&data[at..end]);
            at = end;
            if matches!(piece.first(), Some(b'\n' | b'#')) {
                continue;
            }
            let line = &piece[..piece.iter().position(|&c| c == b'\n').unwrap_or(piece.len())];
            if let Some(known) = line.strip_prefix(ip.as_slice()) {
                if known == ports.as_slice() {
                    return false;
                }
                seen = true;
            }
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&path) {
            let _ = f.write_all(&[ip.as_slice(), &ports, b"\n"].concat());
        }
        ev.decoder = decoder;
        decoders.decoders[decoder].id = if seen { changed_id } else { new_id };
        true
    }
}

// ---------------------------------------------------------------- CIS-CAT

pub const CISCAT_NAME: &str = "ciscat";

/// A number's int value (0 for anything else).
fn int_of(j: &Json) -> i32 {
    match j {
        Json::Number { int, .. } => *int,
        _ => 0,
    }
}

/// `strtoul` taken as an int (wrapping, -1 when out of range).
fn unsigned_as_int(s: &[u8]) -> i32 {
    let mut i = s.iter().take_while(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)).count();
    let neg = s.get(i) == Some(&b'-');
    if matches!(s.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    let mut v: u64 = 0;
    let mut over = false;
    while let Some(c) = s.get(i).filter(|c| c.is_ascii_digit()) {
        match v.checked_mul(10).and_then(|x| x.checked_add(u64::from(c - b'0'))) {
            Some(x) => v = x,
            None => over = true,
        }
        i += 1;
    }
    let v = if over {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    };
    v as u32 as i32
}

/// The location must be the CIS-CAT module (of the manager or an agent).
fn from_module(host: &mut dyn Host, ev: &Event, module: &[u8], what: &str) -> bool {
    let loc = ev.f[F_LOCATION].clone().unwrap_or_default();
    let loc = cut(&loc);
    if loc.first() == Some(&b'(') {
        match loc.iter().position(|&c| c == b'>') {
            None => {
                host.log("DEBUG", b"Invalid received event.");
                false
            }
            Some(p) if &loc[p + 1..] != module => {
                host.log("DEBUG", format!("Invalid received event. Not {what}.").as_bytes());
                false
            }
            _ => true,
        }
    } else if loc != module {
        host.log("DEBUG", b"Invalid received event. (Location)");
        false
    } else {
        true
    }
}

/// CIS-CAT results: a `scan_info` summary is stored in provigil-db; the event goes on only
/// when that worked. Other types go on.
pub fn ciscat(host: &mut dyn Host, decoder: DecoderId, ev: &mut Event) -> bool {
    ev.decoder = decoder;
    if !from_module(host, ev, b"wodle_cis-cat", "CIS-CAT") {
        return false;
    }
    let log = ev.log().to_vec();
    let Ok((root, _)) = provigil_json::parse_with_opts(&log, false) else {
        host.log("DEBUG", b"Error parsing JSON event.");
        host.log("DEBUG2", &[&b"Input JSON: '"[..], &log].concat());
        return false;
    };
    let Some(Json::String(kind)) = root.get("type") else {
        host.log("DEBUG", b"Invalid message. Type not found or not a string.");
        return false;
    };
    if cut(kind) != b"scan_info" {
        return true;
    }
    let agent = ev.agent_id.clone().unwrap_or_default();
    let Some(cis) = root.get("cis") else {
        host.log("DEBUG", &[&b"Unable to parse CIS-CAT event for agent '"[..], &agent, b"'"].concat());
        return false;
    };
    let mut q = [&b"agent "[..], &agent, b" ciscat save"].concat();
    q.truncate(65534);
    let mut add = |v: &[u8], sep: u8| {
        q.push(sep);
        q.extend_from_slice(cut(v));
    };
    match root.get("scan_id") {
        Some(j) => add(int_of(j).to_string().as_bytes(), b' '),
        None => add(b"NULL", b' '),
    }
    for k in ["timestamp", "benchmark", "profile"] {
        match cis.get(k) {
            Some(Json::String(s)) => add(s, b'|'),
            _ => add(b"NULL", b'|'),
        }
    }
    for k in ["pass", "fail", "error", "notchecked", "unknown"] {
        match cis.get(k) {
            Some(j) => add(int_of(j).to_string().as_bytes(), b'|'),
            None => add(b"NULL", b'|'),
        }
    }
    match cis.get("score") {
        Some(Json::String(s)) => add(unsigned_as_int(cut(s)).to_string().as_bytes(), b'|'),
        _ => add(b"NULL", b'|'),
    }
    host.db_query(&q, 6144).is_ok_and(|r| r.starts_with(b"ok ") || r == b"ok")
}

// ---------------------------------------------------------------- rootcheck

pub const ROOTCHECK_NAME: &str = "rootcheck";

/// The check's title: before ` {`, after `System Audit: ` (when before ` - `), up to the
/// first `. `, without a quoted file name.
pub fn rootcheck_title(log: &[u8]) -> Option<Vec<u8>> {
    let mut t = log.to_vec();
    if let Some(c) = find(&t, b" {") {
        if c == 0 {
            return None;
        }
        t.truncate(c);
    }
    if let Some(c) = find(&t, b"System Audit: ") {
        if find(&t, b" - ").map_or(true, |d| c < d) {
            t = t[c + 14..].to_vec();
        }
    }
    if let Some(c) = find(&t, b". ") {
        t.truncate(c + 1);
    }
    if let Some(c) = find(&t, b"File '").or_else(|| find(&t, b"file '")) {
        if let Some(d) = find(&t[c + 6..], b"' ") {
            let tail = t[c + 6 + d + 2..].to_vec();
            t.truncate(c + 5);
            t.extend_from_slice(&tail);
        }
    }
    Some(t)
}

/// The checked file: after `File: ` up to `. ` (or a final `.`), or the quoted name.
pub fn rootcheck_file(log: &[u8]) -> Option<Vec<u8>> {
    if let Some(f) = find(log, b"File: ") {
        let file = &log[f + 6..];
        return match find(file, b". ") {
            Some(c) => Some(file[..c].to_vec()),
            None => file.strip_suffix(b".").map(<[u8]>::to_vec),
        };
    }
    let f = find(log, b"File '").or_else(|| find(log, b"file '"))?;
    let file = &log[f + 6..];
    match find(file, b"' ") {
        Some(c) => Some(file[..c].to_vec()),
        None => file.strip_suffix(b"'").map(<[u8]>::to_vec),
    }
}

/// The first `c` not after a backslash.
pub fn unescaped(s: &[u8], c: u8) -> Option<usize> {
    let mut escaped = false;
    for (i, &b) in s.iter().enumerate() {
        if escaped {
            escaped = false;
        } else if b == c {
            return Some(i);
        } else if b == b'\\' {
            escaped = true;
        }
    }
    None
}

/// C-style `strtol` (saturating).
pub fn long(s: &[u8]) -> i64 {
    let mut i = s.iter().take_while(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)).count();
    let neg = s.get(i) == Some(&b'-');
    if matches!(s.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    let mut v: u64 = 0;
    let mut over = false;
    while let Some(c) = s.get(i).filter(|c| c.is_ascii_digit()) {
        match v.checked_mul(10).and_then(|x| x.checked_add(u64::from(c - b'0'))) {
            Some(x) => v = x,
            None => over = true,
        }
        i += 1;
    }
    match (neg, over || v > i64::MAX as u64 + u64::from(neg)) {
        (true, true) => i64::MIN,
        (false, true) => i64::MAX,
        (true, false) => (v as i64).wrapping_neg(),
        (false, false) => v as i64,
    }
}

/// Rootcheck results: stored in provigil-db (a new entry counts as already seen for the
/// first-time-seen check); fields `title` and `file`.
pub fn rootcheck(host: &mut dyn Host, decoder: DecoderId, ev: &mut Event) -> bool {
    let agent = ev.agent_id.clone().unwrap_or_default();
    let log = ev.log().to_vec();
    let mut q = [&b"agent "[..], &agent, format!(" rootcheck save {} ", ev.time.sec).as_bytes(), &log].concat();
    q.truncate(6143);
    let answer = match host.db_query(&q, 6144) {
        Ok(r) => r,
        Err(code) => {
            if code == -2 {
                host.log("ERROR", &[&b"Bad load query: '"[..], &q, b"'."].concat());
            }
            host.log("ERROR", b"Rootcheck decoder unexpected result: ''");
            return false;
        }
    };
    host.log("DEBUG", &[&b"Rootcheck decoder response: '"[..], &answer, b"'"].concat());
    ev.decoder = decoder;
    if unescaped(&answer, b' ').is_some_and(|p| long(&answer[p + 1..]) == 2) {
        ev.rootcheck_fts = FTS_DONE;
    }
    ev.fields = vec![DynamicField { key: b"title".to_vec(), value: rootcheck_title(&log) }, DynamicField { key: b"file".to_vec(), value: rootcheck_file(&log) }];
    true
}

// ---------------------------------------------------------------- database sync

pub const SYSCHECK_SOCKET: &str = "queue/sockets/syscheck";
pub const MODULES_SOCKET: &str = "queue/sockets/wmodules";

const SYNC_COMPONENTS: &[&[u8]] = &[
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

/// The provigil-db answer's payload when it is `ok`.
fn sync_query(host: &mut dyn Host, q: Vec<u8>, too_long: &[u8]) -> Option<Vec<u8>> {
    if q.len() >= 65536 {
        host.log("ERROR", too_long);
        return None;
    }
    let answer = match host.db_query(&q, 65536) {
        Ok(r) => r,
        Err(-2) => {
            host.log("ERROR", b"dbsync: Cannot communicate with database.");
            return None;
        }
        Err(_) => {
            host.log("ERROR", b"dbsync: Cannot get response from database.");
            return None;
        }
    };
    let (head, arg) = match answer.iter().position(|&c| c == b' ') {
        Some(p) => (&answer[..p], &answer[p + 1..]),
        None => (&answer[..], &answer[..]),
    };
    match head {
        b"ok" => Some(arg.to_vec()),
        b"err" => {
            if arg != b"Agent not found" {
                host.log("ERROR", &[&b"dbsync: Bad response from database: "[..], arg].concat());
            }
            None
        }
        _ => None,
    }
}

/// Database sync messages of an agent's inventory and file integrity modules: the query
/// for provigil-db, and the answer of an integrity check sent back to the agent (or the
/// manager's own module).
pub fn sync(host: &mut dyn Host, agent: &[u8], log: &[u8]) {
    let Ok((mut root, _)) = provigil_json::parse_with_opts(log, false) else {
        host.log("ERROR", &[&b"dbsync: Cannot parse JSON: "[..], log].concat());
        return;
    };
    let text = |j: Option<&Json>| match j {
        Some(Json::String(s)) => Some(cut(s).to_vec()),
        _ => None,
    };
    let Some(component) = text(root.get("component")) else {
        host.log("ERROR", b"dbsync: Corrupt message: cannot get component member.");
        return;
    };
    let Some(kind) = text(root.get("type")) else {
        host.log("ERROR", b"dbsync: Corrupt message: cannot get type member.");
        return;
    };
    if !SYNC_COMPONENTS.contains(&component.as_slice()) {
        host.log("ERROR", b"dbsync: Invalid component specified.");
        return;
    }
    let check = kind.starts_with(b"integrity_check_");
    if !check && kind != b"state" && kind != b"integrity_clear" {
        host.log("ERROR", &[&b"dbsync: Wrong message type '"[..], &kind, b"' received from agent ", agent, b"."].concat());
        return;
    }
    let Some(data) = root.get_mut("data") else {
        host.log("ERROR", b"dbsync: Corrupt message: cannot get data member.");
        return;
    };
    let plain = data.print_unformatted();
    let head = [&b"agent "[..], agent, b" ", &component, b" "].concat();
    if check {
        let q = [&head[..], &kind, b" ", &plain].concat();
        if let Some(answer) = sync_query(host, q, b"dbsync: Cannot build check query: input is too long.").filter(|a| !a.is_empty()) {
            data.remove("tail");
            data.remove("checksum");
            let query = [&b"dbsync "[..], &answer, b" ", &data.print_unformatted()].concat();
            if query.len() >= 65536 {
                host.log("ERROR", b"dbsync: Cannot build query for agent: query is too long.");
                return;
            }
            let request = [&component[..], b" ", &query].concat();
            if agent == b"000" {
                let path = if component.starts_with(b"syscheck") || component.starts_with(b"fim_file") {
                    SYSCHECK_SOCKET
                } else if component.starts_with(b"syscollector") {
                    MODULES_SOCKET
                } else {
                    host.log("ERROR", &[&b"dbsync: unknown location '"[..], &component, b"'"].concat());
                    return;
                };
                if let Err((n, t)) = host.send_local(path, &request) {
                    host.log("ERROR", &[&b"dbsync: cannot connect to "[..], &component, format!(": {t} ({n})").as_bytes()].concat());
                }
            } else {
                let mut request = request;
                request.truncate(65535);
                let mut m = [&b"(msg_to_agent) [] N!S "[..], agent, b" ", &request].concat();
                m.truncate(65535);
                host.responses().send_ar(&m);
            }
        }
    } else if kind == b"state" {
        sync_query(host, [&head[..], b"save2 ", &plain].concat(), b"dbsync: Cannot build save query: input is too long.");
    } else {
        sync_query(host, [&head[..], b"integrity_clear ", &plain].concat(), b"dbsync: Cannot build clear query: input is too long.");
    }
}
