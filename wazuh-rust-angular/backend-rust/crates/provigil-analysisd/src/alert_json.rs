//! The alert JSON (spec section 2.10): member order and texts are what the console and the
//! stored alerts read, so they stay exactly as they were.

use std::sync::OnceLock;

use chrono::TimeZone;
use provigil_json::Json;

use crate::engine::Engine;
use crate::event::*;
use crate::messages::Messages;
use crate::rules::*;

const MAX_TEXT: usize = 1024;

fn s(b: &[u8]) -> Json {
    Json::String(b.to_vec())
}

/// Adds `key` (dots make nested objects) unless it is there; a value that is a whole JSON
/// array is stored as one.
pub fn add_field(root: &mut Json, key: &[u8], value: &[u8]) {
    if let Some(dot) = key.iter().position(|&c| c == b'.') {
        let (head, rest) = (&key[..dot], &key[dot + 1..]);
        match root.get_mut_bytes(head) {
            Some(o) => {
                if matches!(o, Json::Object(_)) {
                    add_field(o, rest, value);
                }
            }
            None => {
                let mut o = Json::object();
                add_field(&mut o, rest, value);
                root.add(head, o);
            }
        }
    } else if root.get_bytes(key).is_none() {
        if value.first() == Some(&b'[') {
            if let Ok((j, end)) = provigil_json::parse_with_opts(value, false) {
                if end == value.len() {
                    root.add(key, j);
                    return;
                }
            }
        }
        root.add(key, s(value));
    }
}

/// `YYYY-MM-DDThh:mm:ss.mmm±hhmm` in local time.
fn timestamp(t: Instant) -> String {
    let off = chrono::FixedOffset::east_opt(crate::time::offset_at(t.sec) as i32).unwrap_or_else(|| chrono::FixedOffset::east_opt(0).expect("zero"));
    let d = off.timestamp_opt(t.sec, 0).single().unwrap_or_else(|| off.timestamp_opt(0, 0).single().expect("epoch"));
    format!("{}.{:03}{}", d.format("%Y-%m-%dT%H:%M:%S"), t.nsec / 1_000_000, d.format("%z"))
}

/// The alert of `ev` as compact JSON.
pub fn alert(eng: &Engine, ev: &Event, full_log_always: bool, msgs: &mut Messages) -> Vec<u8> {
    let rule = ev.generated_rule.map(|r| &*eng.rules.rules[r]);
    let d = &eng.decoders.decoders[ev.decoder];
    let mut root = Json::object();
    if ev.time.sec != 0 {
        root.add("timestamp", Json::string(timestamp(ev.time)));
    }
    // rule, agent and manager come first; the rest in the order it is built
    let mut rule_j = rule.map(|_| Json::object());
    let mut agent = Json::object();
    let mut manager = Json::object();
    let mut data = Json::object();
    let mut tail: Vec<(Vec<u8>, Json)> = Vec::new();
    if ev.time.sec != 0 {
        tail.push((b"id".to_vec(), Json::string(format!("{}.{}", ev.time.sec, eng.alert_counter))));
    }
    if !eng.settings.hide_cluster_info {
        let mut c = Json::object();
        c.add("name", Json::string(eng.settings.cluster_name.clone().unwrap_or_else(|| "provigil".into())));
        if let Some(n) = &eng.settings.node_name {
            c.add("node", Json::string(n));
        }
        tail.push((b"cluster".to_vec(), c));
    }
    manager.add("name", s(&eng.settings.manager_name));

    if let (Some(r), Some(rj)) = (rule, rule_j.as_mut()) {
        if r.level != 0 {
            rj.add("level", Json::number(f64::from(r.level)));
        }
        if let Some(c) = &ev.comment {
            rj.add("description", s(c));
        }
        if r.sigid != 0 {
            rj.add("id", Json::string(r.sigid.to_string()));
        }
        add_mitre(eng, r, rj, msgs);
        if let Some(c) = &r.cve {
            rj.add("cve", Json::string(c));
        }
        if let Some(i) = &r.info {
            rj.add("info", Json::string(i));
        }
        if r.event_search.is_some() {
            rj.add("frequency", Json::number(f64::from(r.frequency + 2)));
        }
        if ev.fired_times != -1 && r.alert_opts & NO_COUNTER == 0 {
            rj.add("firedtimes", Json::number(f64::from(ev.fired_times)));
        }
        rj.add("mail", Json::bool(r.alert_opts & DO_MAILALERT != 0));
        if let Some(l) = ev.last_events.as_ref().filter(|l| l.len() >= 2 && !l[1].is_empty()) {
            tail.push((b"previous_output".to_vec(), s(&l.join(&b'\n'))));
        }
    }
    let fixed = |data: &mut Json, names: &[(&str, usize)]| {
        for &(k, f) in names {
            if let Some(v) = &ev.f[f] {
                data.add(k, s(v));
            }
        }
    };
    fixed(&mut data, &[("protocol", F_PROTOCOL), ("action", F_ACTION), ("srcip", F_SRCIP)]);
    if GEOIP {
        if let Some(v) = &ev.f[F_SRCGEOIP] {
            tail.push((b"srcgeoip".to_vec(), s(v)));
        }
    }
    fixed(&mut data, &[("srcport", F_SRCPORT), ("srcuser", F_SRCUSER), ("dstip", F_DSTIP)]);
    if GEOIP {
        if let Some(v) = &ev.f[F_DSTGEOIP] {
            tail.push((b"dstgeoip".to_vec(), s(v)));
        }
    }
    fixed(&mut data, &[("dstport", F_DSTPORT), ("dstuser", F_DSTUSER)]);
    if !ev.buf.is_empty() && (full_log_always || !rule.is_some_and(|r| r.alert_opts & NO_FULL_LOG != 0)) {
        tail.push((b"full_log".to_vec(), s(ev.full_log())));
    }
    if let Some(a) = &ev.agent_id {
        agent.add("id", s(a));
    }
    let syscheck = d.name.as_deref().is_some_and(|n| n.starts_with("syscheck_"));
    if syscheck {
        tail.push((b"syscheck".to_vec(), syscheck_section(ev, eng.settings.rules.order_size, msgs)));
    }
    if ev.program_name.is_some() || ev.dec_timestamp.is_some() {
        let mut p = Json::object();
        if let Some(v) = &ev.program_name {
            p.add("program_name", s(v));
        }
        if let Some(v) = &ev.dec_timestamp {
            p.add("timestamp", s(v));
        }
        tail.push((b"predecoder".to_vec(), p));
    }
    fixed(&mut data, &[("id", F_ID), ("status", F_STATUS), ("url", F_URL), ("data", F_DATA), ("extra_data", F_EXTRA_DATA), ("system_name", F_SYSTEMNAME)]);
    if syscheck {
        if let Some(a) = audit_section(ev) {
            if let Some((_, sc)) = tail.iter_mut().find(|(k, _)| k == b"syscheck") {
                sc.add("audit", a);
            }
        }
    }
    if d.name.is_some() && !syscheck {
        for f in &ev.fields {
            if let Some(v) = f.value.as_deref().filter(|v| !v.is_empty()) {
                add_field(&mut data, &f.key, v);
            }
        }
    }
    let mut dj = Json::object();
    if d.accumulate != 0 {
        dj.add("accumulate", Json::number(f64::from(d.accumulate)));
    }
    if let Some(p) = &d.parent {
        dj.add("parent", Json::string(p));
    }
    if let Some(n) = &d.name {
        dj.add("name", Json::string(n));
    }
    if let Some(f) = &d.fts_comment {
        dj.add("ftscomment", Json::string(f));
    }
    tail.push((b"decoder".to_vec(), dj));
    if let Some(p) = &ev.previous {
        tail.push((b"previous_log".to_vec(), s(p)));
    }
    if let Some(rj) = rule_j {
        root.add("rule", rj);
    }
    root.add("agent", agent);
    root.add("manager", manager);
    for (k, v) in tail {
        root.add(k, v);
    }
    if !data.is_empty() {
        root.add("data", data);
    }
    extend(eng, &mut root, ev);
    root.print_unformatted()
}

/// The rule's MITRE techniques and tactics (new format pairs, else old format ids).
fn add_mitre(eng: &Engine, r: &Rule, rj: &mut Json, msgs: &mut Messages) {
    let none = crate::mitre::Mitre::default();
    let db = eng.mitre.as_deref().unwrap_or(&none);
    let (mut tactics, mut techniques): (Vec<Vec<u8>>, Vec<Json>) = (Vec::new(), Vec::new());
    let ids: Vec<Json>;
    if let (Some(techs), Some(tacs)) = (&r.mitre_technique_id, &r.mitre_tactic_id) {
        let mut found_ids = Vec::new();
        let mut names: Vec<Vec<u8>> = Vec::new();
        for (i, tid) in techs.iter().enumerate() {
            let Some(t) = db.technique(tid) else {
                msgs.warn(format!("Mitre Technique ID '{tid}' not found in database."));
                continue;
            };
            let want = tacs.get(i).cloned().unwrap_or_default();
            let mut is_tactic = false;
            for ta in t.tactics.iter().filter(|ta| ta.id == want) {
                is_tactic = true;
                if !tactics.iter().any(|x| x == ta.name.as_bytes()) {
                    tactics.push(ta.name.as_bytes().to_vec());
                    break;
                }
            }
            if !is_tactic {
                msgs.warn(format!("Mitre Tactic ID '{want}' is not a tactic of '{tid}'."));
            } else if !names.iter().any(|x| x == t.name.as_bytes()) {
                found_ids.push(Json::string(&t.id));
                names.push(t.name.as_bytes().to_vec());
            }
        }
        ids = found_ids;
        techniques = names.into_iter().map(Json::String).collect();
    } else if let Some(mids) = &r.mitre_id {
        for mid in mids {
            match db.technique(mid) {
                None => msgs.warn(format!("Mitre Technique ID '{mid}' not found in database.")),
                Some(t) => {
                    for ta in &t.tactics {
                        if !tactics.iter().any(|x| x == ta.name.as_bytes()) {
                            tactics.push(ta.name.as_bytes().to_vec());
                        }
                    }
                    techniques.push(Json::string(&t.name));
                }
            }
        }
        ids = mids.iter().map(Json::string).collect();
    } else {
        return;
    }
    if !tactics.is_empty() {
        let mut m = Json::object();
        m.add("id", Json::Array(ids));
        m.add("tactic", Json::Array(tactics.into_iter().map(Json::String).collect()));
        m.add("technique", Json::Array(techniques));
        rj.add("mitre", m);
    }
}

/// Host name, agent address, location, agentless, groups and compliance, rootcheck and
/// labels.
pub fn extend(eng: &Engine, root: &mut Json, ev: &Event) {
    if !ev.buf.is_empty() && ev.hostname.is_some() {
        host_name(root, ev);
        agent_ip(root, ev);
    }
    if ev.f[F_LOCATION].is_some() {
        location(root, ev, false);
        agentless(root, ev);
    }
    if let Some(g) = ev.generated_rule.and_then(|r| eng.rules.rules[r].group.clone()) {
        groups(root, g.as_bytes());
    }
    if !ev.buf.is_empty() && is_rootcheck(root) {
        rootcheck(root, ev);
    }
    if ev.labels.iter().any(|l| !l.system) {
        let mut labels = Json::object();
        for l in ev.labels.iter().filter(|l| !l.system && (!l.hidden || eng.settings.show_hidden_labels)) {
            add_field(&mut labels, &l.key, &l.value);
        }
        if let Some(a) = root.get_mut("agent") {
            a.add("labels", labels);
        }
    }
}

fn syslog_host() -> &'static regex::bytes::Regex {
    static R: OnceLock<regex::bytes::Regex> = OnceLock::new();
    R.get_or_init(|| regex::bytes::Regex::new(r"(?-u)^[A-Z][a-z][a-z] [ 0123][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] ([^ ]+)").expect("pattern"))
}

fn host_name(root: &mut Json, ev: &Event) {
    let loc = ev.f[F_LOCATION].as_deref().unwrap_or(b"");
    if loc.first() == Some(&b'(') {
        if let Some(a) = root.get_mut("agent") {
            a.add("name", s(ev.hostname.as_deref().unwrap_or(b"")));
        }
    } else if ev.agent_id.as_deref() == Some(b"000") {
        let name = root.get("manager").and_then(|m| m.get("name")).cloned();
        if let (Some(n), Some(a)) = (name, root.get_mut("agent")) {
            a.add("name", n);
        }
    }
    if let Some(c) = syslog_host().captures(ev.full_log()) {
        let h = c.get(1).map(|m| m.as_bytes().to_vec()).unwrap_or_default();
        if root.get("predecoder").is_none() {
            root.add("predecoder", Json::object());
        }
        if let Some(p) = root.get_mut("predecoder") {
            p.add("hostname", Json::String(h));
        }
    }
}

fn agent_ip(root: &mut Json, ev: &Event) {
    let from_label = ev.labels.iter().find(|l| l.key == b"_agent_ip").map(|l| l.value.clone());
    let ip = from_label.or_else(|| {
        let loc = ev.f[F_LOCATION].as_deref().unwrap_or(b"");
        if loc.first() != Some(&b'(') {
            return None;
        }
        let p = loc.iter().position(|&c| c == b')')?;
        let mut v = loc[(p + 2).min(loc.len())..].to_vec();
        if let Some(d) = v.iter().position(|&c| c == b'-') {
            v.truncate(d);
        }
        Some(v)
    });
    if let Some(ip) = ip.filter(|ip| ip != b"any") {
        if let Some(a) = root.get_mut("agent") {
            a.add("ip", Json::String(ip));
        }
    }
}

/// `location` (or `location_desc` for archives): after `->` for agent locations.
pub fn location(root: &mut Json, ev: &Event, archives: bool) {
    let key = if archives { "location_desc" } else { "location" };
    let loc = ev.f[F_LOCATION].as_deref().unwrap_or(b"");
    if loc.first() == Some(&b'(') {
        let l = &loc[..loc.len().min(MAX_TEXT - 1)];
        if let Some(p) = l.iter().position(|&c| c == b'>') {
            root.add(key, s(&l[p + 1..]));
        }
    } else {
        root.add(key, s(loc));
    }
}

/// `(script) user@host->...` from the manager: an `agentless` object instead of `agent`.
fn agentless(root: &mut Json, ev: &Event) {
    let loc = ev.f[F_LOCATION].as_deref().unwrap_or(b"");
    if loc.first() != Some(&b'(') || ev.agent_id.as_deref() != Some(b"000") {
        return;
    }
    let all = &loc[1..];
    let Some(u) = find(all, b") ") else { return };
    let rest = &all[u + 2..];
    let Some(at) = rest.iter().position(|&c| c == b'@') else { return };
    let host_all = &rest[at + 1..];
    let Some(e) = find(host_all, b"->") else { return };
    let mut a = Json::object();
    a.add("script", s(&all[..u]));
    a.add("user", s(&rest[..at]));
    a.add("host", s(&host_all[..e]));
    root.add("agentless", a);
    root.remove("agent");
}

fn space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn trim(v: &[u8]) -> Vec<u8> {
    let end = v.iter().rposition(|&c| !space(c)).map_or(0, |p| p + 1);
    let start = v[..end].iter().position(|&c| !space(c)).unwrap_or(end);
    v[start..end].to_vec()
}

/// The rule groups: compliance groups (`pci_dss_10.2.4` ...) go to their own arrays, then
/// the SCA check's compliance.
fn groups(root: &mut Json, group: &[u8]) {
    const COMPLIANCE: [(&[u8], &str); 7] = [(b"pci_dss_", "pci_dss"), (b"cis_", "cis"), (b"gdpr_", "gdpr"), (b"gpg13_", "gpg13"), (b"hipaa_", "hipaa"), (b"nist_800_53_", "nist_800_53"), (b"tsc_", "tsc")];
    let Some(rule) = root.get_mut("rule") else { return };
    rule.add("groups", Json::array());
    let mut plain = Vec::new();
    let mut seen = [false; 7];
    for tok in group[..group.len().min(MAX_TEXT - 1)].split(|&c| c == b',').filter(|t| !t.is_empty()) {
        match COMPLIANCE.iter().position(|(p, _)| tok.starts_with(p)) {
            Some(i) => {
                let v = Json::String(tok[COMPLIANCE[i].0.len()..].to_vec());
                if seen[i] {
                    if let Some(a) = rule.get_mut(COMPLIANCE[i].1) {
                        a.push(v);
                    }
                } else {
                    rule.add(COMPLIANCE[i].1, Json::Array(vec![v]));
                    seen[i] = true;
                }
            }
            None => plain.push(Json::String(tok.to_vec())),
        }
    }
    if let Some(g) = rule.get_mut("groups") {
        *g = Json::Array(plain);
    }
    let compliance: Option<Vec<(Vec<u8>, Option<Vec<u8>>)>> = root.get("data").and_then(|d| d.get("sca")).and_then(|x| x.get("check")).and_then(|c| c.get("compliance")).map(|c| match c {
        Json::Object(m) => m.iter().map(|(k, v)| (k.clone(), v.as_bytes().map(<[u8]>::to_vec))).collect(),
        Json::Array(a) => a.iter().map(|v| (Vec::new(), v.as_bytes().map(<[u8]>::to_vec))).collect(),
        _ => Vec::new(),
    });
    if let (Some(list), Some(rule)) = (compliance, root.get_mut("rule")) {
        for (k, v) in list {
            let Some(v) = v else { continue };
            let items: Vec<Json> = v.split(|&c| c == b',').filter(|t| !t.is_empty()).map(trim).filter(|t| !t.is_empty()).map(Json::String).collect();
            match rule.get_mut_bytes(&k) {
                Some(g) => {
                    for i in items {
                        g.push(i);
                    }
                }
                None if !items.is_empty() => {
                    rule.add(&k, Json::Array(items));
                }
                None => {}
            }
        }
    }
}

fn is_rootcheck(root: &Json) -> bool {
    root.get("rule").and_then(|r| r.get("groups")).is_some_and(|g| g.children().iter().any(|x| x.print() == b"\"rootcheck\""))
}

fn rootcheck_pattern() -> &'static regex::bytes::Regex {
    static R: OnceLock<regex::bytes::Regex> = OnceLock::new();
    R.get_or_init(|| regex::bytes::Regex::new(r"(?-u)\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\}").expect("pattern"))
}

/// `{name: a, b}` parts of a rootcheck log become rule arrays (at most 10, each part cut to
/// 29 bytes).
fn rootcheck(root: &mut Json, ev: &Event) {
    let full = ev.full_log();
    let text = &full[..full.len().min(MAX_TEXT - 1)];
    let mut found: Vec<Vec<u8>> = Vec::new();
    let mut at = 0;
    'scan: while found.len() < 10 {
        let Some(c) = rootcheck_pattern().captures(&text[at..]) else { break };
        for i in 1..c.len() {
            let Some(g) = c.get(i) else { break };
            let mut t = g.as_bytes().to_vec();
            t.truncate(29);
            found.push(t);
            if found.len() >= 10 {
                break 'scan;
            }
        }
        let end = c.get(0).map_or(0, |m| m.end());
        if end == 0 {
            break;
        }
        at += end;
    }
    let Some(rule) = root.get_mut("rule") else { return };
    for f in found {
        let mut parts = f.split(|&c| c == b':').filter(|t| !t.is_empty());
        let Some(name) = parts.next() else { continue };
        let name: Vec<u8> = trim(name).to_ascii_lowercase();
        let values = parts.next().map(|r| trim(r).split(|&c| c == b',').filter(|t| !t.is_empty()).map(|t| Json::String(trim(t))).collect()).unwrap_or_default();
        rule.add(name, Json::Array(values));
    }
}

// ---------------------------------------------------------------- file integrity

/// Positions of the file integrity fields.
pub mod fim {
    pub const FILE: usize = 0;
    pub const HARD_LINKS: usize = 1;
    pub const MODE: usize = 2;
    pub const SIZE: usize = 3;
    pub const SIZE_BEFORE: usize = 4;
    pub const PERM: usize = 5;
    pub const PERM_BEFORE: usize = 6;
    pub const UID: usize = 7;
    pub const UID_BEFORE: usize = 8;
    pub const GID: usize = 9;
    pub const GID_BEFORE: usize = 10;
    pub const MD5: usize = 11;
    pub const MD5_BEFORE: usize = 12;
    pub const SHA1: usize = 13;
    pub const SHA1_BEFORE: usize = 14;
    pub const UNAME: usize = 15;
    pub const UNAME_BEFORE: usize = 16;
    pub const GNAME: usize = 17;
    pub const GNAME_BEFORE: usize = 18;
    pub const MTIME: usize = 19;
    pub const MTIME_BEFORE: usize = 20;
    pub const INODE: usize = 21;
    pub const INODE_BEFORE: usize = 22;
    pub const SHA256: usize = 23;
    pub const SHA256_BEFORE: usize = 24;
    pub const DIFF: usize = 25;
    pub const ATTRS: usize = 26;
    pub const ATTRS_BEFORE: usize = 27;
    pub const CHFIELDS: usize = 28;
    pub const USER_ID: usize = 29;
    pub const USER_NAME: usize = 30;
    pub const GROUP_ID: usize = 31;
    pub const GROUP_NAME: usize = 32;
    pub const PROC_NAME: usize = 33;
    pub const PROC_PNAME: usize = 34;
    pub const AUDIT_CWD: usize = 35;
    pub const AUDIT_PCWD: usize = 36;
    pub const AUDIT_ID: usize = 37;
    pub const AUDIT_NAME: usize = 38;
    pub const EFFECTIVE_UID: usize = 39;
    pub const EFFECTIVE_NAME: usize = 40;
    pub const PPID: usize = 41;
    pub const PROC_ID: usize = 42;
    pub const TAG: usize = 43;
    pub const SYM_PATH: usize = 44;
    pub const REGISTRY_ARCH: usize = 45;
    pub const REGISTRY_VALUE_NAME: usize = 46;
    pub const REGISTRY_VALUE_TYPE: usize = 47;
    pub const REGISTRY_HASH: usize = 48;
    pub const ENTRY_TYPE: usize = 49;
    pub const EVENT_TYPE: usize = 50;
    pub const COUNT: usize = 51;
}

fn fim_field(ev: &Event, i: usize) -> Option<&[u8]> {
    ev.fields.get(i).and_then(|f| f.value.as_deref())
}

fn some_text(v: Option<&[u8]>) -> Option<&[u8]> {
    v.filter(|x| !x.is_empty())
}

/// The before value when set and different from the after value.
fn before(b: Option<&[u8]>, a: Option<&[u8]>) -> Option<Vec<u8>> {
    b.filter(|b| !b.is_empty() && a != Some(*b)).map(<[u8]>::to_vec)
}

/// `a, b, c` as an array (leading spaces of each part removed).
pub fn attributes_json(v: &[u8]) -> Json {
    Json::Array(v.split(|&c| c == b',').map(|p| Json::String(p[p.iter().position(|&c| c != b' ').unwrap_or(p.len())..].to_vec())).collect())
}

/// `user (allowed): PERM|PERM, ...` as `[{"name": user, "allowed": [PERM, ...]}, ...]`; None
/// when a permission list has no names or nothing was read.
pub fn windows_permissions_json(perms: &[u8]) -> Option<Json> {
    let mut out: Vec<Json> = Vec::new();
    for node in perms.split(|&c| c == b',') {
        let node = &node[node.iter().position(|&c| c != b' ').unwrap_or(node.len())..];
        let Some(open) = node.iter().position(|&c| c == b'(') else { continue };
        let mut user = node[..open].to_vec();
        if user.last() == Some(&b' ') {
            user.pop();
        }
        let after = &node[open + 1..];
        let Some(close) = after.iter().position(|&c| c == b')') else { continue };
        let kind = after[..close].to_vec();
        let mut list = &after[close + 1..];
        if list.first() == Some(&b':') {
            list = &list[1..];
        }
        let list = &list[list.iter().position(|&c| c != b' ').unwrap_or(list.len())..];
        // the user's object, unless it already has this kind
        let at = out.iter().position(|j| j.get("name").and_then(|n| n.as_bytes()) == Some(user.as_slice()));
        if at.is_some_and(|i| out[i].get_bytes(&kind).is_some()) {
            continue;
        }
        let i = at.unwrap_or_else(|| {
            let mut o = Json::object();
            o.add("name", Json::String(user.clone()));
            out.push(o);
            out.len() - 1
        });
        if list.is_empty() {
            out[i].add(&kind, Json::array());
            continue;
        }
        let names: Vec<Json> = list.split(|&c| c == b'|').filter(|t| !t.is_empty()).map(|t| Json::String(t.to_ascii_uppercase())).collect();
        if names.is_empty() {
            return None;
        }
        out[i].add(&kind, Json::Array(names));
    }
    (!out.is_empty()).then_some(Json::Array(out))
}

/// C-style `strtol` of a field (saturating).
fn long(v: &[u8]) -> i64 {
    let mut i = v.iter().take_while(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)).count();
    let neg = v.get(i) == Some(&b'-');
    if matches!(v.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    let mut n: u64 = 0;
    let mut over = false;
    while let Some(c) = v.get(i).filter(|c| c.is_ascii_digit()) {
        match n.checked_mul(10).and_then(|x| x.checked_add(u64::from(c - b'0'))) {
            Some(x) => n = x,
            None => over = true,
        }
        i += 1;
    }
    match (neg, over || n > i64::MAX as u64 + u64::from(neg)) {
        (true, true) => i64::MIN,
        (false, true) => i64::MAX,
        (true, false) => (n as i64).wrapping_neg(),
        (false, false) => n as i64,
    }
}

/// A modification time as local `YYYY-MM-DDThh:mm:ss` (the zone does not fit the buffer),
/// or `Invalid: '<value>'` cut to 23 bytes; both kept in one 25-byte buffer.
fn mtime(buf: &mut [u8; 25], v: &[u8]) -> Vec<u8> {
    match crate::time::local(long(v)) {
        Some(tm) => crate::time::write_iso(&mut buf[..], 20, &tm),
        None => {
            let mut m = [&b"Invalid: '"[..], v, b"'"].concat();
            m.truncate(23);
            buf[..m.len()].copy_from_slice(&m);
            buf[m.len()] = 0;
        }
    }
    text_at(&buf[..], 0).to_vec()
}

fn tokens(v: &[u8]) -> Json {
    Json::Array(v.split(|&c| c == b',').filter(|t| !t.is_empty()).map(|t| Json::String(t.to_vec())).collect())
}

/// The `syscheck` object.
pub fn syscheck_section(ev: &Event, order_size: usize, msgs: &mut Messages) -> Json {
    use fim::*;
    let f = |i| fim_field(ev, i);
    let mut d = Json::object();
    if let Some(v) = f(FILE) {
        d.add("path", s(v));
    }
    if let Some(j) = some_text(f(HARD_LINKS)).and_then(provigil_json::parse) {
        d.add("hard_links", j);
    }
    if let Some(v) = f(MODE) {
        d.add("mode", s(v));
    }
    if let Some(v) = some_text(f(SYM_PATH)) {
        d.add("symbolic_path", s(v));
    }
    for (k, i) in [("arch", REGISTRY_ARCH), ("value_name", REGISTRY_VALUE_NAME), ("value_type", REGISTRY_VALUE_TYPE)] {
        if let Some(v) = f(i) {
            d.add(k, s(v));
        }
    }
    if let Some(b) = before(f(SIZE_BEFORE), f(SIZE)) {
        d.add("size_before", Json::String(b));
    }
    if let Some(v) = some_text(f(SIZE)) {
        d.add("size_after", s(v));
    }
    if let Some(b) = before(f(PERM_BEFORE), f(PERM)) {
        if b.contains(&b'|') {
            match windows_permissions_json(&b) {
                Some(j) => {
                    d.add("win_perm_before", j);
                }
                None => msgs.warn("The old permissions of the Windows event could not be added to the JSON alert."),
            }
        } else {
            d.add("perm_before", Json::String(b));
        }
    }
    if let Some(v) = some_text(f(PERM)) {
        if v.contains(&b'|') {
            match windows_permissions_json(v) {
                Some(j) => {
                    d.add("win_perm_after", j);
                }
                None => msgs.error("The new permissions could not be added to the JSON alert."),
            }
        } else {
            d.add("perm_after", s(v));
        }
    }
    let pair = |d: &mut Json, kb: &str, ka: &str, ib: usize, ia: usize| {
        if let Some(b) = before(f(ib), f(ia)) {
            d.add(kb, Json::String(b));
        }
        if let Some(v) = some_text(f(ia)) {
            d.add(ka, s(v));
        }
    };
    pair(&mut d, "uid_before", "uid_after", UID_BEFORE, UID);
    pair(&mut d, "gid_before", "gid_after", GID_BEFORE, GID);
    pair(&mut d, "md5_before", "md5_after", MD5_BEFORE, MD5);
    pair(&mut d, "sha1_before", "sha1_after", SHA1_BEFORE, SHA1);
    pair(&mut d, "sha256_before", "sha256_after", SHA256_BEFORE, SHA256);
    if let Some(b) = before(f(ATTRS_BEFORE), f(ATTRS)) {
        d.add("attrs_before", attributes_json(&b));
    }
    if let Some(v) = some_text(f(ATTRS)) {
        d.add("attrs_after", attributes_json(v));
    }
    pair(&mut d, "uname_before", "uname_after", UNAME_BEFORE, UNAME);
    pair(&mut d, "gname_before", "gname_after", GNAME_BEFORE, GNAME);
    let mut buf = [0u8; 25];
    if let Some(b) = before(f(MTIME_BEFORE), f(MTIME)) {
        d.add("mtime_before", Json::String(mtime(&mut buf, &b)));
    }
    if let Some(v) = some_text(f(MTIME)) {
        d.add("mtime_after", Json::String(mtime(&mut buf, v)));
    }
    if let Some(b) = before(f(INODE_BEFORE), f(INODE)) {
        d.add("inode_before", Json::number(f64::from(long(&b) as i32)));
    }
    if let Some(n) = f(INODE).map(|v| long(v) as i32).filter(|&n| n != 0) {
        d.add("inode_after", Json::number(f64::from(n)));
    }
    if let Some(v) = f(DIFF).filter(|v| order_size > DIFF && *v != b"0") {
        d.add("diff", s(v));
    }
    if let Some(v) = some_text(f(TAG)) {
        d.add("tags", tokens(v));
    }
    if let Some(v) = some_text(f(CHFIELDS)) {
        d.add("changed_attributes", tokens(v));
    }
    if let Some(v) = f(EVENT_TYPE) {
        d.add("event", s(v));
    }
    d
}

/// The who-data `audit` object; None when no field is set.
pub fn audit_section(ev: &Event) -> Option<Json> {
    use fim::*;
    let object = |pairs: &[(&str, usize)]| {
        let mut o: Option<Json> = None;
        for &(k, i) in pairs {
            if let Some(v) = some_text(fim_field(ev, i)) {
                o.get_or_insert_with(Json::object).add(k, s(v));
            }
        }
        o
    };
    let parts = [
        ("user", object(&[("id", USER_ID), ("name", USER_NAME)])),
        ("process", object(&[("id", PROC_ID), ("name", PROC_NAME), ("cwd", AUDIT_CWD), ("parent_name", PROC_PNAME), ("parent_cwd", AUDIT_PCWD), ("ppid", PPID)])),
        ("group", object(&[("id", GROUP_ID), ("name", GROUP_NAME)])),
        ("login_user", object(&[("id", AUDIT_ID), ("name", AUDIT_NAME)])),
        ("effective_user", object(&[("id", EFFECTIVE_UID), ("name", EFFECTIVE_NAME)])),
    ];
    if parts.iter().all(|(_, o)| o.is_none()) {
        return None;
    }
    let mut a = Json::object();
    for (k, o) in parts {
        if let Some(o) = o {
            a.add(k, o);
        }
    }
    Some(a)
}
