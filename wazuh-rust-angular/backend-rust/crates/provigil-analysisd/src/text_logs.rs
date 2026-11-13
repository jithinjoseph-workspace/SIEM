//! The text outputs (spec section 2.9): alerts.log, the custom alert format, archives.log,
//! firewall.log, and the alerts.json / archives.json lines.

use std::io::Write;

use crate::alert_json::fim;
use crate::engine::Engine;
use crate::event::*;
use crate::messages::Messages;
use crate::rules::*;

fn or_null(v: &Option<Bytes>) -> &[u8] {
    v.as_deref().unwrap_or(b"(null)")
}

/// Agents' keep-alive messages are not archived (the location name agents send).
fn keepalive(loc: &[u8]) -> bool {
    loc == b"ossec-keepalive" || find(loc, b"->ossec-keepalive").is_some()
}

/// `host->` before the location of local events.
fn host_prefix(ev: &Event) -> Vec<u8> {
    if ev.f[F_LOCATION].as_deref().unwrap_or(b"").first() == Some(&b'(') {
        Vec::new()
    } else {
        [or_null(&ev.hostname), b"->"].concat()
    }
}

/// `key: value` lines of the visible labels; nothing when they reach 64 KiB.
fn label_lines(ev: &Event, show_hidden: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for l in ev.labels.iter().filter(|l| !l.system && (!l.hidden || show_hidden)) {
        out.extend_from_slice(&[&l.key[..], b": ", &l.value, b"\n"].concat());
        if out.len() >= 65536 {
            return Vec::new();
        }
    }
    out
}

/// C-style `strtol` (saturating).
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

/// `year mon dd hh:mm:ss `
fn date(ev: &Event) -> Vec<u8> {
    format!("{} {} {:02} {} ", ev.year, ev.mon, ev.day, ev.hour).into_bytes()
}

/// One alert in alerts.log.
pub fn alert(eng: &Engine, ev: &Event, w: &mut dyn Write) -> std::io::Result<()> {
    let r = &eng.rules.rules[ev.generated_rule.expect("an alert has a rule")];
    let mut o = format!("** Alert {}.{}:{} - ", ev.time.sec, eng.alert_counter, if r.alert_opts & DO_MAILALERT != 0 { " mail " } else { "" }).into_bytes();
    o.extend_from_slice(r.group.as_deref().unwrap_or("(null)").as_bytes());
    o.push(b'\n');
    o.extend_from_slice(&date(ev));
    o.extend_from_slice(&host_prefix(ev));
    o.extend_from_slice(or_null(&ev.f[F_LOCATION]));
    o.push(b'\n');
    o.extend_from_slice(&label_lines(ev, eng.settings.show_hidden_labels));
    o.extend_from_slice(format!("Rule: {} (level {}) -> '", r.sigid, r.level).as_bytes());
    o.extend_from_slice(or_null(&ev.comment));
    o.push(b'\'');
    for (label, f) in [(&b"\nSrc IP: "[..], F_SRCIP), (b"\nSrc Port: ", F_SRCPORT), (b"\nDst IP: ", F_DSTIP), (b"\nDst Port: ", F_DSTPORT), (b"\nUser: ", F_DSTUSER)] {
        if GEOIP {
            let geo = match f {
                F_SRCPORT => Some((&b"\nSrc Location: "[..], F_SRCGEOIP)),
                F_DSTPORT => Some((&b"\nDst Location: "[..], F_DSTGEOIP)),
                _ => None,
            };
            if let Some((l, g)) = geo {
                if let Some(v) = &ev.f[g] {
                    o.extend_from_slice(&[l, v].concat());
                }
            }
        }
        if let Some(v) = &ev.f[f] {
            o.extend_from_slice(&[label, v].concat());
        }
    }
    o.push(b'\n');
    o.extend_from_slice(ev.full_log());
    o.push(b'\n');

    let d = &eng.decoders.decoders[ev.decoder];
    let syscheck = d.name.as_deref().is_some_and(|n| n.starts_with("syscheck_"));
    let field = |i: usize| ev.fields.get(i).and_then(|f| f.value.as_deref());
    let set = |i: usize| field(i).filter(|v| !v.is_empty());
    let line = |o: &mut Vec<u8>, label: &[u8], v: &[u8]| o.extend_from_slice(&[label, v, b"\n"].concat());
    if syscheck {
        o.extend_from_slice(b"Attributes:\n");
        if let Some(v) = set(fim::SIZE) {
            line(&mut o, b" - Size: ", v);
        }
        if let Some(v) = set(fim::PERM) {
            line(&mut o, b" - Permissions: ", v);
        }
        if let Some(v) = set(fim::MTIME) {
            // the date text ends with its own newline; a raw value has none
            o.extend_from_slice(b" - Date: ");
            match crate::time::ctime(long(v)) {
                Some(t) => o.extend_from_slice(t.as_bytes()),
                None => o.extend_from_slice(v),
            }
        }
        if let Some(v) = set(fim::INODE) {
            line(&mut o, b" - Inode: ", v);
        }
        for (label, id, name) in [(&b" - User: "[..], fim::UID, fim::UNAME), (b" - Group: ", fim::GID, fim::GNAME)] {
            if let (Some(id), Some(name)) = (field(id), set(name)) {
                o.extend_from_slice(&[label, name, b" (", id, b")\n"].concat());
            }
        }
        for (label, i) in [(&b" - MD5: "[..], fim::MD5), (b" - SHA1: ", fim::SHA1), (b" - SHA256: ", fim::SHA256)] {
            if let Some(v) = set(i).filter(|v| *v != b"xxx") {
                line(&mut o, label, v);
            }
        }
        if let Some(v) = set(fim::ATTRS) {
            line(&mut o, b" - File attributes: ", v);
        }
        for (name, i) in [
            ("User name", fim::USER_NAME),
            ("Audit name", fim::AUDIT_NAME),
            ("Effective name", fim::EFFECTIVE_NAME),
            ("Group name", fim::GROUP_NAME),
            ("Process id", fim::PROC_ID),
            ("Process name", fim::PROC_NAME),
            ("Process cwd", fim::AUDIT_CWD),
            ("Parent process name", fim::PROC_PNAME),
            ("Parent process id", fim::PPID),
            ("Parent process cwd", fim::AUDIT_PCWD),
        ] {
            if let Some(v) = set(i) {
                line(&mut o, format!(" - (Audit) {name}: ").as_bytes(), v);
            }
        }
        if let Some(v) = field(fim::DIFF) {
            line(&mut o, b"\nWhat changed:\n", v);
        }
        if let Some(v) = set(fim::TAG) {
            o.extend_from_slice(b"\nTags:\n");
            for t in v.split(|&c| c == b',').filter(|t| !t.is_empty()) {
                line(&mut o, b" - ", t);
            }
        }
    }
    if d.name.is_some() && !syscheck {
        for f in &ev.fields {
            if let Some(v) = f.value.as_deref().filter(|v| !v.is_empty()) {
                o.extend_from_slice(&[&f.key[..], b": ", v, b"\n"].concat());
            }
        }
    }
    for l in ev.last_events.iter().flatten() {
        o.extend_from_slice(l);
        o.push(b'\n');
    }
    o.push(b'\n');
    w.write_all(&o)
}

/// Every `search` replaced by `value`.
pub fn replace_all(text: &[u8], search: &[u8], value: &[u8]) -> Vec<u8> {
    if search.is_empty() {
        return text.to_vec();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = find(&text[i..], search) {
        out.extend_from_slice(&text[i..i + p]);
        out.extend_from_slice(value);
        i += p + search.len();
    }
    out.extend_from_slice(&text[i..]);
    out
}

/// Line breaks (`\n`, `\r`) written as `\n`.
pub fn escape_newlines(s: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(s.len());
    for &c in s {
        if c == b'\n' || c == b'\r' {
            o.extend_from_slice(b"\\n");
        } else {
            o.push(c);
        }
    }
    o
}

fn first_1023(v: &[u8]) -> Vec<u8> {
    v[..v.len().min(1023)].to_vec()
}

/// One alert in the `<custom_alert_output>` format ($TIMESTAMP, $FTELL, $RULEALERT,
/// $HOSTNAME, $LOCATION, $RULEID, $RULELEVEL, $SRCIP, $DSTUSER, $FULLLOG, $RULECOMMENT,
/// $RULEGROUP, replaced in this order).
pub fn custom_alert(eng: &Engine, ev: &Event, format: &[u8], w: &mut dyn Write) -> std::io::Result<()> {
    let r = &eng.rules.rules[ev.generated_rule.expect("an alert has a rule")];
    let or_none = |v: &Option<Bytes>| first_1023(v.as_deref().unwrap_or(b"None"));
    let values: [(&[u8], Vec<u8>); 12] = [
        (b"$TIMESTAMP", ev.time.sec.to_string().into_bytes()),
        (b"$FTELL", eng.alert_counter.to_string().into_bytes()),
        (b"$RULEALERT", if r.alert_opts & DO_MAILALERT != 0 { b"mail ".to_vec() } else { Vec::new() }),
        (b"$HOSTNAME", or_none(&ev.hostname)),
        (b"$LOCATION", or_none(&ev.f[F_LOCATION])),
        (b"$RULEID", r.sigid.to_string().into_bytes()),
        (b"$RULELEVEL", r.level.to_string().into_bytes()),
        (b"$SRCIP", or_none(&ev.f[F_SRCIP])),
        (b"$DSTUSER", or_none(&ev.f[F_DSTUSER])),
        (b"$FULLLOG", escape_newlines(ev.full_log())),
        (b"$RULECOMMENT", first_1023(ev.comment.as_deref().unwrap_or(b""))),
        (b"$RULEGROUP", first_1023(r.group.as_deref().unwrap_or("").as_bytes())),
    ];
    let mut out = format.to_vec();
    for (k, v) in &values {
        out = replace_all(&out, k, v);
    }
    out.push(b'\n');
    w.write_all(&out)
}

/// One event in archives.log (keep-alives left out).
pub fn archive(ev: &Event, w: &mut dyn Write) -> std::io::Result<()> {
    let loc = ev.f[F_LOCATION].as_deref().unwrap_or(b"(null)");
    if keepalive(loc) {
        return Ok(());
    }
    let mut o = date(ev);
    o.extend_from_slice(&host_prefix(ev));
    o.extend_from_slice(&[loc, b" ", ev.full_log(), b"\n"].concat());
    w.write_all(&o)
}

/// The action as DROP, CLOSED, ALLOW or UNKNOWN (by its first letter, else by the words
/// "drop" / "accept"; a "drop" then fails the "accept" test, so it ends as UNKNOWN).
fn firewall_action(a: &[u8]) -> &'static [u8] {
    match a.first().copied().unwrap_or(0) {
        b'd' | b'D' | b'r' | b'R' | b'b' | b'B' => b"DROP",
        b'c' | b'C' | b't' | b'T' => b"CLOSED",
        b'a' | b'A' | b'p' | b'P' | b'o' | b'O' => b"ALLOW",
        _ => {
            let has = |p: &str, v: &[u8]| provigil_regex::OsMatch::compile(p, 0).is_ok_and(|m| m.is_match_bytes(v));
            let now: &[u8] = if has("drop", a) { b"DROP" } else { a };
            if has("accept", now) {
                b"ALLOW"
            } else {
                b"UNKNOWN"
            }
        }
    }
}

/// One event in firewall.log; the event's action becomes the normalised one.
pub fn firewall(ev: &mut Event, w: &mut dyn Write) -> std::io::Result<()> {
    let action = firewall_action(ev.f[F_ACTION].as_deref().unwrap_or(b""));
    ev.f[F_ACTION] = Some(action.to_vec());
    let mut o = date(ev);
    o.extend_from_slice(&host_prefix(ev));
    o.extend_from_slice(or_null(&ev.f[F_LOCATION]));
    for (sep, v) in [(&b" "[..], action), (b" ", or_null(&ev.f[F_PROTOCOL])), (b" ", or_null(&ev.f[F_SRCIP])), (b":", or_null(&ev.f[F_SRCPORT])), (b"->", or_null(&ev.f[F_DSTIP])), (b":", or_null(&ev.f[F_DSTPORT]))] {
        o.extend_from_slice(sep);
        o.extend_from_slice(v);
    }
    o.push(b'\n');
    w.write_all(&o)
}

/// An alerts.json line.
pub fn json_alert(eng: &Engine, ev: &Event, msgs: &mut Messages) -> Vec<u8> {
    let mut v = crate::alert_json::alert(eng, ev, false, msgs);
    v.push(b'\n');
    v
}

/// An archives.json line (keep-alives left out).
pub fn json_archive(eng: &Engine, ev: &Event, msgs: &mut Messages) -> Option<Vec<u8>> {
    if keepalive(ev.f[F_LOCATION].as_deref().unwrap_or(b"")) {
        return None;
    }
    let mut v = crate::alert_json::alert(eng, ev, true, msgs);
    v.push(b'\n');
    Some(v)
}
