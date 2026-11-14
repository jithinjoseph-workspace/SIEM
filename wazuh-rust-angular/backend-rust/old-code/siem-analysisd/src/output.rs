//! Alert, archive and firewall log formats (analysisd/alerts/log.c and
//! analysisd/output/jsonout.c): `OS_Log`, `OS_CustomLog`, `OS_Store`,
//! `FW_Log`, `jsonout_output_event`, `jsonout_output_archive`.

use std::io::Write;

use crate::engine::Engine;
use crate::event::*;
use crate::logmsg::LogList;
use crate::rules::*;
use crate::syscheck_json::fim;

fn opt(v: &Option<Bytes>) -> &[u8] {
    v.as_deref().unwrap_or(b"(null)")
}

fn is_keepalive(loc: &[u8]) -> bool {
    loc == b"ossec-keepalive" || find_sub(loc, b"->ossec-keepalive").is_some()
}

fn agent_prefix(ev: &Event) -> (&[u8], &[u8]) {
    let loc = ev.f[F_LOCATION].as_deref().unwrap_or(b"");
    if loc.first() != Some(&b'(') {
        (opt(&ev.hostname), b"->")
    } else {
        (b"", b"")
    }
}

/// `format_labels`
fn format_labels(ev: &Event, show_hidden: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for l in &ev.labels {
        if !l.flags.system && (!l.flags.hidden || show_hidden) {
            out.extend_from_slice(&l.key);
            out.extend_from_slice(b": ");
            out.extend_from_slice(&l.value);
            out.push(b'\n');
            if out.len() >= 65536 {
                return Vec::new();
            }
        }
    }
    out
}

/// `ctime_r`: "Www Mmm dd hh:mm:ss yyyy\n"
fn ctime(t: i64) -> Option<String> {
    crate::localtime::ctime(t)
}

fn atol(v: &[u8]) -> i64 {
    crate::internal::rootcheck::strtol(v)
}

#[allow(dead_code)]
fn atol_wrapping(v: &[u8]) -> i64 {
    let s = String::from_utf8_lossy(v);
    let s = s.trim_start();
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let mut n: i64 = 0;
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            break;
        }
        n = n.wrapping_mul(10).wrapping_add((c - b'0') as i64);
    }
    if neg {
        -n
    } else {
        n
    }
}

/// `OS_Log`
pub fn os_log(eng: &Engine, ev: &Event, w: &mut dyn Write) -> std::io::Result<()> {
    let rule = &eng.rules.infos[ev.generated_rule.expect("generated rule")];
    let labels = format_labels(ev, eng.cfg.show_hidden_labels);
    let (host, arrow) = agent_prefix(ev);
    let mut o: Vec<u8> = Vec::new();
    o.extend_from_slice(
        format!(
            "** Alert {}.{}:{} - ",
            ev.time.sec,
            eng.alert_second_id,
            if rule.alert_opts & DO_MAILALERT != 0 { " mail " } else { "" }
        )
        .as_bytes(),
    );
    o.extend_from_slice(rule.group.as_deref().unwrap_or("(null)").as_bytes());
    o.extend_from_slice(format!("\n{} {} {:02} {} ", ev.year, ev.mon, ev.day, ev.hour).as_bytes());
    o.extend_from_slice(host);
    o.extend_from_slice(arrow);
    o.extend_from_slice(ev.f[F_LOCATION].as_deref().unwrap_or(b"(null)"));
    o.push(b'\n');
    o.extend_from_slice(&labels);
    o.extend_from_slice(format!("Rule: {} (level {}) -> '", rule.sigid, rule.level).as_bytes());
    o.extend_from_slice(opt(&ev.comment));
    o.push(b'\'');
    for (label, idx) in [
        (&b"\nSrc IP: "[..], F_SRCIP),
        (b"\nSrc Port: ", F_SRCPORT),
        (b"\nDst IP: ", F_DSTIP),
        (b"\nDst Port: ", F_DSTPORT),
        (b"\nUser: ", F_DSTUSER),
    ] {
        if crate::GEOIP_ENABLED {
            if idx == F_SRCPORT {
                if let Some(g) = &ev.f[F_SRCGEOIP] {
                    o.extend_from_slice(b"\nSrc Location: ");
                    o.extend_from_slice(g);
                }
            }
            if idx == F_DSTPORT {
                if let Some(g) = &ev.f[F_DSTGEOIP] {
                    o.extend_from_slice(b"\nDst Location: ");
                    o.extend_from_slice(g);
                }
            }
        }
        if let Some(v) = &ev.f[idx] {
            o.extend_from_slice(label);
            o.extend_from_slice(v);
        }
    }
    o.push(b'\n');
    o.extend_from_slice(ev.full_log());
    o.push(b'\n');

    let dec = &eng.decoders.infos[ev.decoder];
    let is_syscheck = dec.name.as_deref().map_or(false, |n| n.starts_with("syscheck_"));
    let fv = |i: usize| ev.fields.get(i).and_then(|f| f.value.as_deref());
    let ne = |i: usize| fv(i).filter(|v| !v.is_empty());
    if is_syscheck {
        o.extend_from_slice(b"Attributes:\n");
        if let Some(v) = ne(fim::SIZE) {
            o.extend_from_slice(b" - Size: ");
            o.extend_from_slice(v);
            o.push(b'\n');
        }
        if let Some(v) = ne(fim::PERM) {
            o.extend_from_slice(b" - Permissions: ");
            o.extend_from_slice(v);
            o.push(b'\n');
        }
        if let Some(v) = ne(fim::MTIME) {
            o.extend_from_slice(b" - Date: ");
            match ctime(atol(v)) {
                Some(s) => o.extend_from_slice(s.as_bytes()),
                None => o.extend_from_slice(v),
            }
        }
        if let Some(v) = ne(fim::INODE) {
            o.extend_from_slice(b" - Inode: ");
            o.extend_from_slice(v);
            o.push(b'\n');
        }
        if let (Some(uid), Some(uname)) = (fv(fim::UID), ne(fim::UNAME)) {
            o.extend_from_slice(b" - User: ");
            o.extend_from_slice(uname);
            o.extend_from_slice(b" (");
            o.extend_from_slice(uid);
            o.extend_from_slice(b")\n");
        }
        if let (Some(gid), Some(gname)) = (fv(fim::GID), ne(fim::GNAME)) {
            o.extend_from_slice(b" - Group: ");
            o.extend_from_slice(gname);
            o.extend_from_slice(b" (");
            o.extend_from_slice(gid);
            o.extend_from_slice(b")\n");
        }
        for (label, i) in [(&b" - MD5: "[..], fim::MD5), (b" - SHA1: ", fim::SHA1), (b" - SHA256: ", fim::SHA256)] {
            if let Some(v) = ne(i) {
                if v != b"xxx" {
                    o.extend_from_slice(label);
                    o.extend_from_slice(v);
                    o.push(b'\n');
                }
            }
        }
        if let Some(v) = ne(fim::ATTRS) {
            o.extend_from_slice(b" - File attributes: ");
            o.extend_from_slice(v);
            o.push(b'\n');
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
            if let Some(v) = ne(i) {
                o.extend_from_slice(format!(" - (Audit) {name}: ").as_bytes());
                o.extend_from_slice(v);
                o.push(b'\n');
            }
        }
        if let Some(v) = fv(fim::DIFF) {
            o.extend_from_slice(b"\nWhat changed:\n");
            o.extend_from_slice(v);
            o.push(b'\n');
        }
        if let Some(v) = ne(fim::TAG) {
            o.extend_from_slice(b"\nTags:\n");
            for t in v.split(|&c| c == b',').filter(|t| !t.is_empty()) {
                o.extend_from_slice(b" - ");
                o.extend_from_slice(t);
                o.push(b'\n');
            }
        }
    }
    if dec.name.is_some() && !is_syscheck {
        for f in &ev.fields {
            if let Some(v) = &f.value {
                if !v.is_empty() {
                    o.extend_from_slice(&f.key);
                    o.extend_from_slice(b": ");
                    o.extend_from_slice(v);
                    o.push(b'\n');
                }
            }
        }
    }
    if let Some(le) = &ev.last_events {
        for l in le {
            o.extend_from_slice(l);
            o.push(b'\n');
        }
    }
    o.push(b'\n');
    w.write_all(&o)
}

/// `searchAndReplace` (all occurrences).
pub fn search_and_replace(orig: &[u8], search: &[u8], value: &[u8]) -> Vec<u8> {
    if search.is_empty() {
        return orig.to_vec();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = find_sub(&orig[i..], search) {
        out.extend_from_slice(&orig[i..i + p]);
        out.extend_from_slice(value);
        i += p + search.len();
    }
    out.extend_from_slice(&orig[i..]);
    out
}

/// `escape_newlines`: '\n' and '\r' become "\n".
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

/// `snprintf(tmp_buffer, 1024, "%s", v)`
fn buf1024(v: &[u8]) -> Vec<u8> {
    v[..v.len().min(1023)].to_vec()
}

/// `OS_CustomLog`
pub fn os_custom_log(eng: &Engine, ev: &Event, format: &[u8], w: &mut dyn Write) -> std::io::Result<()> {
    let rule = &eng.rules.infos[ev.generated_rule.expect("generated rule")];
    let none = |v: &Option<Bytes>| -> Vec<u8> { buf1024(v.as_deref().unwrap_or(b"None")) };
    let mut log = format.to_vec();
    log = search_and_replace(&log, b"$TIMESTAMP", ev.time.sec.to_string().as_bytes());
    log = search_and_replace(&log, b"$FTELL", eng.alert_second_id.to_string().as_bytes());
    log = search_and_replace(&log, b"$RULEALERT", if rule.alert_opts & DO_MAILALERT != 0 { b"mail " } else { b"" });
    log = search_and_replace(&log, b"$HOSTNAME", &none(&ev.hostname));
    log = search_and_replace(&log, b"$LOCATION", &none(&ev.f[F_LOCATION]));
    log = search_and_replace(&log, b"$RULEID", rule.sigid.to_string().as_bytes());
    log = search_and_replace(&log, b"$RULELEVEL", rule.level.to_string().as_bytes());
    log = search_and_replace(&log, b"$SRCIP", &none(&ev.f[F_SRCIP]));
    log = search_and_replace(&log, b"$DSTUSER", &none(&ev.f[F_DSTUSER]));
    log = search_and_replace(&log, b"$FULLLOG", &escape_newlines(ev.full_log()));
    log = search_and_replace(&log, b"$RULECOMMENT", &buf1024(ev.comment.as_deref().unwrap_or(b"")));
    log = search_and_replace(&log, b"$RULEGROUP", &buf1024(rule.group.as_deref().unwrap_or("").as_bytes()));
    log.push(b'\n');
    w.write_all(&log)
}

/// `OS_Store` (archives.log)
pub fn os_store(ev: &Event, w: &mut dyn Write) -> std::io::Result<()> {
    let loc = ev.f[F_LOCATION].as_deref().unwrap_or(b"(null)");
    if is_keepalive(loc) {
        return Ok(());
    }
    let (host, arrow) = agent_prefix(ev);
    let mut o = format!("{} {} {:02} {} ", ev.year, ev.mon, ev.day, ev.hour).into_bytes();
    o.extend_from_slice(host);
    o.extend_from_slice(arrow);
    o.extend_from_slice(loc);
    o.push(b' ');
    o.extend_from_slice(ev.full_log());
    o.push(b'\n');
    w.write_all(&o)
}

/// `FW_Log`: normalises `action` (on the event) and writes firewall.log.
pub fn fw_log(ev: &mut Event, w: &mut dyn Write) -> std::io::Result<()> {
    let action = ev.f[F_ACTION].clone().unwrap_or_default();
    let new: &[u8] = match action.first().copied().unwrap_or(0) {
        b'd' | b'D' | b'r' | b'R' | b'b' | b'B' => b"DROP",
        b'c' | b'C' | b't' | b'T' => b"CLOSED",
        b'a' | b'A' | b'p' | b'P' | b'o' | b'O' => b"ALLOW",
        _ => {
            // A "drop" match sets DROP, which the following "accept" test
            // (run on the new value) turns into UNKNOWN.
            let m = |p: &str, v: &[u8]| siem_regex::OsMatch::compile(p, 0).map(|m| m.is_match_bytes(v)).unwrap_or(false);
            let cur: &[u8] = if m("drop", &action) { b"DROP" } else { &action };
            if m("accept", cur) {
                b"ALLOW"
            } else {
                b"UNKNOWN"
            }
        }
    };
    ev.f[F_ACTION] = Some(new.to_vec());
    let (host, arrow) = agent_prefix(ev);
    let mut o = format!("{} {} {:02} {} ", ev.year, ev.mon, ev.day, ev.hour).into_bytes();
    o.extend_from_slice(host);
    o.extend_from_slice(arrow);
    o.extend_from_slice(ev.f[F_LOCATION].as_deref().unwrap_or(b"(null)"));
    o.push(b' ');
    o.extend_from_slice(new);
    o.push(b' ');
    o.extend_from_slice(opt(&ev.f[F_PROTOCOL]));
    o.push(b' ');
    o.extend_from_slice(opt(&ev.f[F_SRCIP]));
    o.push(b':');
    o.extend_from_slice(opt(&ev.f[F_SRCPORT]));
    o.extend_from_slice(b"->");
    o.extend_from_slice(opt(&ev.f[F_DSTIP]));
    o.push(b':');
    o.extend_from_slice(opt(&ev.f[F_DSTPORT]));
    o.push(b'\n');
    w.write_all(&o)
}

/// `jsonout_output_event` (alerts.json line)
pub fn json_alert(eng: &Engine, ev: &Event, log: &mut LogList) -> Vec<u8> {
    let mut v = crate::to_json::eventinfo_to_json(eng, ev, false, log);
    v.push(b'\n');
    v
}

/// `jsonout_output_archive` (archives.json line; keepalives skipped)
pub fn json_archive(eng: &Engine, ev: &Event, log: &mut LogList) -> Option<Vec<u8>> {
    let loc = ev.f[F_LOCATION].as_deref().unwrap_or(b"");
    if is_keepalive(loc) {
        return None;
    }
    let mut v = crate::to_json::eventinfo_to_json(eng, ev, true, log);
    v.push(b'\n');
    Some(v)
}
