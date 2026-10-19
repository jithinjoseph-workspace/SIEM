//! `os_csyslogd/alert.c` and the field helpers of `csyslogd.c`: one alert
//! to one syslog server.

use siem_cjson::Json;
use siem_maild::alert::{atoi, AlertData};
use siem_maild::log;

use crate::config::{Syslog, CEF_CSYSLOG, DEFAULT_CSYSLOG, JSON_CSYSLOG, SPLUNK_CSYSLOG};
use crate::{connect_udp, ip_of, resolve_hostname, send_udp, Hostnames};

const OS_SIZE_2048: usize = 2048;
const OS_SIZE_61440: usize = 61440;
const OS_MAXSTR: usize = 65536;

/// The skip test of `field_add_string`/`field_add_truncated` (meant to drop
/// "(none)"/"unknown"; as written it drops less). Bytes past the end read as 0.
fn wanted(v: &[u8]) -> bool {
    let b = |i: usize| v.get(i).copied().unwrap_or(0);
    (b(0) != b'(' && b(1) != b'n' && b(2) != b'o') || (b(0) != b'(' && b(1) != b'u' && b(2) != b'n') || (b(0) != b'u' && b(1) != b'n' && b(4) != b'k')
}

/// `printf("%s", NULL)` prints "(null)".
fn s(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("(null)")
}

fn snprintf(text: String, size: usize) -> Vec<u8> {
    let mut b = text.into_bytes();
    b.truncate(size.saturating_sub(1));
    b
}

/// `field_add_string(dest, 2048, fmt, value)`: the would-be length of the field.
fn field_add_string(dest: &mut Vec<u8>, pre: &str, value: Option<&str>, post: &str) -> i64 {
    let dest_sz = OS_SIZE_2048 as i64 - dest.len() as i64;
    if dest_sz <= 0 {
        return -1;
    }
    let Some(v) = value else { return 0 };
    if !wanted(v.as_bytes()) {
        return 0;
    }
    let piece = format!("{pre}{v}{post}").into_bytes();
    let len = piece.len() as i64;
    let mut buf = piece;
    buf.truncate((OS_MAXSTR as i64 - dest_sz - 2).max(0) as usize);
    buf.truncate(dest_sz as usize);
    dest.extend_from_slice(&buf);
    len
}

/// `field_add_int(dest, 2048, fmt, value)`
fn field_add_int(dest: &mut Vec<u8>, pre: &str, value: i32, post: &str) {
    let dest_sz = OS_SIZE_2048 as i64 - dest.len() as i64;
    if dest_sz <= 0 || value <= 0 {
        return;
    }
    let mut piece = format!("{pre}{value}{post}").into_bytes();
    piece.truncate(254);
    piece.truncate(dest_sz as usize);
    dest.extend_from_slice(&piece);
}

/// `field_add_truncated(dest, 61440, fmt, value, 2)`: long logs end in "...".
fn field_add_truncated(dest: &mut Vec<u8>, pre: &str, value: &str, post: &str) {
    let fmt_len = (pre.len() + 2 + post.len()) as i64;
    let available = OS_SIZE_61440 as i64 - dest.len() as i64;
    if available <= 0 {
        return;
    }
    let v = value.as_bytes();
    if !wanted(v) {
        return;
    }
    let total = v.len() as i64 + fmt_len - 2;
    let field_sz = available - fmt_len + 2;
    let truncated: Vec<u8> = if total > available {
        let keep = (field_sz - 3).max(0) as usize;
        let mut t = v[..keep.min(v.len())].to_vec();
        t.extend_from_slice(b"...");
        t
    } else {
        v[..v.len().min(field_sz.max(0) as usize)].to_vec()
    };
    let mut piece = pre.as_bytes().to_vec();
    piece.extend_from_slice(&truncated);
    piece.extend_from_slice(post.as_bytes());
    piece.truncate((available - 1).max(0) as usize);
    dest.extend_from_slice(&piece);
}

/// "Invalid socket, reconnect": false when the server is still unreachable.
fn ensure_socket(c: &mut Syslog) -> bool {
    if c.socket.is_some() {
        return true;
    }
    resolve_hostname(&mut c.server, 5);
    match connect_udp(c.port, ip_of(&c.server)) {
        Ok(s) => {
            c.socket = Some(s);
            log().debug2(format!("(8300): Successfully reconnected to '{}'", c.server));
            true
        }
        Err(_) => false,
    }
}

fn send(c: &mut Syslog, msg: &[u8]) {
    let ok = c.socket.as_ref().is_some_and(|s| send_udp(s, msg));
    if !ok {
        c.socket = None;
        log().error(format!("(5302): Error sending message to '{}'.", c.server));
    }
}

/// `OS_Alert_SendSyslog` (alerts.log source). Returns 1 when the alert was for this server.
pub fn send_log(al: &mut AlertData, c: &mut Syslog, hosts: &Hostnames) -> i32 {
    if !ensure_socket(c) {
        return 0;
    }
    let location = al.location.clone().unwrap_or_default();
    if let Some(m) = &c.location {
        // only the part after "->" is matched
        let target = location.find("->").map(|p| &location[p + 2..]).unwrap_or(&location);
        if !m.is_match(target) {
            return 0;
        }
    }
    if c.level != 0 && al.level < c.level {
        return 0;
    }
    if let Some(ids) = &c.rule_id {
        if !ids.iter().take_while(|&&x| x != 0).any(|&x| x == al.rule) {
            return 0;
        }
    }
    if let Some(g) = &c.group {
        if !g.is_match(al.group.as_deref().unwrap_or("")) {
            return 0;
        }
    }
    // "2008 Jul 10 10:11:23" -> "Jul 10 10:11:23", day space-padded (C edits the alert itself)
    let mut date = al.date.clone().unwrap_or_default().into_bytes();
    let mut ts_start = 0;
    if date.len() > 14 {
        ts_start = 5;
        if date.get(9) == Some(&b'0') {
            date[9] = b' ';
        }
    }
    al.date = Some(String::from_utf8_lossy(&date).into_owned());
    let tstamp = String::from_utf8_lossy(&date[ts_start.min(date.len())..]).into_owned();
    let host = if c.use_fqdn { &hosts.long } else { &hosts.short };
    let log0 = al.log.first().cloned();
    let mut msg: Vec<u8>;
    match c.format {
        DEFAULT_CSYSLOG => {
            msg = snprintf(
                format!("<{}>{} {} ossec: Alert Level: {}; Rule: {} - {}; Location: {};", c.priority, tstamp, host, al.level, al.rule, s(&al.comment), s(&al.location)),
                OS_SIZE_2048,
            );
            field_add_string(&mut msg, " classification: ", al.group.as_deref(), ";");
            field_add_string(&mut msg, " srcip: ", al.srcip.as_deref(), ";");
            field_add_string(&mut msg, " dstip: ", al.dstip.as_deref(), ";");
            field_add_string(&mut msg, " user: ", al.user.as_deref(), ";");
            // the checksum / size / owner fields are never filled by GetAlertData in 4.14.7
            if let Some(l) = &log0 {
                field_add_truncated(&mut msg, " ", l, "");
            }
        }
        CEF_CSYSLOG => {
            msg = snprintf(
                format!(
                    "<{}>{} CEF:0|Wazuh Inc.|Wazuh|v4.14.7|{}|{}|{}|dvc={} cs1={} cs1Label=Location",
                    c.priority,
                    tstamp,
                    al.rule,
                    s(&al.comment),
                    al.level.min(10),
                    host,
                    s(&al.location)
                ),
                OS_SIZE_2048,
            );
            field_add_string(&mut msg, " cat=", al.group.as_deref(), "");
            field_add_string(&mut msg, " src=", al.srcip.as_deref(), "");
            field_add_int(&mut msg, " dpt=", al.dstport, "");
            field_add_int(&mut msg, " spt=", al.srcport, "");
            field_add_string(&mut msg, " fname=", al.filename.as_deref(), "");
            field_add_string(&mut msg, " dhost=", al.dstip.as_deref(), "");
            field_add_string(&mut msg, " shost=", al.srcip.as_deref(), "");
            field_add_string(&mut msg, " suser=", al.user.as_deref(), "");
            field_add_string(&mut msg, " dst=", al.dstip.as_deref(), "");
            field_add_string(&mut msg, " suser=", al.user.as_deref(), "");
            field_add_string(&mut msg, " dst=", al.dstip.as_deref(), "");
            if let Some(l) = &log0 {
                field_add_truncated(&mut msg, " msg=", l, "");
            }
        }
        JSON_CSYSLOG => {
            let mut r = Json::object();
            r.add("crit", Json::number(al.level as f64));
            r.add("id", Json::number(al.rule as f64));
            if let Some(l) = &al.location {
                r.add("component", Json::string(l));
            }
            for (k, v) in [("classification", &al.group), ("description", &al.comment)] {
                if let Some(v) = v {
                    r.add(k, Json::string(v));
                }
            }
            if let Some(l) = &log0 {
                r.add("message", Json::string(l));
            }
            if let Some(u) = &al.user {
                r.add("acct", Json::string(u));
            }
            if let Some(x) = &al.srcip {
                r.add("src_ip", Json::string(x));
            }
            if al.srcport != 0 {
                r.add("src_port", Json::number(al.srcport as f64));
            }
            if let Some(x) = &al.dstip {
                r.add("dst_ip", Json::string(x));
            }
            if al.dstport != 0 {
                r.add("dst_port", Json::number(al.dstport as f64));
            }
            if let Some(x) = &al.filename {
                r.add("file", Json::string(x));
            }
            let mut m = format!("<{}>{} {} ossec: ", c.priority, tstamp, host).into_bytes();
            m.extend_from_slice(&r.print_unformatted());
            m.truncate(OS_SIZE_2048 - 1);
            msg = m;
        }
        SPLUNK_CSYSLOG => {
            msg = snprintf(
                format!("<{}>{} {} ossec: crit={} id={} description=\"{}\" component=\"{}\",", c.priority, tstamp, host, al.level, al.rule, s(&al.comment), s(&al.location)),
                OS_SIZE_2048,
            );
            field_add_string(&mut msg, " classification=\"", al.group.as_deref(), "\",");
            if field_add_string(&mut msg, " src_ip=\"", al.srcip.as_deref(), "\",") > 0 {
                field_add_int(&mut msg, " src_port=", al.srcport, ",");
            }
            if field_add_string(&mut msg, " dst_ip=\"", al.dstip.as_deref(), "\",") > 0 {
                field_add_int(&mut msg, " dst_port=", al.dstport, ",");
            }
            field_add_string(&mut msg, " file=\"", al.filename.as_deref(), "\",");
            field_add_string(&mut msg, " acct=\"", al.user.as_deref(), "\",");
            if let Some(l) = &log0 {
                field_add_truncated(&mut msg, " message=\"", l, "\"");
            }
        }
        _ => msg = Vec::new(),
    }
    send(c, &msg);
    1
}

/// `strptime(ts, "%FT%T", tm)` on the fields the message prints; parses as
/// far as it can (like glibc), returning whether it reached the end.
fn strptime(ts: &[u8], tm: &mut [u32; 5]) -> bool {
    // tm: [month0, mday, hour, min, sec]
    let mut i = 0;
    let num = |i: &mut usize, digits: usize, lo: u32, hi: u32| -> Option<u32> {
        while ts.get(*i) == Some(&b' ') {
            *i += 1;
        }
        let st = *i;
        let mut v: u32 = 0;
        while *i < ts.len() && *i - st < digits && ts[*i].is_ascii_digit() {
            v = v * 10 + (ts[*i] - b'0') as u32;
            *i += 1;
        }
        (*i > st && (lo..=hi).contains(&v)).then_some(v)
    };
    let lit = |i: &mut usize, c: u8| -> bool {
        if ts.get(*i) == Some(&c) {
            *i += 1;
            true
        } else {
            false
        }
    };
    if num(&mut i, 4, 0, 9999).is_none() || !lit(&mut i, b'-') {
        return false;
    }
    let Some(m) = num(&mut i, 2, 1, 12) else { return false };
    tm[0] = m - 1;
    if !lit(&mut i, b'-') {
        return false;
    }
    let Some(d) = num(&mut i, 2, 1, 31) else { return false };
    tm[1] = d;
    if !lit(&mut i, b'T') {
        return false;
    }
    let Some(h) = num(&mut i, 2, 0, 23) else { return false };
    tm[2] = h;
    if !lit(&mut i, b':') {
        return false;
    }
    let Some(mi) = num(&mut i, 2, 0, 59) else { return false };
    tm[3] = mi;
    if !lit(&mut i, b':') {
        return false;
    }
    let Some(sec) = num(&mut i, 2, 0, 61) else { return false };
    tm[4] = sec;
    i == ts.len()
}

/// `OS_Alert_SendSyslog_JSON` (alerts.json source).
pub fn send_json(j: &mut Json, c: &mut Syslog, hosts: &Hostnames) -> i32 {
    log().debug2("OS_Alert_SendSyslog_JSON()");
    let Some(rule) = j.get("rule").cloned() else {
        log().debug2("Alert with no rule field.");
        return 0;
    };
    if j.get("timestamp").is_none() {
        log().error("Alert with no timestamp field.");
        return 0;
    }
    let bytes = |x: Option<&Json>| x.and_then(|v| v.as_bytes().map(<[u8]>::to_vec));
    if let Some(m) = &c.location {
        match bytes(j.get("location")) {
            Some(l) if m.is_match_bytes(&l) => {}
            _ => return 0,
        }
    }
    if c.level != 0 && !rule.get("level").is_some_and(|l| l.as_i32().unwrap_or(0) >= c.level as i32) {
        return 0;
    }
    if let Some(ids) = &c.rule_id {
        let Some(id) = rule.get("id") else { return 0 };
        let id = atoi(id.as_bytes().unwrap_or_default()) as i32;
        if !ids.iter().take_while(|&&x| x != 0).any(|&x| x as i32 == id) {
            return 0;
        }
    }
    if let Some(g) = &c.group {
        let Some(groups) = rule.get("groups") else { return 0 };
        if !groups.children().iter().any(|x| x.as_bytes().is_some_and(|b| g.is_match_bytes(b))) {
            return 0;
        }
    }
    let string = j.print_unformatted();
    let now = chrono::Local::now();
    use chrono::{Datelike, Timelike};
    let mut tm = [now.month0(), now.day(), now.hour(), now.minute(), now.second()];
    // C cuts the alert's own timestamp at the '.', so later servers see it shortened
    if let Some(Json::String(ts)) = j.get_mut("timestamp") {
        if let Some(p) = ts.iter().position(|&b| b == b'.') {
            ts.truncate(p);
        }
        if !strptime(ts, &mut tm) {
            log().error(format!("Could not parse timestamp '{}'.", String::from_utf8_lossy(ts)));
        }
    }
    const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let mut strtime = format!("{} {:02} {:02}:{:02}:{:02}", MON[tm[0] as usize % 12], tm[1], tm[2], tm[3], tm[4]).into_bytes();
    if strtime[4] == b'0' {
        strtime[4] = b' ';
    }
    let host = if c.use_fqdn { &hosts.long } else { &hosts.short };
    let mut msg = format!("<{}>{} {} ossec: ", c.priority, String::from_utf8_lossy(&strtime), host).into_bytes();
    msg.extend_from_slice(&string);
    msg.truncate(OS_MAXSTR - 1);
    if !ensure_socket(c) {
        return 0;
    }
    let mut d = b"OS_Alert_SendSyslog_JSON(): sending '".to_vec();
    d.extend_from_slice(&msg);
    d.push(b'\'');
    log().debug2(d);
    send(c, &msg);
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_test_as_written() {
        assert!(!wanted(b"(none)"));
        assert!(wanted(b"unknown"));
        assert!(wanted(b"1.2.3.4"));
    }

    #[test]
    fn truncates_long_logs() {
        let mut d = vec![b'x'; OS_SIZE_61440 - 20];
        field_add_truncated(&mut d, " ", &"y".repeat(100), "");
        // C sizes the field for "..." but snprintf then drops the last byte
        assert!(d.ends_with(b"y..") && !d.ends_with(b"..."));
        assert_eq!(d.len(), OS_SIZE_61440 - 1);
    }

    #[test]
    fn timestamps() {
        let mut tm = [0, 1, 0, 0, 0];
        assert!(strptime(b"2026-10-07T09:05:03", &mut tm));
        assert_eq!(tm, [9, 7, 9, 5, 3]);
        let mut tm = [0, 1, 0, 0, 0];
        assert!(!strptime(b"2026-13-07T09:05:03", &mut tm));
    }
}
