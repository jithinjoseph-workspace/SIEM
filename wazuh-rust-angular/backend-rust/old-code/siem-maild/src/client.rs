//! `os_maild/os_maild_client.c`: one alert -> the e-mail text, plus the
//! granular `<email_alerts>` matching (`OS_RecvMailQ`, `OS_RecvMailQ_JSON`,
//! `PrintTable`).

use siem_cjson::Json;

use crate::alert::{atoi, AlertData};
use crate::config::{Mail, DONOTGROUP, FORWARD_NOW, FULL_FORMAT, SMS_FORMAT};
use crate::log;

/// `OS_MAXSTR`, `SUBJECT_SIZE`, `BODY_SIZE`
const OS_MAXSTR: usize = 65536;
pub const SUBJECT_SIZE: usize = 128;
const BODY_SIZE: usize = OS_MAXSTR + 1024;

/// `MailMsg`
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MailMsg {
    pub subject: Vec<u8>,
    pub body: Vec<u8>,
}

/// `_g_subject` / `_g_subject_level`: the highest-level subject of the batch.
#[derive(Debug, Clone, Default)]
pub struct Subject {
    pub text: Vec<u8>,
    pub level: u32,
}

/// `snprintf(buf, size, ...)`: at most `size - 1` bytes.
fn cut(mut v: Vec<u8>, size: usize) -> Vec<u8> {
    v.truncate(size.saturating_sub(1));
    v
}

/// `os_snprintf`: also warns when the text did not fit.
fn os_cut(v: Vec<u8>, size: usize) -> Vec<u8> {
    if v.len() >= size {
        log().warn("String may be truncated because it is too long.");
    }
    cut(v, size)
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn subject_for(m: &Mail, host: &[u8], level: u32, desc: &[u8]) -> Vec<u8> {
    let s = if m.subject_full != 0 {
        cat(&[b"Wazuh alert - ", host, format!(" - Level {level} - ").as_bytes(), desc])
    } else {
        cat(&[b"Wazuh notification - ", host, format!(" - Alert level {level}").as_bytes()])
    };
    cut(s, SUBJECT_SIZE - 1)
}

/// `MAIL_BODY`
fn body_for(date: &[u8], from: &[u8], rule: u32, level: u32, comment: &[u8], extra: &[u8], logs: &[u8]) -> Vec<u8> {
    let b = cat(&[
        b"\r\nWazuh Notification.\r\n",
        date,
        b"\r\n\r\nReceived From: ",
        from,
        format!("\r\nRule: {} fired (level {level}) -> \"", rule as i32).as_bytes(),
        comment,
        b"\"\r\n",
        extra,
        b"Portion of the log(s):\r\n\r\n",
        logs,
        b"\r\n\r\n\r\n --END OF NOTIFICATION\r\n\r\n\r\n",
    ]);
    os_cut(b, BODY_SIZE - 1)
}

/// The granular matching shared by both sources. Returns (sms_set, donotgroup).
fn granular(m: &mut Mail, location: &[u8], level: u32, rule: u32, group_match: &dyn Fn(&siem_regex::OsMatch) -> Option<bool>) -> (bool, bool) {
    let (mut sms, mut dng) = (false, false);
    for i in 0..m.gran_to.len() {
        let mut gr_set = false;
        if let Some(Some(loc)) = m.gran_location.get(i) {
            if !loc.is_match_bytes(location) {
                continue;
            }
            gr_set = true;
        }
        let lvl = m.gran_level.get(i).copied().unwrap_or(0);
        if lvl != 0 {
            if level < lvl {
                continue;
            }
            gr_set = true;
        }
        if let Some(Some(ids)) = m.gran_id.get(i) {
            if !ids.iter().take_while(|&&x| x != 0).any(|&x| x == rule) {
                continue;
            }
            gr_set = true;
        }
        if let Some(Some(g)) = m.gran_group.get(i) {
            match group_match(g) {
                Some(true) => gr_set = true,
                Some(false) => continue,
                None => {}
            }
        }
        if gr_set {
            let f = m.gran_format.get(i).copied().unwrap_or(FULL_FORMAT);
            if f == SMS_FORMAT {
                m.gran_set[i] = SMS_FORMAT;
                sms = true;
            } else if f == FORWARD_NOW {
                m.priority = 1;
                m.gran_set[i] = FULL_FORMAT;
            } else if f == DONOTGROUP {
                m.priority = DONOTGROUP;
                m.gran_set[i] = DONOTGROUP;
                dng = true;
            } else {
                m.gran_set[i] = FULL_FORMAT;
            }
        }
    }
    (sms, dng)
}

fn subject_update(g: &mut Subject, donotgroup: bool, subject: &[u8], level: u32) {
    if donotgroup {
        return;
    }
    if g.text.is_empty() || g.level < level {
        g.text = subject.to_vec();
        g.level = level;
    }
}

fn sms(level: u32, rule: u32, desc: &[u8], logs: &[u8]) -> MailMsg {
    let subject = cut(cat(&[format!("Wazuh {level} - {} - ", rule as i32).as_bytes(), desc]), SUBJECT_SIZE - 1);
    MailMsg { subject, body: logs[..logs.len().min(127)].to_vec() }
}

/// `OS_RecvMailQ` on an alert already read from `alerts.log`.
pub fn mail_from_log(al: AlertData, m: &mut Mail, g: &mut Subject) -> (MailMsg, Option<MailMsg>) {
    m.priority = 0;
    let mut body_size = OS_MAXSTR - 3;
    let mut logs: Vec<u8> = Vec::new();
    for l in &al.log {
        let log_size = l.len() + 4;
        if body_size <= log_size {
            break;
        }
        logs.extend_from_slice(l.as_bytes());
        logs.extend_from_slice(b"\r\n");
        body_size -= log_size;
    }
    let mut extra: Vec<u8> = Vec::new();
    for (pre, v, dec) in [("Src IP: ", &al.srcip, true), ("Dst IP: ", &al.dstip, true), ("User: ", &al.user, false)] {
        if let Some(v) = v {
            let full = format!("{pre}{v}\r\n").into_bytes();
            let log_size = full.len();
            if body_size > log_size {
                extra.extend_from_slice(&full[..full.len().min(OS_MAXSTR / 4 - 1)]);
                if dec {
                    body_size -= log_size;
                }
            }
        }
    }
    // Subject: the location up to the "->"; that byte becomes '-' again afterwards
    let mut location = al.location.clone().unwrap_or_default().into_bytes();
    let host_end = location.iter().position(|&c| c == b'>').map(|p| p.saturating_sub(1));
    let host = match host_end {
        Some(e) => location[..e].to_vec(),
        None => location.clone(),
    };
    let comment = al.comment.clone().unwrap_or_default().into_bytes();
    let subject = subject_for(m, &host, al.level, &comment);
    if let Some(e) = host_end {
        location[e] = b'-';
    }
    let body = body_for(al.date.as_deref().unwrap_or("").as_bytes(), &location, al.rule, al.level, &comment, &extra, &logs);
    log().debug2(cat(&[b"OS_RecvMailQ: mail->body[", &body, b"]"]));

    let group = al.group.clone();
    let (sms_set, dng) = granular(m, &location, al.level, al.rule, &|g| Some(group.as_deref().is_some_and(|x| g.is_match(x))));
    subject_update(g, dng, &subject, al.level);
    let s = sms_set.then(|| sms(al.level, al.rule, &comment, &logs));
    (MailMsg { subject, body }, s)
}

/// `add_field`
fn add_field(value: Option<&[u8]>, dest: &mut Vec<u8>, size: &mut usize, prefix: &str) {
    if let Some(v) = value {
        let log_size = v.len() + prefix.len() + 3;
        if *size > log_size {
            dest.extend_from_slice(prefix.as_bytes());
            dest.extend_from_slice(&v[..v.len().min(*size)]);
            dest.extend_from_slice(b"\r\n");
            *size -= log_size;
        }
    }
}

/// `add_field_from_json`
fn add_field_json(o: &Json, field: &str, dest: &mut Vec<u8>, size: &mut usize, prefix: &str) {
    let Some(f) = o.get(field) else { return };
    let v: Option<Vec<u8>> = match f {
        Json::String(s) => Some(s.clone()),
        Json::Number { double, .. } => Some(format!("{}", *double as i64).into_bytes()),
        _ => None,
    };
    add_field(v.as_deref(), dest, size, prefix);
}

fn string(j: Option<&Json>) -> Option<Vec<u8>> {
    match j {
        Some(Json::String(s)) => Some(s.clone()),
        _ => None,
    }
}

/// `OS_RecvMailQ_JSON` on one alert from `alerts.json`; `None` when it is
/// not mailed or misses a field.
pub fn mail_from_json(mut al: Json, m: &mut Mail, g: &mut Subject) -> Option<(MailMsg, Option<MailMsg>)> {
    m.priority = 0;
    let rule = al.get("rule")?;
    if !matches!(rule.get("mail"), Some(Json::True)) {
        return None;
    }
    let mut body_size = OS_MAXSTR - 3;
    let mut logs: Vec<u8> = Vec::new();

    if let Some(sk) = al.get("syscheck") {
        let s = &mut body_size;
        add_field_json(sk, "path", &mut logs, s, "File: ");
        add_field_json(sk, "event", &mut logs, s, "Event: ");
        add_field_json(sk, "mode", &mut logs, s, "Mode: ");
        let mut ca: Option<Vec<u8>> = None;
        if let Some(Json::Array(a)) = sk.get("changed_attributes") {
            for it in a {
                if let Json::String(v) = it {
                    match ca.as_mut() {
                        Some(c) => {
                            c.push(b',');
                            c.extend_from_slice(v);
                        }
                        None => ca = Some(v.clone()),
                    }
                }
            }
        }
        add_field(ca.as_deref(), &mut logs, s, "Changed attributes: ");
        add_field_json(sk, "changed_attributes", &mut logs, s, "Changed attributes: ");
        for (k, p) in [
            ("size_before", "Size before: "),
            ("size_after", "Size after: "),
            ("md5_before", "Old md5sum was: "),
            ("md5_after", "New md5sum is: "),
            ("sha1_before", "Old sha1sum was: "),
            ("sha1_after", "New sha1sum is: "),
            ("sha256_before", "Old sha256sum was: "),
            ("sha256_after", "New sha256sum is: "),
        ] {
            add_field_json(sk, k, &mut logs, s, p);
        }
        logs.extend_from_slice(b"\nAttributes\n");
        *s = s.wrapping_sub(12);
        for (k, p) in [
            ("size_after", " - Size: "),
            ("perm_after", " - Permissions: "),
            ("mtime_after", " - Date: "),
            ("inode_after", " - Inode: "),
            ("uname_after", " - User name: "),
            ("uid_after", " - User ID: "),
            ("gname_after", " - Group name: "),
            ("gid_after", " - Group ID: "),
            ("md5_after", " - MD5: "),
            ("sha1_after", " - SHA1: "),
            ("sha256_after", " - SHA256: "),
        ] {
            add_field_json(sk, k, &mut logs, s, p);
        }
        if let Some(au) = sk.get("audit") {
            for (obj, key, p) in [
                ("user", "name", "- (Audit) User name: "),
                ("login_user", "name", "- (Audit) Audit name: "),
                ("effective_user", "name", "- (Audit) Effective name: "),
                ("group", "name", "- (Audit) Group name: "),
                ("process", "id", "- (Audit) Process id: "),
                ("process", "name", "- (Audit) Process name: "),
                ("process", "cwd", "- (Audit) Process cwd: "),
                ("process", "parent_name", "- (Audit) Parent process name: "),
                ("process", "ppid", "- (Audit) Parent process id: "),
                ("process", "parent_cwd", "- (Audit) Parent process cwd: "),
            ] {
                if let Some(o) = au.get(obj) {
                    add_field_json(o, key, &mut logs, s, p);
                }
            }
        }
        add_field_json(sk, "diff", &mut logs, s, "\r\n- Changed content:\r\n");
        if let Some(tags) = sk.get("tags") {
            if *s > 7 {
                logs.extend_from_slice(b"Tags:\r\n");
                *s -= 7;
                for t in tags.children() {
                    add_field(string(Some(t)).as_deref(), &mut logs, s, " - ");
                }
            }
        }
    } else if let Some(fl) = al.get("full_log") {
        let v = string(Some(fl)).unwrap_or_default();
        if body_size <= v.len() + 4 {
            return None;
        }
        logs = v;
    } else {
        print_table(&mut al, &mut logs, &mut body_size);
    }

    let location = string(al.get("location"))?;
    let agent = al.get("agent")?;
    let name = string(agent.get("name")).unwrap_or_else(|| b"(null)".to_vec());
    agent.get("name")?;
    let host = match agent.get("ip") {
        Some(ip) => cat(&[b"(", &name, b") ", &string(Some(ip)).unwrap_or_else(|| b"(null)".to_vec()), b"->", &location]),
        None => cat(&[&name, b"->", &location]),
    };
    let rule = al.get("rule")?;
    let level = rule.get("level")?.as_i32().unwrap_or(0) as u32;
    let desc = string(Some(rule.get("description")?)).unwrap_or_default();
    let rule_id = atoi(&string(Some(rule.get("id")?)).unwrap_or_default()) as u32;
    let subject = subject_for(m, &host, level, &desc);
    let ts = string(Some(al.get("timestamp")?)).unwrap_or_default();
    let body = body_for(&ts, &host, rule_id, level, &desc, b"", &logs);
    log().debug2(cat(&[b"OS_RecvMailQ: mail->body[", &body, b"]"]));

    // C looks up "group" (alerts carry "groups"), so the group filter never applies here
    let groups = rule.get("group").cloned();
    let (sms_set, dng) = granular(m, &host, level, rule_id, &|g| {
        groups.as_ref().map(|gs| gs.children().iter().any(|x| string(Some(x)).is_some_and(|v| g.is_match_bytes(&v))))
    });
    subject_update(g, dng, &subject, level);
    let s = sms_set.then(|| sms(level, rule_id, &desc, &logs));
    Some((MailMsg { subject, body }, s))
}

/// `PrintTable(al_json, logs, &body_size, "\t", 2)`
fn print_table(root: &mut Json, out: &mut Vec<u8>, size: &mut usize) {
    // the root object has no key and no siblings
    let Json::Object(members) = root else {
        return;
    };
    if members.is_empty() {
        return;
    }
    pt(members, 0, out, size, b"\t\t", 4);
}

fn upper(k: &mut [u8]) {
    if let Some(c) = k.first_mut() {
        *c = c.to_ascii_uppercase();
    }
}

/// `PrintTable` on member `i` of an object (its `next` is member `i + 1`).
fn pt(list: &mut [(Vec<u8>, Json)], i: usize, out: &mut Vec<u8>, size: &mut usize, tab: &[u8], counter: i32) {
    let has_next = i + 1 < list.len();
    let tab: Vec<u8> = tab[..tab.len().min(255)].to_vec();
    let mut next_early = false;
    {
        let (key, item) = &mut list[i];
        match item {
            Json::Number { .. } | Json::String(_) | Json::True | Json::False => {
                upper(key);
                let v = item.print_unformatted();
                let log_size = v.len() + tab.len() + key.len() + 4;
                if *size > log_size {
                    out.extend_from_slice(&cat(&[&tab, key, b": ", &v, b"\r\n"]));
                    *size -= log_size;
                }
            }
            Json::Array(a) => {
                let log_size = key.len() + tab.len() + 2;
                if *size > log_size {
                    upper(key);
                    out.extend_from_slice(&cat(&[&tab, key, b": "]));
                    *size -= log_size;
                }
                for el in a.iter() {
                    let v = el.print_unformatted();
                    if *size > v.len() + 1 {
                        out.extend_from_slice(&v);
                        out.push(b' ');
                        *size -= v.len() + 1;
                    }
                }
                if *size > 2 {
                    out.extend_from_slice(b"\r\n");
                    *size -= 2;
                }
            }
            Json::Object(children) if !children.is_empty() => {
                let log_size = key.len() + tab.len() + 2;
                if *size > log_size {
                    upper(key);
                    out.extend_from_slice(&cat(&[&tab, key, b"\r\n"]));
                    *size -= log_size;
                }
                if counter < 12 {
                    let mut child_tab = tab.clone();
                    child_tab.push(b'\t');
                    pt(children, 0, out, size, &child_tab, counter + 2);
                } else if has_next {
                    // too deep: C prints the next sibling here and again below
                    next_early = true;
                }
            }
            _ => {}
        }
    }
    if next_early {
        pt(list, i + 1, out, size, &tab, counter);
    }
    if has_next && *size > 2 {
        pt(list, i + 1, out, size, &tab, counter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_mail() {
        let mut m = Mail::default();
        let mut g = Subject::default();
        let al = siem_cjson::parse_str(r#"{"timestamp":"2026-10-16T10:00:00.000+0000","rule":{"level":10,"description":"Multiple failures","id":"5720","mail":true,"groups":["sshd"]},"agent":{"id":"001","name":"web1","ip":"10.0.0.5"},"location":"/var/log/auth.log","full_log":"Oct 16 sshd: fail"}"#).unwrap();
        let (msg, sms) = mail_from_json(al, &mut m, &mut g).unwrap();
        assert_eq!(msg.subject, b"Wazuh notification - (web1) 10.0.0.5->/var/log/auth.log - Alert level 10");
        assert!(msg.body.starts_with(b"\r\nWazuh Notification.\r\n2026-10-16T10:00:00.000+0000\r\n\r\nReceived From: (web1) 10.0.0.5->/var/log/auth.log\r\nRule: 5720 fired (level 10) -> \"Multiple failures\"\r\nPortion of the log(s):\r\n\r\nOct 16 sshd: fail\r\n"));
        assert!(sms.is_none());
        assert_eq!(g.level, 10);
        // not mailed
        let al = siem_cjson::parse_str(r#"{"rule":{"level":3,"mail":false}}"#).unwrap();
        assert!(mail_from_json(al, &mut m, &mut g).is_none());
    }

    #[test]
    fn table_dump() {
        let mut j = siem_cjson::parse_str(r#"{"a":1,"data":{"x":"y","list":[1,"z"]},"n":null,"t":true}"#).unwrap();
        let (mut out, mut size) = (Vec::new(), 1000usize);
        print_table(&mut j, &mut out, &mut size);
        assert_eq!(String::from_utf8(out).unwrap(), "\t\tA: 1\r\n\t\tData\r\n\t\t\tX: \"y\"\r\n\t\t\tList: 1 \"z\" \r\n\t\tT: true\r\n");
    }
}
