//! `shared/read-alert.c` (`GetAlertData`): one alert of an `alerts.log`
//! file, as the `ossecalert` reader needs it.

use crate::*;

/// The fields of `alert_data` the readers use.
#[derive(Debug, Default)]
pub struct AlertData {
    pub rule: u32,
    pub level: u32,
    pub alertid: Option<String>,
    pub date: Option<String>,
    pub location: Option<String>,
    pub comment: Option<String>,
    pub group: Option<String>,
    pub srcip: Option<String>,
    pub srcport: i32,
    pub dstip: Option<String>,
    pub dstport: i32,
    pub user: Option<String>,
    pub filename: Option<String>,
    pub log: Vec<String>,
}

const LOG_LIMIT: usize = 100;
const CRALERT_MAIL_SET: i32 = 0x0001;

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(cstr(b)).into_owned()
}

/// `os_clearnl`: cut at the last '\n'.
fn clearnl(s: &mut [u8]) {
    if let Some(p) = cstr(s).iter().rposition(|&c| c == b'\n') {
        s[p] = 0;
    }
}

/// C `atoi`
fn atoi(b: &[u8]) -> u32 {
    siem_config::util::atoi(&lossy(b)) as u32
}

/// `GetAlertData(flag, fp)`
pub fn get_alert_data(lc: &Lc, flag: i32, fp: &mut CFile) -> Option<AlertData> {
    let mut al = AlertData::default();
    let mut r = 0;
    let mut issyscheck = false;
    let mut s = vec![0u8; OS_MAXSTR + 1];

    while fp.fgets(&mut s, OS_MAXSTR) {
        if s.starts_with(b"** Alert") {
            if r == 2 {
                let back = strlen(&s) as i64;
                if fp.fseek(-back, 1) != -1 {
                    return Some(al);
                }
                fp.clearerr();
                return None;
            }
            let p0 = 9; // ALERT_BEGIN_SZ + 1
            let rest = cstr(&s[p0.min(strlen(&s))..]).to_vec();
            let Some(m) = rest.iter().position(|&c| c == b':') else { continue };
            al.alertid = Some(String::from_utf8_lossy(&rest[..m]).into_owned());
            let Some(sp) = rest.iter().position(|&c| c == b' ') else { continue };
            let p = &rest[sp + 1..];
            if flag & CRALERT_MAIL_SET != 0 && !p.starts_with(b"mail") {
                continue;
            }
            if let Some(d) = p.iter().position(|&c| c == b'-') {
                let mut g = &p[d + 1..];
                while g.first() == Some(&b' ') {
                    g = &g[1..];
                }
                let mut gv = g.to_vec();
                gv.push(0);
                clearnl(&mut gv);
                let gs = lossy(&gv);
                if gs.contains("syscheck") {
                    issyscheck = true;
                }
                al.group = Some(gs);
            }
            r = 1;
            continue;
        }
        if r < 1 {
            continue;
        }
        if r == 1 {
            clearnl(&mut s);
            let line = cstr(&s).to_vec();
            let mut date = line.clone();
            let mut loc: Option<Vec<u8>> = None;
            if let Some(c) = line.iter().position(|&x| x == b':') {
                match line[c..].iter().position(|&x| x == b' ') {
                    Some(sp) => {
                        let at = c + sp;
                        date = line[..at].to_vec();
                        loc = Some(line[at + 1..].to_vec());
                    }
                    None => {
                        lc.log.error("date or location not NULL");
                        fp.clearerr();
                        return None;
                    }
                }
            }
            if al.date.is_some() || al.location.is_some() || loc.is_none() {
                lc.log.error("date or location not NULL or p is NULL");
                fp.clearerr();
                return None;
            }
            al.date = Some(String::from_utf8_lossy(&date).into_owned());
            al.location = Some(String::from_utf8_lossy(&loc.unwrap()).into_owned());
            r = 2;
            continue;
        }
        // r == 2
        if s.starts_with(b"Rule: ") {
            clearnl(&mut s);
            let line = cstr(&s).to_vec();
            let p = &line[6..];
            al.rule = atoi(p);
            let p = p.iter().position(|&c| c == b' ').map(|i| &p[i + 1..]);
            let p = p.and_then(|p| p.iter().position(|&c| c == b' ').map(|i| &p[i + 1..]));
            let Some(p) = p else {
                fp.clearerr();
                return None;
            };
            al.level = atoi(p);
            let Some(q) = p.iter().position(|&c| c == b'\'') else {
                fp.clearerr();
                return None;
            };
            let comment = &p[q + 1..];
            let Some(end) = comment.iter().rposition(|&c| c == b'\'') else {
                fp.clearerr();
                return None;
            };
            al.comment = Some(String::from_utf8_lossy(&comment[..end]).into_owned());
        } else if s.starts_with(b"Src IP: ") {
            clearnl(&mut s);
            al.srcip = Some(lossy(&s[8..]));
        } else if s.starts_with(b"Src Port: ") {
            clearnl(&mut s);
            al.srcport = atoi(&s[10..]) as i32;
        } else if s.starts_with(b"Dst IP: ") {
            clearnl(&mut s);
            al.dstip = Some(lossy(&s[8..]));
        } else if s.starts_with(b"Dst Port: ") {
            clearnl(&mut s);
            al.dstport = atoi(&s[10..]) as i32;
        } else if s.starts_with(b"User: ") {
            clearnl(&mut s);
            al.user = Some(lossy(&s[6..]));
        } else if al.log.len() < LOG_LIMIT {
            clearnl(&mut s);
            if issyscheck {
                const IC: &[u8] = b"Integrity checksum changed for: '";
                if s.starts_with(IC) {
                    let mut f = cstr(&s[IC.len()..]).to_vec();
                    if f.last() == Some(&b'\r') {
                        f.pop();
                    }
                    if f.last() == Some(&b'\'') {
                        f.pop();
                    }
                    al.filename = Some(String::from_utf8_lossy(&f).into_owned());
                }
                issyscheck = false;
            }
            al.log.push(lossy(&s));
        }
    }
    if fp.feof() && s[0] == 0 && r == 2 {
        return Some(al);
    }
    fp.clearerr();
    None
}
