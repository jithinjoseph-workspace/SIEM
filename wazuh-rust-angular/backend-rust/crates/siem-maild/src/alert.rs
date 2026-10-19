//! `shared/read-alert.c` (`GetAlertData`), `shared/file-queue.c`
//! (`Init_FileQueue`, `Read_FileMon`) and `shared/json-queue.c` (`jqueue_*`).

use std::io::SeekFrom;

use crate::cfile::{inode, CFile};
use crate::log;

pub const CRALERT_MAIL_SET: i32 = 0x001;
pub const CRALERT_READ_ALL: i32 = 0x004;
pub const CRALERT_READ_FAILED: i32 = 0x008;
pub const CRALERT_FP_SET: i32 = 0x010;

/// `ALERTS_DAILY`, `ALERTSJSON_DAILY`
pub const ALERTS_DAILY: &str = "logs/alerts/alerts.log";
pub const ALERTSJSON_DAILY: &str = "logs/alerts/alerts.json";
/// `OS_MAXSTR`
const OS_MAXSTR: usize = 65536;
/// `FQ_TIMEOUT`
const FQ_TIMEOUT: u64 = 5;
const LOG_LIMIT: usize = 100;
const INTEGRITY_CHECKSUM_BEGIN: &[u8] = b"Integrity checksum changed for: '";

/// `alert_data`
#[derive(Debug, Clone, Default, PartialEq)]
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

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// `os_clearnl`: cuts at the first '\n'; returns its position.
fn clearnl(b: &mut Vec<u8>) -> Option<usize> {
    let p = b.iter().position(|&c| c == b'\n')?;
    b.truncate(p);
    Some(p)
}

/// `atoi`
pub fn atoi(b: &[u8]) -> i64 {
    let t: &[u8] = {
        let i = b.iter().position(|c| !matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)).unwrap_or(b.len());
        &b[i..]
    };
    let (neg, t) = match t.first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut v: i64 = 0;
    for &c in t.iter().take_while(|c| c.is_ascii_digit()) {
        v = v.wrapping_mul(10).wrapping_add((c - b'0') as i64);
    }
    if neg {
        -v
    } else {
        v
    }
}

/// `GetAlertData`. `str_` persists across lines like the C stack buffer:
/// the end-of-file test looks at the last line read (after `os_clearnl`).
pub fn get_alert_data(flag: i32, fp: &mut CFile) -> Option<AlertData> {
    let mut al = AlertData::default();
    let mut r = 0;
    let mut issyscheck = false;
    // Uninitialized in C: only consulted after a line was read.
    let mut str_: Vec<u8> = vec![b'?'];

    while let Some(line) = fp.fgets(OS_MAXSTR) {
        str_ = line;
        if str_.starts_with(b"** Alert") {
            if r == 2 {
                return if fp.seek(SeekFrom::Current(-(str_.len() as i64))) { Some(al) } else { error(fp) };
            }
            let p = str_.get(9..).unwrap_or_default().to_vec();
            let Some(m) = p.iter().position(|&c| c == b':') else { continue };
            al.alertid = Some(s(&p[..m]));
            // Search for the email flag
            let Some(sp) = p.iter().position(|&c| c == b' ') else { continue };
            let f = &p[sp + 1..];
            if flag & CRALERT_MAIL_SET != 0 && !f.starts_with(b"mail") {
                continue;
            }
            if let Some(d) = f.iter().position(|&c| c == b'-') {
                let mut g = &f[d + 1..];
                while g.first() == Some(&b' ') {
                    g = &g[1..];
                }
                let mut g = g.to_vec();
                clearnl(&mut g);
                let g = s(&g);
                issyscheck = g.contains("syscheck");
                al.group = Some(g);
            }
            r = 1;
            continue;
        }
        if r < 1 {
            continue;
        }
        if r == 1 {
            // "2006 Apr 13 16:15:17 /var/log/auth.log"
            let nl = clearnl(&mut str_);
            let mut loc: Option<usize> = nl; // p keeps os_clearnl's value when there is no ':'
            if let Some(c) = str_.iter().position(|&c| c == b':') {
                match str_[c..].iter().position(|&x| x == b' ') {
                    Some(sp) => loc = Some(c + sp),
                    None => {
                        log().error("date or location not NULL");
                        return error(fp);
                    }
                }
            }
            let Some(lp) = loc else {
                log().error("date or location not NULL or p is NULL");
                return error(fp);
            };
            if al.date.is_some() || al.location.is_some() {
                log().error("date or location not NULL or p is NULL");
                return error(fp);
            }
            al.date = Some(s(&str_[..lp]));
            al.location = Some(s(str_.get(lp + 1..).unwrap_or_default()));
            // the space (or newline) becomes the terminator
            if lp < str_.len() {
                str_.truncate(lp);
            }
            r = 2;
            continue;
        }
        // r == 2
        let field = |pre: &[u8], b: &Vec<u8>| -> Option<String> { b.strip_prefix(pre).map(s) };
        if str_.starts_with(b"Rule: ") {
            clearnl(&mut str_);
            let p = &str_[6..];
            al.rule = atoi(p) as u32;
            let p = p.iter().position(|&c| c == b' ').and_then(|a| {
                let q = &p[a + 1..];
                q.iter().position(|&c| c == b' ').map(|b| &q[b + 1..])
            });
            let Some(p) = p else { return error(fp) };
            al.level = atoi(p) as u32;
            let Some(q) = p.iter().position(|&c| c == b'\'') else { return error(fp) };
            let comment = &p[q + 1..];
            let Some(end) = comment.iter().rposition(|&c| c == b'\'') else { return error(fp) };
            al.comment = Some(s(&comment[..end]));
        } else if str_.starts_with(b"Src IP: ") {
            clearnl(&mut str_);
            al.srcip = field(b"Src IP: ", &str_);
        } else if str_.starts_with(b"Src Port: ") {
            clearnl(&mut str_);
            al.srcport = atoi(&str_[10..]) as i32;
        } else if str_.starts_with(b"Dst IP: ") {
            clearnl(&mut str_);
            al.dstip = field(b"Dst IP: ", &str_);
        } else if str_.starts_with(b"Dst Port: ") {
            clearnl(&mut str_);
            al.dstport = atoi(&str_[10..]) as i32;
        } else if str_.starts_with(b"User: ") {
            clearnl(&mut str_);
            al.user = field(b"User: ", &str_);
        } else if al.log.len() < LOG_LIMIT {
            clearnl(&mut str_);
            if issyscheck {
                if let Some(f) = str_.strip_prefix(INTEGRITY_CHECKSUM_BEGIN) {
                    let mut f = f.to_vec();
                    if f.last() == Some(&b'\r') {
                        f.pop();
                    }
                    if f.last() == Some(&b'\'') {
                        f.pop();
                    }
                    al.filename = Some(s(&f));
                }
                issyscheck = false;
            }
            al.log.push(s(&str_));
        }
    }
    // End of the alert reached and saved.
    if fp.feof() && str_.first().is_none_or(|&c| c == 0) && r == 2 {
        return Some(al);
    }
    error(fp)
}

fn error(fp: &mut CFile) -> Option<AlertData> {
    fp.clearerr();
    None
}

/// `file_queue` for `alerts.log`.
pub struct FileQueue {
    pub fp: Option<CFile>,
    pub flags: i32,
    pub file_name: String,
}

impl FileQueue {
    /// `Init_FileQueue`. With `CRALERT_FP_SET` the caller supplies `fp`.
    pub fn init(fp: Option<CFile>, flags: i32) -> FileQueue {
        let mut q = FileQueue { fp: if flags & CRALERT_FP_SET != 0 { fp } else { None }, flags, file_name: String::new() };
        q.get_file_queue();
        q.handle_queue(q.flags);
        q
    }

    /// `GetFile_Queue`
    fn get_file_queue(&mut self) {
        self.file_name = if self.flags & CRALERT_FP_SET != 0 { "<stdin>".into() } else { ALERTS_DAILY.into() };
    }

    /// `Handle_Queue`: 1, 0 (not available) or -1.
    fn handle_queue(&mut self, flags: i32) -> i32 {
        if flags & CRALERT_FP_SET == 0 {
            self.fp = None;
            match CFile::open(&self.file_name) {
                Ok(f) => self.fp = Some(f),
                Err(_) => return 0,
            }
        }
        if flags & CRALERT_READ_ALL == 0 {
            let Some(fp) = self.fp.as_mut() else { return 0 };
            if !fp.seek(SeekFrom::End(0)) {
                let e = std::io::Error::last_os_error();
                log().error(format!("(1116): Could not set position in file '{}' due to [({})-({})].", self.file_name, e.raw_os_error().unwrap_or(0), crate::strerror(&e)));
                self.fp = None;
                return -1;
            }
        }
        if let Some(fp) = self.fp.as_ref() {
            if let Err(e) = fp.metadata() {
                log().error(format!("(1118): Could not retrieve information of file '{}' due to [({})-({})].", self.file_name, e.raw_os_error().unwrap_or(0), crate::strerror(&e)));
                self.fp = None;
                return -1;
            }
        }
        1
    }

    /// `Read_FileMon`
    pub fn read_filemon(&mut self, timeout: u32, sleep: &dyn Fn(u64)) -> Option<AlertData> {
        if self.fp.is_none() && self.handle_queue(0) != 1 {
            sleep(FQ_TIMEOUT);
            return None;
        }
        let fp = self.fp.as_mut()?;
        if let Some(a) = get_alert_data(self.flags, fp) {
            return Some(a);
        }
        self.get_file_queue();
        if self.handle_queue(0) != 1 {
            sleep(FQ_TIMEOUT);
            return None;
        }
        for _ in 0..timeout {
            if let Some(a) = get_alert_data(self.flags, self.fp.as_mut()?) {
                return Some(a);
            }
            sleep(FQ_TIMEOUT);
        }
        None
    }
}

/// `file_queue` for `alerts.json` (`jqueue_*`).
#[derive(Default)]
pub struct JQueue {
    pub fp: Option<CFile>,
    pub flags: i32,
    ino: u64,
}

impl JQueue {
    /// `jqueue_open`
    pub fn open(&mut self, tail: bool) -> i32 {
        self.fp = None;
        let mut fp = match CFile::open(ALERTSJSON_DAILY) {
            Ok(f) => f,
            Err(e) => {
                log().error(format!("(1103): Could not open file '{ALERTSJSON_DAILY}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), crate::strerror(&e)));
                return -1;
            }
        };
        if tail && !fp.seek(SeekFrom::End(0)) {
            let e = std::io::Error::last_os_error();
            log().error(format!("(1103): Could not open file '{ALERTSJSON_DAILY}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), crate::strerror(&e)));
            return -1;
        }
        match fp.metadata() {
            Ok(m) => self.ino = inode(&m),
            Err(e) => {
                log().error(format!("(1118): Could not retrieve information of file '{ALERTSJSON_DAILY}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), crate::strerror(&e)));
                return -1;
            }
        }
        self.fp = Some(fp);
        0
    }

    /// `jqueue_next`
    pub fn next(&mut self, sleep: &dyn Fn(u64)) -> Option<siem_cjson::Json> {
        if self.fp.is_none() && self.open(true) < 0 {
            return None;
        }
        self.fp.as_mut()?.clearerr();
        let alert = self.parse_json();
        if alert.is_some() && self.flags & CRALERT_READ_FAILED == 0 {
            return alert;
        }
        self.flags = 0;
        let st = std::fs::metadata(ALERTSJSON_DAILY).or_else(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                sleep(1);
                std::fs::metadata(ALERTSJSON_DAILY)
            } else {
                Err(e)
            }
        });
        let st = match st {
            Ok(m) => m,
            Err(e) => {
                log().warn(format!("(1118): Could not retrieve information of file '{ALERTSJSON_DAILY}' due to [({})-({})].", e.raw_os_error().unwrap_or(0), crate::strerror(&e)));
                self.fp = None;
                return None;
            }
        };
        if inode(&st) != self.ino {
            log().debug2("jqueue_next(): Alert file inode changed. Reloading.");
            if self.open(false) < 0 {
                return None;
            }
            self.fp.as_mut()?.clearerr();
            return self.parse_json();
        }
        None
    }

    /// `jqueue_parse_json`
    fn parse_json(&mut self) -> Option<siem_cjson::Json> {
        let fp = self.fp.as_mut()?;
        let initial = fp.ftell();
        let Some(buf) = fp.fgets(OS_MAXSTR + 1) else {
            // Force the queue reload when the read fails
            self.flags = CRALERT_READ_FAILED;
            return None;
        };
        let mut offset = fp.ftell();
        if buf.last() == Some(&b'\n') {
            let line = &buf[..buf.len() - 1];
            if let Ok((j, used)) = siem_cjson::parse_with_opts(line, false) {
                if used == line.len() || line[used] == 0 {
                    return Some(j);
                }
            }
            log().warn(format!("Invalid JSON alert read from '{ALERTSJSON_DAILY}': '{}'", s(line)));
            return None;
        }
        let mut current = initial;
        while offset - current == OS_MAXSTR as i64 {
            match fp.fgets(OS_MAXSTR + 1) {
                Some(b) => {
                    current = offset;
                    offset = fp.ftell();
                    if b.last() == Some(&b'\n') {
                        log().warn(format!("Overlong JSON alert read from '{ALERTSJSON_DAILY}'"));
                        return None;
                    }
                }
                None => break,
            }
        }
        log().debug2(format!("Can't read from '{ALERTSJSON_DAILY}'. Trying again"));
        if initial >= 0 && !fp.seek(SeekFrom::Start(initial as u64)) {
            self.flags = CRALERT_READ_FAILED;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "** Alert 1712345678.123: mail  - syslog,sshd,authentication_success,\n\
        2024 Apr 05 10:00:00 (web1) 10.0.0.5->/var/log/auth.log\n\
        Rule: 5715 (level 3) -> 'sshd: authentication success.'\n\
        Src IP: 1.2.3.4\nUser: root\n\
        Apr  5 10:00:00 web1 sshd[1]: Accepted password for root\n\n";

    #[test]
    fn reads_alerts() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.log");
        std::fs::write(&p, format!("{A}{}", A.replace("mail  -", "- ").replace("5715", "5716"))).unwrap();
        let mut f = CFile::open(p.to_str().unwrap()).unwrap();
        let a = get_alert_data(CRALERT_MAIL_SET, &mut f).unwrap();
        assert_eq!((a.rule, a.level), (5715, 3));
        assert_eq!(a.comment.as_deref(), Some("sshd: authentication success."));
        assert_eq!(a.location.as_deref(), Some("(web1) 10.0.0.5->/var/log/auth.log"));
        assert_eq!(a.date.as_deref(), Some("2024 Apr 05 10:00:00"));
        assert_eq!(a.group.as_deref(), Some("syslog,sshd,authentication_success,"));
        assert_eq!((a.srcip.as_deref(), a.user.as_deref()), (Some("1.2.3.4"), Some("root")));
        assert_eq!(a.log, vec!["Apr  5 10:00:00 web1 sshd[1]: Accepted password for root".to_string(), String::new()]);
        // the second alert has no "mail" flag: skipped with the mail filter
        assert!(get_alert_data(CRALERT_MAIL_SET, &mut f).is_none());
        let mut f = CFile::open(p.to_str().unwrap()).unwrap();
        get_alert_data(CRALERT_READ_ALL, &mut f).unwrap();
        assert_eq!(get_alert_data(CRALERT_READ_ALL, &mut f).unwrap().rule, 5716);
    }
}
