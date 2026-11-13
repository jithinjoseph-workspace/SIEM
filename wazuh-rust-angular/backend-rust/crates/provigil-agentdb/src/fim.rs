//! `agent <id> syscheck | fim_file | fim_registry | fim_registry_key | fim_registry_value <sub>`
//! (spec § 2.1): FIM entries and the FIM scan info.

use std::sync::Arc;

use siem_cjson::Json;
use siem_sqlite::{Stmt, SQLITE_DONE, SQLITE_MISUSE, SQLITE_ROW};

use crate::checksum::{self, Sum};
use crate::integrity;
use crate::text::{find_unescaped, near, read_long, until_nul};
use crate::{Answer, Engine, Handle, INVALID};

/// `(double)` → `(long)` as the old code converted it (out of range = the minimum).
pub fn d2long(d: f64) -> i64 {
    if d.is_nan() || d >= 9.223372036854775808e18 || d < -9.223372036854775808e18 {
        i64::MIN
    } else {
        d as i64
    }
}

/// An octal number (`strtol(s, NULL, 8)`, saturating).
fn read_octal(s: &[u8]) -> i64 {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut v: i128 = 0;
    while i < s.len() && (b'0'..=b'7').contains(&s[i]) {
        v = (v * 8 + (s[i] - b'0') as i128).min(i64::MAX as i128 + 1);
        i += 1;
    }
    let v = if neg { -v } else { v };
    v.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// A whole decimal number, or None (anything after it, or out of range).
fn strict_long(s: &[u8]) -> Option<i64> {
    let (v, end) = read_long(s);
    if end == 0 || end != s.len() {
        return None;
    }
    // read_long saturates; a saturated value is only valid when the text says exactly that
    let digits: Vec<u8> = s.iter().copied().filter(|c| c.is_ascii_digit()).skip_while(|&c| c == b'0').collect();
    let exact = std::str::from_utf8(&digits).ok().and_then(|d| d.parse::<i128>().ok()).unwrap_or(0);
    let exact = if s.contains(&b'-') { -exact } else { exact };
    (exact == v as i128).then_some(v)
}

const SCAN_FIELDS: [(&[u8], &str); 7] = [
    (b"first_start", "first_start = ?, start_scan = ?"),
    (b"first_end", "first_end = ?, end_scan = ?"),
    (b"start_scan", "start_scan = ?"),
    (b"end_scan", "end_scan = ?"),
    (b"fim_first_check", "fim_first_check = ?"),
    (b"fim_second_check", "fim_second_check = ?"),
    (b"fim_third_check", "fim_third_check = ?"),
];

impl Engine {
    fn fim_stmt(&self, h: &mut Handle, sql: &str) -> Option<Arc<Stmt>> {
        let st = self.stmt_plain(h, sql);
        if st.is_none() {
            self.error(cat!("DB(", h.id.clone(), ") Can't cache statement"));
        }
        st
    }

    /// Sets a scan-info field of `module`: rows changed, or -1 (unknown field included).
    fn scan_info_update(&self, h: &mut Handle, module: &[u8], field: &[u8], value: i64) -> i32 {
        let r = match SCAN_FIELDS.iter().find(|(f, _)| *f == until_nul(field)) {
            None => SQLITE_MISUSE,
            Some((_, set)) => {
                let Some(st) = self.stmt_plain(h, &format!("UPDATE scan_info SET {set} WHERE module = ?;")) else {
                    self.error(cat!("DB(", h.id.clone(), ") Cannot cache statement"));
                    return -1;
                };
                st.bind_int64(1, value);
                if set.contains(',') {
                    st.bind_int64(2, value);
                    st.bind_text(3, Some(module));
                } else {
                    st.bind_text(2, Some(module));
                }
                self.step(&st)
            }
        };
        if r == SQLITE_DONE {
            h.db().changes()
        } else {
            self.debug(cat!("DB(", h.id.clone(), ") SQLite: ", h.errmsg()));
            -1
        }
    }

    /// A scan-info field of `module`: (1 found / 0 not / -1 error, value).
    fn scan_info_get(&self, h: &mut Handle, module: &[u8], field: &[u8]) -> (i32, i64) {
        let field = until_nul(field);
        let r = if SCAN_FIELDS.iter().any(|(f, _)| *f == field) {
            let name = String::from_utf8_lossy(field);
            let Some(st) = self.stmt_plain(h, &format!("SELECT {name} FROM scan_info WHERE module = ?;")) else {
                self.error(cat!("DB(", h.id.clone(), ") Cannot cache statement"));
                return (-1, 0);
            };
            st.bind_text(1, Some(module));
            match self.step(&st) {
                SQLITE_ROW => return (1, st.column_int64(0)),
                r => r,
            }
        } else {
            SQLITE_MISUSE
        };
        if r == SQLITE_DONE {
            (0, 0)
        } else {
            self.debug(cat!("DB(", h.id.clone(), ") SQLite: ", h.errmsg()));
            (-1, 0)
        }
    }

    pub(crate) fn fim_command(&self, h: &mut Handle, cmd: &[u8], input: &[u8]) -> Answer {
        let component = match cmd {
            b"syscheck" => integrity::FIM,
            b"fim_file" => integrity::FIM_FILE,
            b"fim_registry" => integrity::FIM_REGISTRY,
            b"fim_registry_key" => integrity::FIM_REGISTRY_KEY,
            _ => integrity::FIM_REGISTRY_VALUE,
        };
        let input = until_nul(input);
        let id = h.id.clone();
        let Some(sp) = find_unescaped(input, b' ') else {
            self.debug2(cat!("DB(", id, ") Invalid FIM query syntax: ", input));
            return (INVALID, near("err Invalid FIM query syntax", input));
        };
        let (sub, next) = (&input[..sp], &input[sp + 1..]);
        match sub {
            b"scan_info_get" => {
                let (r, ts) = self.scan_info_get(h, b"fim", next);
                if r < 0 {
                    self.debug(cat!("DB(", id, ") Cannot get FIM scan info."));
                    (r, b"err Cannot get fim scan info.".to_vec())
                } else {
                    (r, cat!("ok ", ts))
                }
            }
            b"updatedate" => match self.fim_stmt(h, "UPDATE fim_entry SET date = strftime('%s', 'now') WHERE file = ?;") {
                None => self.fim_fail(-1, &id, "Cannot update fim date field.", "err Cannot update fim date field."),
                Some(st) => {
                    st.bind_text(1, Some(next));
                    if self.step(&st) == SQLITE_DONE {
                        self.debug2(cat!("DB(", id, ") Updated date field for file '", next, "' to '", self.time(), "'"));
                        (0, b"ok".to_vec())
                    } else {
                        self.debug(cat!("DB(", id.clone(), ") SQLite: ", h.errmsg()));
                        self.fim_fail(-1, &id, "Cannot update fim date field.", "err Cannot update fim date field.")
                    }
                }
            },
            b"cleandb" => {
                let r = self.fim_clean_old(h);
                if r < 0 {
                    self.fim_fail(r, &id, "Cannot clean fim database.", "err Cannot clean fim database.")
                } else {
                    (r, b"ok".to_vec())
                }
            }
            b"scan_info_update" => {
                let Some(p) = find_unescaped(next, b' ') else {
                    self.debug(cat!("DB(", id, ") Invalid scan_info fim query syntax."));
                    return (INVALID, near("err Invalid Syscheck query syntax", next));
                };
                let ts = read_long(&next[p + 1..]).0;
                let r = self.scan_info_update(h, b"fim", &next[..p], ts);
                if r < 0 {
                    self.fim_fail(r, &id, "Cannot save fim control message.", "err Cannot save fim control message")
                } else {
                    (r, b"ok".to_vec())
                }
            }
            b"control" => {
                self.fim_checks_control(h, next);
                (0, b"ok".to_vec())
            }
            b"load" => {
                let (r, s) = self.fim_load(h, next);
                if r < 0 {
                    self.fim_fail(r, &id, "Cannot load FIM.", "err Cannot load Syscheck")
                } else {
                    (r, cat!("ok ", s))
                }
            }
            b"delete" => {
                let r = self.fim_delete(h, next);
                if r < 0 {
                    self.fim_fail(r, &id, "Cannot delete FIM entry.", "err Cannot delete Syscheck")
                } else {
                    (r, b"ok".to_vec())
                }
            }
            b"save" => {
                let bad = |rest: &[u8], with_prefix: bool| {
                    self.debug(cat!("DB(", id.clone(), ") Invalid FIM query syntax."));
                    if with_prefix {
                        self.debug2(cat!("DB(", id.clone(), ") FIM query: ", rest));
                    } else {
                        self.debug2(cat!("FIM query: ", rest));
                    }
                    (INVALID, near("err Invalid Syscheck query syntax", rest))
                };
                let Some(p) = find_unescaped(next, b' ') else { return bad(next, true) };
                let (kind, rest) = (&next[..p], &next[p + 1..]);
                let ftype = match kind {
                    b"file" => 0,
                    b"registry" => 1,
                    _ => return bad(kind, true),
                };
                let Some(p2) = find_unescaped(rest, b' ') else { return bad(rest, false) };
                let (sum_text, file) = (&rest[..p2], &rest[p2 + 1..]);
                // only the part before '!' carries escaped spaces
                let unesc = match sum_text.iter().position(|&x| x == b'!') {
                    Some(m) => {
                        let mut u = checksum::replace(&sum_text[..m], b"\\ ", b" ");
                        u.extend_from_slice(&sum_text[m..]);
                        u
                    }
                    None => checksum::replace(sum_text, b"\\ ", b" "),
                };
                let r = self.fim_save(h, ftype, &unesc, file);
                if r < 0 {
                    self.fim_fail(r, &id, "Cannot save FIM.", "err Cannot save Syscheck")
                } else {
                    (r, b"ok".to_vec())
                }
            }
            b"save2" => {
                if self.fim_save2(h, next) == INVALID {
                    self.debug(cat!("DB(", id, ") Cannot save FIM."));
                    return (INVALID, b"err Cannot save Syscheck".to_vec());
                }
                (0, b"ok".to_vec())
            }
            s if s.starts_with(b"integrity_check_") => self.integrity_check_command(h, component, s, next, "FIM"),
            b"integrity_clear" => self.integrity_clear_command(h, component, next, "FIM"),
            _ => {
                self.debug(cat!("DB(", id, ") Invalid FIM query syntax."));
                self.debug2(cat!("DB query error near: ", sub));
                (INVALID, near("err Invalid Syscheck query syntax", sub))
            }
        }
    }

    fn fim_fail(&self, r: i32, id: &str, m1: &str, err: &str) -> Answer {
        self.debug(cat!("DB(", id, ") ", m1));
        (r, err.as_bytes().to_vec())
    }

    /// Shifts the three FIM check times (third ← second ← first ← `last`).
    fn fim_checks_control(&self, h: &mut Handle, last: &[u8]) {
        let last = read_long(last).0;
        let id = h.id.clone();
        let mut value = 0i64;
        for (from, to) in [(b"fim_second_check".as_slice(), b"fim_third_check".as_slice()), (b"fim_first_check", b"fim_second_check")] {
            let (r, v) = self.scan_info_get(h, b"fim", from);
            if r < 0 {
                self.debug(cat!("DB(", id.clone(), ") Cannot get scan_info entry"));
            } else {
                value = v;
            }
            if self.scan_info_update(h, b"fim", to, value) < 0 {
                self.debug(cat!("DB(", id.clone(), ") Cannot update scan_info entry"));
            }
        }
        if self.scan_info_update(h, b"fim", b"fim_first_check", last) < 0 {
            self.debug(cat!("DB(", id, ") Cannot update scan_info entry"));
        }
    }

    fn fim_load(&self, h: &mut Handle, file: &[u8]) -> (i32, Vec<u8>) {
        let Some(st) = self.fim_stmt(
            h,
            "SELECT changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, date, attributes, symbolic_path FROM fim_entry WHERE file = ?;",
        ) else {
            return (-1, Vec::new());
        };
        if !h.transaction && !self.begin(h) {
            self.error(cat!("DB(", h.id.clone(), ") Can't begin transaction"));
            return (-1, Vec::new());
        }
        st.bind_text(1, Some(file));
        match self.step(&st) {
            SQLITE_ROW => {
                let mut sum = Sum {
                    changes: st.column_int64(0) as i32,
                    size: st.column_text(1),
                    uid: st.column_text(3),
                    gid: st.column_text(4),
                    md5: st.column_text(5),
                    sha1: st.column_text(6),
                    uname: st.column_text(7),
                    gname: st.column_text(8),
                    mtime: st.column_int64(9),
                    inode: st.column_int64(10),
                    sha256: st.column_text(11),
                    date_alert: st.column_int64(12),
                    attributes: st.column_text(13),
                    symbolic_path: st.column_text(14),
                    ..Default::default()
                };
                match st.column_text(2) {
                    Some(p) if p.first().is_some_and(|c| c.is_ascii_digit()) => sum.perm = read_octal(&p) as i32,
                    p => sum.win_perm = p,
                }
                match checksum::build(&sum, 65536 - 16) {
                    Some(o) => (0, o),
                    None => (-1, Vec::new()),
                }
            }
            SQLITE_DONE => (0, Vec::new()),
            _ => {
                self.error(cat!("DB(", h.id.clone(), ") SQLite: ", h.errmsg()));
                (-1, Vec::new())
            }
        }
    }

    fn fim_delete(&self, h: &mut Handle, path: &[u8]) -> i32 {
        let Some(st) = self.fim_stmt(h, "DELETE FROM fim_entry WHERE full_path = ?;") else { return -1 };
        st.bind_text(1, Some(path));
        match self.step(&st) {
            SQLITE_ROW | SQLITE_DONE => 0,
            _ => {
                self.debug(cat!("DB(", h.id.clone(), ") SQLite: ", h.errmsg()));
                -1
            }
        }
    }

    /// Deletes entries not seen since the third FIM check (the two configuration files kept).
    fn fim_clean_old(&self, h: &mut Handle) -> i32 {
        let id = h.id.clone();
        let (r, third) = self.scan_info_get(h, b"fim", b"fim_third_check");
        if r < 0 {
            self.debug(cat!("DB(", id.clone(), ") Can't get scan_info entry"));
        }
        let Some(st) = self.fim_stmt(
            h,
            "SELECT full_path, changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, date, attributes, symbolic_path FROM fim_entry WHERE date < ?;",
        ) else {
            return -1;
        };
        st.bind_int64(1, third);
        loop {
            match self.step(&st) {
                SQLITE_DONE => break,
                SQLITE_ROW => {}
                _ => {
                    self.debug(cat!("DB(", id, ") SQLite: ", h.errmsg()));
                    return -1;
                }
            }
            let file = st.column_text(0).unwrap_or_default();
            let date = st.column_int64(13);
            self.debug2(cat!("DB(", id.clone(), ") Cleaning FIM DDBB. Deleting entry '", file.clone(), "' date<tscheck3 '", date, "'<'", third, "'."));
            // the configuration files themselves are never removed
            if file != b"internal_options.conf" && file != b"ossec.conf" && self.fim_delete(h, &file) < 0 {
                self.debug(cat!("DB(", id.clone(), ") Can't delete FIM entry '", file, "'."));
            }
        }
        0
    }

    /// `save <file|registry> <checksum> <path>`
    fn fim_save(&self, h: &mut Handle, ftype: i32, text: &[u8], file: &[u8]) -> i32 {
        let mut sum = Sum::default();
        let head = checksum::split_extra(&mut sum, text);
        if checksum::decode(&mut sum, &head) < 0 {
            self.debug(cat!("Checksum: ", head));
            return -1;
        }
        let id = h.id.clone();
        if !h.transaction && !self.begin(h) {
            self.error(cat!("DB(", id, ") Can't begin transaction"));
            return -1;
        }
        let Some(find) = self.fim_stmt(h, "SELECT 1 FROM fim_entry WHERE file = ?") else {
            self.debug(cat!("DB(", id, ") Can't find file by name"));
            return -1;
        };
        find.bind_text(1, Some(file));
        let found = match self.step(&find) {
            SQLITE_ROW => true,
            SQLITE_DONE => false,
            _ => {
                self.debug(cat!("DB(", id.clone(), ") SQLite: ", h.errmsg()));
                self.debug(cat!("DB(", id, ") Can't find file by name"));
                return -1;
            }
        };
        let perm = sum.win_perm.as_ref().map(|w| checksum::replace(w, b"\\:", b":")).unwrap_or_else(|| format!("{:06o}", sum.perm as u32).into_bytes());
        if !found {
            let kind: &[u8] = if ftype == 0 { b"file" } else { b"registry_key" };
            let Some(st) = self.fim_stmt(
                h,
                "INSERT INTO fim_entry (file, type, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes, symbolic_path, full_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            ) else {
                self.debug(cat!("DB(", id, ") Can't insert file entry"));
                return -1;
            };
            st.bind_text(1, Some(file));
            st.bind_text(2, Some(kind));
            st.bind_text(3, sum.size.as_deref());
            st.bind_text(4, Some(&perm));
            for (i, v) in [&sum.uid, &sum.gid, &sum.md5, &sum.sha1, &sum.uname, &sum.gname].into_iter().enumerate() {
                st.bind_text(5 + i as i32, v.as_deref());
            }
            st.bind_int64(11, sum.mtime);
            st.bind_int64(12, sum.inode);
            st.bind_text(13, sum.sha256.as_deref());
            st.bind_text(14, sum.attributes.as_deref());
            st.bind_text(15, sum.symbolic_path.as_deref());
            st.bind_text(16, Some(file));
            if self.step(&st) != SQLITE_DONE {
                self.debug(cat!("DB(", id.clone(), ") SQLite: ", h.errmsg()));
                self.debug(cat!("DB(", id, ") Can't insert file entry"));
                return -1;
            }
            0
        } else {
            let Some(st) = self.fim_stmt(
                h,
                "UPDATE fim_entry SET date = strftime('%s', 'now'), changes = ?, size = ?, perm = ?, uid = ?, gid = ?, md5 = ?, sha1 = ?, uname = ?, gname = ?, mtime = ?, inode = ?, sha256 = ?, attributes = ?, symbolic_path = ? WHERE file = ?;",
            ) else {
                self.debug(cat!("DB(", id, ") Can't update file entry"));
                return -1;
            };
            st.bind_int64(1, sum.changes as i64);
            st.bind_text(2, sum.size.as_deref());
            st.bind_text(3, Some(&perm));
            for (i, v) in [&sum.uid, &sum.gid, &sum.md5, &sum.sha1, &sum.uname, &sum.gname].into_iter().enumerate() {
                st.bind_text(4 + i as i32, v.as_deref());
            }
            st.bind_int64(10, sum.mtime);
            st.bind_int64(11, sum.inode);
            st.bind_text(12, sum.sha256.as_deref());
            st.bind_text(13, sum.attributes.as_deref());
            st.bind_text(14, sum.symbolic_path.as_deref());
            st.bind_text(15, Some(file));
            let changed = if self.step(&st) == SQLITE_DONE {
                h.db().changes()
            } else {
                self.debug(cat!("DB(", id.clone(), ") SQLite: ", h.errmsg()));
                -1
            };
            if changed < 1 {
                self.debug(cat!("DB(", id, ") Can't update file entry"));
                return -1;
            }
            0
        }
    }

    /// `save2 <json>`: a FIM entry from the JSON sync message.
    fn fim_save2(&self, h: &mut Handle, payload: &[u8]) -> i32 {
        let id = h.id.clone();
        let Some(data) = siem_cjson::parse(until_nul(payload)) else {
            self.debug(cat!("DB(", id, "): cannot parse FIM payload: '", until_nul(payload), "'"));
            return -1;
        };
        if !h.transaction && !self.begin(h) {
            self.error(cat!("DB(", id, ") Can't begin transaction."));
            return -1;
        }
        if self.fim_insert2(h, &data) == -1 {
            self.debug(cat!("DB(", id, ") Can't insert file entry."));
            return -1;
        }
        0
    }

    fn fim_insert2(&self, h: &mut Handle, data: &Json) -> i32 {
        let id = h.id.clone();
        let fail = |m: Vec<u8>| {
            self.error(m);
            -1
        };
        let Some(jp) = data.get("path").or_else(|| data.get("index")) else {
            return fail(cat!("DB(", id, ") fim/save request with no file path argument."));
        };
        let path: Option<Vec<u8>> = jp.as_bytes().map(|p| until_nul(p).to_vec());
        let ts = match data.get("timestamp") {
            Some(Json::Number { double, .. }) => *double,
            _ => return fail(cat!("DB(", id, ") fim/save request with no timestamp path argument.")),
        };
        let attrs = match data.get("attributes") {
            Some(a @ Json::Object(_)) => a,
            _ => return fail(cat!("DB(", id, ") fim/save request with no valid attributes.")),
        };
        let Some(t0) = attrs.get("type").and_then(|t| t.as_bytes()).map(|t| until_nul(t).to_vec()) else {
            return fail(cat!("DB(", id, ") fim/save request with no type attribute."));
        };
        let mut kind = t0;
        let mut arch: Option<Vec<u8>> = None;
        let mut value_name: Option<Vec<u8>> = None;
        let esc = |v: &[u8]| checksum::replace(&checksum::replace(v, b"\\", b"\\\\"), b":", b"\\:");
        let full_path: Option<Vec<u8>>;
        if kind == b"file" {
            full_path = path.clone();
        } else if kind == b"registry" {
            full_path = path.clone();
            kind = b"registry_key".to_vec();
        } else if kind.starts_with(b"registry_") {
            let Some(Json::Number { double: ver, .. }) = data.get("version") else {
                // sync messages without a version are ignored
                return 0;
            };
            arch = data.get("arch").and_then(|a| a.as_bytes()).map(|a| until_nul(a).to_vec());
            value_name = data.get("value_name").and_then(|a| a.as_bytes()).map(|a| until_nul(a).to_vec());
            if *ver == 2.0 {
                let pe = match &path {
                    Some(p) => esc(p),
                    None => b"(null)".to_vec(),
                };
                let Some(a) = &arch else { return fail(cat!("DB(", id, ") fim/save registry request with no arch argument.")) };
                if &kind[9..] == b"key" {
                    value_name = None;
                    full_path = Some(cat!(a, " ", pe));
                } else if &kind[9..] == b"value" {
                    let Some(vn) = &value_name else {
                        return fail(cat!("DB(", id, ") fim/save registry value request with no value name argument."));
                    };
                    full_path = Some(cat!(a, " ", pe, ":", esc(vn)));
                } else {
                    return fail(cat!("DB(", id, ") fim/save request with invalid '", kind, "' type argument."));
                }
            } else if *ver == 3.0 {
                let Some(ji) = data.get("index") else {
                    return fail(cat!("DB(", id, ") version 3.0 fim/save request with no index argument."));
                };
                full_path = ji.as_bytes().map(|i| until_nul(i).to_vec());
            } else {
                full_path = None;
            }
        } else {
            return fail(cat!("DB(", id, ") fim/save request with invalid '", kind, "' type argument."));
        }
        let Some(st) = self.fim_stmt(
            h,
            "INSERT OR REPLACE INTO fim_entry (file, type, date, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes, symbolic_path, checksum, arch, value_name, value_type, full_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        ) else {
            return -1;
        };
        st.bind_text(1, path.as_deref());
        st.bind_text(2, Some(&kind));
        st.bind_int64(3, d2long(ts));
        st.bind_text(18, arch.as_deref());
        st.bind_text(19, value_name.as_deref());
        st.bind_text(21, full_path.as_deref());
        if let Json::Object(members) = attrs {
            for (key, el) in members {
                let key = until_nul(key);
                let invalid = || {
                    self.error(cat!("DB(", id.clone(), ") Invalid attribute name: ", key));
                    -1
                };
                match el {
                    Json::Number { double, int } => match key {
                        b"size" => {
                            st.bind_int64(4, d2long(*double));
                        }
                        b"mtime" => {
                            st.bind_int(12, *int);
                        }
                        b"inode" => {
                            st.bind_int64(13, d2long(*double));
                        }
                        _ => return invalid(),
                    },
                    Json::String(v) => {
                        let col = match key {
                            b"type" => continue,
                            b"perm" => 5,
                            b"uid" => 6,
                            b"gid" => 7,
                            b"hash_md5" => 8,
                            b"hash_sha1" => 9,
                            b"user_name" => 10,
                            b"group_name" => 11,
                            b"hash_sha256" => 14,
                            b"attributes" => 15,
                            b"symbolic_path" => 16,
                            b"checksum" => 17,
                            b"value_type" => 20,
                            b"inode" => {
                                let v = until_nul(v);
                                match strict_long(v) {
                                    Some(n) => {
                                        st.bind_int64(13, n);
                                    }
                                    None => {
                                        self.error(cat!("DB(", id.clone(), ") Invalid inode value: ", v));
                                        st.bind_int64(13, 0);
                                    }
                                }
                                continue;
                            }
                            _ => return invalid(),
                        };
                        st.bind_text(col, Some(v));
                    }
                    Json::Object(_) => {
                        if key == b"perm" {
                            st.bind_text(5, Some(&el.print_unformatted()));
                        } else {
                            return invalid();
                        }
                    }
                    _ => {}
                }
            }
        }
        if self.step(&st) != SQLITE_DONE {
            self.debug(cat!("DB(", id, ") SQLite: ", h.errmsg()));
            return -1;
        }
        0
    }
}
