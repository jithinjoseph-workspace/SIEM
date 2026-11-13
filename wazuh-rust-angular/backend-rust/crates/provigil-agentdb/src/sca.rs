//! `agent <id> sca …` (spec § 2.3): security policy checks, scans and policies.

use sha2::{Digest, Sha256};
use siem_cjson::Json;
use siem_sqlite::{Stmt, SQLITE_CONSTRAINT, SQLITE_DONE, SQLITE_ROW};
use std::sync::Arc;

use crate::text::{near, read_long, until_nul};
use crate::{Answer, Engine, Handle, INVALID};

const BAD: &str = "err Invalid Security Configuration Assessment query syntax";
const BAD2: &str = "err Invalid configuration assessment query syntax";
/// (DEBUG1, DEBUG2 prefix) of a missing `|`.
const SCA: (&str, &str) = ("Invalid Security Configuration Assessment query syntax.", "Security Configuration Assessment query: ");
const CA: (&str, &str) = ("Invalid configuration assessment query syntax.", "configuration assessment query: ");
/// Longest text of a "found" answer.
const RESULT_SIZE: usize = 65536 - 16 - 1;

/// A NULL text printed the way C prints it.
fn or_null(s: Option<Vec<u8>>) -> Vec<u8> {
    s.unwrap_or_else(|| b"(null)".to_vec())
}
fn cut(mut v: Vec<u8>) -> Vec<u8> {
    v.truncate(RESULT_SIZE);
    v
}
/// A number field: `NULL…` = -1.
fn num(f: &[u8]) -> i32 {
    if f.starts_with(b"NULL") {
        -1
    } else {
        read_long(f).0 as i32
    }
}

/// Walks a `|`-separated argument the way the commands read it.
struct Fields<'a> {
    s: &'a [u8],
    pos: usize,
}
impl<'a> Fields<'a> {
    /// The rest from the current field to the end.
    fn rest(&self) -> &'a [u8] {
        &self.s[self.pos.min(self.s.len())..]
    }
    /// The current field up to the next `|`, moving past it; None when there is no `|`.
    fn next(&mut self) -> Option<&'a [u8]> {
        let r = self.rest();
        let p = r.iter().position(|&c| c == b'|')?;
        self.pos += p + 1;
        Some(&r[..p])
    }
}

impl Engine {
    fn sca_stmt(&self, h: &mut Handle, sql: &str, cache_msg: &str) -> Option<Arc<Stmt>> {
        if !h.transaction && !self.begin(h) {
            self.debug(b"cannot begin transaction".to_vec());
            return None;
        }
        match self.stmt_plain(h, sql) {
            Some(st) => Some(st),
            None => {
                self.error(cat!("DB(", h.id.clone(), ") sqlite3_prepare_v2() stmt(", sql, "): ", h.errmsg()));
                self.debug(cache_msg.as_bytes().to_vec());
                None
            }
        }
    }

    fn sca_done(&self, h: &Handle, st: &Stmt) -> i32 {
        if self.step(st) == SQLITE_DONE {
            0
        } else {
            self.error(cat!("SQLite: ", h.errmsg()));
            -1
        }
    }

    fn sca_changes(&self, h: &Handle, st: &Stmt) -> i32 {
        if self.step(st) == SQLITE_DONE {
            h.db().changes()
        } else {
            self.error(cat!("SQLite: ", h.errmsg()));
            -1
        }
    }

    /// Inserts where a duplicate is fine (logged at debug level).
    fn sca_unique(&self, h: &Handle, st: &Stmt) -> i32 {
        match self.step(st) {
            SQLITE_DONE => 0,
            SQLITE_CONSTRAINT => {
                let e = h.errmsg();
                if e.starts_with(b"UNIQUE") {
                    self.debug(cat!("SQLite: ", e));
                    0
                } else {
                    self.error(cat!("SQLite: ", e));
                    -1
                }
            }
            _ => {
                self.error(cat!("SQLite: ", h.errmsg()));
                -1
            }
        }
    }

    /// A one-row lookup: (1 found / 0 not found / -1 error, value).
    fn sca_lookup(&self, h: &mut Handle, sql: &str, bind: &dyn Fn(&Stmt), value: &dyn Fn(&Stmt) -> Vec<u8>) -> (i32, Vec<u8>) {
        let Some(st) = self.sca_stmt(h, sql, "cannot cache statement") else { return (-1, Vec::new()) };
        bind(&st);
        match self.step(&st) {
            SQLITE_ROW => (1, cut(value(&st))),
            SQLITE_DONE => (0, Vec::new()),
            _ => {
                self.error(cat!("SQLite: ", h.errmsg()));
                (-1, Vec::new())
            }
        }
    }

    /// Joins one column of every row with `sep`: (1 rows / 0 none / -1 error, text or None when all NULL).
    fn sca_join(&self, h: &mut Handle, sql: &str, bind: &dyn Fn(&Stmt), sep: u8) -> (i32, Option<Vec<u8>>) {
        let Some(st) = self.sca_stmt(h, sql, "cannot cache statement") else { return (-1, None) };
        bind(&st);
        let mut out: Option<Vec<u8>> = None;
        let mut any = false;
        loop {
            match self.step(&st) {
                SQLITE_ROW => {
                    any = true;
                    if let Some(v) = st.column_text(0) {
                        match &mut out {
                            Some(o) => {
                                o.push(sep);
                                o.extend_from_slice(&v);
                            }
                            None => out = Some(v),
                        }
                    }
                }
                SQLITE_DONE => break,
                _ => {
                    self.error(cat!("SQLite: ", h.errmsg()));
                    return (-1, None);
                }
            }
        }
        (if any { 1 } else { 0 }, out)
    }

    fn found(&self, r: (i32, Vec<u8>), err: &str) -> Answer {
        match r.0 {
            0 => (0, b"ok not found".to_vec()),
            1 => (1, cat!("ok found ", r.1)),
            n => {
                self.debug(b"Cannot query Security Configuration Assessment.".to_vec());
                (n, err.as_bytes().to_vec())
            }
        }
    }

    fn sca_written(&self, r: i32, ok_msg: &str, m1: &str, err: &str) -> Answer {
        if r < 0 {
            self.debug(m1.as_bytes().to_vec());
            (r, err.as_bytes().to_vec())
        } else {
            (r, ok_msg.as_bytes().to_vec())
        }
    }

    pub(crate) fn sca_command(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let input = until_nul(input);
        let Some(sp) = input.iter().position(|&c| c == b' ') else {
            self.debug(SCA.0.as_bytes().to_vec());
            self.debug2(cat!(SCA.1, input));
            return (INVALID, near(BAD, input));
        };
        let (cmd, args) = (&input[..sp], &input[sp + 1..]);
        let mut f = Fields { s: args, pos: 0 };
        // a missing `|`: logs with `log`, answers with `msg`
        macro_rules! bar {
            ($log:expr, $msg:expr) => {
                match f.next() {
                    Some(x) => x,
                    None => {
                        self.debug($log.0.as_bytes().to_vec());
                        self.debug2(cat!($log.1, f.rest()));
                        return (INVALID, near($msg, f.rest()));
                    }
                }
            };
        }
        match cmd {
            b"query" => {
                let id = read_long(args).0 as i32;
                let r = self.sca_lookup(h, "SELECT id,result FROM sca_check WHERE id = ?;", &|st| {
                    st.bind_int(1, id);
                }, &|st| or_null(st.column_text(1)));
                self.found(r, "err Cannot query Security Configuration Assessment")
            }
            b"update" => {
                let id = read_long(f.rest()).0 as i32;
                bar!(SCA, BAD);
                let result = bar!(SCA, BAD);
                let reason = bar!(SCA, BAD);
                let rest = f.rest();
                let scan = if rest.starts_with(b"NULL") { -1 } else { read_long(rest).0 as i32 };
                let r = match self.sca_stmt(h, "UPDATE sca_check SET scan_id = ?, result = ?, reason = ? WHERE id = ?;", "cannot cache statement") {
                    None => -1,
                    Some(st) => {
                        st.bind_int(1, scan);
                        st.bind_text(2, Some(result));
                        st.bind_text(3, Some(reason));
                        st.bind_int(4, id);
                        self.sca_changes(h, &st)
                    }
                };
                self.sca_written(r, "ok", "Cannot update Security Configuration Assessment information.", "err Cannot update Security Configuration Assessment information.")
            }
            b"insert" => self.sca_insert(h, args),
            b"delete_policy" => {
                let r = match self.sca_stmt(h, "DELETE FROM sca_policy WHERE id = ?;", "cannot cache statement") {
                    None => -1,
                    Some(st) => {
                        st.bind_text(1, Some(args));
                        if self.step(&st) == SQLITE_DONE {
                            if let Some(del) = self.sca_stmt(h, "DELETE FROM sca_scan_info WHERE policy_id = ?;", "cannot cache statement") {
                                del.bind_text(1, Some(args));
                                self.sca_done(h, &del);
                            }
                            0
                        } else {
                            self.error(cat!("SQLite: ", h.errmsg()));
                            -1
                        }
                    }
                };
                self.sca_written(r, "ok", "Cannot delete Security Configuration Assessment information.", "err Cannot delete Security Configuration Assessment information.")
            }
            b"delete_check_distinct" => {
                let policy = bar!(SCA, BAD);
                let rest = f.rest();
                let scan = if rest.starts_with(b"NULL") { -1 } else { read_long(rest).0 as i32 };
                let r = match self.sca_stmt(h, "DELETE FROM sca_check WHERE scan_id != ? AND policy_id = ?;", "at wdb_sca_check_delete_distinct(): cannot cache statement") {
                    None => -1,
                    Some(st) => {
                        st.bind_int(1, scan);
                        st.bind_text(2, Some(policy));
                        self.sca_done(h, &st)
                    }
                };
                if r >= 0 {
                    self.sca_orphans(h);
                }
                self.sca_written(r, "ok", "Cannot delete Security Configuration Assessment checks.", "err Cannot delete Security Configuration Assessment checks.")
            }
            b"delete_check" => {
                let r = match self.sca_stmt(h, "DELETE FROM sca_check WHERE policy_id = ?;", "cannot cache statement") {
                    None => -1,
                    Some(st) => {
                        st.bind_text(1, Some(args));
                        self.sca_done(h, &st)
                    }
                };
                if r >= 0 {
                    self.sca_orphans(h);
                }
                self.sca_written(r, "ok", "Cannot delete Security Configuration Assessment information.", "err Cannot delete Security Configuration Assessment check information.")
            }
            b"query_results" => {
                let (r, joined) = self.sca_join(h, "SELECT result FROM sca_check WHERE policy_id = ? ORDER BY id;", &|st| {
                    st.bind_text(1, Some(args));
                }, b':');
                // the SHA-256 of all results ("not applicable" left out); empty when every one is NULL
                let v = match (r, joined) {
                    (1, Some(s)) => {
                        let s = replace(&s, b"not applicable", b"");
                        Sha256::digest(&s).iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect()
                    }
                    _ => Vec::new(),
                };
                self.found((r, v), "err Cannot query Security Configuration Assessment global")
            }
            b"query_scan" => {
                let r = self.sca_lookup(h, "SELECT policy_id,hash,id FROM sca_scan_info WHERE policy_id = ?;", &|st| {
                    st.bind_text(1, Some(args));
                }, &|st| cat!(or_null(st.column_text(1)), " ", st.column_int(2)));
                self.found(r, "err Cannot query Security Configuration Assessment scan")
            }
            b"query_policies" => {
                let (r, joined) = self.sca_join(h, "SELECT id FROM sca_policy;", &|_| {}, b',');
                let v = if r == 1 { cut(or_null(joined)) } else { Vec::new() };
                self.found((r, v), "err Cannot query Security Configuration Assessment scan")
            }
            b"query_policy" => {
                let r = self.sca_lookup(h, "SELECT id FROM sca_policy WHERE id = ?;", &|st| {
                    st.bind_text(1, Some(args));
                }, &|st| or_null(st.column_text(0)));
                self.found(r, "err Cannot query policy scan")
            }
            b"query_policy_sha256" => {
                let r = self.sca_lookup(h, "SELECT hash_file FROM sca_policy WHERE id = ?;", &|st| {
                    st.bind_text(1, Some(args));
                }, &|st| or_null(st.column_text(0)));
                self.found(r, "err Cannot query policy scan")
            }
            b"insert_policy" => {
                let mut v: Vec<&[u8]> = Vec::new();
                for _ in 0..5 {
                    v.push(bar!(SCA, BAD));
                }
                v.push(f.rest());
                let r = match self.sca_stmt(h, "INSERT INTO sca_policy (name,file,id,description,`references`,hash_file) VALUES(?,?,?,?,?,?);", "cannot cache statement") {
                    None => -1,
                    Some(st) => {
                        for (i, x) in v.iter().enumerate() {
                            st.bind_text(i as i32 + 1, Some(x));
                        }
                        self.sca_done(h, &st)
                    }
                };
                self.sca_written(r, "ok", "Cannot save Security Configuration Assessment information.", "err Cannot save Security Configuration Assessment global information.")
            }
            b"insert_rules" | b"insert_compliance" => {
                let id = read_long(f.rest()).0 as i32;
                bar!(SCA, BAD);
                let a = bar!(SCA, BAD2);
                let b = f.rest();
                let sql = if cmd == b"insert_rules" {
                    "INSERT INTO sca_check_rules (id_check,`type`, rule) VALUES(?,?,?);"
                } else {
                    "INSERT INTO sca_check_compliance (id_check,`key`,`value`) VALUES(?,?,?);"
                };
                let r = match self.sca_stmt(h, sql, "cannot cache statement") {
                    None => -1,
                    Some(st) => {
                        st.bind_int(1, id);
                        st.bind_text(2, Some(a));
                        st.bind_text(3, Some(b));
                        self.sca_unique(h, &st)
                    }
                };
                self.sca_written(r, "ok", "Cannot save configuration assessment information.", "err Cannot save configuration assessment global information.")
            }
            b"insert_scan_info" => {
                let mut v = [0i32; 3];
                for x in v.iter_mut() {
                    *x = num(bar!(CA, BAD2));
                }
                let policy = bar!(CA, BAD2);
                let mut n = [0i32; 5];
                for x in n.iter_mut() {
                    *x = num(bar!(CA, BAD2));
                }
                let hash = f.rest();
                let r = match self.sca_stmt(h, "INSERT INTO sca_scan_info (start_scan,end_scan,id,policy_id,pass,fail,invalid,total_checks,score,hash) VALUES (?,?,?,?,?,?,?,?,?,?);", "cannot cache statement") {
                    None => -1,
                    Some(st) => {
                        st.bind_int(1, v[0]);
                        st.bind_int(2, v[1]);
                        st.bind_int(3, v[2]);
                        st.bind_text(4, Some(policy));
                        for (i, x) in n.iter().enumerate() {
                            st.bind_int(5 + i as i32, *x);
                        }
                        st.bind_text(10, Some(hash));
                        self.sca_done(h, &st)
                    }
                };
                self.sca_written(r, "ok", "Cannot save configuration assessment information.", "err Cannot save configuration assessment information.")
            }
            b"update_scan_info" => {
                let module = bar!(CA, BAD2);
                let module = if module == b"NULL" { None } else { Some(module) };
                // quirk kept: one character after `|` is skipped before the number
                let rest = f.rest();
                let end = if rest.is_empty() { 0 } else { num(until_nul(&rest[1..])) };
                // quirk kept: the statement has ten values and gets two, so no row changes
                let r = match self.sca_stmt(h, SCAN_INFO_UPDATE, "cannot cache statement") {
                    None => -1,
                    Some(st) => {
                        st.bind_int(1, end);
                        st.bind_text(2, module);
                        self.sca_changes(h, &st)
                    }
                };
                self.sca_written(r, "ok", "Cannot save configuration assessment information.", "err Cannot save configuration assessment information.")
            }
            b"update_scan_info_start" => {
                let policy = bar!(CA, BAD2);
                let policy = if policy == b"NULL" { None } else { Some(policy) };
                // quirk kept: the second field is ignored, start and end both come from the third
                bar!(CA, BAD2);
                let start = num(f.rest());
                let end = num(bar!(CA, BAD2));
                let scan = num(bar!(CA, BAD2));
                let mut n = [0i32; 5];
                for x in n.iter_mut() {
                    *x = num(bar!(CA, BAD2));
                }
                let hash = f.rest();
                let r = match self.sca_stmt(h, SCAN_INFO_UPDATE, "cannot cache statement") {
                    None => -1,
                    Some(st) => {
                        st.bind_int(1, start);
                        st.bind_int(2, end);
                        st.bind_int(3, scan);
                        for (i, x) in n.iter().enumerate() {
                            st.bind_int(4 + i as i32, *x);
                        }
                        st.bind_text(9, Some(hash));
                        st.bind_text(10, policy);
                        self.sca_changes(h, &st)
                    }
                };
                self.sca_written(r, "ok", "Cannot save configuration assessment information.", "err Cannot save configuration assessment information.")
            }
            _ => {
                self.debug(b"Invalid configuration assessment query syntax.".to_vec());
                self.debug2(cat!("DB query error near: ", cmd));
                (INVALID, near("err Invalid Rootcheck query syntax", cmd))
            }
        }
    }

    /// Compliance and rule rows whose check is gone.
    fn sca_orphans(&self, h: &mut Handle) {
        for sql in [
            "DELETE FROM sca_check_compliance WHERE id_check NOT IN ( SELECT id FROM sca_check);",
            "DELETE FROM sca_check_rules WHERE id_check NOT IN ( SELECT id FROM sca_check);",
        ] {
            if let Some(st) = self.sca_stmt(h, sql, "cannot cache statement") {
                self.sca_done(h, &st);
            }
        }
    }

    /// `sca insert <json>` (spec § 2.3.1).
    fn sca_insert(&self, h: &mut Handle, text: &[u8]) -> Answer {
        let bad = |m: &str| {
            self.debug(m.as_bytes().to_vec());
            (INVALID, near(BAD, text))
        };
        let Ok((event, _)) = siem_cjson::parse_with_opts(text, false) else {
            return bad("Invalid Security Configuration Assessment query syntax. JSON object not found or invalid");
        };
        let Some(scan) = event.get("id") else {
            return bad("Invalid Security Configuration Assessment query syntax. JSON object not found or invalid");
        };
        let Json::Number { int: scan, .. } = scan else { return bad("Malformed JSON: field 'id' must be a number") };
        if *scan < 0 {
            return bad("Malformed JSON: field 'id' cannot be negative");
        }
        let Some(policy) = event.get("policy_id") else { return bad("Malformed JSON: field 'policy_id' not found") };
        let Some(policy) = policy.as_bytes() else { return bad("Malformed JSON: field 'policy_id' must be a string") };
        // errors inside `check` give an empty answer (kept)
        let empty = |m: &str| {
            self.debug(m.as_bytes().to_vec());
            (INVALID, Vec::new())
        };
        let Some(check) = event.get("check") else { return empty("Malformed JSON: field 'check' not found") };
        let Some(id) = check.get("id") else { return empty("Malformed JSON: field 'id' not found") };
        let Json::Number { int: id, .. } = id else { return empty("Malformed JSON: field 'id' must be a number") };
        let Some(title) = check.get("title") else { return empty("Malformed JSON: field 'title' not found") };
        let Some(title) = title.as_bytes() else { return empty("Malformed JSON: field 'title' must be a string") };
        let mut v: Vec<Option<Vec<u8>>> = Vec::new();
        for (k, name) in [
            ("description", "description"),
            ("rationale", "rationale"),
            ("remediation", "remediation"),
            ("references", "reference"),
            ("file", "file"),
            ("condition", "condition"),
            ("directory", "directory"),
            ("process", "process"),
            ("registry", "registry"),
            ("command", "command"),
            ("result", "result"),
            ("reason", "reason"),
        ] {
            match check.get(k) {
                None => v.push(None),
                Some(x) => match x.as_bytes() {
                    Some(s) => v.push(Some(until_nul(s).to_vec())),
                    None => return empty(&format!("Malformed JSON: field '{name}' must be a string")),
                },
            }
        }
        let g = |i: usize| v[i].as_deref();
        let result = v[10].clone().unwrap_or_else(|| b"not applicable".to_vec());
        let r = match self.sca_stmt(
            h,
            "INSERT INTO sca_check (id,scan_id,title,description,rationale,remediation,file,directory,process,registry,`references`,result,policy_id,command,reason,condition) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            "cannot cache statement",
        ) {
            None => -1,
            Some(st) => {
                st.bind_int(1, *id);
                st.bind_int(2, *scan);
                st.bind_text(3, Some(until_nul(title)));
                st.bind_text(4, g(0));
                st.bind_text(5, g(1));
                st.bind_text(6, g(2));
                st.bind_text(7, g(4));
                st.bind_text(8, g(6));
                st.bind_text(9, g(7));
                st.bind_text(10, g(8));
                st.bind_text(11, g(3));
                st.bind_text(12, Some(&result));
                st.bind_text(13, Some(until_nul(policy)));
                st.bind_text(14, g(9));
                st.bind_text(15, g(11));
                st.bind_text(16, g(5));
                self.sca_unique(h, &st)
            }
        };
        self.sca_written(r, "ok", "Cannot save Security Configuration Assessment information.", "err Cannot save Security Configuration Assessment information.")
    }
}

/// Both scan-info updates use this statement (see the quirks above).
const SCAN_INFO_UPDATE: &str =
    "UPDATE sca_scan_info SET start_scan = ?, end_scan = ?, id = ?, pass = ?, fail = ?, invalid = ?, total_checks = ?, score = ?, hash = ? WHERE policy_id = ?;";

/// Every `from` replaced by `to`.
pub fn replace(s: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return s.to_vec();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = s[i..].windows(from.len()).position(|w| w == from) {
        out.extend_from_slice(&s[i..i + p]);
        out.extend_from_slice(to);
        i += p + from.len();
    }
    out.extend_from_slice(&s[i..]);
    out
}
