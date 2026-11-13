//! Legacy `|`-separated agent commands (spec § 2.4–2.6): the field splitter with its exact error
//! rule, rootcheck and CIS-CAT.

use crate::text::{near, read_long, until_nul};
use crate::{Answer, Engine, Handle, INVALID, OK};
use siem_sqlite::SQLITE_DONE;

/// How a field is read.
#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    /// `NULL` = none.
    Text,
    /// `NULL…` = -1, else a number (32 bits).
    Int,
    /// `NULL…` = -1, else a number (64 bits).
    Long,
    /// A number (32 bits), no `NULL` rule.
    Plain,
    /// A number read as 64 bits and shown unsigned.
    Unsigned,
    /// A decimal number.
    Real,
}

#[derive(Clone, Debug)]
pub enum Val {
    Text(Option<Vec<u8>>),
    Int(i64),
    Real(f64),
}

impl Val {
    pub fn text(&self) -> Option<&[u8]> {
        match self {
            Val::Text(t) => t.as_deref(),
            _ => None,
        }
    }
    pub fn int(&self) -> i64 {
        match self {
            Val::Int(i) => *i,
            Val::Real(r) => *r as i64,
            Val::Text(_) => 0,
        }
    }
}

/// A decimal number like C's `strtod`.
pub fn read_real(s: &[u8]) -> f64 {
    crate::text::read_real(s).0
}

/// `printf("%f")`
pub fn fmt_f(v: f64) -> String {
    if v.is_nan() {
        if v.is_sign_negative() { "-nan".into() } else { "nan".into() }
    } else if v.is_infinite() {
        if v < 0.0 { "-inf".into() } else { "inf".into() }
    } else {
        format!("{v:.6}")
    }
}

/// The wording of one command's syntax errors.
pub struct Words<'a> {
    /// DEBUG1 text, e.g. `Invalid Network query syntax.`
    pub m1: &'a str,
    /// DEBUG2 prefix, e.g. `Network query: `
    pub p: &'a str,
    /// Answer prefix, e.g. `err Invalid Network query syntax`
    pub err: &'a str,
}

fn read(kind: Kind, f: &[u8]) -> Val {
    let null = f.starts_with(b"NULL");
    match kind {
        Kind::Text => Val::Text(if f == b"NULL" { None } else { Some(f.to_vec()) }),
        Kind::Int => Val::Int(if null { -1 } else { read_long(f).0 as i32 as i64 }),
        Kind::Long => Val::Int(if null { -1 } else { read_long(f).0 }),
        Kind::Plain => Val::Int(read_long(f).0 as i32 as i64),
        Kind::Unsigned => Val::Int(read_long(f).0),
        Kind::Real => Val::Real(read_real(f)),
    }
}

/// How a value is quoted in the "missing `|`" log line.
fn quoted(kind: Kind, v: &Val, raw: &[u8]) -> Vec<u8> {
    match (kind, v) {
        (Kind::Text, _) => raw.to_vec(),
        (Kind::Unsigned, Val::Int(i)) => (*i as u64).to_string().into_bytes(),
        (Kind::Real, Val::Real(r)) => fmt_f(*r).into_bytes(),
        (_, Val::Int(i)) => i.to_string().into_bytes(),
        _ => raw.to_vec(),
    }
}

impl Engine {
    /// Splits `input` into `kinds.len()` fields on `|` (the last takes the rest). A missing `|`
    /// before field `i`: the 1st and 2nd quote the rest of the input; later ones quote the
    /// previous field (its text, or its number with the rest of the input as "near").
    /// `words_at(i)` may change the wording for one field.
    pub fn split_fields(&self, input: &[u8], kinds: &[Kind], words: &Words, words_at: &dyn Fn(usize) -> Option<Words<'static>>) -> Result<Vec<Val>, Answer> {
        let input = until_nul(input);
        let mut out = Vec::with_capacity(kinds.len());
        let mut raws: Vec<&[u8]> = Vec::new();
        let mut rest = input;
        for (i, &k) in kinds.iter().enumerate() {
            if i + 1 == kinds.len() {
                out.push(read(k, rest));
                break;
            }
            match rest.iter().position(|&c| c == b'|') {
                Some(p) => {
                    let f = &rest[..p];
                    out.push(read(k, f));
                    raws.push(f);
                    rest = &rest[p + 1..];
                }
                None => {
                    let w = words_at(i);
                    let w = w.as_ref().unwrap_or(words);
                    let (dbg, nearv): (Vec<u8>, &[u8]) = if i < 2 {
                        (rest.to_vec(), rest)
                    } else {
                        let pk = kinds[i - 1];
                        let q = quoted(pk, &out[i - 1], raws[i - 1]);
                        if pk == Kind::Text {
                            (q, raws[i - 1])
                        } else {
                            (q, rest)
                        }
                    };
                    self.debug(w.m1.as_bytes().to_vec());
                    self.debug2(cat!(w.p, dbg));
                    return Err((INVALID, near(w.err, nearv)));
                }
            }
        }
        Ok(out)
    }

    /// `<action> <rest>` of the legacy commands: the action, or the syntax error.
    pub fn legacy_action<'a>(&self, input: &'a [u8], w: &Words) -> Result<(&'a [u8], &'a [u8]), Answer> {
        let input = until_nul(input);
        match input.iter().position(|&c| c == b' ') {
            Some(p) => Ok((&input[..p], &input[p + 1..])),
            None => {
                self.debug(w.m1.as_bytes().to_vec());
                self.debug2(cat!(w.p, input));
                Err((INVALID, near(w.err, input)))
            }
        }
    }

    /// The unknown-action answer of the legacy commands.
    pub fn legacy_bad(&self, m1: &str, err: &str, action: &[u8]) -> Answer {
        self.debug(m1.as_bytes().to_vec());
        self.debug2(cat!("DB query error near: ", action));
        (INVALID, near(err, action))
    }

    // ------------------------------------------------------------------ CIS-CAT

    pub(crate) fn ciscat_command(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let w = Words { m1: "Invalid CISCAT query syntax.", p: "CISCAT query: ", err: "err Invalid CISCAT query syntax" };
        let (action, rest) = match self.legacy_action(input, &w) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if action != b"save" {
            return self.legacy_bad(w.m1, w.err, action);
        }
        use Kind::*;
        let f = match self.split_fields(rest, &[Text, Text, Text, Text, Int, Int, Int, Int, Int, Int], &w, &|_| None) {
            Ok(f) => f,
            Err(r) => return r,
        };
        if self.ciscat_save(h, &f) {
            (OK, b"ok".to_vec())
        } else {
            self.debug(b"Cannot save CISCAT information.".to_vec());
            (INVALID, b"err Cannot save CISCAT information.".to_vec())
        }
    }

    fn ciscat_save(&self, h: &mut Handle, f: &[Val]) -> bool {
        if !h.transaction && !self.begin(h) {
            self.error(b"at wdb_ciscat_save(): cannot begin transaction".to_vec());
            return false;
        }
        let Some(st) = self.stmt_plain(
            h,
            "INSERT INTO ciscat_results (scan_id, scan_time, benchmark, profile, pass, fail, error, notchecked, unknown, score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        ) else {
            self.error(b"at wdb_ciscat_insert(): cannot cache statement".to_vec());
            return false;
        };
        for i in 0..4 {
            st.bind_text(i as i32 + 1, f[i].text());
        }
        for i in 4..10 {
            let v = f[i].int() as i32;
            if v >= 0 {
                st.bind_int(i as i32 + 1, v);
            } else {
                st.bind_null(i as i32 + 1);
            }
        }
        if self.step(&st) != SQLITE_DONE {
            self.error(cat!("SQLite: ", h.errmsg()));
            return false;
        }
        let Some(del) = self.stmt_plain(h, "DELETE FROM ciscat_results WHERE scan_id != ?;") else {
            self.error(b"at wdb_ciscat_del(): cannot cache statement".to_vec());
            return false;
        };
        del.bind_text(1, f[0].text());
        if self.step(&del) != SQLITE_DONE {
            self.error(cat!("Deleting old information from 'ciscat_results' table: ", h.errmsg()));
            return false;
        }
        true
    }

    // ------------------------------------------------------------------ rootcheck

    pub(crate) fn rootcheck_command(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let input = until_nul(input);
        let (sub, next) = crate::text::split_word(input);
        let bad = || {
            self.debug2(cat!("DB(", h.id.clone(), ") Invalid rootcheck query syntax: ", sub));
            (INVALID, near("err Invalid rootcheck query syntax", sub))
        };
        match sub {
            b"delete" => match self.stmt_plain(h, "DELETE FROM pm_event;") {
                Some(st) if self.step(&st) == SQLITE_DONE => (OK, b"ok 0".to_vec()),
                Some(_) => (INVALID, b"err Error deleting rootcheck PM tuple".to_vec()),
                None => {
                    self.error(cat!("DB(", h.id.clone(), ") Cannot cache statement"));
                    (INVALID, b"err Error deleting rootcheck PM tuple".to_vec())
                }
            },
            b"save" => {
                let Some(next) = next else { return bad() };
                let Some(sp) = crate::text::find_unescaped(next, b' ') else { return bad() };
                let ts = read_long(&next[..sp]).0;
                let log = &next[sp + 1..];
                if ts == i64::MAX || ts < 0 {
                    self.debug2(cat!("DB(", h.id.clone(), ") Invalid rootcheck date timestamp: ", ts));
                    return (INVALID, near("err Invalid rootcheck query syntax", sub));
                }
                match self.rootcheck_update(h, ts, log) {
                    -1 => {
                        self.error(cat!("DB(", h.id.clone(), ") Error updating rootcheck PM tuple on SQLite database"));
                        (INVALID, b"err Error updating rootcheck PM tuple".to_vec())
                    }
                    0 => {
                        if self.rootcheck_insert(h, ts, log) < 0 {
                            self.error(cat!("DB(", h.id.clone(), ") Error inserting rootcheck PM tuple on SQLite database for agent"));
                            (INVALID, b"err Error updating rootcheck PM tuple".to_vec())
                        } else {
                            (OK, b"ok 2".to_vec())
                        }
                    }
                    _ => (OK, b"ok 1".to_vec()),
                }
            }
            _ => bad(),
        }
    }

    /// Rows changed (the last date of an existing finding), or -1.
    fn rootcheck_update(&self, h: &mut Handle, ts: i64, log: &[u8]) -> i32 {
        let Some(st) = self.stmt_plain(h, "UPDATE pm_event SET date_last = ? WHERE log = ?;") else {
            self.error(cat!("DB(", h.id.clone(), ") Cannot cache statement"));
            return -1;
        };
        st.bind_int(1, ts as i32);
        st.bind_text(2, Some(log));
        if self.step(&st) == SQLITE_DONE {
            h.db().changes()
        } else {
            -1
        }
    }

    /// A new finding (first = last date); its row id, or -1.
    fn rootcheck_insert(&self, h: &mut Handle, ts: i64, log: &[u8]) -> i32 {
        let Some(st) = self.stmt_plain(h, "INSERT INTO pm_event (date_first, date_last, log, pci_dss, cis) VALUES (?, ?, ?, ?, ?);") else {
            self.error(cat!("DB(", h.id.clone(), ") Cannot cache statement"));
            return -1;
        };
        // compliance tags written in the log text: `{PCI_DSS: ...}` and `{CIS: ...}`
        let tag = |t: &[u8]| -> Option<Vec<u8>> {
            let p = log.windows(t.len()).position(|w| w == t)?;
            let rest = &log[p + t.len()..];
            Some(rest[..rest.iter().position(|&c| c == b'}')?].to_vec())
        };
        st.bind_int(1, ts as i32);
        st.bind_int(2, ts as i32);
        st.bind_text(3, Some(log));
        st.bind_text(4, tag(b"{PCI_DSS: ").as_deref());
        st.bind_text(5, tag(b"{CIS: ").as_deref());
        if self.step(&st) == SQLITE_DONE {
            h.db().last_insert_rowid() as i32
        } else {
            -1
        }
    }
}
