//! Query rows as JSON (spec § 6): a row is an object of its columns in order (numbers as numbers,
//! texts and blobs as strings, NULL columns left out); a result is an array of rows.

use provigil_json::Json;
use siem_sqlite::{Stmt, SQLITE_BLOB, SQLITE_DONE, SQLITE_ERROR, SQLITE_FLOAT, SQLITE_INTEGER, SQLITE_OK, SQLITE_ROW, SQLITE_TEXT};

use crate::{Engine, Handle, INVALID, OK};

/// How many columns of each row are returned.
#[derive(Clone, Copy, PartialEq)]
pub enum Columns {
    All,
    First,
}

/// Error code for a row too large to be sent.
pub const TOO_BIG: i32 = -4;
/// Error code for a failed send to the client.
pub const SEND_FAILED: i32 = -6;

impl Engine {
    /// The next row (None at the end or on error; `status` holds the step result).
    pub fn next_row(&self, st: &Stmt, status: &mut i32, cols: Columns) -> Option<Json> {
        let s = self.step(st);
        *status = s;
        if s != SQLITE_ROW {
            if s != SQLITE_DONE {
                self.debug(b"SQL statement execution failed".to_vec());
            }
            return None;
        }
        let value = |i: i32| match st.column_type(i) {
            SQLITE_INTEGER | SQLITE_FLOAT => Some(Json::number(st.column_double(i))),
            SQLITE_TEXT | SQLITE_BLOB => Some(Json::String(st.column_text(i).unwrap_or_default())),
            _ => None,
        };
        match cols {
            Columns::First => {
                if st.column_count() > 0 {
                    value(0)
                } else {
                    None
                }
            }
            Columns::All => {
                let n = st.column_count();
                if n == 0 {
                    return None;
                }
                let mut o = Json::object();
                for i in 0..n {
                    if let Some(v) = value(i) {
                        o.add(st.column_name(i), v);
                    }
                }
                Some(o)
            }
        }
    }

    /// All rows, or None when a step failed.
    pub fn rows(&self, st: &Stmt) -> Option<Json> {
        let mut status = SQLITE_ERROR;
        let mut out = Vec::new();
        while let Some(r) = self.next_row(st, &mut status, Columns::All) {
            out.push(r);
        }
        (status == SQLITE_DONE).then_some(Json::Array(out))
    }

    /// Rows while the printed array stays below `max` bytes; `status` is the last step result
    /// (a row still pending means "more to come").
    pub fn rows_sized(&self, st: &Stmt, max: usize, status: &mut i32, cols: Columns) -> Option<Json> {
        let mut out = Vec::new();
        let mut size = 2usize;
        while let Some(r) = self.next_row(st, status, cols) {
            let len = r.print_unformatted().len() + 1;
            if size + len < max {
                out.push(r);
                size += len;
            } else {
                break;
            }
        }
        if *status != SQLITE_DONE && *status != SQLITE_ROW {
            return None;
        }
        Some(Json::Array(out))
    }

    /// Sends every row to the client as its own `due <json>` message.
    pub fn rows_send(&self, st: &Stmt, peer: i32) -> i32 {
        if self.env.set_send_timeout(peer, 1) < 0 {
            let e = std::io::Error::last_os_error();
            self.error(cat!("Socket ", peer, " error setting timeout: ", e.to_string(), " (", e.raw_os_error().unwrap_or(0), ")"));
            return SEND_FAILED;
        }
        let mut result = OK;
        let mut status = SQLITE_ERROR;
        let limit = 65536 - 4;
        while let Some(r) = self.next_row(st, &mut status, Columns::All) {
            let p = r.print_unformatted();
            if p.len() < limit {
                if self.env.send_peer(peer, &cat!("due ", p)) < 0 {
                    let e = std::io::Error::last_os_error();
                    self.error(cat!("Socket ", peer, " error: ", e.to_string(), " (", e.raw_os_error().unwrap_or(0), ")"));
                    result = SEND_FAILED;
                    break;
                }
            } else {
                self.error(cat!("SQL row response for statement ", st.sql(), " is too big to be sent"));
                result = TOO_BIG;
                break;
            }
        }
        if result == OK && status != SQLITE_DONE {
            result = INVALID;
        }
        result
    }

    /// A free SQL statement on a database (the `sql` commands): its rows, or None.
    pub fn sql(&self, h: &Handle, sql: &[u8]) -> Option<Json> {
        let (rc, st, _) = h.db().prepare_v2(sql);
        let st = match st {
            Some(st) if rc == SQLITE_OK => st,
            _ => {
                self.debug(cat!("sqlite3_prepare_v2(): ", h.errmsg()));
                self.debug2(cat!("SQL: ", crate::text::until_nul(sql)));
                return None;
            }
        };
        let r = self.rows(&st);
        if r.is_none() {
            self.debug(cat!("wdb_exec_stmt(): ", h.errmsg()));
        }
        r
    }
}
