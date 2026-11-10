//! Security Configuration Assessment tables (wazuh_db/wdb_sca.c).

use sha2::{Digest, Sha256};
use siem_sqlite::Stmt;

use super::global::wm_strcat;
use super::*;

/// The `char output[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE]` of the queries.
pub const RESULT_SIZE: usize = OS_MAXSTR - 16;

/// `printf("%s", s)` of a possibly NULL string.
fn pz(s: Option<B>) -> B {
    s.unwrap_or_else(|| b"(null)".to_vec())
}

impl Wdbd {
    fn sca_prep(&self, wdb: &mut Wdb, idx: usize, cache_msg: &str) -> Option<std::sync::Arc<Stmt>> {
        if !wdb.transaction && self.begin2(wdb) < 0 {
            self.mdebug1(b"cannot begin transaction");
            return None;
        }
        if self.stmt_cache(wdb, idx) < 0 {
            self.mdebug1(cache_msg.as_bytes());
            return None;
        }
        Some(wdb.st(idx))
    }

    fn sca_done(&self, wdb: &Wdb, st: &Stmt) -> i32 {
        if self.step(st) == SQLITE_DONE {
            0
        } else {
            self.merror(&msg!("SQLite: ", wdb.errmsg()));
            -1
        }
    }

    fn sca_done_changes(&self, wdb: &Wdb, st: &Stmt) -> i32 {
        if self.step(st) == SQLITE_DONE {
            wdb.db().changes()
        } else {
            self.merror(&msg!("SQLite: ", wdb.errmsg()));
            -1
        }
    }

    fn sca_unique(&self, wdb: &Wdb, st: &Stmt) -> i32 {
        match self.step(st) {
            SQLITE_DONE => 0,
            SQLITE_CONSTRAINT => {
                let e = wdb.errmsg();
                if e.starts_with(b"UNIQUE") {
                    self.mdebug1(&msg!("SQLite: ", e));
                    0
                } else {
                    self.merror(&msg!("SQLite: ", e));
                    -1
                }
            }
            _ => {
                self.merror(&msg!("SQLite: ", wdb.errmsg()));
                -1
            }
        }
    }

    /// `wdb_sca_find`: (1 | 0 | -1, the result column).
    pub fn sca_find(&self, wdb: &mut Wdb, pm_id: i32) -> (i32, B) {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_FIND, "cannot cache statement") else {
            return (-1, Vec::new());
        };
        st.bind_int(1, pm_id);
        match self.step(&st) {
            SQLITE_ROW => (1, trunc(pz(st.column_text(1)), RESULT_SIZE)),
            SQLITE_DONE => (0, Vec::new()),
            _ => {
                self.merror(&msg!("SQLite: ", wdb.errmsg()));
                (-1, Vec::new())
            }
        }
    }

    /// `wdb_sca_save`
    #[allow(clippy::too_many_arguments)]
    pub fn sca_save(&self, wdb: &mut Wdb, id: i32, scan_id: i32, texts: &[Option<&[u8]>; 14]) -> i32 {
        // texts: title, description, rationale, remediation, condition, file,
        // directory, process, registry, reference, result, policy_id,
        // command, reason
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_INSERT, "cannot cache statement") else {
            return -1;
        };
        let [title, description, rationale, remediation, condition, file, directory, process, registry, reference, result, policy_id, command, reason] =
            *texts;
        st.bind_int(1, id);
        st.bind_int(2, scan_id);
        st.bind_text(3, title);
        st.bind_text(4, description);
        st.bind_text(5, rationale);
        st.bind_text(6, remediation);
        st.bind_text(7, file);
        st.bind_text(8, directory);
        st.bind_text(9, process);
        st.bind_text(10, registry);
        st.bind_text(11, reference);
        st.bind_text(12, result);
        st.bind_text(13, policy_id);
        st.bind_text(14, command);
        st.bind_text(15, reason);
        st.bind_text(16, condition);
        self.sca_unique(wdb, &st)
    }

    /// `wdb_sca_policy_get_id`
    pub fn sca_policy_get_id(&self, wdb: &mut Wdb) -> (i32, B) {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_POLICY_GET_ALL, "cannot cache statement") else {
            return (-1, Vec::new());
        };
        let mut s: Option<B> = None;
        let mut has = false;
        loop {
            match self.step(&st) {
                SQLITE_ROW => {
                    has = true;
                    if let Some(v) = st.column_text(0) {
                        wm_strcat(&mut s, &v, b',');
                    }
                }
                SQLITE_DONE => break,
                _ => {
                    self.merror(&msg!("SQLite: ", wdb.errmsg()));
                    return (-1, Vec::new());
                }
            }
        }
        if has {
            (1, trunc(pz(s), RESULT_SIZE))
        } else {
            (0, Vec::new())
        }
    }

    /// `wdb_sca_policy_delete`
    pub fn sca_policy_delete(&self, wdb: &mut Wdb, policy_id: &[u8]) -> i32 {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_POLICY_DELETE, "cannot cache statement") else {
            return -1;
        };
        st.bind_text(1, Some(policy_id));
        if self.step(&st) == SQLITE_DONE {
            self.sca_scan_info_delete(wdb, policy_id);
            0
        } else {
            self.merror(&msg!("SQLite: ", wdb.errmsg()));
            -1
        }
    }

    /// `wdb_sca_scan_info_delete`
    pub fn sca_scan_info_delete(&self, wdb: &mut Wdb, policy_id: &[u8]) -> i32 {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_SCAN_INFO_DELETE, "cannot cache statement") else {
            return -1;
        };
        st.bind_text(1, Some(policy_id));
        self.sca_done(wdb, &st)
    }

    /// `wdb_sca_check_delete_distinct`
    pub fn sca_check_delete_distinct(&self, wdb: &mut Wdb, policy_id: &[u8], scan_id: i32) -> i32 {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_CHECK_DELETE_DISTINCT, "at wdb_sca_check_delete_distinct(): cannot cache statement") else {
            return -1;
        };
        st.bind_int(1, scan_id);
        st.bind_text(2, Some(policy_id));
        self.sca_done(wdb, &st)
    }

    /// `wdb_sca_check_delete`
    pub fn sca_check_delete(&self, wdb: &mut Wdb, policy_id: &[u8]) -> i32 {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_CHECK_DELETE, "cannot cache statement") else {
            return -1;
        };
        st.bind_text(1, Some(policy_id));
        self.sca_done(wdb, &st)
    }

    /// `wdb_sca_check_compliances_delete`
    pub fn sca_check_compliances_delete(&self, wdb: &mut Wdb) -> i32 {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_CHECK_COMPLIANCE_DELETE, "cannot cache statement") else {
            return -1;
        };
        self.sca_done(wdb, &st)
    }

    /// `wdb_sca_check_rules_delete`
    pub fn sca_check_rules_delete(&self, wdb: &mut Wdb) -> i32 {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_CHECK_RULES_DELETE, "cannot cache statement") else {
            return -1;
        };
        self.sca_done(wdb, &st)
    }

    /// `wdb_sca_scan_find`
    pub fn sca_scan_find(&self, wdb: &mut Wdb, policy_id: &[u8]) -> (i32, B) {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_FIND_SCAN, "cannot cache statement") else {
            return (-1, Vec::new());
        };
        st.bind_text(1, Some(policy_id));
        match self.step(&st) {
            SQLITE_ROW => (1, trunc(msg!(pz(st.column_text(1)), " ", st.column_int(2)), RESULT_SIZE)),
            SQLITE_DONE => (0, Vec::new()),
            _ => {
                self.merror(&msg!("SQLite: ", wdb.errmsg()));
                (-1, Vec::new())
            }
        }
    }

    /// `wdb_sca_policy_find` / `wdb_sca_policy_sha256`
    fn sca_single(&self, wdb: &mut Wdb, idx: usize, id: &[u8]) -> (i32, B) {
        let Some(st) = self.sca_prep(wdb, idx, "cannot cache statement") else {
            return (-1, Vec::new());
        };
        st.bind_text(1, Some(id));
        match self.step(&st) {
            SQLITE_ROW => (1, trunc(pz(st.column_text(0)), RESULT_SIZE)),
            SQLITE_DONE => (0, Vec::new()),
            _ => {
                self.merror(&msg!("SQLite: ", wdb.errmsg()));
                (-1, Vec::new())
            }
        }
    }

    /// `wdb_sca_policy_find`
    pub fn sca_policy_find(&self, wdb: &mut Wdb, id: &[u8]) -> (i32, B) {
        self.sca_single(wdb, WDB_STMT_SCA_POLICY_FIND, id)
    }

    /// `wdb_sca_policy_sha256`
    pub fn sca_policy_sha256(&self, wdb: &mut Wdb, id: &[u8]) -> (i32, B) {
        self.sca_single(wdb, WDB_STMT_SCA_POLICY_SHA256, id)
    }

    /// `wdb_sca_compliance_save`
    pub fn sca_compliance_save(&self, wdb: &mut Wdb, id_check: i32, key: &[u8], value: &[u8]) -> i32 {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_INSERT_COMPLIANCE, "cannot cache statement") else {
            return -1;
        };
        st.bind_int(1, id_check);
        st.bind_text(2, Some(key));
        st.bind_text(3, Some(value));
        self.sca_unique(wdb, &st)
    }

    /// `wdb_sca_rules_save`
    pub fn sca_rules_save(&self, wdb: &mut Wdb, id_check: i32, type_: &[u8], rule: &[u8]) -> i32 {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_INSERT_RULES, "cannot cache statement") else {
            return -1;
        };
        st.bind_int(1, id_check);
        st.bind_text(2, Some(type_));
        st.bind_text(3, Some(rule));
        self.sca_unique(wdb, &st)
    }

    /// `wdb_sca_policy_info_save`
    pub fn sca_policy_info_save(&self, wdb: &mut Wdb, f: &[&[u8]; 6]) -> i32 {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_POLICY_INSERT, "cannot cache statement") else {
            return -1;
        };
        for (i, v) in f.iter().enumerate() {
            st.bind_text(i as i32 + 1, Some(v));
        }
        self.sca_done(wdb, &st)
    }

    /// `wdb_sca_scan_info_save`
    #[allow(clippy::too_many_arguments)]
    pub fn sca_scan_info_save(&self, wdb: &mut Wdb, start: i32, end: i32, scan_id: i32, policy_id: &[u8], n: [i32; 5], hash: &[u8]) -> i32 {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_SCAN_INFO_INSERT, "cannot cache statement") else {
            return -1;
        };
        st.bind_int(1, start);
        st.bind_int(2, end);
        st.bind_int(3, scan_id);
        st.bind_text(4, Some(policy_id));
        for (i, v) in n.iter().enumerate() {
            st.bind_int(5 + i as i32, *v);
        }
        st.bind_text(10, Some(hash));
        self.sca_done(wdb, &st)
    }

    /// `wdb_sca_scan_info_update`
    pub fn sca_scan_info_update(&self, wdb: &mut Wdb, module: Option<&[u8]>, end_scan: i32) -> i32 {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_SCAN_INFO_UPDATE, "cannot cache statement") else {
            return -1;
        };
        st.bind_int(1, end_scan);
        st.bind_text(2, module);
        self.sca_done_changes(wdb, &st)
    }

    /// `wdb_sca_scan_info_update_start`
    #[allow(clippy::too_many_arguments)]
    pub fn sca_scan_info_update_start(&self, wdb: &mut Wdb, policy_id: Option<&[u8]>, start: i32, end: i32, scan_id: i32, n: [i32; 5], hash: &[u8]) -> i32 {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_SCAN_INFO_UPDATE_START, "cannot cache statement") else {
            return -1;
        };
        st.bind_int(1, start);
        st.bind_int(2, end);
        st.bind_int(3, scan_id);
        for (i, v) in n.iter().enumerate() {
            st.bind_int(4 + i as i32, *v);
        }
        st.bind_text(9, Some(hash));
        st.bind_text(10, policy_id);
        self.sca_done_changes(wdb, &st)
    }

    /// `wdb_sca_checks_get_result`
    pub fn sca_checks_get_result(&self, wdb: &mut Wdb, policy_id: &[u8]) -> (i32, B) {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_CHECK_GET_ALL_RESULTS, "cannot cache statement") else {
            return (-1, Vec::new());
        };
        st.bind_text(1, Some(policy_id));
        let mut s: Option<B> = None;
        let mut has = false;
        loop {
            match self.step(&st) {
                SQLITE_ROW => {
                    has = true;
                    if let Some(v) = st.column_text(0) {
                        wm_strcat(&mut s, &v, b':');
                    }
                }
                SQLITE_DONE => break,
                _ => {
                    self.merror(&msg!("SQLite: ", wdb.errmsg()));
                    return (-1, Vec::new());
                }
            }
        }
        if !has {
            return (0, Vec::new());
        }
        // the output stays empty when every result was NULL
        let mut out = Vec::new();
        if let Some(s) = s {
            let results = super::sk::replace(&s, b"not applicable", b"");
            let h = Sha256::digest(&results);
            out = h.iter().map(|b| format!("{b:02x}")).collect::<String>().into_bytes();
        }
        (1, out)
    }

    /// `wdb_sca_update`
    pub fn sca_update(&self, wdb: &mut Wdb, result: &[u8], id: i32, scan_id: i32, reason: &[u8]) -> i32 {
        let Some(st) = self.sca_prep(wdb, WDB_STMT_SCA_UPDATE, "cannot cache statement") else {
            return -1;
        };
        st.bind_int(1, scan_id);
        st.bind_text(2, Some(result));
        st.bind_text(3, Some(reason));
        st.bind_int(4, id);
        self.sca_done_changes(wdb, &st)
    }
}
