//! The small per-agent tables: CIS-CAT results (wazuh_db/wdb_ciscat.c),
//! rootcheck PM events (wazuh_db/wdb_rootcheck.c) and the agent inventory
//! queries of wazuh_db/wdb_agents.c.

use siem_cjson::Json;

use super::*;

/// `rk_event_t`
#[derive(Debug, Clone)]
pub struct RkEvent {
    pub date_first: i64,
    pub date_last: i64,
    pub log: B,
}

/// `get_pci_dss` / `get_cis`: the text after `tag` up to '}' (None when
/// there is no '}').
fn rk_tag(s: &[u8], tag: &[u8]) -> Option<B> {
    let p = s.windows(tag.len()).position(|w| w == tag)?;
    let out = &s[p + tag.len()..];
    let len = out.iter().position(|&c| c == b'}')?;
    Some(out[..len].to_vec())
}

impl Wdbd {
    /// `wdb_ciscat_save`
    #[allow(clippy::too_many_arguments)]
    pub fn ciscat_save(&self, wdb: &mut Wdb, scan_id: Option<&[u8]>, scan_time: Option<&[u8]>, benchmark: Option<&[u8]>, profile: Option<&[u8]>, n: [i32; 6]) -> i32 {
        if !wdb.transaction && self.begin2(wdb) < 0 {
            self.merror(b"at wdb_ciscat_save(): cannot begin transaction");
            return -1;
        }
        if self.ciscat_insert(wdb, scan_id, scan_time, benchmark, profile, n) < 0 {
            return -1;
        }
        0
    }

    /// `wdb_ciscat_insert`
    fn ciscat_insert(&self, wdb: &mut Wdb, scan_id: Option<&[u8]>, scan_time: Option<&[u8]>, benchmark: Option<&[u8]>, profile: Option<&[u8]>, n: [i32; 6]) -> i32 {
        if self.stmt_cache(wdb, WDB_STMT_CISCAT_INSERT) < 0 {
            self.merror(b"at wdb_ciscat_insert(): cannot cache statement");
            return -1;
        }
        let st = wdb.st(WDB_STMT_CISCAT_INSERT);
        st.bind_text(1, scan_id);
        st.bind_text(2, scan_time);
        st.bind_text(3, benchmark);
        st.bind_text(4, profile);
        for (i, v) in n.iter().enumerate() {
            if *v >= 0 {
                st.bind_int(5 + i as i32, *v);
            } else {
                st.bind_null(5 + i as i32);
            }
        }
        if self.step(&st) == SQLITE_DONE {
            if self.ciscat_del(wdb, scan_id) < 0 {
                return -1;
            }
            0
        } else {
            self.merror(&msg!("SQLite: ", wdb.errmsg()));
            -1
        }
    }

    /// `wdb_ciscat_del`
    fn ciscat_del(&self, wdb: &mut Wdb, scan_id: Option<&[u8]>) -> i32 {
        if self.stmt_cache(wdb, WDB_STMT_CISCAT_DEL) < 0 {
            self.merror(b"at wdb_ciscat_del(): cannot cache statement");
            return -1;
        }
        let st = wdb.st(WDB_STMT_CISCAT_DEL);
        st.bind_text(1, scan_id);
        if self.step(&st) != SQLITE_DONE {
            self.merror(&msg!("Deleting old information from 'ciscat_results' table: ", wdb.errmsg()));
            return -1;
        }
        0
    }

    /// `wdb_rootcheck_insert`: the row id or -1.
    pub fn rootcheck_insert(&self, wdb: &mut Wdb, event: &RkEvent) -> i32 {
        if self.stmt_cache(wdb, WDB_STMT_ROOTCHECK_INSERT_PM) != 0 {
            self.merror(&msg!("DB(", wdb.id, ") Cannot cache statement"));
            return -1;
        }
        let st = wdb.st(WDB_STMT_ROOTCHECK_INSERT_PM);
        let pci_dss = rk_tag(&event.log, b"{PCI_DSS: ");
        let cis = rk_tag(&event.log, b"{CIS: ");
        st.bind_int(1, event.date_first as i32);
        st.bind_int(2, event.date_last as i32);
        st.bind_text(3, Some(&event.log));
        st.bind_text(4, pci_dss.as_deref());
        st.bind_text(5, cis.as_deref());
        if self.step(&st) == SQLITE_DONE {
            wdb.db().last_insert_rowid() as i32
        } else {
            -1
        }
    }

    /// `wdb_rootcheck_update`: the changed rows or -1.
    pub fn rootcheck_update(&self, wdb: &mut Wdb, event: &RkEvent) -> i32 {
        if self.stmt_cache(wdb, WDB_STMT_ROOTCHECK_UPDATE_PM) != 0 {
            self.merror(&msg!("DB(", wdb.id, ") Cannot cache statement"));
            return -1;
        }
        let st = wdb.st(WDB_STMT_ROOTCHECK_UPDATE_PM);
        st.bind_int(1, event.date_last as i32);
        st.bind_text(2, Some(&event.log));
        if self.step(&st) == SQLITE_DONE {
            wdb.db().changes()
        } else {
            -1
        }
    }

    /// `wdb_rootcheck_delete`
    pub fn rootcheck_delete(&self, wdb: &mut Wdb) -> i32 {
        if self.stmt_cache(wdb, WDB_STMT_ROOTCHECK_DELETE_PM) != 0 {
            self.merror(&msg!("DB(", wdb.id, ") Cannot cache statement"));
            return -1;
        }
        let st = wdb.st(WDB_STMT_ROOTCHECK_DELETE_PM);
        if self.step(&st) == SQLITE_DONE {
            wdb.db().changes()
        } else {
            -1
        }
    }

    /// `wdb_agents_get_sys_osinfo`
    pub fn agents_get_sys_osinfo(&self, wdb: &mut Wdb) -> Option<Json> {
        let st = self.init_stmt_in_cache(wdb, WDB_STMT_OSINFO_GET)?;
        let r = self.exec_stmt(Some(&st));
        if r.is_none() {
            self.mdebug1(&msg!("wdb_exec_stmt(): ", wdb.errmsg()));
        }
        r
    }

    /// `wdb_agents_find_package`
    pub fn agents_find_package(&self, wdb: &mut Wdb, reference: &[u8]) -> bool {
        let Some(st) = self.init_stmt_in_cache(wdb, WDB_STMT_PROGRAM_FIND) else {
            return false;
        };
        st.bind_text(1, Some(reference));
        match self.step(&st) {
            SQLITE_ROW => true,
            SQLITE_DONE => false,
            _ => {
                self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
                false
            }
        }
    }

    /// `wdb_agents_get_packages` / `wdb_agents_get_hotfixes`: (status,
    /// response); the rows are streamed to the peer.
    pub fn agents_get_inventory(&self, wdb: &mut Wdb, component: i32, send_stmt: usize) -> (i32, Json) {
        let mut response = Json::object();
        let mut status = OS_SUCCESS;
        let sync = self.wdbi_check_sync_status(wdb, component);
        if sync == 1 {
            status = match self.init_stmt_in_cache(wdb, send_stmt) {
                Some(st) => self.exec_stmt_send(Some(&st), wdb.peer),
                None => OS_INVALID,
            };
            response.add("status", Json::string(if status == OS_SUCCESS { "SUCCESS" } else { "ERROR" }));
        } else if sync == 0 {
            response.add("status", Json::string("NOT_SYNCED"));
        } else {
            response.add("status", Json::string("ERROR"));
            status = OS_INVALID;
        }
        (status, response)
    }
}
