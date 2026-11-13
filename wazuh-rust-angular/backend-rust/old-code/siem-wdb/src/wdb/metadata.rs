//! The metadata table (wazuh_db/wdb_metadata.c).

use super::*;

impl Wdbd {
    /// `wdb_metadata_get_entry`: (OS_SUCCESS | OS_NOTFOUND | OS_INVALID,
    /// the value — "0" when not found — as `strncpy(output, v, 256)`).
    pub fn metadata_get_entry(&self, wdb: &Wdb, key: &[u8]) -> (i32, B) {
        let (rc, st, _) = wdb.db().prepare_v2(b"SELECT value FROM metadata WHERE key = ?;");
        let Some(st) = st.filter(|_| rc == SQLITE_OK) else {
            self.merror(&msg!("DB(", wdb.id, ") sqlite3_prepare_v2(): ", wdb.errmsg()));
            return (OS_INVALID, Vec::new());
        };
        st.bind_text(1, Some(key));
        match self.step(&st) {
            SQLITE_ROW => {
                let mut v = st.column_text(0).unwrap_or_default();
                v.truncate(OS_SIZE_256);
                (OS_SUCCESS, v)
            }
            SQLITE_DONE => (OS_NOTFOUND, b"0".to_vec()),
            _ => {
                self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
                (OS_INVALID, Vec::new())
            }
        }
    }

    /// `wdb_count_tables_with_name`
    pub fn count_tables_with_name(&self, wdb: &Wdb, key: &[u8]) -> Option<i32> {
        let (rc, st, _) = wdb.db().prepare_v2(b"SELECT count(name) FROM sqlite_master WHERE type='table' AND name=?;");
        let Some(st) = st.filter(|_| rc == SQLITE_OK) else {
            self.merror(&msg!("DB(", wdb.id, ") sqlite3_prepare_v2(): ", wdb.errmsg()));
            return None;
        };
        if st.bind_text(1, Some(key)) != SQLITE_OK {
            self.merror(&msg!("DB(", wdb.id, ") sqlite3_bind_text(): ", wdb.errmsg()));
            return None;
        }
        match self.step(&st) {
            SQLITE_ROW => Some(st.column_int(0)),
            _ => {
                self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
                None
            }
        }
    }
}
