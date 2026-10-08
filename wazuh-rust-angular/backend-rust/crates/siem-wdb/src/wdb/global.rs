//! The global database (wazuh_db/wdb_global.c): agents, labels, groups and
//! their membership, synchronization with the cluster, connection status
//! and the global.db backups.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use siem_cjson::Json;
use siem_sqlite::Stmt;

use super::integrity::{first_child, Sha1Buf};
use super::*;

// wdbc_result
pub const WDBC_OK: i32 = 0;
pub const WDBC_DUE: i32 = 1;
pub const WDBC_ERROR: i32 = 2;
pub const WDBC_IGNORE: i32 = 3;
pub const WDBC_UNKNOWN: i32 = 4;

pub const OS_UNDEF: i32 = -9;

// agent_status_code_t
pub const INVALID_VERSION: i32 = 1;
pub const ERR_VERSION_RECV: i32 = 2;
pub const HC_SHUTDOWN_RECV: i32 = 3;
pub const NO_KEEPALIVE: i32 = 4;
pub const RESET_BY_MANAGER: i32 = 5;

// wdb_groups_sync_condition_t
pub const WDB_GROUP_SYNC_STATUS: i32 = 0;
pub const WDB_GROUP_ALL: i32 = 1;
pub const WDB_GROUP_NO_CONDITION: i32 = 2;
pub const WDB_GROUP_INVALID_CONDITION: i32 = 3;

// wdb_groups_set_mode_t
pub const WDB_GROUP_OVERRIDE: i32 = 0;
pub const WDB_GROUP_APPEND: i32 = 1;
pub const WDB_GROUP_EMPTY_ONLY: i32 = 2;
pub const WDB_GROUP_REMOVE: i32 = 3;
pub const WDB_GROUP_INVALID_MODE: i32 = 4;

pub const AGENT_CS_NEVER_CONNECTED: &str = "never_connected";
pub const AGENT_CS_PENDING: &str = "pending";
pub const AGENT_CS_ACTIVE: &str = "active";
pub const AGENT_CS_DISCONNECTED: &str = "disconnected";

pub const MAX_GROUP_NAME: usize = 255;
pub const MULTIGROUP_SEPARATOR: u8 = b',';
pub const MAX_GROUPS_PER_MULTIGROUP: i32 = 128;
pub const WDB_GLOB_BACKUP_NAME: &str = "global.db-backup";

/// `global_db_agent_fields`
const GLOBAL_DB_AGENT_FIELDS: [&str; 22] = [
    ":config_sum",
    ":ip",
    ":manager_host",
    ":merged_sum",
    ":name",
    ":node_name",
    ":os_arch",
    ":os_build",
    ":os_codename",
    ":os_major",
    ":os_minor",
    ":os_name",
    ":os_platform",
    ":os_uname",
    ":os_version",
    ":version",
    ":last_keepalive",
    ":connection_status",
    ":disconnection_time",
    ":group_config_status",
    ":status_code",
    ":id",
];

/// `OS_SHA256_String_sized(str, out, size)`: the first `size` hex digits.
pub fn sha256_sized(s: &[u8], size: usize) -> B {
    let d = Sha256::digest(cstr(s));
    let mut out = String::new();
    for b in d.iter().take(size / 2) {
        out.push_str(&format!("{b:02x}"));
    }
    out.into_bytes()
}

/// `wm_strcat(&dst, src, sep)`
pub fn wm_strcat(dst: &mut Option<B>, src: &[u8], sep: u8) {
    match dst {
        Some(d) => {
            if sep != 0 {
                d.push(sep);
            }
            d.extend_from_slice(src);
        }
        None => *dst = Some(src.to_vec()),
    }
}

/// `w_get_timestamp(t)` in local time ("%d/%02d/%02d %02d:%02d:%02d"),
/// `utc_offset` seconds east of UTC (see [`WdbEnv::utc_offset`]).
pub fn w_get_timestamp(t: i64, utc_offset: i64) -> String {
    use chrono::{Datelike, Timelike};
    match chrono::DateTime::from_timestamp(t + utc_offset, 0) {
        Some(d) => format!("{}/{:02}/{:02} {:02}:{:02}:{:02}", d.year(), d.month(), d.day(), d.hour(), d.minute(), d.second()),
        None => String::new(),
    }
}

impl Wdbd {
    /// The begin + `wdb_stmt_cache` prologue of most queries
    /// (`wdb_init_stmt_in_cache` logs the same messages).
    pub fn prep(&self, wdb: &mut Wdb, index: usize) -> Option<Arc<Stmt>> {
        self.init_stmt_in_cache(wdb, index)
    }

    /// `sqlite3_bind_int` with the error message.
    pub fn bind_int(&self, wdb: &Wdb, st: &Stmt, i: i32, v: i32) -> bool {
        if st.bind_int(i, v) != SQLITE_OK {
            self.merror(&msg!("DB(", wdb.id, ") sqlite3_bind_int(): ", wdb.errmsg()));
            return false;
        }
        true
    }

    /// `sqlite3_bind_int64` with the error message.
    pub fn bind_int64(&self, wdb: &Wdb, st: &Stmt, i: i32, v: i64) -> bool {
        if st.bind_int64(i, v) != SQLITE_OK {
            self.merror(&msg!("DB(", wdb.id, ") sqlite3_bind_int64(): ", wdb.errmsg()));
            return false;
        }
        true
    }

    /// `sqlite3_bind_text` with the error message.
    pub fn bind_text(&self, wdb: &Wdb, st: &Stmt, i: i32, v: Option<&[u8]>) -> bool {
        if st.bind_text(i, v) != SQLITE_OK {
            self.merror(&msg!("DB(", wdb.id, ") sqlite3_bind_text(): ", wdb.errmsg()));
            return false;
        }
        true
    }

    /// `wdb_exec_stmt` + "wdb_exec_stmt(): %s" on failure.
    fn exec_logged(&self, wdb: &Wdb, st: &Stmt) -> Option<Json> {
        let r = self.exec_stmt(Some(st));
        if r.is_none() {
            self.mdebug1(&msg!("wdb_exec_stmt(): ", wdb.errmsg()));
        }
        r
    }

    /// `wdb_global_insert_agent`
    #[allow(clippy::too_many_arguments)]
    pub fn global_insert_agent(
        &self,
        wdb: &mut Wdb,
        id: i32,
        name: Option<&[u8]>,
        ip: Option<&[u8]>,
        register_ip: Option<&[u8]>,
        internal_key: Option<&[u8]>,
        group: Option<&[u8]>,
        date_add: i32,
    ) -> i32 {
        if let Some(g) = group.map(cstr).filter(|g| !g.is_empty()) {
            for group_name in g.split(|&c| c == MULTIGROUP_SEPARATOR).filter(|s| !s.is_empty()) {
                if self.global_validate_group_name(group_name) == OS_INVALID {
                    self.merror(&msg!("Invalid group name '", group_name, "' in multigroup '", g, "' for agent ", id));
                    return OS_INVALID;
                }
            }
        }
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_INSERT_AGENT) else {
            return OS_INVALID;
        };
        if !self.bind_int(wdb, &st, 1, id)
            || !self.bind_text(wdb, &st, 2, name)
            || !self.bind_text(wdb, &st, 3, ip)
            || !self.bind_text(wdb, &st, 4, register_ip)
            || !self.bind_text(wdb, &st, 5, internal_key)
            || !self.bind_int(wdb, &st, 6, date_add)
            || !self.bind_text(wdb, &st, 7, group)
        {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_update_agent_name`
    pub fn global_update_agent_name(&self, wdb: &mut Wdb, id: i32, name: Option<&[u8]>) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_NAME) else {
            return OS_INVALID;
        };
        if !self.bind_text(wdb, &st, 1, name) || !self.bind_int(wdb, &st, 2, id) {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_update_agent_version`
    #[allow(clippy::too_many_arguments)]
    pub fn global_update_agent_version(&self, wdb: &mut Wdb, id: i32, f: &[Option<&[u8]>; 14], agent_ip: Option<&[u8]>, connection_status: Option<&[u8]>, sync_status: Option<&[u8]>, group_config_status: Option<&[u8]>) -> i32 {
        let idx = if agent_ip.is_some() { WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION_IP } else { WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION };
        let Some(st) = self.prep(wdb, idx) else {
            return OS_INVALID;
        };
        let mut index = 1;
        // os_name, os_version, os_major, os_minor, os_codename, os_platform,
        // os_build, os_uname, os_arch, version, config_sum, merged_sum,
        // manager_host, node_name
        for v in f.iter() {
            if !self.bind_text(wdb, &st, index, *v) {
                return OS_INVALID;
            }
            index += 1;
        }
        if agent_ip.is_some() {
            if !self.bind_text(wdb, &st, index, agent_ip) {
                return OS_INVALID;
            }
            index += 1;
        }
        for v in [connection_status, sync_status, group_config_status] {
            if !self.bind_text(wdb, &st, index, v) {
                return OS_INVALID;
            }
            index += 1;
        }
        if !self.bind_int(wdb, &st, index, id) {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_get_agent_labels`
    pub fn global_get_agent_labels(&self, wdb: &mut Wdb, id: i32) -> Option<Json> {
        let st = self.prep(wdb, WDB_STMT_GLOBAL_LABELS_GET)?;
        if !self.bind_int(wdb, &st, 1, id) {
            return None;
        }
        self.exec_logged(wdb, &st)
    }

    /// `wdb_global_del_agent_labels`
    pub fn global_del_agent_labels(&self, wdb: &mut Wdb, id: i32) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_LABELS_DEL) else {
            return OS_INVALID;
        };
        if !self.bind_int(wdb, &st, 1, id) {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_set_agent_label`
    pub fn global_set_agent_label(&self, wdb: &mut Wdb, id: i32, key: &[u8], value: &[u8]) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_LABELS_SET) else {
            return OS_INVALID;
        };
        if !self.bind_int(wdb, &st, 1, id) || !self.bind_text(wdb, &st, 2, Some(key)) || !self.bind_text(wdb, &st, 3, Some(value)) {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_update_agent_keepalive`
    pub fn global_update_agent_keepalive(&self, wdb: &mut Wdb, id: i32, connection_status: Option<&[u8]>, sync_status: Option<&[u8]>) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_KEEPALIVE) else {
            return OS_INVALID;
        };
        if !self.bind_text(wdb, &st, 1, connection_status) || !self.bind_text(wdb, &st, 2, sync_status) || !self.bind_int(wdb, &st, 3, id) {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_update_agent_connection_status`
    pub fn global_update_agent_connection_status(&self, wdb: &mut Wdb, id: i32, connection_status: &[u8], sync_status: Option<&[u8]>, status_code: i32) -> i32 {
        let disconnection_time = if cstr(connection_status) == AGENT_CS_DISCONNECTED.as_bytes() { self.time() } else { 0 };
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_CONNECTION_STATUS) else {
            return OS_INVALID;
        };
        if !self.bind_text(wdb, &st, 1, Some(connection_status))
            || !self.bind_text(wdb, &st, 2, sync_status)
            || !self.bind_int(wdb, &st, 3, disconnection_time as i32)
            || !self.bind_int(wdb, &st, 4, status_code)
            || !self.bind_int(wdb, &st, 5, id)
        {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_update_agent_status_code`
    pub fn global_update_agent_status_code(&self, wdb: &mut Wdb, id: i32, status_code: i32, version: Option<&[u8]>, sync_status: Option<&[u8]>) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_STATUS_CODE) else {
            return OS_INVALID;
        };
        if !self.bind_int(wdb, &st, 1, status_code)
            || !self.bind_text(wdb, &st, 2, version)
            || !self.bind_text(wdb, &st, 3, sync_status)
            || !self.bind_int(wdb, &st, 4, id)
        {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_delete_agent`
    pub fn global_delete_agent(&self, wdb: &mut Wdb, id: i32) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_DELETE_AGENT) else {
            return OS_INVALID;
        };
        if !self.bind_int(wdb, &st, 1, id) {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_select_agent_name`
    pub fn global_select_agent_name(&self, wdb: &mut Wdb, id: i32) -> Option<Json> {
        let st = self.prep(wdb, WDB_STMT_GLOBAL_SELECT_AGENT_NAME)?;
        if !self.bind_int(wdb, &st, 1, id) {
            return None;
        }
        self.exec_logged(wdb, &st)
    }

    /// `wdb_global_select_agent_group`
    pub fn global_select_agent_group(&self, wdb: &mut Wdb, id: i32) -> Option<Json> {
        let st = self.prep(wdb, WDB_STMT_GLOBAL_GROUP_CSV_GET)?;
        if !self.bind_int(wdb, &st, 1, id) {
            return None;
        }
        self.exec_logged(wdb, &st)
    }

    /// `wdb_global_find_agent`
    pub fn global_find_agent(&self, wdb: &mut Wdb, name: Option<&[u8]>, ip: Option<&[u8]>) -> Option<Json> {
        let st = self.prep(wdb, WDB_STMT_GLOBAL_FIND_AGENT)?;
        if !self.bind_text(wdb, &st, 1, name) || !self.bind_text(wdb, &st, 2, ip) || !self.bind_text(wdb, &st, 3, ip) {
            return None;
        }
        self.exec_logged(wdb, &st)
    }

    /// `wdb_global_update_agent_groups_hash`
    pub fn global_update_agent_groups_hash(&self, wdb: &mut Wdb, agent_id: i32, groups_string: Option<&[u8]>) -> i32 {
        let groups_hash = match groups_string {
            Some(g) => sha256_sized(g, WDB_GROUP_HASH_SIZE),
            None => {
                let root = self.global_select_agent_group(wdb, agent_id);
                match root.as_ref().and_then(first_child).and_then(|c| c.get("group")) {
                    Some(Json::String(g)) => sha256_sized(g, WDB_GROUP_HASH_SIZE),
                    _ => {
                        self.mdebug2(&msg!(
                            "Unable to get group column for agent '",
                            agent_id,
                            "'. The groups_hash column won't be updated"
                        ));
                        return OS_SUCCESS;
                    }
                }
            }
        };
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_GROUPS_HASH) else {
            return OS_INVALID;
        };
        if !self.bind_text(wdb, &st, 1, Some(&groups_hash)) || !self.bind_int(wdb, &st, 2, agent_id) {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_adjust_v4`
    pub fn global_adjust_v4(&self, wdb: &mut Wdb) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_GET_AGENTS) else {
            return OS_INVALID;
        };
        if !self.bind_int(wdb, &st, 1, 0) {
            return OS_INVALID;
        }
        let mut result = OS_INVALID;
        let mut update_result = OS_SUCCESS;
        loop {
            let step = self.step(&st);
            match step {
                SQLITE_ROW => {
                    let agent_id = st.column_int(0);
                    update_result = self.global_update_agent_groups_hash(wdb, agent_id, None);
                }
                SQLITE_DONE => result = OS_SUCCESS,
                _ => {
                    self.mdebug1(&msg!("SQLite: ", wdb.errmsg()));
                    result = OS_INVALID;
                }
            }
            if !(step == SQLITE_ROW && update_result == OS_SUCCESS) {
                break;
            }
        }
        if result == OS_SUCCESS && self.commit2(wdb) < 0 {
            self.merror(&msg!("DB(", wdb.id, ") The commit statement could not be executed."));
            return -1;
        }
        result
    }

    /// `wdb_global_find_group`
    pub fn global_find_group(&self, wdb: &mut Wdb, group_name: Option<&[u8]>) -> Option<Json> {
        let st = self.prep(wdb, WDB_STMT_GLOBAL_FIND_GROUP)?;
        if !self.bind_text(wdb, &st, 1, group_name) {
            return None;
        }
        self.exec_logged(wdb, &st)
    }

    /// `wdb_global_insert_agent_group`
    pub fn global_insert_agent_group(&self, wdb: &mut Wdb, group_name: &[u8]) -> i32 {
        if self.global_validate_group_name(group_name) == OS_INVALID {
            self.mdebug1(&msg!("Cannot insert '", cstr(group_name), "'"));
            return OS_INVALID;
        }
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_INSERT_AGENT_GROUP) else {
            return OS_INVALID;
        };
        if !self.bind_text(wdb, &st, 1, Some(group_name)) {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_select_group_belong`
    pub fn global_select_group_belong(&self, wdb: &mut Wdb, id_agent: i32) -> Option<Json> {
        let st = self.prep(wdb, WDB_STMT_GLOBAL_SELECT_GROUP_BELONG)?;
        if !self.bind_int(wdb, &st, 1, id_agent) {
            return None;
        }
        let mut sql_status = SQLITE_ERROR;
        let result = self.exec_stmt_sized(Some(&st), WDB_MAX_RESPONSE_SIZE, &mut sql_status, STMT_SINGLE_COLUMN);
        if sql_status == SQLITE_ROW {
            self.mwarn(b"The agent's groups exceed the socket maximum response size.");
        } else if sql_status != SQLITE_DONE {
            self.mdebug1(&msg!("Failed to get agent groups: ", wdb.errmsg(), "."));
        }
        result
    }

    /// `wdb_global_insert_agent_belong`
    pub fn global_insert_agent_belong(&self, wdb: &mut Wdb, id_group: i32, id_agent: i32, priority: i32) -> i32 {
        if !wdb.transaction && self.begin2(wdb) < 0 {
            self.mdebug1(b"Cannot begin transaction");
            return OS_UNDEF;
        }
        if self.stmt_cache(wdb, WDB_STMT_GLOBAL_INSERT_AGENT_BELONG) < 0 {
            self.mdebug1(b"Cannot cache statement");
            return OS_UNDEF;
        }
        let st = wdb.st(WDB_STMT_GLOBAL_INSERT_AGENT_BELONG);
        if !self.bind_int(wdb, &st, 1, id_group) || !self.bind_int(wdb, &st, 2, id_agent) || !self.bind_int(wdb, &st, 3, priority) {
            return OS_UNDEF;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_delete_tuple_belong`
    pub fn global_delete_tuple_belong(&self, wdb: &mut Wdb, id_group: i32, id_agent: i32) -> i32 {
        let Some(st) = self.init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_DELETE_TUPLE_BELONG) else {
            return OS_INVALID;
        };
        st.bind_int(1, id_group);
        st.bind_int(2, id_agent);
        self.exec_stmt_silent(&st)
    }

    /// `wdb_is_group_empty`
    pub fn is_group_empty(&self, wdb: &mut Wdb, group_name: &[u8]) -> Option<Json> {
        let st = self.init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_BELONG_FIND)?;
        st.bind_text(1, Some(group_name));
        self.exec_logged(wdb, &st)
    }

    /// `wdb_global_delete_group`
    pub fn global_delete_group(&self, wdb: &mut Wdb, group_name: &[u8]) -> i32 {
        let sql_agents_id = self.is_group_empty(wdb, group_name);
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_DELETE_GROUP) else {
            return OS_INVALID;
        };
        if !self.bind_text(wdb, &st, 1, Some(group_name)) {
            return OS_INVALID;
        }
        let mut result = OS_INVALID;
        if self.exec_stmt_silent(&st) == OS_SUCCESS {
            let (single, is_worker) = self.env.is_single_node();
            let sync_status: &[u8] = if single != 0 || is_worker != 0 { b"synced" } else { b"syncreq" };
            let mut err_flag = false;
            if let Some(Json::Array(items)) = &sql_agents_id {
                for item in items {
                    if let Some(Json::Number { int: agent_id, .. }) = item.get("id_agent") {
                        let agent_id = *agent_id;
                        if self.global_if_empty_set_default_agent_group(wdb, agent_id) == WDBC_ERROR
                            || self.global_recalculate_agent_groups_hash(wdb, agent_id, Some(sync_status)) == WDBC_ERROR
                        {
                            self.merror(&msg!("Couldn't recalculate hash group for agent: '", format!("{agent_id:03}"), "'"));
                            err_flag = true;
                            break;
                        }
                    }
                }
            }
            if !err_flag {
                result = OS_SUCCESS;
            }
        } else {
            self.mdebug1(&msg!("SQLite: ", wdb.errmsg()));
        }
        result
    }

    /// `wdb_global_select_groups`
    pub fn global_select_groups(&self, wdb: &mut Wdb) -> Option<Json> {
        let st = self.prep(wdb, WDB_STMT_GLOBAL_SELECT_GROUPS)?;
        let mut sql_status = SQLITE_ERROR;
        let result = self.exec_stmt_sized(Some(&st), WDB_MAX_RESPONSE_SIZE, &mut sql_status, STMT_MULTI_COLUMN);
        if sql_status == SQLITE_ROW {
            self.mwarn(b"The groups exceed the socket maximum response size.");
        } else if sql_status != SQLITE_DONE {
            self.mdebug1(&msg!("Failed to get groups: ", wdb.errmsg(), "."));
        }
        result
    }

    /// `wdb_global_get_group_agents`
    pub fn global_get_group_agents(&self, wdb: &mut Wdb, status: &mut i32, group_name: &[u8], last_agent_id: i32) -> Option<Json> {
        let Some(st) = self.init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_BELONG_GET) else {
            *status = WDBC_ERROR;
            return None;
        };
        if !self.bind_text(wdb, &st, 1, Some(group_name)) || !self.bind_int(wdb, &st, 2, last_agent_id) {
            *status = WDBC_ERROR;
            return None;
        }
        let mut sql_status = SQLITE_ERROR;
        let result = self.exec_stmt_sized(Some(&st), WDB_MAX_RESPONSE_SIZE, &mut sql_status, STMT_SINGLE_COLUMN);
        *status = match sql_status {
            SQLITE_DONE => WDBC_OK,
            SQLITE_ROW => WDBC_DUE,
            _ => WDBC_ERROR,
        };
        result
    }

    /// `wdb_global_delete_agent_belong`
    pub fn global_delete_agent_belong(&self, wdb: &mut Wdb, id: i32) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_DELETE_AGENT_BELONG) else {
            return OS_INVALID;
        };
        if !self.bind_int(wdb, &st, 1, id) {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_validate_sync_status`
    pub fn global_validate_sync_status(&self, wdb: &mut Wdb, id: i32, requested: &[u8]) -> B {
        let requested = cstr(requested);
        let Some(old) = self.global_get_sync_status(wdb, id) else {
            self.mwarn(&msg!("Failed to get old sync_status for agent '", id, "'"));
            return requested.to_vec();
        };
        let allowed = match &old[..] {
            b"synced" | b"syncreq_keepalive" => true,
            b"syncreq_status" => requested != b"syncreq_keepalive",
            b"syncreq" => requested != b"syncreq_keepalive" && requested != b"syncreq_status",
            _ => false,
        };
        if allowed {
            requested.to_vec()
        } else {
            old
        }
    }

    /// `wdb_global_get_sync_status`
    pub fn global_get_sync_status(&self, wdb: &mut Wdb, id: i32) -> Option<B> {
        let st = self.prep(wdb, WDB_STMT_GLOBAL_SYNC_GET)?;
        if !self.bind_int(wdb, &st, 1, id) {
            return None;
        }
        let step = self.step(&st);
        if step == SQLITE_ROW {
            st.column_text(0)
        } else {
            if step != SQLITE_DONE {
                self.mdebug1(&msg!("sqlite3_step(): ", wdb.errmsg()));
            }
            None
        }
    }

    /// `wdb_global_set_sync_status`
    pub fn global_set_sync_status(&self, wdb: &mut Wdb, id: i32, sync_status: &[u8]) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_SYNC_SET) else {
            return OS_INVALID;
        };
        if !self.bind_text(wdb, &st, 1, Some(sync_status)) || !self.bind_int(wdb, &st, 2, id) {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_sync_agent_info_get`: the status and the output buffer
    /// (`WDB_MAX_RESPONSE_SIZE` bytes, an array of agents or an error).
    pub fn global_sync_agent_info_get(&self, wdb: &mut Wdb, last_agent_id: &mut i32) -> (i32, B) {
        let mut output: B = Vec::new();
        let mut response_size: u32 = 2;
        if !wdb.transaction && self.begin2(wdb) < 0 {
            self.mdebug1(b"Cannot begin transaction");
            return (WDBC_ERROR, b"Cannot begin transaction".to_vec());
        }
        output.push(b'[');
        let stmts = [WDB_STMT_GLOBAL_SYNC_REQ_FULL_GET, WDB_STMT_GLOBAL_SYNC_REQ_STATUS_GET, WDB_STMT_GLOBAL_SYNC_REQ_KEEPALIVE_GET];
        let initial_agent_id = *last_agent_id;
        let mut status = WDBC_UNKNOWN;
        // the error texts overwrite the buffer start
        let mut err_text: Option<B> = None;
        for &stmt_id in &stmts {
            *last_agent_id = initial_agent_id;
            status = WDBC_UNKNOWN;
            while status == WDBC_UNKNOWN {
                if self.stmt_cache(wdb, stmt_id) < 0 {
                    self.mdebug1(b"Cannot cache statement");
                    err_text = Some(b"Cannot cache statement".to_vec());
                    status = WDBC_ERROR;
                    break;
                }
                let st = wdb.st(stmt_id);
                if st.bind_int(1, *last_agent_id) != SQLITE_OK {
                    self.merror(&msg!("DB(", wdb.id, ") sqlite3_bind_int(): ", wdb.errmsg()));
                    err_text = Some(b"Cannot bind sql statement".to_vec());
                    status = WDBC_ERROR;
                    break;
                }
                let resp = self.exec_stmt(Some(&st));
                match resp.as_ref().and_then(first_child).cloned() {
                    Some(mut json_agent) => {
                        if let Some(Json::Number { int: agent_id, .. }) = json_agent.get("id").cloned() {
                            if stmt_id == WDB_STMT_GLOBAL_SYNC_REQ_FULL_GET {
                                if let Some(labels) = self.global_get_agent_labels(wdb, agent_id) {
                                    if first_child(&labels).is_some() {
                                        json_agent.add("labels", labels);
                                    }
                                }
                            }
                            let agent_str = json_agent.print_unformatted();
                            let agent_len = agent_str.len() as u32;
                            if (response_size + agent_len + 1) < WDB_MAX_RESPONSE_SIZE as u32 {
                                output.extend_from_slice(&agent_str);
                                output.push(b',');
                                response_size += agent_len + 1;
                                *last_agent_id = agent_id;
                                if self.global_set_sync_status(wdb, agent_id, b"synced") != OS_SUCCESS {
                                    self.merror(&msg!("Cannot set sync_status for agent ", agent_id));
                                    err_text = Some(msg!("Cannot set sync_status for agent ", agent_id));
                                    status = WDBC_ERROR;
                                }
                            } else {
                                status = WDBC_DUE;
                            }
                        } else {
                            *last_agent_id += 1;
                        }
                    }
                    None => status = WDBC_OK,
                }
            }
            if status == WDBC_ERROR || status == WDBC_DUE {
                break;
            }
        }
        if let Some(t) = err_text {
            // snprintf(*output, WDB_MAX_RESPONSE_SIZE, "%s", text): the text
            // and its NUL over the start of the buffer (the status is
            // WDBC_ERROR then, so no ']' follows)
            return (status, trunc(t, WDB_MAX_RESPONSE_SIZE));
        }
        if status != WDBC_ERROR {
            if response_size > 2 {
                output.pop();
            }
            output.push(b']');
        }
        (status, output)
    }

    /// `wdb_global_calculate_agent_group_csv`
    pub fn global_calculate_agent_group_csv(&self, wdb: &mut Wdb, id: i32) -> Option<B> {
        let st = self.prep(wdb, WDB_STMT_GLOBAL_SELECT_GROUP_BELONG)?;
        if !self.bind_int(wdb, &st, 1, id) {
            return None;
        }
        let mut result: Option<B> = None;
        let mut s;
        loop {
            s = self.step(&st);
            if s != SQLITE_ROW {
                break;
            }
            let Some(group_hash) = st.column_text(0) else {
                self.mdebug1(b"Group hash is NULL");
                continue;
            };
            if let Some(r) = &result {
                if WDB_MAX_RESPONSE_SIZE < r.len() + group_hash.len() + 1 {
                    self.mdebug1(b"The agent's groups exceed the socket maximum response size.");
                    break;
                }
            }
            wm_strcat(&mut result, &group_hash, MULTIGROUP_SEPARATOR);
        }
        if s != SQLITE_DONE {
            self.mdebug1(b"SQL statement execution failed");
        }
        result
    }

    /// `wdb_global_set_agent_group_context`
    pub fn global_set_agent_group_context(&self, wdb: &mut Wdb, id: i32, csv: Option<&[u8]>, hash: Option<&[u8]>, sync_status: Option<&[u8]>) -> i32 {
        let Some(st) = self.init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_CTX_SET) else {
            return WDBC_ERROR;
        };
        st.bind_text(1, csv);
        st.bind_text(2, hash);
        st.bind_text(3, sync_status);
        st.bind_int(4, id);
        if self.exec_stmt_silent(&st) == OS_SUCCESS {
            WDBC_OK
        } else {
            self.mdebug1(&msg!("Error executing setting the agent group context: ", wdb.errmsg()));
            WDBC_ERROR
        }
    }

    /// `wdb_global_set_agent_group_hash`
    pub fn global_set_agent_group_hash(&self, wdb: &mut Wdb, id: i32, csv: Option<&[u8]>, hash: Option<&[u8]>) -> i32 {
        let Some(st) = self.init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_HASH_SET) else {
            return WDBC_ERROR;
        };
        st.bind_text(1, csv);
        st.bind_text(2, hash);
        st.bind_int(3, id);
        if self.exec_stmt_silent(&st) == OS_SUCCESS {
            WDBC_OK
        } else {
            self.mdebug1(&msg!("Error executing setting the agent group hash: ", wdb.errmsg()));
            WDBC_ERROR
        }
    }

    /// `wdb_global_get_groups_integrity`
    pub fn global_get_groups_integrity(&self, wdb: &mut Wdb, hash: &[u8]) -> Option<Json> {
        let st = self.init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_SYNCREQ_FIND)?;
        match self.step(&st) {
            SQLITE_ROW => Some(Json::Array(vec![Json::string("syncreq")])),
            SQLITE_DONE => {
                let mut hexdigest: Sha1Buf = Vec::new();
                let r = if self.get_global_group_hash(Some(wdb), &mut hexdigest) == OS_SUCCESS && hexdigest == cstr(hash) {
                    "synced"
                } else {
                    "hash_mismatch"
                };
                Some(Json::Array(vec![Json::string(r)]))
            }
            _ => {
                self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
                None
            }
        }
    }

    /// `wdb_global_get_agent_max_group_priority`
    pub fn global_get_agent_max_group_priority(&self, wdb: &mut Wdb, id: i32) -> i32 {
        let Some(st) = self.init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_PRIORITY_GET) else {
            return OS_INVALID;
        };
        if !self.bind_int(wdb, &st, 1, id) {
            return OS_INVALID;
        }
        match self.exec_stmt(Some(&st)) {
            Some(r) => match first_child(&r).and_then(first_child) {
                Some(j) => valueint(j),
                None => OS_INVALID,
            },
            None => {
                self.mdebug1(&msg!("wdb_exec_stmt(): ", wdb.errmsg()));
                OS_INVALID
            }
        }
    }

    /// `wdb_global_assign_agent_group`
    pub fn global_assign_agent_group(&self, wdb: &mut Wdb, id: i32, j_groups: &Json, mut priority: i32, create_agent_name: Option<&[u8]>) -> i32 {
        let mut result = WDBC_OK;
        for j_group_name in j_groups.children() {
            let Json::String(group_name) = j_group_name else {
                self.mdebug1(b"Invalid groups set information");
                result = WDBC_ERROR;
                continue;
            };
            let group_name = cstr(group_name);
            let find = self.global_find_group(wdb, Some(group_name));
            match find.as_ref().filter(|f| !f.children().is_empty()) {
                Some(f) => match first_child(f).and_then(|c| c.get("id")) {
                    Some(Json::Number { int: group_id, .. }) => {
                        let group_id = *group_id;
                        let mut insert_result = self.global_insert_agent_belong(wdb, group_id, id, priority);
                        if create_agent_name.is_none() && insert_result == OS_INVALID {
                            // If the agent doesn't exist, we don't want to insert the group relationship.
                            insert_result = OS_NOTFOUND;
                        }
                        if insert_result == OS_INVALID {
                            if self.global_agent_exists(wdb, id) == 0 {
                                let ip: &[u8] = b"0.0.0.0";
                                let now = self.time() as i32;
                                if self.global_insert_agent(wdb, id, create_agent_name, Some(ip), Some(ip), None, None, now) == OS_INVALID {
                                    self.mdebug1(&msg!("Unable to create agent '", id, "' in never_connected state"));
                                    result = WDBC_ERROR;
                                } else {
                                    insert_result = self.global_insert_agent_belong(wdb, group_id, id, priority);
                                    if insert_result == OS_INVALID || insert_result == OS_UNDEF {
                                        self.mdebug1(&msg!(
                                            "Unable to insert group '",
                                            group_name,
                                            "' for agent '",
                                            id,
                                            "', retry failed after creating agent in never_connected state."
                                        ));
                                        result = WDBC_ERROR;
                                    } else {
                                        priority += 1;
                                    }
                                }
                            } else {
                                self.mdebug1(&msg!(
                                    "Unable to insert group '",
                                    group_name,
                                    "' for agent '",
                                    id,
                                    "', agent already exists, groups not synced."
                                ));
                                result = WDBC_ERROR;
                            }
                        } else if insert_result == OS_UNDEF {
                            self.mdebug1(&msg!("Unable to insert group '", group_name, "' for agent '", id, "', undefined error."));
                            result = WDBC_ERROR;
                        } else if insert_result == OS_NOTFOUND {
                            self.mdebug1(&msg!("Unable to insert group '", group_name, "' for agent '", id, "', agent not found."));
                            result = WDBC_ERROR;
                        } else {
                            priority += 1;
                        }
                    }
                    _ => {
                        self.mwarn(b"Invalid response from wdb_global_find_group.");
                        result = WDBC_ERROR;
                    }
                },
                None => {
                    self.mwarn(&msg!("Unable to find the id of the group '", group_name, "'"));
                    result = WDBC_ERROR;
                }
            }
        }
        result
    }

    /// `wdb_global_unassign_agent_group`
    pub fn global_unassign_agent_group(&self, wdb: &mut Wdb, id: i32, j_groups: &Json) -> i32 {
        let mut result = WDBC_OK;
        for j_group_name in j_groups.children() {
            let Json::String(group_name) = j_group_name else {
                self.mdebug1(b"Invalid groups remove information");
                result = WDBC_ERROR;
                continue;
            };
            let group_name = cstr(group_name);
            let find = self.global_find_group(wdb, Some(group_name));
            match find.as_ref().filter(|f| !f.children().is_empty()) {
                Some(f) => match first_child(f).and_then(|c| c.get("id")) {
                    Some(Json::Number { int: group_id, .. }) => {
                        if self.global_delete_tuple_belong(wdb, *group_id, id) == OS_SUCCESS {
                            if self.global_if_empty_set_default_agent_group(wdb, id) == WDBC_ERROR {
                                result = WDBC_ERROR;
                            }
                        } else {
                            self.mdebug1(&msg!("Unable to delete group '", group_name, "' for agent '", id, "'"));
                            result = WDBC_ERROR;
                        }
                    }
                    _ => {
                        self.mwarn(b"Invalid response from wdb_global_find_group.");
                        result = WDBC_ERROR;
                    }
                },
                None => {
                    self.mwarn(&msg!("Unable to find the id of the group '", group_name, "'"));
                    result = WDBC_ERROR;
                }
            }
        }
        result
    }

    /// `wdb_global_if_empty_set_default_agent_group`
    pub fn global_if_empty_set_default_agent_group(&self, wdb: &mut Wdb, id: i32) -> i32 {
        let mut result = WDBC_OK;
        if self.global_get_agent_max_group_priority(wdb, id) == OS_INVALID {
            let j_default = Json::Array(vec![Json::string("default")]);
            if self.global_assign_agent_group(wdb, id, &j_default, 0, None) == WDBC_OK {
                self.mdebug1(&msg!("Agent '", format!("{id:03}"), "' reassigned to 'default' group"));
            } else {
                self.merror(&msg!("There was an error assigning the agent '", format!("{id:03}"), "' to default group"));
                result = WDBC_ERROR;
            }
        }
        result
    }

    /// `wdb_global_groups_number_get`
    pub fn global_groups_number_get(&self, wdb: &mut Wdb, agent_id: i32) -> i32 {
        let Some(st) = self.init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_AGENT_GROUPS_NUMBER_GET) else {
            return OS_INVALID;
        };
        if !self.bind_int(wdb, &st, 1, agent_id) {
            return OS_INVALID;
        }
        match self.exec_stmt(Some(&st)) {
            Some(r) => match first_child(&r).and_then(first_child) {
                Some(j) => valueint(j),
                None => OS_INVALID,
            },
            None => {
                self.mdebug1(&msg!("wdb_exec_stmt(): ", wdb.errmsg()));
                OS_INVALID
            }
        }
    }

    /// `wdb_global_validate_group_name`
    pub fn global_validate_group_name(&self, group_name: &[u8]) -> i32 {
        let g = cstr(group_name);
        if g.len() > MAX_GROUP_NAME {
            self.mwarn(&msg!(
                "Invalid group name. The group '",
                g,
                "' exceeds the maximum length of ",
                MAX_GROUP_NAME,
                " characters permitted"
            ));
            return OS_INVALID;
        }
        // regcomp("^[a-zA-Z0-9_\\.\\-]+$", REG_EXTENDED): inside a POSIX
        // bracket expression the backslashes are literal characters
        let ok = !g.is_empty() && g.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'\\' | b'.' | b'-'));
        if !ok {
            self.mwarn(&msg!("Invalid group name. '", g, "' contains invalid characters"));
            return OS_INVALID;
        }
        if g == b"." {
            self.mwarn(b"Invalid group name. '.' represents the current directory in unix systems");
            return OS_INVALID;
        }
        if g == b".." {
            self.mwarn(b"Invalid group name. '..' represents the parent directory in unix systems");
            return OS_INVALID;
        }
        OS_SUCCESS
    }

    /// `wdb_global_validate_groups`
    pub fn global_validate_groups(&self, wdb: &mut Wdb, j_groups: &Json, agent_id: i32) -> i32 {
        let mut ret = OS_SUCCESS;
        let groups_number = self.global_groups_number_get(wdb, agent_id);
        if groups_number != OS_INVALID {
            let mut counter = 0;
            for j in j_groups.children() {
                if let Json::String(g) = j {
                    counter += 1;
                    if counter + groups_number > MAX_GROUPS_PER_MULTIGROUP {
                        self.mwarn(&msg!(
                            "The groups assigned to agent ",
                            format!("{agent_id:03}"),
                            " exceed the maximum of ",
                            MAX_GROUPS_PER_MULTIGROUP,
                            " permitted."
                        ));
                        ret = OS_INVALID;
                        break;
                    }
                    ret = self.global_validate_group_name(g);
                    if ret != 0 {
                        break;
                    }
                }
            }
        } else {
            ret = OS_INVALID;
        }
        ret
    }

    /// `wdb_global_set_agent_groups`
    pub fn global_set_agent_groups(&self, wdb: &mut Wdb, mode: i32, sync_status: Option<&[u8]>, j_agents_group_info: &Json) -> i32 {
        let mut ret = WDBC_OK;
        let mut valid_groups = OS_SUCCESS;
        for j_group_info in j_agents_group_info.children() {
            let (Some(Json::Number { int: agent_id, .. }), Some(j_groups @ Json::Array(_))) = (j_group_info.get("id"), j_group_info.get("groups")) else {
                ret = WDBC_ERROR;
                self.mdebug1(b"Invalid groups set information");
                continue;
            };
            let agent_id = *agent_id;
            let mut group_priority = 0;
            if mode == WDB_GROUP_REMOVE {
                if self.global_unassign_agent_group(wdb, agent_id, j_groups) == WDBC_ERROR {
                    ret = WDBC_ERROR;
                    self.merror(&msg!("There was an error un-assigning the groups to agent '", format!("{agent_id:03}"), "'"));
                }
            } else {
                if mode == WDB_GROUP_OVERRIDE {
                    if self.global_delete_agent_belong(wdb, agent_id) == OS_INVALID {
                        ret = WDBC_ERROR;
                        self.merror(b"There was an error cleaning the previous agent groups");
                    }
                } else {
                    let last = self.global_get_agent_max_group_priority(wdb, agent_id);
                    if last >= 0 {
                        if mode == WDB_GROUP_EMPTY_ONLY {
                            self.mdebug1(b"Agent group set in empty_only mode ignored because the agent already contains groups");
                            continue;
                        }
                        group_priority = last + 1;
                    }
                }
                valid_groups = self.global_validate_groups(wdb, j_groups, agent_id);
                if valid_groups == OS_SUCCESS {
                    let mut agent_name: Option<B> = None;
                    if mode == WDB_GROUP_OVERRIDE {
                        match j_group_info.get("name") {
                            Some(Json::String(n)) => agent_name = Some(cstr(n).to_vec()),
                            _ if self.cfg.is_worker_node => {
                                self.merror(&msg!(
                                    "Agent name is required when overriding groups for agent '",
                                    format!("{agent_id:03}"),
                                    "'"
                                ));
                                ret = WDBC_ERROR;
                                continue;
                            }
                            _ => {
                                self.mdebug1(&msg!(
                                    "Agent name is not provided for agent '",
                                    format!("{agent_id:03}"),
                                    "', the agent not will not be created if it does not exist"
                                ));
                            }
                        }
                    }
                    if self.global_assign_agent_group(wdb, agent_id, j_groups, group_priority, agent_name.as_deref()) == WDBC_ERROR {
                        ret = WDBC_ERROR;
                        self.merror(&msg!("There was an error assigning the groups to agent '", format!("{agent_id:03}"), "'"));
                    }
                } else {
                    ret = WDBC_ERROR;
                }
            }
            if valid_groups == OS_SUCCESS && self.global_recalculate_agent_groups_hash(wdb, agent_id, sync_status) == WDBC_ERROR {
                ret = WDBC_ERROR;
                self.merror(&msg!("Couldn't recalculate hash group for agent: '", format!("{agent_id:03}"), "'"));
            }
        }
        ret
    }

    /// `wdb_global_recalculate_agent_groups_hash`
    pub fn global_recalculate_agent_groups_hash(&self, wdb: &mut Wdb, agent_id: i32, sync_status: Option<&[u8]>) -> i32 {
        let mut result = WDBC_OK;
        let csv = self.global_calculate_agent_group_csv(wdb, agent_id);
        let hash = match &csv {
            Some(c) => Some(sha256_sized(c, WDB_GROUP_HASH_SIZE)),
            None => {
                self.mwarn(&msg!("The groups were empty right after the set for agent '", format!("{agent_id:03}"), "'"));
                None
            }
        };
        if self.global_set_agent_group_context(wdb, agent_id, csv.as_deref(), hash.as_deref(), sync_status) == WDBC_ERROR {
            result = WDBC_ERROR;
            self.merror(&msg!("There was an error assigning the groups context to agent '", format!("{agent_id:03}"), "'"));
        }
        self.group_hash_cache_clear();
        result
    }

    /// `wdb_global_recalculate_agent_groups_hash_without_sync_status`
    pub fn global_recalculate_agent_groups_hash_without_sync_status(&self, wdb: &mut Wdb, agent_id: i32, group: Option<&[u8]>) -> i32 {
        let mut result = WDBC_OK;
        let csv = self.global_calculate_agent_group_csv(wdb, agent_id);
        let hash = match &csv {
            Some(c) => Some(sha256_sized(c, WDB_GROUP_HASH_SIZE)),
            None => {
                self.mdebug1(&msg!("No groups in belongs table for agent '", format!("{agent_id:03}"), "'"));
                None
            }
        };
        let changed = match (group, &csv) {
            (Some(_), None) | (None, Some(_)) => true,
            (Some(g), Some(c)) => cstr(g) != &c[..],
            (None, None) => false,
        };
        if changed && self.global_set_agent_group_hash(wdb, agent_id, csv.as_deref(), hash.as_deref()) == WDBC_ERROR {
            result = WDBC_ERROR;
            self.merror(&msg!("There was an error assigning the groups hash to agent '", format!("{agent_id:03}"), "'"));
        }
        self.group_hash_cache_clear();
        result
    }

    /// `wdb_global_recalculate_all_agent_groups_hash`
    pub fn global_recalculate_all_agent_groups_hash(&self, wdb: &mut Wdb) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_GET_AGENTS_AND_GROUP) else {
            return OS_INVALID;
        };
        if !self.bind_int(wdb, &st, 1, 0) {
            return OS_INVALID;
        }
        let mut s;
        loop {
            s = self.step(&st);
            if s != SQLITE_ROW {
                break;
            }
            let id = st.column_int(0);
            let group = st.column_text(1);
            if self.global_recalculate_agent_groups_hash_without_sync_status(wdb, id, group.as_deref()) == WDBC_ERROR {
                self.merror(&msg!("Couldn't recalculate hash group for agent: '", format!("{id:03}"), "'"));
                return OS_INVALID;
            }
        }
        if s != SQLITE_DONE {
            self.mdebug1(b"SQL statement execution failed");
        }
        OS_SUCCESS
    }

    /// `wdb_global_set_agent_groups_sync_status`
    pub fn global_set_agent_groups_sync_status(&self, wdb: &mut Wdb, id: i32, sync_status: &[u8]) -> i32 {
        let Some(st) = self.init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_SYNC_SET) else {
            return OS_INVALID;
        };
        if !self.bind_text(wdb, &st, 1, Some(sync_status)) || !self.bind_int(wdb, &st, 2, id) {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_sync_agent_groups_get`: (status, output).
    #[allow(clippy::too_many_arguments)]
    pub fn global_sync_agent_groups_get(
        &self,
        wdb: &mut Wdb,
        condition: i32,
        mut last_agent_id: i32,
        set_synced: bool,
        get_hash: bool,
        agent_registration_delta: i32,
    ) -> (i32, Option<Json>) {
        let mut status = WDBC_UNKNOWN;
        let sync_index = match condition {
            WDB_GROUP_SYNC_STATUS => WDB_STMT_GLOBAL_GROUP_SYNC_REQ_GET,
            WDB_GROUP_ALL => WDB_STMT_GLOBAL_GROUP_SYNC_ALL_GET,
            WDB_GROUP_INVALID_CONDITION => {
                self.mdebug1(b"Invalid groups sync condition");
                return (WDBC_ERROR, None);
            }
            _ => WDB_STMT_GLOBAL_GROUP_SYNC_REQ_GET,
        };
        let mut j_response = Json::object();
        let mut j_data: Vec<Json> = Vec::new();
        // "[{\"data\":[]}]"
        let mut response_size = 13usize;
        if condition != WDB_GROUP_NO_CONDITION {
            if !wdb.transaction && self.begin2(wdb) < 0 {
                self.mdebug1(b"Cannot begin transaction");
                j_response.add("data", Json::Array(j_data));
                return (WDBC_ERROR, Some(Json::Array(vec![j_response])));
            }
            let agent_registration_time = self.time() - agent_registration_delta as i64;
            while status == WDBC_UNKNOWN {
                if self.stmt_cache(wdb, sync_index) < 0 {
                    self.mdebug1(b"Cannot cache statement");
                    status = WDBC_ERROR;
                    break;
                }
                let st = wdb.st(sync_index);
                if st.bind_int(1, last_agent_id) != SQLITE_OK {
                    self.merror(&msg!("DB(", wdb.id, ") sqlite3_bind_int(): ", wdb.errmsg()));
                    status = WDBC_ERROR;
                    break;
                }
                if st.bind_int(2, agent_registration_time as i32) != SQLITE_OK {
                    self.merror(&msg!("DB(", wdb.id, ") sqlite3_bind_int(): ", wdb.errmsg()));
                    status = WDBC_ERROR;
                    break;
                }
                let j_agent_stmt = self.exec_stmt(Some(&st));
                match j_agent_stmt.as_ref().and_then(first_child).cloned() {
                    Some(mut j_agent) => {
                        if let Some(Json::Number { int: id, .. }) = j_agent.get("id") {
                            last_agent_id = *id;
                            let j_groups = self.global_select_group_belong(wdb, last_agent_id);
                            match j_groups {
                                Some(g) if first_child(&g).is_some() => {
                                    j_agent.add("groups", g);
                                }
                                _ => {
                                    j_agent.add("groups", Json::array());
                                }
                            }
                            let agent_len = j_agent.print_unformatted().len();
                            if response_size + agent_len + 1 < WDB_MAX_RESPONSE_SIZE {
                                j_data.push(j_agent);
                                response_size += agent_len + 1;
                                if set_synced && self.global_set_agent_groups_sync_status(wdb, last_agent_id, b"synced") != OS_SUCCESS {
                                    self.merror(&msg!("Cannot set group_sync_status for agent ", last_agent_id));
                                    status = WDBC_ERROR;
                                }
                            } else {
                                status = WDBC_DUE;
                            }
                        } else {
                            last_agent_id += 1;
                        }
                    }
                    None => {
                        if get_hash {
                            j_response.add("data", Json::Array(std::mem::take(&mut j_data)));
                            status = self.global_add_global_group_hash_to_response(wdb, &mut j_response, response_size);
                            return (status, Some(Json::Array(vec![j_response])));
                        } else {
                            status = WDBC_OK;
                        }
                    }
                }
            }
        } else if get_hash {
            j_response.add("data", Json::Array(j_data));
            status = self.global_add_global_group_hash_to_response(wdb, &mut j_response, response_size);
            return (status, Some(Json::Array(vec![j_response])));
        } else {
            status = WDBC_OK;
        }
        j_response.add("data", Json::Array(j_data));
        (status, Some(Json::Array(vec![j_response])))
    }

    /// `wdb_global_add_global_group_hash_to_response`
    pub fn global_add_global_group_hash_to_response(&self, wdb: &mut Wdb, response: &mut Json, response_size: usize) -> i32 {
        if !response.is_object() {
            self.mdebug1(b"Invalid JSON object.");
            return WDBC_ERROR;
        }
        // strlen("hash:\"\"") + sizeof(os_sha1)
        let hash_len = 7 + 41;
        if response_size + hash_len + 1 < WDB_MAX_RESPONSE_SIZE {
            let mut hash: Sha1Buf = Vec::new();
            if self.get_global_group_hash(Some(wdb), &mut hash) == OS_SUCCESS {
                if hash.is_empty() {
                    response.add("hash", Json::Null);
                } else {
                    response.add("hash", Json::String(hash));
                }
            } else {
                self.merror(b"Cannot obtain the global group hash");
                return WDBC_ERROR;
            }
            return WDBC_OK;
        }
        WDBC_DUE
    }

    /// `wdb_global_sync_agent_info_set`
    pub fn global_sync_agent_info_set(&self, wdb: &mut Wdb, json_agent: &Json) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_INFO) else {
            return OS_INVALID;
        };
        for field in GLOBAL_DB_AGENT_FIELDS {
            let json_field = json_agent.get(&field[1..]);
            let index = st.bind_parameter_index(field.as_bytes());
            match json_field {
                Some(Json::Number { int, .. }) if index != 0 => {
                    if !self.bind_int(wdb, &st, index, *int) {
                        return OS_INVALID;
                    }
                }
                Some(Json::String(s)) if index != 0 => {
                    if !self.bind_text(wdb, &st, index, Some(s)) {
                        return OS_INVALID;
                    }
                }
                _ => {}
            }
        }
        let index = st.bind_parameter_index(b":sync_status");
        if !self.bind_text(wdb, &st, index, Some(b"synced")) {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_get_agent_info`
    pub fn global_get_agent_info(&self, wdb: &mut Wdb, id: i32) -> Option<Json> {
        let st = self.prep(wdb, WDB_STMT_GLOBAL_GET_AGENT_INFO)?;
        if !self.bind_int(wdb, &st, 1, id) {
            return None;
        }
        self.exec_logged(wdb, &st)
    }

    /// `wdb_global_get_agents_to_disconnect`
    pub fn global_get_agents_to_disconnect(&self, wdb: &mut Wdb, last_agent_id: i32, keep_alive: i32, sync_status: Option<&[u8]>, status: &mut i32) -> Option<Json> {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_GET_AGENTS_TO_DISCONNECT) else {
            *status = WDBC_ERROR;
            return None;
        };
        if !self.bind_int(wdb, &st, 1, last_agent_id) || !self.bind_int(wdb, &st, 2, keep_alive) {
            *status = WDBC_ERROR;
            return None;
        }
        let mut sql_status = SQLITE_ERROR;
        let result = self.exec_stmt_sized(Some(&st), WDB_MAX_RESPONSE_SIZE, &mut sql_status, STMT_MULTI_COLUMN);
        *status = match sql_status {
            SQLITE_DONE => WDBC_OK,
            SQLITE_ROW => WDBC_DUE,
            _ => WDBC_ERROR,
        };
        if let Some(r) = &result {
            for agent in r.children() {
                match agent.get("id") {
                    Some(Json::Number { int: id, .. }) => {
                        if self.global_update_agent_connection_status(wdb, *id, b"disconnected", sync_status, NO_KEEPALIVE) != OS_SUCCESS {
                            self.merror(&msg!("Cannot set connection_status for agent ", *id));
                            *status = WDBC_ERROR;
                        }
                    }
                    _ => {
                        self.merror(b"Invalid element returned by disconnect query");
                        *status = WDBC_ERROR;
                    }
                }
            }
        }
        result
    }

    /// `wdb_global_get_all_agents_context`
    pub fn global_get_all_agents_context(&self, wdb: &mut Wdb) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_GET_AGENTS_CONTEXT) else {
            return OS_INVALID;
        };
        self.exec_stmt_send(Some(&st), wdb.peer)
    }

    /// `wdb_global_get_all_agents`
    pub fn global_get_all_agents(&self, wdb: &mut Wdb, last_agent_id: i32, status: &mut i32) -> Option<Json> {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_GET_AGENTS) else {
            *status = WDBC_ERROR;
            return None;
        };
        if !self.bind_int(wdb, &st, 1, last_agent_id) {
            *status = WDBC_ERROR;
            return None;
        }
        let mut sql_status = SQLITE_ERROR;
        let result = self.exec_stmt_sized(Some(&st), WDB_MAX_RESPONSE_SIZE, &mut sql_status, STMT_MULTI_COLUMN);
        *status = match sql_status {
            SQLITE_DONE => WDBC_OK,
            SQLITE_ROW => WDBC_DUE,
            _ => WDBC_ERROR,
        };
        result
    }

    /// `wdb_global_agent_exists`: 1, 0 or OS_INVALID.
    pub fn global_agent_exists(&self, wdb: &mut Wdb, agent_id: i32) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_AGENT_EXISTS) else {
            return OS_INVALID;
        };
        if !self.bind_int(wdb, &st, 1, agent_id) {
            return OS_INVALID;
        }
        match self.step(&st) {
            SQLITE_ROW => st.column_int(0),
            SQLITE_DONE => 0,
            _ => {
                self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
                OS_INVALID
            }
        }
    }

    /// `wdb_global_reset_agents_connection`
    pub fn global_reset_agents_connection(&self, wdb: &mut Wdb, sync_status: Option<&[u8]>) -> i32 {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_RESET_CONNECTION_STATUS) else {
            return OS_INVALID;
        };
        if st.bind_int(1, RESET_BY_MANAGER) != SQLITE_OK {
            self.merror(&msg!("DB(", wdb.id, ") sqlite3_bind_text(): ", wdb.errmsg()));
            return OS_INVALID;
        }
        if !self.bind_text(wdb, &st, 2, sync_status) {
            return OS_INVALID;
        }
        self.exec_stmt_silent(&st)
    }

    /// `wdb_global_get_agents_by_connection_status`
    pub fn global_get_agents_by_connection_status(
        &self,
        wdb: &mut Wdb,
        last_agent_id: i32,
        connection_status: &[u8],
        node_name: Option<&[u8]>,
        limit: i32,
        status: &mut i32,
    ) -> Option<Json> {
        if !wdb.transaction && self.begin2(wdb) < 0 {
            self.mdebug1(b"Cannot begin transaction");
            *status = WDBC_ERROR;
            return None;
        }
        let idx = if node_name.is_none() {
            WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS
        } else {
            WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS_AND_NODE
        };
        if self.stmt_cache(wdb, idx) < 0 {
            self.mdebug1(b"Cannot cache statement");
            *status = WDBC_ERROR;
            return None;
        }
        let st = wdb.st(idx);
        if !self.bind_int(wdb, &st, 1, last_agent_id) || !self.bind_text(wdb, &st, 2, Some(connection_status)) {
            *status = WDBC_ERROR;
            return None;
        }
        if node_name.is_some() && (!self.bind_text(wdb, &st, 3, node_name) || !self.bind_int(wdb, &st, 4, limit)) {
            *status = WDBC_ERROR;
            return None;
        }
        let mut sql_status = SQLITE_ERROR;
        let result = self.exec_stmt_sized(Some(&st), WDB_MAX_RESPONSE_SIZE, &mut sql_status, STMT_MULTI_COLUMN);
        *status = match sql_status {
            SQLITE_DONE => WDBC_OK,
            SQLITE_ROW => WDBC_DUE,
            _ => WDBC_ERROR,
        };
        result
    }

    /// `wdb_global_create_backup`: OS_SUCCESS/OS_INVALID and the output.
    pub fn global_create_backup(&self, wdb: &mut Wdb, output: &mut B, tag: Option<&str>) -> i32 {
        let now = self.time();
        let timestamp = w_get_timestamp(now, self.env.utc_offset(now)).replace(' ', "-").replace('/', "-");
        let rel = String::from_utf8_lossy(&trunc(
            format!("{WDB_BACKUP_FOLDER}/{WDB_GLOB_BACKUP_NAME}-{timestamp}{}", tag.unwrap_or("")).into_bytes(),
            PATH_MAX - 3,
        ))
        .into_owned();
        if self.commit2(wdb) < 0 {
            *output = out(b"err Cannot commit current transaction to create backup".to_vec());
            return OS_INVALID;
        }
        self.finalize_all_statements(wdb);
        let (rc, st, _) = wdb.db().prepare_v2(b"VACUUM INTO ?;");
        let Some(st) = st.filter(|_| rc == SQLITE_OK) else {
            *output = out(msg!("err DB(", wdb.id, ") sqlite3_prepare_v2(): ", wdb.errmsg()));
            return OS_INVALID;
        };
        // the path SQLite writes to (relative to the working directory in
        // the daemon)
        let full = self.path(&rel);
        if st.bind_text(1, Some(full.to_string_lossy().as_bytes())) != SQLITE_OK {
            *output = out(msg!("err DB(", wdb.id, ") sqlite3_bind_text(): ", wdb.errmsg()));
            return OS_INVALID;
        }
        let mut result = self.exec_stmt_silent(&st);
        if result == OS_INVALID {
            *output = out(msg!("err SQLite: ", wdb.errmsg()));
        }
        drop(st);
        if result == OS_SUCCESS {
            let rel_gz = format!("{rel}.gz");
            result = self.compress_gzfile(&rel, &rel_gz);
            let _ = std::fs::remove_file(&full);
            if result == OS_SUCCESS {
                self.minfo(&msg!("Created Global database backup \"", rel_gz, "\""));
                self.global_remove_old_backups();
                let j = Json::Array(vec![Json::string(&rel_gz)]);
                *output = out(msg!("ok ", j.print_unformatted()));
            } else {
                *output = out(b"err Failed during database backup compression".to_vec());
            }
        }
        result
    }

    /// The backup file names, in directory order.
    fn backup_entries(&self) -> Option<Vec<(String, Option<i64>)>> {
        let dir = std::fs::read_dir(self.path(WDB_BACKUP_FOLDER)).ok()?;
        let mut v = Vec::new();
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with(WDB_GLOB_BACKUP_NAME) {
                continue;
            }
            let mtime = e.metadata().ok().and_then(|m| m.modified().ok()).map(|t| match t.duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_secs() as i64,
                Err(e) => -(e.duration().as_secs() as i64),
            });
            v.push((name, mtime));
        }
        Some(v)
    }

    /// `wdb_global_remove_old_backups`
    pub fn global_remove_old_backups(&self) -> i32 {
        let Some(entries) = self.backup_entries() else {
            self.mdebug1(&msg!("Unable to open backup directory '", WDB_BACKUP_FOLDER, "'"));
            return OS_INVALID;
        };
        let to_delete = entries.len() as i64 - self.cfg.backup[WDB_GLOBAL_BACKUP].max_files as i64;
        for _ in 0..to_delete.max(0) {
            let (_, name) = self.global_get_oldest_backup();
            if let Some(n) = name {
                let tmp = String::from_utf8_lossy(&trunc(format!("{WDB_BACKUP_FOLDER}/{n}").into_bytes(), OS_SIZE_512)).into_owned();
                let _ = std::fs::remove_file(self.path(&tmp));
                self.minfo(&msg!("Deleted Global database backup: \"", tmp, "\""));
            }
        }
        OS_SUCCESS
    }

    /// `wdb_global_get_backups`
    pub fn global_get_backups(&self) -> Option<Json> {
        let Some(entries) = self.backup_entries() else {
            self.mdebug1(&msg!("Unable to open backup directory '", WDB_BACKUP_FOLDER, "'"));
            return None;
        };
        Some(Json::Array(entries.into_iter().map(|(n, _)| Json::string(&n)).collect()))
    }

    /// `wdb_global_restore_backup`. The database stays in the pool (its
    /// connection closed) like the C, which keeps the same `wdb_t`.
    pub fn global_restore_backup(&self, wdb: &mut Wdb, snapshot: Option<&[u8]>, save_pre_restore_state: bool, output: &mut B) -> i32 {
        let backup_to_restore: Option<B> = match snapshot {
            Some(s) => Some(cstr(s).to_vec()),
            None => self.global_get_most_recent_backup().1.map(|s| s.into_bytes()),
        };
        let global_rel = format!("{WDB2_DIR}/{WDB_GLOB_NAME}.db");
        if save_pre_restore_state && self.global_create_backup(wdb, output, Some("-pre_restore")) != OS_SUCCESS {
            self.merror(&msg!("Creating pre-restore Global DB snapshot failed. Backup restore stopped: ", cstr(output)));
            return OS_INVALID;
        }
        let Some(b) = backup_to_restore else {
            self.mdebug1(b"Unable to found a snapshot to restore");
            *output = out(b"err Unable to found a snapshot to restore".to_vec());
            return OS_INVALID;
        };
        let tmp_rel = format!("{WDB2_DIR}/{WDB_GLOB_NAME}.db.back");
        let backup_rel = trunc(msg!(WDB_BACKUP_FOLDER, "/", b), OS_SIZE_256);
        let backup_rel = String::from_utf8_lossy(&backup_rel).into_owned();
        if self.uncompress_gzfile(&backup_rel, &tmp_rel) == 0 {
            self.close(wdb, true);
            let _ = std::fs::remove_file(self.path(&global_rel));
            match std::fs::rename(self.path(&tmp_rel), self.path(&global_rel)) {
                Err(e) => {
                    let (_, t) = errno_text(&e);
                    self.merror(&msg!("Renaming ", tmp_rel, " to ", global_rel, ": ", t));
                    OS_INVALID
                }
                Ok(()) => {
                    *output = out(b"ok".to_vec());
                    OS_SUCCESS
                }
            }
        } else {
            self.mdebug1(b"Failed during backup decompression");
            *output = out(b"err Failed during backup decompression".to_vec());
            OS_INVALID
        }
    }

    /// `wdb_global_get_most_recent_backup`: (time, name).
    pub fn global_get_most_recent_backup(&self) -> (i64, Option<String>) {
        let Some(entries) = self.backup_entries() else {
            self.mdebug1(&msg!("Unable to open backup directory '", WDB_BACKUP_FOLDER, "'"));
            return (OS_INVALID as i64, None);
        };
        let mut t = OS_INVALID as i64;
        let mut name = None;
        for (n, m) in entries {
            if let Some(m) = m {
                if m >= t {
                    t = m;
                    name = Some(n);
                }
            }
        }
        (t, name)
    }

    /// `wdb_global_get_oldest_backup`: (time, name).
    pub fn global_get_oldest_backup(&self) -> (i64, Option<String>) {
        let Some(entries) = self.backup_entries() else {
            self.mdebug1(&msg!("Unable to open backup directory '", WDB_BACKUP_FOLDER, "'"));
            return (OS_INVALID as i64, None);
        };
        let current = self.time();
        let mut oldest = OS_INVALID as i64;
        let mut aux = OS_INVALID as i64;
        let mut name = None;
        for (n, m) in entries {
            if let Some(m) = m {
                if current - m >= aux {
                    aux = current - m;
                    oldest = m;
                    name = Some(n);
                }
            }
        }
        (oldest, name)
    }

    /// `wdb_global_get_distinct_agent_groups`
    pub fn global_get_distinct_agent_groups(&self, wdb: &mut Wdb, group_hash: Option<&[u8]>, status: &mut i32) -> Option<Json> {
        let Some(st) = self.prep(wdb, WDB_STMT_GLOBAL_GET_GROUPS) else {
            *status = WDBC_ERROR;
            return None;
        };
        if !self.bind_text(wdb, &st, 1, Some(group_hash.unwrap_or(b""))) {
            *status = WDBC_ERROR;
            return None;
        }
        let mut sql_status = SQLITE_ERROR;
        let result = self.exec_stmt_sized(Some(&st), WDB_MAX_RESPONSE_SIZE, &mut sql_status, STMT_MULTI_COLUMN);
        *status = match sql_status {
            SQLITE_DONE => WDBC_OK,
            SQLITE_ROW => WDBC_DUE,
            _ => WDBC_ERROR,
        };
        result
    }
}

/// `->valueint` of any item (0 for non-numbers, 1 for true).
pub fn valueint(j: &Json) -> i32 {
    match j {
        Json::Number { int, .. } => *int,
        Json::True => 1,
        _ => 0,
    }
}

/// zlib's gzFile API (shared/file_op.c compresses through it; the bundled
/// zlib of libz-sys keeps the output byte-identical to the C build).
mod gz {
    use std::os::raw::{c_char, c_int, c_uint, c_void};

    // link the bundled zlib
    use libz_sys as _;

    pub type GzFile = *mut c_void;

    extern "C" {
        pub fn gzopen(path: *const c_char, mode: *const c_char) -> GzFile;
        pub fn gzwrite(file: GzFile, buf: *const c_void, len: c_uint) -> c_int;
        pub fn gzread(file: GzFile, buf: *mut c_void, len: c_uint) -> c_int;
        pub fn gzclose(file: GzFile) -> c_int;
        pub fn gzerror(file: GzFile, errnum: *mut c_int) -> *const c_char;
        pub fn gzeof(file: GzFile) -> c_int;
    }

    /// `gzerror` as bytes.
    pub fn error(file: GzFile) -> (i32, Vec<u8>) {
        let mut err: c_int = 0;
        let p = unsafe { gzerror(file, &mut err) };
        let s = if p.is_null() { Vec::new() } else { unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes().to_vec() };
        (err, s)
    }

    /// The last OS error (`errno`, `strerror(errno)`).
    pub fn last_errno() -> (i32, String) {
        super::errno_text(&std::io::Error::last_os_error())
    }

    pub fn cpath(p: &std::path::Path) -> std::ffi::CString {
        std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap_or_default()
    }
}

/// `umask(0027)` of the gz helpers (process-wide, like the C).
fn umask_0027() {
    #[cfg(unix)]
    unsafe {
        libc::umask(0o027);
    }
}

impl Wdbd {
    /// gzerror's "<path>: <msg>" with the daemon-relative path.
    fn gz_message(&self, full: &std::path::Path, rel: &str, msg: &[u8]) -> B {
        let f = full.to_string_lossy();
        match msg.strip_prefix(f.as_bytes()) {
            Some(rest) => msg!(rel, rest),
            None => msg.to_vec(),
        }
    }

    /// `w_compress_gzfile` (paths relative to the home): 0 or -1.
    pub fn compress_gzfile(&self, filesrc: &str, filedst: &str) -> i32 {
        use std::io::Read;
        umask_0027();
        let mut fd = match std::fs::File::open(self.path(filesrc)) {
            Ok(f) => f,
            Err(e) => {
                let (n, t) = errno_text(&e);
                self.merror(&msg!("in w_compress_gzfile(): fopen error ", filesrc, " (", n, "):'", t, "'"));
                return -1;
            }
        };
        let full_dst = self.path(filedst);
        let p = gz::cpath(&full_dst);
        let gz_fd = unsafe { gz::gzopen(p.as_ptr(), c"w".as_ptr()) };
        if gz_fd.is_null() {
            let (n, t) = gz::last_errno();
            self.merror(&msg!("in w_compress_gzfile(): gzopen error ", filedst, " (", n, "):'", t, "'"));
            return -1;
        }
        let mut buf = vec![0u8; OS_SIZE_8192];
        loop {
            let len = match fd.read(&mut buf) {
                Ok(n) if n > 0 => n,
                _ => break,
            };
            let w = unsafe { gz::gzwrite(gz_fd, buf.as_ptr().cast(), len as u32) };
            if w != len as i32 {
                let (_, m) = gz::error(gz_fd);
                self.merror(&msg!("in w_compress_gzfile(): Compression error: ", self.gz_message(&full_dst, filedst, &m)));
                unsafe { gz::gzclose(gz_fd) };
                return -1;
            }
        }
        unsafe { gz::gzclose(gz_fd) };
        0
    }

    /// `w_uncompress_gzfile` (paths relative to the home): 0 or -1.
    pub fn uncompress_gzfile(&self, gzfilesrc: &str, gzfiledst: &str) -> i32 {
        use std::io::Write;
        let full_src = self.path(gzfilesrc);
        if std::fs::symlink_metadata(&full_src).is_err() {
            return -1;
        }
        umask_0027();
        let mut fd = match std::fs::File::create(self.path(gzfiledst)) {
            Ok(f) => f,
            Err(e) => {
                let (n, t) = errno_text(&e);
                self.merror(&msg!("in w_uncompress_gzfile(): fopen error ", gzfiledst, " (", n, "):'", t, "'"));
                return -1;
            }
        };
        let p = gz::cpath(&full_src);
        let gz_fd = unsafe { gz::gzopen(p.as_ptr(), c"rb".as_ptr()) };
        if gz_fd.is_null() {
            let (n, t) = gz::last_errno();
            self.merror(&msg!("in w_uncompress_gzfile(): gzopen error ", gzfilesrc, " (", n, "):'", t, "'"));
            return -1;
        }
        let mut buf = vec![0u8; OS_SIZE_8192];
        loop {
            let len = unsafe { gz::gzread(gz_fd, buf.as_mut_ptr().cast(), OS_SIZE_8192 as u32) };
            if len > 0 {
                let _ = fd.write_all(&buf[..len as usize]);
            }
            if len != OS_SIZE_8192 as i32 {
                break;
            }
        }
        if unsafe { gz::gzeof(gz_fd) } == 0 {
            let (err, m) = gz::error(gz_fd);
            if err != 0 {
                self.merror(&msg!("in w_uncompress_gzfile(): gzread error: '", self.gz_message(&full_src, gzfilesrc, &m), "'"));
                unsafe { gz::gzclose(gz_fd) };
                return -1;
            }
        }
        unsafe { gz::gzclose(gz_fd) };
        0
    }
}
