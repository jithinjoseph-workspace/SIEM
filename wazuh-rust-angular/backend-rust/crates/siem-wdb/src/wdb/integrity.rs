//! Data integrity synchronization (wazuh_db/wdb_integrity.c): table
//! checksums (SHA-1 of the ordered row checksums), range checks, the
//! deletion of out-of-range rows (reported to the inventory router), the
//! sync_info bookkeeping and the global group hash.

use sha1::{Digest, Sha1};
use siem_cjson::Json;
use siem_sqlite::Stmt;

use super::*;

pub const COMPONENT_NAMES: [&str; 19] = [
    "fim",
    "fim_file",
    "fim_registry",
    "fim_registry_key",
    "fim_registry_value",
    "syscollector-processes",
    "syscollector-packages",
    "syscollector-hotfixes",
    "syscollector-ports",
    "syscollector-netproto",
    "syscollector-netaddress",
    "syscollector-netinfo",
    "syscollector-hwinfo",
    "syscollector-osinfo",
    "syscollector-users",
    "syscollector-groups",
    "syscollector-browser-extensions",
    "syscollector-services",
    "",
];

// integrity_sync_status_t
pub const INTEGRITY_SYNC_ERR: i32 = -1;
pub const INTEGRITY_SYNC_NO_DATA: i32 = 0;
pub const INTEGRITY_SYNC_CKS_FAIL: i32 = 1;
pub const INTEGRITY_SYNC_CKS_OK: i32 = 2;

// dbsync_msg
pub const INTEGRITY_CHECK_LEFT: i32 = 0;
pub const INTEGRITY_CHECK_RIGHT: i32 = 1;
pub const INTEGRITY_CHECK_GLOBAL: i32 = 2;
pub const INTEGRITY_CLEAR: i32 = 3;

/// `INTEGRITY_COMMANDS`
pub const INTEGRITY_COMMANDS: [&str; 4] = ["integrity_check_left", "integrity_check_right", "integrity_check_global", "integrity_clear"];

/// The statement per component of a family (`INDEXES[]` tables); None
/// where the C array has no entry (0, `WDB_STMT_FIM_LOAD`).
fn index(component: i32, table: &[usize; 18]) -> usize {
    table.get(component as usize).copied().unwrap_or(WDB_STMT_FIM_LOAD)
}

const SELECT_CHECKSUM: [usize; 18] = [
    WDB_STMT_FIM_SELECT_CHECKSUM,
    WDB_STMT_FIM_FILE_SELECT_CHECKSUM,
    WDB_STMT_FIM_REGISTRY_SELECT_CHECKSUM,
    WDB_STMT_FIM_REGISTRY_KEY_SELECT_CHECKSUM,
    WDB_STMT_FIM_REGISTRY_VALUE_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_PORTS_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_NETINFO_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_HWINFO_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_OSINFO_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_USERS_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_GROUPS_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_BROWSER_EXTENSIONS_SELECT_CHECKSUM,
    WDB_STMT_SYSCOLLECTOR_SERVICES_SELECT_CHECKSUM,
];

const SELECT_CHECKSUM_RANGE: [usize; 18] = [
    WDB_STMT_FIM_SELECT_CHECKSUM_RANGE,
    WDB_STMT_FIM_FILE_SELECT_CHECKSUM_RANGE,
    WDB_STMT_FIM_REGISTRY_SELECT_CHECKSUM_RANGE,
    WDB_STMT_FIM_REGISTRY_KEY_SELECT_CHECKSUM_RANGE,
    WDB_STMT_FIM_REGISTRY_VALUE_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_PORTS_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETINFO_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_HWINFO_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_OSINFO_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_USERS_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_GROUPS_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_BROWSER_EXTENSIONS_SELECT_CHECKSUM_RANGE,
    WDB_STMT_SYSCOLLECTOR_SERVICES_SELECT_CHECKSUM_RANGE,
];

const DELETE_AROUND: [usize; 18] = [
    WDB_STMT_FIM_DELETE_AROUND,
    WDB_STMT_FIM_FILE_DELETE_AROUND,
    WDB_STMT_FIM_REGISTRY_DELETE_AROUND,
    WDB_STMT_FIM_REGISTRY_KEY_DELETE_AROUND,
    WDB_STMT_FIM_REGISTRY_VALUE_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_USERS_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_GROUPS_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_BROWSER_EXTENSIONS_DELETE_AROUND,
    WDB_STMT_SYSCOLLECTOR_SERVICES_DELETE_AROUND,
];

const DELETE_RANGE: [usize; 18] = [
    WDB_STMT_FIM_DELETE_RANGE,
    WDB_STMT_FIM_FILE_DELETE_RANGE,
    WDB_STMT_FIM_REGISTRY_DELETE_RANGE,
    WDB_STMT_FIM_REGISTRY_KEY_DELETE_RANGE,
    WDB_STMT_FIM_REGISTRY_VALUE_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_USERS_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_GROUPS_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_BROWSER_EXTENSIONS_DELETE_RANGE,
    WDB_STMT_SYSCOLLECTOR_SERVICES_DELETE_RANGE,
];

/// `wdbi_remove_by_pk`'s table (no entries for registry keys/values).
const DELETE_BY_PK: [Option<usize>; 18] = [
    Some(WDB_STMT_FIM_DELETE_BY_PK),
    Some(WDB_STMT_FIM_FILE_DELETE_BY_PK),
    Some(WDB_STMT_FIM_REGISTRY_DELETE_BY_PK),
    None,
    None,
    Some(WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_BY_PK),
    Some(WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_BY_PK),
    Some(WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_BY_PK),
    Some(WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_BY_PK),
    Some(WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_BY_PK),
    Some(WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_BY_PK),
    Some(WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_BY_PK),
    Some(WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_BY_PK),
    Some(WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_BY_PK),
    Some(WDB_STMT_SYSCOLLECTOR_USERS_DELETE_BY_PK),
    Some(WDB_STMT_SYSCOLLECTOR_GROUPS_DELETE_BY_PK),
    Some(WDB_STMT_SYSCOLLECTOR_BROWSER_EXTENSIONS_DELETE_BY_PK),
    Some(WDB_STMT_SYSCOLLECTOR_SERVICES_DELETE_BY_PK),
];

const CLEAR: [usize; 18] = [
    WDB_STMT_FIM_CLEAR,
    WDB_STMT_FIM_FILE_CLEAR,
    WDB_STMT_FIM_REGISTRY_CLEAR,
    WDB_STMT_FIM_REGISTRY_KEY_CLEAR,
    WDB_STMT_FIM_REGISTRY_VALUE_CLEAR,
    WDB_STMT_SYSCOLLECTOR_PROCESSES_CLEAR,
    WDB_STMT_SYSCOLLECTOR_PACKAGES_CLEAR,
    WDB_STMT_SYSCOLLECTOR_HOTFIXES_CLEAR,
    WDB_STMT_SYSCOLLECTOR_PORTS_CLEAR,
    WDB_STMT_SYSCOLLECTOR_NETPROTO_CLEAR,
    WDB_STMT_SYSCOLLECTOR_NETADDRESS_CLEAR,
    WDB_STMT_SYSCOLLECTOR_NETINFO_CLEAR,
    WDB_STMT_SYSCOLLECTOR_HWINFO_CLEAR,
    WDB_STMT_SYSCOLLECTOR_OSINFO_CLEAR,
    WDB_STMT_SYSCOLLECTOR_USERS_CLEAR,
    WDB_STMT_SYSCOLLECTOR_GROUPS_CLEAR,
    WDB_STMT_SYSCOLLECTOR_BROWSER_EXTENSIONS_CLEAR,
    WDB_STMT_SYSCOLLECTOR_SERVICES_CLEAR,
];

fn name(component: i32) -> &'static str {
    COMPONENT_NAMES.get(component as usize).copied().unwrap_or("")
}

/// `OS_SHA1_Hexdigest`
pub fn sha1_hex(d: &[u8]) -> B {
    d.iter().map(|b| format!("{b:02x}")).collect::<String>().into_bytes()
}

/// A 41-byte `os_sha1` buffer as C reads it (up to the first NUL).
pub type Sha1Buf = B;

impl Wdbd {
    /// `wdbi_report_removed`: publish the deleted rows (the statement is on
    /// its first RETURNING row).
    pub fn report_removed(&self, agent_id: &str, component: i32, st: &Stmt) {
        if !self.router_inventory {
            self.mdebug2(b"Router handle not available.");
            return;
        }
        loop {
            if (WDB_FIM..=WDB_FIM_REGISTRY_VALUE).contains(&component) {
                if self.step(st) != SQLITE_ROW {
                    break;
                }
                continue;
            }
            let mut agent_info = Json::object();
            agent_info.add("agent_id", Json::string(agent_id));
            let mut msg = Json::object();
            msg.add("agent_info", agent_info);
            let mut data = Json::object();
            let mut handle = 0;
            // cJSON_CreateString(NULL) is NULL: the member is not added
            let text = |d: &mut Json, k: &str, i: i32| {
                if let Some(t) = st.column_text(i) {
                    d.add(k, Json::String(t));
                }
            };
            let action = match component {
                WDB_SYSCOLLECTOR_OSINFO => {
                    text(&mut data, "os_name", 0);
                    Some("deleteOs")
                }
                WDB_SYSCOLLECTOR_HOTFIXES => {
                    text(&mut data, "hotfix", 0);
                    Some("deleteHotfix")
                }
                WDB_SYSCOLLECTOR_PACKAGES => {
                    text(&mut data, "name", 0);
                    text(&mut data, "version", 1);
                    text(&mut data, "architecture", 2);
                    text(&mut data, "format", 3);
                    text(&mut data, "location", 4);
                    text(&mut data, "item_id", 5);
                    Some("deletePackage")
                }
                WDB_SYSCOLLECTOR_PROCESSES => {
                    text(&mut data, "pid", 0);
                    Some("deleteProcess")
                }
                WDB_SYSCOLLECTOR_PORTS => {
                    text(&mut data, "protocol", 0);
                    text(&mut data, "local_ip", 1);
                    data.add("local_port", Json::number(st.column_int64(2) as f64));
                    data.add("inode", Json::number(st.column_int64(3) as f64));
                    text(&mut data, "item_id", 4);
                    Some("deletePort")
                }
                WDB_SYSCOLLECTOR_HWINFO => {
                    text(&mut data, "board_serial", 0);
                    Some("deleteHardware")
                }
                WDB_SYSCOLLECTOR_NETPROTO => {
                    text(&mut data, "item_id", 0);
                    Some("deleteNetProto")
                }
                WDB_SYSCOLLECTOR_NETINFO => {
                    text(&mut data, "item_id", 0);
                    Some("deleteNetIface")
                }
                WDB_SYSCOLLECTOR_NETADDRESS => {
                    text(&mut data, "item_id", 0);
                    Some("deleteNetworkAddress")
                }
                WDB_SYSCOLLECTOR_USERS => {
                    text(&mut data, "user_name", 0);
                    Some("deleteUser")
                }
                WDB_SYSCOLLECTOR_GROUPS => {
                    text(&mut data, "group_name", 0);
                    Some("deleteGroup")
                }
                WDB_SYSCOLLECTOR_BROWSER_EXTENSIONS => {
                    text(&mut data, "item_id", 0);
                    Some("deleteBrowserExtension")
                }
                WDB_SYSCOLLECTOR_SERVICES => {
                    text(&mut data, "item_id", 0);
                    Some("deleteService")
                }
                _ => None,
            };
            if let Some(a) = action {
                msg.add("action", Json::string(a));
                handle = 2;
            }
            msg.add("data", data);
            let s = msg.print_unformatted();
            if handle != 0 {
                self.env.router_send(handle, &s);
            } else {
                self.merror(&msg!("Invalid handle to send delete message. Agent ", agent_id));
            }
            if self.step(st) != SQLITE_ROW {
                break;
            }
        }
    }

    /// `wdbi_remove_by_pk`
    pub fn wdbi_remove_by_pk(&self, wdb: &mut Wdb, component: i32, pk_value: Option<&[u8]>) {
        let Some(pk) = pk_value else {
            self.mwarn(&msg!("PK value is NULL during the removal of the component '", name(component), "'"));
            return;
        };
        // INDEXES[] holds 0 (WDB_STMT_FIM_LOAD) for the components it skips
        let idx = DELETE_BY_PK.get(component as usize).copied().flatten().unwrap_or(WDB_STMT_FIM_LOAD);
        if self.begin2(wdb) == -1 {
            self.mdebug1(b"Cannot begin transaction");
        }
        if self.stmt_cache(wdb, idx) == OS_INVALID {
            self.mdebug1(b"Cannot cache statement");
            return;
        }
        let st = wdb.st(idx);
        if st.bind_text(1, Some(pk)) != SQLITE_OK {
            self.merror(&msg!("DB(", wdb.id, ") sqlite3_bind_text(): ", wdb.errmsg()));
            return;
        }
        let r = self.step(&st);
        if r == SQLITE_ROW {
            let id = wdb.id.clone();
            self.report_removed(&id, component, &st);
        } else if r != SQLITE_DONE {
            self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
        }
    }

    /// `wdb_calculate_stmt_checksum`: 1 with rows (hexdigest set unless a
    /// duplicated PK was removed), 0 without.
    pub fn calculate_stmt_checksum(&self, wdb: &mut Wdb, st: &Stmt, component: i32, hexdigest: &mut Sha1Buf, pk_value: Option<&[u8]>) -> i32 {
        let mut step = self.step(st);
        if step != SQLITE_ROW {
            return 0;
        }
        let mut ctx = Sha1::new();
        let mut row_count = 0usize;
        while step == SQLITE_ROW {
            row_count += 1;
            match st.column_text(0) {
                None => self.mdebug1(&msg!("DB(", wdb.id, ") has a NULL ", name(component), " checksum.")),
                Some(c) => ctx.update(&c),
            }
            step = self.step(st);
        }
        let digest = ctx.finalize();
        match pk_value {
            Some(pk) if row_count > 1 => {
                self.mwarn(&msg!(
                    "DB(",
                    wdb.id,
                    ") ",
                    name(component),
                    " component has more than one element with the same PK value '",
                    pk,
                    "'."
                ));
                self.wdbi_remove_by_pk(wdb, component, Some(pk));
            }
            _ => *hexdigest = sha1_hex(&digest),
        }
        1
    }

    /// `wdbi_checksum`: 1, 0 (no rows) or -1.
    pub fn wdbi_checksum(&self, wdb: &mut Wdb, component: i32, hexdigest: &mut Sha1Buf) -> i32 {
        let idx = index(component, &SELECT_CHECKSUM);
        if self.begin2(wdb) == -1 {
            self.mdebug1(b"Cannot begin transaction");
        }
        if self.stmt_cache(wdb, idx) == -1 {
            self.mdebug1(b"Cannot cache statement");
            return -1;
        }
        let st = wdb.st(idx);
        self.calculate_stmt_checksum(wdb, &st, component, hexdigest, None)
    }

    /// `wdbi_checksum_range`
    pub fn wdbi_checksum_range(&self, wdb: &mut Wdb, component: i32, begin: &[u8], end: &[u8], hexdigest: &mut Sha1Buf) -> i32 {
        let idx = index(component, &SELECT_CHECKSUM_RANGE);
        if self.begin2(wdb) == -1 {
            self.mdebug1(b"Cannot begin transaction");
        }
        if self.stmt_cache(wdb, idx) == -1 {
            self.mdebug1(b"Cannot cache statement");
            return -1;
        }
        let st = wdb.st(idx);
        st.bind_text(1, Some(begin));
        st.bind_text(2, Some(end));
        // If begin and end have the same value, a duplicity check will be performed.
        let unique = if cstr(begin) == cstr(end) { Some(begin) } else { None };
        self.calculate_stmt_checksum(wdb, &st, component, hexdigest, unique)
    }

    /// `wdbi_delete`
    pub fn wdbi_delete(&self, wdb: &mut Wdb, component: i32, begin: Option<&[u8]>, end: Option<&[u8]>, tail: Option<&[u8]>) -> i32 {
        let idx = if tail.is_some() { index(component, &DELETE_RANGE) } else { index(component, &DELETE_AROUND) };
        if self.begin2(wdb) == -1 {
            self.mdebug1(b"Cannot begin transaction");
        }
        if self.stmt_cache(wdb, idx) == -1 {
            return -1;
        }
        let st = wdb.st(idx);
        if tail.is_some() {
            st.bind_text(1, end);
            st.bind_text(2, tail);
        } else {
            st.bind_text(1, begin);
            st.bind_text(2, end);
        }
        let r = self.step(&st);
        if r == SQLITE_ROW {
            let id = wdb.id.clone();
            self.report_removed(&id, component, &st);
        } else if r != SQLITE_DONE {
            self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
            return -1;
        }
        0
    }

    /// `wdbi_update_attempt`
    pub fn wdbi_update_attempt(&self, wdb: &mut Wdb, component: i32, timestamp: i64, last_agent_checksum: &[u8], manager_checksum: &[u8], legacy: bool) {
        if self.begin2(wdb) == -1 {
            self.mdebug1(b"Cannot begin transaction");
        }
        let idx = if legacy { WDB_STMT_SYNC_UPDATE_ATTEMPT_LEGACY } else { WDB_STMT_SYNC_UPDATE_ATTEMPT };
        if self.stmt_cache(wdb, idx) == -1 {
            return;
        }
        let st = wdb.st(idx);
        st.bind_int64(1, timestamp);
        st.bind_text(2, Some(last_agent_checksum));
        st.bind_text(3, Some(manager_checksum));
        st.bind_text(4, Some(name(component).as_bytes()));
        if self.step(&st) != SQLITE_DONE {
            self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
        }
    }

    /// `wdbi_update_completion`
    pub fn wdbi_update_completion(&self, wdb: &mut Wdb, component: i32, timestamp: i64, last_agent_checksum: &[u8], manager_checksum: &[u8]) {
        if self.begin2(wdb) == -1 {
            self.mdebug1(b"Cannot begin transaction");
        }
        if self.stmt_cache(wdb, WDB_STMT_SYNC_UPDATE_COMPLETION) == -1 {
            return;
        }
        let st = wdb.st(WDB_STMT_SYNC_UPDATE_COMPLETION);
        st.bind_int64(1, timestamp);
        st.bind_int64(2, timestamp);
        st.bind_text(3, Some(last_agent_checksum));
        st.bind_text(4, Some(manager_checksum));
        st.bind_text(5, Some(name(component).as_bytes()));
        if self.step(&st) != SQLITE_DONE {
            self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
        }
    }

    /// `wdbi_set_last_completion`
    pub fn wdbi_set_last_completion(&self, wdb: &mut Wdb, component: i32, timestamp: i64) {
        if self.begin2(wdb) == -1 {
            self.mdebug1(b"Cannot begin transaction");
        }
        if self.stmt_cache(wdb, WDB_STMT_SYNC_SET_COMPLETION) == -1 {
            return;
        }
        let st = wdb.st(WDB_STMT_SYNC_SET_COMPLETION);
        st.bind_int64(1, timestamp);
        st.bind_text(2, Some(name(component).as_bytes()));
        if self.step(&st) != SQLITE_DONE {
            self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
        }
    }

    /// `wdbi_query_checksum`
    pub fn wdbi_query_checksum(&self, wdb: &mut Wdb, component: i32, action: i32, payload: &[u8]) -> i32 {
        let mut status = INTEGRITY_SYNC_ERR;
        let Some(data) = siem_cjson::parse(cstr(payload)) else {
            self.mdebug1(&msg!("DB(", wdb.id, "): cannot parse checksum range payload: '", cstr(payload), "'"));
            return -1;
        };
        let sv = |k: &str| match data.get(k) {
            Some(Json::String(s)) => Some(cstr(s).to_vec()),
            _ => None,
        };
        let Some(begin) = sv("begin") else {
            self.mdebug1(b"No such string 'begin' in JSON payload.");
            return status;
        };
        let Some(end) = sv("end") else {
            self.mdebug1(b"No such string 'end' in JSON payload.");
            return status;
        };
        let Some(checksum) = sv("checksum") else {
            self.mdebug1(b"No such string 'checksum' in JSON payload.");
            return status;
        };
        let timestamp = match data.get("id") {
            Some(Json::Number { double, .. }) => d2long(*double),
            _ => {
                self.mdebug1(b"No such string 'id' in JSON payload.");
                return status;
            }
        };
        let mut manager_checksum: Sha1Buf = Vec::new();
        if action == INTEGRITY_CHECK_GLOBAL
            && self.wdbi_get_last_manager_checksum(wdb, component, &mut manager_checksum) == OS_SUCCESS
            && manager_checksum == checksum
        {
            self.mdebug2(&msg!("Agent '", wdb.id, "' ", name(component), " range checksum avoided."));
            status = INTEGRITY_SYNC_CKS_OK;
        }
        if status != INTEGRITY_SYNC_CKS_OK {
            let start = self.env.timeofday();
            match self.wdbi_checksum_range(wdb, component, &begin, &end, &mut manager_checksum) {
                -1 => return status,
                0 => status = INTEGRITY_SYNC_NO_DATA,
                _ => {
                    let e = self.env.timeofday();
                    let d = state::Tv::diff(e, start);
                    let ms = (d.sec as f64 + d.usec as f64 / 1e6) * 1e3;
                    self.mdebug2(&msg!("Agent '", wdb.id, "' ", name(component), " range checksum: Time: ", format!("{ms:.3}"), " ms."));
                    status = if manager_checksum != checksum { INTEGRITY_SYNC_CKS_FAIL } else { INTEGRITY_SYNC_CKS_OK };
                }
            }
        }
        if action == INTEGRITY_CHECK_GLOBAL {
            self.wdbi_delete(wdb, component, Some(&begin), Some(&end), None);
            match status {
                INTEGRITY_SYNC_NO_DATA | INTEGRITY_SYNC_CKS_FAIL => {
                    self.wdbi_update_attempt(wdb, component, timestamp, &checksum, b"", false)
                }
                INTEGRITY_SYNC_CKS_OK => self.wdbi_update_completion(wdb, component, timestamp, &checksum, &manager_checksum),
                _ => {}
            }
        } else if action == INTEGRITY_CHECK_LEFT {
            let tail = sv("tail");
            self.wdbi_delete(wdb, component, Some(&begin), Some(&end), tail.as_deref());
        }
        status
    }

    /// `wdbi_query_clear`
    pub fn wdbi_query_clear(&self, wdb: &mut Wdb, component: i32, payload: &[u8]) -> i32 {
        let Some(data) = siem_cjson::parse(cstr(payload)) else {
            self.mdebug1(&msg!("DB(", wdb.id, "): cannot parse checksum range payload: '", cstr(payload), "'"));
            return -1;
        };
        let timestamp = match data.get("id") {
            Some(Json::Number { double, .. }) => d2long(*double),
            _ => {
                self.mdebug1(b"No such string 'id' in JSON payload.");
                return -1;
            }
        };
        if self.begin2(wdb) == -1 {
            self.mdebug1(b"Cannot begin transaction");
        }
        let idx = index(component, &CLEAR);
        if self.stmt_cache(wdb, idx) == -1 {
            return -1;
        }
        let st = wdb.st(idx);
        if self.step(&st) != SQLITE_DONE {
            self.mdebug1(&msg!("DB(", wdb.id, ") SQLite: ", wdb.errmsg()));
            return -1;
        }
        self.wdbi_update_completion(wdb, component, timestamp, b"", b"");
        0
    }

    /// `wdbi_get_last_manager_checksum`
    pub fn wdbi_get_last_manager_checksum(&self, wdb: &mut Wdb, component: i32, manager_checksum: &mut Sha1Buf) -> i32 {
        if self.begin2(wdb) == -1 {
            self.mdebug1(b"Cannot begin transaction");
        }
        if self.stmt_cache(wdb, WDB_STMT_SYNC_GET_INFO) == -1 {
            self.mdebug1(b"Cannot cache statement");
            return OS_INVALID;
        }
        let st = wdb.st(WDB_STMT_SYNC_GET_INFO);
        st.bind_text(1, Some(name(component).as_bytes()));
        let Some(info) = self.exec_stmt(Some(&st)) else {
            self.mdebug1(&msg!("wdb_exec_stmt(): ", wdb.errmsg()));
            return OS_INVALID;
        };
        match first_child(&info).and_then(|c| c.get("last_manager_checksum")) {
            Some(Json::String(s)) => {
                // strncpy(manager_checksum, s, sizeof(os_sha1))
                let s = cstr(s);
                *manager_checksum = s[..s.len().min(41)].to_vec();
                OS_SUCCESS
            }
            _ => OS_INVALID,
        }
    }

    /// `wdbi_check_sync_status`: 1 ready, 0 not ready, -1 error.
    pub fn wdbi_check_sync_status(&self, wdb: &mut Wdb, component: i32) -> i32 {
        if self.begin2(wdb) == -1 {
            self.mdebug1(b"Cannot begin transaction");
        }
        if self.stmt_cache(wdb, WDB_STMT_SYNC_GET_INFO) == -1 {
            self.mdebug1(b"Cannot cache statement");
            return OS_INVALID;
        }
        let st = wdb.st(WDB_STMT_SYNC_GET_INFO);
        st.bind_text(1, Some(name(component).as_bytes()));
        let Some(info) = self.exec_stmt(Some(&st)) else {
            self.mdebug1(&msg!("wdb_exec_stmt(): ", wdb.errmsg()));
            return OS_INVALID;
        };
        let child = first_child(&info);
        let get = |k: &str| child.and_then(|c| c.get(k));
        match (get("last_attempt"), get("last_completion"), get("last_agent_checksum")) {
            (Some(Json::Number { int: last_attempt, .. }), Some(Json::Number { int: last_completion, .. }), Some(Json::String(checksum))) => {
                let checksum = cstr(checksum).to_vec();
                if *last_completion != 0 && last_attempt <= last_completion {
                    1
                } else if !checksum.is_empty() {
                    let mut hexdigest: Sha1Buf = Vec::new();
                    match self.wdbi_checksum(wdb, component, &mut hexdigest) {
                        -1 => OS_INVALID,
                        0 => 0,
                        _ => {
                            let r = (hexdigest == checksum) as i32;
                            if r == 1 {
                                let t = self.time() as u32 as i64;
                                self.wdbi_set_last_completion(wdb, component, t);
                            }
                            r
                        }
                    }
                } else {
                    0
                }
            }
            _ => {
                self.mdebug1(b"Failed to get agent's sync status data");
                OS_INVALID
            }
        }
    }

    /// `wdb_get_global_group_hash`: the cached or computed hash ("" when
    /// there are no group hashes).
    pub fn get_global_group_hash(&self, wdb: Option<&mut Wdb>, hexdigest: &mut Sha1Buf) -> i32 {
        if self.group_hash_cache_read(hexdigest) {
            self.mdebug2(b"Using global group hash from cache");
            return OS_SUCCESS;
        }
        let Some(wdb) = wdb else {
            self.mdebug1(b"Database structure not initialized. Unable to calculate global group hash.");
            return OS_INVALID;
        };
        let Some(st) = self.init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_HASH_GET) else {
            return OS_INVALID;
        };
        if self.calculate_stmt_checksum(wdb, &st, WDB_GENERIC_COMPONENT, hexdigest, None) != 0 {
            self.group_hash_cache_write(hexdigest);
            self.mdebug2(b"New global group hash calculated and stored in cache.");
        } else {
            hexdigest.clear();
            self.mdebug2(b"No group hash was found to calculate the global group hash.");
        }
        OS_SUCCESS
    }

    /// `wdb_global_group_hash_cache(WDB_GLOBAL_GROUP_HASH_READ, ...)`
    fn group_hash_cache_read(&self, out: &mut Sha1Buf) -> bool {
        let g = self.group_hash.lock();
        if g.is_empty() {
            false
        } else {
            *out = g.clone();
            true
        }
    }

    fn group_hash_cache_write(&self, v: &[u8]) {
        *self.group_hash.lock() = v.to_vec();
    }

    /// `wdb_global_group_hash_cache(WDB_GLOBAL_GROUP_HASH_CLEAR, NULL)`
    pub fn group_hash_cache_clear(&self) {
        self.group_hash.lock().clear();
    }
}

/// `cJSON *->child` of an array result.
pub fn first_child(j: &Json) -> Option<&Json> {
    match j {
        Json::Array(a) => a.first(),
        Json::Object(m) => m.first().map(|(_, v)| v),
        _ => None,
    }
}

/// `(long)double` (C truncation; out-of-range saturates like x86-64's
/// cvttsd2si gives LONG_MIN).
pub fn d2long(d: f64) -> i64 {
    if d.is_nan() || d >= 9.223372036854775808e18 || d < -9.223372036854775808e18 {
        i64::MIN
    } else {
        d as i64
    }
}
