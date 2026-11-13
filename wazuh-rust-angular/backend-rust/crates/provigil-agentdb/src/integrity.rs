//! Inventory integrity (spec § integrity): per-component checksums and the sync bookkeeping in
//! the `sync_info` table.

use sha1::{Digest, Sha1};
use siem_cjson::Json;
use siem_sqlite::{Stmt, SQLITE_DONE, SQLITE_ROW};

use crate::{Engine, Handle, INVALID};

/// Components, by number.
pub const FIM: i32 = 0;
pub const FIM_FILE: i32 = 1;
pub const FIM_REGISTRY: i32 = 2;
pub const FIM_REGISTRY_KEY: i32 = 3;
pub const FIM_REGISTRY_VALUE: i32 = 4;
pub const PROCESSES: i32 = 5;
pub const PACKAGES: i32 = 6;
pub const HOTFIXES: i32 = 7;
pub const PORTS: i32 = 8;
pub const NETPROTO: i32 = 9;
pub const NETADDRESS: i32 = 10;
pub const NETINFO: i32 = 11;
pub const HWINFO: i32 = 12;
pub const OSINFO: i32 = 13;
pub const USERS: i32 = 14;
pub const GROUPS: i32 = 15;
pub const BROWSER_EXTENSIONS: i32 = 16;
pub const SERVICES: i32 = 17;
pub const GENERIC: i32 = 18;

/// The component name stored in `sync_info.component` (and used in log lines).
pub const NAMES: [&str; 19] = [
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

pub fn name(c: i32) -> &'static str {
    NAMES.get(c as usize).copied().unwrap_or("")
}

/// (table, filter, order column) of each component's checksum rows.
const CHECKSUM_ROWS: [(&str, &str, &str); 18] = [
    ("fim_entry", "", "file"),
    ("fim_entry", "type='file'", "file"),
    ("fim_entry", "(type='registry_key' OR type='registry_value')", "full_path"),
    ("fim_entry", "type='registry_key'", "full_path"),
    ("fim_entry", "type='registry_value'", "full_path"),
    ("sys_processes", "inv", "pid"),
    ("sys_programs", "inv", "item_id"),
    ("sys_hotfixes", "inv", "hotfix"),
    ("sys_ports", "inv", "item_id"),
    ("sys_netproto", "inv", "item_id"),
    ("sys_netaddr", "inv", "item_id"),
    ("sys_netiface", "inv", "item_id"),
    ("sys_hwinfo", "inv", "board_serial"),
    ("sys_osinfo", "inv", "os_name"),
    ("sys_users", "inv", "user_name"),
    ("sys_groups", "inv", "group_name"),
    ("sys_browser_extensions", "inv", "item_id"),
    ("sys_services", "inv", "item_id"),
];

/// The query of all checksums of a component, in key order (FIM statements end without `;`
/// for the registry kinds, as stored).
pub fn checksum_sql(c: i32) -> String {
    let (table, filter, order) = CHECKSUM_ROWS[c as usize];
    let semi = if (FIM_REGISTRY..=FIM_REGISTRY_VALUE).contains(&c) { "" } else { ";" };
    match filter {
        "" => format!("SELECT checksum FROM {table} ORDER BY {order}{semi}"),
        "inv" => format!("SELECT checksum FROM {table} WHERE checksum != 'legacy' AND checksum != '' ORDER BY {order}{semi}"),
        f => format!("SELECT checksum FROM {table} WHERE {f} ORDER BY {order}{semi}"),
    }
}

pub fn hex(d: &[u8]) -> Vec<u8> {
    d.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect()
}

impl Engine {
    /// SHA-1 of the first column of every row: 1 with the digest, 0 when there are no rows.
    /// With `unique` and more than one row: a warning, the duplicates are removed, no digest.
    pub fn rows_checksum(&self, h: &mut Handle, st: &Stmt, component: i32, digest: &mut Vec<u8>, unique: Option<&[u8]>) -> i32 {
        let mut step = self.step(st);
        if step != SQLITE_ROW {
            return 0;
        }
        let mut ctx = Sha1::new();
        let mut rows = 0usize;
        while step == SQLITE_ROW {
            rows += 1;
            match st.column_text(0) {
                None => self.debug(cat!("DB(", h.id.clone(), ") has a NULL ", name(component), " checksum.")),
                Some(c) => ctx.update(&c),
            }
            step = self.step(st);
        }
        let d = ctx.finalize();
        match unique {
            Some(pk) if rows > 1 => {
                self.warn(cat!(
                    "DB(", h.id.clone(), ") ", name(component), " component has more than one element with the same PK value '", pk, "'."
                ));
                self.remove_by_pk(h, component, Some(pk));
            }
            _ => *digest = hex(&d),
        }
        1
    }

    /// The checksum of a whole component: 1 / 0 (no rows) / -1.
    pub fn component_checksum(&self, h: &mut Handle, component: i32, digest: &mut Vec<u8>) -> i32 {
        if !self.begin(h) {
            self.debug(b"Cannot begin transaction".to_vec());
        }
        let Some(st) = self.stmt_plain(h, &checksum_sql(component)) else {
            self.debug(b"Cannot cache statement".to_vec());
            return -1;
        };
        self.rows_checksum(h, &st, component, digest, None)
    }

    fn sync_update(&self, h: &mut Handle, sql: &str, bind: &dyn Fn(&Stmt)) {
        if !self.begin(h) {
            self.debug(b"Cannot begin transaction".to_vec());
        }
        let Some(st) = self.stmt_plain(h, sql) else { return };
        bind(&st);
        if self.step(&st) != SQLITE_DONE {
            self.debug(cat!("DB(", h.id.clone(), ") SQLite: ", h.errmsg()));
        }
    }

    /// Records a sync attempt. `legacy`: the old protocol's statement, which has two values and
    /// gets the component in the wrong one, so it changes no row (kept).
    pub fn sync_attempt(&self, h: &mut Handle, component: i32, ts: i64, agent_sum: &[u8], manager_sum: &[u8], legacy: bool) {
        let sql = if legacy {
            "UPDATE sync_info SET last_attempt = ? WHERE component = ?;"
        } else {
            "UPDATE sync_info SET last_attempt = ?, last_agent_checksum = ?, last_manager_checksum = ?, n_attempts = n_attempts + 1 WHERE component = ?;"
        };
        self.sync_update(h, sql, &|st| {
            st.bind_int64(1, ts);
            st.bind_text(2, Some(agent_sum));
            st.bind_text(3, Some(manager_sum));
            st.bind_text(4, Some(name(component).as_bytes()));
        });
    }

    /// Records a completed sync.
    pub fn sync_completion(&self, h: &mut Handle, component: i32, ts: i64, agent_sum: &[u8], manager_sum: &[u8]) {
        self.sync_update(
            h,
            "UPDATE sync_info SET last_attempt = ?, last_completion = ?, last_agent_checksum = ?, last_manager_checksum = ?, n_attempts = n_attempts + 1, n_completions = n_completions + 1 WHERE component = ?;",
            &|st| {
                st.bind_int64(1, ts);
                st.bind_int64(2, ts);
                st.bind_text(3, Some(agent_sum));
                st.bind_text(4, Some(manager_sum));
                st.bind_text(5, Some(name(component).as_bytes()));
            },
        );
    }

    pub fn sync_set_completion(&self, h: &mut Handle, component: i32, ts: i64) {
        self.sync_update(h, "UPDATE sync_info SET last_completion = ? WHERE component = ?;", &|st| {
            st.bind_int64(1, ts);
            st.bind_text(2, Some(name(component).as_bytes()));
        });
    }

    /// Whether the component is in sync: 1 yes, 0 no, -1 error. A component never completed
    /// but whose stored agent checksum equals the current one counts as synced (and is marked).
    pub fn component_sync_status(&self, h: &mut Handle, component: i32) -> i32 {
        if !self.begin(h) {
            self.debug(b"Cannot begin transaction".to_vec());
        }
        let Some(st) = self.stmt_plain(h, "SELECT * FROM sync_info WHERE component = ?;") else {
            self.debug(b"Cannot cache statement".to_vec());
            return INVALID;
        };
        st.bind_text(1, Some(name(component).as_bytes()));
        let Some(info) = self.rows(&st) else {
            self.debug(cat!("wdb_exec_stmt(): ", h.errmsg()));
            return INVALID;
        };
        let row = match &info {
            Json::Array(a) => a.first(),
            _ => None,
        };
        let get = |k: &str| row.and_then(|c| c.get(k));
        match (get("last_attempt"), get("last_completion"), get("last_agent_checksum")) {
            (Some(Json::Number { int: attempt, .. }), Some(Json::Number { int: done, .. }), Some(Json::String(sum))) => {
                let sum = crate::text::until_nul(sum).to_vec();
                if *done != 0 && attempt <= done {
                    1
                } else if !sum.is_empty() {
                    let mut d = Vec::new();
                    match self.component_checksum(h, component, &mut d) {
                        -1 => INVALID,
                        0 => 0,
                        _ => {
                            let same = d == sum;
                            if same {
                                let t = self.time() as u32 as i64;
                                self.sync_set_completion(h, component, t);
                            }
                            same as i32
                        }
                    }
                } else {
                    0
                }
            }
            _ => {
                self.debug(b"Failed to get agent's sync status data".to_vec());
                INVALID
            }
        }
    }

    /// Removes rows of a component by primary key (filled in with the integrity commands).
    pub fn remove_by_pk(&self, _h: &mut Handle, _component: i32, _pk: Option<&[u8]>) {}
}
