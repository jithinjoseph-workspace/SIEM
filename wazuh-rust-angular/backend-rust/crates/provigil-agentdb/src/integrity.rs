//! Inventory integrity (spec § integrity): per-component checksums and the sync bookkeeping in
//! the `sync_info` table.

use sha1::{Digest, Sha1};
use provigil_json::Json;
use provigil_sqlite::{Stmt, SQLITE_DONE, SQLITE_ROW};

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

    // ------------------------------------------------------------------ integrity commands

    fn integrity_stmt(&self, h: &mut Handle, sql: &str) -> Option<std::sync::Arc<Stmt>> {
        if !self.begin(h) {
            self.debug(b"Cannot begin transaction".to_vec());
        }
        self.stmt_plain(h, sql)
    }

    /// Publishes the rows a delete returned (the statement stands on its first row).
    fn report_removed(&self, h: &Handle, component: i32, st: &Stmt) {
        if !self.settings.router_inventory {
            self.debug2(b"Router handle not available.".to_vec());
            return;
        }
        loop {
            if (FIM..=FIM_REGISTRY_VALUE).contains(&component) {
                if self.step(st) != SQLITE_ROW {
                    break;
                }
                continue;
            }
            let mut info = Json::object();
            info.add("agent_id", Json::string(h.id.as_bytes()));
            let mut msg = Json::object();
            msg.add("agent_info", info);
            let mut data = Json::object();
            // a NULL column adds no member
            let text = |d: &mut Json, k: &str, i: i32| {
                if let Some(t) = st.column_text(i) {
                    d.add(k, Json::String(t));
                }
            };
            let action = match component {
                OSINFO => {
                    text(&mut data, "os_name", 0);
                    Some("deleteOs")
                }
                HOTFIXES => {
                    text(&mut data, "hotfix", 0);
                    Some("deleteHotfix")
                }
                PACKAGES => {
                    for (i, k) in ["name", "version", "architecture", "format", "location", "item_id"].iter().enumerate() {
                        text(&mut data, k, i as i32);
                    }
                    Some("deletePackage")
                }
                PROCESSES => {
                    text(&mut data, "pid", 0);
                    Some("deleteProcess")
                }
                PORTS => {
                    text(&mut data, "protocol", 0);
                    text(&mut data, "local_ip", 1);
                    data.add("local_port", Json::number(st.column_int64(2) as f64));
                    data.add("inode", Json::number(st.column_int64(3) as f64));
                    text(&mut data, "item_id", 4);
                    Some("deletePort")
                }
                HWINFO => {
                    text(&mut data, "board_serial", 0);
                    Some("deleteHardware")
                }
                NETPROTO => {
                    text(&mut data, "item_id", 0);
                    Some("deleteNetProto")
                }
                NETINFO => {
                    text(&mut data, "item_id", 0);
                    Some("deleteNetIface")
                }
                NETADDRESS => {
                    text(&mut data, "item_id", 0);
                    Some("deleteNetworkAddress")
                }
                USERS => {
                    text(&mut data, "user_name", 0);
                    Some("deleteUser")
                }
                GROUPS => {
                    text(&mut data, "group_name", 0);
                    Some("deleteGroup")
                }
                BROWSER_EXTENSIONS => {
                    text(&mut data, "item_id", 0);
                    Some("deleteBrowserExtension")
                }
                SERVICES => {
                    text(&mut data, "item_id", 0);
                    Some("deleteService")
                }
                _ => None,
            };
            if let Some(a) = action {
                msg.add("action", Json::string(a));
            }
            msg.add("data", data);
            if action.is_some() {
                self.env.router_send(crate::TOPIC_INVENTORY, &msg.print_unformatted());
            } else {
                self.error(cat!("Invalid handle to send delete message. Agent ", h.id.clone()));
            }
            if self.step(st) != SQLITE_ROW {
                break;
            }
        }
    }

    /// Deletes one row of a component by its key (and publishes it).
    pub fn remove_by_pk(&self, h: &mut Handle, component: i32, pk: Option<&[u8]>) {
        let Some(pk) = pk else {
            self.warn(cat!("PK value is NULL during the removal of the component '", name(component), "'"));
            return;
        };
        let Some(st) = self.integrity_stmt(h, sql::DELETE_BY_PK[component as usize]) else {
            self.debug(b"Cannot cache statement".to_vec());
            return;
        };
        if st.bind_text(1, Some(pk)) != provigil_sqlite::SQLITE_OK {
            self.error(cat!("DB(", h.id.clone(), ") sqlite3_bind_text(): ", h.errmsg()));
            return;
        }
        match self.step(&st) {
            SQLITE_ROW => self.report_removed(h, component, &st),
            SQLITE_DONE => {}
            _ => self.debug(cat!("DB(", h.id.clone(), ") SQLite: ", h.errmsg())),
        }
    }

    /// Deletes rows outside [begin, end], or inside (end, tail) when `tail` is given.
    fn delete_range(&self, h: &mut Handle, component: i32, begin: &[u8], end: &[u8], tail: Option<&[u8]>) -> i32 {
        let q = if tail.is_some() { sql::DELETE_RANGE } else { sql::DELETE_AROUND };
        let Some(st) = self.integrity_stmt(h, q[component as usize]) else { return -1 };
        match tail {
            Some(t) => {
                st.bind_text(1, Some(end));
                st.bind_text(2, Some(t));
            }
            None => {
                st.bind_text(1, Some(begin));
                st.bind_text(2, Some(end));
            }
        }
        match self.step(&st) {
            SQLITE_ROW => self.report_removed(h, component, &st),
            SQLITE_DONE => {}
            _ => {
                self.debug(cat!("DB(", h.id.clone(), ") SQLite: ", h.errmsg()));
                return -1;
            }
        }
        0
    }

    /// The manager checksum stored by the last sync of the component.
    fn last_manager_checksum(&self, h: &mut Handle, component: i32) -> Option<Vec<u8>> {
        let Some(st) = self.integrity_stmt(h, "SELECT * FROM sync_info WHERE component = ?;") else {
            self.debug(b"Cannot cache statement".to_vec());
            return None;
        };
        st.bind_text(1, Some(name(component).as_bytes()));
        let Some(info) = self.rows(&st) else {
            self.debug(cat!("wdb_exec_stmt(): ", h.errmsg()));
            return None;
        };
        let row = match &info {
            Json::Array(a) => a.first(),
            _ => None,
        };
        match row.and_then(|r| r.get("last_manager_checksum")) {
            Some(Json::String(s)) => {
                let s = crate::text::until_nul(s);
                Some(s[..s.len().min(41)].to_vec())
            }
            _ => None,
        }
    }

    fn payload_id(&self, data: &Json) -> Option<i64> {
        match data.get("id") {
            Some(Json::Number { double, .. }) => Some(crate::fim::d2long(*double)),
            _ => {
                self.debug(b"No such string 'id' in JSON payload.".to_vec());
                None
            }
        }
    }

    fn parse_payload(&self, h: &Handle, payload: &[u8]) -> Option<Json> {
        let payload = crate::text::until_nul(payload);
        let data = provigil_json::parse(payload);
        if data.is_none() {
            self.debug(cat!("DB(", h.id.clone(), "): cannot parse checksum range payload: '", payload, "'"));
        }
        data
    }

    /// Range checksum check: -1 error, 0 no data, 1 checksum differs, 2 checksum equal.
    fn query_checksum(&self, h: &mut Handle, component: i32, action: i32, payload: &[u8]) -> i32 {
        let Some(data) = self.parse_payload(h, payload) else { return -1 };
        let text = |k: &str| match data.get(k) {
            Some(Json::String(s)) => Some(crate::text::until_nul(s).to_vec()),
            _ => None,
        };
        let need = |k: &str| {
            let v = text(k);
            if v.is_none() {
                self.debug(cat!("No such string '", k, "' in JSON payload."));
            }
            v
        };
        let Some(begin) = need("begin") else { return -1 };
        let Some(end) = need("end") else { return -1 };
        let Some(sum) = need("checksum") else { return -1 };
        let Some(ts) = self.payload_id(&data) else { return -1 };
        let mut status = -1;
        let mut manager = Vec::new();
        if action == CHECK_GLOBAL {
            if let Some(m) = self.last_manager_checksum(h, component) {
                manager = m;
                if manager == sum {
                    self.debug2(cat!("Agent '", h.id.clone(), "' ", name(component), " range checksum avoided."));
                    status = 2;
                }
            }
        }
        if status != 2 {
            let Some(st) = self.integrity_stmt(h, sql::RANGE_CHECKSUM[component as usize]) else {
                self.debug(b"Cannot cache statement".to_vec());
                return -1;
            };
            st.bind_text(1, Some(&begin));
            st.bind_text(2, Some(&end));
            // the same begin and end: a check for duplicates of that key
            let unique = (begin == end).then_some(begin.as_slice());
            match self.rows_checksum(h, &st, component, &mut manager, unique) {
                0 => status = 0,
                _ => {
                    // shortcut: the time is not measured (always 0.000 ms), add a clock to Env if it is needed
                    self.debug2(cat!("Agent '", h.id.clone(), "' ", name(component), " range checksum: Time: 0.000 ms."));
                    status = if manager != sum { 1 } else { 2 };
                }
            }
        }
        if action == CHECK_GLOBAL {
            self.delete_range(h, component, &begin, &end, None);
            match status {
                0 | 1 => self.sync_attempt(h, component, ts, &sum, b"", false),
                _ => self.sync_completion(h, component, ts, &sum, &manager),
            }
        } else if action == CHECK_LEFT {
            let tail = text("tail");
            self.delete_range(h, component, &begin, &end, tail.as_deref());
        }
        status
    }

    /// Clears a component (the agent has none of it).
    fn query_clear(&self, h: &mut Handle, component: i32, payload: &[u8]) -> i32 {
        let Some(data) = self.parse_payload(h, payload) else { return -1 };
        let Some(ts) = self.payload_id(&data) else { return -1 };
        let Some(st) = self.integrity_stmt(h, sql::CLEAR[component as usize]) else { return -1 };
        if self.step(&st) != SQLITE_DONE {
            self.debug(cat!("DB(", h.id.clone(), ") SQLite: ", h.errmsg()));
            return -1;
        }
        self.sync_completion(h, component, ts, b"", b"");
        0
    }

    /// `integrity_check_<action> <payload>` of FIM (`what` = "FIM") and inventory ("Syscollector").
    pub(crate) fn integrity_check_command(&self, h: &mut Handle, component: i32, cmd: &[u8], payload: &[u8], what: &str) -> crate::Answer {
        let action = match cmd {
            b"integrity_check_global" => CHECK_GLOBAL,
            b"integrity_check_left" => CHECK_LEFT,
            b"integrity_check_right" => CHECK_RIGHT,
            _ => CLEAR_ACTION,
        };
        // FIM answers with 0, the inventory kinds with their component number
        let good = if what == "FIM" { 0 } else { component };
        match self.query_checksum(h, component, action, payload) {
            -1 => {
                self.debug(cat!("DB(", h.id.clone(), ") Cannot query ", what, " range checksum."));
                (INVALID, b"err Cannot perform range checksum".to_vec())
            }
            0 => (good, b"ok no_data".to_vec()),
            1 => (good, b"ok checksum_fail".to_vec()),
            _ => (good, b"ok ".to_vec()),
        }
    }

    pub(crate) fn integrity_clear_command(&self, h: &mut Handle, component: i32, payload: &[u8], what: &str) -> crate::Answer {
        let good = if what == "FIM" { 0 } else { component };
        if self.query_clear(h, component, payload) == -1 {
            self.debug(cat!("DB(", h.id.clone(), ") Cannot query ", what, " range checksum."));
            return (INVALID, b"err Cannot perform range checksum".to_vec());
        }
        (good, b"ok ".to_vec())
    }
}

const CHECK_LEFT: i32 = 0;
const CHECK_RIGHT: i32 = 1;
const CHECK_GLOBAL: i32 = 2;
const CLEAR_ACTION: i32 = 3;

use crate::integrity_sql as sql;
