//! `agent <id> dbsync <kind> <INSERTED|MODIFIED|DELETED> <json>` (spec § 2.7): inventory
//! changes sent one row at a time, written with statements built from the column lists below.

use std::sync::Arc;

use provigil_json::Json;
use siem_sqlite::{Stmt, SQLITE_DONE, SQLITE_OK};

use crate::text::{near, read_long, read_real, until_nul};
use crate::{Answer, Engine, Handle, INVALID, OK};

/// Kind word, table, and its columns in table order: `name[<json name]:type[flags]` with type
/// `i` int, `l` 64-bit int, `r` real, `t` text; flags `*` key column, `+` always the default
/// (not taken from the message), `=` an empty text stays empty (otherwise it becomes NULL).
/// Defaults: 0 for numbers, "" for text.
const TABLES: [(&str, &str, &str); 13] = [
    ("network_iface", "sys_netiface", "scan_id:i+ scan_time:t name:t* adapter:t type:t state:t mtu:i mac:t tx_packets:i rx_packets:i tx_bytes:i rx_bytes:i tx_errors:i rx_errors:i tx_dropped:i rx_dropped:i checksum:t= item_id:t"),
    ("network_protocol", "sys_netproto", "scan_id:i+ iface:t* type:t* gateway:t dhcp:t= metric:i checksum:t= item_id:t"),
    ("network_address", "sys_netaddr", "scan_id:i+ iface:t* proto:t* address:t* netmask:t broadcast:t checksum:t= item_id:t"),
    ("osinfo", "sys_osinfo", "scan_id:i+ scan_time:t hostname:t architecture:t os_name:t* os_version:t os_codename:t os_major:t os_minor:t os_patch:t os_build:t os_platform:t sysname:t release:t version:t os_release:t checksum:t= os_display_version:t reference:t+="),
    ("hwinfo", "sys_hwinfo", "scan_id:i+ scan_time:t board_serial:t* cpu_name:t cpu_cores:i cpu_mhz:r ram_total:i ram_free:i ram_usage:i checksum:t="),
    ("ports", "sys_ports", "scan_id:i+ scan_time:t protocol:t* local_ip:t* local_port:i* remote_ip:t remote_port:i tx_queue:i rx_queue:i inode:l* state:t PID<pid:i process:t checksum:t= item_id:t"),
    ("packages", "sys_programs", "scan_id:i+ scan_time:t format:t*= name:t* priority:t section<groups:t size:i vendor:t install_time:t version:t* architecture:t* multiarch:t source:t description:t location:t*= cpe:t+ msu_name:t+ checksum:t= item_id:t"),
    ("hotfixes", "sys_hotfixes", "scan_id:i+ scan_time:t hotfix:t* checksum:t="),
    ("processes", "sys_processes", "scan_id:i+ scan_time:t pid:t* name:t state:t ppid:i utime:i stime:i cmd:t argvs:t euser:t ruser:t suser:t egroup:t rgroup:t sgroup:t fgroup:t priority:i nice:i size:i vm_size:i resident:i share:i start_time:l pgrp:i session:i nlwp:i tgid:i tty:i processor:i checksum:t="),
    ("users", "sys_users", "scan_id:i+ scan_time:t user_name:t* user_full_name:t user_home:t user_id:l user_uid_signed:l user_uuid:t user_groups:t user_group_id:l user_group_id_signed:l user_created:r user_roles:t user_shell:t user_type:t user_is_hidden:i user_is_remote:i user_last_login:l user_auth_failed_count:l user_auth_failed_timestamp:r user_password_last_change:r user_password_expiration_date:i user_password_hash_algorithm:t user_password_inactive_days:i user_password_max_days_between_changes:i user_password_min_days_between_changes:i user_password_status:t user_password_warning_days_before_expiration:i process_pid:l host_ip:t login_status:i login_tty:t login_type:t checksum:t="),
    ("groups", "sys_groups", "scan_id:i+ scan_time:t group_id:l group_name:t* group_description:t group_id_signed:l group_uuid:t group_is_hidden:i group_users:t checksum:t="),
    ("browser_extensions", "sys_browser_extensions", "scan_id:i+ scan_time:t browser_name:t* user_id:t* package_name:t* package_id:t package_version:t* package_description:t package_vendor:t package_build_version:t package_path:t browser_profile_name:t browser_profile_path:t* package_reference:t package_permissions:t package_type:t package_enabled:i package_visible:i package_autoupdate:i package_persistent:i package_from_webstore:i browser_profile_referenced:i package_installed:t file_hash_sha256:t checksum:t= item_id:t"),
    ("services", "sys_services", "scan_id:i+ scan_time:t service_id:t* service_name:t service_description:t service_type:t service_state:t service_sub_state:t service_enabled:t service_start_type:t service_restart:t service_frequency:l service_starts_on_mount:i service_starts_on_path_modified:t service_starts_on_not_empty_directory:t service_inetd_compatibility:i process_pid:l process_executable:t process_args:t process_user_name:t process_group_name:t process_working_directory:t process_root_directory:t file_path:t service_address:t log_file_path:t error_log_file_path:t service_exit_code:i service_win32_exit_code:i service_following:t service_object_path:t service_target_ephemeral_id:l service_target_type:t service_target_address:t checksum:t= item_id:t"),
];

/// The longest statement the delta writer builds.
const QUERY_MAX: usize = 2048;

struct Col<'a> {
    column: &'a str,
    json: &'a str,
    kind: u8,
    key: bool,
    fixed: bool,
    keep_empty: bool,
}

fn columns(spec: &str) -> Vec<Col<'_>> {
    spec.split(' ')
        .map(|tok| {
            let (name, ty) = tok.split_once(':').unwrap_or((tok, "t"));
            let (column, json) = name.split_once('<').unwrap_or((name, name));
            let b = ty.as_bytes();
            Col { column, json, kind: b[0], key: ty.contains('*'), fixed: ty.contains('+'), keep_empty: ty.contains('=') }
        })
        .collect()
}

fn default_of(c: &Col) -> Json {
    if c.kind == b't' {
        Json::string("")
    } else {
        Json::number(0.0)
    }
}

/// Numbers outside the range a column accepts are stored as NULL.
fn in_range(table: &str, field: &str, v: f64) -> bool {
    match (table, field) {
        ("sys_hwinfo", "cpu_cores" | "cpu_mhz" | "ram_total" | "ram_free") => v > 0.0,
        ("sys_hwinfo", "ram_usage") => v > 0.0 && v <= 100.0,
        (
            "sys_users",
            "user_id" | "user_group_id" | "user_auth_failed_count" | "user_password_inactive_days" | "user_password_max_days_between_changes"
            | "user_password_min_days_between_changes" | "user_password_warning_days_before_expiration" | "process_pid",
        ) => v >= 0.0,
        ("sys_users", "user_created" | "user_last_login" | "user_auth_failed_timestamp" | "user_password_last_change" | "user_password_expiration_date") => v > 0.0,
        ("sys_groups", "group_id") => v >= 0.0,
        // the process id of services is named `process_pid`: this rule never matched it (kept)
        ("sys_services", "service_frequency" | "service_process_pid" | "service_target_ephemeral_id" | "service_exit_code" | "service_win32_exit_code") => v >= 0.0,
        _ => true,
    }
}

/// A text holding only a number: the parsed value, or None (an empty text reads as 0).
fn whole<T>(s: &[u8], (v, end): (T, usize)) -> Option<T> {
    let used = if end == 0 { s.is_empty() } else { end == s.len() };
    used.then_some(v)
}

/// Binds one JSON value to a column of the given type: false when the value does not fit.
fn bind(st: &Stmt, i: i32, c: &Col, v: &Json, table: &str) -> bool {
    let ok = |r: i32| r == SQLITE_OK;
    let num = |n: f64, bind_it: &dyn Fn() -> i32| if in_range(table, c.json, n) { ok(bind_it()) } else { ok(st.bind_null(i)) };
    if let Json::Null = v {
        return ok(st.bind_null(i));
    }
    match (c.kind, v) {
        (b't', Json::String(s)) => {
            let s = until_nul(s);
            if s.is_empty() && !c.keep_empty {
                ok(st.bind_null(i))
            } else {
                ok(st.bind_text(i, Some(s)))
            }
        }
        (b't', Json::Number { double, int }) => {
            let mut t = if *int as f64 == *double { int.to_string() } else { provigil_json::fmt_f6(*double) }.into_bytes();
            t.truncate(1023);
            ok(st.bind_text(i, Some(&t)))
        }
        (b'i', Json::String(s)) => {
            let s = until_nul(s);
            match whole(s, read_long(s)) {
                Some(n) => {
                    let n = n as i32;
                    num(n as f64, &|| st.bind_int(i, n))
                }
                None => false,
            }
        }
        (b'i', Json::Number { int, .. }) => num(*int as f64, &|| st.bind_int(i, *int)),
        (b'r', Json::String(s)) => {
            let s = until_nul(s);
            match whole(s, read_real(s)) {
                Some(d) => num(d, &|| st.bind_double(i, d)),
                None => false,
            }
        }
        (b'r', Json::Number { double, .. }) => num(*double, &|| st.bind_double(i, *double)),
        (b'l', Json::String(s)) => {
            let s = until_nul(s);
            match whole(s, read_long(s)) {
                Some(n) => num(n as f64, &|| st.bind_int64(i, n)),
                None => false,
            }
        }
        (b'l', Json::Number { double, .. }) => num(*double, &|| st.bind_int64(i, crate::fim::d2long(*double))),
        _ => false,
    }
}

impl Engine {
    pub(crate) fn dbsync_command(&self, h: &mut Handle, input: &[u8]) -> Answer {
        let input = until_nul(input);
        let bad = |quoted: &[u8]| {
            self.debug2(cat!("DBSYNC query: ", quoted));
            (INVALID, near("err Invalid dbsync query syntax", quoted))
        };
        let Some(p) = input.iter().position(|&c| c == b' ') else { return bad(input) };
        // past the first word, errors quote only the kind
        let (kind, rest) = (&input[..p], &input[p + 1..]);
        let Some(p2) = rest.iter().position(|&c| c == b' ') else { return bad(kind) };
        let (operation, data) = (&rest[..p2], &rest[p2 + 1..]);
        if data.is_empty() {
            return bad(kind);
        }
        let done = match TABLES.iter().find(|(k, ..)| k.as_bytes() == kind) {
            Some(&(k, table, spec)) => self.dbsync_apply(h, k, table, spec, operation, data),
            None => false,
        };
        if done {
            (OK, b"ok ".to_vec())
        } else {
            (INVALID, b"err".to_vec())
        }
    }

    fn dbsync_apply(&self, h: &mut Handle, kind: &str, table: &str, spec: &str, operation: &[u8], raw: &[u8]) -> bool {
        match provigil_json::parse_with_opts(raw, true) {
            Ok((data, _)) => match operation {
                b"INSERTED" | b"MODIFIED" => self.dbsync_upsert(h, kind, table, &columns(spec), &data),
                b"DELETED" => {
                    // a failed delete still answers ok
                    self.dbsync_delete(h, kind, table, &columns(spec), &data);
                    true
                }
                _ => {
                    self.debug(cat!("Invalid operation type: ", operation));
                    false
                }
            },
            Err(at) => {
                self.debug(b"(5217): Could not parse syscollector delta information as JSON.".to_vec());
                self.debug2(cat!("JSON error near: ", until_nul(&raw[at.min(raw.len())..])));
                false
            }
        }
    }

    /// A statement kept per query text. A reset that reports the last run's error keeps the
    /// old bindings (unbound parameters then hold the previous values).
    fn delta_stmt(&self, h: &mut Handle, sql: &str) -> Option<Arc<Stmt>> {
        if let Some(st) = h.stmts.get(sql).cloned() {
            if st.reset() != SQLITE_OK || st.clear_bindings() != SQLITE_OK {
                self.debug(cat!("DB(", h.id.clone(), ") sqlite3_reset() stmt(", st.sql(), "): ", h.errmsg()));
            }
            return Some(st);
        }
        let (rc, st, _) = h.db().prepare_v2(sql.as_bytes());
        match st {
            Some(st) if rc == SQLITE_OK => {
                let st = Arc::new(st);
                h.stmts.insert(sql.to_string(), st.clone());
                Some(st)
            }
            _ => {
                self.error(cat!("DB(", h.id.clone(), ") sqlite3_prepare_v2() : ", h.errmsg()));
                None
            }
        }
    }

    fn too_long(&self, what: &str) -> bool {
        self.error(cat!("Exceeding maximum query size of ", QUERY_MAX, " bytes adding ", what, "."));
        false
    }

    fn bind_failed(&self, h: &Handle, field: &str, kind: &str) {
        self.error(cat!("(5216): DB(", h.id.clone(), ") Could not bind delta field '", field, "' from '", kind, "' scan."));
    }

    fn dbsync_upsert(&self, h: &mut Handle, kind: &str, table: &str, cols: &[Col], data: &Json) -> bool {
        let mut q = format!("INSERT INTO {table} VALUES( ");
        for i in 0..cols.len() {
            if q.len() + 3 > QUERY_MAX {
                return self.too_long("values placeholders");
            }
            q.push('?');
            if i + 1 < cols.len() {
                q.push(',');
            }
        }
        if q.len() + 29 > QUERY_MAX {
            return self.too_long("conflict clause");
        }
        q.push_str(") ON CONFLICT DO UPDATE SET ");
        let mut first = true;
        for c in cols.iter().filter(|c| !c.fixed && !c.key) {
            if q.len() + c.column.len() + if first { 3 } else { 4 } > QUERY_MAX {
                return self.too_long(if first { "first field" } else { "subsequent fields" });
            }
            if !first {
                q.push(',');
            }
            q.push_str(c.column);
            q.push_str("=?");
            first = false;
        }
        let Some(st) = self.delta_stmt(h, &q) else {
            self.error(b"(5214): Null statement on internal cache.".to_vec());
            return false;
        };
        let mut i = 1;
        // the insert part: every column, missing values as their default
        for c in cols {
            let v = match (c.fixed, data.get(c.json)) {
                (false, Some(v)) if !matches!(v, Json::Null) => v.clone(),
                _ => default_of(c),
            };
            if !bind(&st, i, c, &v, table) {
                self.bind_failed(h, c.json, kind);
                return false;
            }
            i += 1;
        }
        // the update part: only the values the message has
        for c in cols.iter().filter(|c| !c.fixed && !c.key) {
            if let Some(v) = data.get(c.json) {
                if !bind(&st, i, c, v, table) {
                    self.bind_failed(h, c.json, kind);
                    return false;
                }
            }
            i += 1;
        }
        self.step(&st) == SQLITE_DONE
    }

    fn dbsync_delete(&self, h: &mut Handle, kind: &str, table: &str, cols: &[Col], data: &Json) -> bool {
        let mut q = format!("DELETE FROM {table} WHERE ");
        let mut first = true;
        for c in cols.iter().filter(|c| c.key) {
            if q.len() + c.column.len() + if first { 3 } else { 8 } > QUERY_MAX {
                return self.too_long(if first { "first pk" } else { "subsequent pks" });
            }
            if !first {
                q.push_str(" AND ");
            }
            q.push_str(c.column);
            q.push_str("=?");
            first = false;
        }
        let Some(st) = self.delta_stmt(h, &q) else {
            self.error(b"(5214): Null statement on internal cache.".to_vec());
            return false;
        };
        for (n, c) in cols.iter().filter(|c| c.key).enumerate() {
            let v = match data.get(c.json) {
                Some(v) if !matches!(v, Json::Null) => v.clone(),
                _ => default_of(c),
            };
            if !bind(&st, n as i32 + 1, c, &v, table) {
                self.bind_failed(h, c.json, kind);
                return false;
            }
        }
        self.step(&st) == SQLITE_DONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_specs() {
        let ports = columns(TABLES[5].2);
        let pid = ports.iter().find(|c| c.column == "PID").unwrap();
        assert_eq!((pid.json, pid.kind, pid.key), ("pid", b'i', false));
        let fmt = &columns(TABLES[6].2)[2];
        assert!(fmt.key && fmt.keep_empty && !fmt.fixed);
        assert!(TABLES.iter().all(|t| columns(t.2)[0].column == "scan_id" && columns(t.2)[0].fixed));
    }
}
