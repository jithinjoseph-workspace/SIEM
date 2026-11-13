//! `agent <id> syscollector_<kind> save2|integrity_check_*|integrity_clear <payload>`
//! (spec § 2.6): inventory rows from the JSON sync messages of the 13 inventory kinds.

use siem_cjson::Json;
use siem_sqlite::{Stmt, SQLITE_DONE};

use crate::fim::d2long;
use crate::integrity::*;
use crate::inventory::LEGACY;
use crate::text::{find_unescaped, near, until_nul};
use crate::{Answer, Engine, Handle, INVALID};

/// The `attributes` object, read the way the sync messages were always read.
struct A<'a>(&'a Json);

impl A<'_> {
    /// A string member (None when missing or not a string).
    fn s(&self, k: &str) -> Option<Vec<u8>> {
        match self.0.get(k) {
            Some(Json::String(s)) => Some(until_nul(s).to_vec()),
            _ => None,
        }
    }
    /// The integer value of a member (true = 1, other kinds 0), `def` when missing.
    fn int(&self, k: &str, def: i32) -> i32 {
        match self.0.get(k) {
            Some(Json::Number { int, .. }) => *int,
            Some(Json::True) => 1,
            Some(_) => 0,
            None => def,
        }
    }
    /// The double value of a number member (other kinds 0), `def` when missing.
    fn real(&self, k: &str, def: f64) -> f64 {
        match self.0.get(k) {
            Some(Json::Number { double, .. }) => *double,
            Some(_) => 0.0,
            None => def,
        }
    }
    /// The double value cut to a whole number, `def` when missing.
    fn long(&self, k: &str, def: i64) -> i64 {
        match self.0.get(k) {
            Some(Json::Number { double, .. }) => d2long(*double),
            Some(_) => 0,
            None => def,
        }
    }
}

fn empty(v: &Option<Vec<u8>>) -> bool {
    v.as_deref().is_none_or(|s| s.is_empty())
}

/// Binding helpers: a value, or NULL when `keep` is false.
fn int_or_null(st: &Stmt, i: i32, v: i32, keep: bool) {
    if keep {
        st.bind_int(i, v);
    } else {
        st.bind_null(i);
    }
}
fn long_or_null(st: &Stmt, i: i32, v: i64, keep: bool) {
    if keep {
        st.bind_int64(i, v);
    } else {
        st.bind_null(i);
    }
}
fn positive_real(st: &Stmt, i: i32, v: f64) {
    if v > 0.0 {
        st.bind_double(i, v);
    } else {
        st.bind_null(i);
    }
}
fn texts(st: &Stmt, first: i32, a: &A, keys: &[&str]) {
    for (n, k) in keys.iter().enumerate() {
        st.bind_text(first + n as i32, a.s(k).as_deref());
    }
}

/// Per kind: the function-name stem used in log lines and the insert-or-replace statement.
fn kind(component: i32) -> (&'static str, &'static str) {
    match component {
        PROCESSES => ("process", "INSERT OR REPLACE INTO sys_processes (scan_id, scan_time, pid, name, state, ppid, utime, stime, cmd, argvs, euser, ruser, suser, egroup, rgroup, sgroup, fgroup, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp, tgid, tty, processor, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
        PACKAGES => ("package", "INSERT OR REPLACE INTO sys_programs (scan_id, scan_time, format, name, priority, section, size, vendor, install_time, version, architecture, multiarch, source, description, location, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"),
        HOTFIXES => ("hotfix", "INSERT OR REPLACE INTO sys_hotfixes (scan_id, scan_time, hotfix, checksum) VALUES (?, ?, ?, ?);"),
        PORTS => ("port", "INSERT OR REPLACE INTO sys_ports (scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode, state, PID, process, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"),
        NETPROTO => ("netproto", "INSERT OR REPLACE INTO sys_netproto (scan_id, iface, type, gateway, dhcp, metric, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);"),
        NETADDRESS => ("netaddr", "INSERT OR REPLACE INTO sys_netaddr (scan_id, iface, proto, address, netmask, broadcast, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);"),
        NETINFO => ("netinfo", "INSERT OR REPLACE INTO sys_netiface (scan_id, scan_time, name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"),
        HWINFO => ("hardware", "INSERT OR REPLACE INTO sys_hwinfo (scan_id, scan_time, board_serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"),
        OSINFO => ("osinfo", "INSERT OR REPLACE INTO sys_osinfo (scan_id, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor,  os_patch, os_build, os_platform, sysname, release, version, os_release, os_display_version, checksum, reference) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"),
        USERS => ("users", "INSERT OR REPLACE INTO sys_users (scan_id, scan_time, user_name, user_full_name, user_home, user_id, user_uid_signed, user_uuid, user_groups, user_group_id, user_group_id_signed, user_created, user_roles, user_shell, user_type, user_is_hidden, user_is_remote, user_last_login, user_auth_failed_count, user_auth_failed_timestamp, user_password_last_change, user_password_expiration_date, user_password_hash_algorithm, user_password_inactive_days, user_password_max_days_between_changes, user_password_min_days_between_changes, user_password_status, user_password_warning_days_before_expiration, process_pid, host_ip, login_status, login_type, login_tty, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"),
        GROUPS => ("groups", "INSERT OR REPLACE INTO sys_groups (scan_id, scan_time, group_id, group_name, group_description, group_id_signed, group_uuid, group_is_hidden, group_users, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"),
        BROWSER_EXTENSIONS => ("browser_extensions", "INSERT OR REPLACE INTO sys_browser_extensions (scan_id, scan_time, browser_name, user_id, package_name, package_id, package_version, package_description, package_vendor, package_build_version, package_path, browser_profile_name, browser_profile_path, package_reference, package_permissions, package_type, package_enabled, package_visible, package_autoupdate, package_persistent, package_from_webstore, browser_profile_referenced, package_installed, file_hash_sha256, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"),
        _ => ("services", "INSERT OR REPLACE INTO sys_services (scan_id, scan_time, service_id, service_name, service_description, service_type, service_state, service_sub_state, service_enabled, service_start_type, service_restart, service_frequency, service_starts_on_mount, service_starts_on_path_modified, service_starts_on_not_empty_directory, service_inetd_compatibility, process_pid, process_executable, process_args, process_user_name, process_group_name, process_working_directory, process_root_directory, file_path, service_address, log_file_path, error_log_file_path, service_exit_code, service_win32_exit_code, service_following, service_object_path, service_target_ephemeral_id, service_target_type, service_target_address, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"),
    }
}

/// The `syscollector_<kind>` command words, by component.
fn component_of(cmd: &[u8]) -> Option<i32> {
    Some(match cmd {
        b"syscollector_processes" => PROCESSES,
        b"syscollector_packages" => PACKAGES,
        b"syscollector_hotfixes" => HOTFIXES,
        b"syscollector_ports" => PORTS,
        b"syscollector_network_protocol" => NETPROTO,
        b"syscollector_network_address" => NETADDRESS,
        b"syscollector_network_iface" => NETINFO,
        b"syscollector_hwinfo" => HWINFO,
        b"syscollector_osinfo" => OSINFO,
        b"syscollector_users" => USERS,
        b"syscollector_groups" => GROUPS,
        b"syscollector_browser_extensions" => BROWSER_EXTENSIONS,
        b"syscollector_services" => SERVICES,
        _ => return None,
    })
}

impl Engine {
    pub(crate) fn syscollector_command(&self, h: &mut Handle, cmd: &[u8], input: &[u8]) -> Answer {
        let id = h.id.clone();
        let Some(component) = component_of(cmd) else {
            self.debug2(cat!("DB(", id, ") Invalid Syscollector query : ", cmd));
            return (INVALID, near("err Invalid Syscollector query syntax", cmd));
        };
        self.debug2(cat!("DB(", id.clone(), ") ", cmd, " Syscollector query. "));
        let input = until_nul(input);
        let Some(sp) = find_unescaped(input, b' ') else {
            self.debug2(cat!("DB(", id, ") Invalid Syscollector query syntax: ", input));
            return (INVALID, near("err Invalid Syscollector query syntax", input));
        };
        let (sub, next) = (&input[..sp], &input[sp + 1..]);
        if sub == b"save2" {
            if self.syscollector_save2(h, component, next) == INVALID {
                self.debug(cat!("DB(", id, ") Cannot save Syscollector."));
                return (INVALID, b"err Cannot save Syscollector".to_vec());
            }
            (component, b"ok".to_vec())
        } else if sub.starts_with(b"integrity_check_") {
            self.integrity_check_command(h, component, sub, next, "Syscollector")
        } else if sub.starts_with(b"integrity_clear") {
            self.integrity_clear_command(h, component, next, "Syscollector")
        } else {
            self.debug(cat!("DB(", id, ") Invalid Syscollector query syntax."));
            self.debug2(cat!("DB query error near: ", sub));
            (INVALID, near("err Invalid Syscollector query syntax", sub))
        }
    }

    /// One inventory row from a sync message: 0 or -1.
    fn syscollector_save2(&self, h: &mut Handle, component: i32, payload: &[u8]) -> i32 {
        let Some(data) = siem_cjson::parse(until_nul(payload)) else {
            self.debug(b"at wdb_syscollector_save2(): no payload".to_vec());
            return -1;
        };
        let Some(attrs) = data.get("attributes") else {
            self.debug(b"at wdb_syscollector_save2(): no attributes".to_vec());
            return -1;
        };
        let a = A(attrs);
        let (stem, sql) = kind(component);
        if !h.transaction && !self.begin(h) {
            self.debug(cat!("at wdb_", stem, "_save(): cannot begin transaction"));
            return -1;
        }
        // OS and hardware keep one row: the old one goes first
        if component == OSINFO || component == HWINFO {
            let table = if component == OSINFO { "sys_osinfo" } else { "sys_hwinfo" };
            let Some(del) = self.stmt_plain(h, &format!("DELETE FROM {table};")) else {
                if component == OSINFO {
                    self.debug(b"at wdb_osinfo_save(): cannot cache statement (12)".to_vec());
                } else {
                    self.debug(b"at wdb_hardware_save(): cannot cache statement".to_vec());
                }
                return -1;
            };
            if self.step(&del) != SQLITE_DONE {
                self.error(cat!("Deleting old information from '", table, "' table: ", h.errmsg()));
                return -1;
            }
        }
        let checksum = a.s("checksum");
        let item = a.s("item_id");
        let pid = a.s("pid").map(|p| crate::text::read_long(&p).0 as i32).unwrap_or(-1);
        // rows that cannot be stored are refused before the statement
        let refused = match component {
            PROCESSES => pid < 0,
            HOTFIXES => a.s("hotfix").is_none(),
            USERS => empty(&a.s("user_name")),
            GROUPS => empty(&a.s("group_name")),
            BROWSER_EXTENSIONS => ["browser_name", "user_id", "browser_profile_path", "package_name", "package_version"].iter().any(|k| empty(&a.s(k))),
            SERVICES => empty(&a.s("service_id")) || empty(&a.s("file_path")),
            _ => false,
        };
        if refused {
            return -1;
        }
        // a row without its key fields replaces nothing: the stored row with its id goes
        let keyless = match component {
            NETINFO => a.s("name").is_none(),
            NETPROTO => a.s("iface").is_none(),
            NETADDRESS => a.s("iface").is_none() || a.s("address").is_none(),
            PACKAGES => a.s("name").is_none() || a.s("version").is_none() || a.s("architecture").is_none(),
            PORTS => a.s("protocol").is_none() || a.s("local_ip").is_none() || a.int("local_port", 0) < 0 || a.long("inode", 0) < 0,
            _ => false,
        };
        if keyless && checksum.as_deref().is_some_and(|c| c != LEGACY) {
            self.remove_by_pk(h, component, item.as_deref());
        }
        let func = format!("wdb_{stem}_insert");
        let Some(st) = self.stmt_plain(h, sql) else {
            self.debug(cat!("at ", func, "(): cannot cache statement"));
            return -1;
        };
        st.bind_text(1, Some(b"0"));
        self.bind_row(&st, component, &a, pid);
        let ok = if matches!(component, NETINFO | NETPROTO | PACKAGES) { self.written_unique(h, &st) } else { self.written_done(h, &st) };
        if ok {
            0
        } else {
            -1
        }
    }

    /// Binds parameters 2.. of a kind's insert (1 is the scan id).
    fn bind_row(&self, st: &Stmt, component: i32, a: &A, pid: i32) {
        let t = |i: i32, k: &str| st.bind_text(i, a.s(k).as_deref());
        match component {
            PROCESSES => {
                t(2, "scan_time");
                int_or_null(st, 3, pid, pid >= 0);
                t(4, "name");
                t(5, "state");
                for (i, k) in ["ppid", "utime", "stime"].iter().enumerate() {
                    let v = a.int(k, 0);
                    int_or_null(st, 6 + i as i32, v, v >= 0);
                }
                texts(st, 9, a, &["cmd", "argvs", "euser", "ruser", "suser", "egroup", "rgroup", "sgroup", "fgroup"]);
                let priority = a.int("priority", 0);
                int_or_null(st, 18, priority, priority >= 0);
                st.bind_int(19, a.int("nice", 0));
                for (i, k) in ["size", "vm_size", "resident", "share"].iter().enumerate() {
                    let v = a.int(k, 0);
                    int_or_null(st, 20 + i as i32, v, v >= 0);
                }
                let start = a.long("start_time", 0);
                long_or_null(st, 24, start, start >= 0);
                for (i, k) in ["pgrp", "session", "nlwp", "tgid", "tty", "processor"].iter().enumerate() {
                    let v = a.int(k, 0);
                    int_or_null(st, 25 + i as i32, v, v >= 0);
                }
                t(31, "checksum");
            }
            PACKAGES => {
                t(2, "scan_time");
                st.bind_text(3, Some(&a.s("format").unwrap_or_default()));
                t(4, "name");
                t(5, "priority");
                t(6, "groups");
                let size = a.int("size", 0) as i64;
                long_or_null(st, 7, size, size >= 0);
                texts(st, 8, a, &["vendor", "install_time", "version", "architecture", "multiarch", "source", "description"]);
                st.bind_text(15, Some(&a.s("location").unwrap_or_default()));
                t(16, "checksum");
                t(17, "item_id");
            }
            HOTFIXES => texts(st, 2, a, &["scan_time", "hotfix", "checksum"]),
            PORTS => {
                texts(st, 2, a, &["scan_time", "protocol", "local_ip"]);
                let lp = a.int("local_port", 0);
                int_or_null(st, 5, lp, lp >= 0);
                t(6, "remote_ip");
                for (i, k) in ["remote_port", "tx_queue", "rx_queue"].iter().enumerate() {
                    let v = a.int(k, 0);
                    int_or_null(st, 7 + i as i32, v, v >= 0);
                }
                let inode = a.long("inode", 0);
                long_or_null(st, 10, inode, inode >= 0);
                t(11, "state");
                let p = a.int("pid", 0);
                int_or_null(st, 12, p, p >= 0);
                texts(st, 13, a, &["process", "checksum", "item_id"]);
            }
            NETPROTO => {
                t(2, "iface");
                let v6 = a.s("type").is_some_and(|t| t == b"ipv6");
                st.bind_text(3, Some(if v6 { b"ipv6" } else { b"ipv4" }));
                texts(st, 4, a, &["gateway", "dhcp"]);
                let metric = a.int("metric", 0);
                long_or_null(st, 6, metric as i64, metric >= 0);
                texts(st, 7, a, &["checksum", "item_id"]);
            }
            NETADDRESS => {
                t(2, "iface");
                st.bind_text(3, Some(if a.int("proto", 0) == 0 { b"ipv4" } else { b"ipv6" }));
                texts(st, 4, a, &["address", "netmask", "broadcast", "checksum", "item_id"]);
            }
            NETINFO => {
                texts(st, 2, a, &["scan_time", "name", "adapter", "type", "state"]);
                let mtu = a.long("mtu", 0);
                long_or_null(st, 7, mtu, mtu > 0);
                t(8, "mac");
                for (i, k) in ["tx_packets", "rx_packets", "tx_bytes", "rx_bytes", "tx_errors", "rx_errors", "tx_dropped", "rx_dropped"].iter().enumerate() {
                    let v = a.int(k, 0) as i64;
                    long_or_null(st, 9 + i as i32, v, v >= 0);
                }
                texts(st, 17, a, &["checksum", "item_id"]);
            }
            HWINFO => {
                texts(st, 2, a, &["scan_time", "board_serial", "cpu_name"]);
                let cores = a.int("cpu_cores", 0);
                int_or_null(st, 5, cores, cores > 0);
                positive_real(st, 6, a.real("cpu_mhz", 0.0));
                // stored unsigned: any value but 0 counts
                for (i, k) in ["ram_total", "ram_free"].iter().enumerate() {
                    let v = a.int(k, 0) as i64;
                    long_or_null(st, 7 + i as i32, v, v != 0);
                }
                let usage = a.int("ram_usage", 0);
                int_or_null(st, 9, usage, usage > 0 && usage <= 100);
                t(10, "checksum");
            }
            OSINFO => {
                const KEYS: [&str; 17] = [
                    "scan_time", "hostname", "architecture", "os_name", "os_version", "os_codename", "os_major", "os_minor", "os_patch", "os_build",
                    "os_platform", "sysname", "release", "version", "os_release", "os_display_version", "checksum",
                ];
                texts(st, 2, a, &KEYS);
                // the reference: SHA-1 of the fields that identify the OS release
                use sha1::{Digest, Sha1};
                let mut c = Sha1::new();
                for k in &KEYS[2..15] {
                    c.update(a.s(k).unwrap_or_default());
                }
                st.bind_text(19, Some(&hex(&c.finalize())));
            }
            USERS => {
                texts(st, 2, a, &["scan_time", "user_name", "user_full_name", "user_home"]);
                let uid = a.long("user_id", -1);
                long_or_null(st, 6, uid, uid >= 0);
                st.bind_int64(7, a.long("user_uid_signed", 0));
                texts(st, 8, a, &["user_uuid", "user_groups"]);
                let gid = a.long("user_group_id", -1);
                long_or_null(st, 10, gid, gid >= 0);
                st.bind_int64(11, a.long("user_group_id_signed", 0));
                positive_real(st, 12, a.real("user_created", 0.0));
                texts(st, 13, a, &["user_roles", "user_shell", "user_type"]);
                st.bind_int(16, a.int("user_is_hidden", -1));
                st.bind_int(17, a.int("user_is_remote", -1));
                let last = a.long("user_last_login", 0);
                long_or_null(st, 18, last, last > 0);
                let failed = a.long("user_auth_failed_count", -1);
                long_or_null(st, 19, failed, failed >= 0);
                positive_real(st, 20, a.real("user_auth_failed_timestamp", 0.0));
                positive_real(st, 21, a.real("user_password_last_change", 0.0));
                let exp = a.int("user_password_expiration_date", 0);
                int_or_null(st, 22, exp, exp > 0);
                t(23, "user_password_hash_algorithm");
                for (i, k) in ["user_password_inactive_days", "user_password_max_days_between_changes", "user_password_min_days_between_changes"].iter().enumerate() {
                    let v = a.int(k, -1);
                    int_or_null(st, 24 + i as i32, v, v >= 0);
                }
                t(27, "user_password_status");
                let warn = a.int("user_password_warning_days_before_expiration", -1);
                int_or_null(st, 28, warn, warn >= 0);
                let ppid = a.long("process_pid", -1);
                long_or_null(st, 29, ppid, ppid >= 0);
                t(30, "host_ip");
                st.bind_int(31, a.int("login_status", -1));
                texts(st, 32, a, &["login_type", "login_tty", "checksum"]);
            }
            GROUPS => {
                t(2, "scan_time");
                let gid = a.long("group_id", -1);
                long_or_null(st, 3, gid, gid >= 0);
                texts(st, 4, a, &["group_name", "group_description"]);
                st.bind_int64(6, a.long("group_id_signed", 0));
                t(7, "group_uuid");
                st.bind_int(8, a.int("group_is_hidden", -1));
                texts(st, 9, a, &["group_users", "checksum"]);
            }
            BROWSER_EXTENSIONS => {
                texts(
                    st,
                    2,
                    a,
                    &[
                        "scan_time", "browser_name", "user_id", "package_name", "package_id", "package_version", "package_description", "package_vendor",
                        "package_build_version", "package_path", "browser_profile_name", "browser_profile_path", "package_reference", "package_permissions",
                        "package_type",
                    ],
                );
                for (i, k) in ["package_enabled", "package_visible", "package_autoupdate", "package_persistent", "package_from_webstore", "browser_profile_referenced"]
                    .iter()
                    .enumerate()
                {
                    st.bind_int(17 + i as i32, a.int(k, -1));
                }
                texts(st, 23, a, &["package_installed", "file_hash_sha256", "checksum", "item_id"]);
            }
            _ => {
                texts(
                    st,
                    2,
                    a,
                    &[
                        "scan_time", "service_id", "service_name", "service_description", "service_type", "service_state", "service_sub_state", "service_enabled",
                        "service_start_type", "service_restart",
                    ],
                );
                let freq = a.long("service_frequency", -1);
                long_or_null(st, 12, freq, freq >= 0);
                st.bind_int(13, a.int("service_starts_on_mount", -1));
                texts(st, 14, a, &["service_starts_on_path_modified", "service_starts_on_not_empty_directory"]);
                st.bind_int(16, a.int("service_inetd_compatibility", -1));
                let ppid = a.long("process_pid", -1);
                long_or_null(st, 17, ppid, ppid >= 0);
                texts(
                    st,
                    18,
                    a,
                    &[
                        "process_executable", "process_args", "process_user_name", "process_group_name", "process_working_directory", "process_root_directory",
                        "file_path", "service_address", "log_file_path", "error_log_file_path",
                    ],
                );
                for (i, k) in ["service_exit_code", "service_win32_exit_code"].iter().enumerate() {
                    let v = a.int(k, 0);
                    int_or_null(st, 28 + i as i32, v, v >= 0);
                }
                texts(st, 30, a, &["service_following", "service_object_path"]);
                let eph = a.long("service_target_ephemeral_id", -1);
                long_or_null(st, 32, eph, eph >= 0);
                texts(st, 33, a, &["service_target_type", "service_target_address", "checksum", "item_id"]);
            }
        }
    }
}
