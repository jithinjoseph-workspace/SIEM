//! Syscollector inventory tables (wazuh_db/wdb_syscollector.c): the legacy
//! save/delete functions used by the old agent protocol and the `save2`
//! (dbsync) entry points.

use siem_cjson::Json;
use siem_sqlite::Stmt;

use super::integrity::d2long;
use super::*;

type S = Option<B>;

/// Text binding of an optional string.
fn t(st: &Stmt, i: i32, v: &S) {
    st.bind_text(i, v.as_deref());
}

/// `checksum && strcmp("legacy", checksum)`
fn not_legacy(checksum: &S) -> bool {
    checksum.as_deref().is_some_and(|c| c != SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE.as_bytes())
}

/// `wdbi_strings_hash`: SHA-1 of the concatenated strings, in hex.
pub fn strings_hash(parts: &[&[u8]]) -> B {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    for p in parts {
        h.update(cstr(p));
    }
    super::integrity::sha1_hex(&h.finalize())
}

#[derive(Debug, Default, Clone)]
pub struct Netinfo {
    pub scan_id: S,
    pub scan_time: S,
    pub name: S,
    pub adapter: S,
    pub type_: S,
    pub state: S,
    pub mtu: i64,
    pub mac: S,
    pub tx_packets: i64,
    pub rx_packets: i64,
    pub tx_bytes: i64,
    pub rx_bytes: i64,
    pub tx_errors: i64,
    pub rx_errors: i64,
    pub tx_dropped: i64,
    pub rx_dropped: i64,
    pub checksum: S,
    pub item_id: S,
}

#[derive(Debug, Default, Clone)]
pub struct Netproto {
    pub scan_id: S,
    pub iface: S,
    pub type_: i32,
    pub gateway: S,
    pub dhcp: S,
    pub metric: i32,
    pub checksum: S,
    pub item_id: S,
}

#[derive(Debug, Default, Clone)]
pub struct Netaddr {
    pub scan_id: S,
    pub iface: S,
    pub proto: i32,
    pub address: S,
    pub netmask: S,
    pub broadcast: S,
    pub checksum: S,
    pub item_id: S,
}

#[derive(Debug, Default, Clone)]
pub struct Osinfo {
    pub scan_id: S,
    pub scan_time: S,
    pub hostname: S,
    pub architecture: S,
    pub os_name: S,
    pub os_version: S,
    pub os_codename: S,
    pub os_major: S,
    pub os_minor: S,
    pub os_patch: S,
    pub os_build: S,
    pub os_platform: S,
    pub sysname: S,
    pub release: S,
    pub version: S,
    pub os_release: S,
    pub os_display_version: S,
    pub checksum: S,
}

#[derive(Debug, Default, Clone)]
pub struct Package {
    pub scan_id: S,
    pub scan_time: S,
    pub format: S,
    pub name: S,
    pub priority: S,
    pub section: S,
    pub size: i64,
    pub vendor: S,
    pub install_time: S,
    pub version: S,
    pub architecture: S,
    pub multiarch: S,
    pub source: S,
    pub description: S,
    pub location: S,
    pub checksum: S,
    pub item_id: S,
}

#[derive(Debug, Default, Clone)]
pub struct Hardware {
    pub scan_id: S,
    pub scan_time: S,
    pub serial: S,
    pub cpu_name: S,
    pub cpu_cores: i32,
    pub cpu_mhz: f64,
    /// `uint64_t` in the C (a negative value is a huge positive one)
    pub ram_total: u64,
    pub ram_free: u64,
    pub ram_usage: i32,
    pub checksum: S,
}

#[derive(Debug, Default, Clone)]
pub struct Port {
    pub scan_id: S,
    pub scan_time: S,
    pub protocol: S,
    pub local_ip: S,
    pub local_port: i32,
    pub remote_ip: S,
    pub remote_port: i32,
    pub tx_queue: i32,
    pub rx_queue: i32,
    pub inode: i64,
    pub state: S,
    pub pid: i32,
    pub process: S,
    pub checksum: S,
    pub item_id: S,
}

#[derive(Debug, Default, Clone)]
pub struct Process {
    pub scan_id: S,
    pub scan_time: S,
    pub pid: i32,
    pub name: S,
    pub state: S,
    pub ppid: i32,
    pub utime: i32,
    pub stime: i32,
    pub cmd: S,
    pub argvs: S,
    pub euser: S,
    pub ruser: S,
    pub suser: S,
    pub egroup: S,
    pub rgroup: S,
    pub sgroup: S,
    pub fgroup: S,
    pub priority: i32,
    pub nice: i32,
    pub size: i32,
    pub vm_size: i32,
    pub resident: i32,
    pub share: i32,
    pub start_time: i64,
    pub pgrp: i32,
    pub session: i32,
    pub nlwp: i32,
    pub tgid: i32,
    pub tty: i32,
    pub processor: i32,
    pub checksum: S,
}

/// `user_record_t`
#[derive(Debug, Default, Clone)]
pub struct User {
    pub scan_id: S,
    pub scan_time: S,
    pub user_name: S,
    pub user_full_name: S,
    pub user_home: S,
    pub user_id: i64,
    pub user_uid_signed: i64,
    pub user_uuid: S,
    pub user_groups: S,
    pub user_group_id: i64,
    pub user_group_id_signed: i64,
    pub user_created: f64,
    pub user_roles: S,
    pub user_shell: S,
    pub user_type: S,
    pub user_is_hidden: i32,
    pub user_is_remote: i32,
    pub user_last_login: i64,
    pub user_auth_failed_count: i64,
    pub user_auth_failed_timestamp: f64,
    pub user_password_last_change: f64,
    pub user_password_expiration_date: i32,
    pub user_password_hash_algorithm: S,
    pub user_password_inactive_days: i32,
    pub user_password_max_days_between_changes: i32,
    pub user_password_min_days_between_changes: i32,
    pub user_password_status: S,
    pub user_password_warning_days_before_expiration: i32,
    pub process_pid: i64,
    pub host_ip: S,
    pub login_status: i32,
    pub login_type: S,
    pub login_tty: S,
    pub checksum: S,
}

#[derive(Debug, Default, Clone)]
pub struct Group {
    pub scan_id: S,
    pub scan_time: S,
    pub group_id: i64,
    pub group_name: S,
    pub group_description: S,
    pub group_id_signed: i64,
    pub group_uuid: S,
    pub group_is_hidden: i32,
    pub group_users: S,
    pub checksum: S,
}

/// `browser_extension_record_t`
#[derive(Debug, Default, Clone)]
pub struct BrowserExtension {
    pub scan_id: S,
    pub scan_time: S,
    pub browser_name: S,
    pub user_id: S,
    pub package_name: S,
    pub package_id: S,
    pub package_version: S,
    pub package_description: S,
    pub package_vendor: S,
    pub package_build_version: S,
    pub package_path: S,
    pub browser_profile_name: S,
    pub browser_profile_path: S,
    pub package_reference: S,
    pub package_permissions: S,
    pub package_type: S,
    pub package_enabled: i32,
    pub package_visible: i32,
    pub package_autoupdate: i32,
    pub package_persistent: i32,
    pub package_from_webstore: i32,
    pub browser_profile_referenced: i32,
    pub package_installed: S,
    pub file_hash_sha256: S,
    pub checksum: S,
    pub item_id: S,
}

/// `service_record_t`
#[derive(Debug, Default, Clone)]
pub struct Service {
    pub scan_id: S,
    pub scan_time: S,
    pub service_id: S,
    pub service_name: S,
    pub service_description: S,
    pub service_type: S,
    pub service_state: S,
    pub service_sub_state: S,
    pub service_enabled: S,
    pub service_start_type: S,
    pub service_restart: S,
    pub service_frequency: i64,
    pub service_starts_on_mount: i32,
    pub service_starts_on_path_modified: S,
    pub service_starts_on_not_empty_directory: S,
    pub service_inetd_compatibility: i32,
    pub process_pid: i64,
    pub process_executable: S,
    pub process_args: S,
    pub process_user_name: S,
    pub process_group_name: S,
    pub process_working_directory: S,
    pub process_root_directory: S,
    pub file_path: S,
    pub service_address: S,
    pub log_file_path: S,
    pub error_log_file_path: S,
    pub service_exit_code: i32,
    pub service_win32_exit_code: i32,
    pub service_following: S,
    pub service_object_path: S,
    pub service_target_ephemeral_id: i64,
    pub service_target_type: S,
    pub service_target_address: S,
    pub checksum: S,
    pub item_id: S,
}

fn i64_or_null(st: &Stmt, i: i32, v: i64, cond: bool) {
    if cond {
        st.bind_int64(i, v);
    } else {
        st.bind_null(i);
    }
}

fn i32_or_null(st: &Stmt, i: i32, v: i32, cond: bool) {
    if cond {
        st.bind_int(i, v);
    } else {
        st.bind_null(i);
    }
}

fn empty(v: &S) -> bool {
    v.as_deref().is_none_or(|s| s.is_empty())
}

impl Wdbd {
    fn begin_or(&self, wdb: &mut Wdb, func: &str) -> bool {
        if !wdb.transaction && self.begin2(wdb) < 0 {
            self.mdebug1(&msg!("at ", func, "(): cannot begin transaction"));
            return false;
        }
        true
    }

    fn cache_or(&self, wdb: &mut Wdb, idx: usize, func: &str) -> Option<std::sync::Arc<Stmt>> {
        if self.stmt_cache(wdb, idx) < 0 {
            self.mdebug1(&msg!("at ", func, "(): cannot cache statement"));
            return None;
        }
        Some(wdb.st(idx))
    }

    /// The DONE / CONSTRAINT("UNIQUE...") / error result of the inserts
    /// that tolerate duplicates.
    fn step_unique(&self, wdb: &Wdb, st: &Stmt) -> i32 {
        match self.step(st) {
            SQLITE_DONE => OS_SUCCESS,
            SQLITE_CONSTRAINT => {
                let e = wdb.errmsg();
                if e.starts_with(b"UNIQUE") {
                    self.mdebug1(&msg!("SQLite: ", e));
                    OS_SUCCESS
                } else {
                    self.merror(&msg!("SQLite: ", e));
                    OS_INVALID
                }
            }
            _ => {
                self.merror(&msg!("SQLite: ", wdb.errmsg()));
                OS_INVALID
            }
        }
    }

    fn step_done(&self, wdb: &Wdb, st: &Stmt) -> i32 {
        if self.step(st) == SQLITE_DONE {
            OS_SUCCESS
        } else {
            self.merror(&msg!("SQLite: ", wdb.errmsg()));
            OS_INVALID
        }
    }

    /// `wdb_netinfo_save`
    pub fn netinfo_save(&self, wdb: &mut Wdb, r: &Netinfo, replace: bool) -> i32 {
        if !self.begin_or(wdb, "wdb_netinfo_save") {
            return OS_INVALID;
        }
        if self.netinfo_insert(wdb, r, replace) < 0 {
            return OS_INVALID;
        }
        OS_SUCCESS
    }

    /// `wdb_netinfo_insert`
    pub fn netinfo_insert(&self, wdb: &mut Wdb, r: &Netinfo, replace: bool) -> i32 {
        if r.name.is_none() && not_legacy(&r.checksum) {
            self.wdbi_remove_by_pk(wdb, WDB_SYSCOLLECTOR_NETINFO, r.item_id.as_deref());
        }
        let idx = if replace { WDB_STMT_NETINFO_INSERT2 } else { WDB_STMT_NETINFO_INSERT };
        let Some(st) = self.cache_or(wdb, idx, "wdb_netinfo_insert") else {
            return OS_INVALID;
        };
        t(&st, 1, &r.scan_id);
        t(&st, 2, &r.scan_time);
        t(&st, 3, &r.name);
        t(&st, 4, &r.adapter);
        t(&st, 5, &r.type_);
        t(&st, 6, &r.state);
        i64_or_null(&st, 7, r.mtu, r.mtu > 0);
        t(&st, 8, &r.mac);
        for (i, v) in [r.tx_packets, r.rx_packets, r.tx_bytes, r.rx_bytes, r.tx_errors, r.rx_errors, r.tx_dropped, r.rx_dropped]
            .into_iter()
            .enumerate()
        {
            i64_or_null(&st, 9 + i as i32, v, v >= 0);
        }
        t(&st, 17, &r.checksum);
        t(&st, 18, &r.item_id);
        self.step_unique(wdb, &st)
    }

    /// `wdb_netproto_save`
    pub fn netproto_save(&self, wdb: &mut Wdb, r: &Netproto, replace: bool) -> i32 {
        if !self.begin_or(wdb, "wdb_netproto_save") {
            return OS_INVALID;
        }
        if self.netproto_insert(wdb, r, replace) < 0 {
            return OS_INVALID;
        }
        OS_SUCCESS
    }

    /// `wdb_netproto_insert`
    pub fn netproto_insert(&self, wdb: &mut Wdb, r: &Netproto, replace: bool) -> i32 {
        if r.iface.is_none() && not_legacy(&r.checksum) {
            self.wdbi_remove_by_pk(wdb, WDB_SYSCOLLECTOR_NETPROTO, r.item_id.as_deref());
        }
        let idx = if replace { WDB_STMT_PROTO_INSERT2 } else { WDB_STMT_PROTO_INSERT };
        let Some(st) = self.cache_or(wdb, idx, "wdb_netproto_insert") else {
            return OS_INVALID;
        };
        t(&st, 1, &r.scan_id);
        t(&st, 2, &r.iface);
        st.bind_text(3, Some(if r.type_ == WDB_NETADDR_IPV4 { b"ipv4" } else { b"ipv6" }));
        t(&st, 4, &r.gateway);
        t(&st, 5, &r.dhcp);
        i64_or_null(&st, 6, r.metric as i64, r.metric >= 0);
        t(&st, 7, &r.checksum);
        t(&st, 8, &r.item_id);
        self.step_unique(wdb, &st)
    }

    /// `wdb_netaddr_save`
    pub fn netaddr_save(&self, wdb: &mut Wdb, r: &Netaddr, replace: bool) -> i32 {
        if !self.begin_or(wdb, "wdb_netaddr_save") {
            return -1;
        }
        if self.netaddr_insert(wdb, r, replace) < 0 {
            return -1;
        }
        0
    }

    /// `wdb_netaddr_insert`
    pub fn netaddr_insert(&self, wdb: &mut Wdb, r: &Netaddr, replace: bool) -> i32 {
        if (r.iface.is_none() || r.address.is_none()) && not_legacy(&r.checksum) {
            self.wdbi_remove_by_pk(wdb, WDB_SYSCOLLECTOR_NETADDRESS, r.item_id.as_deref());
        }
        let idx = if replace { WDB_STMT_ADDR_INSERT2 } else { WDB_STMT_ADDR_INSERT };
        let Some(st) = self.cache_or(wdb, idx, "wdb_netaddr_insert") else {
            return OS_INVALID;
        };
        t(&st, 1, &r.scan_id);
        t(&st, 2, &r.iface);
        st.bind_text(3, Some(if r.proto == WDB_NETADDR_IPV4 { b"ipv4" } else { b"ipv6" }));
        t(&st, 4, &r.address);
        t(&st, 5, &r.netmask);
        t(&st, 6, &r.broadcast);
        t(&st, 7, &r.checksum);
        t(&st, 8, &r.item_id);
        self.step_done(wdb, &st)
    }

    /// A `DELETE ... WHERE scan_id != ?` of the legacy deletes.
    fn scan_delete(&self, wdb: &mut Wdb, idx: usize, func: &str, table: &str, scan_id: Option<&[u8]>) -> i32 {
        let Some(st) = self.cache_or(wdb, idx, func) else {
            return -1;
        };
        st.bind_text(1, scan_id);
        if self.step(&st) != SQLITE_DONE {
            self.merror(&msg!("Deleting old information from '", table, "' table: ", wdb.errmsg()));
            return -1;
        }
        0
    }

    /// `wdb_netinfo_delete`
    pub fn netinfo_delete(&self, wdb: &mut Wdb, scan_id: Option<&[u8]>) -> i32 {
        if !self.begin_or(wdb, "wdb_netinfo_delete") {
            return -1;
        }
        if self.scan_delete(wdb, WDB_STMT_NETINFO_DEL, "wdb_netinfo_delete", "sys_netiface", scan_id) < 0
            || self.scan_delete(wdb, WDB_STMT_PROTO_DEL, "wdb_netinfo_delete", "sys_netproto", scan_id) < 0
            || self.scan_delete(wdb, WDB_STMT_ADDR_DEL, "wdb_netinfo_delete", "sys_netaddr", scan_id) < 0
        {
            return -1;
        }
        0
    }

    /// `wdb_hotfix_delete`
    pub fn hotfix_delete(&self, wdb: &mut Wdb, scan_id: Option<&[u8]>) -> i32 {
        if !self.begin_or(wdb, "wdb_hotfix_delete") {
            return -1;
        }
        self.scan_delete(wdb, WDB_STMT_HOTFIX_DEL, "wdb_hotfix_delete", "sys_hotfixes", scan_id)
    }

    /// `wdb_osinfo_save`
    pub fn osinfo_save(&self, wdb: &mut Wdb, r: &Osinfo, replace: bool) -> i32 {
        if !self.begin_or(wdb, "wdb_osinfo_save") {
            return -1;
        }
        if self.stmt_cache(wdb, WDB_STMT_OSINFO_DEL) < 0 {
            self.mdebug1(&msg!("at wdb_osinfo_save(): cannot cache statement (", WDB_STMT_OSINFO_DEL, ")"));
            return -1;
        }
        let del = wdb.st(WDB_STMT_OSINFO_DEL);
        if self.step(&del) != SQLITE_DONE {
            self.merror(&msg!("Deleting old information from 'sys_osinfo' table: ", wdb.errmsg()));
            return -1;
        }
        let e = |v: &S| v.clone().unwrap_or_default();
        let hexdigest = strings_hash(&[
            &e(&r.architecture),
            &e(&r.os_name),
            &e(&r.os_version),
            &e(&r.os_codename),
            &e(&r.os_major),
            &e(&r.os_minor),
            &e(&r.os_patch),
            &e(&r.os_build),
            &e(&r.os_platform),
            &e(&r.sysname),
            &e(&r.release),
            &e(&r.version),
            &e(&r.os_release),
        ]);
        if self.osinfo_insert(wdb, r, replace, &hexdigest) < 0 {
            return -1;
        }
        0
    }

    /// `wdb_osinfo_insert`
    pub fn osinfo_insert(&self, wdb: &mut Wdb, r: &Osinfo, replace: bool, hexdigest: &[u8]) -> i32 {
        let idx = if replace { WDB_STMT_OSINFO_INSERT2 } else { WDB_STMT_OSINFO_INSERT };
        let Some(st) = self.cache_or(wdb, idx, "wdb_osinfo_insert") else {
            return OS_INVALID;
        };
        let fields = [
            &r.scan_id,
            &r.scan_time,
            &r.hostname,
            &r.architecture,
            &r.os_name,
            &r.os_version,
            &r.os_codename,
            &r.os_major,
            &r.os_minor,
            &r.os_patch,
            &r.os_build,
            &r.os_platform,
            &r.sysname,
            &r.release,
            &r.version,
            &r.os_release,
            &r.os_display_version,
            &r.checksum,
        ];
        for (i, v) in fields.into_iter().enumerate() {
            t(&st, i as i32 + 1, v);
        }
        st.bind_text(19, Some(hexdigest));
        self.step_done(wdb, &st)
    }

    /// `wdb_package_save`
    pub fn package_save(&self, wdb: &mut Wdb, r: &Package, replace: bool) -> i32 {
        if !self.begin_or(wdb, "wdb_package_save") {
            return -1;
        }
        if self.package_insert(wdb, r, replace) < 0 {
            return -1;
        }
        0
    }

    /// `wdb_hotfix_save`
    pub fn hotfix_save(&self, wdb: &mut Wdb, scan_id: &S, scan_time: &S, hotfix: &S, checksum: &S, replace: bool) -> i32 {
        if !self.begin_or(wdb, "wdb_hotfix_save") {
            return -1;
        }
        if self.hotfix_insert(wdb, scan_id, scan_time, hotfix, checksum, replace) < 0 {
            return -1;
        }
        0
    }

    /// `wdb_package_insert`
    pub fn package_insert(&self, wdb: &mut Wdb, r: &Package, replace: bool) -> i32 {
        if (r.name.is_none() || r.version.is_none() || r.architecture.is_none()) && not_legacy(&r.checksum) {
            self.wdbi_remove_by_pk(wdb, WDB_SYSCOLLECTOR_PACKAGES, r.item_id.as_deref());
        }
        let idx = if replace { WDB_STMT_PROGRAM_INSERT2 } else { WDB_STMT_PROGRAM_INSERT };
        let Some(st) = self.cache_or(wdb, idx, "wdb_package_insert") else {
            return OS_INVALID;
        };
        t(&st, 1, &r.scan_id);
        t(&st, 2, &r.scan_time);
        st.bind_text(3, Some(r.format.as_deref().unwrap_or(b"")));
        t(&st, 4, &r.name);
        t(&st, 5, &r.priority);
        t(&st, 6, &r.section);
        i64_or_null(&st, 7, r.size, r.size >= 0);
        t(&st, 8, &r.vendor);
        t(&st, 9, &r.install_time);
        t(&st, 10, &r.version);
        t(&st, 11, &r.architecture);
        t(&st, 12, &r.multiarch);
        t(&st, 13, &r.source);
        t(&st, 14, &r.description);
        st.bind_text(15, Some(r.location.as_deref().unwrap_or(b"")));
        t(&st, 16, &r.checksum);
        t(&st, 17, &r.item_id);
        self.step_unique(wdb, &st)
    }

    /// `wdb_hotfix_insert`
    pub fn hotfix_insert(&self, wdb: &mut Wdb, scan_id: &S, scan_time: &S, hotfix: &S, checksum: &S, replace: bool) -> i32 {
        if hotfix.is_none() {
            return OS_INVALID;
        }
        let idx = if replace { WDB_STMT_HOTFIX_INSERT2 } else { WDB_STMT_HOTFIX_INSERT };
        let Some(st) = self.cache_or(wdb, idx, "wdb_hotfix_insert") else {
            return OS_INVALID;
        };
        t(&st, 1, scan_id);
        t(&st, 2, scan_time);
        t(&st, 3, hotfix);
        t(&st, 4, checksum);
        self.step_done(wdb, &st)
    }

    /// `wdb_package_update`
    pub fn package_update(&self, wdb: &mut Wdb, scan_id: Option<&[u8]>) -> i32 {
        if !wdb.transaction && self.begin2(wdb) < 0 {
            self.mdebug1(b"at wdb_package_update(): cannot begin transaction");
            return -1;
        }
        if self.stmt_cache(wdb, WDB_STMT_PROGRAM_GET) < 0 {
            self.mdebug1(b"at wdb_package_update(): cannot cache get statement");
            return -1;
        }
        let get = wdb.st(WDB_STMT_PROGRAM_GET);
        get.bind_text(1, scan_id);
        let mut result;
        loop {
            result = self.step(&get);
            if result != SQLITE_ROW {
                break;
            }
            let vals: Vec<S> = (0..7).map(|i| get.column_text(i)).collect();
            if self.stmt_cache(wdb, WDB_STMT_PROGRAM_UPD) < 0 {
                self.mdebug1(b"at wdb_package_update(): cannot cache update statement");
                return -1;
            }
            let upd = wdb.st(WDB_STMT_PROGRAM_UPD);
            t(&upd, 1, &vals[0]);
            t(&upd, 2, &vals[1]);
            upd.bind_text(3, scan_id);
            t(&upd, 4, &vals[2]);
            t(&upd, 5, &vals[3]);
            t(&upd, 6, &vals[4]);
            t(&upd, 7, &vals[5]);
            t(&upd, 8, &vals[6]);
            if self.step(&upd) != SQLITE_DONE {
                self.merror(&msg!("Unable to update the 'sys_programs' table: ", wdb.errmsg()));
                return -1;
            }
        }
        if result != SQLITE_DONE {
            self.merror(&msg!("Unable to update the 'sys_programs' table: ", wdb.errmsg()));
            return -1;
        }
        0
    }

    /// `wdb_package_delete`
    pub fn package_delete(&self, wdb: &mut Wdb, scan_id: Option<&[u8]>) -> i32 {
        if !self.begin_or(wdb, "wdb_package_delete") {
            return -1;
        }
        self.scan_delete(wdb, WDB_STMT_PROGRAM_DEL, "wdb_package_delete", "sys_programs", scan_id)
    }

    /// `wdb_hardware_save`
    pub fn hardware_save(&self, wdb: &mut Wdb, r: &Hardware, replace: bool) -> i32 {
        if !self.begin_or(wdb, "wdb_hardware_save") {
            return -1;
        }
        let Some(del) = self.cache_or(wdb, WDB_STMT_HWINFO_DEL, "wdb_hardware_save") else {
            return -1;
        };
        if self.step(&del) != SQLITE_DONE {
            self.merror(&msg!("Deleting old information from 'sys_hwinfo' table: ", wdb.errmsg()));
            return -1;
        }
        if self.hardware_insert(wdb, r, replace) < 0 {
            return -1;
        }
        0
    }

    /// `wdb_hardware_insert`
    pub fn hardware_insert(&self, wdb: &mut Wdb, r: &Hardware, replace: bool) -> i32 {
        let idx = if replace { WDB_STMT_HWINFO_INSERT2 } else { WDB_STMT_HWINFO_INSERT };
        let Some(st) = self.cache_or(wdb, idx, "wdb_hardware_insert") else {
            return OS_INVALID;
        };
        t(&st, 1, &r.scan_id);
        t(&st, 2, &r.scan_time);
        t(&st, 3, &r.serial);
        t(&st, 4, &r.cpu_name);
        i32_or_null(&st, 5, r.cpu_cores, r.cpu_cores > 0);
        if r.cpu_mhz > 0.0 {
            st.bind_double(6, r.cpu_mhz);
        } else {
            st.bind_null(6);
        }
        i64_or_null(&st, 7, r.ram_total as i64, r.ram_total > 0);
        i64_or_null(&st, 8, r.ram_free as i64, r.ram_free > 0);
        i32_or_null(&st, 9, r.ram_usage, r.ram_usage > 0 && r.ram_usage <= 100);
        t(&st, 10, &r.checksum);
        self.step_done(wdb, &st)
    }

    /// `wdb_port_save`
    pub fn port_save(&self, wdb: &mut Wdb, r: &Port, replace: bool) -> i32 {
        if !self.begin_or(wdb, "wdb_port_save") {
            return -1;
        }
        if self.port_insert(wdb, r, replace) < 0 {
            return -1;
        }
        0
    }

    /// `wdb_port_insert`
    pub fn port_insert(&self, wdb: &mut Wdb, r: &Port, replace: bool) -> i32 {
        if (r.protocol.is_none() || r.local_ip.is_none() || r.local_port < 0 || r.inode < 0) && not_legacy(&r.checksum) {
            self.wdbi_remove_by_pk(wdb, WDB_SYSCOLLECTOR_PORTS, r.item_id.as_deref());
        }
        let idx = if replace { WDB_STMT_PORT_INSERT2 } else { WDB_STMT_PORT_INSERT };
        let Some(st) = self.cache_or(wdb, idx, "wdb_port_insert") else {
            return OS_INVALID;
        };
        t(&st, 1, &r.scan_id);
        t(&st, 2, &r.scan_time);
        t(&st, 3, &r.protocol);
        t(&st, 4, &r.local_ip);
        i32_or_null(&st, 5, r.local_port, r.local_port >= 0);
        t(&st, 6, &r.remote_ip);
        i32_or_null(&st, 7, r.remote_port, r.remote_port >= 0);
        i32_or_null(&st, 8, r.tx_queue, r.tx_queue >= 0);
        i32_or_null(&st, 9, r.rx_queue, r.rx_queue >= 0);
        i64_or_null(&st, 10, r.inode, r.inode >= 0);
        t(&st, 11, &r.state);
        i32_or_null(&st, 12, r.pid, r.pid >= 0);
        t(&st, 13, &r.process);
        t(&st, 14, &r.checksum);
        t(&st, 15, &r.item_id);
        self.step_done(wdb, &st)
    }

    /// `wdb_port_delete`
    pub fn port_delete(&self, wdb: &mut Wdb, scan_id: Option<&[u8]>) -> i32 {
        if !self.begin_or(wdb, "wdb_port_delete") {
            return -1;
        }
        self.scan_delete(wdb, WDB_STMT_PORT_DEL, "wdb_port_delete", "sys_ports", scan_id)
    }

    /// `wdb_process_save`
    pub fn process_save(&self, wdb: &mut Wdb, r: &Process, replace: bool) -> i32 {
        if !self.begin_or(wdb, "wdb_process_save") {
            return -1;
        }
        if self.process_insert(wdb, r, replace) < 0 {
            return -1;
        }
        0
    }

    /// `wdb_process_insert`
    pub fn process_insert(&self, wdb: &mut Wdb, r: &Process, replace: bool) -> i32 {
        if r.pid < 0 {
            return OS_INVALID;
        }
        let idx = if replace { WDB_STMT_PROC_INSERT2 } else { WDB_STMT_PROC_INSERT };
        let Some(st) = self.cache_or(wdb, idx, "wdb_process_insert") else {
            return OS_INVALID;
        };
        t(&st, 1, &r.scan_id);
        t(&st, 2, &r.scan_time);
        i32_or_null(&st, 3, r.pid, r.pid >= 0);
        t(&st, 4, &r.name);
        t(&st, 5, &r.state);
        i32_or_null(&st, 6, r.ppid, r.ppid >= 0);
        i32_or_null(&st, 7, r.utime, r.utime >= 0);
        i32_or_null(&st, 8, r.stime, r.stime >= 0);
        for (i, v) in [&r.cmd, &r.argvs, &r.euser, &r.ruser, &r.suser, &r.egroup, &r.rgroup, &r.sgroup, &r.fgroup].into_iter().enumerate() {
            t(&st, 9 + i as i32, v);
        }
        i32_or_null(&st, 18, r.priority, r.priority >= 0);
        st.bind_int(19, r.nice);
        i32_or_null(&st, 20, r.size, r.size >= 0);
        i32_or_null(&st, 21, r.vm_size, r.vm_size >= 0);
        i32_or_null(&st, 22, r.resident, r.resident >= 0);
        i32_or_null(&st, 23, r.share, r.share >= 0);
        i64_or_null(&st, 24, r.start_time, r.start_time >= 0);
        i32_or_null(&st, 25, r.pgrp, r.pgrp >= 0);
        i32_or_null(&st, 26, r.session, r.session >= 0);
        i32_or_null(&st, 27, r.nlwp, r.nlwp >= 0);
        i32_or_null(&st, 28, r.tgid, r.tgid >= 0);
        i32_or_null(&st, 29, r.tty, r.tty >= 0);
        i32_or_null(&st, 30, r.processor, r.processor >= 0);
        t(&st, 31, &r.checksum);
        self.step_done(wdb, &st)
    }

    /// `wdb_process_delete`
    pub fn process_delete(&self, wdb: &mut Wdb, scan_id: Option<&[u8]>) -> i32 {
        if !self.begin_or(wdb, "wdb_process_delete") {
            return -1;
        }
        self.scan_delete(wdb, WDB_STMT_PROC_DEL, "wdb_process_delete", "sys_processes", scan_id)
    }

    /// `wdb_users_save`
    pub fn users_save(&self, wdb: &mut Wdb, r: &User, replace: bool) -> i32 {
        if !self.begin_or(wdb, "wdb_users_save") {
            return -1;
        }
        if self.users_insert(wdb, r, replace) != 0 {
            return -1;
        }
        0
    }

    /// `wdb_users_insert`
    pub fn users_insert(&self, wdb: &mut Wdb, r: &User, replace: bool) -> i32 {
        if empty(&r.user_name) {
            return OS_INVALID;
        }
        let idx = if replace { WDB_STMT_USER_INSERT2 } else { WDB_STMT_USER_INSERT };
        let Some(st) = self.cache_or(wdb, idx, "wdb_users_insert") else {
            return OS_INVALID;
        };
        t(&st, 1, &r.scan_id);
        t(&st, 2, &r.scan_time);
        t(&st, 3, &r.user_name);
        t(&st, 4, &r.user_full_name);
        t(&st, 5, &r.user_home);
        i64_or_null(&st, 6, r.user_id, r.user_id >= 0);
        st.bind_int64(7, r.user_uid_signed);
        t(&st, 8, &r.user_uuid);
        t(&st, 9, &r.user_groups);
        i64_or_null(&st, 10, r.user_group_id, r.user_group_id >= 0);
        st.bind_int64(11, r.user_group_id_signed);
        if r.user_created > 0.0 {
            st.bind_double(12, r.user_created);
        } else {
            st.bind_null(12);
        }
        t(&st, 13, &r.user_roles);
        t(&st, 14, &r.user_shell);
        t(&st, 15, &r.user_type);
        st.bind_int(16, r.user_is_hidden);
        st.bind_int(17, r.user_is_remote);
        i64_or_null(&st, 18, r.user_last_login, r.user_last_login > 0);
        i64_or_null(&st, 19, r.user_auth_failed_count, r.user_auth_failed_count >= 0);
        if r.user_auth_failed_timestamp > 0.0 {
            st.bind_double(20, r.user_auth_failed_timestamp);
        } else {
            st.bind_null(20);
        }
        if r.user_password_last_change > 0.0 {
            st.bind_double(21, r.user_password_last_change);
        } else {
            st.bind_null(21);
        }
        i32_or_null(&st, 22, r.user_password_expiration_date, r.user_password_expiration_date > 0);
        t(&st, 23, &r.user_password_hash_algorithm);
        i32_or_null(&st, 24, r.user_password_inactive_days, r.user_password_inactive_days >= 0);
        i32_or_null(&st, 25, r.user_password_max_days_between_changes, r.user_password_max_days_between_changes >= 0);
        i32_or_null(&st, 26, r.user_password_min_days_between_changes, r.user_password_min_days_between_changes >= 0);
        t(&st, 27, &r.user_password_status);
        i32_or_null(
            &st,
            28,
            r.user_password_warning_days_before_expiration,
            r.user_password_warning_days_before_expiration >= 0,
        );
        i64_or_null(&st, 29, r.process_pid, r.process_pid >= 0);
        t(&st, 30, &r.host_ip);
        st.bind_int(31, r.login_status);
        t(&st, 32, &r.login_type);
        t(&st, 33, &r.login_tty);
        t(&st, 34, &r.checksum);
        self.step_done(wdb, &st)
    }

    /// `wdb_groups_save`
    pub fn groups_save(&self, wdb: &mut Wdb, r: &Group, replace: bool) -> i32 {
        if !self.begin_or(wdb, "wdb_groups_save") {
            return -1;
        }
        if self.groups_insert(wdb, r, replace) != 0 {
            return -1;
        }
        0
    }

    /// `wdb_groups_insert`
    pub fn groups_insert(&self, wdb: &mut Wdb, r: &Group, replace: bool) -> i32 {
        if empty(&r.group_name) {
            return OS_INVALID;
        }
        let idx = if replace { WDB_STMT_GROUP_INSERT2 } else { WDB_STMT_GROUP_INSERT };
        let Some(st) = self.cache_or(wdb, idx, "wdb_groups_insert") else {
            return OS_INVALID;
        };
        t(&st, 1, &r.scan_id);
        t(&st, 2, &r.scan_time);
        i64_or_null(&st, 3, r.group_id, r.group_id >= 0);
        t(&st, 4, &r.group_name);
        t(&st, 5, &r.group_description);
        st.bind_int64(6, r.group_id_signed);
        t(&st, 7, &r.group_uuid);
        st.bind_int(8, r.group_is_hidden);
        t(&st, 9, &r.group_users);
        t(&st, 10, &r.checksum);
        self.step_done(wdb, &st)
    }

    /// `wdb_browser_extensions_save`
    pub fn browser_extensions_save(&self, wdb: &mut Wdb, r: &BrowserExtension, replace: bool) -> i32 {
        if !self.begin_or(wdb, "wdb_browser_extensions_save") {
            return -1;
        }
        if self.browser_extensions_insert(wdb, r, replace) != 0 {
            return -1;
        }
        0
    }

    /// `wdb_browser_extensions_insert`
    pub fn browser_extensions_insert(&self, wdb: &mut Wdb, r: &BrowserExtension, replace: bool) -> i32 {
        if empty(&r.browser_name) || empty(&r.user_id) || empty(&r.browser_profile_path) || empty(&r.package_name) || empty(&r.package_version) {
            return OS_INVALID;
        }
        let idx = if replace { WDB_STMT_BROWSER_EXTENSION_INSERT2 } else { WDB_STMT_BROWSER_EXTENSION_INSERT };
        let Some(st) = self.cache_or(wdb, idx, "wdb_browser_extensions_insert") else {
            return OS_INVALID;
        };
        let texts = [
            &r.scan_id,
            &r.scan_time,
            &r.browser_name,
            &r.user_id,
            &r.package_name,
            &r.package_id,
            &r.package_version,
            &r.package_description,
            &r.package_vendor,
            &r.package_build_version,
            &r.package_path,
            &r.browser_profile_name,
            &r.browser_profile_path,
            &r.package_reference,
            &r.package_permissions,
            &r.package_type,
        ];
        for (i, v) in texts.into_iter().enumerate() {
            t(&st, i as i32 + 1, v);
        }
        st.bind_int(17, r.package_enabled);
        st.bind_int(18, r.package_visible);
        st.bind_int(19, r.package_autoupdate);
        st.bind_int(20, r.package_persistent);
        st.bind_int(21, r.package_from_webstore);
        st.bind_int(22, r.browser_profile_referenced);
        t(&st, 23, &r.package_installed);
        t(&st, 24, &r.file_hash_sha256);
        t(&st, 25, &r.checksum);
        t(&st, 26, &r.item_id);
        self.step_done(wdb, &st)
    }

    /// `wdb_services_save`
    pub fn services_save(&self, wdb: &mut Wdb, r: &Service, replace: bool) -> i32 {
        if !self.begin_or(wdb, "wdb_services_save") {
            return OS_INVALID;
        }
        if self.services_insert(wdb, r, replace) < 0 {
            return OS_INVALID;
        }
        OS_SUCCESS
    }

    /// `wdb_services_insert`
    pub fn services_insert(&self, wdb: &mut Wdb, r: &Service, replace: bool) -> i32 {
        if empty(&r.service_id) || empty(&r.file_path) {
            return OS_INVALID;
        }
        let idx = if replace { WDB_STMT_SERVICE_INSERT2 } else { WDB_STMT_SERVICE_INSERT };
        let Some(st) = self.cache_or(wdb, idx, "wdb_services_insert") else {
            return OS_INVALID;
        };
        let texts1 = [
            &r.scan_id,
            &r.scan_time,
            &r.service_id,
            &r.service_name,
            &r.service_description,
            &r.service_type,
            &r.service_state,
            &r.service_sub_state,
            &r.service_enabled,
            &r.service_start_type,
            &r.service_restart,
        ];
        for (i, v) in texts1.into_iter().enumerate() {
            t(&st, i as i32 + 1, v);
        }
        i64_or_null(&st, 12, r.service_frequency, r.service_frequency >= 0);
        st.bind_int(13, r.service_starts_on_mount);
        t(&st, 14, &r.service_starts_on_path_modified);
        t(&st, 15, &r.service_starts_on_not_empty_directory);
        st.bind_int(16, r.service_inetd_compatibility);
        i64_or_null(&st, 17, r.process_pid, r.process_pid >= 0);
        let texts2 = [
            &r.process_executable,
            &r.process_args,
            &r.process_user_name,
            &r.process_group_name,
            &r.process_working_directory,
            &r.process_root_directory,
            &r.file_path,
            &r.service_address,
            &r.log_file_path,
            &r.error_log_file_path,
        ];
        for (i, v) in texts2.into_iter().enumerate() {
            t(&st, 18 + i as i32, v);
        }
        i32_or_null(&st, 28, r.service_exit_code, r.service_exit_code >= 0);
        i32_or_null(&st, 29, r.service_win32_exit_code, r.service_win32_exit_code >= 0);
        t(&st, 30, &r.service_following);
        t(&st, 31, &r.service_object_path);
        i64_or_null(&st, 32, r.service_target_ephemeral_id, r.service_target_ephemeral_id >= 0);
        t(&st, 33, &r.service_target_type);
        t(&st, 34, &r.service_target_address);
        t(&st, 35, &r.checksum);
        t(&st, 36, &r.item_id);
        self.step_done(wdb, &st)
    }

    /// `wdb_syscollector_save2`
    pub fn syscollector_save2(&self, wdb: &mut Wdb, component: i32, payload: &[u8]) -> i32 {
        let Some(data) = siem_cjson::parse(cstr(payload)) else {
            self.mdebug1(b"at wdb_syscollector_save2(): no payload");
            return -1;
        };
        let Some(a) = data.get("attributes") else {
            self.mdebug1(b"at wdb_syscollector_save2(): no attributes");
            return -1;
        };
        let a = A(a);
        let zero = || Some(b"0".to_vec());
        match component {
            WDB_SYSCOLLECTOR_PROCESSES => {
                let r = Process {
                    scan_id: zero(),
                    scan_time: a.s("scan_time"),
                    pid: a.s("pid").map(|p| strtol(&p) as i32).unwrap_or(-1),
                    name: a.s("name"),
                    state: a.s("state"),
                    ppid: a.vi("ppid", 0),
                    utime: a.vi("utime", 0),
                    stime: a.vi("stime", 0),
                    cmd: a.s("cmd"),
                    argvs: a.s("argvs"),
                    euser: a.s("euser"),
                    ruser: a.s("ruser"),
                    suser: a.s("suser"),
                    egroup: a.s("egroup"),
                    rgroup: a.s("rgroup"),
                    sgroup: a.s("sgroup"),
                    fgroup: a.s("fgroup"),
                    priority: a.vi("priority", 0),
                    nice: a.vi("nice", 0),
                    size: a.vi("size", 0),
                    vm_size: a.vi("vm_size", 0),
                    resident: a.vi("resident", 0),
                    share: a.vi("share", 0),
                    start_time: a.vd_ll("start_time", 0),
                    pgrp: a.vi("pgrp", 0),
                    session: a.vi("session", 0),
                    nlwp: a.vi("nlwp", 0),
                    tgid: a.vi("tgid", 0),
                    tty: a.vi("tty", 0),
                    processor: a.vi("processor", 0),
                    checksum: a.s("checksum"),
                };
                self.process_save(wdb, &r, true)
            }
            WDB_SYSCOLLECTOR_PACKAGES => {
                let r = Package {
                    scan_id: zero(),
                    scan_time: a.s("scan_time"),
                    format: a.s("format"),
                    name: a.s("name"),
                    priority: a.s("priority"),
                    section: a.s("groups"),
                    size: a.vi("size", 0) as i64,
                    vendor: a.s("vendor"),
                    install_time: a.s("install_time"),
                    version: a.s("version"),
                    architecture: a.s("architecture"),
                    multiarch: a.s("multiarch"),
                    source: a.s("source"),
                    description: a.s("description"),
                    location: a.s("location"),
                    checksum: a.s("checksum"),
                    item_id: a.s("item_id"),
                };
                self.package_save(wdb, &r, true)
            }
            WDB_SYSCOLLECTOR_HOTFIXES => {
                self.hotfix_save(wdb, &zero(), &a.s("scan_time"), &a.s("hotfix"), &a.s("checksum"), true)
            }
            WDB_SYSCOLLECTOR_PORTS => {
                let r = Port {
                    scan_id: zero(),
                    scan_time: a.s("scan_time"),
                    protocol: a.s("protocol"),
                    local_ip: a.s("local_ip"),
                    local_port: a.vi("local_port", 0),
                    remote_ip: a.s("remote_ip"),
                    remote_port: a.vi("remote_port", 0),
                    tx_queue: a.vi("tx_queue", 0),
                    rx_queue: a.vi("rx_queue", 0),
                    inode: a.vd_ll("inode", 0),
                    state: a.s("state"),
                    pid: a.vi("pid", 0),
                    process: a.s("process"),
                    checksum: a.s("checksum"),
                    item_id: a.s("item_id"),
                };
                self.port_save(wdb, &r, true)
            }
            WDB_SYSCOLLECTOR_NETPROTO => {
                let type_ = match a.s("type") {
                    Some(t) => (t == b"ipv6") as i32,
                    None => 0,
                };
                let r = Netproto {
                    scan_id: zero(),
                    iface: a.s("iface"),
                    type_,
                    gateway: a.s("gateway"),
                    dhcp: a.s("dhcp"),
                    metric: a.vi("metric", 0),
                    checksum: a.s("checksum"),
                    item_id: a.s("item_id"),
                };
                self.netproto_save(wdb, &r, true)
            }
            WDB_SYSCOLLECTOR_NETADDRESS => {
                let r = Netaddr {
                    scan_id: zero(),
                    iface: a.s("iface"),
                    proto: a.vi("proto", 0),
                    address: a.s("address"),
                    netmask: a.s("netmask"),
                    broadcast: a.s("broadcast"),
                    checksum: a.s("checksum"),
                    item_id: a.s("item_id"),
                };
                self.netaddr_save(wdb, &r, true)
            }
            WDB_SYSCOLLECTOR_NETINFO => {
                let r = Netinfo {
                    scan_id: zero(),
                    scan_time: a.s("scan_time"),
                    name: a.s("name"),
                    adapter: a.s("adapter"),
                    type_: a.s("type"),
                    state: a.s("state"),
                    mtu: a.vd_ll("mtu", 0),
                    mac: a.s("mac"),
                    tx_packets: a.vi("tx_packets", 0) as i64,
                    rx_packets: a.vi("rx_packets", 0) as i64,
                    tx_bytes: a.vi("tx_bytes", 0) as i64,
                    rx_bytes: a.vi("rx_bytes", 0) as i64,
                    tx_errors: a.vi("tx_errors", 0) as i64,
                    rx_errors: a.vi("rx_errors", 0) as i64,
                    tx_dropped: a.vi("tx_dropped", 0) as i64,
                    rx_dropped: a.vi("rx_dropped", 0) as i64,
                    checksum: a.s("checksum"),
                    item_id: a.s("item_id"),
                };
                self.netinfo_save(wdb, &r, true)
            }
            WDB_SYSCOLLECTOR_HWINFO => {
                // ram_* are `long` from valueint, passed as uint64_t;
                // ram_usage is a `long` passed as int
                let r = Hardware {
                    scan_id: zero(),
                    scan_time: a.s("scan_time"),
                    serial: a.s("board_serial"),
                    cpu_name: a.s("cpu_name"),
                    cpu_cores: a.vi("cpu_cores", 0),
                    cpu_mhz: a.vd("cpu_mhz", 0.0),
                    ram_total: a.vi("ram_total", 0) as i64 as u64,
                    ram_free: a.vi("ram_free", 0) as i64 as u64,
                    ram_usage: a.vi("ram_usage", 0),
                    checksum: a.s("checksum"),
                };
                self.hardware_save(wdb, &r, true)
            }
            WDB_SYSCOLLECTOR_OSINFO => {
                let r = Osinfo {
                    scan_id: zero(),
                    scan_time: a.s("scan_time"),
                    hostname: a.s("hostname"),
                    architecture: a.s("architecture"),
                    os_name: a.s("os_name"),
                    os_version: a.s("os_version"),
                    os_codename: a.s("os_codename"),
                    os_major: a.s("os_major"),
                    os_minor: a.s("os_minor"),
                    os_patch: a.s("os_patch"),
                    os_build: a.s("os_build"),
                    os_platform: a.s("os_platform"),
                    sysname: a.s("sysname"),
                    release: a.s("release"),
                    version: a.s("version"),
                    os_release: a.s("os_release"),
                    os_display_version: a.s("os_display_version"),
                    checksum: a.s("checksum"),
                };
                self.osinfo_save(wdb, &r, true)
            }
            WDB_SYSCOLLECTOR_USERS => {
                let r = User {
                    scan_id: zero(),
                    scan_time: a.s("scan_time"),
                    user_name: a.s("user_name"),
                    user_full_name: a.s("user_full_name"),
                    user_home: a.s("user_home"),
                    user_id: a.vd_ll("user_id", -1),
                    user_uid_signed: a.vd_ll("user_uid_signed", 0),
                    user_uuid: a.s("user_uuid"),
                    user_groups: a.s("user_groups"),
                    user_group_id: a.vd_ll("user_group_id", -1),
                    user_group_id_signed: a.vd_ll("user_group_id_signed", 0),
                    user_created: a.vd("user_created", 0.0),
                    user_roles: a.s("user_roles"),
                    user_shell: a.s("user_shell"),
                    user_type: a.s("user_type"),
                    user_is_hidden: a.vi("user_is_hidden", -1),
                    user_is_remote: a.vi("user_is_remote", -1),
                    user_last_login: a.vd_ll("user_last_login", 0),
                    user_auth_failed_count: a.vd_ll("user_auth_failed_count", -1),
                    user_auth_failed_timestamp: a.vd("user_auth_failed_timestamp", 0.0),
                    user_password_last_change: a.vd("user_password_last_change", 0.0),
                    user_password_expiration_date: a.vi("user_password_expiration_date", 0),
                    user_password_hash_algorithm: a.s("user_password_hash_algorithm"),
                    user_password_inactive_days: a.vi("user_password_inactive_days", -1),
                    user_password_max_days_between_changes: a.vi("user_password_max_days_between_changes", -1),
                    user_password_min_days_between_changes: a.vi("user_password_min_days_between_changes", -1),
                    user_password_status: a.s("user_password_status"),
                    user_password_warning_days_before_expiration: a.vi("user_password_warning_days_before_expiration", -1),
                    process_pid: a.vd_ll("process_pid", -1),
                    host_ip: a.s("host_ip"),
                    login_status: a.vi("login_status", -1),
                    login_type: a.s("login_type"),
                    login_tty: a.s("login_tty"),
                    checksum: a.s("checksum"),
                };
                self.users_save(wdb, &r, true)
            }
            WDB_SYSCOLLECTOR_GROUPS => {
                let r = Group {
                    scan_id: zero(),
                    scan_time: a.s("scan_time"),
                    group_id: a.vd_ll("group_id", -1),
                    group_name: a.s("group_name"),
                    group_description: a.s("group_description"),
                    group_id_signed: a.vd_ll("group_id_signed", 0),
                    group_uuid: a.s("group_uuid"),
                    group_is_hidden: a.vi("group_is_hidden", -1),
                    group_users: a.s("group_users"),
                    checksum: a.s("checksum"),
                };
                self.groups_save(wdb, &r, true)
            }
            WDB_SYSCOLLECTOR_BROWSER_EXTENSIONS => {
                let r = BrowserExtension {
                    scan_id: zero(),
                    scan_time: a.s("scan_time"),
                    browser_name: a.s("browser_name"),
                    user_id: a.s("user_id"),
                    package_name: a.s("package_name"),
                    package_id: a.s("package_id"),
                    package_version: a.s("package_version"),
                    package_description: a.s("package_description"),
                    package_vendor: a.s("package_vendor"),
                    package_build_version: a.s("package_build_version"),
                    package_path: a.s("package_path"),
                    browser_profile_name: a.s("browser_profile_name"),
                    browser_profile_path: a.s("browser_profile_path"),
                    package_reference: a.s("package_reference"),
                    package_permissions: a.s("package_permissions"),
                    package_type: a.s("package_type"),
                    package_enabled: a.vi("package_enabled", -1),
                    package_visible: a.vi("package_visible", -1),
                    package_autoupdate: a.vi("package_autoupdate", -1),
                    package_persistent: a.vi("package_persistent", -1),
                    package_from_webstore: a.vi("package_from_webstore", -1),
                    browser_profile_referenced: a.vi("browser_profile_referenced", -1),
                    package_installed: a.s("package_installed"),
                    file_hash_sha256: a.s("file_hash_sha256"),
                    checksum: a.s("checksum"),
                    item_id: a.s("item_id"),
                };
                self.browser_extensions_save(wdb, &r, true)
            }
            WDB_SYSCOLLECTOR_SERVICES => {
                let r = Service {
                    scan_id: zero(),
                    scan_time: a.s("scan_time"),
                    service_id: a.s("service_id"),
                    service_name: a.s("service_name"),
                    service_description: a.s("service_description"),
                    service_type: a.s("service_type"),
                    service_state: a.s("service_state"),
                    service_sub_state: a.s("service_sub_state"),
                    service_enabled: a.s("service_enabled"),
                    service_start_type: a.s("service_start_type"),
                    service_restart: a.s("service_restart"),
                    service_frequency: a.vd_ll("service_frequency", -1),
                    service_starts_on_mount: a.vi("service_starts_on_mount", -1),
                    service_starts_on_path_modified: a.s("service_starts_on_path_modified"),
                    service_starts_on_not_empty_directory: a.s("service_starts_on_not_empty_directory"),
                    service_inetd_compatibility: a.vi("service_inetd_compatibility", -1),
                    process_pid: a.vd_ll("process_pid", -1),
                    process_executable: a.s("process_executable"),
                    process_args: a.s("process_args"),
                    process_user_name: a.s("process_user_name"),
                    process_group_name: a.s("process_group_name"),
                    process_working_directory: a.s("process_working_directory"),
                    process_root_directory: a.s("process_root_directory"),
                    file_path: a.s("file_path"),
                    service_address: a.s("service_address"),
                    log_file_path: a.s("log_file_path"),
                    error_log_file_path: a.s("error_log_file_path"),
                    service_exit_code: a.vi("service_exit_code", 0),
                    service_win32_exit_code: a.vi("service_win32_exit_code", 0),
                    service_following: a.s("service_following"),
                    service_object_path: a.s("service_object_path"),
                    service_target_ephemeral_id: a.vd_ll("service_target_ephemeral_id", -1),
                    service_target_type: a.s("service_target_type"),
                    service_target_address: a.s("service_target_address"),
                    checksum: a.s("checksum"),
                    item_id: a.s("item_id"),
                };
                self.services_save(wdb, &r, true)
            }
            _ => {
                self.mdebug1(b"at wdb_syscollector_save2(): Invalid component.");
                OS_INVALID
            }
        }
    }
}

/// `attributes` accessors with the C conversions.
struct A<'a>(&'a Json);

impl A<'_> {
    /// `cJSON_GetStringValue(cJSON_GetObjectItem(a, k))`
    fn s(&self, k: &str) -> S {
        match self.0.get(k) {
            Some(Json::String(s)) => Some(cstr(s).to_vec()),
            _ => None,
        }
    }

    /// `item ? item->valueint : def`
    fn vi(&self, k: &str, def: i32) -> i32 {
        match self.0.get(k) {
            Some(j) => super::global::valueint(j),
            None => def,
        }
    }

    /// `item ? item->valuedouble : def`
    fn vd(&self, k: &str, def: f64) -> f64 {
        match self.0.get(k) {
            Some(Json::Number { double, .. }) => *double,
            Some(_) => 0.0,
            None => def,
        }
    }

    /// `item ? (long long) item->valuedouble : def`
    fn vd_ll(&self, k: &str, def: i64) -> i64 {
        match self.0.get(k) {
            Some(Json::Number { double, .. }) => d2long(*double),
            Some(_) => 0,
            None => def,
        }
    }
}
