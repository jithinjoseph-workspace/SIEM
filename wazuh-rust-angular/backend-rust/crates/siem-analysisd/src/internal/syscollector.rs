//! Syscollector decoder (analysisd/decoders/syscollector.c): inventory
//! messages from the agents' syscollector module (network interfaces, OS,
//! hardware, packages, hotfixes, ports, processes and the `dbsync_*`
//! deltas) are stored in wazuh-db and exposed as dynamic fields.

use sha1::{Digest, Sha1};
use siem_cjson::Json;

use crate::daemon::Env;
use crate::event::Event;

/// `SYSCOLLECTOR_MOD`
pub const SYSCOLLECTOR_MOD: &str = "syscollector";
const OS_SIZE_64: usize = 64;
const OS_SIZE_256: usize = 256;
const OS_SIZE_1024: usize = 1024;
const OS_SIZE_6144: usize = 6144;
/// `WDB_NETADDR_IPV4`
const WDB_NETADDR_IPV4: i32 = 0;

type B = Vec<u8>;

/// `deltas_fields_match_list`: (JSON key, event field or None).
type Fields = &'static [(&'static str, Option<&'static str>)];

const HOTFIXES_FIELDS: Fields = &[("scan_time", None), ("hotfix", Some("hotfix")), ("checksum", None)];

const PACKAGES_FIELDS: Fields = &[
    ("scan_time", None),
    ("format", Some("program.format")),
    ("name", Some("program.name")),
    ("priority", Some("program.priority")),
    ("groups", Some("program.section")),
    ("size", Some("program.size")),
    ("vendor", Some("program.vendor")),
    ("install_time", Some("program.install_time")),
    ("version", Some("program.version")),
    ("architecture", Some("program.architecture")),
    ("multiarch", Some("program.multiarch")),
    ("source", Some("program.source")),
    ("description", Some("program.description")),
    ("location", Some("program.location")),
    ("checksum", None),
    ("item_id", None),
];

const PROCESSES_FIELDS: Fields = &[
    ("scan_time", None),
    ("pid", Some("process.pid")),
    ("name", Some("process.name")),
    ("state", Some("process.state")),
    ("ppid", Some("process.ppid")),
    ("utime", Some("process.utime")),
    ("stime", Some("process.stime")),
    ("cmd", Some("process.cmd")),
    ("argvs", Some("process.args")),
    ("euser", Some("process.euser")),
    ("ruser", Some("process.ruser")),
    ("suser", Some("process.suser")),
    ("egroup", Some("process.egroup")),
    ("rgroup", Some("process.rgroup")),
    ("sgroup", Some("process.sgroup")),
    ("fgroup", Some("process.fgroup")),
    ("priority", Some("process.priority")),
    ("nice", Some("process.nice")),
    ("size", Some("process.size")),
    ("vm_size", Some("process.vm_size")),
    ("resident", Some("process.resident")),
    ("share", Some("process.share")),
    ("start_time", Some("process.start_time")),
    ("pgrp", Some("process.pgrp")),
    ("session", Some("process.session")),
    ("nlwp", Some("process.nlwp")),
    ("tgid", Some("process.tgid")),
    ("tty", Some("process.tty")),
    ("processor", Some("process.processor")),
    ("checksum", None),
];

const PORTS_FIELDS: Fields = &[
    ("scan_time", None),
    ("protocol", Some("port.protocol")),
    ("local_ip", Some("port.local_ip")),
    ("local_port", Some("port.local_port")),
    ("remote_ip", Some("port.remote_ip")),
    ("remote_port", Some("port.remote_port")),
    ("tx_queue", Some("port.tx_queue")),
    ("rx_queue", Some("port.rx_queue")),
    ("inode", Some("port.inode")),
    ("state", Some("port.state")),
    ("pid", Some("port.pid")),
    ("process", Some("port.process")),
    ("checksum", None),
    ("item_id", None),
];

const NETWORK_IFACE_FIELDS: Fields = &[
    ("scan_time", None),
    ("name", Some("netinfo.iface.name")),
    ("adapter", Some("netinfo.iface.adapter")),
    ("type", Some("netinfo.iface.type")),
    ("state", Some("netinfo.iface.state")),
    ("mtu", Some("netinfo.iface.mtu")),
    ("mac", Some("netinfo.iface.mac")),
    ("tx_packets", Some("netinfo.iface.tx_packets")),
    ("rx_packets", Some("netinfo.iface.rx_packets")),
    ("tx_bytes", Some("netinfo.iface.tx_bytes")),
    ("rx_bytes", Some("netinfo.iface.rx_bytes")),
    ("tx_errors", Some("netinfo.iface.tx_errors")),
    ("rx_errors", Some("netinfo.iface.rx_errors")),
    ("tx_dropped", Some("netinfo.iface.tx_dropped")),
    ("rx_dropped", Some("netinfo.iface.rx_dropped")),
    ("checksum", None),
    ("item_id", None),
];

const NETWORK_PROTOCOL_FIELDS: Fields = &[
    ("iface", Some("netinfo.proto.iface")),
    ("type", Some("netinfo.proto.type")),
    ("gateway", Some("netinfo.proto.gateway")),
    ("dhcp", Some("netinfo.proto.dhcp")),
    ("metric", Some("netinfo.proto.metric")),
    ("checksum", None),
    ("item_id", None),
];

const NETWORK_ADDRESS_FIELDS: Fields = &[
    ("iface", Some("netinfo.addr.iface")),
    ("proto", Some("netinfo.addr.proto")),
    ("address", Some("netinfo.addr.address")),
    ("netmask", Some("netinfo.addr.netmask")),
    ("broadcast", Some("netinfo.addr.broadcast")),
    ("checksum", None),
    ("item_id", None),
];

const HARDWARE_FIELDS: Fields = &[
    ("scan_time", None),
    ("board_serial", Some("hardware.serial")),
    ("cpu_name", Some("hardware.cpu_name")),
    ("cpu_cores", Some("hardware.cpu_cores")),
    ("cpu_mhz", Some("hardware.cpu_mhz")),
    ("ram_total", Some("hardware.ram_total")),
    ("ram_free", Some("hardware.ram_free")),
    ("ram_usage", Some("hardware.ram_usage")),
    ("checksum", None),
];

const OS_FIELDS: Fields = &[
    ("scan_time", None),
    ("hostname", Some("os.hostname")),
    ("architecture", Some("os.architecture")),
    ("os_name", Some("os.name")),
    ("os_version", Some("os.version")),
    ("os_codename", Some("os.codename")),
    ("os_major", Some("os.major")),
    ("os_minor", Some("os.minor")),
    ("os_patch", Some("os.patch")),
    ("os_build", Some("os.build")),
    ("os_platform", Some("os.platform")),
    ("sysname", Some("os.sysname")),
    ("release", Some("os.release")),
    ("version", Some("os.version")),
    ("os_release", Some("os.os_release")),
    ("os_display_version", Some("os.display_version")),
    ("checksum", None),
];

const USER_FIELDS: Fields = &[
    ("scan_time", None),
    ("user_name", Some("user.user_name")),
    ("user_full_name", Some("user.user_full_name")),
    ("user_home", Some("user.user_home")),
    ("user_id", Some("user.user_id")),
    ("user_uid_signed", Some("user.user_uid_signed")),
    ("user_uuid", Some("user.user_uuid")),
    ("user_groups", Some("user.user_groups")),
    ("user_group_id", Some("user.user_group_id")),
    ("user_group_id_signed", Some("user.user_group_id_signed")),
    ("user_created", Some("user.user_created")),
    ("user_roles", Some("user.user_roles")),
    ("user_shell", Some("user.user_shell")),
    ("user_type", Some("user.user_type")),
    ("user_is_hidden", Some("user.user_is_hidden")),
    ("user_is_remote", Some("user.user_is_remote")),
    ("user_last_login", Some("user.user_last_login")),
    ("user_auth_failed_count", Some("user.user_auth_failed_count")),
    ("user_auth_failed_timestamp", Some("user.user_auth_failed_timestamp")),
    ("user_password_last_change", Some("user.user_password_last_change")),
    ("user_password_expiration_date", Some("user.user_password_expiration_date")),
    ("user_password_hash_algorithm", Some("user.user_password_hash_algorithm")),
    ("user_password_inactive_days", Some("user.user_password_inactive_days")),
    ("user_password_max_days_between_changes", Some("user.user_password_max_days_between_changes")),
    ("user_password_min_days_between_changes", Some("user.user_password_min_days_between_changes")),
    ("user_password_status", Some("user.user_password_status")),
    ("user_password_warning_days_before_expiration", Some("user.user_password_warning_days_before_expiration")),
    ("process_pid", Some("user.process_pid")),
    ("host_ip", Some("user.host_ip")),
    ("login_status", Some("user.login_status")),
    ("login_tty", Some("user.login_tty")),
    ("login_type", Some("user.login_type")),
    ("checksum", None),
];

const GROUP_FIELDS: Fields = &[
    ("scan_time", None),
    ("group_id", Some("group.group_id")),
    ("group_name", Some("group.group_name")),
    ("group_description", Some("group.group_description")),
    ("group_id_signed", Some("group.group_id_signed")),
    ("group_uuid", Some("group.group_uuid")),
    ("group_is_hidden", Some("group.group_is_hidden")),
    ("group_users", Some("group.group_users")),
    ("checksum", None),
];

const BROWSER_EXTENSION_FIELDS: Fields = &[
    ("scan_time", None),
    ("browser_name", Some("browser_extension.browser_name")),
    ("user_id", Some("browser_extension.user_id")),
    ("package_name", Some("browser_extension.package_name")),
    ("package_id", Some("browser_extension.package_id")),
    ("package_version", Some("browser_extension.package_version")),
    ("package_description", Some("browser_extension.package_description")),
    ("package_vendor", Some("browser_extension.package_vendor")),
    ("package_build_version", Some("browser_extension.package_build_version")),
    ("package_path", Some("browser_extension.package_path")),
    ("browser_profile_name", Some("browser_extension.browser_profile_name")),
    ("browser_profile_path", Some("browser_extension.browser_profile_path")),
    ("package_reference", Some("browser_extension.package_reference")),
    ("package_permissions", Some("browser_extension.package_permissions")),
    ("package_type", Some("browser_extension.package_type")),
    ("package_enabled", Some("browser_extension.package_enabled")),
    ("package_visible", Some("browser_extension.package_visible")),
    ("package_autoupdate", Some("browser_extension.package_autoupdate")),
    ("package_persistent", Some("browser_extension.package_persistent")),
    ("package_from_webstore", Some("browser_extension.package_from_webstore")),
    ("browser_profile_referenced", Some("browser_extension.browser_profile_referenced")),
    ("package_installed", Some("browser_extension.package_installed")),
    ("file_hash_sha256", Some("browser_extension.file_hash_sha256")),
    ("checksum", None),
    ("item_id", None),
];

const SERVICE_FIELDS: Fields = &[
    ("scan_time", None),
    ("service_id", Some("service.service_id")),
    ("service_name", Some("service.service_name")),
    ("service_description", Some("service.service_description")),
    ("service_type", Some("service.service_type")),
    ("service_state", Some("service.service_state")),
    ("service_sub_state", Some("service.service_sub_state")),
    ("service_enabled", Some("service.service_enabled")),
    ("service_start_type", Some("service.service_start_type")),
    ("service_restart", Some("service.service_restart")),
    ("service_frequency", Some("service.service_frequency")),
    ("service_starts_on_mount", Some("service.service_starts_on_mount")),
    ("service_starts_on_path_modified", Some("service.service_starts_on_path_modified")),
    ("service_starts_on_not_empty_directory", Some("service.service_starts_on_not_empty_directory")),
    ("service_inetd_compatibility", Some("service.service_inetd_compatibility")),
    ("process_pid", Some("service.process_pid")),
    ("process_executable", Some("service.process_executable")),
    ("process_args", Some("service.process_args")),
    ("process_user_name", Some("service.process_user_name")),
    ("process_group_name", Some("service.process_group_name")),
    ("process_working_directory", Some("service.process_working_directory")),
    ("process_root_directory", Some("service.process_root_directory")),
    ("file_path", Some("service.file_path")),
    ("service_address", Some("service.service_address")),
    ("log_file_path", Some("service.log_file_path")),
    ("error_log_file_path", Some("service.error_log_file_path")),
    ("service_exit_code", Some("service.service_exit_code")),
    ("service_win32_exit_code", Some("service.service_win32_exit_code")),
    ("service_following", Some("service.service_following")),
    ("service_object_path", Some("service.service_object_path")),
    ("service_target_ephemeral_id", Some("service.service_target_ephemeral_id")),
    ("service_target_type", Some("service.service_target_type")),
    ("service_target_address", Some("service.service_target_address")),
    ("checksum", None),
    ("item_id", None),
];

fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

fn cat(p: &[&[u8]]) -> B {
    p.concat()
}

/// `->valuestring`: NULL for anything but a string.
fn vs(j: Option<&Json>) -> Option<&[u8]> {
    match j {
        Some(Json::String(s)) => Some(cstr(s)),
        _ => None,
    }
}

/// `->valueint`: the parser sets 1 for `true`, 0 for other non-numbers.
fn vi(j: Option<&Json>) -> i32 {
    match j {
        Some(Json::Number { int, .. }) => *int,
        Some(Json::True) => 1,
        _ => 0,
    }
}

fn vd(j: Option<&Json>) -> f64 {
    match j {
        Some(Json::Number { double, .. }) => *double,
        _ => 0.0,
    }
}

fn is_num(j: Option<&Json>) -> bool {
    matches!(j, Some(Json::Number { .. }))
}

fn is_obj(j: Option<&Json>) -> bool {
    matches!(j, Some(Json::Object(_)))
}

/// `cJSON_GetArrayItem` (on arrays and objects alike).
fn nth(j: Option<&Json>, i: usize) -> Option<&Json> {
    match j {
        Some(Json::Array(a)) => a.get(i),
        Some(Json::Object(m)) => m.get(i).map(|(_, v)| v),
        _ => None,
    }
}

/// `wm_strcat(str1, str2, sep)`: nothing when `str2` is NULL.
fn strcat(dst: &mut Option<B>, src: Option<&[u8]>, sep: u8) {
    let Some(src) = src else { return };
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

/// `snprintf(buf, size, ...)` truncation.
fn trunc(mut v: B, size: usize) -> B {
    v.truncate(size.saturating_sub(1));
    v
}

/// `printf("%f")`
fn f6(d: f64) -> B {
    siem_cjson::fmt_f6(d).into_bytes()
}

/// `wdbc_parse_result(response, ...) == WDBC_OK`
fn result_ok(response: &[u8]) -> bool {
    let r = cstr(response);
    let head = match r.iter().position(|&c| c == b' ') {
        Some(p) => &r[..p],
        None => r,
    };
    head == b"ok"
}

/// `wdbi_strings_hash`: SHA-1 of the concatenated strings, in hex.
fn strings_hash(parts: &[&[u8]]) -> B {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>().into_bytes()
}

/// The scan error state of one inventory (`error_*` / `prev_*_id`).
#[derive(Debug, Default, Clone, Copy)]
struct ScanError {
    error: bool,
    prev_id: i32,
}

impl ScanError {
    /// The check at the start of a save / end message: true when the
    /// message belongs to a scan that already failed.
    fn skip(&mut self, id: i32) -> bool {
        if self.error {
            if id == self.prev_id {
                return true;
            }
            self.error = false;
        }
        false
    }

    fn fail(&mut self, id: i32) {
        self.error = true;
        self.prev_id = id;
    }
}

/// Process-wide state of the decoder.
#[derive(Debug, Default)]
pub struct Syscollector {
    package: ScanError,
    port: ScanError,
    process: ScanError,
}

struct Ctx<'a> {
    env: &'a mut dyn Env,
    agent: B,
    order_size: usize,
}

impl Ctx<'_> {
    fn log(&mut self, level: &str, m: &[u8]) {
        self.env.log(level, m);
    }

    fn fill(&mut self, ev: &mut Event, k: &str, v: &[u8]) {
        crate::plugins::fill_data(ev, Some(k.as_bytes()), cstr(v), self.order_size);
    }

    /// `wdbc_query_ex` + `wdbc_parse_result(...) == WDBC_OK`.
    fn query_ok(&mut self, msg: &[u8], len: usize) -> bool {
        match self.env.wdb_query_ex(msg, len) {
            Ok(r) => result_ok(&r),
            Err(_) => false,
        }
    }

    /// `snprintf(msg, OS_SIZE_6144 - 1, "agent %s <what>", lf->agent_id)`
    fn head(&self, what: &[u8]) -> Option<B> {
        Some(trunc(cat(&[b"agent ", &self.agent, b" ", what]), OS_SIZE_6144 - 1))
    }

    /// A string member: appended (or `NULL`) and filled when present.
    fn s(&mut self, ev: &mut Event, msg: &mut Option<B>, j: Option<&Json>, key: Option<&str>) {
        match vs(j) {
            Some(v) => {
                strcat(msg, Some(v), b'|');
                if let Some(k) = key {
                    self.fill(ev, k, v);
                }
            }
            None => strcat(msg, Some(b"NULL"), b'|'),
        }
    }

    /// A `%d` number member.
    fn n(&mut self, ev: &mut Event, msg: &mut Option<B>, j: Option<&Json>, key: &str) {
        if is_num(j) {
            let v = vi(j).to_string().into_bytes();
            self.fill(ev, key, &v);
            strcat(msg, Some(&v), b'|');
        } else {
            strcat(msg, Some(b"NULL"), b'|');
        }
    }

    /// A `%f` number member.
    fn f(&mut self, ev: &mut Event, msg: &mut Option<B>, j: Option<&Json>, key: &str) {
        if is_num(j) {
            let v = trunc(f6(vd(j)), 511);
            self.fill(ev, key, &v);
            strcat(msg, Some(&v), b'|');
        } else {
            strcat(msg, Some(b"NULL"), b'|');
        }
    }
}

impl Syscollector {
    /// `DecodeSyscollector`: false when the event goes no further.
    pub fn decode(&mut self, env: &mut dyn Env, dec: usize, order_size: usize, ev: &mut Event) -> bool {
        ev.decoder = dec;
        // Check location
        let loc = ev.f[crate::event::F_LOCATION].clone().unwrap_or_default();
        let loc = cstr(&loc);
        if loc.first() == Some(&b'(') {
            match loc.iter().position(|&c| c == b'>') {
                None => {
                    env.log("DEBUG", b"Invalid received event.");
                    return false;
                }
                Some(p) if &loc[p + 1..] != b"syscollector" => {
                    env.log("DEBUG", b"Invalid received event. Not syscollector.");
                    return false;
                }
                _ => {}
            }
        } else if loc != b"syscollector" {
            env.log("DEBUG", b"Invalid received event. (Location)");
            return false;
        }

        let log = cstr(ev.log()).to_vec();
        let Ok((mut root, _)) = siem_cjson::parse_with_opts(&log, false) else {
            env.log("DEBUG", b"Error parsing JSON event.");
            env.log("DEBUG2", &cat(&[b"Input JSON: '", &log]));
            return false;
        };
        let Some(msg_type) = vs(root.get("type")).map(|t| t.to_vec()) else {
            env.log("DEBUG", b"Invalid message. Type not found.");
            return false;
        };
        let agent = cstr(ev.agent_id.as_deref().unwrap_or(b"")).to_vec();
        let has_agent = ev.agent_id.is_some();
        let mut c = Ctx { env, agent, order_size };
        c.fill(ev, "type", &msg_type);
        let t = &msg_type[..];
        let (r, what): (i32, &[u8]) = if t == b"port" || t == b"port_end" {
            (self.decode_port(&mut c, ev, &root), b"Unable to send ports information to Wazuh DB.")
        } else if t == b"program" || t == b"program_end" {
            (self.decode_package(&mut c, ev, &root), b"Unable to send packages information to Wazuh DB.")
        } else if t == b"hotfix" || t == b"hotfix_end" {
            (decode_hotfix(&mut c, ev, &root), b"Unable to send hotfixes information to Wazuh DB.")
        } else if t == b"hardware" {
            (decode_hardware(&mut c, ev, &root), b"Unable to send hardware information to Wazuh DB.")
        } else if t == b"OS" {
            (decode_osinfo(&mut c, ev, &root), b"Unable to send osinfo message to Wazuh DB.")
        } else if t == b"network" || t == b"network_end" {
            if decode_netinfo(&mut c, ev, &root) < 0 {
                c.log("ERROR", b"Unable to send netinfo message to Wazuh DB.");
                return false;
            }
            (0, b"")
        } else if t == b"process" || t == b"process_end" {
            (self.decode_process(&mut c, ev, &root), b"Unable to send processes information to Wazuh DB.")
        } else if t.starts_with(b"dbsync_") {
            (
                decode_dbsync(&mut c, ev, has_agent, t, &mut root),
                b"(9201): Unable to send dbsync information to Wazuh DB.",
            )
        } else {
            c.log("DEBUG", &cat(&[b"Invalid message type: ", t, b"."]));
            return false;
        };
        if r < 0 {
            c.log("DEBUG", what);
            return false;
        }
        true
    }

    /// `decode_port`
    fn decode_port(&mut self, c: &mut Ctx, ev: &mut Event, root: &Json) -> i32 {
        let scan_id = root.get("ID");
        if !is_num(scan_id) {
            return -1;
        }
        let id = vi(scan_id);
        let inventory = root.get("port");
        if is_obj(inventory) {
            if self.port.skip(id) {
                return 0;
            }
            let g = |k: &str| inventory.and_then(|i| i.get(k));
            let mut msg = c.head(b"port save");
            strcat(&mut msg, Some(id.to_string().as_bytes()), b' ');
            c.s(ev, &mut msg, root.get("timestamp"), None);
            c.s(ev, &mut msg, g("protocol"), Some("port.protocol"));
            c.s(ev, &mut msg, g("local_ip"), Some("port.local_ip"));
            // `if (local_port)`: any member, through its valueint
            let local_port = g("local_port");
            if local_port.is_some() {
                let v = vi(local_port).to_string().into_bytes();
                c.fill(ev, "port.local_port", &v);
                strcat(&mut msg, Some(&v), b'|');
            } else {
                strcat(&mut msg, Some(b"NULL"), b'|');
            }
            c.s(ev, &mut msg, g("remote_ip"), Some("port.remote_ip"));
            c.n(ev, &mut msg, g("remote_port"), "port.remote_port");
            c.n(ev, &mut msg, g("tx_queue"), "port.tx_queue");
            c.n(ev, &mut msg, g("rx_queue"), "port.rx_queue");
            c.n(ev, &mut msg, g("inode"), "port.inode");
            c.s(ev, &mut msg, g("state"), Some("port.state"));
            c.n(ev, &mut msg, g("PID"), "port.pid");
            c.s(ev, &mut msg, g("process"), Some("port.process"));
            if !c.query_ok(&msg.unwrap_or_default(), OS_SIZE_6144) {
                self.port.fail(id);
                return -1;
            }
        } else {
            let Some(t) = vs(root.get("type")) else {
                c.log("ERROR", b"Invalid message. Type not found.");
                return -1;
            };
            if t == b"port_end" {
                if self.port.skip(id) {
                    return 0;
                }
                let msg = c.agent_msg(b"port del ", id);
                if !c.query_ok(&msg, OS_SIZE_6144) {
                    self.port.fail(id);
                    return -1;
                }
            }
        }
        0
    }

    /// `decode_package`
    fn decode_package(&mut self, c: &mut Ctx, ev: &mut Event, root: &Json) -> i32 {
        let scan_id = root.get("ID");
        if !is_num(scan_id) {
            return -1;
        }
        let id = vi(scan_id);
        let package = root.get("program");
        if is_obj(package) {
            if self.package.skip(id) {
                return 0;
            }
            let g = |k: &str| package.and_then(|i| i.get(k));
            let mut msg = c.head(b"package save");
            strcat(&mut msg, Some(id.to_string().as_bytes()), b' ');
            c.s(ev, &mut msg, root.get("timestamp"), None);
            c.s(ev, &mut msg, g("format"), Some("program.format"));
            c.s(ev, &mut msg, g("name"), Some("program.name"));
            c.s(ev, &mut msg, g("priority"), Some("program.priority"));
            c.s(ev, &mut msg, g("group"), Some("program.section"));
            c.n(ev, &mut msg, g("size"), "program.size");
            c.s(ev, &mut msg, g("vendor"), Some("program.vendor"));
            c.s(ev, &mut msg, g("install_time"), Some("program.install_time"));
            c.s(ev, &mut msg, g("version"), Some("program.version"));
            c.s(ev, &mut msg, g("architecture"), Some("program.architecture"));
            c.s(ev, &mut msg, g("multi-arch"), Some("program.multiarch"));
            c.s(ev, &mut msg, g("source"), Some("program.source"));
            c.s(ev, &mut msg, g("description"), Some("program.description"));
            c.s(ev, &mut msg, g("location"), Some("program.location"));
            // The reference for packages is calculated with the name, version and architecture
            let hexdigest = strings_hash(&[
                vs(g("name")).unwrap_or(b""),
                vs(g("version")).unwrap_or(b""),
                vs(g("architecture")).unwrap_or(b""),
            ]);
            strcat(&mut msg, Some(&hexdigest), b'|');
            if !c.query_ok(&msg.unwrap_or_default(), OS_SIZE_6144) {
                self.package.fail(id);
                return -1;
            }
        } else {
            let Some(t) = vs(root.get("type")) else {
                c.log("ERROR", b"Invalid message. Type not found.");
                return -1;
            };
            if t == b"program_end" {
                if self.package.skip(id) {
                    return 0;
                }
                let msg = c.agent_msg(b"package del ", id);
                if !c.query_ok(&msg, OS_SIZE_6144) {
                    self.package.fail(id);
                    return -1;
                }
            }
        }
        0
    }

    /// `decode_process`
    fn decode_process(&mut self, c: &mut Ctx, ev: &mut Event, root: &Json) -> i32 {
        let scan_id = root.get("ID");
        if !is_num(scan_id) {
            return -1;
        }
        let id = vi(scan_id);
        let inventory = root.get("process");
        if is_obj(inventory) {
            if self.process.skip(id) {
                return 0;
            }
            let g = |k: &str| inventory.and_then(|i| i.get(k));
            let mut msg = c.head(b"process save");
            strcat(&mut msg, Some(id.to_string().as_bytes()), b' ');
            c.s(ev, &mut msg, root.get("timestamp"), None);
            c.n(ev, &mut msg, g("pid"), "process.pid");
            c.s(ev, &mut msg, g("name"), Some("process.name"));
            c.s(ev, &mut msg, g("state"), Some("process.state"));
            c.n(ev, &mut msg, g("ppid"), "process.ppid");
            c.n(ev, &mut msg, g("utime"), "process.utime");
            c.n(ev, &mut msg, g("stime"), "process.stime");
            c.s(ev, &mut msg, g("cmd"), Some("process.cmd"));
            let argvs = g("argvs");
            if let Some(a) = argvs.filter(|a| a.is_array()) {
                let mut args: Option<B> = None;
                for it in a.children() {
                    strcat(&mut args, vs(Some(it)), b',');
                }
                let printed = a.print();
                c.fill(ev, "process.args", &printed);
                strcat(&mut msg, args.as_deref(), b'|');
            } else {
                strcat(&mut msg, Some(b"NULL"), b'|');
            }
            c.s(ev, &mut msg, g("euser"), Some("process.euser"));
            c.s(ev, &mut msg, g("ruser"), Some("process.ruser"));
            c.s(ev, &mut msg, g("suser"), Some("process.suser"));
            c.s(ev, &mut msg, g("egroup"), Some("process.egroup"));
            c.s(ev, &mut msg, g("rgroup"), Some("process.rgroup"));
            c.s(ev, &mut msg, g("sgroup"), Some("process.sgroup"));
            c.s(ev, &mut msg, g("fgroup"), Some("process.fgroup"));
            c.n(ev, &mut msg, g("priority"), "process.priority");
            c.n(ev, &mut msg, g("nice"), "process.nice");
            c.n(ev, &mut msg, g("size"), "process.size");
            c.n(ev, &mut msg, g("vm_size"), "process.vm_size");
            c.n(ev, &mut msg, g("resident"), "process.resident");
            c.n(ev, &mut msg, g("share"), "process.share");
            c.n(ev, &mut msg, g("start_time"), "process.start_time");
            c.n(ev, &mut msg, g("pgrp"), "process.pgrp");
            c.n(ev, &mut msg, g("session"), "process.session");
            c.n(ev, &mut msg, g("nlwp"), "process.nlwp");
            c.n(ev, &mut msg, g("tgid"), "process.tgid");
            c.n(ev, &mut msg, g("tty"), "process.tty");
            c.n(ev, &mut msg, g("processor"), "process.processor");
            if !c.query_ok(&msg.unwrap_or_default(), OS_SIZE_6144) {
                self.process.fail(id);
                return -1;
            }
        } else {
            let Some(t) = vs(root.get("type")) else {
                c.log("ERROR", b"Invalid message. Type not found.");
                return -1;
            };
            if t == b"process_end" {
                if self.process.skip(id) {
                    return 0;
                }
                let msg = c.agent_msg(b"process del ", id);
                if !c.query_ok(&msg, OS_SIZE_6144) {
                    self.process.fail(id);
                    return -1;
                }
            }
        }
        0
    }
}

impl Ctx<'_> {
    /// `snprintf(msg, OS_SIZE_6144 - 1, "agent %s <what>%d", agent, id)`
    fn agent_msg(&self, what: &[u8], id: i32) -> B {
        trunc(cat(&[b"agent ", &self.agent, b" ", what, id.to_string().as_bytes()]), OS_SIZE_6144 - 1)
    }
}

/// `decode_netinfo`
fn decode_netinfo(c: &mut Ctx, ev: &mut Event, root: &Json) -> i32 {
    let iface = root.get("iface");
    if !is_obj(iface) {
        // Looking for 'end' message.
        let Some(t) = vs(root.get("type")) else {
            c.log("ERROR", b"Invalid message. Type not found.");
            return -1;
        };
        if t != b"network_end" {
            c.log("ERROR", b"at decode_netinfo(): unknown type found.");
            return -1;
        }
        let scan_id = root.get("ID");
        if !is_num(scan_id) {
            c.log("ERROR", b"at decode_netinfo(): missing scan ID.");
            return -1;
        }
        let msg = c.agent_msg(b"netinfo del ", vi(scan_id));
        if !c.query_ok(&msg, OS_SIZE_6144) {
            return -1;
        }
        return 0;
    }
    let g = |k: &str| iface.and_then(|i| i.get(k));
    let scan_id = root.get("ID");
    let id: Option<B> = is_num(scan_id).then(|| vi(scan_id).to_string().into_bytes());
    let id_or_null = || id.clone().unwrap_or_else(|| b"NULL".to_vec());
    let name = vs(g("name"));

    let mut msg = c.head(b"netinfo save");
    strcat(&mut msg, Some(&id_or_null()), b' ');
    c.s(ev, &mut msg, root.get("timestamp"), None);
    c.s(ev, &mut msg, g("name"), Some("netinfo.iface.name"));
    c.s(ev, &mut msg, g("adapter"), Some("netinfo.iface.adapter"));
    c.s(ev, &mut msg, g("type"), Some("netinfo.iface.type"));
    c.s(ev, &mut msg, g("state"), Some("netinfo.iface.state"));
    c.n(ev, &mut msg, g("MTU"), "netinfo.iface.mtu");
    c.s(ev, &mut msg, g("MAC"), Some("netinfo.iface.mac"));
    c.n(ev, &mut msg, g("tx_packets"), "netinfo.iface.tx_packets");
    c.n(ev, &mut msg, g("rx_packets"), "netinfo.iface.rx_packets");
    c.n(ev, &mut msg, g("tx_bytes"), "netinfo.iface.tx_bytes");
    c.n(ev, &mut msg, g("rx_bytes"), "netinfo.iface.rx_bytes");
    c.n(ev, &mut msg, g("tx_errors"), "netinfo.iface.tx_errors");
    c.n(ev, &mut msg, g("rx_errors"), "netinfo.iface.rx_errors");
    c.n(ev, &mut msg, g("tx_dropped"), "netinfo.iface.tx_dropped");
    c.n(ev, &mut msg, g("rx_dropped"), "netinfo.iface.rx_dropped");
    if !c.query_ok(&msg.unwrap_or_default(), OS_SIZE_6144) {
        return -1;
    }

    for (key, proto, v6) in [("IPv4", b"0", false), ("IPv6", b"1", true)] {
        let ip = g(key);
        if !is_obj(ip) {
            continue;
        }
        let pfx = if v6 { "netinfo.iface.ipv6" } else { "netinfo.iface.ipv4" };
        let gi = |k: &str| ip.and_then(|i| i.get(k));
        let address = gi("address");
        let netmask = gi("netmask");
        let broadcast = gi("broadcast");

        let mut msg = c.head(b"netproto save");
        strcat(&mut msg, Some(&id_or_null()), b' ');
        strcat(&mut msg, Some(name.unwrap_or(b"NULL")), b'|');
        strcat(&mut msg, Some(proto), b'|');
        c.s(ev, &mut msg, gi("gateway"), Some(&format!("{pfx}.gateway")));
        c.s(ev, &mut msg, gi("dhcp"), Some(&format!("{pfx}.dhcp")));
        c.n(ev, &mut msg, gi("metric"), &format!("{pfx}.metric"));
        if !c.query_ok(&msg.unwrap_or_default(), OS_SIZE_6144) {
            return -1;
        }

        // Save addresses information into 'sys_netaddr' table
        let Some(Json::Array(addrs)) = address else {
            continue;
        };
        let mut all_address: Option<B> = None;
        let mut all_netmask: Option<B> = None;
        let mut all_broadcast: Option<B> = None;
        for i in 0..addrs.len() {
            let Some(address_i) = vs(addrs.get(i)) else {
                break;
            };
            let netmask_i = nth(netmask, i);
            let broadcast_i = nth(broadcast, i);
            let mut msg = c.head(b"netaddr save");
            strcat(&mut msg, Some(&id_or_null()), b' ');
            strcat(&mut msg, Some(name.unwrap_or(b"NULL")), b'|');
            strcat(&mut msg, Some(proto), b'|');
            strcat(&mut msg, Some(address_i), b'|');
            strcat(&mut all_address, Some(address_i), b',');
            for (item, all) in [(netmask_i, &mut all_netmask), (broadcast_i, &mut all_broadcast)] {
                // IPv4 requires a string; IPv6 takes any member (a NULL
                // valuestring appends nothing)
                let present = if v6 { item.is_some() } else { vs(item).is_some() };
                if present {
                    strcat(&mut msg, vs(item), b'|');
                    strcat(all, vs(item), b',');
                } else {
                    strcat(&mut msg, Some(b"NULL"), b'|');
                }
            }
            if !c.query_ok(&msg.unwrap_or_default(), OS_SIZE_6144) {
                return -1;
            }
        }
        for (all, k) in [(all_address, "address"), (all_netmask, "netmask"), (all_broadcast, "broadcast")] {
            if let Some(a) = all {
                let buf = crate::internal::sca::csv_to_json(&a);
                c.fill(ev, &format!("{pfx}.{k}"), &buf);
            }
        }
    }
    0
}

/// `decode_osinfo`
fn decode_osinfo(c: &mut Ctx, ev: &mut Event, root: &Json) -> i32 {
    let inventory = root.get("inventory");
    if !is_obj(inventory) {
        return 0;
    }
    let g = |k: &str| inventory.and_then(|i| i.get(k));
    let scan_id = root.get("ID");
    let mut msg = c.head(b"osinfo set");
    let id = if is_num(scan_id) { vi(scan_id).to_string().into_bytes() } else { b"NULL".to_vec() };
    strcat(&mut msg, Some(&id), b' ');
    c.s(ev, &mut msg, root.get("timestamp"), None);
    c.s(ev, &mut msg, g("hostname"), Some("os.hostname"));
    c.s(ev, &mut msg, g("architecture"), Some("os.architecture"));
    c.s(ev, &mut msg, g("os_name"), Some("os.name"));
    c.s(ev, &mut msg, g("os_version"), Some("os.version"));
    c.s(ev, &mut msg, g("os_codename"), Some("os.codename"));
    c.s(ev, &mut msg, g("os_major"), Some("os.major"));
    c.s(ev, &mut msg, g("os_minor"), Some("os.minor"));
    c.s(ev, &mut msg, g("os_build"), Some("os.build"));
    c.s(ev, &mut msg, g("os_platform"), Some("os.platform"));
    c.s(ev, &mut msg, g("sysname"), Some("os.sysname"));
    c.s(ev, &mut msg, g("release"), Some("os.release"));
    c.s(ev, &mut msg, g("version"), Some("os.release_version"));
    c.s(ev, &mut msg, g("os_release"), Some("os.os_release"));
    c.s(ev, &mut msg, g("os_patch"), Some("os.patch"));
    c.s(ev, &mut msg, g("os_display_version"), Some("os.display_version"));
    if !c.query_ok(&msg.unwrap_or_default(), OS_SIZE_6144) {
        return -1;
    }
    0
}

/// `decode_hardware`
fn decode_hardware(c: &mut Ctx, ev: &mut Event, root: &Json) -> i32 {
    let inventory = root.get("inventory");
    if !is_obj(inventory) {
        return 0;
    }
    let g = |k: &str| inventory.and_then(|i| i.get(k));
    let scan_id = root.get("ID");
    let mut msg = c.head(b"hardware save");
    let id = if is_num(scan_id) { vi(scan_id).to_string().into_bytes() } else { b"NULL".to_vec() };
    strcat(&mut msg, Some(&id), b' ');
    c.s(ev, &mut msg, root.get("timestamp"), None);
    c.s(ev, &mut msg, g("board_serial"), Some("hardware.serial"));
    c.s(ev, &mut msg, g("cpu_name"), Some("hardware.cpu_name"));
    c.n(ev, &mut msg, g("cpu_cores"), "hardware.cpu_cores");
    c.f(ev, &mut msg, g("cpu_mhz"), "hardware.cpu_mhz");
    c.f(ev, &mut msg, g("ram_total"), "hardware.ram_total");
    c.f(ev, &mut msg, g("ram_free"), "hardware.ram_free");
    c.n(ev, &mut msg, g("ram_usage"), "hardware.ram_usage");
    if !c.query_ok(&msg.unwrap_or_default(), OS_SIZE_6144) {
        return -1;
    }
    0
}

/// `decode_hotfix`
fn decode_hotfix(c: &mut Ctx, ev: &mut Event, root: &Json) -> i32 {
    let hotfix = vs(root.get("hotfix"));
    let scan_id = root.get("ID");
    let scan_time = vs(root.get("timestamp"));
    if !is_num(scan_id) {
        return -1;
    }
    let id = vi(scan_id).to_string().into_bytes();
    if let (Some(hotfix), Some(scan_time)) = (hotfix, scan_time) {
        let msg = trunc(cat(&[b"agent ", &c.agent, b" hotfix save ", &id, b"|", scan_time, b"|", hotfix, b"|"]), OS_SIZE_1024);
        c.fill(ev, "hotfix", hotfix);
        if !c.query_ok(&msg, 4096) {
            return -1;
        }
    } else {
        // Looking for 'end' message.
        let Some(t) = vs(root.get("type")) else {
            c.log("ERROR", b"Invalid message. Type not found.");
            return -1;
        };
        if t == b"hotfix_end" {
            let msg = trunc(cat(&[b"agent ", &c.agent, b" hotfix del ", &id]), OS_SIZE_1024 - 1);
            if !c.query_ok(&msg, 4096) {
                return -1;
            }
        }
    }
    0
}

/// `get_field_list`
fn field_list(t: &[u8]) -> Option<Fields> {
    Some(match t {
        b"hotfixes" => HOTFIXES_FIELDS,
        b"packages" => PACKAGES_FIELDS,
        b"processes" => PROCESSES_FIELDS,
        b"ports" => PORTS_FIELDS,
        b"network_iface" => NETWORK_IFACE_FIELDS,
        b"network_protocol" => NETWORK_PROTOCOL_FIELDS,
        b"network_address" => NETWORK_ADDRESS_FIELDS,
        b"hwinfo" => HARDWARE_FIELDS,
        b"osinfo" => OS_FIELDS,
        b"users" => USER_FIELDS,
        b"groups" => GROUP_FIELDS,
        b"browser_extensions" => BROWSER_EXTENSION_FIELDS,
        b"services" => SERVICE_FIELDS,
        _ => return None,
    })
}

/// `fill_event_alert`
fn fill_event_alert(c: &mut Ctx, ev: &mut Event, fields: Fields, operation: &[u8], data: &Json) {
    for &(key, value) in fields {
        let Some(value) = value else { continue };
        match data.get(key) {
            Some(Json::String(s)) => c.fill(ev, value, s),
            Some(Json::Number { double, int }) => {
                let v = if *int as f64 == *double { int.to_string().into_bytes() } else { f6(*double) };
                c.fill(ev, value, &trunc(v, OS_SIZE_64 - 1));
            }
            _ => c.fill(ev, value, b""),
        }
    }
    c.fill(ev, "operation_type", operation);
}

/// `protocol_mapping` (`cJSON_ReplaceItemInObject` renames the member to
/// the lookup key).
fn protocol_mapping(c: &mut Ctx, data: &mut Json, key: &str) -> bool {
    if let Json::Object(m) = data {
        if let Some(e) = m.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(key.as_bytes())) {
            if let Json::Number { int, .. } = e.1 {
                let proto: &[u8] = if int == WDB_NETADDR_IPV4 { b"ipv4" } else { b"ipv6" };
                *e = (key.as_bytes().to_vec(), Json::String(proto.to_vec()));
                return true;
            }
        }
    }
    c.log("DEBUG2", format!("Field '{key}' cannot be obtained.").as_bytes());
    false
}

/// `decode_dbsync`
fn decode_dbsync(c: &mut Ctx, ev: &mut Event, has_agent: bool, msg_type: &[u8], root: &mut Json) -> i32 {
    if !has_agent {
        return -1;
    }
    // strtok_r(msg_type, "_", &type): the table name follows the first '_'
    let p = msg_type.iter().position(|&c| c == b'_').unwrap_or(msg_type.len());
    let t = msg_type.get(p + 1..).unwrap_or(b"").to_vec();
    if t.is_empty() {
        let prefix = &msg_type[..p];
        c.log("ERROR", &cat(&[b"(1283): Incorrect prefix message, message type: ", prefix, b"."]));
        return -1;
    }
    let Some(fields) = field_list(&t) else {
        c.log("ERROR", &cat(&[b"(1287): Incorrect/unknown type value ", &t, b"."]));
        return -1;
    };
    let operation = vs(root.get("operation")).map(|o| o.to_vec());
    let Some(operation) = operation.filter(|_| is_obj(root.get("data"))) else {
        c.log("ERROR", &cat(&[b"(1284): Incorrect/unknown operation, type: ", &t, b"."]));
        return -1;
    };
    let data = root.get_mut("data").expect("checked");
    // delta_map_values
    if t == b"network_address" && !protocol_mapping(c, data, "proto") {
        c.log("DEBUG2", b"Error while mapping 'proto' field value.");
    }
    let printed = data.print_unformatted();
    let msg = cat(&[b"agent ", &c.agent, b" dbsync ", &t, b" ", &operation, b" ", &printed]);
    // snprintf(msg, data_len + OS_SIZE_256 - 1, ...), data_len = strlen(data) + 1
    let msg = trunc(msg, printed.len() + OS_SIZE_256);
    fill_event_alert(c, ev, fields, &operation, data);
    match c.env.wdb_query_ex(&msg, OS_SIZE_1024) {
        Ok(r) => {
            if r.starts_with(b"err") {
                c.log("DEBUG", b"(1286): Wazuh-db query error, check wdb logs.");
            } else if !r.starts_with(b"ok ") {
                c.log("ERROR", b"(1285): Response with unexpected content.");
            }
            0
        }
        Err(code) => {
            c.log("DEBUG2", b"(1288): Wazuh-db query execution error.");
            code
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_helpers() {
        assert_eq!(strings_hash(&[b"", b"", b""]), b"da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert!(result_ok(b"ok"));
        assert!(result_ok(b"ok 1"));
        assert!(!result_ok(b"okay"));
        let mut a = None;
        strcat(&mut a, Some(b""), b',');
        strcat(&mut a, Some(b"x"), b',');
        assert_eq!(a.unwrap(), b",x");
    }
}
