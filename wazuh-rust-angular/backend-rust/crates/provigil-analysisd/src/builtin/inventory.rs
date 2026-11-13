//! Inventory events (spec section 2.27): network interfaces, OS, hardware, packages,
//! hotfixes, ports, processes and the `dbsync_*` changes, stored in provigil-db and given to
//! the rules as fields.

use sha1::{Digest, Sha1};
use provigil_json::Json;

use crate::event::*;
use crate::host::Host;

pub const NAME: &str = "syscollector";

type B = Vec<u8>;

/// (JSON member, event field or None) of each `dbsync_<table>` message.
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

fn cut(b: &[u8]) -> &[u8] {
    text_at(b, 0)
}

/// A string member's text; None for anything else.
fn text(j: Option<&Json>) -> Option<&[u8]> {
    match j {
        Some(Json::String(s)) => Some(cut(s)),
        _ => None,
    }
}

/// A number's int value; `true` is 1; other values 0.
fn int(j: Option<&Json>) -> i32 {
    match j {
        Some(Json::Number { int, .. }) => *int,
        Some(Json::True) => 1,
        _ => 0,
    }
}

fn double(j: Option<&Json>) -> f64 {
    match j {
        Some(Json::Number { double, .. }) => *double,
        _ => 0.0,
    }
}

fn number(j: Option<&Json>) -> bool {
    matches!(j, Some(Json::Number { .. }))
}

fn object(j: Option<&Json>) -> bool {
    matches!(j, Some(Json::Object(_)))
}

/// The i-th element of an array or the i-th member of an object.
fn nth(j: Option<&Json>, i: usize) -> Option<&Json> {
    match j {
        Some(Json::Array(a)) => a.get(i),
        Some(Json::Object(m)) => m.get(i).map(|(_, v)| v),
        _ => None,
    }
}

/// Appends `sep` + `v` (the first value without `sep`); nothing for None.
fn join(to: &mut Option<B>, v: Option<&[u8]>, sep: u8) {
    let Some(v) = v else { return };
    match to {
        Some(t) => {
            if sep != 0 {
                t.push(sep);
            }
            t.extend_from_slice(v);
        }
        None => *to = Some(v.to_vec()),
    }
}

fn first(mut v: B, room: usize) -> B {
    v.truncate(room.saturating_sub(1));
    v
}

fn ok(answer: &[u8]) -> bool {
    let a = cut(answer);
    a.split(|&c| c == b' ').next() == Some(b"ok")
}

/// SHA-1 of the texts one after the other, in hex.
fn sha1_hex(parts: &[&[u8]]) -> B {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>().into_bytes()
}

/// Comma-separated values as a JSON array (formatted).
pub fn csv_json(s: &[u8]) -> B {
    Json::Array(s.split(|&c| c == b',').filter(|t| !t.is_empty()).map(|t| Json::String(t.to_vec())).collect()).print()
}

/// A scan that failed: its later messages (same scan id) are skipped.
#[derive(Debug, Default, Clone, Copy)]
struct Failed {
    on: bool,
    scan: i32,
}

impl Failed {
    fn skip(&mut self, scan: i32) -> bool {
        if self.on && scan == self.scan {
            return true;
        }
        self.on = false;
        false
    }
    fn set(&mut self, scan: i32) {
        *self = Failed { on: true, scan };
    }
}

#[derive(Debug, Default)]
pub struct Inventory {
    packages: Failed,
    ports: Failed,
    processes: Failed,
}

struct Cx<'a> {
    host: &'a mut dyn Host,
    agent: B,
    order: usize,
}

impl Cx<'_> {
    fn fill(&mut self, ev: &mut Event, k: &str, v: &[u8]) {
        crate::plugins::fill(ev, Some(k.as_bytes()), cut(v), self.order);
    }

    fn query_ok(&mut self, q: &[u8], room: usize) -> bool {
        self.host.db_query(q, room).is_ok_and(|a| ok(&a))
    }

    fn start(&self, what: &[u8]) -> Option<B> {
        Some(first([&b"agent "[..], &self.agent, b" ", what].concat(), 6143))
    }

    /// `agent <id> <what><scan>`
    fn with_scan(&self, what: &[u8], scan: i32) -> B {
        first([&b"agent "[..], &self.agent, b" ", what, scan.to_string().as_bytes()].concat(), 6143)
    }

    /// A string member: its value (and field), or NULL.
    fn s(&mut self, ev: &mut Event, q: &mut Option<B>, j: Option<&Json>, field: Option<&str>) {
        match text(j) {
            Some(v) => {
                join(q, Some(v), b'|');
                if let Some(f) = field {
                    self.fill(ev, f, v);
                }
            }
            None => join(q, Some(b"NULL"), b'|'),
        }
    }

    /// A number member as an integer, or NULL.
    fn n(&mut self, ev: &mut Event, q: &mut Option<B>, j: Option<&Json>, field: &str) {
        if number(j) {
            let v = int(j).to_string().into_bytes();
            self.fill(ev, field, &v);
            join(q, Some(&v), b'|');
        } else {
            join(q, Some(b"NULL"), b'|');
        }
    }

    /// A number member with six decimals, or NULL.
    fn f(&mut self, ev: &mut Event, q: &mut Option<B>, j: Option<&Json>, field: &str) {
        if number(j) {
            let v = first(provigil_json::fmt_f6(double(j)).into_bytes(), 511);
            self.fill(ev, field, &v);
            join(q, Some(&v), b'|');
        } else {
            join(q, Some(b"NULL"), b'|');
        }
    }
}

impl Inventory {
    /// One inventory event; false when it goes no further.
    pub fn decode(&mut self, host: &mut dyn Host, decoder: DecoderId, order: usize, ev: &mut Event) -> bool {
        ev.decoder = decoder;
        let loc = ev.f[F_LOCATION].clone().unwrap_or_default();
        let loc = cut(&loc);
        if loc.first() == Some(&b'(') {
            match loc.iter().position(|&c| c == b'>') {
                None => {
                    host.log("DEBUG", b"Invalid received event.");
                    return false;
                }
                Some(p) if &loc[p + 1..] != b"syscollector" => {
                    host.log("DEBUG", b"Invalid received event. Not syscollector.");
                    return false;
                }
                _ => {}
            }
        } else if loc != b"syscollector" {
            host.log("DEBUG", b"Invalid received event. (Location)");
            return false;
        }
        let log = cut(ev.log()).to_vec();
        let Ok((mut root, _)) = provigil_json::parse_with_opts(&log, false) else {
            host.log("DEBUG", b"Error parsing JSON event.");
            host.log("DEBUG2", &[&b"Input JSON: '"[..], &log].concat());
            return false;
        };
        let Some(kind) = text(root.get("type")).map(<[u8]>::to_vec) else {
            host.log("DEBUG", b"Invalid message. Type not found.");
            return false;
        };
        let agent = cut(ev.agent_id.as_deref().unwrap_or(b"")).to_vec();
        let has_agent = ev.agent_id.is_some();
        let mut c = Cx { host, agent, order };
        c.fill(ev, "type", &kind);
        let k = kind.as_slice();
        let (result, failure): (i32, &[u8]) = match k {
            b"port" | b"port_end" => (self.ports(&mut c, ev, &root), b"Unable to send ports information to provigil-db."),
            b"program" | b"program_end" => (self.packages(&mut c, ev, &root), b"Unable to send packages information to provigil-db."),
            b"hotfix" | b"hotfix_end" => (hotfix(&mut c, ev, &root), b"Unable to send hotfixes information to provigil-db."),
            b"hardware" => (hardware(&mut c, ev, &root), b"Unable to send hardware information to provigil-db."),
            b"OS" => (os(&mut c, ev, &root), b"Unable to send osinfo message to provigil-db."),
            b"network" | b"network_end" => {
                if network(&mut c, ev, &root) < 0 {
                    c.host.log("ERROR", b"Unable to send netinfo message to provigil-db.");
                    return false;
                }
                (0, b"")
            }
            b"process" | b"process_end" => (self.processes(&mut c, ev, &root), b"Unable to send processes information to provigil-db."),
            _ if k.starts_with(b"dbsync_") => (sync(&mut c, ev, has_agent, k, &mut root), b"(9201): Unable to send dbsync information to provigil-db."),
            _ => {
                c.host.log("DEBUG", &[&b"Invalid message type: "[..], k, b"."].concat());
                return false;
            }
        };
        if result < 0 {
            c.host.log("DEBUG", failure);
            return false;
        }
        true
    }

    /// The `<kind>_end` message of a scan: `<what> del <scan>`.
    fn end(c: &mut Cx, root: &Json, end: &[u8], what: &[u8], scan: i32, failed: &mut Failed) -> i32 {
        let Some(t) = text(root.get("type")) else {
            c.host.log("ERROR", b"Invalid message. Type not found.");
            return -1;
        };
        if t == end {
            if failed.skip(scan) {
                return 0;
            }
            let q = c.with_scan(what, scan);
            if !c.query_ok(&q, 6144) {
                failed.set(scan);
                return -1;
            }
        }
        0
    }

    fn ports(&mut self, c: &mut Cx, ev: &mut Event, root: &Json) -> i32 {
        let scan_j = root.get("ID");
        if !number(scan_j) {
            return -1;
        }
        let scan = int(scan_j);
        let p = root.get("port");
        if !object(p) {
            return Self::end(c, root, b"port_end", b"port del ", scan, &mut self.ports);
        }
        if self.ports.skip(scan) {
            return 0;
        }
        let g = |k: &str| p.and_then(|x| x.get(k));
        let mut q = c.start(b"port save");
        join(&mut q, Some(scan.to_string().as_bytes()), b' ');
        c.s(ev, &mut q, root.get("timestamp"), None);
        c.s(ev, &mut q, g("protocol"), Some("port.protocol"));
        c.s(ev, &mut q, g("local_ip"), Some("port.local_ip"));
        // any member counts here, through its int value
        match g("local_port") {
            Some(j) => {
                let v = int(Some(j)).to_string().into_bytes();
                c.fill(ev, "port.local_port", &v);
                join(&mut q, Some(&v), b'|');
            }
            None => join(&mut q, Some(b"NULL"), b'|'),
        }
        c.s(ev, &mut q, g("remote_ip"), Some("port.remote_ip"));
        for (k, f) in [("remote_port", "port.remote_port"), ("tx_queue", "port.tx_queue"), ("rx_queue", "port.rx_queue"), ("inode", "port.inode")] {
            c.n(ev, &mut q, g(k), f);
        }
        c.s(ev, &mut q, g("state"), Some("port.state"));
        c.n(ev, &mut q, g("PID"), "port.pid");
        c.s(ev, &mut q, g("process"), Some("port.process"));
        if !c.query_ok(&q.unwrap_or_default(), 6144) {
            self.ports.set(scan);
            return -1;
        }
        0
    }

    fn packages(&mut self, c: &mut Cx, ev: &mut Event, root: &Json) -> i32 {
        let scan_j = root.get("ID");
        if !number(scan_j) {
            return -1;
        }
        let scan = int(scan_j);
        let p = root.get("program");
        if !object(p) {
            return Self::end(c, root, b"program_end", b"package del ", scan, &mut self.packages);
        }
        if self.packages.skip(scan) {
            return 0;
        }
        let g = |k: &str| p.and_then(|x| x.get(k));
        let mut q = c.start(b"package save");
        join(&mut q, Some(scan.to_string().as_bytes()), b' ');
        c.s(ev, &mut q, root.get("timestamp"), None);
        for (k, f) in [("format", "program.format"), ("name", "program.name"), ("priority", "program.priority"), ("group", "program.section")] {
            c.s(ev, &mut q, g(k), Some(f));
        }
        c.n(ev, &mut q, g("size"), "program.size");
        for (k, f) in [
            ("vendor", "program.vendor"),
            ("install_time", "program.install_time"),
            ("version", "program.version"),
            ("architecture", "program.architecture"),
            ("multi-arch", "program.multiarch"),
            ("source", "program.source"),
            ("description", "program.description"),
            ("location", "program.location"),
        ] {
            c.s(ev, &mut q, g(k), Some(f));
        }
        // the package reference: name, version and architecture
        let reference = sha1_hex(&[text(g("name")).unwrap_or(b""), text(g("version")).unwrap_or(b""), text(g("architecture")).unwrap_or(b"")]);
        join(&mut q, Some(&reference), b'|');
        if !c.query_ok(&q.unwrap_or_default(), 6144) {
            self.packages.set(scan);
            return -1;
        }
        0
    }

    fn processes(&mut self, c: &mut Cx, ev: &mut Event, root: &Json) -> i32 {
        let scan_j = root.get("ID");
        if !number(scan_j) {
            return -1;
        }
        let scan = int(scan_j);
        let p = root.get("process");
        if !object(p) {
            return Self::end(c, root, b"process_end", b"process del ", scan, &mut self.processes);
        }
        if self.processes.skip(scan) {
            return 0;
        }
        let g = |k: &str| p.and_then(|x| x.get(k));
        let mut q = c.start(b"process save");
        join(&mut q, Some(scan.to_string().as_bytes()), b' ');
        c.s(ev, &mut q, root.get("timestamp"), None);
        c.n(ev, &mut q, g("pid"), "process.pid");
        c.s(ev, &mut q, g("name"), Some("process.name"));
        c.s(ev, &mut q, g("state"), Some("process.state"));
        for (k, f) in [("ppid", "process.ppid"), ("utime", "process.utime"), ("stime", "process.stime")] {
            c.n(ev, &mut q, g(k), f);
        }
        c.s(ev, &mut q, g("cmd"), Some("process.cmd"));
        match g("argvs").filter(|a| matches!(a, Json::Array(_))) {
            Some(a) => {
                let mut args = None;
                for x in a.children() {
                    join(&mut args, text(Some(x)), b',');
                }
                c.fill(ev, "process.args", &a.print());
                join(&mut q, args.as_deref(), b'|');
            }
            None => join(&mut q, Some(b"NULL"), b'|'),
        }
        for (k, f) in [("euser", "process.euser"), ("ruser", "process.ruser"), ("suser", "process.suser"), ("egroup", "process.egroup"), ("rgroup", "process.rgroup"), ("sgroup", "process.sgroup"), ("fgroup", "process.fgroup")] {
            c.s(ev, &mut q, g(k), Some(f));
        }
        for (k, f) in [
            ("priority", "process.priority"),
            ("nice", "process.nice"),
            ("size", "process.size"),
            ("vm_size", "process.vm_size"),
            ("resident", "process.resident"),
            ("share", "process.share"),
            ("start_time", "process.start_time"),
            ("pgrp", "process.pgrp"),
            ("session", "process.session"),
            ("nlwp", "process.nlwp"),
            ("tgid", "process.tgid"),
            ("tty", "process.tty"),
            ("processor", "process.processor"),
        ] {
            c.n(ev, &mut q, g(k), f);
        }
        if !c.query_ok(&q.unwrap_or_default(), 6144) {
            self.processes.set(scan);
            return -1;
        }
        0
    }
}

fn network(c: &mut Cx, ev: &mut Event, root: &Json) -> i32 {
    let iface = root.get("iface");
    if !object(iface) {
        let Some(t) = text(root.get("type")) else {
            c.host.log("ERROR", b"Invalid message. Type not found.");
            return -1;
        };
        if t != b"network_end" {
            c.host.log("ERROR", b"at decode_netinfo(): unknown type found.");
            return -1;
        }
        let scan = root.get("ID");
        if !number(scan) {
            c.host.log("ERROR", b"at decode_netinfo(): missing scan ID.");
            return -1;
        }
        let q = c.with_scan(b"netinfo del ", int(scan));
        return if c.query_ok(&q, 6144) { 0 } else { -1 };
    }
    let g = |k: &str| iface.and_then(|x| x.get(k));
    let scan = root.get("ID");
    let scan_text = if number(scan) { int(scan).to_string().into_bytes() } else { b"NULL".to_vec() };
    let name = text(g("name"));

    let mut q = c.start(b"netinfo save");
    join(&mut q, Some(&scan_text), b' ');
    c.s(ev, &mut q, root.get("timestamp"), None);
    for (k, f) in [("name", "netinfo.iface.name"), ("adapter", "netinfo.iface.adapter"), ("type", "netinfo.iface.type"), ("state", "netinfo.iface.state")] {
        c.s(ev, &mut q, g(k), Some(f));
    }
    c.n(ev, &mut q, g("MTU"), "netinfo.iface.mtu");
    c.s(ev, &mut q, g("MAC"), Some("netinfo.iface.mac"));
    for (k, f) in [
        ("tx_packets", "netinfo.iface.tx_packets"),
        ("rx_packets", "netinfo.iface.rx_packets"),
        ("tx_bytes", "netinfo.iface.tx_bytes"),
        ("rx_bytes", "netinfo.iface.rx_bytes"),
        ("tx_errors", "netinfo.iface.tx_errors"),
        ("rx_errors", "netinfo.iface.rx_errors"),
        ("tx_dropped", "netinfo.iface.tx_dropped"),
        ("rx_dropped", "netinfo.iface.rx_dropped"),
    ] {
        c.n(ev, &mut q, g(k), f);
    }
    if !c.query_ok(&q.unwrap_or_default(), 6144) {
        return -1;
    }
    for (key, proto, v6) in [("IPv4", &b"0"[..], false), ("IPv6", b"1", true)] {
        let ip = g(key);
        if !object(ip) {
            continue;
        }
        let prefix = if v6 { "netinfo.iface.ipv6" } else { "netinfo.iface.ipv4" };
        let gi = |k: &str| ip.and_then(|x| x.get(k));
        let mut q = c.start(b"netproto save");
        join(&mut q, Some(&scan_text), b' ');
        join(&mut q, Some(name.unwrap_or(b"NULL")), b'|');
        join(&mut q, Some(proto), b'|');
        c.s(ev, &mut q, gi("gateway"), Some(&format!("{prefix}.gateway")));
        c.s(ev, &mut q, gi("dhcp"), Some(&format!("{prefix}.dhcp")));
        c.n(ev, &mut q, gi("metric"), &format!("{prefix}.metric"));
        if !c.query_ok(&q.unwrap_or_default(), 6144) {
            return -1;
        }
        let Some(Json::Array(addresses)) = gi("address") else { continue };
        let (mut all_addr, mut all_mask, mut all_broad) = (None, None, None);
        for (i, a) in addresses.iter().enumerate() {
            let Some(a) = text(Some(a)) else { break };
            let mut q = c.start(b"netaddr save");
            join(&mut q, Some(&scan_text), b' ');
            join(&mut q, Some(name.unwrap_or(b"NULL")), b'|');
            join(&mut q, Some(proto), b'|');
            join(&mut q, Some(a), b'|');
            join(&mut all_addr, Some(a), b',');
            for (item, all) in [(nth(gi("netmask"), i), &mut all_mask), (nth(gi("broadcast"), i), &mut all_broad)] {
                // IPv4 needs a text, IPv6 any member (a non-text adds nothing)
                let present = if v6 { item.is_some() } else { text(item).is_some() };
                if present {
                    join(&mut q, text(item), b'|');
                    join(all, text(item), b',');
                } else {
                    join(&mut q, Some(b"NULL"), b'|');
                }
            }
            if !c.query_ok(&q.unwrap_or_default(), 6144) {
                return -1;
            }
        }
        for (all, k) in [(all_addr, "address"), (all_mask, "netmask"), (all_broad, "broadcast")] {
            if let Some(a) = all {
                c.fill(ev, &format!("{prefix}.{k}"), &csv_json(&a));
            }
        }
    }
    0
}

fn os(c: &mut Cx, ev: &mut Event, root: &Json) -> i32 {
    let inv = root.get("inventory");
    if !object(inv) {
        return 0;
    }
    let g = |k: &str| inv.and_then(|x| x.get(k));
    let scan = root.get("ID");
    let mut q = c.start(b"osinfo set");
    join(&mut q, Some(&if number(scan) { int(scan).to_string().into_bytes() } else { b"NULL".to_vec() }), b' ');
    c.s(ev, &mut q, root.get("timestamp"), None);
    for (k, f) in [
        ("hostname", "os.hostname"),
        ("architecture", "os.architecture"),
        ("os_name", "os.name"),
        ("os_version", "os.version"),
        ("os_codename", "os.codename"),
        ("os_major", "os.major"),
        ("os_minor", "os.minor"),
        ("os_build", "os.build"),
        ("os_platform", "os.platform"),
        ("sysname", "os.sysname"),
        ("release", "os.release"),
        ("version", "os.release_version"),
        ("os_release", "os.os_release"),
        ("os_patch", "os.patch"),
        ("os_display_version", "os.display_version"),
    ] {
        c.s(ev, &mut q, g(k), Some(f));
    }
    if c.query_ok(&q.unwrap_or_default(), 6144) {
        0
    } else {
        -1
    }
}

fn hardware(c: &mut Cx, ev: &mut Event, root: &Json) -> i32 {
    let inv = root.get("inventory");
    if !object(inv) {
        return 0;
    }
    let g = |k: &str| inv.and_then(|x| x.get(k));
    let scan = root.get("ID");
    let mut q = c.start(b"hardware save");
    join(&mut q, Some(&if number(scan) { int(scan).to_string().into_bytes() } else { b"NULL".to_vec() }), b' ');
    c.s(ev, &mut q, root.get("timestamp"), None);
    c.s(ev, &mut q, g("board_serial"), Some("hardware.serial"));
    c.s(ev, &mut q, g("cpu_name"), Some("hardware.cpu_name"));
    c.n(ev, &mut q, g("cpu_cores"), "hardware.cpu_cores");
    c.f(ev, &mut q, g("cpu_mhz"), "hardware.cpu_mhz");
    c.f(ev, &mut q, g("ram_total"), "hardware.ram_total");
    c.f(ev, &mut q, g("ram_free"), "hardware.ram_free");
    c.n(ev, &mut q, g("ram_usage"), "hardware.ram_usage");
    if c.query_ok(&q.unwrap_or_default(), 6144) {
        0
    } else {
        -1
    }
}

fn hotfix(c: &mut Cx, ev: &mut Event, root: &Json) -> i32 {
    let scan_j = root.get("ID");
    if !number(scan_j) {
        return -1;
    }
    let scan = int(scan_j).to_string().into_bytes();
    if let (Some(h), Some(t)) = (text(root.get("hotfix")), text(root.get("timestamp"))) {
        let q = first([&b"agent "[..], &c.agent, b" hotfix save ", &scan, b"|", t, b"|", h, b"|"].concat(), 1024);
        c.fill(ev, "hotfix", h);
        return if c.query_ok(&q, 4096) { 0 } else { -1 };
    }
    let Some(t) = text(root.get("type")) else {
        c.host.log("ERROR", b"Invalid message. Type not found.");
        return -1;
    };
    if t == b"hotfix_end" {
        let q = first([&b"agent "[..], &c.agent, b" hotfix del ", &scan].concat(), 1023);
        if !c.query_ok(&q, 4096) {
            return -1;
        }
    }
    0
}

fn fields_of(table: &[u8]) -> Option<Fields> {
    Some(match table {
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

/// `dbsync_<table>`: the change goes to provigil-db and its values become fields.
fn sync(c: &mut Cx, ev: &mut Event, has_agent: bool, kind: &[u8], root: &mut Json) -> i32 {
    if !has_agent {
        return -1;
    }
    let p = kind.iter().position(|&x| x == b'_').unwrap_or(kind.len());
    let table = kind.get(p + 1..).unwrap_or(b"").to_vec();
    if table.is_empty() {
        c.host.log("ERROR", &[&b"(1283): Incorrect prefix message, message type: "[..], &kind[..p], b"."].concat());
        return -1;
    }
    let Some(fields) = fields_of(&table) else {
        c.host.log("ERROR", &[&b"(1287): Incorrect/unknown type value "[..], &table, b"."].concat());
        return -1;
    };
    let Some(operation) = text(root.get("operation")).map(<[u8]>::to_vec).filter(|_| object(root.get("data"))) else {
        c.host.log("ERROR", &[&b"(1284): Incorrect/unknown operation, type: "[..], &table, b"."].concat());
        return -1;
    };
    let data = root.get_mut("data").expect("checked above");
    if table == b"network_address" {
        // the protocol number becomes its name (the member takes the lookup's spelling)
        let mut mapped = false;
        if let Json::Object(m) = data {
            if let Some(e) = m.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(b"proto")) {
                if let Json::Number { int, .. } = e.1 {
                    *e = (b"proto".to_vec(), Json::String(if int == 0 { b"ipv4".to_vec() } else { b"ipv6".to_vec() }));
                    mapped = true;
                }
            }
        }
        if !mapped {
            c.host.log("DEBUG2", b"Field 'proto' cannot be obtained.");
            c.host.log("DEBUG2", b"Error while mapping 'proto' field value.");
        }
    }
    let printed = data.print_unformatted();
    let q = first([&b"agent "[..], &c.agent, b" dbsync ", &table, b" ", &operation, b" ", &printed].concat(), printed.len() + 256);
    for &(key, field) in fields {
        let Some(field) = field else { continue };
        let v = match data.get(key) {
            Some(Json::String(s)) => s.clone(),
            Some(Json::Number { double, int }) => first(if f64::from(*int) == *double { int.to_string().into_bytes() } else { provigil_json::fmt_f6(*double).into_bytes() }, 63),
            _ => Vec::new(),
        };
        c.fill(ev, field, &v);
    }
    c.fill(ev, "operation_type", &operation);
    match c.host.db_query(&q, 1024) {
        Ok(a) => {
            if a.starts_with(b"err") {
                c.host.log("DEBUG", b"(1286): provigil-db query error, check wdb logs.");
            } else if !a.starts_with(b"ok ") {
                c.host.log("ERROR", b"(1285): Response with unexpected content.");
            }
            0
        }
        Err(code) => {
            c.host.log("DEBUG2", b"(1288): provigil-db query execution error.");
            code
        }
    }
}
