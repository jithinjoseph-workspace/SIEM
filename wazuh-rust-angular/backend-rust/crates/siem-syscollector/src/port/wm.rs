//! The syscollector wodle: `wm_sys_t`, `wm_syscollector_read`
//! (config/wmodules-syscollector.c), `wm_sys_dump`, `wm_sys_main`,
//! `wm_sys_stop` and `wm_sync_message` (wm_syscollector.c).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use siem_cjson::Json;
use siem_config::messages;
use siem_xml::{OsXml, XmlNode};

use super::syscollector::{LogFn, LogLevel, Options, ReportFn, SysInfoSource, Syscollector};

/// `WM_SYS_CONTEXT.name`
pub const NAME: &str = "syscollector";
/// `WM_SYS_LOCATION`
pub const WM_SYS_LOCATION: &str = "syscollector";
/// `WM_SYSCOLLECTOR_DEFAULT_INTERVAL` (`W_HOUR_SECONDS`)
pub const DEFAULT_INTERVAL: u32 = 3600;
/// `SYSCOLLECTOR_MQ`
pub const SYSCOLLECTOR_MQ: u8 = b'd';
/// `DBSYNC_MQ`
pub const DBSYNC_MQ: u8 = b'5';

/// `SYSCOLLECTOR_DB_DISK_PATH`, `SYSCOLLECTOR_NORM_CONFIG_DISK_PATH`, `SYSCOLLECTOR_NORM_TYPE`
#[cfg(windows)]
pub const DB_DISK_PATH: &str = ".\\local.db";
#[cfg(windows)]
pub const NORM_CONFIG_DISK_PATH: &str = ".\\norm_config.json";
#[cfg(windows)]
pub const NORM_TYPE: &str = "windows";
#[cfg(target_os = "macos")]
pub const DB_DISK_PATH: &str = "queue/syscollector/db/local.db";
#[cfg(target_os = "macos")]
pub const NORM_CONFIG_DISK_PATH: &str = "queue/syscollector/norm_config.json";
#[cfg(target_os = "macos")]
pub const NORM_TYPE: &str = "macos";
#[cfg(all(unix, not(target_os = "macos")))]
pub const DB_DISK_PATH: &str = "queue/syscollector/db/local.db";
#[cfg(all(unix, not(target_os = "macos")))]
pub const NORM_CONFIG_DISK_PATH: &str = "queue/syscollector/norm_config.json";
#[cfg(all(unix, not(target_os = "macos")))]
pub const NORM_TYPE: &str = "linux";

/// `wm_sys_t`
#[derive(Clone, Debug)]
pub struct WmSys {
    pub interval: u32,
    pub enabled: bool,
    pub scan_on_start: bool,
    pub hwinfo: bool,
    pub netinfo: bool,
    pub osinfo: bool,
    pub programinfo: bool,
    pub hotfixinfo: bool,
    pub portsinfo: bool,
    pub allports: bool,
    pub procinfo: bool,
    pub groups: bool,
    pub users: bool,
    pub services: bool,
    pub browser_extensions: bool,
    /// `sync.sync_max_eps`
    pub sync_max_eps: i64,
}

impl Default for WmSys {
    /// The defaults `wm_syscollector_read` sets when it allocates the module.
    fn default() -> Self {
        WmSys {
            interval: DEFAULT_INTERVAL,
            enabled: true,
            scan_on_start: true,
            hwinfo: true,
            netinfo: true,
            osinfo: true,
            programinfo: true,
            hotfixinfo: cfg!(windows),
            portsinfo: true,
            allports: false,
            procinfo: true,
            groups: true,
            users: true,
            services: true,
            browser_extensions: true,
            sync_max_eps: 10,
        }
    }
}

/// The messages of the reader: (level, text); Err is the `merror` that
/// makes it return OS_INVALID.
pub type ReadLog = Vec<(&'static str, String)>;

/// C `strtoul(s, &end, 0)` with a 32-bit `unsigned long`: (value, rest).
fn strtoul0(s: &str) -> (u32, &str) {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && (b[i] == b' ' || (b'\t'..=b'\r').contains(&b[i])) {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut base = 10u32;
    if i + 1 < b.len() && b[i] == b'0' && (b[i + 1] == b'x' || b[i + 1] == b'X') && i + 2 < b.len() && b[i + 2].is_ascii_hexdigit() {
        base = 16;
        i += 2;
    } else if i < b.len() && b[i] == b'0' {
        base = 8;
    }
    let start = i;
    let mut v: u64 = 0;
    let mut overflow = false;
    while i < b.len() {
        let d = match b[i] {
            c @ b'0'..=b'9' => (c - b'0') as u32,
            c @ b'a'..=b'z' => (c - b'a' + 10) as u32,
            c @ b'A'..=b'Z' => (c - b'A' + 10) as u32,
            _ => break,
        };
        if d >= base {
            break;
        }
        v = v * base as u64 + d as u64;
        if v > u32::MAX as u64 {
            overflow = true;
        }
        i += 1;
    }
    if i == start {
        // no digits: value 0, end at the start of the string
        return (0, s);
    }
    let v = if overflow {
        u32::MAX
    } else if neg {
        (v as u32).wrapping_neg()
    } else {
        v as u32
    };
    (v, &s[i..])
}

/// C `strtol(s, &end, 10)` with a 32-bit `long`: (value, rest is empty).
fn strtol10(s: &str) -> (i64, bool) {
    let t = s.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let n = digits.bytes().take_while(|c| c.is_ascii_digit()).count();
    if n == 0 {
        return (0, s.is_empty());
    }
    let v: i128 = digits[..n].parse().unwrap_or(i128::MAX);
    let v = if neg { -v } else { v };
    let v = v.clamp(i32::MIN as i128, i32::MAX as i128) as i64;
    (v, digits[n..].is_empty())
}

/// `parse_synchronization_section`
fn parse_synchronization(sys: &mut WmSys, nodes: &[XmlNode], log: &mut ReadLog) {
    for n in nodes {
        // strncmp(element, "max_eps", 7)
        if n.element.as_bytes().starts_with(b"max_eps") {
            let content = n.content.as_deref().unwrap_or("");
            let (v, end_ok) = strtol10(content);
            if !(0..=1_000_000).contains(&v) || !end_ok {
                log.push(("WARNING", messages::xml_valueerr(&n.element, content)));
            } else {
                sys.sync_max_eps = v;
            }
        } else {
            log.push(("WARNING", messages::xml_invelem(&n.element)));
        }
    }
}

/// `wm_syscollector_read(xml, node, module)`: updates `sys` (created with
/// the defaults by the caller the first time).
pub fn wm_syscollector_read(xml: &OsXml, nodes: Option<&[XmlNode]>, sys: &mut WmSys, log: &mut ReadLog) -> Result<(), String> {
    let Some(nodes) = nodes else { return Ok(()) };
    let yes_no = |n: &XmlNode, tag: &str| -> Result<bool, String> {
        match n.content.as_deref() {
            Some("yes") => Ok(true),
            Some("no") => Ok(false),
            _ => Err(format!("Invalid content for tag '{tag}' at module '{NAME}'.")),
        }
    };
    for n in nodes {
        let el = n.element.as_str();
        match el {
            "" => return Err(messages::XML_ELEMNULL.into()),
            "interval" => {
                let c = n.content.as_deref().unwrap_or("");
                let err = || format!("Invalid interval at module '{NAME}'");
                if c.is_empty() {
                    return Err(err());
                }
                let (v, rest) = strtoul0(c);
                if v == 0 || v == u32::MAX {
                    return Err(err());
                }
                sys.interval = match rest.as_bytes().first() {
                    Some(b'd') => v.wrapping_mul(86400),
                    Some(b'h') => v.wrapping_mul(3600),
                    Some(b'm') => v.wrapping_mul(60),
                    Some(b's') | None => v,
                    _ => return Err(err()),
                };
            }
            "scan_on_start" => sys.scan_on_start = yes_no(n, el)?,
            "disabled" => sys.enabled = !yes_no(n, el)?,
            "network" => sys.netinfo = yes_no(n, el)?,
            "os" => sys.osinfo = yes_no(n, el)?,
            "hardware" => sys.hwinfo = yes_no(n, el)?,
            "packages" => sys.programinfo = yes_no(n, el)?,
            "hotfixes" => {
                if cfg!(windows) {
                    sys.hotfixinfo = yes_no(n, el)?;
                } else {
                    log.push(("WARNING", "The 'hotfixes' option is only available on Windows systems. Ignoring it.".into()));
                }
            }
            "processes" => sys.procinfo = yes_no(n, el)?,
            "ports" => {
                if !n.attributes.is_empty() {
                    if n.attributes[0] == "all" {
                        match n.values[0].as_str() {
                            "no" => sys.allports = false,
                            "yes" => sys.allports = true,
                            _ => return Err(format!("Invalid content for attribute '{}' at module '{NAME}'.", n.attributes[0])),
                        }
                    } else {
                        return Err(format!("Invalid attribute for tag 'ports' at module '{NAME}'."));
                    }
                }
                match n.content.as_deref().unwrap_or("") {
                    "yes" => sys.portsinfo = true,
                    "no" => sys.portsinfo = false,
                    _ => return Err(format!("Invalid content for tag 'ports' at module '{NAME}'.")),
                }
            }
            "groups" => sys.groups = yes_no(n, el)?,
            "users" => sys.users = yes_no(n, el)?,
            "services" => match n.content.as_deref().unwrap_or("") {
                "yes" => sys.services = true,
                "no" => sys.services = false,
                _ => return Err(format!("Invalid content for tag 'services' at module '{NAME}'.")),
            },
            "browser_extensions" => sys.browser_extensions = yes_no(n, el)?,
            "synchronization" => {
                if let Some(ch) = xml.get_elements_by_node(Some(n)) {
                    parse_synchronization(sys, &ch, log);
                }
            }
            _ => return Err(format!("No such tag '{el}' at module '{NAME}'.")),
        }
    }
    Ok(())
}

/// `wm_sys_dump`
pub fn wm_sys_dump(sys: &WmSys) -> Json {
    let yn = |b: bool| Json::string(if b { "yes" } else { "no" });
    let mut w = Json::object();
    w.add("disabled", yn(!sys.enabled));
    w.add("scan-on-start", yn(sys.scan_on_start));
    w.add("interval", Json::number(sys.interval as f64));
    w.add("network", yn(sys.netinfo));
    w.add("os", yn(sys.osinfo));
    w.add("hardware", yn(sys.hwinfo));
    w.add("packages", yn(sys.programinfo));
    w.add("ports", yn(sys.portsinfo));
    w.add("ports_all", yn(sys.allports));
    w.add("processes", yn(sys.procinfo));
    w.add("groups", yn(sys.groups));
    w.add("users", yn(sys.users));
    w.add("services", yn(sys.services));
    w.add("browser_extensions", yn(sys.browser_extensions));
    if cfg!(windows) {
        w.add("hotfixes", yn(sys.hotfixinfo));
    }
    w.add("sync_max_eps", Json::number(sys.sync_max_eps as f64));
    let mut root = Json::object();
    root.add("syscollector", w);
    root
}

/// How the module reaches the rest of the agent.
pub struct Env {
    /// `wm_sendmsg_ex(usec, queue, msg, WM_SYS_LOCATION, loc, predicate)`:
    /// < 0 when the message could not be sent.
    pub send: Box<dyn Fn(i64, &[u8], u8, &dyn Fn() -> bool) -> i32 + Send + Sync>,
    /// `MQReconnectPredicated(DEFAULTQUEUE, predicate)` (Unix; Windows sends in-process).
    pub reconnect: Box<dyn Fn(&dyn Fn() -> bool) -> i32 + Send + Sync>,
    /// `mtinfo` / `mterror` / ... with the module's tag.
    pub log: Box<dyn Fn(LogLevel, &str) + Send + Sync>,
    /// `DEFAULTQUEUE`
    pub default_queue: String,
    /// CLIENT: "wazuh-agentd" in the reconnection message, else "wazuh-analysisd".
    pub peer: &'static str,
}

/// The module's runtime state (`running`, `shutdown_process_started`, ...).
pub struct WmSysModule {
    pub sys: parking_lot::Mutex<WmSys>,
    running: AtomicBool,
    shutdown_started: Arc<AtomicBool>,
    reconnect: parking_lot::Mutex<()>,
    need_shutdown_wait: parking_lot::Mutex<bool>,
    stop_cv: parking_lot::Condvar,
    started: AtomicBool,
}

impl WmSysModule {
    pub fn new(sys: WmSys) -> Arc<WmSysModule> {
        Arc::new(WmSysModule {
            sys: parking_lot::Mutex::new(sys),
            running: AtomicBool::new(false),
            shutdown_started: Arc::new(AtomicBool::new(false)),
            reconnect: parking_lot::Mutex::new(()),
            need_shutdown_wait: parking_lot::Mutex::new(false),
            stop_cv: parking_lot::Condvar::new(),
            started: AtomicBool::new(false),
        })
    }

    /// `wm_sys_send_message(data, queue_id)`
    fn send_message(self: &Arc<Self>, env: &Env, max_eps: i64, data: &[u8], queue_id: u8) {
        let stop = || self.shutdown_started.load(Ordering::SeqCst);
        if stop() {
            return;
        }
        let eps = 1_000_000 / max_eps;
        if (env.send)(eps, data, queue_id, &stop) < 0 {
            (env.log)(LogLevel::Debug, &format!("Unable to send message to '{}' ({} might be down). Attempting to reconnect.", env.default_queue, env.peer));
            let _g = self.reconnect.lock();
            if !stop() && (env.send)(eps, data, queue_id, &stop) < 0 && (env.reconnect)(&stop) >= 0 {
                (env.log)(LogLevel::Info, &format!("Successfully reconnected to '{}'", env.default_queue));
                if (env.send)(eps, data, queue_id, &stop) < 0 {
                    (env.log)(LogLevel::Error, &format!("Unable to send message to '{}' after a successfull reconnection...", env.default_queue));
                }
            }
        }
    }

    /// `wm_sys_main(sys)`: runs until `stop`.
    pub fn main(self: &Arc<Self>, env: Arc<Env>, info: Arc<dyn SysInfoSource>, base_log: LogFn) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let sys = self.sys.lock().clone();
        if !sys.enabled {
            (env.log)(LogLevel::Info, "Module disabled. Exiting...");
            return;
        }
        (env.log)(LogLevel::Debug, "Starting Syscollector.");
        *self.need_shutdown_wait.lock() = true;
        self.started.store(true, Ordering::SeqCst);
        // 0 from the configuration: the default 10
        let max_eps = if sys.sync_max_eps != 0 { sys.sync_max_eps } else { 10 };
        (env.log)(LogLevel::Debug, &String::from_utf8_lossy(&wm_sys_dump(&sys).print_unformatted()));
        let (m1, e1) = (self.clone(), env.clone());
        let diff: ReportFn = Arc::new(move |d| m1.send_message(&e1, max_eps, d, SYSCOLLECTOR_MQ));
        let (m2, e2) = (self.clone(), env.clone());
        let dbsync: ReportFn = Arc::new(move |d| m2.send_message(&e2, max_eps, d, DBSYNC_MQ));
        // DBSync::initialize(callbackErrorLogWrapper)
        let l = base_log.clone();
        siem_dbsync::initialize(move |m: &[u8]| l(LogLevel::Error, &String::from_utf8_lossy(m)));
        let o = Options {
            interval: sys.interval,
            scan_on_start: sys.scan_on_start,
            hardware: sys.hwinfo,
            os: sys.osinfo,
            network: sys.netinfo,
            packages: sys.programinfo,
            ports: sys.portsinfo,
            ports_all: sys.allports,
            processes: sys.procinfo,
            hotfixes: sys.hotfixinfo,
            groups: sys.groups,
            users: sys.users,
            services: sys.services,
            browser_extensions: sys.browser_extensions,
            notify_on_first_scan: false,
        };
        if let Err(e) = Syscollector::instance().init(info, diff, dbsync, base_log.clone(), DB_DISK_PATH, NORM_CONFIG_DISK_PATH, NORM_TYPE, o) {
            base_log(LogLevel::Error, &e);
        }
        self.started.store(false, Ordering::SeqCst);
        (env.log)(LogLevel::Info, "Module finished.");
        let mut w = self.need_shutdown_wait.lock();
        *w = false;
        self.stop_cv.notify_all();
    }

    /// `wm_sys_stop`
    pub fn stop(&self, env: &Env) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        (env.log)(LogLevel::Info, "Stop received for Syscollector.");
        self.shutdown_started.store(true, Ordering::SeqCst);
        Syscollector::instance().destroy();
        let mut w = self.need_shutdown_wait.lock();
        while *w {
            self.stop_cv.wait(&mut w);
        }
    }

    /// `wm_sync_message(data)` (`syscollector_sync_message`): 0 or -1.
    pub fn sync_message(&self, data: &str) -> i32 {
        if !self.started.load(Ordering::SeqCst) {
            return 0;
        }
        match Syscollector::instance().push(data) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    }
}
