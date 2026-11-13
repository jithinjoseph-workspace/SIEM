//! Reading the analysis settings: the internal options and the parts of `etc/ossec.conf` this
//! service uses (spec section 2.29). The file is read in four passes, as the order matters for
//! what a failing section stops: active responses and commands (then `etc/shared/ar.conf` is
//! written), global + ruleset + alerts + cluster + socket, labels, rule_test.

use std::path::{Path, PathBuf};

use provigil_daemon::xml::{self, Node};
use provigil_regex::{OsIp, OsMatch, OsRegex};

type Result<T> = std::result::Result<T, String>;

// ---------------------------------------------------------------- message texts

fn invalid_element(e: &str) -> String {
    format!("(1230): Invalid element in the configuration: '{e}'.")
}
fn invalid_attribute(a: &str, e: &str) -> String {
    format!("(1233): Invalid attribute '{a}' in the configuration: '{e}'.")
}
fn invalid_value(e: &str, v: &str) -> String {
    format!("(1235): Invalid value for element '{e}': {v}.")
}
fn config_error(file: &str) -> String {
    format!("(1202): Configuration error at '{file}'.")
}

// ---------------------------------------------------------------- numbers

/// Leading white space, a sign and digits, saturating; (value, bytes used; 0 when no digit).
fn leading_number(s: &str) -> (i64, usize) {
    let b = s.as_bytes();
    let mut i = b.iter().take_while(|c| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')).count();
    let neg = matches!(b.get(i), Some(b'-'));
    if matches!(b.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    let digits = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return (0, 0);
    }
    let mut v: i128 = 0;
    for &c in &b[i..i + digits] {
        v = (v * 10 + (c - b'0') as i128).min(i64::MAX as i128 + 1);
    }
    let v = if neg { -v } else { v };
    (v.clamp(i64::MIN as i128, i64::MAX as i128) as i64, i + digits)
}

fn int(s: &str) -> i32 {
    leading_number(s).0.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// Seconds with an optional unit w/d/h/m/s; -1 when invalid.
fn seconds(s: &str) -> i64 {
    let (n, used) = leading_number(s);
    if n < 0 || n == i64::MAX {
        return -1;
    }
    let unit = match s.as_bytes().get(used) {
        None => 1,
        Some(b'w') => 604_800,
        Some(b'd') => 86_400,
        Some(b'h') => 3_600,
        Some(b'm') => 60,
        Some(b's') => 1,
        Some(_) => return -1,
    };
    n.checked_mul(unit).filter(|v| *v >= 0).unwrap_or(-1)
}

/// A number and an optional unit character right after it: None when no number.
fn number_and_unit(s: &str) -> Option<(i64, Option<char>)> {
    let (n, used) = leading_number(s);
    if used == 0 {
        return None;
    }
    Some((n, s[used..].chars().next()))
}

fn digits(s: &str) -> bool {
    provigil_regex::str_is_num(s)
}

fn yes_no(e: &str, v: &str) -> Result<bool> {
    match v {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err(invalid_value(e, v)),
    }
}

fn small(e: &str, v: &str) -> Result<u8> {
    if !digits(v) {
        return Err(invalid_value(e, v));
    }
    Ok(int(v) as u8)
}

// ---------------------------------------------------------------- internal options

/// `group.name=value` lines: `etc/local_internal_options.conf` first, then
/// `etc/internal_options.conf`.
pub struct InternalOptions {
    files: [PathBuf; 2],
}

impl InternalOptions {
    pub fn new(home: &Path) -> InternalOptions {
        let etc = home.join("etc");
        InternalOptions { files: [etc.join("local_internal_options.conf"), etc.join("internal_options.conf")] }
    }

    fn find(path: &Path, group: &str, name: &str) -> Option<String> {
        let data = std::fs::read(path).ok()?;
        #[cfg(windows)]
        let data = provigil_fileop::crt::text_in(&data);
        // lines are read in pieces of at most 1,023 bytes
        let mut pieces = Vec::new();
        let mut rest = &data[..];
        while !rest.is_empty() {
            let n = rest.iter().take(1023).position(|&c| c == b'\n').map_or(rest.len().min(1023), |p| p + 1);
            pieces.push(&rest[..n]);
            rest = &rest[n..];
        }
        for piece in pieces {
            let line = String::from_utf8_lossy(piece);
            if matches!(line.as_bytes().first(), Some(b'#' | b' ' | b'\n')) {
                continue;
            }
            let Some((g, rest)) = line.split_once('.') else { continue };
            if g != group {
                continue;
            }
            let Some((n, v)) = rest.split_once('=') else { continue };
            if n.trim_end_matches(' ') != name {
                continue;
            }
            let mut v = v.trim_start_matches(' ').to_string();
            if let Some(p) = v.rfind('\n') {
                v.truncate(p);
            }
            if let Some(p) = v.rfind('\r') {
                v.truncate(p);
            }
            return Some(v);
        }
        None
    }

    pub fn text(&self, group: &str, name: &str) -> Option<String> {
        self.files.iter().find_map(|f| Self::find(f, group, name))
    }

    pub fn number(&self, group: &str, name: &str, min: i32, max: i32) -> Result<i32> {
        let v = self.text(group, name).ok_or_else(|| format!("(2301): Definition not found for: '{group}.{name}'."))?;
        let n = int(&v);
        if !v.bytes().all(|c| c.is_ascii_digit()) || n < min || n > max {
            return Err(format!("(2302): Invalid definition for {group}.{name}: '{v}'."));
        }
        Ok(n)
    }
}

/// The analysis internal options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Internal {
    pub debug: i32,
    pub decoder_order_size: i32,
    pub log_fw: i32,
    pub label_cache_maxage: i32,
    pub show_hidden_labels: i32,
    pub min_rotate_interval: i32,
    pub default_timeframe: i32,
    pub fts_list_size: i32,
    pub fts_min_size_for_str: i32,
    pub rule_matching_threads: i32,
    pub stats_maxdiff: i32,
    pub stats_mindiff: i32,
    pub stats_percent_diff: i32,
    pub rlimit_nofile: i32,
    pub state_interval: i32,
    pub event_threads: i32,
    pub geoip_jsonout: i32,
    /// syscheck, syscollector, rootcheck, sca, hostinfo, winevt, dbsync
    pub decoder_threads: [i32; 7],
    /// archives, alerts, statistical, firewall, fts, syscheck, syscollector, rootcheck, sca,
    /// hostinfo, winevt, event, output, dbsync, upgrade
    pub queues: [usize; 15],
}

pub const QUEUE_NAMES: [&str; 15] = [
    "archives_queue_size",
    "alerts_queue_size",
    "statistical_queue_size",
    "firewall_queue_size",
    "fts_queue_size",
    "decode_syscheck_queue_size",
    "decode_syscollector_queue_size",
    "decode_rootcheck_queue_size",
    "decode_sca_queue_size",
    "decode_hostinfo_queue_size",
    "decode_winevt_queue_size",
    "decode_event_queue_size",
    "decode_output_queue_size",
    "dbsync_queue_size",
    "upgrade_queue_size",
];

impl Internal {
    pub fn read(o: &InternalOptions) -> Result<Internal> {
        let n = |k: &str, min, max| o.number("analysisd", k, min, max);
        let mut i = Internal {
            debug: n("debug", 0, 2)?,
            decoder_order_size: n("decoder_order_size", 32, 1024)?,
            log_fw: n("log_fw", 0, 1)?,
            label_cache_maxage: n("label_cache_maxage", 0, 60)?,
            show_hidden_labels: n("show_hidden_labels", 0, 1)?,
            min_rotate_interval: n("min_rotate_interval", 10, 86400)?,
            default_timeframe: n("default_timeframe", 60, 3600)?,
            fts_list_size: n("fts_list_size", 12, 512)?,
            fts_min_size_for_str: n("fts_min_size_for_str", 6, 128)?,
            rule_matching_threads: n("rule_matching_threads", 0, 32)?,
            stats_maxdiff: n("stats_maxdiff", 10, 999999)?,
            stats_mindiff: n("stats_mindiff", 10, 999999)?,
            stats_percent_diff: n("stats_percent_diff", 5, 9999)?,
            rlimit_nofile: n("rlimit_nofile", 1024, 1048576)?,
            state_interval: n("state_interval", 0, 86400)?,
            event_threads: n("event_threads", 0, 32)?,
            geoip_jsonout: n("geoip_jsonout", 0, 1)?,
            decoder_threads: [0; 7],
            queues: [0; 15],
        };
        // in this order: the first failing option is the one reported
        for (t, k) in i.decoder_threads.iter_mut().zip(["syscheck", "syscollector", "rootcheck", "sca", "hostinfo", "winevt", "dbsync"]) {
            *t = n(&format!("{k}_threads"), 0, 32)?;
        }
        for (q, k) in i.queues.iter_mut().zip(QUEUE_NAMES) {
            *q = n(k, 128, 2_000_000)? as usize;
        }
        Ok(i)
    }
}

// ---------------------------------------------------------------- settings

/// `<global>` and the `<syscheck>` options this service reads.
#[derive(Debug, Clone, Default)]
pub struct Global {
    pub logall: bool,
    pub logall_json: bool,
    pub stats: u8,
    pub integrity: u8,
    pub rootcheck: u8,
    pub hostinfo: u8,
    pub mailnotify: i16,
    pub prelude: bool,
    pub prelude_profile: Option<String>,
    pub prelude_log_level: u8,
    pub geoipdb: Option<String>,
    pub zeromq_output: bool,
    pub zeromq_uri: Option<String>,
    pub zeromq_server_cert: Option<String>,
    pub zeromq_client_cert: Option<String>,
    pub jsonout_output: bool,
    pub alerts_log: bool,
    pub update_check: bool,
    pub memory_size: i32,
    pub white_list: Vec<OsIp>,
    pub hostname_white_list: Vec<OsMatch>,
    pub custom_alert_output: Option<String>,
    pub forward_to: Vec<String>,
    pub rotate_interval: i32,
    pub min_rotate_interval: i32,
    pub max_output_size: i64,
    pub queue_size: i64,
    pub eps_maximum: u32,
    pub eps_timeframe: u32,
    pub eps_maximum_found: bool,
    pub agents_disconnection_time: i64,
    pub agents_disconnection_alert_time: i64,
    pub cti_url: Option<String>,
    pub geoip_db_path: Option<String>,
    pub geoip6_db_path: Option<String>,
    pub syscheck_auto_ignore: bool,
    pub syscheck_ignore_frequency: i32,
    pub syscheck_ignore_time: i32,
    pub syscheck_alert_new: bool,
    pub syscheck_ignore: Vec<String>,
    pub mailbylevel: u8,
    pub logbylevel: u8,
    pub cluster_name: Option<String>,
    pub node_name: Option<String>,
    pub node_type: Option<String>,
    pub hide_cluster_info: bool,
    pub label_cache_maxage: i32,
    pub show_hidden_labels: i32,
    /// active responses: 0 none, bit 1 on agents, bit 2 on the manager
    pub ar: i32,
}

/// The vulnerability feed address used when `<cti-url>` is not set.
pub const CTI_URL_DEFAULT: &str = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0";

fn white_list_is_ip(s: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^!?[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2}([0-9](\.[0-9]{1,3}){3})?)?$").unwrap()).is_match(s)
}

/// `x@y` with letters, digits, `.`, `_`, `-` or `\` on both sides of the `@`.
fn looks_like_email(s: &str) -> bool {
    let b = s.as_bytes();
    let ok = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'\\');
    (1..b.len().saturating_sub(1)).any(|i| b[i] == b'@' && ok(b[i - 1]) && ok(b[i + 1]))
}

impl Global {
    fn defaults() -> Global {
        Global {
            stats: 4,
            integrity: 8,
            rootcheck: 8,
            hostinfo: 8,
            jsonout_output: true,
            alerts_log: true,
            memory_size: 8192,
            mailnotify: -1,
            syscheck_alert_new: true,
            syscheck_ignore_frequency: 10,
            syscheck_ignore_time: 3600,
            mailbylevel: 7,
            logbylevel: 1,
            label_cache_maxage: 10,
            hide_cluster_info: true,
            ..Global::default()
        }
    }

    fn read(&mut self, items: &[Node]) -> Result<()> {
        if self.cti_url.is_none() {
            self.cti_url = Some(CTI_URL_DEFAULT.into());
        }
        self.update_check = true;
        for n in items {
            let (e, v) = (n.name.as_str(), n.content.as_str());
            match e {
                "custom_alert_output" => self.custom_alert_output = Some(v.into()),
                "forward_to" => {
                    let count = v.matches(',').count() + 1;
                    if let Some(l) = provigil_regex::str_break(',', v, count) {
                        self.forward_to = l.iter().map(|t| t.trim_matches(|c| matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')).to_string()).collect();
                    }
                }
                "email_notification" => self.mailnotify = yes_no(e, v)? as i16,
                "prelude_output" => self.prelude = yes_no(e, v)?,
                "geoipdb" => self.geoipdb = Some(v.into()),
                "prelude_profile" => self.prelude_profile = Some(v.into()),
                "prelude_log_level" => self.prelude_log_level = small(e, v)?,
                "zeromq_output" => self.zeromq_output = yes_no(e, v)?,
                "zeromq_uri" => self.zeromq_uri = Some(v.into()),
                "zeromq_server_cert" => self.zeromq_server_cert = Some(v.into()),
                "zeromq_client_cert" => self.zeromq_client_cert = Some(v.into()),
                "jsonout_output" => self.jsonout_output = yes_no(e, v)?,
                "alerts_log" => self.alerts_log = yes_no(e, v)?,
                "logall" => self.logall = yes_no(e, v)?,
                "logall_json" => self.logall_json = yes_no(e, v)?,
                "update_check" => self.update_check = yes_no(e, v)?,
                "compress_alerts" => {}
                "integrity_checking" => self.integrity = small(e, v)?,
                "rootkit_detection" => self.rootcheck = small(e, v)?,
                "host_information" => self.hostinfo = small(e, v)?,
                "stats" => self.stats = small(e, v)?,
                "memory_size" => {
                    if !digits(v) {
                        return Err(invalid_value(e, v));
                    }
                    self.memory_size = int(v);
                }
                "limits" => {
                    if n.children.is_empty() {
                        return Err(invalid_element(e));
                    }
                    self.read_limits(&n.children)?;
                }
                "white_list" => {
                    if white_list_is_ip(v) {
                        match provigil_regex::is_valid_ip(v) {
                            (0, _) | (_, None) => return Err(format!("(1237): Invalid ip address: '{v}'.")),
                            (_, Some(ip)) => self.white_list.push(ip),
                        }
                    } else {
                        match OsMatch::compile(v, 0) {
                            Ok(m) => self.hostname_white_list.push(m),
                            Err(err) => return Err(format!("(1450): Syntax error on regex: '{v}': {}.", err as i32)),
                        }
                    }
                }
                "email_to" => {
                    if !looks_like_email(v) {
                        return Err(format!("Invalid Email address: {v}."));
                    }
                }
                // e-mail settings belong to the mail service
                "email_from" | "email_reply_to" | "email_idsname" | "smtp_server" | "helo_server" | "email_maxperhour" | "email_log_source" => {}
                "geoip_db_path" => self.geoip_db_path = Some(v.into()),
                "geoip6_db_path" => self.geoip6_db_path = Some(v.into()),
                "rotate_interval" => {
                    let Some((n, unit)) = number_and_unit(v) else { return Err(invalid_value(e, v)) };
                    let n = n as i32;
                    let r = match unit {
                        None | Some('s') => n,
                        Some('d') => n.wrapping_mul(86400),
                        Some('h') => n.wrapping_mul(3600),
                        Some('m') => n.wrapping_mul(60),
                        Some(_) => return Err(invalid_value(e, v)),
                    };
                    self.rotate_interval = r;
                    if r < 0 {
                        return Err(invalid_value(e, v));
                    }
                }
                "max_output_size" => {
                    let Some((n, unit)) = number_and_unit(v) else { return Err(invalid_value(e, v)) };
                    self.max_output_size = match unit {
                        None | Some('B' | 'b') => n,
                        Some('G' | 'g') => n.wrapping_mul(1 << 30),
                        Some('M' | 'm') => n.wrapping_mul(1 << 20),
                        Some('K' | 'k') => n.wrapping_mul(1 << 10),
                        Some(_) => return Err(invalid_value(e, v)),
                    };
                }
                "queue_size" => {
                    let (n, used) = leading_number(v);
                    self.queue_size = n;
                    if used != v.len() || n < 1 {
                        return Err("Invalid value for option '<queue_size>'".into());
                    }
                }
                "agents_disconnection_time" => {
                    let t = seconds(v);
                    if t < 1 {
                        return Err(invalid_value(e, v));
                    }
                    self.agents_disconnection_time = t;
                }
                "agents_disconnection_alert_time" => {
                    let t = seconds(v);
                    if t < 0 {
                        return Err(invalid_value(e, v));
                    }
                    self.agents_disconnection_alert_time = t;
                }
                "cti-url" => {
                    if !v.is_empty() {
                        self.cti_url = Some(v.into());
                    }
                }
                _ => return Err(invalid_element(e)),
            }
        }
        Ok(())
    }

    fn read_limits(&mut self, items: &[Node]) -> Result<()> {
        for n in items.iter().filter(|n| n.name == "eps") {
            if n.children.is_empty() {
                return Err(invalid_element("eps"));
            }
            self.eps_maximum_found = false;
            self.eps_timeframe = 10;
            for c in &n.children {
                let v = c.content.as_str();
                match c.name.as_str() {
                    "maximum" => {
                        if !digits(v) {
                            return Err(invalid_value(&c.name, v));
                        }
                        self.eps_maximum_found = true;
                        self.eps_maximum = int(v) as u32;
                        if self.eps_maximum > 100_000 {
                            return Err(invalid_value(&c.name, v));
                        }
                    }
                    "timeframe" => {
                        if !digits(v) {
                            return Err(invalid_value(&c.name, v));
                        }
                        self.eps_timeframe = int(v) as u32;
                        if !(1..=3600).contains(&self.eps_timeframe) {
                            return Err(invalid_value(&c.name, v));
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn read_syscheck(&mut self, items: &[Node]) -> Result<()> {
        for n in items {
            let (e, v) = (n.name.as_str(), n.content.as_str());
            match e {
                "auto_ignore" => {
                    self.syscheck_auto_ignore = yes_no(e, v)?;
                    // the numbers are taken from the first and second attribute, whichever names them
                    let first = n.attributes.first().map_or("", |a| a.1.as_str());
                    let second = n.attributes.get(1).map_or("", |a| a.1.as_str());
                    for (a, value) in &n.attributes {
                        match a.as_str() {
                            "frequency" => {
                                if !digits(first) {
                                    return Err(invalid_value(a, value));
                                }
                                self.syscheck_ignore_frequency = int(first);
                                if !(1..=99).contains(&self.syscheck_ignore_frequency) {
                                    return Err(invalid_value(a, value));
                                }
                            }
                            "timeframe" => {
                                if !digits(value) {
                                    return Err(invalid_value(a, value));
                                }
                                self.syscheck_ignore_time = int(second);
                                if !(0..=43200).contains(&self.syscheck_ignore_time) {
                                    return Err(invalid_value(a, value));
                                }
                            }
                            _ => return Err(invalid_attribute(a, e)),
                        }
                    }
                }
                "alert_new_files" => self.syscheck_alert_new = yes_no(e, v)?,
                "ignore" => self.syscheck_ignore.push(v.into()),
                _ => {}
            }
        }
        Ok(())
    }
}

/// `<cluster>`: what alerts show about the node.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cluster {
    pub name: Option<String>,
    pub node_name: Option<String>,
    pub node_type: Option<String>,
    pub hidden: bool,
}

const NAME_CHARACTERS: &str = r##"!"#$%&'-.0123456789:<=>?ABCDEFGHIJKLMNOPQRESTUVWXYZ[\]^_abcdefghijklmnopqrstuvwxyz{|}~"##;

impl Cluster {
    fn read(&mut self, items: &[Node], warn: &mut Vec<String>) -> Result<()> {
        self.hidden = false;
        let mut disabled = false;
        let check_name = |what: &str, v: &str| -> Result<()> {
            if v.is_empty() {
                return Err(format!("{} is empty in configuration", if what == "cluster" { "Cluster name" } else { "Node name" }));
            }
            if !v.bytes().all(|b| NAME_CHARACTERS.as_bytes().contains(&b)) {
                return Err(format!("Detected a not allowed character in {what} name: \"{v}\". Characters allowed: \"{NAME_CHARACTERS}\"."));
            }
            Ok(())
        };
        for n in items {
            let (e, v) = (n.name.as_str(), n.content.as_str());
            match e {
                "name" => {
                    check_name("cluster", v)?;
                    self.name = Some(v.into());
                }
                "node_name" => {
                    check_name("node", v)?;
                    self.node_name = Some(v.into());
                }
                "node_type" => {
                    if v.is_empty() {
                        return Err("Node type is empty in configuration".into());
                    }
                    if !matches!(v, "worker" | "client" | "master") {
                        return Err(format!("Detected a not allowed node type '{v}'. Valid types are 'master' and 'worker'."));
                    }
                    self.node_type = Some(v.into());
                }
                "key" | "socket_timeout" | "connection_timeout" | "nodes" | "port" | "bind_addr" => {}
                "disabled" => {
                    if v != "yes" && v != "no" {
                        return Err(format!("Detected a not allowed value for disabled tag '{v}'. Valid values are 'yes' and 'no'."));
                    }
                    disabled |= v == "yes";
                }
                "hidden" => self.hidden = yes_no(e, v)?,
                "interval" => warn.push("Detected a deprecated configuration for cluster. Interval option is not longer available.".into()),
                "haproxy_helper" => {
                    for c in &n.children {
                        let cv = c.content.as_str();
                        // the "missing" checks look at the helper's own text, not the option's
                        match c.name.as_str() {
                            "haproxy_disabled" if cv != "yes" && cv != "no" => {
                                return Err(format!("Detected an invalid value for the disabled tag '{}'. Valid values are 'yes' and 'no'.", c.name))
                            }
                            "haproxy_address" if v.is_empty() => return Err("HAProxy address is missing in the configuration".into()),
                            "haproxy_user" if v.is_empty() => return Err("HAProxy user is missing in the configuration".into()),
                            "haproxy_password" if v.is_empty() => return Err("HAProxy password is missing in the configuration".into()),
                            "haproxy_protocol" if cv != "http" && cv != "https" => {
                                return Err(format!("Detected an invalid value for the haproxy_protocol tag '{}'. Valid values are 'http' and 'https'.", c.name))
                            }
                            "haproxy_disabled" | "haproxy_protocol" | "frequency" | "haproxy_address" | "haproxy_port" | "haproxy_user" | "haproxy_password" | "haproxy_cert" | "client_cert"
                            | "client_cert_key" | "client_cert_password" | "haproxy_backend" | "haproxy_resolver" | "excluded_nodes" | "agent_chunk_size" | "agent_reconnection_time"
                            | "agent_reconnection_stability_time" | "imbalance_tolerance" | "remove_disconnected_node_after" => {}
                            other => return Err(invalid_element(other)),
                        }
                    }
                }
                _ => return Err(invalid_element(e)),
            }
            if disabled {
                self.hidden = true;
            }
        }
        Ok(())
    }
}

/// A `<socket>` that alerts can be forwarded to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub name: String,
    pub location: String,
    pub tcp: bool,
    pub prefix: Option<String>,
}

/// Backslashes removed, each keeping the byte after it.
fn unescape(s: &str) -> String {
    let mut out = Vec::new();
    let mut it = s.bytes();
    while let Some(c) = it.next() {
        match c {
            b'\\' => match it.next() {
                Some(n) => out.push(n),
                None => break,
            },
            c => out.push(c),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_socket(items: &[Node], list: &mut Vec<Socket>) -> Result<()> {
    let (mut name, mut location, mut tcp, mut prefix) = (None, None, false, None);
    for n in items {
        let (e, v) = (n.name.as_str(), n.content.as_str());
        match e {
            "name" if v == "agent" => return Err("Invalid socket name 'agent'.".into()),
            "name" => name = Some(v.to_string()),
            "location" => location = Some(v.to_string()),
            "mode" if v.eq_ignore_ascii_case("tcp") => tcp = true,
            "mode" if v.eq_ignore_ascii_case("udp") => tcp = false,
            "mode" => return Err(format!("Socket type '{v}' is not valid at <{e}>. Should be 'udp' or 'tcp'.")),
            "prefix" => prefix = Some(unescape(v)),
            _ => return Err(invalid_element(e)),
        }
    }
    let name = name.filter(|n| !n.is_empty()).ok_or("(1954): Missing field 'name' for socket.")?;
    let location = location.filter(|l| !l.is_empty()).ok_or("(1955): Missing field 'location' for socket.")?;
    list.push(Socket { name, location, tcp, prefix });
    Ok(())
}

/// A manager label (`<labels>`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Label {
    pub key: String,
    pub value: String,
    pub hidden: bool,
    pub system: bool,
}

fn read_labels(items: &[Node], labels: &mut Vec<Label>, warn: &mut Vec<String>) -> Result<()> {
    let r = (|| {
        for n in items {
            if n.name != "label" {
                return Err(invalid_element(&n.name));
            }
            let (mut key, mut hidden, mut system) = (None, false, false);
            for (a, v) in &n.attributes {
                match a.as_str() {
                    "key" if v.is_empty() => return Err("Label with empty key.".to_string()),
                    "key" => {
                        if v.starts_with('_') {
                            warn.push(format!("Label keys starting with \"_\"  are reserved for internal use. Skipping label '{v}'."));
                            system = true;
                        }
                        key = Some(v.as_str());
                    }
                    "hidden" => hidden = yes_no_attr(a, v)?,
                    _ => {}
                }
            }
            if system {
                continue;
            }
            let key = key.ok_or("Expected 'key' attribute for label.")?;
            if n.content.is_empty() {
                warn.push(format!("Label '{key}' is empty."));
            }
            let l = Label { key: key.into(), value: n.content.clone(), hidden, system: false };
            match labels.iter_mut().find(|x| x.key == key) {
                Some(x) => *x = l,
                None => labels.push(l),
            }
        }
        Ok(())
    })();
    if r.is_err() {
        labels.clear();
    }
    r
}

fn yes_no_attr(a: &str, v: &str) -> Result<bool> {
    match v {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err(format!("Invalid content for attribute '{a}'.")),
    }
}

// ---------------------------------------------------------------- active responses

pub const ALL_AGENTS: i32 = 1;
pub const REMOTE_AGENT: i32 = 2;
pub const SPECIFIC_AGENT: i32 = 4;
pub const AS_ONLY: i32 = 8;
pub const REMOTE_AR: i32 = 1;
pub const LOCAL_AR: i32 = 2;

/// The start of `ar.conf`: the restart commands older agents look up by these names.
pub const AR_CONF_START: &str = "restart-ossec0 - restart-ossec.sh - 0\nrestart-ossec0 - restart-ossec.cmd - 0\n\
restart-wazuh0 - restart-ossec.sh - 0\nrestart-wazuh0 - restart-ossec.cmd - 0\n\
restart-wazuh0 - restart-wazuh - 0\nrestart-wazuh0 - restart-wazuh.exe - 0\n";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Command {
    pub name: String,
    pub executable: String,
    pub timeout_allowed: bool,
    pub extra_args: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Response {
    /// command name + timeout
    pub name: String,
    pub command: String,
    /// index in [`ActiveResponses::commands`]
    pub command_index: usize,
    pub location: i32,
    pub level: i32,
    pub timeout: i32,
    pub agent_id: Option<String>,
    pub rules_id: Option<String>,
    pub rules_group: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ActiveResponses {
    pub commands: Vec<Command>,
    pub responses: Vec<Response>,
    /// [`REMOTE_AR`] | [`LOCAL_AR`]
    pub flags: i32,
    pub ar_conf: String,
    /// What was skipped or adjusted, in order.
    pub notes: Vec<String>,
}

impl ActiveResponses {
    fn read_command(&mut self, items: &[Node]) -> Result<()> {
        let mut c = Command::default();
        let (mut name, mut executable) = (None, None);
        for n in items {
            let (e, v) = (n.name.as_str(), n.content.as_str());
            match e {
                "name" if v.starts_with('!') => return Err(invalid_value(e, v)),
                "name" => name = Some(v.to_string()),
                "expect" => self.notes.push("The <expect> tag is deprecated since version 4.2.0.".into()),
                "executable" => executable = Some(v.to_string()),
                "timeout_allowed" => c.timeout_allowed = yes_no(e, v)?,
                "extra_args" => c.extra_args = Some(v.into()),
                _ => return Err(invalid_element(e)),
            }
        }
        let (Some(name), Some(executable)) = (name, executable) else {
            return Err("(1280): Missing command options. You must specify a 'name' and 'executable'.".into());
        };
        self.commands.push(Command { name, executable, ..c });
        Ok(())
    }

    fn read_response(&mut self, items: &[Node]) -> Result<()> {
        let mut r = Response::default();
        let (mut command, mut location, mut repeated, mut disabled) = (None, None, false, false);
        for n in items {
            let (e, v) = (n.name.as_str(), n.content.as_str());
            match e {
                "command" => command = Some(v.to_string()),
                "location" => location = Some(v.to_string()),
                "agent_id" => r.agent_id = Some(v.into()),
                "rules_id" => r.rules_id = Some(v.into()),
                "rules_group" => r.rules_group = Some(v.into()),
                "level" => {
                    if !digits(v) {
                        return Err(invalid_value(e, v));
                    }
                    r.level = int(v);
                    if !(0..=20).contains(&r.level) {
                        return Err(invalid_value(e, v));
                    }
                }
                "timeout" => r.timeout = int(v),
                "disabled" => disabled |= yes_no(e, v)?,
                "repeated_offenders" => repeated = true,
                "ca_store" => {}
                _ => return Err(invalid_element(e)),
            }
        }
        // a disabled block skips only itself; the old reader also cleared the flags of the blocks before it (A-9)
        if disabled {
            if let Some(c) = &command {
                self.notes.push(format!("active response command '{c}' is disabled"));
            }
            return Ok(());
        }
        let (Some(command), Some(location)) = (command.filter(|c| !c.is_empty()), location.filter(|l| !l.is_empty())) else {
            self.notes.push("Command or location missing".into());
            if repeated {
                return Ok(());
            }
            return Err("(1281): Missing options in the active response configuration. ".into());
        };
        let at = |p: &str| provigil_regex::os_regex(p, &location);
        if at("AS|analysisd|analysis-server|server") {
            r.location |= AS_ONLY;
        }
        if at("local") {
            r.location |= REMOTE_AGENT;
        }
        if at("defined-agent") {
            let Some(id) = &r.agent_id else {
                self.notes.push("'defined-agent' agent_id not defined".into());
                return Err("(1304): No agent defined for response.".into());
            };
            if int(id) == 0 {
                self.notes.push("'defined-agent' is 0".into());
                self.notes.push("(1306): Invalid agent ID. Use location=server to run AR on the manager.".into());
                return Ok(());
            }
            r.location |= SPECIFIC_AGENT;
        }
        if at("all|any") {
            r.location |= ALL_AGENTS;
        }
        if r.location == 0 {
            self.notes.push("No location defined".into());
            return Err(format!("(1302): Invalid active response location: '{location}'."));
        }
        let Some(i) = self.commands.iter().position(|c| c.name == command) else {
            self.notes.push("Invalid command".into());
            return Err(format!("(1303): Invalid command '{command}' in the active response."));
        };
        let c = &self.commands[i];
        if r.timeout != 0 && !c.timeout_allowed {
            self.notes.push(format!("(1305): Timeout not allowed for command: '{}'.", c.name));
            r.timeout = 0;
        }
        let mut name = format!("{}{}", c.name, r.timeout);
        name.truncate(255);
        self.ar_conf.push_str(&format!("{name} - {} - {}\n", c.executable, r.timeout));
        let on_agents = r.location & (ALL_AGENTS | REMOTE_AGENT | SPECIFIC_AGENT) != 0;
        let on_manager = r.location & (AS_ONLY | REMOTE_AGENT) != 0;
        if on_agents {
            self.flags |= REMOTE_AR;
        }
        if on_manager {
            self.flags |= LOCAL_AR;
        }
        self.responses.push(Response { name, command, command_index: i, ..r });
        Ok(())
    }
}

// ---------------------------------------------------------------- logtest

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logtest {
    pub enabled: bool,
    pub threads: u16,
    pub max_sessions: u16,
    pub session_timeout: i64,
}

impl Default for Logtest {
    fn default() -> Self {
        Logtest { enabled: true, threads: 1, max_sessions: 64, session_timeout: 900 }
    }
}

pub fn cpu_count() -> u16 {
    std::thread::available_parallelism().map_or(1, |n| n.get() as u16)
}

impl Logtest {
    fn read(&mut self, items: &[Node], warn: &mut Vec<String>) -> Result<()> {
        for n in items {
            let (e, v) = (n.name.as_str(), n.content.as_str());
            let small = || match leading_number(v) {
                (n, used) if used == v.len() && (0..=65534).contains(&n) => Some(n),
                _ => None,
            };
            match e {
                "enabled" => self.enabled = yes_no(e, v)?,
                "threads" if v == "auto" => self.threads = cpu_count(),
                "threads" => {
                    let n = small().ok_or_else(|| invalid_value(e, v))?;
                    self.threads = if n > 128 {
                        warn.push("(7000): Number of logtest threads too high. Only creates 128 threads".into());
                        128
                    } else {
                        n as u16
                    };
                }
                "max_sessions" => {
                    let n = small().ok_or_else(|| invalid_value(e, v))?;
                    self.max_sessions = if n > 500 {
                        warn.push("(7001): Number of maximum users connected in logtest too high. Only allows 500 users".into());
                        500
                    } else {
                        n as u16
                    };
                }
                "session_timeout" => {
                    let t = seconds(v);
                    if t <= 0 {
                        return Err(invalid_value(e, v));
                    }
                    self.session_timeout = if t > 31_536_000 {
                        warn.push("(7002): Number of maximum user timeouts in logtest too high. Only allows 31536000s maximum timeouts".into());
                        31_536_000
                    } else {
                        t
                    };
                }
                _ => return Err(invalid_element(e)),
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- ruleset files

pub const RULE_DIR: &str = "ruleset/rules";
pub const DECODER_DIR: &str = "ruleset/decoders";

/// Which decoder, rule and list files to load, and the alert levels of `<alerts>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ruleset {
    pub decoders: Vec<String>,
    pub rules: Vec<String>,
    pub lists: Vec<String>,
    pub email_level: Option<u8>,
    pub log_level: Option<u8>,
}

pub fn resolve(home: &Path, p: &str) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        home.join(p)
    }
}

fn file_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

impl Ruleset {
    /// One `<ruleset>` block.
    pub fn read(&mut self, items: &[Node], home: &Path) -> Result<()> {
        let (mut skip_rules, mut skip_decoders) = (Vec::new(), Vec::new());
        let (mut decoder_dirs, mut rule_dirs) = (Vec::new(), Vec::new());
        for n in items {
            let (e, v) = (n.name.as_str(), n.content.as_str());
            let in_dir = |dir: &str| if v.contains('/') { v.to_string() } else { format!("{dir}/{v}") };
            match e {
                "rule_include" => self.rules.push(in_dir(RULE_DIR)),
                "decoder_include" => self.decoders.push(in_dir(DECODER_DIR)),
                "list" => self.lists.push(v.into()),
                "rule_exclude" => skip_rules.push(v.to_string()),
                "decoder_exclude" => skip_decoders.push(v.to_string()),
                "decoder_dir" | "rule_dir" => {
                    // with attributes, only a `pattern` one gives the pattern (the last one wins)
                    let pattern = if n.attributes.is_empty() {
                        Some(".xml$".to_string())
                    } else {
                        n.attributes.iter().filter(|(a, _)| a.eq_ignore_ascii_case("pattern")).last().map(|(_, p)| p.clone())
                    };
                    if e == "decoder_dir" { &mut decoder_dirs } else { &mut rule_dirs }.push((v.to_string(), pattern));
                }
                _ => return Err(invalid_element(e)),
            }
        }
        if decoder_dirs.is_empty() {
            decoder_dirs.push((DECODER_DIR.into(), Some(".xml$".into())));
        }
        if rule_dirs.is_empty() {
            rule_dirs.push((RULE_DIR.into(), Some(".xml$".into())));
        }
        for (decoders, dirs) in [(true, &decoder_dirs), (false, &rule_dirs)] {
            for (dir, pattern) in dirs {
                let Some(re) = pattern.as_deref().and_then(|p| OsRegex::compile(p, 0).ok()) else {
                    return Err(config_error(if decoders { "pattern in decoder_dir does not compile" } else { "pattern in rules_dir does not compile" }));
                };
                let (skip, list) = if decoders { (&skip_decoders, &mut self.decoders) } else { (&skip_rules, &mut self.rules) };
                let names: Vec<String> = std::fs::read_dir(resolve(home, dir)).into_iter().flatten().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
                for name in names {
                    let path = format!("{dir}/{name}");
                    let known = |l: &[String]| l.iter().any(|x| *x == path || *x == name);
                    if !known(skip) && !known(list) && re.is_match(&path) {
                        list.push(path);
                    }
                }
            }
        }
        // stable: equal names keep their order
        self.rules.sort_by(|a, b| file_name(a).as_bytes().cmp(file_name(b).as_bytes()));
        self.decoders.sort_by(|a, b| file_name(a).as_bytes().cmp(file_name(b).as_bytes()));
        Ok(())
    }

    /// One `<alerts>` block.
    pub fn read_alerts(&mut self, items: &[Node]) -> Result<()> {
        for n in items {
            let (e, v) = (n.name.as_str(), n.content.as_str());
            if e == "email_alert_level" || e == "log_alert_level" {
                if !digits(v) {
                    return Err(invalid_value(e, v));
                }
                let level = Some(int(v) as u8);
                if e == "email_alert_level" {
                    self.email_level = level;
                } else {
                    self.log_level = level;
                }
            }
        }
        Ok(())
    }
}

/// The `<ruleset>` (and with `alerts`, `<alerts>`) blocks of a configuration file, for
/// logtest sessions and ruleset reloads. `shown` is the file name in messages.
pub fn ruleset_from_file(conf: &Path, shown: &str, home: &Path, alerts: bool, msgs: &mut crate::messages::Messages) -> Option<Ruleset> {
    use crate::messages as m;
    let roots = match xml::read_file(conf) {
        Ok(r) => r,
        Err(e) => {
            msgs.error(m::xml_failed(shown, &e.message, e.line));
            return None;
        }
    };
    if roots.is_empty() {
        msgs.error(format!("There are no configuration blocks inside of '{shown}'"));
        return None;
    }
    let mut r = Ruleset::default();
    for root in roots.iter().filter(|n| n.name == "ossec_config") {
        for section in &root.children {
            // any section without options fails the read
            if section.children.is_empty() {
                msgs.error(m::NULL_ELEMENT);
                msgs.error(m::config_error(shown));
                return None;
            }
            let result = match section.name.as_str() {
                "ruleset" => r.read(&section.children, home),
                "alerts" if alerts => r.read_alerts(&section.children),
                _ => Ok(()),
            };
            if let Err(e) = result {
                msgs.error(e);
                msgs.error(m::config_error(shown));
                return None;
            }
        }
    }
    Some(r)
}

// ---------------------------------------------------------------- the whole file

/// Everything this service reads at start.
#[derive(Debug, Clone)]
pub struct Config {
    pub home: PathBuf,
    pub global: Global,
    pub ruleset: Ruleset,
    pub cluster: Cluster,
    pub labels: Vec<Label>,
    pub sockets: Vec<Socket>,
    pub ar: ActiveResponses,
    pub logtest: Logtest,
    pub internal: Internal,
    /// Warnings, in the order they were found.
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    Responses,
    Main,
    Labels,
    RuleTest,
}

/// Every section name of the file: (name, must have child elements).
const SECTIONS: &[(&str, bool)] = &[
    ("global", true),
    ("email_alerts", true),
    ("database_output", true),
    ("syslog_output", true),
    ("integration", true),
    ("agentless", true),
    ("ruleset", true),
    ("syscheck", false),
    ("rootcheck", false),
    ("alerts", true),
    ("localfile", true),
    ("remote", true),
    ("client", true),
    ("anti_tampering", true),
    ("client_buffer", false),
    ("command", true),
    ("active-response", true),
    ("reports", true),
    ("wodle", false),
    ("sca", false),
    ("vulnerability-detection", false),
    ("vulnerability-detector", false),
    ("indexer", false),
    ("gcp-pubsub", false),
    ("gcp-bucket", false),
    ("fluent-forward", false),
    ("auth", false),
    ("labels", true),
    ("logging", false),
    ("cluster", true),
    ("socket", true),
    ("rule_test", true),
    ("agent-upgrade", true),
    ("task-manager", true),
    ("wdb", true),
    ("github", true),
    ("office365", true),
    ("ms-graph", true),
];

impl Config {
    /// Reads `cfgfile` (`home` resolves relative paths); `write_ar_conf` also writes
    /// `etc/shared/ar.conf`.
    pub fn load(home: &Path, cfgfile: &Path, write_ar_conf: bool) -> Result<Config> {
        let internal = Internal::read(&InternalOptions::new(home))?;
        let mut c = Config {
            home: home.to_path_buf(),
            global: Global::defaults(),
            ruleset: Ruleset::default(),
            cluster: Cluster { hidden: true, ..Cluster::default() },
            labels: Vec::new(),
            sockets: Vec::new(),
            ar: ActiveResponses { ar_conf: AR_CONF_START.into(), ..ActiveResponses::default() },
            logtest: Logtest::default(),
            internal,
            warnings: Vec::new(),
        };
        c.pass(cfgfile, Pass::Responses)?;
        if write_ar_conf {
            let p = home.join("etc/shared/ar.conf");
            if let Some(d) = p.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            std::fs::write(&p, &c.ar.ar_conf)
                .map_err(|e| format!("(1103): Could not open file '{}' due to [({})-({})].", p.display(), e.raw_os_error().unwrap_or(0), e))?;
        }
        c.pass(cfgfile, Pass::Main)?;
        c.pass(cfgfile, Pass::Labels)?;
        c.pass(cfgfile, Pass::RuleTest)?;

        let g = &mut c.global;
        if let Some(v) = c.ruleset.email_level {
            g.mailbylevel = v;
        }
        if let Some(v) = c.ruleset.log_level {
            g.logbylevel = v;
        }
        g.min_rotate_interval = c.internal.min_rotate_interval;
        g.memory_size = g.memory_size.max(2048);
        if g.rotate_interval != 0 && (g.rotate_interval < g.min_rotate_interval || g.rotate_interval > 86400) {
            return Err(format!("Rotate interval setting must be between {} seconds and one day.", g.min_rotate_interval));
        }
        if g.max_output_size != 0 && !(1_000_000..=1_099_511_627_776).contains(&g.max_output_size) {
            return Err("Maximum output size must be between 1 MiB and 1 TiB.".into());
        }
        if c.ruleset.rules.is_empty() || c.ruleset.decoders.is_empty() {
            let mut d = Ruleset::default();
            let _ = d.read(&[], home);
            if c.ruleset.decoders.is_empty() {
                c.ruleset.decoders = d.decoders;
            }
            if c.ruleset.rules.is_empty() {
                c.ruleset.rules = d.rules;
            }
        }
        g.cluster_name = c.cluster.name.clone();
        g.node_name = c.cluster.node_name.clone();
        g.node_type = c.cluster.node_type.clone();
        g.hide_cluster_info = c.cluster.hidden;
        g.label_cache_maxage = c.internal.label_cache_maxage;
        g.show_hidden_labels = c.internal.show_hidden_labels;
        g.ar = c.ar.flags.max(0);
        Ok(c)
    }

    fn pass(&mut self, cfgfile: &Path, pass: Pass) -> Result<()> {
        let shown = cfgfile.display().to_string();
        let roots = xml::read_file(cfgfile).map_err(|e| format!("(1226): Error reading XML file '{shown}': {} (line {}).", e.message, e.line))?;
        for root in &roots {
            if root.name != "ossec_config" {
                return Err(invalid_element(&root.name));
            }
            for s in &root.children {
                self.section(s, pass)?;
            }
        }
        Ok(())
    }

    fn section(&mut self, s: &Node, pass: Pass) -> Result<()> {
        let has = !s.children.is_empty();
        let e = s.name.as_str();
        if !SECTIONS.iter().any(|(n, needs)| *n == e && (has || !needs)) {
            return Err(invalid_element(e));
        }
        let ch = &s.children[..];
        match (pass, e) {
            (_, "database_output") => {
                self.warnings.push("The 'database_output' configuration is deprecated and no longer supported. This configuration will be ignored.".into())
            }
            (Pass::Responses, "command") => self.ar.read_command(ch)?,
            (Pass::Responses, "active-response") => self.ar.read_response(ch)?,
            (Pass::Main, "global") => self.global.read(ch)?,
            (Pass::Main, "syscheck") => self.global.read_syscheck(ch)?,
            (Pass::Main, "ruleset") => self.ruleset.read(ch, &self.home)?,
            (Pass::Main, "alerts") => self.ruleset.read_alerts(ch)?,
            (Pass::Main, "cluster") => self.cluster.read(ch, &mut self.warnings)?,
            (Pass::Main, "socket") => read_socket(ch, &mut self.sockets)?,
            (Pass::Labels, "labels") => read_labels(ch, &mut self.labels, &mut self.warnings)?,
            (Pass::RuleTest, "rule_test") => self.logtest.read(ch, &mut self.warnings)?,
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(leading_number(" -12x"), (-12, 4));
        assert_eq!(leading_number("x"), (0, 0));
        assert_eq!(seconds("2h"), 7200);
        assert_eq!(seconds("5x"), -1);
        assert_eq!(seconds(""), 0);
        assert_eq!(number_and_unit("10m"), Some((10, Some('m'))));
        assert!(white_list_is_ip("!10.0.0.1/24"));
        assert!(!white_list_is_ip("host"));
        assert!(looks_like_email("a@b"));
        assert!(!looks_like_email("@b"));
        assert_eq!(unescape("a\\;b\\"), "a;b");
    }

    #[test]
    fn disabled_response_keeps_earlier_ones() {
        let node = |name: &str, content: &str| Node { name: name.into(), attributes: vec![], content: content.into(), children: vec![], from_var: false, more_attributes: false };
        let mut ar = ActiveResponses::default();
        ar.read_command(&[node("name", "fw"), node("executable", "fw.sh")]).unwrap();
        ar.read_response(&[node("command", "fw"), node("location", "local")]).unwrap();
        ar.read_response(&[node("command", "fw"), node("location", "all"), node("disabled", "yes")]).unwrap();
        assert_eq!((ar.flags, ar.responses.len()), (REMOTE_AR | LOCAL_AR, 1));
    }
}
