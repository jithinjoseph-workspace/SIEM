//! Port of `src/config/global-config.c` (`Read_Global`, `Read_GlobalSK`,
//! `Read_Global_limits`) with the `_Config` / `MailConfig` fields it fills.

use crate::messages::*;
use crate::util::{atoi, parse_time, sscanf_int_char, str_is_num, strtol, strtrim};
use crate::{ConfigContext, ConfigError, Result};
use siem_regex::{is_valid_ip, OsIp, OsMatch};
use siem_xml::{OsXml, XmlNode};

pub const CTI_URL_DEFAULT: &str = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0";
pub const EPS_LIMITS_DEFAULT_TIMEFRAME: u32 = 10;
pub const EPS_LIMITS_MAX_TIMEFRAME: u32 = 3600;
pub const EPS_LIMITS_MIN_TIMEFRAME: u32 = 1;
pub const EPS_LIMITS_MAX_EPS: u32 = 100000;

/// `_eps`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EpsLimits {
    pub maximum: u32,
    pub timeframe: u32,
    pub maximum_found: bool,
}

/// `_Config` (global part). Zero-initialised like `os_calloc`; daemons set
/// their own defaults before reading, as in Wazuh.
#[derive(Debug, Clone, Default)]
pub struct GlobalConfig {
    pub logall: u8,
    pub logall_json: u8,
    pub stats: u8,
    pub integrity: u8,
    pub syscheck_auto_ignore: u8,
    pub syscheck_ignore_frequency: i32,
    pub syscheck_ignore_time: i32,
    pub syscheck_alert_new: u8,
    pub rootcheck: u8,
    pub hostinfo: u8,
    pub mailbylevel: u8,
    pub logbylevel: u8,
    pub logfw: u8,
    pub update_check: u8,
    pub decoder_order_size: i32,
    pub agents_disconnection_time: i64,
    pub agents_disconnection_alert_time: i64,
    pub prelude: u8,
    pub prelude_log_level: u8,
    pub prelude_profile: Option<String>,
    pub geoipdb_file: Option<String>,
    pub zeromq_output: u8,
    pub zeromq_output_uri: Option<String>,
    pub zeromq_output_server_cert: Option<String>,
    pub zeromq_output_client_cert: Option<String>,
    pub jsonout_output: u8,
    pub alerts_log: u8,
    pub keeplogdate: u8,
    pub mailnotify: i16,
    pub custom_alert_output: i16,
    pub custom_alert_output_format: Option<String>,
    pub ar: i32,
    pub memorysize: i32,
    pub syscheck_ignore: Vec<String>,
    pub white_list: Vec<OsIp>,
    pub hostname_white_list: Vec<OsMatch>,
    pub includes: Vec<String>,
    pub lists: Vec<String>,
    pub decoders: Vec<String>,
    pub forwarders_list: Vec<String>,
    pub label_cache_maxage: i32,
    pub show_hidden_labels: i32,
    pub cluster_name: Option<String>,
    pub node_name: Option<String>,
    pub node_type: Option<String>,
    pub hide_cluster_info: u8,
    pub rotate_interval: i32,
    pub min_rotate_interval: i32,
    pub max_output_size: i64,
    pub queue_size: i64,
    pub eps: EpsLimits,
    pub cti_url: Option<String>,
    pub geoip_db_path: Option<String>,
    pub geoip6_db_path: Option<String>,
}

/// `MAIL_SOURCE_LOGS` / `MAIL_SOURCE_JSON`
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MailSource {
    #[default]
    Json,
    Logs,
}

/// `MailConfig` (the part `Read_Global` fills).
#[derive(Debug, Clone, Default)]
pub struct MailConfig {
    pub mn: i32,
    pub to: Vec<String>,
    pub from: Option<String>,
    pub reply_to: Option<String>,
    pub idsname: Option<String>,
    pub smtpserver: Option<String>,
    pub heloserver: Option<String>,
    pub maxperhour: i32,
    pub source: MailSource,
}

fn content<'a>(n: &'a XmlNode) -> Result<&'a str> {
    n.content.as_deref().ok_or_else(|| ConfigError::new(xml_valuenull(&n.element)))
}

fn yes_no(n: &XmlNode, c: &str) -> Result<u8> {
    match c {
        "yes" => Ok(1),
        "no" => Ok(0),
        _ => Err(ConfigError::new(xml_valueerr(&n.element, c))),
    }
}

fn num_u8(n: &XmlNode, c: &str) -> Result<u8> {
    if !str_is_num(c) {
        return Err(ConfigError::new(xml_valueerr(&n.element, c)));
    }
    Ok(atoi(c) as u8)
}

/// POSIX `[a-zA-Z0-9\._-]+@[a-zA-Z0-9\._-]` (OS_PRegex, unanchored).
fn looks_like_email(s: &str) -> bool {
    let b = s.as_bytes();
    let ok = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'\\');
    (1..b.len().saturating_sub(1)).any(|i| b[i] == b'@' && ok(b[i - 1]) && ok(b[i + 1]))
}

/// The `white_list` IPv4 test regex from `Read_Global`.
fn white_list_is_ip(s: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"^!?[[:digit:]]{1,3}(\.[[:digit:]]{1,3}){3}(/[[:digit:]]{1,2}([[:digit:]](\.[[:digit:]]{1,3}){3})?)?$").unwrap()
    })
    .is_match(s)
}

/// `Read_GlobalSK`
pub fn read_global_sk(cfg: &mut GlobalConfig, nodes: Option<&[XmlNode]>) -> Result<()> {
    let Some(nodes) = nodes else { return Ok(()) };
    for n in nodes {
        let c = content(n)?;
        match n.element.as_str() {
            "auto_ignore" => {
                cfg.syscheck_auto_ignore = yes_no(n, c)?;
                for (j, a) in n.attributes.iter().enumerate() {
                    match a.as_str() {
                        // The C code reads values[0] / values[1] here, not values[j].
                        "frequency" => {
                            let v0 = n.values.first().map(String::as_str).unwrap_or("");
                            if !str_is_num(v0) {
                                return Err(ConfigError::new(xml_valueerr(a, &n.values[j])));
                            }
                            cfg.syscheck_ignore_frequency = atoi(v0);
                            if !(1..=99).contains(&cfg.syscheck_ignore_frequency) {
                                return Err(ConfigError::new(xml_valueerr(a, &n.values[j])));
                            }
                        }
                        "timeframe" => {
                            if !str_is_num(&n.values[j]) {
                                return Err(ConfigError::new(xml_valueerr(a, &n.values[j])));
                            }
                            let v1 = n.values.get(1).map(String::as_str).unwrap_or("");
                            cfg.syscheck_ignore_time = atoi(v1);
                            if !(0..=43200).contains(&cfg.syscheck_ignore_time) {
                                return Err(ConfigError::new(xml_valueerr(a, &n.values[j])));
                            }
                        }
                        _ => return Err(ConfigError::new(xml_invattr(a, &n.element))),
                    }
                }
            }
            "alert_new_files" => cfg.syscheck_alert_new = yes_no(n, c)?,
            "ignore" => cfg.syscheck_ignore.push(c.to_string()),
            _ => {}
        }
    }
    Ok(())
}

/// `Read_Global`. Either config may be absent, exactly like the C NULL checks.
pub fn read_global(
    _ctx: &mut ConfigContext,
    xml: &OsXml,
    nodes: &[XmlNode],
    mut cfg: Option<&mut GlobalConfig>,
    mut mail: Option<&mut MailConfig>,
    client: bool,
    windows: bool,
) -> Result<()> {
    if let Some(c) = cfg.as_deref_mut() {
        if c.cti_url.is_none() {
            c.cti_url = Some(CTI_URL_DEFAULT.to_string());
        }
        c.update_check = 1;
    }

    for n in nodes {
        let c = content(n)?;
        let el = n.element.as_str();
        macro_rules! set_cfg {
            ($f:ident, $v:expr) => {
                if let Some(cf) = cfg.as_deref_mut() {
                    cf.$f = $v;
                }
            };
        }
        match el {
            "custom_alert_output" => {
                if let Some(cf) = cfg.as_deref_mut() {
                    cf.custom_alert_output = 1;
                    cf.custom_alert_output_format = Some(c.to_string());
                }
            }
            "forward_to" => {
                if let Some(cf) = cfg.as_deref_mut() {
                    let count = c.matches(',').count() + 1;
                    if let Some(list) = siem_regex::str_break(',', c, count) {
                        cf.forwarders_list = list.iter().map(|t| strtrim(t).to_string()).collect();
                    }
                }
            }
            "email_notification" => {
                let v = yes_no(n, c)?;
                set_cfg!(mailnotify, v as i16);
                if let Some(m) = mail.as_deref_mut() {
                    m.mn = v as i32;
                }
            }
            "prelude_output" => {
                let v = yes_no(n, c)?;
                set_cfg!(prelude, v);
            }
            "geoipdb" => set_cfg!(geoipdb_file, Some(c.to_string())),
            "prelude_profile" => set_cfg!(prelude_profile, Some(c.to_string())),
            "prelude_log_level" => {
                let v = num_u8(n, c)?;
                set_cfg!(prelude_log_level, v);
            }
            "zeromq_output" => {
                let v = yes_no(n, c)?;
                set_cfg!(zeromq_output, v);
            }
            "zeromq_uri" => set_cfg!(zeromq_output_uri, Some(c.to_string())),
            "zeromq_server_cert" => set_cfg!(zeromq_output_server_cert, Some(c.to_string())),
            "zeromq_client_cert" => set_cfg!(zeromq_output_client_cert, Some(c.to_string())),
            "jsonout_output" => {
                let v = yes_no(n, c)?;
                set_cfg!(jsonout_output, v);
            }
            "alerts_log" => {
                let v = yes_no(n, c)?;
                set_cfg!(alerts_log, v);
            }
            "logall" => {
                let v = yes_no(n, c)?;
                set_cfg!(logall, v);
            }
            "logall_json" => {
                let v = yes_no(n, c)?;
                set_cfg!(logall_json, v);
            }
            "update_check" => {
                let v = yes_no(n, c)?;
                set_cfg!(update_check, v);
            }
            "compress_alerts" => {}
            "integrity_checking" => {
                let v = num_u8(n, c)?;
                set_cfg!(integrity, v);
            }
            "rootkit_detection" => {
                let v = num_u8(n, c)?;
                set_cfg!(rootcheck, v);
            }
            "host_information" => {
                let v = num_u8(n, c)?;
                set_cfg!(hostinfo, v);
            }
            "stats" => {
                let v = num_u8(n, c)?;
                set_cfg!(stats, v);
            }
            "memory_size" => {
                if !str_is_num(c) {
                    return Err(ConfigError::new(xml_valueerr(el, c)));
                }
                set_cfg!(memorysize, atoi(c));
            }
            "limits" if !client => {
                let ch = xml.get_elements_by_node(Some(n)).ok_or_else(|| ConfigError::new(xml_invelem(el)))?;
                read_global_limits(xml, &ch, cfg.as_deref_mut())?;
            }
            "white_list" => {
                if !windows {
                    if let Some(cf) = cfg.as_deref_mut() {
                        if white_list_is_ip(c) {
                            match is_valid_ip(c) {
                                (0, _) | (_, None) => return Err(ConfigError::new(invalid_ip(c))),
                                (_, Some(ip)) => cf.white_list.push(ip),
                            }
                        } else {
                            match OsMatch::compile(c, 0) {
                                Ok(m) => cf.hostname_white_list.push(m),
                                Err(e) => return Err(ConfigError::new(regex_compile(c, e as i32))),
                            }
                        }
                    }
                }
            }
            "email_to" => {
                if !windows && !looks_like_email(c) {
                    return Err(ConfigError::new(format!("Invalid Email address: {c}.")));
                }
                if let Some(m) = mail.as_deref_mut() {
                    m.to.push(c.to_string());
                }
            }
            "email_from" => {
                if let Some(m) = mail.as_deref_mut() {
                    m.from = Some(c.to_string());
                }
            }
            "email_reply_to" => {
                if let Some(m) = mail.as_deref_mut() {
                    m.reply_to = Some(c.to_string());
                }
            }
            "email_idsname" => {
                if let Some(m) = mail.as_deref_mut() {
                    m.idsname = Some(c.to_string());
                }
            }
            "smtp_server" => {
                if !windows {
                    if let Some(m) = mail.as_deref_mut() {
                        m.smtpserver = Some(c.to_string());
                    }
                }
            }
            "helo_server" => {
                if let Some(m) = mail.as_deref_mut() {
                    m.heloserver = Some(c.to_string());
                }
            }
            "email_maxperhour" => {
                if let Some(m) = mail.as_deref_mut() {
                    if !str_is_num(c) {
                        return Err(ConfigError::new(xml_valueerr(el, c)));
                    }
                    m.maxperhour = atoi(c);
                    if m.maxperhour <= 0 || m.maxperhour > 1_000_000 {
                        return Err(ConfigError::new(xml_valueerr(el, c)));
                    }
                }
            }
            "email_log_source" => {
                if let Some(m) = mail.as_deref_mut() {
                    if str_is_num(c) {
                        return Err(ConfigError::new(xml_valueerr(el, c)));
                    }
                    m.source = if c.starts_with("alerts.log") { MailSource::Logs } else { MailSource::Json };
                }
            }
            "geoip_db_path" => set_cfg!(geoip_db_path, Some(c.to_string())),
            "geoip6_db_path" => set_cfg!(geoip6_db_path, Some(c.to_string())),
            "rotate_interval" => {
                if let Some(cf) = cfg.as_deref_mut() {
                    let (k, v, ch) = sscanf_int_char(c);
                    let mut v = v as i32;
                    match k {
                        1 => {}
                        2 => match ch {
                            Some('d') => v = v.wrapping_mul(86400),
                            Some('h') => v = v.wrapping_mul(3600),
                            Some('m') => v = v.wrapping_mul(60),
                            Some('s') => {}
                            _ => return Err(ConfigError::new(xml_valueerr(el, c))),
                        },
                        _ => return Err(ConfigError::new(xml_valueerr(el, c))),
                    }
                    cf.rotate_interval = v;
                    if v < 0 {
                        return Err(ConfigError::new(xml_valueerr(el, c)));
                    }
                }
            }
            "max_output_size" => {
                if let Some(cf) = cfg.as_deref_mut() {
                    let (k, mut v, ch) = sscanf_int_char(c);
                    match k {
                        1 => {}
                        2 => match ch {
                            Some('G' | 'g') => v = v.wrapping_mul(1073741824),
                            Some('M' | 'm') => v = v.wrapping_mul(1048576),
                            Some('K' | 'k') => v = v.wrapping_mul(1024),
                            Some('B' | 'b') => {}
                            _ => return Err(ConfigError::new(xml_valueerr(el, c))),
                        },
                        _ => return Err(ConfigError::new(xml_valueerr(el, c))),
                    }
                    cf.max_output_size = v;
                }
            }
            "queue_size" => {
                if let Some(cf) = cfg.as_deref_mut() {
                    let (v, end) = strtol(c);
                    cf.queue_size = v;
                    if end != c.len() || v < 1 {
                        return Err(ConfigError::new("Invalid value for option '<queue_size>'"));
                    }
                }
            }
            "agents_disconnection_time" => {
                if let Some(cf) = cfg.as_deref_mut() {
                    let t = parse_time(c);
                    if t < 1 {
                        return Err(ConfigError::new(xml_valueerr(el, c)));
                    }
                    cf.agents_disconnection_time = t;
                }
            }
            "agents_disconnection_alert_time" => {
                if let Some(cf) = cfg.as_deref_mut() {
                    let t = parse_time(c);
                    if t < 0 {
                        return Err(ConfigError::new(xml_valueerr(el, c)));
                    }
                    cf.agents_disconnection_alert_time = t;
                }
            }
            "cti-url" if !client => {
                if let Some(cf) = cfg.as_deref_mut() {
                    if !c.is_empty() {
                        cf.cti_url = Some(c.to_string());
                    }
                }
            }
            _ => return Err(ConfigError::new(xml_invelem(el))),
        }
    }
    Ok(())
}

/// `Read_Global_limits` / `Read_Global_limits_eps`
fn read_global_limits(xml: &OsXml, nodes: &[XmlNode], mut cfg: Option<&mut GlobalConfig>) -> Result<()> {
    for n in nodes {
        if n.element == "eps" {
            let ch = xml.get_elements_by_node(Some(n)).ok_or_else(|| ConfigError::new(xml_invelem(&n.element)))?;
            if let Some(c) = cfg.as_deref_mut() {
                c.eps.maximum_found = false;
                c.eps.timeframe = EPS_LIMITS_DEFAULT_TIMEFRAME;
            }
            for e in &ch {
                let v = e.content.as_deref().unwrap_or("");
                if e.element == "maximum" {
                    if !str_is_num(v) {
                        return Err(ConfigError::new(xml_valueerr(&e.element, v)));
                    }
                    if let Some(c) = cfg.as_deref_mut() {
                        c.eps.maximum_found = true;
                        c.eps.maximum = atoi(v) as u32;
                        if c.eps.maximum > EPS_LIMITS_MAX_EPS {
                            return Err(ConfigError::new(xml_valueerr(&e.element, v)));
                        }
                    }
                } else if e.element == "timeframe" {
                    if !str_is_num(v) {
                        return Err(ConfigError::new(xml_valueerr(&e.element, v)));
                    }
                    if let Some(c) = cfg.as_deref_mut() {
                        c.eps.timeframe = atoi(v) as u32;
                        if c.eps.timeframe < EPS_LIMITS_MIN_TIMEFRAME || c.eps.timeframe > EPS_LIMITS_MAX_TIMEFRAME {
                            return Err(ConfigError::new(xml_valueerr(&e.element, v)));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
