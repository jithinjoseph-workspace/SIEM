//! `config/csyslogd-config.c` (`Read_CSyslog`), `os_csyslogd/config.c`
//! (`getCsyslogConfig`) and `csyscom.c`.

use std::net::UdpSocket;
use std::path::Path;

use siem_cjson::Json;
use siem_config::messages::{xml_invelem, xml_valueerr, xml_valuenull, XML_ELEMNULL};
use siem_config::{modules, read_config, ConfigContext, ConfigError, ConfigHandler, LogLevel, Platform, Section};
use siem_regex::OsMatch;
use siem_xml::{OsXml, XmlNode};

pub const DEFAULT_CSYSLOG: u32 = 0;
pub const CEF_CSYSLOG: u32 = 1;
pub const JSON_CSYSLOG: u32 = 2;
pub const SPLUNK_CSYSLOG: u32 = 3;

/// `SyslogConfig`
#[derive(Debug)]
pub struct Syslog {
    pub port: u32,
    pub format: u32,
    pub level: u32,
    /// Ends at its first 0, like the C array.
    pub rule_id: Option<Vec<u32>>,
    pub priority: u32,
    pub use_fqdn: bool,
    pub socket: Option<UdpSocket>,
    pub server: String,
    pub group: Option<OsMatch>,
    pub location: Option<OsMatch>,
}

impl Default for Syslog {
    fn default() -> Self {
        // local 0 facility (16) + severity 4 (warning)
        Syslog { port: 514, format: DEFAULT_CSYSLOG, level: 0, rule_id: None, priority: 16 * 8 + 4, use_fqdn: false, socket: None, server: String::new(), group: None, location: None }
    }
}

fn num(n: &XmlNode, c: &str) -> siem_config::Result<u32> {
    if !siem_regex::str_is_num(c) {
        return Err(ConfigError::new(xml_valueerr(&n.element, c)));
    }
    Ok(siem_maild::alert::atoi(c.as_bytes()) as u32)
}

fn compile(c: &str) -> siem_config::Result<OsMatch> {
    OsMatch::compile(c, 0).map_err(|e| ConfigError::new(format!("(1450): Syntax error on regex: '{c}': {}.", e as i32)))
}

/// `Read_CSyslog`: appends one `<syslog_output>`.
pub fn read_csyslog(ctx: &mut ConfigContext, nodes: &[XmlNode], list: &mut Vec<Syslog>) -> siem_config::Result<()> {
    let mut c = Syslog::default();
    for n in nodes {
        if n.element.is_empty() {
            return Err(ConfigError::new(XML_ELEMNULL));
        }
        let Some(v) = n.content.as_deref() else { return Err(ConfigError::new(xml_valuenull(&n.element))) };
        match n.element.as_str() {
            "level" => c.level = num(n, v)?,
            "port" => c.port = num(n, v)?,
            "server" => c.server = v.to_string(),
            "rule_id" => {
                let b = v.as_bytes();
                let mut i = 0;
                while i < b.len() {
                    if b[i] == b' ' || b[i] == b',' {
                        i += 1;
                    } else if b[i].is_ascii_digit() {
                        let r_id = siem_maild::alert::atoi(&b[i..]) as u32;
                        ctx.debug1(format!("Adding '{}' to syslog alerting", r_id as i32));
                        let ids = c.rule_id.get_or_insert_with(Vec::new);
                        ids.truncate(ids.iter().position(|&x| x == 0).unwrap_or(ids.len()));
                        ids.push(r_id);
                        match b[i..].iter().position(|&x| x == b',') {
                            Some(p) => i += p + 1,
                            None => break,
                        }
                    } else {
                        break;
                    }
                }
            }
            "format" => {
                c.format = match v {
                    "default" => c.format,
                    "cef" => CEF_CSYSLOG,
                    "json" => JSON_CSYSLOG,
                    "splunk" => SPLUNK_CSYSLOG,
                    _ => return Err(ConfigError::new(xml_valueerr(&n.element, v))),
                }
            }
            "location" => c.location = Some(compile(v)?),
            "use_fqdn" => {
                c.use_fqdn = match v {
                    "yes" => true,
                    "no" => false,
                    _ => return Err(ConfigError::new(xml_valueerr(&n.element, v))),
                }
            }
            "group" => c.group = Some(compile(v)?),
            _ => return Err(ConfigError::new(xml_invelem(&n.element))),
        }
    }
    if c.server.is_empty() {
        return Err(ConfigError::new("(5301): Invalid client-syslog configuration."));
    }
    list.push(c);
    Ok(())
}

struct Handler<'a>(&'a mut Vec<Syslog>);

impl ConfigHandler for Handler<'_> {
    fn section(&mut self, ctx: &mut ConfigContext, _xml: &OsXml, s: Section, _node: &XmlNode, ch: Option<&[XmlNode]>) -> siem_config::Result<()> {
        match s {
            Section::SyslogOutput => read_csyslog(ctx, ch.unwrap_or(&[]), self.0),
            _ => Ok(()),
        }
    }
}

/// `OS_ReadSyslogConf`: `None` on a configuration error.
pub fn read_syslog_conf(home: &Path, cfg: &str, log: &mut Vec<(LogLevel, String)>) -> Option<Vec<Syslog>> {
    let mut list = Vec::new();
    let mut ctx = ConfigContext::new(Platform::MANAGER);
    let r = read_config(&mut ctx, modules::CSYSLOGD, home.join(cfg), None, &mut Handler(&mut list));
    log.append(&mut ctx.log);
    r.ok().map(|_| list)
}

/// `getCsyslogConfig`. C walks past its single `OSMatch` for group/location
/// (undefined behaviour); here the patterns of that one matcher are listed.
pub fn csyslog_config_json(list: &[Syslog]) -> Json {
    let mut arr = Json::array();
    for c in list {
        let mut o = Json::object();
        o.add("server", Json::string(&c.server));
        o.add("port", Json::number(c.port as f64));
        o.add("level", Json::number(c.level as f64));
        let pats = |m: &OsMatch| {
            let mut a = Json::array();
            for p in m.patterns() {
                a.push(Json::string(p));
            }
            a
        };
        if let Some(g) = &c.group {
            o.add("group", pats(g));
        }
        if let Some(ids) = &c.rule_id {
            let mut a = Json::array();
            for id in ids.iter().take_while(|&&x| x != 0) {
                a.push(Json::number(*id as f64));
            }
            o.add("rule_id", a);
        }
        if let Some(l) = &c.location {
            o.add("location", pats(l));
        }
        o.add("use_fqdn", Json::string(if c.use_fqdn { "yes" } else { "no" }));
        o.add("format", Json::string(["default", "cef", "json", "splunk"][c.format as usize]));
        arr.push(o);
    }
    let mut root = Json::object();
    root.add("syslog_output", arr);
    root
}

/// `csyscom_dispatch`
pub fn csyscom_dispatch(list: &[Syslog], command: &[u8]) -> String {
    let command = &command[..command.iter().position(|&c| c == 0).unwrap_or(command.len())];
    let command = String::from_utf8_lossy(command);
    let (cmd, args) = match command.split_once(' ') {
        Some((c, a)) => (c, Some(a)),
        None => (command.as_ref(), None),
    };
    let log = siem_maild::log();
    if cmd != "getconfig" {
        log.debug1(format!("CSYSCOM Unrecognized command '{cmd}'."));
        return "err Unrecognized command".into();
    }
    match args {
        None => {
            log.debug1("CSYSCOM getconfig needs arguments.");
            "err CSYSCOM getconfig needs arguments".into()
        }
        Some("csyslog") => format!("ok {}", csyslog_config_json(list).to_string_unformatted()),
        Some(s) => {
            log.debug1(format!("At CSYSCOM getconfig: Could not get '{s}' section"));
            "err Could not get requested section".into()
        }
    }
}
