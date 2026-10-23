//! `config/agentlessd-config.c` (`Read_CAgentless`), `getAgentlessConfig`
//! (agentlessd.c) and `lessdcom.c`.

use std::path::Path;

use siem_cjson::Json;
use siem_config::messages::{xml_invelem, xml_valueerr, xml_valuenull, XML_ELEMNULL};
use siem_config::{modules, read_config, ConfigContext, ConfigError, ConfigHandler, LogLevel, Platform, Section};
use siem_xml::{OsXml, XmlNode};

use crate::AGENTLESSDIR;

pub const LESSD_STATE_CONNECTED: i32 = 0x001;
pub const LESSD_STATE_PERIODIC: i32 = 0x002;
pub const LESSD_STATE_DIFF: i32 = 0x004;

/// `agentlessd_entries`
#[derive(Debug, Clone)]
pub struct Entry {
    pub state: i32,
    pub frequency: i32,
    pub current_state: i64,
    pub port: i32,
    pub error_flag: i32,
    pub type_: String,
    /// Each prefixed with ' ', 's' (use_su) or 'o' (use_sudo).
    pub server: Vec<String>,
    pub options: String,
    pub command: Option<String>,
}

fn num(n: &XmlNode, c: &str) -> siem_config::Result<i32> {
    if !siem_regex::str_is_num(c) {
        return Err(ConfigError::new(xml_valueerr(&n.element, c)));
    }
    Ok(siem_maild::alert::atoi(c.as_bytes()) as i32)
}

/// `snprintf(buf, 1024, ...)`: at most 1023 bytes.
pub fn trunc1023(mut s: String) -> String {
    if s.len() > 1023 {
        let mut n = 1023;
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        s.truncate(n);
    }
    s
}

/// `Read_CAgentless`: appends one `<agentless>`.
pub fn read_cagentless(ctx: &mut ConfigContext, nodes: &[XmlNode], list: &mut Vec<Entry>) -> siem_config::Result<()> {
    let mut e = Entry { state: 0, frequency: 86400, current_state: 0, port: 0, error_flag: 0, type_: String::new(), server: Vec::new(), options: String::new(), command: None };
    let mut has_type = false;
    for n in nodes {
        if n.element.is_empty() {
            return Err(ConfigError::new(XML_ELEMNULL));
        }
        let Some(v) = n.content.as_deref() else { return Err(ConfigError::new(xml_valuenull(&n.element))) };
        match n.element.as_str() {
            "frequency" => e.frequency = num(n, v)?,
            "port" => e.port = num(n, v)?,
            "host" => {
                let s = if let Some(r) = v.strip_prefix("use_su ") {
                    format!("s{r}")
                } else if let Some(r) = v.strip_prefix("use_sudo ") {
                    format!("o{r}")
                } else {
                    format!(" {v}")
                };
                e.server.push(trunc1023(s));
            }
            "type" => {
                let script_path = trunc1023(format!("{AGENTLESSDIR}/{v}"));
                if siem_fileop::ref_parent_folder(&script_path) {
                    return Err(ConfigError::new(format!("Invalid Agentless type '{v}': it contains references to parent folder.")));
                }
                if siem_fileop::mtime(&script_path).unwrap_or(-1) <= 0 {
                    ctx.error(format!("Unable to find '{v}' at '{AGENTLESSDIR}'."));
                    return Err(ConfigError::new(xml_valueerr(&n.element, v)));
                }
                e.type_ = v.to_string();
                has_type = true;
            }
            "run_command" => e.command = Some(v.to_string()),
            "arguments" => e.options = v.to_string(),
            "state" => match v {
                "periodic" => e.state |= LESSD_STATE_PERIODIC,
                "stay_connected" => e.state |= LESSD_STATE_CONNECTED,
                "periodic_diff" => e.state |= LESSD_STATE_PERIODIC | LESSD_STATE_DIFF,
                _ => return Err(ConfigError::new(xml_valueerr(&n.element, v))),
            },
            _ => return Err(ConfigError::new(xml_invelem(&n.element))),
        }
    }
    if e.server.is_empty() || e.state == 0 || !has_type {
        return Err(ConfigError::new("(7103): Missing agentless options."));
    }
    if e.state == LESSD_STATE_PERIODIC && e.frequency == 0 {
        return Err(ConfigError::new("(7102): Frequency not set for the periodic option."));
    }
    list.push(e);
    Ok(())
}

struct Handler<'a>(&'a mut Vec<Entry>);

impl ConfigHandler for Handler<'_> {
    fn section(&mut self, ctx: &mut ConfigContext, _xml: &OsXml, s: Section, _node: &XmlNode, ch: Option<&[XmlNode]>) -> siem_config::Result<()> {
        match s {
            Section::Agentless => read_cagentless(ctx, ch.unwrap_or(&[]), self.0),
            _ => Ok(()),
        }
    }
}

/// `ReadConfig(CAGENTLESS, cfg, &lessdc)`: `None` on a configuration error.
pub fn read_agentless_conf(home: &Path, cfg: &str, log: &mut Vec<(LogLevel, String)>) -> Option<Vec<Entry>> {
    let mut list = Vec::new();
    let mut ctx = ConfigContext::new(Platform::MANAGER);
    let r = read_config(&mut ctx, modules::CAGENTLESS, home.join(cfg), None, &mut Handler(&mut list));
    log.append(&mut ctx.log);
    r.ok().map(|_| list)
}

/// `getAgentlessConfig`
pub fn agentless_config_json(list: &[Entry]) -> Json {
    let mut arr = Json::array();
    for e in list {
        let mut o = Json::object();
        let mut hosts = Json::array();
        for s in &e.server {
            hosts.push(Json::string(s));
        }
        o.add("host", hosts);
        o.add("port", Json::number(e.port as f64));
        o.add("frequency", Json::number(e.frequency as f64));
        if e.state & LESSD_STATE_PERIODIC != 0 && e.state & LESSD_STATE_DIFF != 0 {
            o.add("state", Json::string("periodic_diff"));
        } else if e.state & LESSD_STATE_CONNECTED != 0 {
            o.add("state", Json::string("stay_connected"));
        } else if e.state & LESSD_STATE_PERIODIC != 0 {
            o.add("state", Json::string("periodic"));
        }
        o.add("arguments", Json::string(&e.options));
        if let Some(c) = &e.command {
            o.add("run_command", Json::string(c));
        }
        o.add("type", Json::string(&e.type_));
        arr.push(o);
    }
    let mut root = Json::object();
    root.add("agentless", arr);
    root
}

/// `lessdcom_dispatch`
pub fn lessdcom_dispatch(list: &[Entry], command: &[u8]) -> String {
    let command = &command[..command.iter().position(|&c| c == 0).unwrap_or(command.len())];
    let command = String::from_utf8_lossy(command);
    let (cmd, args) = match command.split_once(' ') {
        Some((c, a)) => (c, Some(a)),
        None => (command.as_ref(), None),
    };
    let log = siem_maild::log();
    if cmd != "getconfig" {
        log.debug1(format!("LESSDCOM Unrecognized command '{cmd}'."));
        return "err Unrecognized command".into();
    }
    match args {
        None => {
            log.debug1("LESSDCOM getconfig needs arguments.");
            "err LESSDCOM getconfig needs arguments".into()
        }
        Some("agentless") => format!("ok {}", agentless_config_json(list).to_string_unformatted()),
        Some(s) => {
            log.debug1(format!("At LESSDCOM getconfig: Could not get '{s}' section"));
            "err Could not get requested section".into()
        }
    }
}
