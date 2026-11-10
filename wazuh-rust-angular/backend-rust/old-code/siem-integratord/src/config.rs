//! `config/integrator-config.c` (`Read_Integrator`) and
//! `os_integrator/config.c` (`OS_ReadIntegratorConf`, `getIntegratorConfig`).

use std::path::Path;

use siem_cjson::Json;
use siem_config::messages::{xml_invelem, xml_valueerr, xml_valuenull, XML_ELEMNULL};
use siem_config::{modules, read_config, ConfigContext, ConfigError, ConfigHandler, LogLevel, Platform, Section};
use siem_regex::OsMatch;
use siem_xml::{OsXml, XmlNode};

/// `IntegratorConfig`
#[derive(Debug, Clone)]
pub struct Integration {
    pub level: u32,
    pub enabled: bool,
    /// Ends at its first 0, like the C array.
    pub rule_id: Option<Vec<u32>>,
    pub max_log: u32,
    pub timeout: u32,
    pub retries: u32,
    pub name: Option<String>,
    pub apikey: Option<String>,
    pub hookurl: Option<String>,
    pub path: Option<String>,
    pub alert_format: Option<String>,
    pub group: Option<String>,
    pub options: Option<String>,
    pub location: Option<OsMatch>,
}

impl Default for Integration {
    fn default() -> Self {
        Integration {
            level: 0,
            enabled: false,
            rule_id: None,
            max_log: 165,
            timeout: 10,
            retries: 3,
            name: None,
            apikey: None,
            hookurl: None,
            path: None,
            alert_format: None,
            group: None,
            options: None,
            location: None,
        }
    }
}

fn num(n: &XmlNode, c: &str) -> siem_config::Result<u32> {
    if !siem_regex::str_is_num(c) {
        return Err(ConfigError::new(xml_valueerr(&n.element, c)));
    }
    Ok(siem_maild::alert::atoi(c.as_bytes()) as u32)
}

/// `Read_Integrator`: appends one `<integration>`.
pub fn read_integrator(nodes: &[XmlNode], list: &mut Vec<Integration>) -> siem_config::Result<()> {
    list.push(Integration::default());
    let it = list.last_mut().unwrap();
    for n in nodes {
        if n.element.is_empty() {
            return Err(ConfigError::new(XML_ELEMNULL));
        }
        let Some(c) = n.content.as_deref() else { return Err(ConfigError::new(xml_valuenull(&n.element))) };
        match n.element.as_str() {
            "level" => it.level = num(n, c)?,
            "name" => it.name = Some(c.into()),
            "api_key" => it.apikey = Some(c.into()),
            "alert_format" => it.alert_format = Some(c.into()),
            "hook_url" => it.hookurl = Some(c.into()),
            "options" => it.options = Some(c.into()),
            "rule_id" => {
                let b = c.as_bytes();
                let mut i = 0;
                while i < b.len() {
                    if b[i] == b' ' || b[i] == b',' {
                        i += 1;
                    } else if b[i].is_ascii_digit() {
                        let v = it.rule_id.get_or_insert_with(Vec::new);
                        v.truncate(v.iter().position(|&x| x == 0).unwrap_or(v.len()));
                        v.push(siem_maild::alert::atoi(&b[i..]) as u32);
                        match b[i..].iter().position(|&x| x == b',') {
                            Some(p) => i += p + 1,
                            None => break,
                        }
                    } else {
                        break;
                    }
                }
            }
            "event_location" => {
                it.location = Some(OsMatch::compile(c, 0).map_err(|e| ConfigError::new(format!("(1450): Syntax error on regex: '{c}': {}.", e as i32)))?);
            }
            "group" => it.group = Some(c.into()),
            "max_log" => {
                let v = num(n, c)?;
                it.max_log = v;
                if !(165..=1024).contains(&v) {
                    return Err(ConfigError::new(xml_valueerr(&n.element, c)));
                }
            }
            "timeout" => it.timeout = num(n, c)?,
            "retries" => it.retries = num(n, c)?,
            _ => return Err(ConfigError::new(xml_invelem(&n.element))),
        }
    }
    if it.name.is_none() {
        return Err(ConfigError::new("(5310): Invalid integratord configuration."));
    }
    Ok(())
}

struct Handler<'a>(&'a mut Vec<Integration>);

impl ConfigHandler for Handler<'_> {
    fn section(&mut self, _ctx: &mut ConfigContext, _xml: &OsXml, s: Section, _node: &XmlNode, ch: Option<&[XmlNode]>) -> siem_config::Result<()> {
        match s {
            Section::Integration => read_integrator(ch.unwrap_or(&[]), self.0),
            _ => Ok(()),
        }
    }
}

/// `OS_ReadIntegratorConf`: `None` on a configuration error.
pub fn read_integrator_conf(home: &Path, cfg: &str, log: &mut Vec<(LogLevel, String)>) -> Option<Vec<Integration>> {
    let mut list = Vec::new();
    let mut ctx = ConfigContext::new(Platform::MANAGER);
    let r = read_config(&mut ctx, modules::CINTEGRATORD, home.join(cfg), None, &mut Handler(&mut list));
    log.append(&mut ctx.log);
    r.ok().map(|_| list)
}

/// `getIntegratorConfig`
pub fn integrator_config_json(list: &[Integration]) -> Json {
    let mut arr = Json::array();
    for it in list {
        let mut c = Json::object();
        for (k, v) in [("name", &it.name), ("hook_url", &it.hookurl), ("api_key", &it.apikey)] {
            if let Some(v) = v {
                c.add(k, Json::string(v));
            }
        }
        c.add("level", Json::number(it.level as f64));
        c.add("max_log", Json::number(it.max_log as f64));
        if let Some(ids) = &it.rule_id {
            let mut a = Json::array();
            for id in ids.iter().take_while(|&&x| x != 0) {
                a.push(Json::number(*id as f64));
            }
            c.add("rule_id", a);
        }
        for (k, v) in [("group", &it.group), ("alert_format", &it.alert_format)] {
            if let Some(v) = v {
                c.add(k, Json::string(v));
            }
        }
        if let Some(l) = &it.location {
            let mut a = Json::array();
            for p in l.patterns() {
                a.push(Json::string(p));
            }
            c.add("location", a);
        }
        c.add("timeout", Json::number(it.timeout as f64));
        c.add("retries", Json::number(it.retries as f64));
        arr.push(c);
    }
    let mut root = Json::object();
    root.add("integration", arr);
    root
}

/// `intgcom_dispatch`
pub fn intgcom_dispatch(list: &[Integration], command: &[u8]) -> String {
    let command = &command[..command.iter().position(|&c| c == 0).unwrap_or(command.len())];
    let command = String::from_utf8_lossy(command);
    let (cmd, args) = match command.split_once(' ') {
        Some((c, a)) => (c, Some(a)),
        None => (command.as_ref(), None),
    };
    let log = siem_maild::log();
    if cmd != "getconfig" {
        log.debug1(format!("INTGCOM Unrecognized command '{cmd}'."));
        return "err Unrecognized command".into();
    }
    match args {
        None => {
            log.debug1("INTGCOM getconfig needs arguments.");
            "err INTGCOM getconfig needs arguments".into()
        }
        Some("integration") => format!("ok {}", integrator_config_json(list).to_string_unformatted()),
        Some(s) => {
            log.debug1(format!("At INTGCOM getconfig: Could not get '{s}' section"));
            "err Could not get requested section".into()
        }
    }
}
