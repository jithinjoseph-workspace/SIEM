//! `os_maild/config.c` (`MailConf`, `getMail*Config`) and
//! `config/email-alerts-config.c` (`Read_EmailAlerts`).

use std::path::Path;
use std::sync::Arc;

use siem_cjson::Json;
use siem_config::global::{read_global, GlobalConfig, MailConfig as GlobalMail, MailSource};
use siem_config::messages::{xml_invelem, xml_valueerr, xml_valuenull, XML_ELEMNULL};
use siem_config::{modules, read_config, ConfigContext, ConfigError, ConfigHandler, LogLevel, Platform, Section};
use siem_regex::OsMatch;
use siem_xml::{OsXml, XmlNode};

/// E-mail formats (`mail-config.h`)
pub const FULL_FORMAT: i32 = 2;
pub const SMS_FORMAT: i32 = 3;
pub const FORWARD_NOW: i32 = 4;
pub const DONOTGROUP: i32 = 5;

pub const MAIL_SOURCE_LOGS: i32 = 0;
pub const MAIL_SOURCE_JSON: i32 = 1;

/// `MailConfig`
#[derive(Debug, Clone, Default)]
pub struct Mail {
    pub mn: i32,
    pub maxperhour: i32,
    pub strict_checking: i32,
    pub grouping: i32,
    pub subject_full: i32,
    pub priority: i32,
    pub to: Vec<String>,
    pub reply_to: Option<String>,
    pub from: Option<String>,
    pub idsname: Option<String>,
    pub smtpserver: Option<String>,
    pub heloserver: Option<String>,
    pub source: i32,
    /// `gran_to` (NULL in C while empty).
    pub gran_to: Vec<String>,
    pub gran_level: Vec<u32>,
    pub gran_id: Vec<Option<Vec<u32>>>,
    pub gran_set: Vec<i32>,
    pub gran_format: Vec<i32>,
    pub gran_location: Vec<Option<Arc<OsMatch>>>,
    pub gran_group: Vec<Option<Arc<OsMatch>>>,
}

impl Mail {
    /// `os_realloc(x, granto_size + 2)` on every granular array, then the
    /// two slots at `size` reset (C leaves anything past them freed).
    fn resize_gran(&mut self, size: usize) {
        self.gran_id.resize(size + 2, None);
        self.gran_level.resize(size + 2, 0);
        self.gran_set.resize(size + 2, 0);
        self.gran_format.resize(size + 2, FULL_FORMAT);
        self.gran_location.resize(size + 2, None);
        self.gran_group.resize(size + 2, None);
        for i in [size, size + 1] {
            self.gran_id[i] = None;
            self.gran_location[i] = None;
            self.gran_group[i] = None;
            self.gran_level[i] = 0;
            self.gran_format[i] = FULL_FORMAT;
            self.gran_set[i] = 0;
        }
    }
}

/// `Read_EmailAlerts`
pub fn read_email_alerts(ctx: &mut ConfigContext, nodes: &[XmlNode], m: &mut Mail) -> siem_config::Result<()> {
    let mut granto_size = m.gran_to.len();
    let mut counter = granto_size;
    m.resize_gran(granto_size);

    for n in nodes {
        if n.element.is_empty() {
            return Err(ConfigError::new(XML_ELEMNULL));
        }
        let Some(c) = n.content.as_deref() else { return Err(ConfigError::new(xml_valuenull(&n.element))) };
        match n.element.as_str() {
            "level" => {
                if !siem_regex::str_is_num(c) {
                    return Err(ConfigError::new(xml_valueerr(&n.element, c)));
                }
                m.gran_level[granto_size] = crate::alert::atoi(c.as_bytes()) as u32;
            }
            "email_to" => {
                m.gran_to.truncate(counter);
                m.gran_to.push(c.to_string());
                counter += 1;
            }
            "rule_id" => {
                let b = c.as_bytes();
                let mut i = 0;
                while i < b.len() {
                    if b[i] == b' ' || b[i] == b',' {
                        i += 1;
                    } else if b[i].is_ascii_digit() {
                        let r_id = crate::alert::atoi(&b[i..]) as i32;
                        ctx.debug1(format!("Adding '{r_id}' to granular e-mail"));
                        // the list ends at its first 0 (C reuses that slot)
                        let v = m.gran_id[granto_size].get_or_insert_with(Vec::new);
                        v.truncate(v.iter().position(|&x| x == 0).unwrap_or(v.len()));
                        v.push(r_id as u32);
                        match b[i..].iter().position(|&x| x == b',') {
                            Some(p) => i += p + 1,
                            None => break,
                        }
                    } else {
                        break;
                    }
                }
            }
            "format" => match c {
                "sms" => m.gran_format[granto_size] = SMS_FORMAT,
                "default" | "full" => {}
                _ => return Err(ConfigError::new(xml_valueerr(&n.element, c))),
            },
            "do_not_delay" => {
                if m.gran_format[granto_size] != SMS_FORMAT && m.gran_format[granto_size] != DONOTGROUP {
                    m.gran_format[granto_size] = FORWARD_NOW;
                }
            }
            "do_not_group" => {
                if m.gran_format[granto_size] != SMS_FORMAT {
                    m.gran_format[granto_size] = DONOTGROUP;
                }
            }
            "event_location" | "group" => {
                let compiled = OsMatch::compile(c, 0).map_err(|e| ConfigError::new(format!("(1450): Syntax error on regex: '{c}': {}.", e as i32)))?;
                let slot = if n.element == "group" { &mut m.gran_group } else { &mut m.gran_location };
                slot[granto_size] = Some(Arc::new(compiled));
            }
            _ => return Err(ConfigError::new(xml_invelem(&n.element))),
        }
    }

    // Expand multimail attributes
    while counter > 0 && granto_size < counter - 1 {
        granto_size += 1;
        let prev = granto_size - 1;
        m.gran_id.resize(granto_size + 2, None);
        m.gran_id[granto_size + 1] = None;
        m.gran_id[granto_size] = m.gran_id[prev].as_ref().map(|v| v.iter().copied().take_while(|&x| x != 0).collect::<Vec<u32>>()).filter(|v| !v.is_empty());
        for (v, d) in [(&mut m.gran_level, 0u32)] {
            v.resize(granto_size + 2, d);
            v[granto_size] = v[prev];
            v[granto_size + 1] = 0;
        }
        for v in [&mut m.gran_set, &mut m.gran_format] {
            v.resize(granto_size + 2, 0);
            v[granto_size] = v[prev];
            v[granto_size + 1] = 0;
        }
        for v in [&mut m.gran_location, &mut m.gran_group] {
            v.resize(granto_size + 2, None);
            v[granto_size] = v[prev].clone();
            v[granto_size + 1] = None;
        }
    }

    // We must have at least one entry set
    let g = granto_size;
    let empty = m.gran_location[g].is_none() && m.gran_level[g] == 0 && m.gran_group[g].is_none() && m.gran_id[g].is_none() && m.gran_format[g] == FULL_FORMAT;
    if empty || (m.to.is_empty() && m.gran_to.get(g).is_none()) {
        return Err(ConfigError::new("(1264): Invalid 'email_alerts' config (missing parameters)."));
    }
    Ok(())
}

struct Handler<'a> {
    mail: &'a mut Mail,
    gm: &'a mut GlobalMail,
    global: Option<&'a mut GlobalConfig>,
}

impl ConfigHandler for Handler<'_> {
    fn section(&mut self, ctx: &mut ConfigContext, xml: &OsXml, s: Section, _node: &XmlNode, ch: Option<&[XmlNode]>) -> siem_config::Result<()> {
        let ch = ch.unwrap_or(&[]);
        match s {
            Section::Global => match self.global.as_deref_mut() {
                Some(g) => read_global(ctx, xml, ch, Some(g), None, false, false),
                None => {
                    // Read_Global fills the mail fields; mirror them so `to` keeps its order with granular reads
                    let r = read_global(ctx, xml, ch, None, Some(self.gm), false, false);
                    self.mail.to = self.gm.to.clone();
                    r
                }
            },
            Section::EmailAlerts if self.global.is_none() => read_email_alerts(ctx, ch, self.mail),
            _ => Ok(()),
        }
    }
}

/// What `MailConf` decided.
pub enum Conf {
    Ok(Mail),
    /// `!Mail->mn`: C logs `MAIL_DIS` (unless testing) and exits 0.
    Disabled,
    Err,
}

/// `MailConf`. Messages are returned in the order the C code logs them.
pub fn mail_conf(home: &Path, cfg: &str, test_config: bool, log: &mut Vec<(LogLevel, String)>) -> Conf {
    let mut m = Mail { maxperhour: 12, grouping: 1, source: -1, ..Default::default() };
    let mut gm = GlobalMail { maxperhour: 12, source: MailSource::Json, ..Default::default() };
    let path = home.join(cfg);

    // CMAIL: <global> mail fields and <email_alerts>
    {
        let mut ctx = ConfigContext::new(Platform::MANAGER);
        let mut h = Handler { mail: &mut m, gm: &mut gm, global: None };
        let r = read_config(&mut ctx, modules::CMAIL, &path, None, &mut h);
        log.append(&mut ctx.log);
        if r.is_err() {
            return Conf::Err;
        }
    }
    m.mn = gm.mn;
    m.maxperhour = gm.maxperhour;
    m.from = gm.from.clone();
    m.reply_to = gm.reply_to.clone();
    m.idsname = gm.idsname.clone();
    m.smtpserver = gm.smtpserver.clone();
    m.heloserver = gm.heloserver.clone();
    m.to = gm.to.clone();
    // C keeps -1 until the end when email_log_source is absent; both mean alerts.json
    m.source = if gm.source == MailSource::Logs { MAIL_SOURCE_LOGS } else { MAIL_SOURCE_JSON };

    // CGLOBAL: alerts_log / jsonout_output
    let mut g = GlobalConfig { alerts_log: 1, ..Default::default() };
    {
        let mut ctx = ConfigContext::new(Platform::MANAGER);
        let mut h = Handler { mail: &mut m, gm: &mut gm, global: Some(&mut g) };
        let r = read_config(&mut ctx, modules::CGLOBAL, &path, None, &mut h);
        log.append(&mut ctx.log);
        if r.is_err() {
            return Conf::Err;
        }
    }
    if m.mn == 0 {
        if !test_config {
            log.push((LogLevel::Info, "E-Mail notification disabled. Clean Exit.".into()));
        }
        return Conf::Disabled;
    }
    if m.source == -1 {
        m.source = MAIL_SOURCE_JSON;
    }
    if g.alerts_log == 0 && g.jsonout_output == 0 {
        log.push((LogLevel::Error, "All alert formats are disabled.".into()));
        return Conf::Err;
    }
    if g.alerts_log == 0 && m.source == MAIL_SOURCE_LOGS {
        log.push((LogLevel::Error, "Alerts.log is disabled".into()));
        return Conf::Err;
    }
    if g.jsonout_output == 0 && m.source == MAIL_SOURCE_JSON {
        log.push((LogLevel::Error, "Alerts.json is disabled".into()));
        return Conf::Err;
    }
    Conf::Ok(m)
}

/// `getMailConfig`
pub fn mail_config_json(m: &Mail) -> Json {
    let mut e = Json::object();
    if !m.to.is_empty() {
        let mut l = Json::array();
        for t in &m.to {
            l.push(Json::string(t));
        }
        e.add("email_to", l);
    }
    for (k, v) in [("email_from", &m.from), ("email_reply_to", &m.reply_to), ("email_idsname", &m.idsname), ("smtp_server", &m.smtpserver), ("helo_server", &m.heloserver)] {
        if let Some(v) = v {
            e.add(k, Json::string(v));
        }
    }
    e.add("email_log_source", Json::string(if m.source < 0 || m.source == MAIL_SOURCE_JSON { "alerts.json" } else { "alerts.log" }));
    e.add("email_maxperhour", Json::number(m.maxperhour as f64));
    let mut root = Json::object();
    root.add("global", e);
    root
}

/// `getMailAlertsConfig`
pub fn mail_alerts_json(m: &Mail) -> Json {
    let mut list = Json::array();
    for (i, to) in m.gran_to.iter().enumerate() {
        let mut e = Json::object();
        e.add("email_to", Json::string(to));
        e.add("level", Json::number(m.gran_level.get(i).copied().unwrap_or(0) as f64));
        for (k, v) in [("group", m.gran_group.get(i)), ("location", m.gran_location.get(i))] {
            if let Some(Some(om)) = v {
                let mut l = Json::array();
                for p in om.patterns() {
                    l.push(Json::string(p));
                }
                e.add(k, l);
            }
        }
        if let Some(Some(ids)) = m.gran_id.get(i) {
            let mut l = Json::array();
            for id in ids.iter().take_while(|&&x| x != 0) {
                l.push(Json::number(*id as f64));
            }
            e.add("rule_id", l);
        }
        match m.gran_format.get(i).copied().unwrap_or(0) {
            FULL_FORMAT => e.add("format", Json::string("full")),
            SMS_FORMAT => e.add("format", Json::string("sms")),
            FORWARD_NOW => e.add("format", Json::string("do_not_delay")),
            DONOTGROUP => e.add("format", Json::string("do_not_group")),
            _ => &mut e,
        };
        list.push(e);
    }
    let mut root = Json::object();
    root.add("email_alerts", list);
    root
}

/// `getMailInternalOptions`
pub fn mail_internal_json(m: &Mail) -> Json {
    let mut d = Json::object();
    d.add("strict_checking", Json::number(m.strict_checking as f64));
    d.add("grouping", Json::number(m.grouping as f64));
    let mut i = Json::object();
    i.add("mail", d);
    let mut root = Json::object();
    root.add("internal", i);
    root
}
