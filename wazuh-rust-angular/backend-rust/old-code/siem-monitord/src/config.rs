//! `MonitordConfig` (monitord.c), `Read_CReports` (config/reports-config.c)
//! and the configuration half of `shared/report_op.c`
//! (`os_report_configfilter`, `_report_filter_value`).

use std::path::Path;

use siem_config::global::{read_global, GlobalConfig};
use siem_config::internal_options::InternalOptions;
use siem_config::messages::{xml_invelem, xml_valueerr, xml_valuenull, XML_ELEMNULL};
use siem_config::{modules, read_config, ConfigContext, ConfigError, ConfigHandler, LogLevel, Platform, Section};
use siem_xml::{OsXml, XmlNode};

/// `MAX_DAY_WAIT`
pub const MAX_DAY_WAIT: i16 = 600;

pub use siem_maild::report::*;

/// `os_report_configfilter` with its errors logged through the reader context.
fn configfilter(ctx: &mut ConfigContext, filter_by: &str, value: &str, f: &mut ReportFilter, arg_type: i32) -> i32 {
    let mut errs = Vec::new();
    let r = os_report_configfilter(filter_by, value, f, arg_type, &mut |e| errs.push(e));
    for e in errs {
        ctx.error(e);
    }
    r
}

/// `report_config`
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReportConfig {
    pub title: Option<String>,
    pub type_: Option<String>,
    pub emailto: Vec<String>,
    pub r_filter: ReportFilter,
}

/// `monitor_config`
#[derive(Debug, Clone, Default)]
pub struct MonitorConfig {
    pub day_wait: i16,
    pub compress: u32,
    pub sign: u32,
    pub monitor_agents: u32,
    pub rotate_log: u32,
    pub delete_old_agents: u32,
    pub keep_log_days: i32,
    pub size_rotate: u64,
    pub daily_rotations: i32,
    pub smtpserver: Option<String>,
    pub emailfrom: Option<String>,
    pub emailidsname: Option<String>,
    pub reports: Vec<ReportConfig>,
    pub global: GlobalConfig,
}

/// A message the C code would have logged while reading the configuration.
pub type LogLine = (LogLevel, String);

/// `_filter_arg`: every byte outside `[A-Za-z0-9._-]` becomes '-'.
fn filter_arg(s: &str) -> String {
    let b: Vec<u8> = s.bytes().map(|c| if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.') { c } else { b'-' }).collect();
    String::from_utf8(b).unwrap_or_default()
}

/// `Read_CReports`: appends one report to `reports`.
pub fn read_creports(ctx: &mut ConfigContext, nodes: &[XmlNode], reports: &mut Vec<ReportConfig>) -> siem_config::Result<()> {
    reports.push(ReportConfig::default());
    let r = reports.last_mut().unwrap();
    for n in nodes {
        if n.element.is_empty() {
            return Err(ConfigError::new(XML_ELEMNULL));
        }
        let Some(content) = n.content.as_deref() else {
            return Err(ConfigError::new(xml_valuenull(&n.element)));
        };
        match n.element.as_str() {
            "title" => {
                if r.title.is_none() {
                    r.title = Some(content.to_string());
                }
            }
            "type" => {
                if content == "email" {
                    if r.type_.is_none() {
                        r.type_ = Some(content.to_string());
                    }
                } else {
                    ctx.error(xml_valueerr(&n.element, content));
                }
            }
            "frequency" => {}
            "showlogs" => {
                if content.eq_ignore_ascii_case("yes") {
                    r.r_filter.show_alerts = 1;
                }
            }
            "category" => {
                let v = filter_arg(content);
                if configfilter(ctx, "group", &v, &mut r.r_filter, REPORT_FILTER) != 0 {
                    ctx.error(siem_config::messages::config_error("user argument"));
                }
            }
            "group" | "rule" | "level" | "location" | "srcip" | "user" => {
                let mut reportf = REPORT_FILTER;
                let v = filter_arg(content);
                if let (Some(a), Some(val)) = (n.attributes.first(), n.values.first()) {
                    if a == "type" {
                        if val == "relation" {
                            reportf = REPORT_RELATED;
                        } else {
                            ctx.warn(format!("Invalid value for 'relation' attribute: '{val}'. (ignored)."));
                            continue;
                        }
                    } else {
                        ctx.warn(format!("Invalid attribute: {a} (ignored). "));
                        continue;
                    }
                }
                if configfilter(ctx, &n.element, &v, &mut r.r_filter, reportf) != 0 {
                    ctx.error(format!("Invalid filter: {}:{} (ignored).", n.element, v));
                }
            }
            "email_to" => r.emailto.push(content.to_string()),
            _ => return Err(ConfigError::new(xml_invelem(&n.element))),
        }
    }
    r.r_filter.report_type = REPORT_TYPE_DAILY;
    if r.emailto.is_empty() {
        match &r.title {
            Some(t) => ctx.error(format!("No \"email to\" configured for the report '{t}'. Ignoring it.")),
            None => ctx.error("No \"email to\" and title configured for report. Ignoring it."),
        }
    }
    if r.title.is_none() {
        r.title = Some("OSSEC Report (unnamed)".to_string());
    }
    r.r_filter.report_name = r.title.clone();
    Ok(())
}

struct Handler<'a> {
    reports: &'a mut Vec<ReportConfig>,
    global: &'a mut GlobalConfig,
}

impl ConfigHandler for Handler<'_> {
    fn section(&mut self, ctx: &mut ConfigContext, xml: &OsXml, s: Section, _node: &XmlNode, ch: Option<&[XmlNode]>) -> siem_config::Result<()> {
        let ch = ch.unwrap_or(&[]);
        match s {
            Section::Reports => read_creports(ctx, ch, self.reports),
            Section::Global => read_global(ctx, xml, ch, Some(self.global), None, false, false),
            _ => Ok(()),
        }
    }
}

/// `MonitordConfig`. The messages the readers logged are returned with the
/// result (Err carries the critical message the daemon exits with).
pub fn monitord_config(home: &Path, cfg: &str, no_agents: bool, day_wait: i16) -> (Result<MonitorConfig, String>, Vec<LogLine>) {
    let mut log = Vec::new();
    let r = load(home, cfg, no_agents, day_wait, &mut log);
    (r, log)
}

fn load(home: &Path, cfg: &str, no_agents: bool, day_wait: i16, log: &mut Vec<LogLine>) -> Result<MonitorConfig, String> {
    let opts = InternalOptions::from_home(home);
    let get = |name: &str, min: i32, max: i32| opts.get_int("monitord", name, min, max).map_err(|e| e.0);
    let mut m = MonitorConfig {
        day_wait: if day_wait >= 0 { day_wait } else { get("day_wait", 0, MAX_DAY_WAIT as i32)? as i16 },
        compress: get("compress", 0, 1)? as u32,
        sign: get("sign", 0, 1)? as u32,
        ..Default::default()
    };
    m.monitor_agents = if no_agents { 0 } else { get("monitor_agents", 0, 1)? as u32 };
    m.rotate_log = get("rotate_log", 0, 1)? as u32;
    m.keep_log_days = get("keep_log_days", 0, 500)?;
    m.size_rotate = get("size_rotate", 0, 4096)? as u64 * 1024 * 1024;
    m.daily_rotations = get("daily_rotations", 1, 256)?;
    m.delete_old_agents = get("delete_old_agents", 0, 9600)? as u32;

    // Default agent's global configuration
    m.global.agents_disconnection_time = 900;
    m.global.agents_disconnection_alert_time = 0;

    let cfgfile = home.join(cfg);
    let crit = siem_config::messages::config_error(cfg);
    let mut global = std::mem::take(&mut m.global);
    for pass in [modules::CREPORTS, modules::CGLOBAL] {
        let mut ctx = ConfigContext::new(Platform::MANAGER);
        let mut h = Handler { reports: &mut m.reports, global: &mut global };
        let r = read_config(&mut ctx, pass, &cfgfile, None, &mut h);
        log.append(&mut ctx.log);
        if r.is_err() {
            return Err(crit);
        }
    }
    m.global = global;
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes(xml: &str) -> Vec<XmlNode> {
        let x = OsXml::read_string(xml, false).unwrap();
        let root = x.get_elements_by_node(None).unwrap();
        x.get_elements_by_node(Some(&root[0])).unwrap()
    }

    #[test]
    fn reports_reader() {
        let mut ctx = ConfigContext::new(Platform::MANAGER);
        let mut v = Vec::new();
        let n = nodes("<reports><category>sys log</category><user type=\"relation\">srcip</user><srcip>1.2.3.4</srcip><email_to>a@b</email_to><showlogs>YES</showlogs></reports>");
        read_creports(&mut ctx, &n, &mut v).unwrap();
        let r = &v[0];
        assert_eq!(r.r_filter.group.as_deref(), Some("sys-log"));
        assert_eq!(r.r_filter.related_user, REPORT_REL_SRCIP);
        assert_eq!(r.r_filter.srcip.as_deref(), Some("1.2.3.4"));
        assert_eq!(r.title.as_deref(), Some("OSSEC Report (unnamed)"));
        assert_eq!((r.r_filter.show_alerts, r.r_filter.report_type), (1, REPORT_TYPE_DAILY));
        // the relation value names the filter element, not the content
        let n = nodes("<reports><title>t</title><level type=\"x\">5</level></reports>");
        read_creports(&mut ctx, &n, &mut v).unwrap();
        assert!(ctx.log.iter().any(|(_, m)| m == "Invalid value for 'relation' attribute: 'x'. (ignored)."));
        assert!(ctx.log.iter().any(|(_, m)| m == "No \"email to\" configured for the report 't'. Ignoring it."));
        assert!(read_creports(&mut ctx, &nodes("<reports><bad>1</bad></reports>"), &mut v).is_err());
    }
}
