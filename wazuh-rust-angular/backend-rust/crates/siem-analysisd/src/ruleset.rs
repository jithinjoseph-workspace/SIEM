//! Ruleset file selection: `Read_Rules` (config/rules-config.c) and
//! `Read_Alerts` (config/alerts-config.c), as used by analysisd and
//! `w_logtest_ruleset_load`.

use std::path::Path;

use siem_regex::OsRegex;
use siem_xml::{OsXml, XmlNode};

use crate::logmsg::{self, LogList};

const DEFAULT_RULE_DIR: &str = "ruleset/rules";
const DEFAULT_DECODER_DIR: &str = "ruleset/decoders";

/// The ruleset part of `_Config`.
#[derive(Debug, Clone, Default)]
pub struct RulesetConfig {
    pub decoders: Vec<String>,
    pub includes: Vec<String>,
    pub lists: Vec<String>,
    pub mailbylevel: Option<u8>,
    pub logbylevel: Option<u8>,
}

fn basename(p: &str) -> &str {
    match p.rfind('/') {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

fn file_in_list(f_name: &str, d_name: &str, list: &[String]) -> bool {
    list.iter().any(|a| a == f_name || a == d_name)
}

/// Directory entries in `readdir` order (the platform order).
fn read_dir_names(home: &Path, dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(crate::rules::resolve(home, dir)) {
        for e in rd.flatten() {
            out.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    out
}

/// `Read_Rules` for one `<ruleset>` block.
pub fn read_rules(node: &[XmlNode], cfg: &mut RulesetConfig, home: &Path, log: &mut LogList) -> Result<(), ()> {
    let mut exclude_rules: Vec<String> = Vec::new();
    let mut exclude_decoders: Vec<String> = Vec::new();
    let mut decoder_dirs: Vec<(String, Option<String>)> = Vec::new();
    let mut rules_dirs: Vec<(String, Option<String>)> = Vec::new();

    for n in node {
        let Some(content) = n.content.as_deref() else {
            log.error(logmsg::xml_valuenull(&n.element));
            return Err(());
        };
        match n.element.as_str() {
            "rule_include" => {
                let f = if !content.contains('/') { format!("{DEFAULT_RULE_DIR}/{content}") } else { content.to_string() };
                cfg.includes.push(f);
            }
            "decoder_include" => {
                let f = if !content.contains('/') { format!("{DEFAULT_DECODER_DIR}/{content}") } else { content.to_string() };
                cfg.decoders.push(f);
            }
            "list" => cfg.lists.push(content.to_string()),
            "rule_exclude" => exclude_rules.push(content.to_string()),
            "decoder_exclude" => exclude_decoders.push(content.to_string()),
            "decoder_dir" | "rule_dir" => {
                let pattern = if !n.attributes.is_empty() {
                    let mut p = None;
                    for (i, a) in n.attributes.iter().enumerate() {
                        if a.eq_ignore_ascii_case("pattern") {
                            p = Some(n.values[i].clone());
                        }
                    }
                    p
                } else {
                    Some(".xml$".to_string())
                };
                if n.element == "decoder_dir" {
                    decoder_dirs.push((content.to_string(), pattern));
                } else {
                    rules_dirs.push((content.to_string(), pattern));
                }
            }
            e => {
                log.error(logmsg::xml_invelem(e));
                return Err(());
            }
        }
    }

    if decoder_dirs.is_empty() {
        decoder_dirs.push((DEFAULT_DECODER_DIR.to_string(), Some(".xml$".to_string())));
    }
    if rules_dirs.is_empty() {
        rules_dirs.push((DEFAULT_RULE_DIR.to_string(), Some(".xml$".to_string())));
    }

    for (is_dec, dirs) in [(true, &decoder_dirs), (false, &rules_dirs)] {
        for (dir, pattern) in dirs.iter() {
            let Some(re) = pattern.as_deref().and_then(|p| OsRegex::compile(p, 0).ok()) else {
                log.error(logmsg::config_error(if is_dec {
                    "pattern in decoder_dir does not compile"
                } else {
                    "pattern in rules_dir does not compile"
                }));
                return Err(());
            };
            for d_name in read_dir_names(home, dir) {
                let f_name = format!("{dir}/{d_name}");
                let (excl, list) = if is_dec { (&exclude_decoders, &mut cfg.decoders) } else { (&exclude_rules, &mut cfg.includes) };
                if file_in_list(&f_name, &d_name, excl) {
                    continue;
                }
                if file_in_list(&f_name, &d_name, list) {
                    continue;
                }
                if re.is_match(&f_name) {
                    list.push(f_name);
                }
            }
        }
    }

    // qsort by basename (glibc's merge sort keeps equal keys in order)
    cfg.includes.sort_by(|a, b| basename(a).as_bytes().cmp(basename(b).as_bytes()));
    cfg.decoders.sort_by(|a, b| basename(a).as_bytes().cmp(basename(b).as_bytes()));
    Ok(())
}

/// `Read_Alerts`
pub fn read_alerts(node: &[XmlNode], cfg: &mut RulesetConfig, log: &mut LogList) -> Result<(), ()> {
    for n in node {
        let Some(content) = n.content.as_deref() else {
            log.error(logmsg::xml_valuenull(&n.element));
            return Err(());
        };
        if n.element == "email_alert_level" || n.element == "log_alert_level" {
            if !siem_regex::str_is_num(content) {
                log.error(logmsg::xml_valueerr(&n.element, content));
                return Err(());
            }
            let v = crate::rules::atoi(content) as u8;
            if n.element == "email_alert_level" {
                cfg.mailbylevel = Some(v);
            } else {
                cfg.logbylevel = Some(v);
            }
        }
    }
    Ok(())
}

/// `w_logtest_ruleset_load`: the `<ruleset>` and `<alerts>` blocks of
/// `ossec.conf`.
pub fn load_from_ossec_conf(conf: &Path, home: &Path, log: &mut LogList) -> Option<RulesetConfig> {
    load_ruleset_conf(conf, &conf.display().to_string(), home, true, log)
}

/// `w_logtest_ruleset_load` (`alerts`: also the `<alerts>` blocks) and
/// `w_hotreload_ruleset_load` (only `<ruleset>`). `shown` is the file name
/// used in messages (analysisd's relative `etc/ossec.conf`).
pub fn load_ruleset_conf(conf: &Path, shown: &str, home: &Path, alerts: bool, log: &mut LogList) -> Option<RulesetConfig> {
    let xml = match OsXml::read_file(conf, false) {
        Ok(x) => x,
        Err(e) => {
            log.error(logmsg::xml_error(shown, &e.message, e.line));
            return None;
        }
    };
    let Some(nodes) = xml.get_elements_by_node(None) else {
        log.error(format!("There are no configuration blocks inside of '{shown}'"));
        return None;
    };
    let mut cfg = RulesetConfig::default();
    for n in &nodes {
        if n.element != "ossec_config" {
            continue;
        }
        let Some(sections) = xml.get_elements_by_node(Some(n)) else {
            continue;
        };
        for sec in &sections {
            let Some(opts) = xml.get_elements_by_node(Some(sec)) else {
                log.error(logmsg::XML_ELEMNULL);
                log.error(logmsg::config_error(shown));
                return None;
            };
            if sec.element == "ruleset" && read_rules(&opts, &mut cfg, home, log).is_err() {
                log.error(logmsg::config_error(shown));
                return None;
            }
            if alerts && sec.element == "alerts" && read_alerts(&opts, &mut cfg, log).is_err() {
                log.error(logmsg::config_error(shown));
                return None;
            }
        }
    }
    Some(cfg)
}
