//! Rules: `rules.c` (`Rules_OP_ReadRules`, attributes, AR binding, hashes,
//! `_setlevels`) and `rules_list.c` (rule tree, overwrite, if_matched marks).

use std::collections::HashMap;

use siem_regex::{ExpType, Expression, OsMatch, OsRegex};
use siem_xml::{OsXml, XmlNode};

use crate::decoders::Decoders;
use crate::event::*;
use crate::lists::{ListRule, Lists, LR_ADDRESS_MATCH, LR_ADDRESS_MATCH_VALUE, LR_ADDRESS_NOT_MATCH, LR_STRING_MATCH,
    LR_STRING_MATCH_VALUE, LR_STRING_NOT_MATCH};
use crate::logmsg::{self, LogList};
use crate::timeday;

pub type RuleId = usize;
pub type ListId = usize;

/* Event fields - stored on a u_int32_t */
pub const FIELD_SRCIP: u32 = 0x01;
pub const FIELD_ID: u32 = 0x02;
pub const FIELD_DSTIP: u32 = 0x04;
pub const FIELD_SRCPORT: u32 = 0x08;
pub const FIELD_DSTPORT: u32 = 0x10;
pub const FIELD_SRCUSER: u32 = 0x20;
pub const FIELD_USER: u32 = 0x40;
pub const FIELD_PROTOCOL: u32 = 0x80;
pub const FIELD_ACTION: u32 = 0x100;
pub const FIELD_URL: u32 = 0x200;
pub const FIELD_DATA: u32 = 0x400;
pub const FIELD_EXTRADATA: u32 = 0x800;
pub const FIELD_STATUS: u32 = 0x1000;
pub const FIELD_SYSTEMNAME: u32 = 0x2000;
pub const FIELD_SRCGEOIP: u32 = 0x4000;
pub const FIELD_DSTGEOIP: u32 = 0x8000;
pub const FIELD_LOCATION: u32 = 0x10000;
pub const ALL_FIELDS: u32 = (1 << 17) - 1;
pub const FIELD_DYNAMICS: u32 = 0x20000;
pub const FIELD_AGENT: u32 = 0x40000;

pub const FIELD_DODIFF: u16 = 0x01;
pub const FIELD_GFREQUENCY: u16 = 0x02;

/* Alert options */
pub const DO_FTS: u16 = 0x0001;
pub const DO_MAILALERT: u16 = 0x0002;
pub const DO_LOGALERT: u16 = 0x0004;
pub const NO_AR: u16 = 0x0008;
pub const NO_ALERT: u16 = 0x0010;
pub const DO_OVERWRITE: u16 = 0x0020;
pub const DO_PACKETINFO: u16 = 0x0040;
pub const DO_EXTRAINFO: u16 = 0x0100;
pub const SAME_EXTRAINFO: u16 = 0x0200;
pub const NO_FULL_LOG: u16 = 0x0400;
pub const NO_COUNTER: u16 = 0x1000;

pub const RULE_SRCIP: i32 = 2;
pub const RULE_SRCPORT: i32 = 4;
pub const RULE_DSTIP: i32 = 8;
pub const RULE_DSTPORT: i32 = 16;
pub const RULE_USER: i32 = 32;
pub const RULE_URL: i32 = 64;
pub const RULE_ID: i32 = 128;
pub const RULE_HOSTNAME: i32 = 256;
pub const RULE_PROGRAM_NAME: i32 = 512;
pub const RULE_STATUS: i32 = 1024;
pub const RULE_ACTION: i32 = 2048;
pub const RULE_DYNAMIC: i32 = 4096;
pub const RULE_PROTOCOL: i32 = 8192;
pub const RULE_SYSTEMNAME: i32 = 16384;
pub const RULE_DATA: i32 = 32768;
pub const RULE_EXTRA_DATA: i32 = 65536;

pub const RULEINFODETAIL_TEXT: i32 = 0;
pub const RULEINFODETAIL_LINK: i32 = 1;
pub const RULEINFODETAIL_CVE: i32 = 2;
pub const RULEINFODETAIL_OSVDB: i32 = 3;
pub const MAX_RULEINFODETAIL: usize = 32;

/// The functions of `compiled_rules_list[]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledRule {
    CheckIdSize,
    CompSrcuserDstuser,
    CompMswinTargetuserCalleruserDiff,
    IsSimpleHttpRequest,
    IsValidCrawler,
}

impl CompiledRule {
    pub fn from_name(n: &str) -> Option<Self> {
        match n {
            "check_id_size" => Some(Self::CheckIdSize),
            "comp_srcuser_dstuser" => Some(Self::CompSrcuserDstuser),
            "comp_mswin_targetuser_calleruser_diff" => Some(Self::CompMswinTargetuserCalleruserDiff),
            "is_simple_http_request" => Some(Self::IsSimpleHttpRequest),
            "is_valid_crawler" => Some(Self::IsValidCrawler),
            _ => None,
        }
    }

    /// Returns true when the C function returns non-NULL.
    pub fn eval(self, ev: &Event) -> bool {
        match self {
            Self::CompSrcuserDstuser => match (&ev.f[F_SRCUSER], &ev.f[F_DSTUSER]) {
                (Some(s), Some(d)) => s == d,
                _ => true,
            },
            Self::CheckIdSize => ev.f[F_ID].as_ref().map_or(false, |id| id.len() >= 10),
            Self::CompMswinTargetuserCalleruserDiff => {
                let log = ev.log();
                let (Some(t), Some(c)) = (find_sub(log, b"Target Account Name"), find_sub(log, b"Caller User Name")) else {
                    return false;
                };
                let (Some(t2), Some(c2)) = (log[t..].iter().position(|&x| x == b':'), log[c..].iter().position(|&x| x == b':'))
                else {
                    return false;
                };
                let mut ti = t + t2 + 1;
                let mut ci = c + c2 + 1;
                let at = |i: usize| log.get(i).copied().unwrap_or(0);
                while at(ti) != 0 {
                    if at(ti) != at(ci) {
                        return true;
                    }
                    if at(ti) == b'\t' || (at(ti) == b' ' && at(ti + 1) == b' ') {
                        break;
                    }
                    ti += 1;
                    ci += 1;
                }
                false
            }
            Self::IsSimpleHttpRequest => match &ev.f[F_URL] {
                None => false,
                Some(u) => u.as_slice() == b"/" || !u.contains(&b'?'),
            },
            Self::IsValidCrawler => {
                let l = ev.log();
                [&b"66.249."[..], b"72.14.", b"209.85.", b"65.55.", b"207.46.", b"74.6.", b"72.30.", b"67.195."]
                    .iter()
                    .any(|p| l.starts_with(p))
            }
        }
    }
}

/// How a context rule searches previous events (`event_search`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSearch {
    LastSids,
    LastGroups,
    LastEvents,
}

#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub name: Option<String>,
    pub regex: Expression,
}

#[derive(Debug, Clone)]
pub struct InfoDetail {
    pub type_: i32,
    pub data: String,
}

/// An active response bound to rules (`active_response`).
#[derive(Debug, Clone, Default)]
pub struct ActiveResponse {
    pub name: Option<String>,
    pub command: Option<String>,
    pub agent_id: Option<String>,
    pub rules_id: Option<String>,
    pub rules_group: Option<String>,
    pub level: i32,
    pub timeout: i32,
    pub location: i32,
    pub ar_cmd: Option<String>,
}

/// `RuleInfo`
#[derive(Debug, Clone, Default)]
pub struct RuleInfo {
    pub sigid: i32,
    pub level: i32,
    pub maxsize: usize,
    pub frequency: i32,
    pub timeframe: i32,
    pub context: u8,
    pub firedtimes: i32,
    pub time_ignored: i64,
    pub ignore_time: i32,
    pub ignore: i32,
    pub ckignore: i32,
    pub ignore_fields: Option<Vec<Option<String>>>,
    pub ckignore_fields: Option<Vec<Option<String>>>,
    pub alert_opts: u16,
    pub context_opts: u16,
    pub same_field: u32,
    pub different_field: u32,
    pub category: u8,
    pub decoded_as: u16,
    pub sid_prev_matched: Option<ListId>,
    pub sid_search: Option<ListId>,
    pub group_prev_matched: Option<Vec<ListId>>,
    pub group_search: Option<ListId>,
    pub event_search: Option<EventSearch>,
    pub group: Option<String>,
    pub match_: Option<Expression>,
    pub regex: Option<Expression>,
    pub day_time: Option<String>,
    pub week_day: Option<Vec<u8>>,
    pub srcip: Option<Expression>,
    pub dstip: Option<Expression>,
    pub srcgeoip: Option<Expression>,
    pub dstgeoip: Option<Expression>,
    pub srcport: Option<Expression>,
    pub dstport: Option<Expression>,
    pub user: Option<Expression>,
    pub url: Option<Expression>,
    pub id: Option<Expression>,
    pub status: Option<Expression>,
    pub hostname: Option<Expression>,
    pub program_name: Option<Expression>,
    pub data: Option<Expression>,
    pub extra_data: Option<Expression>,
    pub location: Option<Expression>,
    pub system_name: Option<Expression>,
    pub protocol: Option<Expression>,
    pub fields: Vec<FieldInfo>,
    pub action: Option<Expression>,
    pub comment: Option<String>,
    pub info: Option<String>,
    pub cve: Option<String>,
    pub info_details: Vec<InfoDetail>,
    pub lists: Vec<ListRule>,
    pub if_sid: Option<String>,
    pub if_level: Option<String>,
    pub if_group: Option<String>,
    pub if_matched_regex: Option<OsRegex>,
    pub if_matched_group: Option<OsMatch>,
    pub if_matched_sid: i32,
    pub compiled_rule: Option<CompiledRule>,
    pub ar: Option<Vec<usize>>,
    pub file: Option<String>,
    pub same_fields: Option<Vec<String>>,
    pub not_same_fields: Option<Vec<String>>,
    pub mitre_id: Option<Vec<String>>,
    pub mitre_tactic_id: Option<Vec<String>>,
    pub mitre_technique_id: Option<Vec<String>>,
}

/// `RuleNode` (`next` is the position in the containing Vec).
#[derive(Debug, Clone)]
pub struct RNode {
    pub rule: RuleId,
    pub children: Vec<RNode>,
}

/// An `OSList` of events (`sid_prev_matched`, `group_search`). Entries are
/// (node id, event id), oldest first.
#[derive(Debug, Clone, Default)]
pub struct EvList {
    pub nodes: Vec<(u64, u64)>,
}

/// Global options the rule loader reads from `Config`.
#[derive(Debug, Clone)]
pub struct RuleConfig {
    pub decoder_order_size: usize,
    pub mailbylevel: i32,
    pub logbylevel: i32,
    /// `analysisd.default_timeframe` internal option.
    pub default_timeframe: i32,
    /// `RULEPATH` prefix for rule files given without a directory.
    pub rulepath: String,
    /// Wazuh home: relative ruleset paths are resolved against it (analysisd
    /// runs chdir'ed there).
    pub home: std::path::PathBuf,
}

/// Resolve a path relative to the Wazuh home.
pub fn resolve(home: &std::path::Path, p: &str) -> std::path::PathBuf {
    let pb = std::path::Path::new(p);
    if pb.is_absolute() {
        pb.to_path_buf()
    } else {
        home.join(pb)
    }
}

impl Default for RuleConfig {
    fn default() -> Self {
        RuleConfig {
            decoder_order_size: 256,
            mailbylevel: 7,
            logbylevel: 1,
            default_timeframe: 360,
            rulepath: "ruleset/rules".into(),
            home: std::path::PathBuf::from("."),
        }
    }
}

/// A loaded rule set: rules arena, tree, the event lists owned by rules and
/// the per-EventList `_max_freq`.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    pub infos: Vec<RuleInfo>,
    pub tree: Vec<RNode>,
    pub lists: Vec<EvList>,
    /// `last_event_list->_max_freq`
    pub max_freq: i32,
    /// Overwriting rules kept alive (`rule_overwrite`).
    pub overwrites: Vec<RuleInfo>,
}

/// Rule files are UTF-8 in practice; `OS_StrIsNum`.
fn str_is_num(s: &str) -> bool {
    siem_regex::str_is_num(s)
}

/// C `atoi`.
pub fn atoi(s: &str) -> i32 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add((b[i] - b'0') as i64);
        i += 1;
    }
    (if neg { -v } else { v }) as i32
}

/// `sscanf(s, "%<w>d", &v)` for a string of digits (as validated by OS_StrIsNum).
fn sscanf_width(s: &str, w: usize) -> i32 {
    let t: String = s.chars().take(w).collect();
    atoi(&t)
}

/// `loadmemory` (rules.c): 2048 byte limits.
fn loadmemory(at: Option<String>, s: &str, log: &mut LogList) -> Option<String> {
    match at {
        None => {
            if s.len() < 2048 {
                Some(s.to_string())
            } else {
                log.error(logmsg::size_error(s));
                None
            }
        }
        Some(mut a) => {
            if a.len() > 2048 || s.len() > 2048 {
                log.error(logmsg::size_error(s));
                return None;
            }
            a.push_str(s);
            Some(a)
        }
    }
}

/// `w_check_attr_negate`
fn check_attr_negate(node: &XmlNode, rule_id: i32, log: &mut LogList) -> bool {
    match node.attr("negate") {
        None => false,
        Some(v) if v.eq_ignore_ascii_case("yes") => true,
        Some(v) if v.eq_ignore_ascii_case("no") => false,
        Some(v) => {
            log.warn(logmsg::inv_value_rule(v, "negate", rule_id));
            false
        }
    }
}

/// `w_check_attr_type`
fn check_attr_type(node: &XmlNode, default: ExpType, rule_id: i32, log: &mut LogList) -> ExpType {
    match node.attr("type") {
        None => default,
        Some(t) if t.eq_ignore_ascii_case("osregex") => ExpType::OsRegex,
        Some(t) if t.eq_ignore_ascii_case("osmatch") => ExpType::OsMatch,
        Some(t) if t.eq_ignore_ascii_case("pcre2") => ExpType::Pcre2,
        Some(t) => {
            log.warn(logmsg::inv_value_rule(t, "type", rule_id));
            default
        }
    }
}

/// `get_info_attributes`
fn get_info_attributes(node: &XmlNode, log: &mut LogList) -> i32 {
    if node.attributes.is_empty() {
        return RULEINFODETAIL_TEXT;
    }
    let a = &node.attributes[0];
    if a.eq_ignore_ascii_case("type") {
        match node.values[0].as_str() {
            "text" => RULEINFODETAIL_TEXT,
            "link" => RULEINFODETAIL_LINK,
            "cve" => RULEINFODETAIL_CVE,
            "osvdb" => RULEINFODETAIL_OSVDB,
            v => {
                log.error(format!("rules_op: Element info attribute \"{a}\" has invalid value \"{v}\""));
                -1
            }
        }
    } else {
        log.error(format!("rules_op: Element info has invalid attribute \"{a}\""));
        -1
    }
}

struct RuleAttrs {
    id: i32,
    level: i32,
    maxsize: i32,
    timeframe: i32,
    frequency: i32,
    accuracy: i32,
    noalert: i32,
    ignore_time: i32,
    overwrite: i32,
}

/// `getattributes`
fn getattributes(node: &XmlNode, a: &mut RuleAttrs, log: &mut LogList) -> Result<(), ()> {
    for (k, attr) in node.attributes.iter().enumerate() {
        let v = node.values[k].as_str();
        if attr.eq_ignore_ascii_case("id") {
            if str_is_num(v) && v.len() <= 6 {
                a.id = sscanf_width(v, 6);
            } else {
                log.error(format!("rules_op: Invalid rule id: {v}. Must be integer (max 6 digits)"));
                return Err(());
            }
        } else if attr.eq_ignore_ascii_case("level") {
            if str_is_num(v) {
                a.level = atoi(v);
                if a.level < 0 || a.level > 16 {
                    log.error(format!("rules_op: Invalid level: {}. Must be an integer between 0 and 16.", a.level));
                    return Err(());
                }
            }
        } else if attr.eq_ignore_ascii_case("maxsize") {
            if str_is_num(v) {
                a.maxsize = sscanf_width(v, 4);
            } else {
                log.error(format!("rules_op: Invalid maxsize: {v}. Must be integer"));
                return Err(());
            }
        } else if attr.eq_ignore_ascii_case("timeframe") {
            if str_is_num(v) {
                a.timeframe = sscanf_width(v, 5);
            } else {
                log.error(format!("rules_op: Invalid timeframe: {v}. Must be integer (max 5 digits)"));
                return Err(());
            }
        } else if attr.eq_ignore_ascii_case("frequency") {
            if str_is_num(v) {
                a.frequency = atoi(v);
                if a.frequency < 2 || a.frequency > 9999 {
                    log.error(format!(
                        "rules_op: Invalid frequency: {}. Must be higher than 1 and lower than 10000.",
                        a.frequency
                    ));
                    return Err(());
                }
                a.frequency -= 2;
            } else {
                log.error(format!("rules_op: Invalid frequency: {v}. Must be integer"));
                return Err(());
            }
        } else if attr.eq_ignore_ascii_case("accuracy") {
            if str_is_num(v) {
                a.accuracy = sscanf_width(v, 4);
            } else {
                log.error(format!("rules_op: Invalid accuracy: {v}. Must be integer"));
                return Err(());
            }
        } else if attr.eq_ignore_ascii_case("ignore") {
            if str_is_num(v) {
                a.ignore_time = sscanf_width(v, 6);
            } else {
                log.error(format!("rules_op: Invalid ignore_time: {v}. Must be integer (max 6 digits)"));
                return Err(());
            }
        } else if attr.eq_ignore_ascii_case("noalert") {
            if v == "0" {
                a.noalert = 0;
            } else if v == "1" {
                a.noalert = 1;
            } else {
                log.warn("Invalid value for attribute 'noalert'");
            }
        } else if attr.eq_ignore_ascii_case("overwrite") {
            if v == "yes" {
                a.overwrite = 1;
            } else if v == "no" {
                a.overwrite = 0;
            } else {
                log.error(format!("rules_op: Invalid overwrite: {v}. Can only by 'yes' or 'no'."));
                return Err(());
            }
        } else {
            log.error(format!(
                "rules_op: Invalid attribute \"{attr}\". Only id, level, maxsize, accuracy, noalert, ignore, frequency and timeframe are allowed."
            ));
            return Err(());
        }
    }
    Ok(())
}

/// Temporary (string) values of a rule before compiling.
#[derive(Default)]
struct Tmp {
    regex: Option<String>,
    match_: Option<String>,
    url: Option<String>,
    if_matched_regex: Option<String>,
    if_matched_group: Option<String>,
    user: Option<String>,
    id: Option<String>,
    srcport: Option<String>,
    dstport: Option<String>,
    srcgeoip: Option<String>,
    dstgeoip: Option<String>,
    protocol: Option<String>,
    system_name: Option<String>,
    status: Option<String>,
    hostname: Option<String>,
    data: Option<String>,
    extra_data: Option<String>,
    program_name: Option<String>,
    location: Option<String>,
    action: Option<String>,
}

/// One string option: (value, negate, type).
struct Opt {
    neg: bool,
    ty: ExpType,
}

impl Rules {
    /// `doesRuleExist`
    pub fn does_rule_exist(&self, sid: i32, nodes: &[RNode]) -> bool {
        nodes.iter().any(|n| self.infos[n.rule].sigid == sid || self.does_rule_exist(sid, &n.children))
    }

    fn new_list(&mut self) -> ListId {
        self.lists.push(EvList::default());
        self.lists.len() - 1
    }

    /// `zerorulemember`
    fn zerorulemember(&mut self, a: &RuleAttrs, cfg: &RuleConfig) -> RuleInfo {
        let mut r = RuleInfo {
            level: a.level,
            category: SYSLOG,
            sigid: a.id,
            maxsize: a.maxsize.max(0) as usize,
            frequency: a.frequency,
            ignore_time: a.ignore_time,
            timeframe: a.timeframe,
            ..Default::default()
        };
        if r.frequency > self.max_freq {
            self.max_freq = r.frequency;
        }
        if a.noalert != 0 {
            r.alert_opts |= NO_ALERT;
        }
        if cfg.mailbylevel <= a.level {
            r.alert_opts |= DO_MAILALERT;
        }
        if cfg.logbylevel <= a.level {
            r.alert_opts |= DO_LOGALERT;
        }
        if a.overwrite != 0 {
            r.alert_opts |= DO_OVERWRITE;
        }
        r
    }

    /// `Rules_OP_ReadRules`: 0 on success (or a missing file), -1 on error.
    #[allow(clippy::too_many_arguments)]
    pub fn read_rules(
        &mut self,
        rulefile: &str,
        lists: &Lists,
        decoders: &Decoders,
        cfg: &RuleConfig,
        ars: Option<&[ActiveResponse]>,
        log: &mut LogList,
    ) -> i32 {
        let rulepath = if !rulefile.contains('/') { format!("{}/{}", cfg.rulepath, rulefile) } else { rulefile.to_string() };

        let full = resolve(&cfg.home, &rulepath);
        let mut xml = match OsXml::read_file(&full, false) {
            Ok(x) => x,
            Err(e) if e.code == -2 => {
                log.warn(logmsg::fopen_error(&rulepath, 2, "No such file or directory"));
                return 0;
            }
            Err(e) => {
                log.error(logmsg::xml_error(&rulepath, &e.message, e.line));
                return -1;
            }
        };
        if let Err(e) = xml.apply_variables() {
            log.error(logmsg::xml_error_var(&rulepath, &e.message));
            return -1;
        }
        if std::fs::metadata(&full).map(|m| m.len()).unwrap_or(0) == 0 {
            return 0;
        }
        let Some(nodes) = xml.get_elements_by_node(None) else {
            log.error(logmsg::config_error(&rulepath));
            return -1;
        };

        let default_timeframe = cfg.default_timeframe;

        for n in &nodes {
            if !n.element.eq_ignore_ascii_case("group") {
                log.error(format!("rules_op: Invalid root element \"{}\".Only \"group\" is allowed", n.element));
                return -1;
            }
            if n.attributes.is_empty() || !n.attributes[0].eq_ignore_ascii_case("name") || n.attributes.len() > 1 {
                log.error(format!("rules_op: Invalid root element '{}'.Only the group name is allowed", n.element));
                return -1;
            }
        }

        for n in &nodes {
            let Some(rules) = xml.get_elements_by_node(Some(n)) else {
                log.error(format!("Group '{}' without any rule.", n.element));
                return -1;
            };

            for (j, rnode) in rules.iter().enumerate() {
                if !rnode.element.eq_ignore_ascii_case("rule") {
                    log.error(format!("Invalid configuration. '{}' is not a valid element.", rnode.element));
                    return -1;
                }
                if rnode.attributes.is_empty() {
                    log.error(format!("Invalid rule '{j}'. You must specify an ID and a level at least."));
                    return -1;
                }

                let mut a = RuleAttrs {
                    id: -1,
                    level: -1,
                    maxsize: 0,
                    timeframe: default_timeframe,
                    frequency: 0,
                    accuracy: 1,
                    noalert: 0,
                    ignore_time: 0,
                    overwrite: 0,
                };
                if getattributes(rnode, &mut a, log).is_err() {
                    log.error("Invalid attribute for rule.");
                    return -1;
                }
                if a.id == -1 || a.level == -1 {
                    log.error(format!("No rule id or level specified for rule '{j}'."));
                    return -1;
                }
                if self.does_rule_exist(a.id, &self.tree) {
                    if a.overwrite != 1 {
                        log.warn(logmsg::duplicated_sig_id(a.id));
                        continue;
                    }
                } else if a.overwrite == 1 {
                    log.warn(logmsg::overwrite_missing_rule(a.id));
                    a.overwrite = 0;
                }

                let mut r = self.zerorulemember(&a, cfg);
                if r.level == 0 {
                    r.level = 99;
                }
                if a.accuracy != 0 {
                    r.level *= 100;
                }
                if r.maxsize > 0 {
                    r.alert_opts |= DO_EXTRAINFO;
                }
                r.group = Some(n.values[0].clone());
                r.file = Some(rulefile.to_string());

                match self.read_rule_elements(&mut xml, rnode, r, lists, decoders, cfg, log) {
                    Err(()) => return -1,
                    Ok(None) => continue, // skipped
                    Ok(Some(mut r)) => {
                        if let Some(ars) = ars {
                            rule_add_ar(&mut r, ars);
                        }
                        if !self.add_loaded_rule(r, log) {
                            continue;
                        }
                    }
                }
            }
        }
        0
    }

    /// The element loop and compilation of one rule. `Ok(None)` = skip rule.
    #[allow(clippy::too_many_arguments)]
    fn read_rule_elements(
        &mut self,
        xml: &mut OsXml,
        rnode: &XmlNode,
        mut r: RuleInfo,
        lists: &Lists,
        decoders: &Decoders,
        cfg: &RuleConfig,
        log: &mut LogList,
    ) -> Result<Option<RuleInfo>, ()> {
        let sid = r.sigid;
        let mut do_skip_rule = false;
        let mut count_info_detail = 0usize;
        let mut mitre_size = 0usize;
        let mut mitre_size_deprecated = 0usize;
        let mut mitre_deprecated = false;
        let mut mitre_new_format = false;
        let mut t = Tmp::default();

        let mut o_regex = Opt { neg: false, ty: ExpType::OsRegex };
        let mut o_match = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_extra = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_host = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_loc = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_pname = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_proto = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_user = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_url = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_sport = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_dport = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_status = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_sysname = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_data = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_sgeo = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_dgeo = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_id = Opt { neg: false, ty: ExpType::OsMatch };
        let mut o_action = Opt { neg: false, ty: ExpType::String };

        let Some(opts) = xml.get_elements_by_node(Some(rnode)) else {
            log.error(format!(
                "Rule '{sid}' without any option. It may lead to false positives and some other problems for the system. Exiting."
            ));
            return Err(());
        };

        for el in &opts {
            let Some(content) = el.content.as_deref() else {
                break;
            };
            let e = el.element.as_str();
            let ie = |name: &str| e.eq_ignore_ascii_case(name);

            macro_rules! stropt {
                ($field:ident, $opt:ident, $default:expr) => {{
                    t.$field = loadmemory(t.$field.take(), content, log);
                    $opt.neg = check_attr_negate(el, sid, log);
                    $opt.ty = check_attr_type(el, $default, sid, log);
                }};
            }

            if ie("regex") {
                stropt!(regex, o_regex, ExpType::OsRegex);
            } else if ie("match") {
                stropt!(match_, o_match, ExpType::OsMatch);
            } else if ie("decoded_as") {
                r.decoded_as = decoders.get_decoder_from_list(content);
                if r.decoded_as == 0 {
                    log.error(format!("Invalid decoder name: '{content}'."));
                    return Err(());
                }
            } else if ie("cve") {
                if r.info_details.is_empty() {
                    r.info_details.push(InfoDetail { type_: RULEINFODETAIL_CVE, data: content.to_string() });
                } else {
                    count_info_detail += r.info_details.len() - 1;
                    if count_info_detail <= MAX_RULEINFODETAIL {
                        r.info_details.push(InfoDetail { type_: RULEINFODETAIL_CVE, data: content.to_string() });
                    }
                }
                r.cve = loadmemory(r.cve.take(), content, log);
            } else if ie("info") {
                let info_type = get_info_attributes(el, log);
                if r.info_details.is_empty() {
                    r.info_details.push(InfoDetail { type_: info_type, data: content.to_string() });
                } else {
                    count_info_detail += r.info_details.len() - 1;
                    if count_info_detail <= MAX_RULEINFODETAIL {
                        r.info_details.push(InfoDetail { type_: info_type, data: content.to_string() });
                    }
                }
                r.info = loadmemory(r.info.take(), content, log);
            } else if ie("time") {
                r.day_time = timeday::os_is_valid_time(content);
                if r.day_time.is_none() {
                    log.error(logmsg::invalid_config(e, content));
                    return Err(());
                }
                r.alert_opts |= DO_EXTRAINFO;
            } else if ie("weekday") {
                r.week_day = timeday::os_is_valid_day(content);
                if r.week_day.is_none() {
                    log.error(logmsg::invalid_day(content));
                    log.error(logmsg::invalid_config(e, content));
                    return Err(());
                }
                r.alert_opts |= DO_EXTRAINFO;
            } else if ie("group") {
                r.group = loadmemory(r.group.take(), content, log);
                if let Some(g) = &mut r.group {
                    // Avoid new lines in group name (wstr_replace "\n" -> "")
                    if g.contains('\n') {
                        *g = g.replace('\n', "");
                    }
                }
            } else if ie("description") {
                let c = content.replacen('\n', " ", 1);
                r.comment = loadmemory(r.comment.take(), &c, log);
            } else if ie("srcip") || ie("dstip") {
                let is_src = ie("srcip");
                let target = if is_src { &mut r.srcip } else { &mut r.dstip };
                if Expression::add_osip(target, content).is_err() || target.is_none() {
                    log.error(logmsg::invalid_ip(content));
                    return Err(());
                }
                let neg = check_attr_negate(el, sid, log);
                let target = if is_src { &mut r.srcip } else { &mut r.dstip };
                if let Some(x) = target {
                    x.negate = neg;
                }
                r.alert_opts |= DO_PACKETINFO;
            } else if ie("user") {
                stropt!(user, o_user, ExpType::OsMatch);
                r.alert_opts |= DO_EXTRAINFO;
            } else if ie("srcgeoip") {
                stropt!(srcgeoip, o_sgeo, ExpType::OsMatch);
                r.alert_opts |= DO_EXTRAINFO;
            } else if ie("dstgeoip") {
                stropt!(dstgeoip, o_dgeo, ExpType::OsMatch);
                r.alert_opts |= DO_EXTRAINFO;
            } else if ie("id") {
                stropt!(id, o_id, ExpType::OsMatch);
            } else if ie("srcport") {
                stropt!(srcport, o_sport, ExpType::OsMatch);
                r.alert_opts |= DO_PACKETINFO;
            } else if ie("dstport") {
                stropt!(dstport, o_dport, ExpType::OsMatch);
                r.alert_opts |= DO_PACKETINFO;
            } else if ie("status") {
                stropt!(status, o_status, ExpType::OsMatch);
                r.alert_opts |= DO_EXTRAINFO;
            } else if ie("hostname") {
                stropt!(hostname, o_host, ExpType::OsMatch);
                r.alert_opts |= DO_EXTRAINFO;
            } else if ie("data") {
                stropt!(data, o_data, ExpType::OsMatch);
                r.alert_opts |= DO_EXTRAINFO;
            } else if ie("extra_data") {
                stropt!(extra_data, o_extra, ExpType::OsMatch);
                r.alert_opts |= DO_EXTRAINFO;
            } else if ie("program_name") {
                stropt!(program_name, o_pname, ExpType::OsMatch);
            } else if ie("action") {
                stropt!(action, o_action, ExpType::String);
            } else if ie("system_name") {
                stropt!(system_name, o_sysname, ExpType::OsMatch);
            } else if ie("protocol") {
                stropt!(protocol, o_proto, ExpType::OsMatch);
            } else if ie("location") {
                stropt!(location, o_loc, ExpType::OsMatch);
            } else if ie("field") {
                if cfg.decoder_order_size <= r.fields.len() {
                    log.error(format!("Rule {sid} has exceeded the maximum number of allowed fields"));
                    return Err(());
                }
                // w_check_attr_field_name
                let Some(name) = (if el.attributes.is_empty() { None } else { el.attr("name") }) else {
                    if !el.attributes.is_empty() {
                        log.error(format!("Failure to read rule {sid}. No such attribute 'name' for field."));
                    }
                    return Err(());
                };
                const STATIC_FIELDS: [&str; 17] = [
                    "srcip", "dstip", "srcgeoip", "dstgeoip", "srcport", "dstport", "user", "srcuser", "dstuser", "url", "id",
                    "data", "extra_data", "status", "protocol", "system_name", "action",
                ];
                if STATIC_FIELDS.iter().any(|f| name.eq_ignore_ascii_case(f)) {
                    log.error(format!("Failure to read rule {sid}. Field '{name}' is static."));
                    return Err(());
                }
                let fname = loadmemory(None, name, log);
                let ty = check_attr_type(el, ExpType::OsRegex, sid, log);
                let neg = check_attr_negate(el, sid, log);
                match Expression::compile(ty, content, 0) {
                    Ok(mut x) => {
                        x.negate = neg;
                        r.fields.push(FieldInfo { name: fname, regex: x });
                    }
                    Err(_) => {
                        log.error(logmsg::rl_regex_syntax(fname.as_deref().unwrap_or("(null)"), sid));
                        return Err(());
                    }
                }
            } else if ie("list") {
                if el.attributes.is_empty() {
                    log.error("List must have a correctly formatted field attribute");
                    log.error(logmsg::invalid_config(e, content));
                    return Err(());
                }
                let mut rule_type = 0;
                let mut rule_dfield: Option<String> = None;
                let mut matcher: Option<OsMatch> = None;
                let mut lookup_type = LR_STRING_MATCH;
                for (ai, attr) in el.attributes.iter().enumerate() {
                    let v = el.values[ai].as_str();
                    if attr.eq_ignore_ascii_case("lookup") {
                        lookup_type = if v.eq_ignore_ascii_case("match_key") {
                            LR_STRING_MATCH
                        } else if v.eq_ignore_ascii_case("not_match_key") {
                            LR_STRING_NOT_MATCH
                        } else if v.eq_ignore_ascii_case("match_key_value") {
                            LR_STRING_MATCH_VALUE
                        } else if v.eq_ignore_ascii_case("address_match_key") {
                            LR_ADDRESS_MATCH
                        } else if v.eq_ignore_ascii_case("not_address_match_key") {
                            LR_ADDRESS_NOT_MATCH
                        } else if v.eq_ignore_ascii_case("address_match_key_value") {
                            LR_ADDRESS_MATCH_VALUE
                        } else {
                            log.error(logmsg::invalid_config(e, content));
                            log.error(format!("List match lookup=\"{v}\" is not valid."));
                            return Err(());
                        };
                    } else if attr.eq_ignore_ascii_case("field") {
                        rule_type = match () {
                            _ if v.eq_ignore_ascii_case("srcip") => RULE_SRCIP,
                            _ if v.eq_ignore_ascii_case("srcport") => RULE_SRCPORT,
                            _ if v.eq_ignore_ascii_case("dstip") => RULE_DSTIP,
                            _ if v.eq_ignore_ascii_case("dstport") => RULE_DSTPORT,
                            _ if v.eq_ignore_ascii_case("user") => RULE_USER,
                            _ if v.eq_ignore_ascii_case("url") => RULE_URL,
                            _ if v.eq_ignore_ascii_case("id") => RULE_ID,
                            _ if v.eq_ignore_ascii_case("hostname") => RULE_HOSTNAME,
                            _ if v.eq_ignore_ascii_case("program_name") => RULE_PROGRAM_NAME,
                            _ if v.eq_ignore_ascii_case("status") => RULE_STATUS,
                            _ if v.eq_ignore_ascii_case("action") => RULE_ACTION,
                            _ if v.eq_ignore_ascii_case("protocol") => RULE_PROTOCOL,
                            _ if v.eq_ignore_ascii_case("system_name") => RULE_SYSTEMNAME,
                            _ if v.eq_ignore_ascii_case("data") => RULE_DATA,
                            _ if v.eq_ignore_ascii_case("extra_data") => RULE_EXTRA_DATA,
                            _ => {
                                let w = v.trim_start_matches(' ');
                                let w = match w.find(' ') {
                                    Some(p) => &w[..p],
                                    None => w,
                                };
                                rule_dfield = Some(w.to_string());
                                RULE_DYNAMIC
                            }
                        };
                    } else if attr.eq_ignore_ascii_case("check_value") {
                        match OsMatch::compile(v, 0) {
                            Ok(m) => matcher = Some(m),
                            Err(_) => {
                                log.error(logmsg::invalid_config(e, content));
                                log.error(logmsg::regex_compile(v, 0));
                                return Err(());
                            }
                        }
                    } else {
                        log.error(format!("List field=\"{v}\" is not valid"));
                        log.error(logmsg::invalid_config(e, content));
                        return Err(());
                    }
                }
                if rule_type == 0 {
                    log.error("List requires the field=\"\" attribute");
                    log.error(logmsg::invalid_config(e, content));
                    return Err(());
                }
                match lists.find_list(content) {
                    None => {
                        log.warn(logmsg::list_not_loaded(content, sid));
                        do_skip_rule = true;
                        break;
                    }
                    Some(db) => r.lists.push(ListRule {
                        field: rule_type,
                        lookup_type,
                        matcher,
                        dfield: if rule_type == RULE_DYNAMIC { rule_dfield } else { None },
                        filename: content.to_string(),
                        db: Some(db),
                    }),
                }
            } else if ie("url") {
                stropt!(url, o_url, ExpType::OsMatch);
            } else if ie("compiled_rule") {
                match CompiledRule::from_name(content) {
                    Some(c) => r.compiled_rule = Some(c),
                    None => {
                        log.error(format!("Compiled rule not found: '{content}'"));
                        log.error(logmsg::invalid_config(e, content));
                        return Err(());
                    }
                }
                r.alert_opts |= DO_EXTRAINFO;
            } else if ie("category") {
                r.category = match content {
                    "firewall" => FIREWALL,
                    "ids" => IDS,
                    "syslog" => SYSLOG,
                    "web-log" => WEBLOG,
                    "squid" => SQUID,
                    "windows" => DECODER_WINDOWS,
                    "ossec" => OSSEC_RL,
                    _ => {
                        log.error(logmsg::invalid_cat(content));
                        return Err(());
                    }
                };
            } else if ie("if_sid") {
                r.if_sid = loadmemory(r.if_sid.take(), content, log);
            } else if ie("if_level") {
                if !str_is_num(content) {
                    log.warn(logmsg::inv_if_level(content, sid));
                    do_skip_rule = true;
                    break;
                }
                r.if_level = loadmemory(r.if_level.take(), content, log);
            } else if ie("if_group") {
                r.if_group = loadmemory(r.if_group.take(), content, log);
            } else if ie("if_matched_regex") {
                r.context = 1;
                t.if_matched_regex = loadmemory(t.if_matched_regex.take(), content, log);
            } else if ie("if_matched_group") {
                r.context = 1;
                t.if_matched_group = loadmemory(t.if_matched_group.take(), content, log);
            } else if ie("if_matched_sid") {
                r.context = 1;
                if !str_is_num(content) {
                    log.warn(logmsg::inv_if_matched_sid(content, sid));
                    do_skip_rule = true;
                    break;
                }
                r.if_matched_sid = atoi(content);
            } else if ie("same_source_ip") || ie("same_srcip") {
                r.same_field |= FIELD_SRCIP;
            } else if ie("same_dstip") {
                r.same_field |= FIELD_DSTIP;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("same_src_port") || ie("same_srcport") {
                r.same_field |= FIELD_SRCPORT;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("same_dst_port") || ie("same_dstport") {
                r.same_field |= FIELD_DSTPORT;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("same_protocol") {
                r.same_field |= FIELD_PROTOCOL;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("same_action") {
                r.same_field |= FIELD_ACTION;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "same_id" {
                r.same_field |= FIELD_ID;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "same_url" {
                r.same_field |= FIELD_URL;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "same_data" {
                r.same_field |= FIELD_DATA;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "same_extra_data" {
                r.same_field |= FIELD_EXTRADATA;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "same_status" {
                r.same_field |= FIELD_STATUS;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "same_system_name" {
                r.same_field |= FIELD_SYSTEMNAME;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "same_srcgeoip" {
                r.same_field |= FIELD_SRCGEOIP;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "same_dstgeoip" {
                r.same_field |= FIELD_DSTGEOIP;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("same_location") {
                r.same_field |= FIELD_LOCATION;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("same_agent") {
                log.warn("Detected a deprecated field option for rule, same_agent is not longer available.");
            } else if ie("same_srcuser") {
                r.same_field |= FIELD_SRCUSER;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("same_user") {
                r.same_field |= FIELD_USER;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("check_diff") {
                r.context = 1;
                r.context_opts |= FIELD_DODIFF;
                r.alert_opts |= DO_EXTRAINFO;
            } else if e == "different_srcip" || e == "not_same_source_ip" {
                r.different_field |= FIELD_SRCIP;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("different_dstip") {
                r.different_field |= FIELD_DSTIP;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("different_src_port") || ie("different_srcport") {
                r.different_field |= FIELD_SRCPORT;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("different_dst_port") || ie("different_dstport") {
                r.different_field |= FIELD_DSTPORT;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "different_protocol" {
                r.different_field |= FIELD_PROTOCOL;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "different_action" {
                r.different_field |= FIELD_ACTION;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "different_id" || e == "not_same_id" {
                r.different_field |= FIELD_ID;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "different_url" {
                r.different_field |= FIELD_URL;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "different_data" {
                r.different_field |= FIELD_DATA;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "different_extra_data" {
                r.different_field |= FIELD_EXTRADATA;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "different_status" {
                r.different_field |= FIELD_STATUS;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "different_system_name" {
                r.different_field |= FIELD_SYSTEMNAME;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "different_srcgeoip" {
                r.different_field |= FIELD_SRCGEOIP;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if e == "different_dstgeoip" {
                r.different_field |= FIELD_DSTGEOIP;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("if_fts") {
                r.alert_opts |= DO_FTS;
            } else if ie("different_srcuser") {
                r.different_field |= FIELD_SRCUSER;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("different_user") || ie("not_same_user") {
                r.different_field |= FIELD_USER;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("not_same_agent") {
                log.warn("Detected a deprecated field option for rule, not_same_agent is not longer available.");
            } else if ie("different_location") {
                r.different_field |= FIELD_LOCATION;
                r.alert_opts |= SAME_EXTRAINFO;
            } else if ie("global_frequency") {
                r.context_opts |= FIELD_GFREQUENCY;
            } else if ie("same_field") {
                r.same_field |= FIELD_DYNAMICS;
                r.same_fields.get_or_insert_with(Vec::new).push(content.to_string());
            } else if ie("not_same_field") || ie("different_field") {
                r.different_field |= FIELD_DYNAMICS;
                r.not_same_fields.get_or_insert_with(Vec::new).push(content.to_string());
            } else if ie("options") {
                match content {
                    "alert_by_email" => r.alert_opts |= DO_MAILALERT,
                    "no_email_alert" => {
                        if r.alert_opts & DO_MAILALERT != 0 {
                            r.alert_opts &= 0xfff - DO_MAILALERT;
                        }
                    }
                    "log_alert" => r.alert_opts |= DO_LOGALERT,
                    "no_log" => {
                        if r.alert_opts & DO_LOGALERT != 0 {
                            r.alert_opts &= 0xfff - DO_LOGALERT;
                        }
                    }
                    "no_ar" => r.alert_opts |= NO_AR,
                    "no_full_log" => r.alert_opts |= NO_FULL_LOG,
                    "no_counter" => r.alert_opts |= NO_COUNTER,
                    _ => {
                        log.error(logmsg::xml_valueerr("options", content));
                        log.error(format!("Invalid option '{e}' for rule '{sid}'."));
                        return Err(());
                    }
                }
            } else if ie("ignore") || ie("check_if_ignored") {
                let is_ignore = ie("ignore");
                let words = siem_regex::str_break(',', content, cfg.decoder_order_size).unwrap_or_default();
                let mut flist: Vec<Option<String>> = vec![None; cfg.decoder_order_size];
                let mut bits = if is_ignore { r.ignore } else { r.ckignore };
                for (i, raw) in words.iter().enumerate() {
                    let w = raw.trim_start_matches(' ');
                    let w = match w.find(' ') {
                        Some(p) => &w[..p],
                        None => w,
                    };
                    if w.is_empty() {
                        log.error(if is_ignore {
                            format!("Wrong ignore option: '{content}'")
                        } else {
                            format!("Wrong check_if_ignored option: '{content}'")
                        });
                        return Err(());
                    }
                    match w {
                        "user" => bits |= FTS_DSTUSER,
                        "srcip" => bits |= FTS_SRCIP,
                        "dstip" => bits |= FTS_DSTIP,
                        "id" => bits |= FTS_ID,
                        "location" => bits |= FTS_LOCATION,
                        "data" => bits |= FTS_DATA,
                        "name" => bits |= FTS_NAME,
                        _ => {
                            if i >= cfg.decoder_order_size {
                                log.error(if is_ignore {
                                    "Too many dynamic fields for ignore."
                                } else {
                                    "Too many dynamic fields for check_if_ignored."
                                });
                                return Err(());
                            }
                            bits |= FTS_DYNAMIC;
                            flist[i] = Some(w.to_string());
                        }
                    }
                }
                if is_ignore {
                    r.ignore = bits;
                    r.ignore_fields = Some(flist);
                } else {
                    r.ckignore = bits;
                    r.ckignore_fields = Some(flist);
                }
            } else if ie("mitre") {
                let Some(mitre_opt) = xml.get_elements_by_node(Some(el)) else {
                    log.warn(format!("Empty Mitre information for rule '{sid}'"));
                    continue;
                };
                let mut failure = false;
                let (mut id_flag, mut tac_flag, mut tech_flag) = (false, false, false);
                let (mut tac_n, mut tech_n) = (0, 0);
                for m in &mitre_opt {
                    let Some(mc) = m.content.as_deref() else {
                        failure = true;
                        break;
                    };
                    if m.element.eq_ignore_ascii_case("id") {
                        if mc.is_empty() {
                            log.warn(format!("No Mitre Technique ID found for rule '{sid}'"));
                            failure = true;
                        } else {
                            id_flag = true;
                        }
                    } else if m.element.eq_ignore_ascii_case("tacticID") {
                        if mc.is_empty() {
                            log.warn(format!("No Mitre Tactic ID found for rule '{sid}'"));
                            failure = true;
                        } else {
                            tac_flag = true;
                            tac_n += 1;
                        }
                    } else if m.element.eq_ignore_ascii_case("techniqueID") {
                        if mc.is_empty() {
                            log.warn(format!("No Mitre Technique ID found for rule '{sid}'"));
                            failure = true;
                        } else {
                            tech_flag = true;
                            tech_n += 1;
                        }
                    } else {
                        log.error(format!("Invalid option '{}' for rule '{sid}'", m.element));
                        failure = true;
                    }
                }
                if !failure {
                    if id_flag {
                        if tac_flag || tech_flag {
                            log.warn(format!(
                                "Rule '{sid}' combined old and new Mitre formats in the same block. The Mitre block will be discarded."
                            ));
                            failure = true;
                        } else if mitre_new_format {
                            log.warn(format!(
                                "Rule '{sid}' combined old and new Mitre formats, the old Mitre Technique format will be discarded."
                            ));
                            r.mitre_id = None;
                            failure = true;
                        } else {
                            mitre_deprecated = true;
                        }
                    } else if tac_flag && tech_flag {
                        if tac_n > 1 || tech_n > 1 {
                            log.warn(format!(
                                "In rule '{sid}' is not allowed to join more than one Mitre techniqueID or tacticID in the same block. The Mitre block will be discarded."
                            ));
                            failure = true;
                        } else {
                            mitre_new_format = true;
                            if mitre_deprecated {
                                log.warn(format!(
                                    "Rule '{sid}' combined old and new Mitre formats, the old Mitre Technique format will be discarded."
                                ));
                                r.mitre_id = None;
                                mitre_deprecated = false;
                            }
                        }
                    } else if !tac_flag && tech_flag {
                        log.warn(format!("Mitre tacticID should be defined in rule '{sid}'"));
                        failure = true;
                    } else if tac_flag && !tech_flag {
                        log.warn(format!("Mitre techniqueID should be defined in rule '{sid}'"));
                        failure = true;
                    }
                }
                if !failure {
                    let mut tactic: Option<String> = None;
                    let mut technique: Option<String> = None;
                    for m in &mitre_opt {
                        let mc = m.content.clone().unwrap_or_default();
                        if m.element.eq_ignore_ascii_case("id") {
                            let ids = r.mitre_id.get_or_insert_with(Vec::new);
                            // `mitre_size_deprecated` counts entries added in this rule
                            let present = ids.iter().take(mitre_size_deprecated).any(|x| *x == mc);
                            if !present {
                                ids.truncate(mitre_size_deprecated);
                                ids.push(mc);
                                mitre_size_deprecated += 1;
                            }
                        } else if m.element.eq_ignore_ascii_case("tacticID") {
                            tactic = Some(mc);
                        } else if m.element.eq_ignore_ascii_case("techniqueID") {
                            technique = Some(mc);
                        }
                    }
                    if let (Some(ta), Some(te)) = (tactic, technique) {
                        let tacs = r.mitre_tactic_id.get_or_insert_with(Vec::new);
                        let techs = r.mitre_technique_id.get_or_insert_with(Vec::new);
                        let present = (0..mitre_size).any(|l| techs[l] == te && tacs[l] == ta);
                        if !present {
                            tacs.push(ta);
                            techs.push(te);
                            mitre_size += 1;
                        }
                    }
                }
            } else {
                log.error(format!("Invalid option '{e}' for rule '{sid}'."));
                return Err(());
            }
        }

        // Check syntax if_sid
        if let Some(if_sid) = &r.if_sid {
            // PCRE2 "^[\d, ]+$" ('$' also matches before a final newline)
            let body = if_sid.strip_suffix('\n').unwrap_or(if_sid);
            let ok = !body.is_empty() && body.bytes().all(|c| c.is_ascii_digit() || c == b',' || c == b' ');
            if !ok {
                do_skip_rule = true;
                log.warn(logmsg::invalid_if_sid(if_sid, sid));
            }
        }

        if do_skip_rule {
            return Ok(None);
        }

        if r.comment.is_none() {
            log.error(format!("No such description at rule '{sid}'."));
            return Err(());
        }

        if (r.context_opts != 0 || r.same_field != 0 || r.different_field != 0 || r.frequency != 0) && r.context == 0 {
            log.error(format!("Invalid use of frequency/context options. Missing if_matched on rule '{sid}'."));
            return Err(());
        }

        if t.if_matched_group.is_some() && r.alert_opts & DO_OVERWRITE == 0 && r.if_sid.is_none() && r.if_group.is_none() {
            r.if_group = t.if_matched_group.clone();
        }

        if r.if_matched_sid != 0 && r.if_sid.is_none() && r.if_group.is_none() && r.alert_opts & DO_OVERWRITE == 0 {
            let mut s = r.if_matched_sid.to_string();
            s.truncate(14);
            r.if_sid = Some(s);
        }

        macro_rules! compile {
            ($src:expr, $dst:expr, $opt:expr, $tag:expr) => {
                if let Some(s) = &$src {
                    match Expression::compile($opt.ty, s, 0) {
                        Ok(mut x) => {
                            x.negate = $opt.neg;
                            $dst = Some(x);
                        }
                        Err(_) => {
                            log.error(logmsg::rl_regex_syntax($tag, sid));
                            return Err(());
                        }
                    }
                }
            };
        }

        compile!(t.regex, r.regex, o_regex, "regex");
        compile!(t.match_, r.match_, o_match, "match");
        compile!(t.id, r.id, o_id, "id");
        compile!(t.srcport, r.srcport, o_sport, "srcport");
        compile!(t.dstport, r.dstport, o_dport, "dstport");
        compile!(t.status, r.status, o_status, "status");
        compile!(t.hostname, r.hostname, o_host, "hostname");
        compile!(t.data, r.data, o_data, "data");
        compile!(t.extra_data, r.extra_data, o_extra, "extra_data");
        compile!(t.program_name, r.program_name, o_pname, "program_name");
        compile!(t.user, r.user, o_user, "user");
        compile!(t.srcgeoip, r.srcgeoip, o_sgeo, "srcgeoip");
        compile!(t.dstgeoip, r.dstgeoip, o_dgeo, "dstgeoip");
        compile!(t.url, r.url, o_url, "url");
        compile!(t.location, r.location, o_loc, "location");
        compile!(t.action, r.action, o_action, "action");

        if let Some(s) = &t.if_matched_group {
            match OsMatch::compile(s, 0) {
                Ok(m) => r.if_matched_group = Some(m),
                Err(_) => {
                    log.error(logmsg::regex_compile(s, 0));
                    return Err(());
                }
            }
        }
        if let Some(s) = &t.if_matched_regex {
            match OsRegex::compile(s, 0) {
                Ok(m) => r.if_matched_regex = Some(m),
                Err(_) => {
                    log.error(logmsg::regex_compile(s, 0));
                    return Err(());
                }
            }
        }
        if let Some(s) = &t.protocol {
            match Expression::compile(o_proto.ty, s, 0) {
                Ok(mut x) => {
                    x.negate = o_proto.neg;
                    r.protocol = Some(x);
                }
                Err(_) => {
                    log.error(logmsg::rl_regex_syntax(s, sid));
                    return Err(());
                }
            }
        }
        compile!(t.system_name, r.system_name, o_sysname, "system_name");

        Ok(Some(r))
    }

    /// The tail of the rule loop: tree insertion and context marks.
    /// Returns false when the rule was dropped.
    fn add_loaded_rule(&mut self, r: RuleInfo, log: &mut LogList) -> bool {
        self.infos.push(r);
        let id = self.infos.len() - 1;
        let sigid = self.infos[id].sigid;

        if sigid < 10 {
            insert_sorted(&self.infos, &mut self.tree, id);
        } else if self.infos[id].alert_opts & DO_OVERWRITE != 0 {
            if self.add_rule_info(id, sigid, log) == 0 && self.add_child(id, log) == -1 {
                return false;
            }
        } else if self.add_child(id, log) == -1 {
            return false;
        }

        self.infos[id].if_group = None;

        let info = &self.infos[id];
        if info.if_matched_sid != 0 && info.alert_opts & DO_OVERWRITE == 0 {
            self.infos[id].event_search = Some(EventSearch::LastSids);
            self.mark_id(id);
        } else if info.if_matched_group.is_some() && info.alert_opts & DO_OVERWRITE == 0 {
            let l = self.new_list();
            self.infos[id].group_search = Some(l);
            self.mark_group(id);
            self.infos[id].event_search = Some(EventSearch::LastGroups);
        } else if info.context != 0 {
            if info.context == 1 && info.context_opts & FIELD_DODIFF != 0 {
                self.infos[id].context = 0;
            } else {
                self.infos[id].event_search = Some(EventSearch::LastEvents);
            }
        }
        true
    }

    /// `_AddtoRule` (recursive).
    fn add_to_rule(&mut self, sid: i32, level: i32, group: Option<&str>, path: &mut Vec<usize>, read: RuleId) -> bool {
        let mut r_code = false;
        let mut i = 0;
        loop {
            let len = node_list(&self.tree, path).len();
            if i >= len {
                break;
            }
            let nrule = node_list(&self.tree, path)[i].rule;
            if sid != 0 {
                if self.infos[nrule].sigid == sid {
                    self.infos[read].category = self.infos[nrule].category;
                    path.push(i);
                    insert_sorted(&self.infos, node_list_mut(&mut self.tree, path), read);
                    path.pop();
                    return true;
                }
            } else if let Some(g) = group {
                let ng = self.infos[nrule].group.clone().unwrap_or_default();
                if siem_regex::os_word_match(g, &ng) && self.infos[nrule].sigid != self.infos[read].sigid {
                    path.push(i);
                    insert_sorted(&self.infos, node_list_mut(&mut self.tree, path), read);
                    path.pop();
                    r_code = true;
                }
            } else if level != 0 {
                if self.infos[nrule].level >= level && self.infos[nrule].sigid != self.infos[read].sigid {
                    path.push(i);
                    insert_sorted(&self.infos, node_list_mut(&mut self.tree, path), read);
                    path.pop();
                    r_code = true;
                }
            } else if self.infos[read].category != self.infos[nrule].category {
                i += 1;
                continue;
            } else {
                self.infos[read].category = self.infos[nrule].category;
                path.push(i);
                insert_sorted(&self.infos, node_list_mut(&mut self.tree, path), read);
                path.pop();
                return true;
            }

            // Check if the child has a rule
            path.push(i);
            let has_children = !node_list(&self.tree, path).is_empty();
            if has_children && self.add_to_rule(sid, level, group, path, read) {
                r_code = true;
            }
            path.pop();
            i += 1;
        }
        r_code
    }

    /// `OS_AddChild`: 0 ok, -1 drop the rule.
    fn add_child(&mut self, read: RuleId, log: &mut LogList) -> i32 {
        let sigid = self.infos[read].sigid;
        if let Some(if_sid) = self.infos[read].if_sid.clone() {
            let b = if_sid.as_bytes();
            let mut id_found = false;
            let mut added_as_child = false;
            let mut p = 0usize;
            loop {
                let c = b.get(p).copied().unwrap_or(0);
                if c == b',' || c == b' ' {
                    id_found = false;
                } else if c.is_ascii_digit() || c == 0 {
                    if !id_found {
                        id_found = true;
                        let rid = atoi(&if_sid[p..]);
                        let mut path = Vec::new();
                        if !self.add_to_rule(rid, 0, None, &mut path, read) {
                            if self.infos[read].if_matched_sid != 0 {
                                log.warn(logmsg::sig_id_not_found_mid(rid, sigid));
                                return -1;
                            } else {
                                log.warn(logmsg::sig_id_not_found(rid, sigid));
                            }
                        } else {
                            added_as_child = true;
                        }
                    }
                } else {
                    let opt = if self.infos[read].if_matched_sid != 0 { "if_matched_sid" } else { "if_sid" };
                    log.warn(logmsg::inv_sig_id(opt, sigid));
                    return if added_as_child { 0 } else { -1 };
                }
                if c == 0 {
                    break;
                }
                p += 1;
            }
            if !added_as_child {
                log.warn(logmsg::empty_sid(sigid));
                return -1;
            }
        } else if let Some(if_level) = self.infos[read].if_level.clone() {
            let mut ilevel = atoi(&if_level);
            if ilevel == 0 {
                log.warn(logmsg::inv_if_level(&if_level, sigid));
                return -1;
            }
            ilevel *= 100;
            let mut path = Vec::new();
            if !self.add_to_rule(0, ilevel, None, &mut path, read) {
                log.warn(logmsg::level_not_found(ilevel, sigid));
                return -1;
            }
        } else if let Some(if_group) = self.infos[read].if_group.clone() {
            let mut path = Vec::new();
            if !self.add_to_rule(0, 0, Some(&if_group), &mut path, read) {
                log.warn(logmsg::group_not_found(&if_group, sigid));
                return -1;
            }
        } else {
            let mut path = Vec::new();
            if !self.add_to_rule(0, 0, None, &mut path, read) {
                log.warn(logmsg::category_not_found(sigid));
                return -1;
            }
        }
        0
    }

    /// `OS_AddRuleInfo`: overwrite the first rule (DFS order) with `sid`.
    /// Returns 1 when overwritten.
    fn add_rule_info(&mut self, newrule: RuleId, sid: i32, log: &mut LogList) -> i32 {
        if self.tree.is_empty() {
            return -1;
        }
        if sid == 0 {
            return 0;
        }
        fn find(rules: &Rules, nodes: &[RNode], sid: i32) -> Option<RuleId> {
            for n in nodes {
                if rules.infos[n.rule].sigid == sid {
                    return Some(n.rule);
                }
                if let Some(r) = find(rules, &n.children, sid) {
                    return Some(r);
                }
            }
            None
        }
        let Some(target) = find(self, &self.tree, sid) else {
            return 0;
        };
        if target == newrule {
            return 0;
        }
        let n = self.infos[newrule].clone();
        let o = &mut self.infos[target];
        o.level = n.level;
        o.maxsize = n.maxsize;
        o.frequency = n.frequency;
        o.timeframe = n.timeframe;
        o.context = n.context;
        o.ignore_time = n.ignore_time;
        o.ignore = n.ignore;
        o.ckignore = n.ckignore;
        o.ignore_fields = n.ignore_fields.clone();
        o.ckignore_fields = n.ckignore_fields.clone();
        o.alert_opts = n.alert_opts;
        o.context_opts = n.context_opts;
        o.same_field = n.same_field;
        o.different_field = n.different_field;
        o.category = n.category;
        o.decoded_as = n.decoded_as;
        o.group = n.group.clone();
        o.match_ = n.match_.clone();
        o.regex = n.regex.clone();
        o.day_time = n.day_time.clone();
        o.week_day = n.week_day.clone();
        o.srcip = n.srcip.clone();
        o.dstip = n.dstip.clone();
        if crate::GEOIP_ENABLED {
            o.srcgeoip = n.srcgeoip.clone();
            o.dstgeoip = n.dstgeoip.clone();
        }
        o.srcport = n.srcport.clone();
        o.dstport = n.dstport.clone();
        o.user = n.user.clone();
        o.url = n.url.clone();
        o.id = n.id.clone();
        o.status = n.status.clone();
        o.hostname = n.hostname.clone();
        o.program_name = n.program_name.clone();
        o.data = n.data.clone();
        o.extra_data = n.extra_data.clone();
        o.location = n.location.clone();
        o.system_name = n.system_name.clone();
        o.protocol = n.protocol.clone();
        o.fields = n.fields.clone();
        o.action = n.action.clone();
        o.comment = n.comment.clone();
        o.info = n.info.clone();
        o.cve = n.cve.clone();
        o.info_details = n.info_details.clone();
        o.lists = n.lists.clone();

        if let Some(ns) = &n.if_sid {
            if n.if_matched_sid == 0 && o.if_sid.as_deref() != Some(ns.as_str()) {
                log.warn(logmsg::inv_overwrite("if_sid", sid));
            }
        }
        if let Some(ng) = &n.if_group {
            if n.if_matched_group.is_none() && o.if_group.as_deref() != Some(ng.as_str()) {
                log.warn(logmsg::inv_overwrite("if_group", sid));
            }
        }
        if let Some(nl) = &n.if_level {
            if o.if_level.as_deref() != Some(nl.as_str()) {
                log.warn(logmsg::inv_overwrite("if_level", sid));
            }
        }
        o.if_matched_regex = n.if_matched_regex.clone();
        if let Some(ng) = &n.if_matched_group {
            if o.if_matched_group.as_ref().map(|m| m.raw()) != Some(ng.raw()) {
                log.warn(logmsg::inv_overwrite("if_matched_group", sid));
            }
        }
        if n.if_matched_sid != 0 && (o.if_matched_sid == 0 || o.if_matched_sid != n.if_matched_sid) {
            log.warn(logmsg::inv_overwrite("if_matched_sid", sid));
        }
        o.compiled_rule = n.compiled_rule;
        o.ar = n.ar.clone();
        o.file = n.file.clone();
        o.same_fields = n.same_fields.clone();
        o.not_same_fields = n.not_same_fields.clone();
        o.mitre_id = n.mitre_id.clone();
        o.mitre_tactic_id = n.mitre_tactic_id.clone();
        o.mitre_technique_id = n.mitre_technique_id.clone();
        // newrule's if_sid / if_level are freed by OS_AddRuleInfo
        self.infos[newrule].if_sid = None;
        self.infos[newrule].if_level = None;
        1
    }

    /// `OS_MarkID`
    fn mark_id(&mut self, orig: RuleId) {
        let want = self.infos[orig].if_matched_sid;
        let mut targets = Vec::new();
        collect_dfs(&self.tree, &mut |n| {
            targets.push(n.rule);
        });
        for r in targets {
            if self.infos[r].sigid == want {
                if self.infos[r].sid_prev_matched.is_none() {
                    let l = self.new_list();
                    self.infos[r].sid_prev_matched = Some(l);
                }
                self.infos[orig].sid_search = self.infos[r].sid_prev_matched;
            }
        }
    }

    /// `OS_MarkGroup`
    fn mark_group(&mut self, orig: RuleId) {
        let gs = self.infos[orig].group_search.expect("group_search");
        let m = self.infos[orig].if_matched_group.clone().expect("if_matched_group");
        let mut targets = Vec::new();
        collect_dfs(&self.tree, &mut |n| targets.push(n.rule));
        for r in targets {
            let g = self.infos[r].group.clone().unwrap_or_default();
            if m.is_match(&g) {
                self.infos[r].group_prev_matched.get_or_insert_with(Vec::new).push(gs);
            }
        }
    }

    /// `_setlevels`
    pub fn set_levels(&mut self) {
        let mut ids = Vec::new();
        collect_dfs(&self.tree, &mut |n| ids.push(n.rule));
        for r in ids {
            let l = &mut self.infos[r].level;
            if *l == 9900 {
                *l = 0;
            }
            if *l >= 100 {
                *l /= 100;
            }
        }
    }

    /// `AddHash_Rule`: sid -> first rule found (DFS order).
    pub fn rules_hash(&self, into: &mut HashMap<String, RuleId>) {
        collect_dfs(&self.tree, &mut |n| {
            into.entry(self.infos[n.rule].sigid.to_string()).or_insert(n.rule);
        });
    }
}

/// Pre-order DFS over a rule tree (node, then its children, then next).
pub fn collect_dfs<'a>(nodes: &'a [RNode], f: &mut dyn FnMut(&'a RNode)) {
    for n in nodes {
        f(n);
        collect_dfs(&n.children, f);
    }
}

fn node_list<'a>(tree: &'a [RNode], path: &[usize]) -> &'a [RNode] {
    let mut l = tree;
    for &p in path {
        l = &l[p].children;
    }
    l
}

fn node_list_mut<'a>(tree: &'a mut Vec<RNode>, path: &[usize]) -> &'a mut Vec<RNode> {
    let mut l = tree;
    for &p in path {
        l = &mut l[p].children;
    }
    l
}

/// `_OS_AddRule`: insert before the first node with a lower level.
fn insert_sorted(infos: &[RuleInfo], list: &mut Vec<RNode>, read: RuleId) {
    let lvl = infos[read].level;
    let pos = list.iter().position(|n| lvl > infos[n.rule].level).unwrap_or(list.len());
    list.insert(pos, RNode { rule: read, children: Vec::new() });
}

/// `Rule_AddAR`
pub fn rule_add_ar(r: &mut RuleInfo, ars: &[ActiveResponse]) {
    let real_level = if r.level == 9900 {
        0
    } else if r.level >= 100 {
        r.level / 100
    } else {
        0
    };
    if real_level == 0 || r.alert_opts & NO_AR != 0 {
        return;
    }
    let group = r.group.clone().unwrap_or_default();
    for (idx, ar) in ars.iter().enumerate() {
        let mut mark = false;
        if ar.level != 0 && ar.rules_group.is_some() {
            if real_level >= ar.level && siem_regex::os_regex(ar.rules_group.as_deref().unwrap(), &group) {
                mark = true;
            }
        } else {
            if ar.level != 0 && real_level >= ar.level {
                mark = true;
            }
            if let Some(rg) = &ar.rules_group {
                if siem_regex::os_regex(rg, &group) {
                    mark = true;
                }
            }
        }
        if let Some(ids) = &ar.rules_id {
            let b = ids.as_bytes();
            let mut p = 0;
            while p < b.len() {
                if b[p] == b' ' || b[p] == b',' {
                    p += 1;
                    continue;
                } else if b[p].is_ascii_digit() {
                    if atoi(&ids[p..]) == r.sigid {
                        mark = true;
                    }
                    match b[p..].iter().position(|&c| c == b',') {
                        Some(c) => p += c + 1,
                        None => break,
                    }
                } else {
                    break;
                }
            }
        }
        if mark {
            r.ar.get_or_insert_with(Vec::new).push(idx);
        }
    }
}
