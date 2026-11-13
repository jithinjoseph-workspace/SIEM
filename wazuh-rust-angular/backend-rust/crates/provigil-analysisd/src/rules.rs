//! Rules (spec section 2.6): reading the rule files into the rule tree (children under the
//! rules they name in `if_sid`, `if_level`, `if_group`, or by category), overwrites, the
//! context lists of `if_matched_*` rules, active response binding, levels and the rule hash.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use provigil_regex::{ExpType, Expression, OsMatch, OsRegex};

use crate::config::Response;
use crate::decoders::DecoderSet;
use crate::event::*;
use crate::lists::{self, ListCheck, Lists};
use crate::messages::{self as m, Messages};

pub type ListId = usize;

// Fields compared by same_* / different_* (bit order of the fixed fields).
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

// Alert options.
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

// List condition fields.
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

pub const INFO_TEXT: i32 = 0;
pub const INFO_LINK: i32 = 1;
pub const INFO_CVE: i32 = 2;
pub const INFO_OSVDB: i32 = 3;
const MAX_INFO_DETAILS: usize = 32;

/// The built-in checks a rule can name in `<compiled_rule>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    IdSize,
    SameUsers,
    WindowsAccountDiffers,
    SimpleHttpRequest,
    Crawler,
}

impl Check {
    pub fn named(n: &str) -> Option<Check> {
        Some(match n {
            "check_id_size" => Check::IdSize,
            "comp_srcuser_dstuser" => Check::SameUsers,
            "comp_mswin_targetuser_calleruser_diff" => Check::WindowsAccountDiffers,
            "is_simple_http_request" => Check::SimpleHttpRequest,
            "is_valid_crawler" => Check::Crawler,
            _ => return None,
        })
    }

    pub fn passes(self, ev: &Event) -> bool {
        match self {
            Check::SameUsers => match (&ev.f[F_SRCUSER], &ev.f[F_DSTUSER]) {
                (Some(s), Some(d)) => s == d,
                _ => true,
            },
            Check::IdSize => ev.f[F_ID].as_ref().is_some_and(|id| id.len() >= 10),
            Check::WindowsAccountDiffers => {
                let log = ev.log();
                let after_colon = |label: &[u8]| find(log, label).and_then(|p| log[p..].iter().position(|&c| c == b':').map(|c| p + c + 1));
                let (Some(mut t), Some(mut c)) = (after_colon(b"Target Account Name"), after_colon(b"Caller User Name")) else { return false };
                let at = |i: usize| log.get(i).copied().unwrap_or(0);
                while at(t) != 0 {
                    if at(t) != at(c) {
                        return true;
                    }
                    if at(t) == b'\t' || (at(t) == b' ' && at(t + 1) == b' ') {
                        break;
                    }
                    t += 1;
                    c += 1;
                }
                false
            }
            Check::SimpleHttpRequest => ev.f[F_URL].as_ref().is_some_and(|u| u.as_slice() == b"/" || !u.contains(&b'?')),
            Check::Crawler => {
                let l = ev.log();
                ["66.249.", "72.14.", "209.85.", "65.55.", "207.46.", "74.6.", "72.30.", "67.195."].iter().any(|p| l.starts_with(p.as_bytes()))
            }
        }
    }
}

/// How a context rule looks at earlier events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSearch {
    LastSids,
    LastGroups,
    LastEvents,
}

#[derive(Debug, Clone)]
pub struct FieldMatch {
    pub name: Option<String>,
    pub regex: Expression,
}

#[derive(Debug, Clone)]
pub struct InfoDetail {
    pub kind: i32,
    pub data: String,
}

#[derive(Debug, Clone, Default)]
pub struct Rule {
    pub sigid: i32,
    /// times 100 while loading; 9900 is level 0
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
    pub fields: Vec<FieldMatch>,
    pub action: Option<Expression>,
    pub comment: Option<String>,
    pub info: Option<String>,
    pub cve: Option<String>,
    pub info_details: Vec<InfoDetail>,
    pub lists: Vec<ListCheck>,
    pub if_sid: Option<String>,
    pub if_level: Option<String>,
    pub if_group: Option<String>,
    pub if_matched_regex: Option<OsRegex>,
    pub if_matched_group: Option<OsMatch>,
    pub if_matched_sid: i32,
    pub check: Option<Check>,
    /// indexes in the active responses
    pub ar: Option<Vec<usize>>,
    pub file: Option<String>,
    pub same_fields: Option<Vec<String>>,
    pub not_same_fields: Option<Vec<String>>,
    pub mitre_id: Option<Vec<String>>,
    pub mitre_tactic_id: Option<Vec<String>>,
    pub mitre_technique_id: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct RuleNode {
    pub rule: RuleId,
    pub children: Vec<RuleNode>,
}

/// Earlier events kept for context rules: (node id, event id), oldest first.
#[derive(Debug, Clone, Default)]
pub struct EventList {
    pub nodes: Vec<(u64, u64)>,
}

/// What the loader needs from the settings.
#[derive(Debug, Clone)]
pub struct RuleSettings {
    pub order_size: usize,
    pub email_level: i32,
    pub log_level: i32,
    pub default_timeframe: i32,
    /// Where rule files named without a folder are.
    pub rule_dir: String,
    pub home: PathBuf,
}

impl Default for RuleSettings {
    fn default() -> RuleSettings {
        RuleSettings { order_size: 256, email_level: 7, log_level: 1, default_timeframe: 360, rule_dir: crate::config::RULE_DIR.into(), home: ".".into() }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    /// Shared, so matching reads a rule without copying it.
    pub rules: Vec<Arc<Rule>>,
    pub tree: Vec<RuleNode>,
    pub event_lists: Vec<EventList>,
    /// The highest frequency of all rules.
    pub max_frequency: i32,
}

/// C-style leading integer (wrapping).
pub fn atoi(s: &str) -> i32 {
    let b = s.as_bytes();
    let mut i = b.iter().take_while(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)).count();
    let neg = b.get(i) == Some(&b'-');
    if matches!(b.get(i), Some(b'+' | b'-')) {
        i += 1;
    }
    let mut v: i64 = 0;
    while let Some(c) = b.get(i).filter(|c| c.is_ascii_digit()) {
        v = v.wrapping_mul(10).wrapping_add(i64::from(c - b'0'));
        i += 1;
    }
    (if neg { -v } else { v }) as i32
}

/// The number in the first `w` characters.
fn first_digits(s: &str, w: usize) -> i32 {
    atoi(&s.chars().take(w).collect::<String>())
}

fn digits(s: &str) -> bool {
    provigil_regex::str_is_num(s)
}

/// Appends to a rule text: a first text under 2,048 bytes; later ones each at most 2,048
/// bytes after a text of at most 2,048 (too long drops the whole text).
fn append(to: Option<String>, s: &str, msgs: &mut Messages) -> Option<String> {
    let ok = match &to {
        None => s.len() < 2048,
        Some(t) => t.len() <= 2048 && s.len() <= 2048,
    };
    if !ok {
        msgs.error(m::too_long(s));
        return None;
    }
    Some(to.unwrap_or_default() + s)
}

type XNode = provigil_daemon::xml::Node;

fn negate_attribute(n: &XNode, id: i32, msgs: &mut Messages) -> bool {
    match n.attribute("negate") {
        Some(v) if v.eq_ignore_ascii_case("yes") => true,
        None => false,
        Some(v) if v.eq_ignore_ascii_case("no") => false,
        Some(v) => {
            msgs.warn(m::bad_rule_attribute(v, "negate", id));
            false
        }
    }
}

fn type_attribute(n: &XNode, default: ExpType, id: i32, msgs: &mut Messages) -> ExpType {
    match n.attribute("type") {
        None => default,
        Some(t) if t.eq_ignore_ascii_case("osregex") => ExpType::OsRegex,
        Some(t) if t.eq_ignore_ascii_case("osmatch") => ExpType::OsMatch,
        Some(t) if t.eq_ignore_ascii_case("pcre2") => ExpType::Pcre2,
        Some(t) => {
            msgs.warn(m::bad_rule_attribute(t, "type", id));
            default
        }
    }
}

fn info_kind(n: &XNode, msgs: &mut Messages) -> i32 {
    let Some((a, v)) = n.attributes.first() else { return INFO_TEXT };
    if !a.eq_ignore_ascii_case("type") {
        msgs.error(format!("rules_op: Element info has invalid attribute \"{a}\""));
        return -1;
    }
    match v.as_str() {
        "text" => INFO_TEXT,
        "link" => INFO_LINK,
        "cve" => INFO_CVE,
        "osvdb" => INFO_OSVDB,
        _ => {
            msgs.error(format!("rules_op: Element info attribute \"{a}\" has invalid value \"{v}\""));
            -1
        }
    }
}

/// The `<rule>` attributes.
struct Head {
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

fn read_head(n: &XNode, h: &mut Head, msgs: &mut Messages) -> Result<(), ()> {
    for (a, v) in &n.attributes {
        let is = |x: &str| a.eq_ignore_ascii_case(x);
        let fail = |msgs: &mut Messages, t: String| {
            msgs.error(t);
            Err(())
        };
        if is("id") {
            if !(digits(v) && v.len() <= 6) {
                return fail(msgs, format!("rules_op: Invalid rule id: {v}. Must be integer (max 6 digits)"));
            }
            h.id = first_digits(v, 6);
        } else if is("level") {
            if digits(v) {
                h.level = atoi(v);
                if !(0..=16).contains(&h.level) {
                    return fail(msgs, format!("rules_op: Invalid level: {}. Must be an integer between 0 and 16.", h.level));
                }
            }
        } else if is("maxsize") {
            if !digits(v) {
                return fail(msgs, format!("rules_op: Invalid maxsize: {v}. Must be integer"));
            }
            h.maxsize = first_digits(v, 4);
        } else if is("timeframe") {
            if !digits(v) {
                return fail(msgs, format!("rules_op: Invalid timeframe: {v}. Must be integer (max 5 digits)"));
            }
            h.timeframe = first_digits(v, 5);
        } else if is("frequency") {
            if !digits(v) {
                return fail(msgs, format!("rules_op: Invalid frequency: {v}. Must be integer"));
            }
            h.frequency = atoi(v);
            if !(2..=9999).contains(&h.frequency) {
                return fail(msgs, format!("rules_op: Invalid frequency: {}. Must be higher than 1 and lower than 10000.", h.frequency));
            }
            h.frequency -= 2;
        } else if is("accuracy") {
            if !digits(v) {
                return fail(msgs, format!("rules_op: Invalid accuracy: {v}. Must be integer"));
            }
            h.accuracy = first_digits(v, 4);
        } else if is("ignore") {
            if !digits(v) {
                return fail(msgs, format!("rules_op: Invalid ignore_time: {v}. Must be integer (max 6 digits)"));
            }
            h.ignore_time = first_digits(v, 6);
        } else if is("noalert") {
            match v.as_str() {
                "0" => h.noalert = 0,
                "1" => h.noalert = 1,
                _ => msgs.warn("Invalid value for attribute 'noalert'"),
            }
        } else if is("overwrite") {
            match v.as_str() {
                "yes" => h.overwrite = 1,
                "no" => h.overwrite = 0,
                _ => return fail(msgs, format!("rules_op: Invalid overwrite: {v}. Can only by 'yes' or 'no'.")),
            }
        } else {
            return fail(msgs, format!("rules_op: Invalid attribute \"{a}\". Only id, level, maxsize, accuracy, noalert, ignore, frequency and timeframe are allowed."));
        }
    }
    Ok(())
}

/// The pattern options of a rule, in the order they are compiled.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Text {
    Regex,
    Match,
    Id,
    SrcPort,
    DstPort,
    Status,
    Hostname,
    Data,
    ExtraData,
    ProgramName,
    User,
    SrcGeoip,
    DstGeoip,
    Url,
    Location,
    Action,
    Protocol,
    SystemName,
}

const TEXTS: [(Text, &str, ExpType, u16); 18] = [
    (Text::Regex, "regex", ExpType::OsRegex, 0),
    (Text::Match, "match", ExpType::OsMatch, 0),
    (Text::Id, "id", ExpType::OsMatch, 0),
    (Text::SrcPort, "srcport", ExpType::OsMatch, DO_PACKETINFO),
    (Text::DstPort, "dstport", ExpType::OsMatch, DO_PACKETINFO),
    (Text::Status, "status", ExpType::OsMatch, DO_EXTRAINFO),
    (Text::Hostname, "hostname", ExpType::OsMatch, DO_EXTRAINFO),
    (Text::Data, "data", ExpType::OsMatch, DO_EXTRAINFO),
    (Text::ExtraData, "extra_data", ExpType::OsMatch, DO_EXTRAINFO),
    (Text::ProgramName, "program_name", ExpType::OsMatch, 0),
    (Text::User, "user", ExpType::OsMatch, DO_EXTRAINFO),
    (Text::SrcGeoip, "srcgeoip", ExpType::OsMatch, DO_EXTRAINFO),
    (Text::DstGeoip, "dstgeoip", ExpType::OsMatch, DO_EXTRAINFO),
    (Text::Url, "url", ExpType::OsMatch, 0),
    (Text::Location, "location", ExpType::OsMatch, 0),
    (Text::Action, "action", ExpType::String, 0),
    (Text::Protocol, "protocol", ExpType::OsMatch, 0),
    (Text::SystemName, "system_name", ExpType::OsMatch, 0),
];

#[derive(Clone)]
struct TextOption {
    text: Option<String>,
    negate: bool,
    kind: ExpType,
}

impl Rule {
    fn slot(&mut self, t: Text) -> &mut Option<Expression> {
        match t {
            Text::Regex => &mut self.regex,
            Text::Match => &mut self.match_,
            Text::Id => &mut self.id,
            Text::SrcPort => &mut self.srcport,
            Text::DstPort => &mut self.dstport,
            Text::Status => &mut self.status,
            Text::Hostname => &mut self.hostname,
            Text::Data => &mut self.data,
            Text::ExtraData => &mut self.extra_data,
            Text::ProgramName => &mut self.program_name,
            Text::User => &mut self.user,
            Text::SrcGeoip => &mut self.srcgeoip,
            Text::DstGeoip => &mut self.dstgeoip,
            Text::Url => &mut self.url,
            Text::Location => &mut self.location,
            Text::Action => &mut self.action,
            Text::Protocol => &mut self.protocol,
            Text::SystemName => &mut self.system_name,
        }
    }
}

/// Element names compared exactly (the others without case).
const EXACT: &[&str] = &[
    "same_id",
    "same_url",
    "same_data",
    "same_extra_data",
    "same_status",
    "same_system_name",
    "same_srcgeoip",
    "same_dstgeoip",
    "different_srcip",
    "not_same_source_ip",
    "different_protocol",
    "different_action",
    "different_id",
    "not_same_id",
    "different_url",
    "different_data",
    "different_extra_data",
    "different_status",
    "different_system_name",
    "different_srcgeoip",
    "different_dstgeoip",
];

/// same_* / different_* elements: (same, field, also SAME_EXTRAINFO).
fn compare_element(e: &str) -> Option<(bool, u32, bool)> {
    Some(match e {
        "same_source_ip" | "same_srcip" => (true, FIELD_SRCIP, false),
        "same_dstip" => (true, FIELD_DSTIP, true),
        "same_src_port" | "same_srcport" => (true, FIELD_SRCPORT, true),
        "same_dst_port" | "same_dstport" => (true, FIELD_DSTPORT, true),
        "same_protocol" => (true, FIELD_PROTOCOL, true),
        "same_action" => (true, FIELD_ACTION, true),
        "same_id" => (true, FIELD_ID, true),
        "same_url" => (true, FIELD_URL, true),
        "same_data" => (true, FIELD_DATA, true),
        "same_extra_data" => (true, FIELD_EXTRADATA, true),
        "same_status" => (true, FIELD_STATUS, true),
        "same_system_name" => (true, FIELD_SYSTEMNAME, true),
        "same_srcgeoip" => (true, FIELD_SRCGEOIP, true),
        "same_dstgeoip" => (true, FIELD_DSTGEOIP, true),
        "same_location" => (true, FIELD_LOCATION, true),
        "same_srcuser" => (true, FIELD_SRCUSER, true),
        "same_user" => (true, FIELD_USER, true),
        "different_srcip" | "not_same_source_ip" => (false, FIELD_SRCIP, true),
        "different_dstip" => (false, FIELD_DSTIP, true),
        "different_src_port" | "different_srcport" => (false, FIELD_SRCPORT, true),
        "different_dst_port" | "different_dstport" => (false, FIELD_DSTPORT, true),
        "different_protocol" => (false, FIELD_PROTOCOL, true),
        "different_action" => (false, FIELD_ACTION, true),
        "different_id" | "not_same_id" => (false, FIELD_ID, true),
        "different_url" => (false, FIELD_URL, true),
        "different_data" => (false, FIELD_DATA, true),
        "different_extra_data" => (false, FIELD_EXTRADATA, true),
        "different_status" => (false, FIELD_STATUS, true),
        "different_system_name" => (false, FIELD_SYSTEMNAME, true),
        "different_srcgeoip" => (false, FIELD_SRCGEOIP, true),
        "different_dstgeoip" => (false, FIELD_DSTGEOIP, true),
        "different_srcuser" => (false, FIELD_SRCUSER, true),
        "different_user" | "not_same_user" => (false, FIELD_USER, true),
        "different_location" => (false, FIELD_LOCATION, true),
        _ => return None,
    })
}

fn list_field(v: &str) -> (i32, Option<String>) {
    let known = [
        ("srcip", RULE_SRCIP),
        ("srcport", RULE_SRCPORT),
        ("dstip", RULE_DSTIP),
        ("dstport", RULE_DSTPORT),
        ("user", RULE_USER),
        ("url", RULE_URL),
        ("id", RULE_ID),
        ("hostname", RULE_HOSTNAME),
        ("program_name", RULE_PROGRAM_NAME),
        ("status", RULE_STATUS),
        ("action", RULE_ACTION),
        ("protocol", RULE_PROTOCOL),
        ("system_name", RULE_SYSTEMNAME),
        ("data", RULE_DATA),
        ("extra_data", RULE_EXTRA_DATA),
    ];
    match known.iter().find(|(n, _)| v.eq_ignore_ascii_case(n)) {
        Some((_, f)) => (*f, None),
        None => (RULE_DYNAMIC, Some(v.trim_start_matches(' ').split(' ').next().unwrap_or("").to_string())),
    }
}

/// Looks a rule up by id anywhere in the tree (depth first).
fn find_in(rules: &[Arc<Rule>], nodes: &[RuleNode], sid: i32) -> Option<RuleId> {
    nodes.iter().find_map(|n| if rules[n.rule].sigid == sid { Some(n.rule) } else { find_in(rules, &n.children, sid) })
}

/// Every node, parent before children.
pub fn walk<'a>(nodes: &'a [RuleNode], f: &mut dyn FnMut(&'a RuleNode)) {
    for n in nodes {
        f(n);
        walk(&n.children, f);
    }
}

fn list_at<'a>(tree: &'a [RuleNode], path: &[usize]) -> &'a [RuleNode] {
    path.iter().fold(tree, |l, &p| &l[p].children)
}

fn list_at_mut<'a>(tree: &'a mut Vec<RuleNode>, path: &[usize]) -> &'a mut Vec<RuleNode> {
    path.iter().fold(tree, |l, &p| &mut l[p].children)
}

/// Inserts before the first node of a lower level.
fn insert(rules: &[Arc<Rule>], list: &mut Vec<RuleNode>, r: RuleId) {
    let level = rules[r].level;
    let at = list.iter().position(|n| level > rules[n.rule].level).unwrap_or(list.len());
    list.insert(at, RuleNode { rule: r, children: Vec::new() });
}

/// Binds active responses to a rule: by level and group, and by rule id.
pub fn bind_responses(r: &mut Rule, responses: &[Response]) {
    let level = match r.level {
        9900 => 0,
        l if l >= 100 => l / 100,
        _ => 0,
    };
    if level == 0 || r.alert_opts & NO_AR != 0 {
        return;
    }
    let group = r.group.clone().unwrap_or_default();
    for (i, ar) in responses.iter().enumerate() {
        let in_group = |g: &str| provigil_regex::os_regex(g, &group);
        let mut bound = match &ar.rules_group {
            Some(g) if ar.level != 0 => level >= ar.level && in_group(g),
            g => (ar.level != 0 && level >= ar.level) | g.as_deref().is_some_and(in_group),
        };
        if let Some(ids) = &ar.rules_id {
            let b = ids.as_bytes();
            let mut p = 0;
            while p < b.len() {
                match b[p] {
                    b' ' | b',' => p += 1,
                    c if c.is_ascii_digit() => {
                        bound |= atoi(&ids[p..]) == r.sigid;
                        match b[p..].iter().position(|&c| c == b',') {
                            Some(c) => p += c + 1,
                            None => break,
                        }
                    }
                    _ => break,
                }
            }
        }
        if bound {
            r.ar.get_or_insert_with(Vec::new).push(i);
        }
    }
}

impl RuleSet {
    pub fn exists(&self, sid: i32) -> bool {
        find_in(&self.rules, &self.tree, sid).is_some()
    }

    fn new_event_list(&mut self) -> ListId {
        self.event_lists.push(EventList::default());
        self.event_lists.len() - 1
    }

    fn rule_mut(&mut self, r: RuleId) -> &mut Rule {
        Arc::make_mut(&mut self.rules[r])
    }

    /// Loads a rule file (`file` as configured: without `/` it is in the rule folder). 0 on
    /// success or when missing, -1 on error.
    pub fn load_file(&mut self, file: &str, lists: &Lists, decoders: &DecoderSet, s: &RuleSettings, responses: Option<&[Response]>, msgs: &mut Messages) -> i32 {
        let shown = if file.contains('/') { file.to_string() } else { format!("{}/{file}", s.rule_dir) };
        let Ok(data) = std::fs::read(crate::config::resolve(&s.home, &shown)) else {
            msgs.warn(m::open_failed(&shown, 2, "No such file or directory"));
            return 0;
        };
        if let Err(e) = provigil_daemon::xml::parse(&data) {
            msgs.error(m::xml_failed(&shown, &e.message, e.line));
            return -1;
        }
        let groups = match provigil_daemon::xml::parse_with_variables(&data) {
            Ok(r) => r,
            Err(e) => {
                msgs.error(m::variables_failed(&shown, &e.message));
                return -1;
            }
        };
        if data.is_empty() {
            return 0;
        }
        if groups.is_empty() {
            msgs.error(m::config_error(&shown));
            return -1;
        }
        for g in &groups {
            if !g.name.eq_ignore_ascii_case("group") {
                msgs.error(format!("rules_op: Invalid root element \"{}\".Only \"group\" is allowed", g.name));
                return -1;
            }
            if g.attributes.len() != 1 || !g.attributes[0].0.eq_ignore_ascii_case("name") {
                msgs.error(format!("rules_op: Invalid root element '{}'.Only the group name is allowed", g.name));
                return -1;
            }
        }
        for g in &groups {
            if g.children.is_empty() {
                msgs.error(format!("Group '{}' without any rule.", g.name));
                return -1;
            }
            for (j, node) in g.children.iter().enumerate() {
                if !node.name.eq_ignore_ascii_case("rule") {
                    msgs.error(format!("Invalid configuration. '{}' is not a valid element.", node.name));
                    return -1;
                }
                if node.attributes.is_empty() {
                    msgs.error(format!("Invalid rule '{j}'. You must specify an ID and a level at least."));
                    return -1;
                }
                let mut h = Head { id: -1, level: -1, maxsize: 0, timeframe: s.default_timeframe, frequency: 0, accuracy: 1, noalert: 0, ignore_time: 0, overwrite: 0 };
                if read_head(node, &mut h, msgs).is_err() {
                    msgs.error("Invalid attribute for rule.");
                    return -1;
                }
                if h.id == -1 || h.level == -1 {
                    msgs.error(format!("No rule id or level specified for rule '{j}'."));
                    return -1;
                }
                if self.exists(h.id) {
                    if h.overwrite != 1 {
                        msgs.warn(m::duplicated_rule(h.id));
                        continue;
                    }
                } else if h.overwrite == 1 {
                    msgs.warn(m::overwrite_missing(h.id));
                    h.overwrite = 0;
                }
                let mut r = self.new_rule(&h, s);
                r.group = Some(g.attributes[0].1.clone());
                r.file = Some(file.to_string());
                match self.read_rule(node, r, lists, decoders, s, msgs) {
                    Err(()) => return -1,
                    Ok(None) => continue,
                    Ok(Some(mut r)) => {
                        if let Some(rs) = responses {
                            bind_responses(&mut r, rs);
                        }
                        self.add_rule(r, msgs);
                    }
                }
            }
        }
        0
    }

    fn new_rule(&mut self, h: &Head, s: &RuleSettings) -> Rule {
        let mut r = Rule {
            level: h.level,
            category: SYSLOG,
            sigid: h.id,
            maxsize: h.maxsize.max(0) as usize,
            frequency: h.frequency,
            ignore_time: h.ignore_time,
            timeframe: h.timeframe,
            ..Rule::default()
        };
        self.max_frequency = self.max_frequency.max(r.frequency);
        for (on, flag) in [(h.noalert != 0, NO_ALERT), (s.email_level <= h.level, DO_MAILALERT), (s.log_level <= h.level, DO_LOGALERT), (h.overwrite != 0, DO_OVERWRITE)] {
            if on {
                r.alert_opts |= flag;
            }
        }
        if r.level == 0 {
            r.level = 99;
        }
        if h.accuracy != 0 {
            r.level *= 100;
        }
        if r.maxsize > 0 {
            r.alert_opts |= DO_EXTRAINFO;
        }
        r
    }

    /// The options of one rule. Ok(None): the rule is skipped (with a warning).
    fn read_rule(&mut self, node: &XNode, mut r: Rule, lists: &Lists, decoders: &DecoderSet, s: &RuleSettings, msgs: &mut Messages) -> Result<Option<Rule>, ()> {
        let sid = r.sigid;
        let mut skip = false;
        let mut info_count = 0usize;
        let (mut mitre_pairs, mut mitre_ids) = (0usize, 0usize);
        let (mut mitre_old, mut mitre_new) = (false, false);
        let mut texts: Vec<TextOption> = TEXTS.iter().map(|&(_, _, kind, _)| TextOption { text: None, negate: false, kind }).collect();
        let (mut matched_regex, mut matched_group) = (None::<String>, None::<String>);

        if node.children.is_empty() {
            msgs.error(format!("Rule '{sid}' without any option. It may lead to false positives and some other problems for the system. Exiting."));
            return Err(());
        }
        for el in &node.children {
            let (e, v) = (el.name.as_str(), el.content.as_str());
            let name = e.to_ascii_lowercase();
            // a few names must be written in lower case
            let name = if EXACT.contains(&name.as_str()) && e != name { String::new() } else { name };
            let invalid = |msgs: &mut Messages| {
                msgs.error(format!("Invalid option '{e}' for rule '{sid}'."));
                Err(())
            };

            if let Some(k) = TEXTS.iter().position(|(_, n, _, _)| *n == name) {
                let (_, _, default, flag) = TEXTS[k];
                let o = &mut texts[k];
                o.text = append(o.text.take(), v, msgs);
                o.negate = negate_attribute(el, sid, msgs);
                o.kind = type_attribute(el, default, sid, msgs);
                r.alert_opts |= flag;
                continue;
            }
            if let Some((same, field, extra)) = compare_element(&name) {
                if same {
                    r.same_field |= field;
                } else {
                    r.different_field |= field;
                }
                if extra {
                    r.alert_opts |= SAME_EXTRAINFO;
                }
                continue;
            }
            match name.as_str() {
                "decoded_as" => {
                    r.decoded_as = decoders.id_of(v);
                    if r.decoded_as == 0 {
                        msgs.error(format!("Invalid decoder name: '{v}'."));
                        return Err(());
                    }
                }
                "cve" | "info" => {
                    let kind = if name == "cve" { INFO_CVE } else { info_kind(el, msgs) };
                    if r.info_details.is_empty() {
                        r.info_details.push(InfoDetail { kind, data: v.into() });
                    } else {
                        info_count += r.info_details.len() - 1;
                        if info_count <= MAX_INFO_DETAILS {
                            r.info_details.push(InfoDetail { kind, data: v.into() });
                        }
                    }
                    if name == "cve" {
                        r.cve = append(r.cve.take(), v, msgs);
                    } else {
                        r.info = append(r.info.take(), v, msgs);
                    }
                }
                "time" => {
                    r.day_time = crate::time::rule_time(v);
                    if r.day_time.is_none() {
                        msgs.error(m::bad_configuration(e, v));
                        return Err(());
                    }
                    r.alert_opts |= DO_EXTRAINFO;
                }
                "weekday" => {
                    r.week_day = crate::time::rule_days(v);
                    if r.week_day.is_none() {
                        msgs.error(m::bad_day(v));
                        msgs.error(m::bad_configuration(e, v));
                        return Err(());
                    }
                    r.alert_opts |= DO_EXTRAINFO;
                }
                "group" => {
                    r.group = append(r.group.take(), v, msgs).map(|g| g.replace('\n', ""));
                }
                "description" => r.comment = append(r.comment.take(), &v.replacen('\n', " ", 1), msgs),
                "srcip" | "dstip" => {
                    let slot = if name == "srcip" { &mut r.srcip } else { &mut r.dstip };
                    if Expression::add_osip(slot, v).is_err() || slot.is_none() {
                        msgs.error(m::bad_ip(v));
                        return Err(());
                    }
                    let neg = negate_attribute(el, sid, msgs);
                    let slot = if name == "srcip" { &mut r.srcip } else { &mut r.dstip };
                    if let Some(x) = slot {
                        x.negate = neg;
                    }
                    r.alert_opts |= DO_PACKETINFO;
                }
                "field" => {
                    if s.order_size <= r.fields.len() {
                        msgs.error(format!("Rule {sid} has exceeded the maximum number of allowed fields"));
                        return Err(());
                    }
                    let Some(fname) = el.attribute("name").filter(|_| !el.attributes.is_empty()) else {
                        if !el.attributes.is_empty() {
                            msgs.error(format!("Failure to read rule {sid}. No such attribute 'name' for field."));
                        }
                        return Err(());
                    };
                    const FIXED: [&str; 17] =
                        ["srcip", "dstip", "srcgeoip", "dstgeoip", "srcport", "dstport", "user", "srcuser", "dstuser", "url", "id", "data", "extra_data", "status", "protocol", "system_name", "action"];
                    if FIXED.iter().any(|f| fname.eq_ignore_ascii_case(f)) {
                        msgs.error(format!("Failure to read rule {sid}. Field '{fname}' is static."));
                        return Err(());
                    }
                    let fname = append(None, fname, msgs);
                    let kind = type_attribute(el, ExpType::OsRegex, sid, msgs);
                    let neg = negate_attribute(el, sid, msgs);
                    match Expression::compile(kind, v, 0) {
                        Ok(mut x) => {
                            x.negate = neg;
                            r.fields.push(FieldMatch { name: fname, regex: x });
                        }
                        Err(_) => {
                            msgs.error(m::rule_tag_syntax(fname.as_deref().unwrap_or("(null)"), sid));
                            return Err(());
                        }
                    }
                }
                "list" => match self.read_list(el, lists, sid, msgs)? {
                    Some(c) => r.lists.push(c),
                    None => {
                        skip = true;
                        break;
                    }
                },
                "compiled_rule" => {
                    match Check::named(v) {
                        Some(c) => r.check = Some(c),
                        None => {
                            msgs.error(format!("Compiled rule not found: '{v}'"));
                            msgs.error(m::bad_configuration(e, v));
                            return Err(());
                        }
                    }
                    r.alert_opts |= DO_EXTRAINFO;
                }
                "category" => {
                    r.category = match v {
                        "firewall" => FIREWALL,
                        "ids" => IDS,
                        "syslog" => SYSLOG,
                        "web-log" => WEBLOG,
                        "squid" => SQUID,
                        "windows" => DECODER_WINDOWS,
                        "ossec" => OSSEC_RL,
                        _ => {
                            msgs.error(m::bad_category(v));
                            return Err(());
                        }
                    }
                }
                "if_sid" => r.if_sid = append(r.if_sid.take(), v, msgs),
                "if_level" => {
                    if !digits(v) {
                        msgs.warn(m::bad_if_level(v, sid));
                        skip = true;
                        break;
                    }
                    r.if_level = append(r.if_level.take(), v, msgs);
                }
                "if_group" => r.if_group = append(r.if_group.take(), v, msgs),
                "if_matched_regex" => {
                    r.context = 1;
                    matched_regex = append(matched_regex.take(), v, msgs);
                }
                "if_matched_group" => {
                    r.context = 1;
                    matched_group = append(matched_group.take(), v, msgs);
                }
                "if_matched_sid" => {
                    r.context = 1;
                    if !digits(v) {
                        msgs.warn(m::bad_if_matched_sid(v, sid));
                        skip = true;
                        break;
                    }
                    r.if_matched_sid = atoi(v);
                }
                "same_agent" => msgs.warn("Detected a deprecated field option for rule, same_agent is not longer available."),
                "not_same_agent" => msgs.warn("Detected a deprecated field option for rule, not_same_agent is not longer available."),
                "check_diff" => {
                    r.context = 1;
                    r.context_opts |= FIELD_DODIFF;
                    r.alert_opts |= DO_EXTRAINFO;
                }
                "if_fts" => r.alert_opts |= DO_FTS,
                "global_frequency" => r.context_opts |= FIELD_GFREQUENCY,
                "same_field" => {
                    r.same_field |= FIELD_DYNAMICS;
                    r.same_fields.get_or_insert_with(Vec::new).push(v.into());
                }
                "not_same_field" | "different_field" => {
                    r.different_field |= FIELD_DYNAMICS;
                    r.not_same_fields.get_or_insert_with(Vec::new).push(v.into());
                }
                "options" => match v {
                    "alert_by_email" => r.alert_opts |= DO_MAILALERT,
                    // only bits below 0x1000 survive clearing
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
                        msgs.error(m::bad_value("options", v));
                        return invalid(msgs);
                    }
                },
                "ignore" | "check_if_ignored" => {
                    let ignore = name == "ignore";
                    let mut names = vec![None; s.order_size];
                    let mut bits = if ignore { r.ignore } else { r.ckignore };
                    for (i, raw) in provigil_regex::str_break(',', v, s.order_size).unwrap_or_default().iter().enumerate() {
                        let w = raw.trim_start_matches(' ').split(' ').next().unwrap_or("");
                        if w.is_empty() {
                            msgs.error(if ignore { format!("Wrong ignore option: '{v}'") } else { format!("Wrong check_if_ignored option: '{v}'") });
                            return Err(());
                        }
                        bits |= match w {
                            "user" => FTS_DSTUSER,
                            "srcip" => FTS_SRCIP,
                            "dstip" => FTS_DSTIP,
                            "id" => FTS_ID,
                            "location" => FTS_LOCATION,
                            "data" => FTS_DATA,
                            "name" => FTS_NAME,
                            _ => {
                                if i >= s.order_size {
                                    msgs.error(if ignore { "Too many dynamic fields for ignore." } else { "Too many dynamic fields for check_if_ignored." });
                                    return Err(());
                                }
                                names[i] = Some(w.to_string());
                                FTS_DYNAMIC
                            }
                        };
                    }
                    if ignore {
                        r.ignore = bits;
                        r.ignore_fields = Some(names);
                    } else {
                        r.ckignore = bits;
                        r.ckignore_fields = Some(names);
                    }
                }
                "mitre" => {
                    if el.children.is_empty() {
                        msgs.warn(format!("Empty Mitre information for rule '{sid}'"));
                        continue;
                    }
                    read_mitre(&el.children, &mut r, sid, msgs, (&mut mitre_old, &mut mitre_new, &mut mitre_ids, &mut mitre_pairs));
                }
                _ => return invalid(msgs),
            }
        }

        if let Some(ids) = &r.if_sid {
            let body = ids.strip_suffix('\n').unwrap_or(ids);
            if body.is_empty() || !body.bytes().all(|c| c.is_ascii_digit() || c == b',' || c == b' ') {
                skip = true;
                msgs.warn(m::bad_if_sid(ids, sid));
            }
        }
        if skip {
            return Ok(None);
        }
        if r.comment.is_none() {
            msgs.error(format!("No such description at rule '{sid}'."));
            return Err(());
        }
        if (r.context_opts != 0 || r.same_field != 0 || r.different_field != 0 || r.frequency != 0) && r.context == 0 {
            msgs.error(format!("Invalid use of frequency/context options. Missing if_matched on rule '{sid}'."));
            return Err(());
        }
        let overwrite = r.alert_opts & DO_OVERWRITE != 0;
        if matched_group.is_some() && !overwrite && r.if_sid.is_none() && r.if_group.is_none() {
            r.if_group = matched_group.clone();
        }
        if r.if_matched_sid != 0 && r.if_sid.is_none() && r.if_group.is_none() && !overwrite {
            let mut t = r.if_matched_sid.to_string();
            t.truncate(14);
            r.if_sid = Some(t);
        }

        let compile = |r: &mut Rule, k: usize, msgs: &mut Messages| -> Result<(), ()> {
            let o = &texts[k];
            let Some(t) = &o.text else { return Ok(()) };
            match Expression::compile(o.kind, t, 0) {
                Ok(mut x) => {
                    x.negate = o.negate;
                    *r.slot(TEXTS[k].0) = Some(x);
                    Ok(())
                }
                Err(_) => {
                    // the protocol error names the pattern, the others the option
                    let tag = if TEXTS[k].0 == Text::Protocol { t.as_str() } else { TEXTS[k].1 };
                    msgs.error(m::rule_tag_syntax(tag, sid));
                    Err(())
                }
            }
        };
        for k in 0..TEXTS.len() {
            if TEXTS[k].0 == Text::Protocol {
                // the context patterns are compiled just before the protocol
                if let Some(t) = &matched_group {
                    r.if_matched_group = Some(OsMatch::compile(t, 0).map_err(|_| msgs.error(m::regex_failed(t, 0)))?);
                }
                if let Some(t) = &matched_regex {
                    r.if_matched_regex = Some(OsRegex::compile(t, 0).map_err(|_| msgs.error(m::regex_failed(t, 0)))?);
                }
            }
            compile(&mut r, k, msgs)?;
        }
        Ok(Some(r))
    }

    /// A `<list>` condition; None when its list is not loaded (the rule is skipped).
    fn read_list(&self, el: &XNode, lists: &Lists, sid: i32, msgs: &mut Messages) -> Result<Option<ListCheck>, ()> {
        let (e, v) = (el.name.as_str(), el.content.as_str());
        let fail = |msgs: &mut Messages, first: String| {
            msgs.error(first);
            msgs.error(m::bad_configuration(e, v));
            Err(())
        };
        if el.attributes.is_empty() {
            return fail(msgs, "List must have a correctly formatted field attribute".into());
        }
        let (mut field, mut dynamic, mut pattern, mut lookup) = (0, None, None, lists::MATCH_KEY);
        for (a, value) in &el.attributes {
            if a.eq_ignore_ascii_case("lookup") {
                let kinds = [
                    ("match_key", lists::MATCH_KEY),
                    ("not_match_key", lists::NOT_MATCH_KEY),
                    ("match_key_value", lists::MATCH_KEY_VALUE),
                    ("address_match_key", lists::ADDRESS_MATCH_KEY),
                    ("not_address_match_key", lists::NOT_ADDRESS_MATCH_KEY),
                    ("address_match_key_value", lists::ADDRESS_MATCH_KEY_VALUE),
                ];
                match kinds.iter().find(|(n, _)| value.eq_ignore_ascii_case(n)) {
                    Some((_, k)) => lookup = *k,
                    None => {
                        msgs.error(m::bad_configuration(e, v));
                        msgs.error(format!("List match lookup=\"{value}\" is not valid."));
                        return Err(());
                    }
                }
            } else if a.eq_ignore_ascii_case("field") {
                (field, dynamic) = list_field(value);
            } else if a.eq_ignore_ascii_case("check_value") {
                match OsMatch::compile(value, 0) {
                    Ok(p) => pattern = Some(p),
                    Err(_) => {
                        msgs.error(m::bad_configuration(e, v));
                        msgs.error(m::regex_failed(value, 0));
                        return Err(());
                    }
                }
            } else {
                return fail(msgs, format!("List field=\"{value}\" is not valid"));
            }
        }
        if field == 0 {
            return fail(msgs, "List requires the field=\"\" attribute".into());
        }
        match lists.find(v) {
            None => {
                msgs.warn(m::list_not_loaded(v, sid));
                Ok(None)
            }
            Some(db) => Ok(Some(ListCheck { field, lookup, value_pattern: pattern, dynamic_field: if field == RULE_DYNAMIC { dynamic } else { None }, file: v.into(), list: Some(db) })),
        }
    }

    /// Puts a read rule into the tree and sets up its context lists.
    fn add_rule(&mut self, r: Rule, msgs: &mut Messages) -> bool {
        self.rules.push(Arc::new(r));
        let id = self.rules.len() - 1;
        let sid = self.rules[id].sigid;
        if sid < 10 {
            insert(&self.rules, &mut self.tree, id);
        } else if self.rules[id].alert_opts & DO_OVERWRITE != 0 {
            if self.overwrite(id, sid, msgs) == 0 && self.add_child(id, msgs) == -1 {
                return false;
            }
        } else if self.add_child(id, msgs) == -1 {
            return false;
        }
        self.rule_mut(id).if_group = None;
        let r = &self.rules[id];
        let overwrite = r.alert_opts & DO_OVERWRITE != 0;
        if r.if_matched_sid != 0 && !overwrite {
            self.rule_mut(id).event_search = Some(EventSearch::LastSids);
            self.mark_sid(id);
        } else if r.if_matched_group.is_some() && !overwrite {
            let l = self.new_event_list();
            self.rule_mut(id).group_search = Some(l);
            self.mark_group(id);
            self.rule_mut(id).event_search = Some(EventSearch::LastGroups);
        } else if r.context != 0 {
            if r.context == 1 && r.context_opts & FIELD_DODIFF != 0 {
                self.rule_mut(id).context = 0;
            } else {
                self.rule_mut(id).event_search = Some(EventSearch::LastEvents);
            }
        }
        true
    }

    /// Adds rule `new` under every node at `path` that fits: the rule with id `sid`, or
    /// rules of group `group`, or rules of level `level` and up, or (none of these) the first
    /// rule of the same category.
    fn attach(&mut self, sid: i32, level: i32, group: Option<&str>, path: &mut Vec<usize>, new: RuleId) -> bool {
        let mut added = false;
        let mut i = 0;
        while i < list_at(&self.tree, path).len() {
            let n = list_at(&self.tree, path)[i].rule;
            let here = if sid != 0 {
                if self.rules[n].sigid == sid {
                    let c = self.rules[n].category;
                    self.rule_mut(new).category = c;
                    path.push(i);
                    insert(&self.rules, list_at_mut(&mut self.tree, path), new);
                    path.pop();
                    return true;
                }
                false
            } else if let Some(g) = group {
                provigil_regex::os_word_match(g, self.rules[n].group.as_deref().unwrap_or("")) && self.rules[n].sigid != self.rules[new].sigid
            } else if level != 0 {
                self.rules[n].level >= level && self.rules[n].sigid != self.rules[new].sigid
            } else if self.rules[new].category != self.rules[n].category {
                i += 1;
                continue;
            } else {
                let c = self.rules[n].category;
                self.rule_mut(new).category = c;
                path.push(i);
                insert(&self.rules, list_at_mut(&mut self.tree, path), new);
                path.pop();
                return true;
            };
            if here {
                path.push(i);
                insert(&self.rules, list_at_mut(&mut self.tree, path), new);
                path.pop();
                added = true;
            }
            path.push(i);
            if !list_at(&self.tree, path).is_empty() && self.attach(sid, level, group, path, new) {
                added = true;
            }
            path.pop();
            i += 1;
        }
        added
    }

    /// Places rule `r` by its `if_sid`, `if_level`, `if_group` or category. -1: dropped.
    fn add_child(&mut self, r: RuleId, msgs: &mut Messages) -> i32 {
        let sid = self.rules[r].sigid;
        let context = self.rules[r].if_matched_sid != 0;
        if let Some(ids) = self.rules[r].if_sid.clone() {
            let b = ids.as_bytes();
            let (mut in_number, mut placed) = (false, false);
            for p in 0..=b.len() {
                let c = b.get(p).copied().unwrap_or(0);
                if c == b',' || c == b' ' {
                    in_number = false;
                } else if c.is_ascii_digit() || c == 0 {
                    if !in_number {
                        in_number = true;
                        let parent = atoi(&ids[p..]);
                        if self.attach(parent, 0, None, &mut Vec::new(), r) {
                            placed = true;
                        } else if context {
                            msgs.warn(m::matched_sid_not_found(parent, sid));
                            return -1;
                        } else {
                            msgs.warn(m::sid_not_found(parent, sid));
                        }
                    }
                } else {
                    msgs.warn(m::sid_not_number(if context { "if_matched_sid" } else { "if_sid" }, sid));
                    return if placed { 0 } else { -1 };
                }
            }
            if !placed {
                msgs.warn(m::empty_if_sid(sid));
                return -1;
            }
        } else if let Some(l) = self.rules[r].if_level.clone() {
            let level = atoi(&l);
            if level == 0 {
                msgs.warn(m::bad_if_level(&l, sid));
                return -1;
            }
            if !self.attach(0, level * 100, None, &mut Vec::new(), r) {
                msgs.warn(m::level_not_found(level * 100, sid));
                return -1;
            }
        } else if let Some(g) = self.rules[r].if_group.clone() {
            if !self.attach(0, 0, Some(&g), &mut Vec::new(), r) {
                msgs.warn(m::group_not_found(&g, sid));
                return -1;
            }
        } else if !self.attach(0, 0, None, &mut Vec::new(), r) {
            msgs.warn(m::category_not_found(sid));
            return -1;
        }
        0
    }

    /// `overwrite="yes"`: the first rule with `sid` (depth first) takes the new rule's
    /// options; its parents (if_sid, if_group, if_level, if_matched_*) stay. 1 when done.
    fn overwrite(&mut self, new: RuleId, sid: i32, msgs: &mut Messages) -> i32 {
        if self.tree.is_empty() {
            return -1;
        }
        if sid == 0 {
            return 0;
        }
        let Some(target) = find_in(&self.rules, &self.tree, sid) else { return 0 };
        if target == new {
            return 0;
        }
        let n = (*self.rules[new]).clone();
        let o = self.rule_mut(target);
        let kept = (o.sigid, o.firedtimes, o.time_ignored, o.sid_prev_matched, o.sid_search, o.group_prev_matched.clone(), o.group_search, o.event_search);
        let old_parents = (o.if_sid.clone(), o.if_group.clone(), o.if_level.clone(), o.if_matched_group.as_ref().map(|g| g.raw().to_string()), o.if_matched_sid);
        let mut warn = Vec::new();
        if let Some(ns) = &n.if_sid {
            if n.if_matched_sid == 0 && old_parents.0.as_deref() != Some(ns.as_str()) {
                warn.push("if_sid");
            }
        }
        if let Some(ng) = &n.if_group {
            if n.if_matched_group.is_none() && old_parents.1.as_deref() != Some(ng.as_str()) {
                warn.push("if_group");
            }
        }
        if let Some(nl) = &n.if_level {
            if old_parents.2.as_deref() != Some(nl.as_str()) {
                warn.push("if_level");
            }
        }
        if let Some(ng) = &n.if_matched_group {
            if old_parents.3.as_deref() != Some(ng.raw()) {
                warn.push("if_matched_group");
            }
        }
        if n.if_matched_sid != 0 && (old_parents.4 == 0 || old_parents.4 != n.if_matched_sid) {
            warn.push("if_matched_sid");
        }
        let geo = (o.srcgeoip.clone(), o.dstgeoip.clone());
        let old_matched_group = o.if_matched_group.clone();
        *o = Rule {
            sigid: kept.0,
            firedtimes: kept.1,
            time_ignored: kept.2,
            sid_prev_matched: kept.3,
            sid_search: kept.4,
            group_prev_matched: kept.5,
            group_search: kept.6,
            event_search: kept.7,
            if_sid: old_parents.0,
            if_group: old_parents.1,
            if_level: old_parents.2,
            if_matched_group: old_matched_group,
            if_matched_sid: old_parents.4,
            srcgeoip: if GEOIP { n.srcgeoip.clone() } else { geo.0 },
            dstgeoip: if GEOIP { n.dstgeoip.clone() } else { geo.1 },
            ..n
        };
        for w in warn {
            msgs.warn(m::cannot_overwrite(w, sid));
        }
        let r = self.rule_mut(new);
        r.if_sid = None;
        r.if_level = None;
        1
    }

    /// Context rule `orig` (if_matched_sid) watches the events of the rules with that id.
    fn mark_sid(&mut self, orig: RuleId) {
        let want = self.rules[orig].if_matched_sid;
        let mut all = Vec::new();
        walk(&self.tree, &mut |n| all.push(n.rule));
        for r in all {
            if self.rules[r].sigid == want {
                if self.rules[r].sid_prev_matched.is_none() {
                    let l = self.new_event_list();
                    self.rule_mut(r).sid_prev_matched = Some(l);
                }
                let l = self.rules[r].sid_prev_matched;
                self.rule_mut(orig).sid_search = l;
            }
        }
    }

    /// Context rule `orig` (if_matched_group) watches the events of the rules in that group.
    fn mark_group(&mut self, orig: RuleId) {
        let (Some(list), Some(pattern)) = (self.rules[orig].group_search, self.rules[orig].if_matched_group.clone()) else { return };
        let mut all = Vec::new();
        walk(&self.tree, &mut |n| all.push(n.rule));
        for r in all {
            if pattern.is_match(self.rules[r].group.as_deref().unwrap_or("")) {
                self.rule_mut(r).group_prev_matched.get_or_insert_with(Vec::new).push(list);
            }
        }
    }

    /// The final levels: 9900 becomes 0, the others are divided by 100.
    pub fn set_levels(&mut self) {
        let mut all = Vec::new();
        walk(&self.tree, &mut |n| all.push(n.rule));
        for r in all {
            let l = &mut self.rule_mut(r).level;
            if *l == 9900 {
                *l = 0;
            }
            if *l >= 100 {
                *l /= 100;
            }
        }
    }

    /// Rule id text -> the first rule with it (depth first).
    pub fn hash(&self, into: &mut HashMap<String, RuleId>) {
        walk(&self.tree, &mut |n| {
            into.entry(self.rules[n.rule].sigid.to_string()).or_insert(n.rule);
        });
    }
}

/// One `<mitre>` block: old format (`<id>`) or new (`<tacticID>` + `<techniqueID>`).
fn read_mitre(items: &[XNode], r: &mut Rule, sid: i32, msgs: &mut Messages, state: (&mut bool, &mut bool, &mut usize, &mut usize)) {
    let (old_format, new_format, ids_added, pairs_added) = state;
    let (mut has_id, mut has_tactic, mut has_technique) = (false, false, false);
    let (mut tactics, mut techniques) = (0, 0);
    let mut failed = false;
    for x in items {
        let empty = x.content.is_empty();
        if x.name.eq_ignore_ascii_case("id") {
            if empty {
                msgs.warn(format!("No Mitre Technique ID found for rule '{sid}'"));
                failed = true;
            } else {
                has_id = true;
            }
        } else if x.name.eq_ignore_ascii_case("tacticID") {
            if empty {
                msgs.warn(format!("No Mitre Tactic ID found for rule '{sid}'"));
                failed = true;
            } else {
                has_tactic = true;
                tactics += 1;
            }
        } else if x.name.eq_ignore_ascii_case("techniqueID") {
            if empty {
                msgs.warn(format!("No Mitre Technique ID found for rule '{sid}'"));
                failed = true;
            } else {
                has_technique = true;
                techniques += 1;
            }
        } else {
            msgs.error(format!("Invalid option '{}' for rule '{sid}'", x.name));
            failed = true;
        }
    }
    let mixed = format!("Rule '{sid}' combined old and new Mitre formats, the old Mitre Technique format will be discarded.");
    if !failed {
        if has_id {
            if has_tactic || has_technique {
                msgs.warn(format!("Rule '{sid}' combined old and new Mitre formats in the same block. The Mitre block will be discarded."));
                failed = true;
            } else if *new_format {
                msgs.warn(mixed);
                r.mitre_id = None;
                failed = true;
            } else {
                *old_format = true;
            }
        } else if has_tactic && has_technique {
            if tactics > 1 || techniques > 1 {
                msgs.warn(format!("In rule '{sid}' is not allowed to join more than one Mitre techniqueID or tacticID in the same block. The Mitre block will be discarded."));
                failed = true;
            } else {
                *new_format = true;
                if *old_format {
                    msgs.warn(mixed);
                    r.mitre_id = None;
                    *old_format = false;
                }
            }
        } else if has_technique {
            msgs.warn(format!("Mitre tacticID should be defined in rule '{sid}'"));
            failed = true;
        } else if has_tactic {
            msgs.warn(format!("Mitre techniqueID should be defined in rule '{sid}'"));
            failed = true;
        }
    }
    if failed {
        return;
    }
    let (mut tactic, mut technique) = (None, None);
    for x in items {
        let v = x.content.clone();
        if x.name.eq_ignore_ascii_case("id") {
            let ids = r.mitre_id.get_or_insert_with(Vec::new);
            if !ids.iter().take(*ids_added).any(|i| *i == v) {
                ids.truncate(*ids_added);
                ids.push(v);
                *ids_added += 1;
            }
        } else if x.name.eq_ignore_ascii_case("tacticID") {
            tactic = Some(v);
        } else if x.name.eq_ignore_ascii_case("techniqueID") {
            technique = Some(v);
        }
    }
    if let (Some(ta), Some(te)) = (tactic, technique) {
        let tacs = r.mitre_tactic_id.get_or_insert_with(Vec::new);
        let techs = r.mitre_technique_id.get_or_insert_with(Vec::new);
        if !(0..*pairs_added).any(|l| techs[l] == te && tacs[l] == ta) {
            tacs.push(ta);
            techs.push(te);
            *pairs_added += 1;
        }
    }
}
