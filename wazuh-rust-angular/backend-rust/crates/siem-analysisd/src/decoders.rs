//! Decoders: `decode-xml.c` (loader), `decoders_list.c` (decoder trees),
//! `decoder.c` (`DecodeEvent` and the field setters).

use std::collections::HashMap;

use siem_regex::{ExpType, Expression, OS_RETURN_SUBSTRING};
use siem_xml::{OsXml, XmlNode};

use crate::event::*;
use crate::logmsg::{self, LogList};
use crate::plugins::{self, Plugin};
use crate::rules::RuleId;

pub type DecId = usize;
/// `NULL_Decoder`: id 0, type syslog, no name.
pub const NULL_DECODER: DecId = 0;

pub const AFTER_PARENT: u16 = 0x001;
pub const AFTER_PREMATCH: u16 = 0x002;
pub const AFTER_PREVREGEX: u16 = 0x004;
pub const AFTER_ERROR: u16 = 0x010;

pub const JSON_TREAT_NULL_AS_DISCARD: u8 = 1 << 0;
pub const JSON_TREAT_NULL_AS_STRING: u8 = 1 << 1;
pub const JSON_TREAT_ARRAY_AS_CSV_STRING: u8 = 1 << 2;
pub const JSON_TREAT_ARRAY_AS_ARRAY: u8 = 1 << 3;
pub const JSON_TREAT_NULL_MASK: u8 = JSON_TREAT_NULL_AS_DISCARD | JSON_TREAT_NULL_AS_STRING;
pub const JSON_TREAT_ARRAY_MASK: u8 = JSON_TREAT_ARRAY_AS_CSV_STRING | JSON_TREAT_ARRAY_AS_ARRAY;
pub const JSON_TREAT_ARRAY_DEFAULT: u8 = JSON_TREAT_ARRAY_AS_ARRAY;
pub const JSON_TREAT_NULL_DEFAULT: u8 = JSON_TREAT_NULL_AS_STRING;

/// Names of the internal decoders registered by `SetDecodeXML`.
pub const INTERNAL_DECODERS: [&str; 16] = [
    "rootcheck",
    "syscheck_integrity_changed",
    "syscheck_new_entry",
    "syscheck_deleted",
    "syscheck_registry_key_modified",
    "syscheck_registry_key_added",
    "syscheck_registry_key_deleted",
    "syscheck_registry_value_modified",
    "syscheck_registry_value_added",
    "syscheck_registry_value_deleted",
    "hostinfo_new",
    "hostinfo_modified",
    "syscollector",
    "ciscat",
    "windows_eventchannel",
    "sca",
];

pub const XML_LDECODER: &str = "etc/decoders/local_decoder.xml";

/// The `order` field setters (`*_FP`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderFn {
    DstUser,
    SrcUser,
    SrcIp,
    DstIp,
    SrcPort,
    DstPort,
    Protocol,
    Action,
    Id,
    Url,
    Data,
    ExtraData,
    Status,
    SystemName,
    Dynamic,
}

/// `OSDecoderInfo`
#[derive(Debug, Clone, Default)]
pub struct DecoderInfo {
    pub get_next: bool,
    pub type_: u8,
    pub use_own_name: bool,
    pub flags: u8,
    pub id: u16,
    pub regex_offset: u16,
    pub prematch_offset: u16,
    pub plugin_offset: u16,
    pub fts: i32,
    pub accumulate: i32,
    pub parent: Option<String>,
    pub name: Option<String>,
    pub ftscomment: Option<String>,
    /// `fields` (dynamic field names by order position), `decoder_order_size` long.
    pub fields: Option<Vec<Option<String>>>,
    pub fts_fields: Option<Vec<bool>>,
    pub regex: Option<Expression>,
    pub prematch: Option<Expression>,
    pub program_name: Option<Expression>,
    pub plugin: Option<Plugin>,
    pub order: Option<Vec<Option<OrderFn>>>,
}

/// `OSDecoderNode` (`next` is the position in the containing Vec).
#[derive(Debug, Clone)]
pub struct DNode {
    pub dec: DecId,
    pub children: Vec<DNode>,
}

/// A loaded decoder set: the arena of `OSDecoderInfo`, the two decoder
/// lists and the decoder name store (`OSStore`).
#[derive(Debug, Clone)]
pub struct Decoders {
    pub infos: Vec<DecoderInfo>,
    pub pn: Vec<DNode>,
    pub nopn: Vec<DNode>,
    /// `OSStore` keys, kept sorted (strcmp order); id = 1-based position.
    pub store: Vec<Vec<u8>>,
}

impl Default for Decoders {
    fn default() -> Self {
        let null = DecoderInfo { type_: SYSLOG, ..Default::default() };
        Decoders { infos: vec![null], pn: Vec::new(), nopn: Vec::new(), store: Vec::new() }
    }
}

fn opt_str(c: &Option<String>) -> &str {
    c.as_deref().unwrap_or("")
}

/// `_loadmemory` (decode-xml.c): append with a 1024 byte limit.
fn loadmemory(at: Option<String>, s: &str, log: &mut LogList) -> Option<String> {
    match at {
        None => {
            if s.len() < 1024 {
                Some(s.to_string())
            } else {
                log.error(logmsg::size_error(s));
                None
            }
        }
        Some(mut a) => {
            if a.len() + s.len() + 1 > 1024 {
                log.error(logmsg::size_error(s));
                return None;
            }
            a.push_str(s);
            Some(a)
        }
    }
}

/// `w_get_attr_offset`
fn get_attr_offset(node: &XmlNode) -> u16 {
    match node.attr("offset") {
        None => 0,
        Some(v) if v.eq_ignore_ascii_case("after_parent") => AFTER_PARENT,
        Some(v) if v.eq_ignore_ascii_case("after_prematch") => AFTER_PREMATCH,
        Some(v) if v.eq_ignore_ascii_case("after_regex") => AFTER_PREVREGEX,
        Some(_) => AFTER_ERROR,
    }
}

/// `w_get_attr_regex_type`: `None` when there is no `type` attribute,
/// `Some(None)` for an invalid one.
fn get_attr_regex_type(node: &XmlNode) -> Option<Option<ExpType>> {
    node.attr("type").map(|t| {
        if t.eq_ignore_ascii_case("osregex") {
            Some(ExpType::OsRegex)
        } else if t.eq_ignore_ascii_case("osmatch") {
            Some(ExpType::OsMatch)
        } else if t.eq_ignore_ascii_case("pcre2") {
            Some(ExpType::Pcre2)
        } else {
            None
        }
    })
}

/// Split a `order` / `fts` word list like the C loops do: `OS_StrBreak` on
/// ',' then skip leading spaces and cut at the next space.
fn break_words(content: &str, size: usize) -> Vec<(String, String)> {
    siem_regex::str_break(',', content, size)
        .unwrap_or_default()
        .into_iter()
        .map(|raw| {
            let w = raw.trim_start_matches(' ');
            let w = match w.find(' ') {
                Some(p) => &w[..p],
                None => w,
            };
            (raw.clone(), w.to_string())
        })
        .collect()
}

impl Decoders {
    /// `getDecoderfromlist`: 1-based position of `name` in the store, 0 if absent.
    pub fn get_decoder_from_list(&self, name: &str) -> u16 {
        match self.store.binary_search(&name.as_bytes().to_vec()) {
            Ok(p) => (p + 1) as u16,
            Err(_) => 0,
        }
    }

    /// `addDecoder2list`
    fn add_decoder_to_list(&mut self, name: &str) {
        let k = name.as_bytes().to_vec();
        if let Err(p) = self.store.binary_search(&k) {
            self.store.insert(p, k);
        }
    }

    pub fn info(&self, id: DecId) -> &DecoderInfo {
        &self.infos[id]
    }

    /// `OS_GetFirstOSDecoder`
    pub fn first_list(&self, has_program_name: bool) -> &[DNode] {
        if has_program_name {
            &self.pn
        } else {
            &self.nopn
        }
    }

    /// `_OS_AddOSDecoder` on a list (`Err` = the C `NULL` return).
    fn add_to_list(infos: &mut [DecoderInfo], list: &mut Vec<DNode>, pi: DecId, log: &mut LogList) -> Result<(), ()> {
        if !list.is_empty() {
            let mut rm_f = false;
            let pi_name = infos[pi].name.clone();
            let pi_has_parent = infos[pi].parent.is_some();
            for node in list.iter() {
                let tmp = node.dec;
                if infos[tmp].name == pi_name && pi_has_parent {
                    if (infos[tmp].prematch.is_some() || infos[tmp].regex.is_some()) && infos[pi].regex_offset != 0 {
                        rm_f = true;
                    }
                    if infos[pi].prematch.is_some() {
                        log.error(logmsg::pdup_inv(opt_str(&infos[pi].name)));
                        return Err(());
                    }
                    if infos[pi].fts != 0 {
                        log.error(logmsg::pdupfts_inv(opt_str(&infos[pi].name)));
                        return Err(());
                    }
                    if (infos[tmp].regex.is_some() || infos[tmp].plugin.is_some())
                        && (infos[pi].regex.is_some() || infos[pi].plugin.is_some())
                    {
                        infos[tmp].get_next = true;
                    } else {
                        log.error(logmsg::dup_inv(opt_str(&infos[pi].name)));
                        return Err(());
                    }
                }
            }
            if !rm_f && (infos[pi].regex_offset & AFTER_PREVREGEX) != 0 {
                log.error(logmsg::inv_offset(opt_str(&infos[pi].name)));
                return Err(());
            }
            list.push(DNode { dec: pi, children: Vec::new() });
        } else {
            if (infos[pi].regex_offset & AFTER_PREVREGEX) != 0 {
                log.error(logmsg::inv_offset(opt_str(&infos[pi].name)));
                return Err(());
            }
            list.push(DNode { dec: pi, children: Vec::new() });
        }
        Ok(())
    }

    /// `OS_AddOSDecoder`: 1 success, 0 failure, -1 failure after a partial add.
    fn add_os_decoder(&mut self, pi: DecId, log: &mut LogList) -> i32 {
        let mut added = 0;
        if let Some(parent) = self.infos[pi].parent.clone() {
            for which in 0..2 {
                let len = if which == 0 { self.pn.len() } else { self.nopn.len() };
                for i in 0..len {
                    let tmp_dec = if which == 0 { self.pn[i].dec } else { self.nopn[i].dec };
                    if self.infos[tmp_dec].name.as_deref() == Some(parent.as_str()) {
                        let infos = &mut self.infos;
                        let node = if which == 0 { &mut self.pn[i] } else { &mut self.nopn[i] };
                        if Self::add_to_list(infos, &mut node.children, pi, log).is_err() {
                            log.error(logmsg::DEC_PLUGIN_ERR);
                            return -added;
                        }
                        added = 1;
                    }
                }
            }
            if added == 1 {
                return 1;
            }
            log.error(logmsg::pplugin_inv(&parent));
            0
        } else {
            let infos = &mut self.infos;
            let list = if infos[pi].program_name.is_some() { &mut self.pn } else { &mut self.nopn };
            if Self::add_to_list(infos, list, pi, log).is_err() {
                log.error(logmsg::DEC_PLUGIN_ERR);
                return 0;
            }
            1
        }
    }

    /// `ReadDecodeXML`: non-zero on success (1, or -2 for an empty local decoder file).
    pub fn read_decode_xml(&mut self, file: &str, order_size: usize, home: &std::path::Path, log: &mut LogList) -> i32 {
        let full = crate::rules::resolve(home, file);
        let mut xml = match OsXml::read_file(&full, false) {
            Ok(x) => x,
            Err(e) if e.code == -2 => {
                log.warn(logmsg::fopen_error(file, 2, "No such file or directory"));
                return 1;
            }
            Err(e) => {
                log.error(logmsg::xml_error(file, &e.message, e.line));
                return 0;
            }
        };
        if let Err(e) = xml.apply_variables() {
            log.error(logmsg::xml_error_var(file, &e.message));
            return 0;
        }
        if std::fs::metadata(&full).map(|m| m.len()).unwrap_or(0) == 0 && file != XML_LDECODER {
            return 0;
        }
        let nodes = match xml.get_elements_by_node(None) {
            Some(n) => n,
            None => {
                if file != XML_LDECODER {
                    log.error(logmsg::XML_ELEMNULL);
                    return 0;
                }
                return -2;
            }
        };

        for node in &nodes {
            if !node.element.eq_ignore_ascii_case("decoder") {
                log.error(logmsg::xml_invelem(&node.element));
                return 0;
            }
            if node.attributes.is_empty() || !node.attributes[0].eq_ignore_ascii_case("name") {
                log.error(logmsg::xml_invelem(&node.element));
                return 0;
            }
            if node.attributes.len() > 1 {
                if !node.attributes[1].eq_ignore_ascii_case("status") {
                    log.error(logmsg::xml_invelem(&node.element));
                    return 0;
                }
                if node.attributes.len() > 2 {
                    log.error(logmsg::xml_invelem(&node.element));
                    return 0;
                }
            }
            let elements = match xml.get_elements_by_node(Some(node)) {
                Some(e) => e,
                None => {
                    log.error(logmsg::XML_ELEMNULL);
                    return 0;
                }
            };

            let mut pi = DecoderInfo {
                name: Some(node.values[0].clone()),
                type_: SYSLOG,
                flags: JSON_TREAT_NULL_DEFAULT | JSON_TREAT_ARRAY_DEFAULT,
                ..Default::default()
            };
            let pname = node.values[0].clone();
            let mut regex_str: Option<String> = None;
            let mut prematch_str: Option<String> = None;
            let mut p_name_str: Option<String> = None;
            let mut regex_type = ExpType::OsRegex;
            let mut prematch_type = ExpType::OsRegex;
            let mut p_name_type = ExpType::OsMatch;

            self.add_decoder_to_list(&pname);

            for el in &elements {
                let content = match &el.content {
                    Some(c) => c.as_str(),
                    None => {
                        log.error(logmsg::xml_valuenull(&el.element));
                        return 0;
                    }
                };
                let e = el.element.as_str();
                if e.eq_ignore_ascii_case("parent") {
                    pi.parent = loadmemory(pi.parent.take(), content, log);
                } else if e.eq_ignore_ascii_case("regex") {
                    let mut r_offset = get_attr_offset(el);
                    if r_offset & AFTER_ERROR != 0 {
                        log.warn(logmsg::inv_value_default("offset", "regex", &pname));
                        r_offset = 0;
                    }
                    if regex_str.is_some() && r_offset != 0 {
                        log.error(logmsg::dup_regex(&pname));
                        log.error(logmsg::dec_regex_error(&pname));
                        return 0;
                    }
                    if r_offset != 0 {
                        pi.regex_offset = r_offset;
                    }
                    regex_type = match get_attr_regex_type(el) {
                        None => ExpType::OsRegex,
                        Some(t) => match t {
                            Some(ExpType::OsRegex) => ExpType::OsRegex,
                            Some(ExpType::Pcre2) => ExpType::Pcre2,
                            _ => {
                                log.warn(logmsg::inv_value_default("type", "regex", &pname));
                                ExpType::OsRegex
                            }
                        },
                    };
                    regex_str = loadmemory(regex_str.take(), content, log);
                } else if e.eq_ignore_ascii_case("prematch") {
                    let mut pre_offset = get_attr_offset(el);
                    if pre_offset & AFTER_ERROR != 0 {
                        log.error(logmsg::inv_value_default("offset", "prematch", &pname));
                        pre_offset = 0;
                    }
                    if prematch_str.is_some() && pre_offset != 0 {
                        log.error(logmsg::dup_regex(&pname));
                        log.error(logmsg::dec_regex_error(&pname));
                        return 0;
                    }
                    if pre_offset != 0 {
                        pi.prematch_offset = pre_offset;
                    }
                    prematch_type = match get_attr_regex_type(el) {
                        None => ExpType::OsRegex,
                        Some(t) => match t {
                            Some(ExpType::OsRegex) => ExpType::OsRegex,
                            Some(ExpType::Pcre2) => ExpType::Pcre2,
                            _ => {
                                log.warn(logmsg::inv_value_default("type", "prematch", &pname));
                                ExpType::OsRegex
                            }
                        },
                    };
                    prematch_str = loadmemory(prematch_str.take(), content, log);
                } else if e.eq_ignore_ascii_case("program_name") {
                    p_name_type = match get_attr_regex_type(el) {
                        None => ExpType::OsMatch,
                        Some(t) => match t {
                            Some(t @ (ExpType::OsMatch | ExpType::OsRegex | ExpType::Pcre2)) => t,
                            _ => {
                                log.warn(logmsg::inv_value_default("type", "program_name", &pname));
                                ExpType::OsMatch
                            }
                        },
                    };
                    p_name_str = loadmemory(p_name_str.take(), content, log);
                } else if e.eq_ignore_ascii_case("ftscomment") {
                    pi.ftscomment = loadmemory(pi.ftscomment.take(), content, log);
                } else if e.eq_ignore_ascii_case("use_own_name") {
                    if content == "true" {
                        pi.use_own_name = true;
                    }
                } else if e.eq_ignore_ascii_case("plugin_decoder") {
                    if let Some(p) = Plugin::from_name(content) {
                        pi.plugin = Some(p);
                    }
                    if pi.plugin.is_none() {
                        log.error(logmsg::inv_decoption(e, content));
                        return 0;
                    }
                    pi.plugin_offset = get_attr_offset(el);
                    if pi.plugin_offset & AFTER_ERROR != 0 {
                        log.error(logmsg::dec_regex_error(&pname));
                        return 0;
                    }
                } else if e.eq_ignore_ascii_case("json_null_field") {
                    pi.flags &= !JSON_TREAT_NULL_MASK;
                    if content.eq_ignore_ascii_case("discard") {
                        pi.flags |= JSON_TREAT_NULL_AS_DISCARD;
                    } else if content.eq_ignore_ascii_case("empty") {
                        log.warn(logmsg::dec_deprecated_opt_value(content, "json_null_field", &pname));
                        pi.flags |= JSON_TREAT_NULL_DEFAULT;
                    } else if content.eq_ignore_ascii_case("string") {
                        pi.flags |= JSON_TREAT_NULL_AS_STRING;
                    } else {
                        log.warn(logmsg::inv_opt_value_default(content, "json_null_field", &pname));
                        pi.flags |= JSON_TREAT_NULL_DEFAULT;
                    }
                } else if e.eq_ignore_ascii_case("json_array_structure") {
                    pi.flags &= !JSON_TREAT_ARRAY_MASK;
                    if content.eq_ignore_ascii_case("csv") {
                        pi.flags |= JSON_TREAT_ARRAY_AS_CSV_STRING;
                    } else if content.eq_ignore_ascii_case("array") {
                        pi.flags |= JSON_TREAT_ARRAY_AS_ARRAY;
                    } else {
                        log.warn(logmsg::inv_opt_value_default(content, "json_array_structure", &pname));
                        pi.flags |= JSON_TREAT_ARRAY_DEFAULT;
                    }
                } else if e == "type" {
                    pi.type_ = match content {
                        "firewall" => FIREWALL,
                        "ids" => IDS,
                        "web-log" => WEBLOG,
                        "syslog" => SYSLOG,
                        "squid" => SQUID,
                        "windows" => DECODER_WINDOWS,
                        "host-information" => HOST_INFO,
                        "ossec" => OSSEC_RL,
                        _ => {
                            log.error(format!("Invalid decoder type '{content}'."));
                            return 0;
                        }
                    };
                } else if e.eq_ignore_ascii_case("order") {
                    if content.bytes().filter(|&c| c == b',').count() >= order_size {
                        log.error("Order has too many fields.");
                        return 0;
                    }
                    let mut order: Vec<Option<OrderFn>> = vec![None; order_size];
                    let mut fields: Vec<Option<String>> = vec![None; order_size];
                    for (i, (raw, word)) in break_words(content, order_size).into_iter().enumerate() {
                        if word.is_empty() {
                            log.error(format!("decode-xml: Wrong field '{raw}' in the order of decoder '{pname}'"));
                            return 0;
                        }
                        let f = match word.as_str() {
                            "dstuser" | "user" => OrderFn::DstUser,
                            "srcuser" => OrderFn::SrcUser,
                            "srcip" => OrderFn::SrcIp,
                            "dstip" => OrderFn::DstIp,
                            "srcport" => OrderFn::SrcPort,
                            "dstport" => OrderFn::DstPort,
                            "protocol" => OrderFn::Protocol,
                            "action" => OrderFn::Action,
                            "id" => OrderFn::Id,
                            "url" => OrderFn::Url,
                            "data" => OrderFn::Data,
                            "extra_data" => OrderFn::ExtraData,
                            "status" => OrderFn::Status,
                            "system_name" => OrderFn::SystemName,
                            _ => {
                                fields[i] = Some(word.clone());
                                OrderFn::Dynamic
                            }
                        };
                        order[i] = Some(f);
                    }
                    pi.order = Some(order);
                    pi.fields = Some(fields);
                } else if e.eq_ignore_ascii_case("accumulate") {
                    pi.accumulate = 1;
                } else if e.eq_ignore_ascii_case("fts") {
                    let mut fts_fields = vec![false; order_size];
                    for (raw, word) in break_words(content, order_size) {
                        if word.is_empty() {
                            log.error(format!("decode-xml: Wrong field '{raw}' in the fts decoder '{pname}'"));
                            return 0;
                        }
                        match word.as_str() {
                            "dstuser" | "user" => pi.fts |= FTS_DSTUSER,
                            "srcuser" => pi.fts |= FTS_SRCUSER,
                            "srcip" => pi.fts |= FTS_SRCIP,
                            "dstip" => pi.fts |= FTS_DSTIP,
                            "id" => pi.fts |= FTS_ID,
                            "location" => pi.fts |= FTS_LOCATION,
                            "data" | "extra_data" => pi.fts |= FTS_DATA,
                            "system_name" => pi.fts |= FTS_SYSTEMNAME,
                            "name" => pi.fts |= FTS_NAME,
                            _ => {
                                if let Some(fields) = &pi.fields {
                                    let mut i = 0;
                                    while i < fields.len() {
                                        match &fields[i] {
                                            Some(f) if f.eq_ignore_ascii_case(&word) => break,
                                            Some(_) => i += 1,
                                            None => break,
                                        }
                                    }
                                    if i >= fields.len() || fields[i].is_none() {
                                        log.error(format!("decode-xml: Wrong field '{raw}' in the fts decoder '{pname}'"));
                                        return 0;
                                    }
                                    pi.fts |= FTS_DYNAMIC;
                                    fts_fields[i] = true;
                                }
                            }
                        }
                    }
                    pi.fts_fields = Some(fts_fields);
                } else {
                    log.error(format!("Invalid element '{}' for decoder '{}'", e, node.element));
                    return 0;
                }
            }

            // Prematch must be set
            if prematch_str.is_none() && pi.parent.is_none() && p_name_str.is_none() {
                log.error(logmsg::decode_nopre(&pname));
                log.error(logmsg::dec_regex_error(&pname));
                return 0;
            }
            // If pi->regex is not set, fts must not be set too
            if (regex_str.is_none() && (pi.fts != 0 || pi.order.is_some())) || (regex_str.is_some() && pi.order.is_none()) {
                log.error(logmsg::dec_regex_error(&pname));
                return 0;
            }
            if (pi.regex_offset & AFTER_PARENT) != 0 && pi.parent.is_none() {
                log.error(logmsg::inv_offset("after_parent"));
                log.error(logmsg::dec_regex_error(&pname));
                return 0;
            }
            if (pi.regex_offset & AFTER_PREMATCH) != 0 {
                if pi.parent.is_none() {
                    pi.regex_offset = AFTER_PARENT;
                } else if prematch_str.is_none() {
                    log.error(logmsg::inv_offset("after_prematch"));
                    log.error(logmsg::dec_regex_error(&pname));
                    return 0;
                }
            }
            if (pi.regex_offset & AFTER_PREVREGEX) != 0 && (pi.parent.is_none() || regex_str.is_none()) {
                log.error(logmsg::inv_offset("after_regex"));
                log.error(logmsg::dec_regex_error(&pname));
                return 0;
            }
            if pi.prematch_offset != 0 {
                if (pi.prematch_offset & AFTER_PARENT) != 0 {
                    if pi.parent.is_none() {
                        log.error(logmsg::inv_offset("after_parent"));
                        log.error(logmsg::dec_regex_error(&pname));
                        return 0;
                    }
                } else {
                    log.error(logmsg::dec_regex_error(&pname));
                    return 0;
                }
            }
            if (pi.plugin_offset & AFTER_PARENT) != 0 && pi.parent.is_none() {
                log.error(logmsg::inv_offset("after_parent"));
                log.error(logmsg::dec_regex_error(&pname));
                return 0;
            }
            if (pi.plugin_offset & AFTER_PREMATCH) != 0 && prematch_str.is_none() {
                log.error(logmsg::inv_offset("after_prematch"));
                log.error(logmsg::dec_regex_error(&pname));
                return 0;
            }

            if let Some(s) = &prematch_str {
                match Expression::compile(prematch_type, s, 0) {
                    Ok(x) => pi.prematch = Some(x),
                    Err(_) => {
                        log.error(logmsg::regex_syntax(s));
                        log.error(logmsg::dec_regex_error(&pname));
                        return 0;
                    }
                }
            }
            if let Some(s) = &p_name_str {
                match Expression::compile(p_name_type, s, 0) {
                    Ok(x) => pi.program_name = Some(x),
                    Err(_) => {
                        log.error(logmsg::regex_syntax(s));
                        log.error(logmsg::dec_regex_error(&pname));
                        return 0;
                    }
                }
            }
            if let Some(s) = &regex_str {
                match Expression::compile(regex_type, s, OS_RETURN_SUBSTRING) {
                    Ok(x) => {
                        if let siem_regex::ExpressionKind::OsRegex(r) = &x.kind {
                            if !r.has_sub_strings() {
                                log.error(logmsg::regex_subs(s));
                                return 0;
                            }
                        }
                        pi.regex = Some(x);
                    }
                    Err(_) => {
                        log.error(logmsg::regex_syntax(s));
                        log.error(logmsg::dec_regex_error(&pname));
                        return 0;
                    }
                }
            }
            if pi.plugin.is_some() && (pi.regex.is_some() || pi.order.is_some()) {
                log.error(logmsg::decode_add(&pname));
                return 0;
            }

            self.infos.push(pi);
            let id = self.infos.len() - 1;
            if self.add_os_decoder(id, log) < 1 {
                log.error(logmsg::DECODER_ERROR);
                return 0;
            }
        }
        1
    }

    /// `os_setdecoderids` for one list.
    fn set_ids(&mut self, pn: bool) -> bool {
        let list = if pn { &self.pn } else { &self.nopn };
        // Collect (node dec, children decs) first to avoid borrow conflicts.
        let plan: Vec<(DecId, Vec<DecId>)> = list.iter().map(|n| (n.dec, n.children.iter().map(|c| c.dec).collect())).collect();
        for (dec, children) in plan {
            let name = self.infos[dec].name.clone().unwrap_or_default();
            let id = self.get_decoder_from_list(&name);
            self.infos[dec].id = id;
            if id == 0 {
                return false;
            }
            for c in children {
                if self.infos[c].use_own_name {
                    let cname = self.infos[c].name.clone().unwrap_or_default();
                    self.infos[c].id = self.get_decoder_from_list(&cname);
                } else {
                    self.infos[c].id = id;
                    self.infos[c].name = Some(name.clone());
                }
                if self.infos[c].id == 0 {
                    return false;
                }
            }
        }
        true
    }

    /// `SetDecodeXML`
    pub fn set_decode_xml(&mut self, log: &mut LogList) -> bool {
        for n in INTERNAL_DECODERS {
            self.add_decoder_to_list(n);
        }
        if !self.set_ids(false) {
            log.error(logmsg::DECODER_ERROR);
            return false;
        }
        if !self.set_ids(true) {
            log.error(logmsg::DECODER_ERROR);
            return false;
        }
        true
    }
}

/// Apply an `order` setter (`*_FP`) to the event.
pub fn apply_order(ev: &mut Event, f: OrderFn, value: Bytes, field_name: Option<&str>) {
    let idx = match f {
        OrderFn::DstUser => F_DSTUSER,
        OrderFn::SrcUser => F_SRCUSER,
        OrderFn::SrcIp => F_SRCIP,
        OrderFn::DstIp => F_DSTIP,
        OrderFn::SrcPort => F_SRCPORT,
        OrderFn::DstPort => F_DSTPORT,
        OrderFn::Protocol => F_PROTOCOL,
        OrderFn::Action => F_ACTION,
        OrderFn::Id => F_ID,
        OrderFn::Url => F_URL,
        OrderFn::Data => F_DATA,
        OrderFn::ExtraData => F_EXTRA_DATA,
        OrderFn::Status => F_STATUS,
        OrderFn::SystemName => F_SYSTEMNAME,
        OrderFn::Dynamic => {
            let key = field_name.map(|s| s.as_bytes().to_vec()).unwrap_or_default();
            ev.fields.push(DynamicField { key, value: Some(value) });
            return;
        }
    };
    ev.f[idx] = Some(value);
}

/// Context shared by the decoding phase.
pub struct DecodeCtx<'a> {
    pub order_size: usize,
    /// `rules_hash` (sid string -> rule) for the OSSEC alert plugin.
    pub rules_hash: &'a HashMap<String, RuleId>,
}

/// Position of a node: the list it lives in plus its index (`OSDecoderNode *`).
#[derive(Clone, Copy)]
struct Cursor<'n> {
    list: &'n [DNode],
    idx: usize,
}

impl<'n> Cursor<'n> {
    fn node(&self) -> Option<&'n DNode> {
        self.list.get(self.idx)
    }
    fn next(self) -> Self {
        Cursor { list: self.list, idx: self.idx + 1 }
    }
}

fn expr_match(expr: Option<&Expression>, ev_buf: &[u8], at: Option<isize>, dm: &mut Vec<Bytes>) -> (bool, Option<isize>) {
    let (Some(expr), Some(at)) = (expr, at) else {
        return (false, None);
    };
    if at < 0 {
        return (false, None);
    }
    let s = cstr(ev_buf, at as usize);
    let (m, end) = expr.match_bytes(s, Some(dm));
    (m, end.map(|e| at + e))
}

/// `DecodeEvent`
pub fn decode_event(decs: &mut Decoders, ev: &mut Event, decoder_match: &mut Vec<Bytes>, ctx: &DecodeCtx<'_>, pn: bool) {
    // The trees are not modified while decoding; plugins may change the
    // decoder info (`type`), so work on a snapshot of the node lists.
    let lists = if pn { decs.pn.clone() } else { decs.nopn.clone() };
    let top: &[DNode] = &lists;

    let mut pmatch: Option<isize> = None;
    let mut cmatch: Option<isize> = None;
    let mut llog: Option<isize> = None;
    let mut regex_prev: Option<isize> = None;

    for (ti, node) in top.iter().enumerate() {
        let nnode_id = node.dec;

        // First check program name
        if let Some(pn_val) = ev.program_name.clone() {
            let info = &decs.infos[nnode_id];
            let matched = match &info.program_name {
                Some(e) => e.match_bytes(&pn_val, Some(decoder_match)).0,
                None => false,
            };
            if !matched {
                continue;
            }
            pmatch = Some(ev.log as isize);
        }

        // If prematch fails, go to the next decoder
        if decs.infos[nnode_id].prematch.is_some() {
            let base = ev.log as isize;
            let (m, end) = expr_match(decs.infos[nnode_id].prematch.as_ref(), &ev.buf, Some(base), decoder_match);
            if !m {
                continue;
            }
            if end.is_some() {
                pmatch = end;
            }
            if let Some(p) = pmatch {
                if byte_at(&ev.buf, p) != 0 {
                    pmatch = Some(p + 1);
                }
            }
        }

        ev.decoder = nnode_id;
        ev.log_after_prematch = pmatch;

        let mut nnode: Option<DecId> = Some(nnode_id);
        let mut child: Cursor;
        if node.children.is_empty() {
            child = Cursor { list: top, idx: ti };
        } else {
            child = Cursor { list: &node.children, idx: 0 };
            nnode = None;
            while let Some(cn) = child.node() {
                let cid = cn.dec;
                if decs.infos[cid].prematch.is_some() {
                    let llog2 = if decs.infos[cid].prematch_offset & AFTER_PARENT != 0 { pmatch } else { Some(ev.log as isize) };
                    let (m, end) = expr_match(decs.infos[cid].prematch.as_ref(), &ev.buf, llog2, decoder_match);
                    if m {
                        if end.is_some() {
                            cmatch = end;
                        }
                        if let Some(c) = cmatch {
                            if byte_at(&ev.buf, c) != 0 {
                                cmatch = Some(c + 1);
                            }
                        }
                        ev.decoder = cid;
                        ev.log_after_parent = pmatch;
                        ev.log_after_prematch = cmatch;
                        nnode = Some(cid);
                        break;
                    }
                } else {
                    cmatch = pmatch;
                    nnode = Some(cid);
                    break;
                }

                // Multiple regex-only children: skip the whole group
                if decs.infos[cid].get_next {
                    loop {
                        child = child.next();
                        match child.node() {
                            Some(n) if decs.infos[n.dec].get_next => continue,
                            _ => break,
                        }
                    }
                    if child.node().is_none() {
                        return;
                    }
                    child = child.next();
                } else {
                    child = child.next();
                }
            }
        }

        let Some(mut cur) = nnode else {
            return;
        };

        // Get the regex
        while child.node().is_some() {
            let info = &decs.infos[cur];
            if let Some(plugin) = info.plugin {
                plugins::run(plugin, decs, ev, decoder_match, ctx);
            } else if info.regex.is_some() {
                if info.regex_offset != 0 {
                    if info.regex_offset & AFTER_PARENT != 0 {
                        llog = pmatch;
                    } else if info.regex_offset & AFTER_PREMATCH != 0 {
                        llog = cmatch;
                    } else if info.regex_offset & AFTER_PREVREGEX != 0 {
                        llog = if regex_prev.is_none() { cmatch } else { regex_prev };
                    }
                } else {
                    llog = Some(ev.log as isize);
                }

                let (m, result) = expr_match(info.regex.as_ref(), &ev.buf, llog, decoder_match);
                if !m {
                    if info.get_next {
                        child = child.next();
                        match child.node() {
                            Some(n) => {
                                cur = n.dec;
                                continue;
                            }
                            None => return,
                        }
                    }
                    return;
                }

                regex_prev = result;
                if let Some(r) = regex_prev {
                    if byte_at(&ev.buf, r) != 0 {
                        regex_prev = Some(r + 1);
                    }
                }

                if ev.fields.len() >= ctx.order_size {
                    // merror("Regex has too many groups.")
                    return;
                }

                let subs = std::mem::take(decoder_match);
                let order = info.order.clone().unwrap_or_default();
                let fields = info.fields.clone().unwrap_or_default();
                for (i, s) in subs.into_iter().enumerate() {
                    if let Some(Some(f)) = order.get(i) {
                        let name = fields.get(i).and_then(|x| x.as_deref());
                        apply_order(ev, *f, s, name);
                    }
                }
            } else {
                return;
            }

            if decs.infos[cur].get_next {
                child = child.next();
                match child.node() {
                    Some(n) => cur = n.dec,
                    None => return,
                }
            } else {
                return;
            }
        }
        return;
    }
}
