//! Decoders (spec section 2.5): loading the decoder files into two trees (decoders with a
//! `program_name` and the others), giving each decoder its id, and decoding an event.

use std::collections::HashMap;
use std::path::Path;

use provigil_regex::{ExpType, Expression, ExpressionKind, OS_RETURN_SUBSTRING};

use crate::event::*;
use crate::messages::{self as m, Messages};
use crate::plugins::{self, Plugin};

/// The decoder of events no decoder matched: id 0, type syslog, no name.
pub const NO_DECODER: DecoderId = 0;

pub const AFTER_PARENT: u16 = 0x001;
pub const AFTER_PREMATCH: u16 = 0x002;
pub const AFTER_PREVREGEX: u16 = 0x004;
pub const AFTER_ERROR: u16 = 0x010;

pub const JSON_NULL_DISCARD: u8 = 1;
pub const JSON_NULL_STRING: u8 = 2;
pub const JSON_ARRAY_CSV: u8 = 4;
pub const JSON_ARRAY_ARRAY: u8 = 8;
const JSON_NULL_BITS: u8 = JSON_NULL_DISCARD | JSON_NULL_STRING;
const JSON_ARRAY_BITS: u8 = JSON_ARRAY_CSV | JSON_ARRAY_ARRAY;

/// The built-in decoders' names: they get ids like the file decoders.
pub const BUILT_IN: [&str; 16] = [
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

/// The local decoder file: it may be empty.
pub const LOCAL_FILE: &str = "etc/decoders/local_decoder.xml";

/// Where an `order` value goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Fixed(usize),
    /// a dynamic field named by [`Decoder::field_names`]
    Named,
}

#[derive(Debug, Clone, Default)]
pub struct Decoder {
    /// Several regex-only decoders share a name: try the next on failure.
    pub get_next: bool,
    pub kind: u8,
    pub use_own_name: bool,
    pub json_flags: u8,
    pub id: u16,
    pub regex_offset: u16,
    pub prematch_offset: u16,
    pub plugin_offset: u16,
    pub fts: i32,
    pub accumulate: i32,
    pub parent: Option<String>,
    pub name: Option<String>,
    pub fts_comment: Option<String>,
    /// Dynamic field names by `order` position (order size long).
    pub field_names: Option<Vec<Option<String>>>,
    pub fts_fields: Option<Vec<bool>>,
    pub regex: Option<Expression>,
    pub prematch: Option<Expression>,
    pub program_name: Option<Expression>,
    pub plugin: Option<Plugin>,
    pub order: Option<Vec<Option<Target>>>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub decoder: DecoderId,
    pub children: Vec<Node>,
}

#[derive(Debug, Clone)]
pub struct DecoderSet {
    pub decoders: Vec<Decoder>,
    pub with_program: Vec<Node>,
    pub without_program: Vec<Node>,
    /// Decoder names, sorted by bytes; a decoder's id is its position plus one.
    pub names: Vec<Vec<u8>>,
}

impl Default for DecoderSet {
    fn default() -> DecoderSet {
        DecoderSet { decoders: vec![Decoder { kind: SYSLOG, ..Decoder::default() }], with_program: Vec::new(), without_program: Vec::new(), names: Vec::new() }
    }
}

/// Appends to a text of at most 1,023 bytes; too long drops the whole text.
fn append(to: Option<String>, s: &str, msgs: &mut Messages) -> Option<String> {
    let total = to.as_ref().map_or(s.len(), |t| t.len() + s.len() + 1);
    if (to.is_none() && s.len() >= 1024) || (to.is_some() && total > 1024) {
        msgs.error(m::too_long(s));
        return None;
    }
    Some(to.unwrap_or_default() + s)
}

fn offset_attribute(n: &provigil_daemon::xml::Node) -> u16 {
    match n.attribute("offset") {
        None => 0,
        Some(v) if v.eq_ignore_ascii_case("after_parent") => AFTER_PARENT,
        Some(v) if v.eq_ignore_ascii_case("after_prematch") => AFTER_PREMATCH,
        Some(v) if v.eq_ignore_ascii_case("after_regex") => AFTER_PREVREGEX,
        Some(_) => AFTER_ERROR,
    }
}

/// The `type` attribute: None when absent, Some(None) when not a known type.
fn type_attribute(n: &provigil_daemon::xml::Node) -> Option<Option<ExpType>> {
    n.attribute("type").map(|t| {
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

/// A comma list as (the piece as written, its first word).
fn words(content: &str, size: usize) -> Vec<(String, String)> {
    provigil_regex::str_break(',', content, size)
        .unwrap_or_default()
        .into_iter()
        .map(|raw| {
            let w = raw.trim_start_matches(' ');
            let w = w.split(' ').next().unwrap_or("").to_string();
            (raw, w)
        })
        .collect()
}

fn fixed_target(word: &str) -> Option<usize> {
    Some(match word {
        "dstuser" | "user" => F_DSTUSER,
        "srcuser" => F_SRCUSER,
        "srcip" => F_SRCIP,
        "dstip" => F_DSTIP,
        "srcport" => F_SRCPORT,
        "dstport" => F_DSTPORT,
        "protocol" => F_PROTOCOL,
        "action" => F_ACTION,
        "id" => F_ID,
        "url" => F_URL,
        "data" => F_DATA,
        "extra_data" => F_EXTRA_DATA,
        "status" => F_STATUS,
        "system_name" => F_SYSTEMNAME,
        _ => return None,
    })
}

impl DecoderSet {
    /// The id of a decoder name (0: unknown).
    pub fn id_of(&self, name: &str) -> u16 {
        self.names.binary_search_by(|n| n.as_slice().cmp(name.as_bytes())).map_or(0, |p| (p + 1) as u16)
    }

    fn remember(&mut self, name: &str) {
        if let Err(p) = self.names.binary_search_by(|n| n.as_slice().cmp(name.as_bytes())) {
            self.names.insert(p, name.as_bytes().to_vec());
        }
    }

    pub fn tree(&self, has_program_name: bool) -> &[Node] {
        if has_program_name {
            &self.with_program
        } else {
            &self.without_program
        }
    }

    /// Adds decoder `d` to `list` (a top list or a parent's children).
    fn add_to(decoders: &mut [Decoder], list: &mut Vec<Node>, d: DecoderId, msgs: &mut Messages) -> Result<(), ()> {
        let name = decoders[d].name.clone().unwrap_or_default();
        let mut after_regex_ok = false;
        if decoders[d].parent.is_some() {
            for n in list.iter() {
                let t = n.decoder;
                if decoders[t].name != decoders[d].name {
                    continue;
                }
                // a sibling with the same name: they are tried in turn
                if (decoders[t].prematch.is_some() || decoders[t].regex.is_some()) && decoders[d].regex_offset != 0 {
                    after_regex_ok = true;
                }
                if decoders[d].prematch.is_some() {
                    msgs.error(m::duplicated_with_prematch(&name));
                    return Err(());
                }
                if decoders[d].fts != 0 {
                    msgs.error(m::duplicated_with_fts(&name));
                    return Err(());
                }
                let decodes = |x: &Decoder| x.regex.is_some() || x.plugin.is_some();
                if !(decodes(&decoders[t]) && decodes(&decoders[d])) {
                    msgs.error(m::bad_duplicate(&name));
                    return Err(());
                }
                decoders[t].get_next = true;
            }
        }
        if decoders[d].regex_offset & AFTER_PREVREGEX != 0 && !(after_regex_ok && !list.is_empty()) {
            msgs.error(m::bad_offset(&name));
            return Err(());
        }
        list.push(Node { decoder: d, children: Vec::new() });
        Ok(())
    }

    /// Places decoder `d`: under every top decoder named as its parent, or at the top.
    /// 1 added, 0 failed, -1 failed after adding somewhere.
    fn place(&mut self, d: DecoderId, msgs: &mut Messages) -> i32 {
        let Some(parent) = self.decoders[d].parent.clone() else {
            let list = if self.decoders[d].program_name.is_some() { &mut self.with_program } else { &mut self.without_program };
            if Self::add_to(&mut self.decoders, list, d, msgs).is_err() {
                msgs.error(m::DECODER_OPTIONS_FAILED);
                return 0;
            }
            return 1;
        };
        let mut added = 0;
        for list in [&mut self.with_program, &mut self.without_program] {
            for n in list.iter_mut() {
                if self.decoders[n.decoder].name.as_deref() == Some(parent.as_str()) {
                    if Self::add_to(&mut self.decoders, &mut n.children, d, msgs).is_err() {
                        msgs.error(m::DECODER_OPTIONS_FAILED);
                        return -added;
                    }
                    added = 1;
                }
            }
        }
        if added == 0 {
            msgs.error(m::bad_parent(&parent));
        }
        added
    }

    /// Loads one decoder file (`file` as configured, resolved from `home`). Non-zero on
    /// success: 1, or -2 for an empty local decoder file.
    pub fn load_file(&mut self, file: &str, order_size: usize, home: &Path, msgs: &mut Messages) -> i32 {
        let path = crate::config::resolve(home, file);
        let Ok(data) = std::fs::read(&path) else {
            msgs.warn(m::open_failed(file, 2, "No such file or directory"));
            return 1;
        };
        if let Err(e) = provigil_daemon::xml::parse(&data) {
            msgs.error(m::xml_failed(file, &e.message, e.line));
            return 0;
        }
        let roots = match provigil_daemon::xml::parse_with_variables(&data) {
            Ok(r) => r,
            Err(e) => {
                msgs.error(m::variables_failed(file, &e.message));
                return 0;
            }
        };
        if data.is_empty() && file != LOCAL_FILE {
            return 0;
        }
        if roots.is_empty() {
            if file != LOCAL_FILE {
                msgs.error(m::NULL_ELEMENT);
                return 0;
            }
            return -2;
        }
        for node in &roots {
            let attrs = &node.attributes;
            let attrs_ok = node.name.eq_ignore_ascii_case("decoder")
                && attrs.first().is_some_and(|(a, _)| a.eq_ignore_ascii_case("name"))
                && (attrs.len() < 2 || (attrs[1].0.eq_ignore_ascii_case("status") && attrs.len() == 2));
            if !attrs_ok {
                msgs.error(m::bad_element(&node.name));
                return 0;
            }
            if node.children.is_empty() {
                msgs.error(m::NULL_ELEMENT);
                return 0;
            }
            if self.read_decoder(node, order_size, msgs).is_err() {
                return 0;
            }
        }
        1
    }

    fn read_decoder(&mut self, node: &provigil_daemon::xml::Node, order_size: usize, msgs: &mut Messages) -> Result<(), ()> {
        let name = node.attributes[0].1.clone();
        let mut d = Decoder { name: Some(name.clone()), kind: SYSLOG, json_flags: JSON_NULL_STRING | JSON_ARRAY_ARRAY, ..Decoder::default() };
        let (mut regex, mut prematch, mut program) = (None::<String>, None::<String>, None::<String>);
        let (mut regex_type, mut prematch_type, mut program_type) = (ExpType::OsRegex, ExpType::OsRegex, ExpType::OsMatch);
        let fail = |msgs: &mut Messages| {
            msgs.error(m::decoder_failed(&name));
            Err(())
        };
        self.remember(&name);

        for el in &node.children {
            let (e, v) = (el.name.as_str(), el.content.as_str());
            let is = |x: &str| e.eq_ignore_ascii_case(x);
            if is("parent") {
                d.parent = append(d.parent.take(), v, msgs);
            } else if is("regex") || is("prematch") {
                let which = if is("regex") { "regex" } else { "prematch" };
                let mut offset = offset_attribute(el);
                if offset & AFTER_ERROR != 0 {
                    // a bad offset on prematch is reported as an error, on regex as a warning
                    let t = m::bad_attribute_default("offset", which, &name);
                    if which == "regex" {
                        msgs.warn(t);
                    } else {
                        msgs.error(t);
                    }
                    offset = 0;
                }
                let (text, kind, at) = if which == "regex" { (&mut regex, &mut regex_type, &mut d.regex_offset) } else { (&mut prematch, &mut prematch_type, &mut d.prematch_offset) };
                if text.is_some() && offset != 0 {
                    msgs.error(m::duplicated_offsets(&name));
                    return fail(msgs);
                }
                if offset != 0 {
                    *at = offset;
                }
                *kind = match type_attribute(el) {
                    None | Some(Some(ExpType::OsRegex)) => ExpType::OsRegex,
                    Some(Some(ExpType::Pcre2)) => ExpType::Pcre2,
                    Some(_) => {
                        msgs.warn(m::bad_attribute_default("type", which, &name));
                        ExpType::OsRegex
                    }
                };
                *text = append(text.take(), v, msgs);
            } else if is("program_name") {
                program_type = match type_attribute(el) {
                    None => ExpType::OsMatch,
                    Some(Some(t)) => t,
                    Some(None) => {
                        msgs.warn(m::bad_attribute_default("type", "program_name", &name));
                        ExpType::OsMatch
                    }
                };
                program = append(program.take(), v, msgs);
            } else if is("ftscomment") {
                d.fts_comment = append(d.fts_comment.take(), v, msgs);
            } else if is("use_own_name") {
                d.use_own_name |= v == "true";
            } else if is("plugin_decoder") {
                // an unknown name keeps a plugin set by an earlier element
                if let Some(p) = Plugin::named(v) {
                    d.plugin = Some(p);
                }
                if d.plugin.is_none() {
                    msgs.error(m::bad_decoder_argument(e, v));
                    return Err(());
                }
                d.plugin_offset = offset_attribute(el);
                if d.plugin_offset & AFTER_ERROR != 0 {
                    return fail(msgs);
                }
            } else if is("json_null_field") {
                d.json_flags &= !JSON_NULL_BITS;
                d.json_flags |= if v.eq_ignore_ascii_case("discard") {
                    JSON_NULL_DISCARD
                } else if v.eq_ignore_ascii_case("string") {
                    JSON_NULL_STRING
                } else {
                    msgs.warn(if v.eq_ignore_ascii_case("empty") {
                        m::deprecated_value(v, "json_null_field", &name)
                    } else {
                        m::bad_value_default(v, "json_null_field", &name)
                    });
                    JSON_NULL_STRING
                };
            } else if is("json_array_structure") {
                d.json_flags &= !JSON_ARRAY_BITS;
                d.json_flags |= if v.eq_ignore_ascii_case("csv") {
                    JSON_ARRAY_CSV
                } else {
                    if !v.eq_ignore_ascii_case("array") {
                        msgs.warn(m::bad_value_default(v, "json_array_structure", &name));
                    }
                    JSON_ARRAY_ARRAY
                };
            } else if e == "type" {
                d.kind = match v {
                    "firewall" => FIREWALL,
                    "ids" => IDS,
                    "web-log" => WEBLOG,
                    "syslog" => SYSLOG,
                    "squid" => SQUID,
                    "windows" => DECODER_WINDOWS,
                    "host-information" => HOST_INFO,
                    "ossec" => OSSEC_RL,
                    _ => {
                        msgs.error(format!("Invalid decoder type '{v}'."));
                        return Err(());
                    }
                };
            } else if is("order") {
                if v.bytes().filter(|&c| c == b',').count() >= order_size {
                    msgs.error("Order has too many fields.");
                    return Err(());
                }
                let mut order = vec![None; order_size];
                let mut names = vec![None; order_size];
                for (i, (raw, w)) in words(v, order_size).into_iter().enumerate() {
                    if w.is_empty() {
                        msgs.error(format!("decode-xml: Wrong field '{raw}' in the order of decoder '{name}'"));
                        return Err(());
                    }
                    order[i] = Some(match fixed_target(&w) {
                        Some(f) => Target::Fixed(f),
                        None => {
                            names[i] = Some(w);
                            Target::Named
                        }
                    });
                }
                d.order = Some(order);
                d.field_names = Some(names);
            } else if is("accumulate") {
                d.accumulate = 1;
            } else if is("fts") {
                let mut marks = vec![false; order_size];
                for (raw, w) in words(v, order_size) {
                    let wrong = |msgs: &mut Messages| {
                        msgs.error(format!("decode-xml: Wrong field '{raw}' in the fts decoder '{name}'"));
                        Err(())
                    };
                    if w.is_empty() {
                        return wrong(msgs);
                    }
                    d.fts |= match w.as_str() {
                        "dstuser" | "user" => FTS_DSTUSER,
                        "srcuser" => FTS_SRCUSER,
                        "srcip" => FTS_SRCIP,
                        "dstip" => FTS_DSTIP,
                        "id" => FTS_ID,
                        "location" => FTS_LOCATION,
                        "data" | "extra_data" => FTS_DATA,
                        "system_name" => FTS_SYSTEMNAME,
                        "name" => FTS_NAME,
                        _ => {
                            // a dynamic field of `order` (an earlier `order` element); none: ignored
                            let Some(names) = &d.field_names else { continue };
                            let at = names.iter().position(|n| n.as_ref().map_or(true, |n| n.eq_ignore_ascii_case(&w)));
                            match at {
                                Some(i) if names[i].is_some() => {
                                    marks[i] = true;
                                    FTS_DYNAMIC
                                }
                                _ => return wrong(msgs),
                            }
                        }
                    };
                }
                d.fts_fields = Some(marks);
            } else {
                msgs.error(format!("Invalid element '{e}' for decoder '{}'", node.name));
                return Err(());
            }
        }

        if prematch.is_none() && d.parent.is_none() && program.is_none() {
            msgs.error(m::no_prematch(&name));
            return fail(msgs);
        }
        if (regex.is_none() && (d.fts != 0 || d.order.is_some())) || (regex.is_some() && d.order.is_none()) {
            return fail(msgs);
        }
        let bad_offset = |msgs: &mut Messages, which: &str| {
            msgs.error(m::bad_offset(which));
            fail(msgs)
        };
        if d.regex_offset & AFTER_PARENT != 0 && d.parent.is_none() {
            return bad_offset(msgs, "after_parent");
        }
        if d.regex_offset & AFTER_PREMATCH != 0 {
            if d.parent.is_none() {
                d.regex_offset = AFTER_PARENT;
            } else if prematch.is_none() {
                return bad_offset(msgs, "after_prematch");
            }
        }
        if d.regex_offset & AFTER_PREVREGEX != 0 && (d.parent.is_none() || regex.is_none()) {
            return bad_offset(msgs, "after_regex");
        }
        if d.prematch_offset != 0 {
            if d.prematch_offset & AFTER_PARENT == 0 {
                return fail(msgs);
            }
            if d.parent.is_none() {
                return bad_offset(msgs, "after_parent");
            }
        }
        if d.plugin_offset & AFTER_PARENT != 0 && d.parent.is_none() {
            return bad_offset(msgs, "after_parent");
        }
        if d.plugin_offset & AFTER_PREMATCH != 0 && prematch.is_none() {
            return bad_offset(msgs, "after_prematch");
        }

        for (text, kind, flags, slot) in [(&prematch, prematch_type, 0, &mut d.prematch), (&program, program_type, 0, &mut d.program_name)] {
            if let Some(t) = text {
                match Expression::compile(kind, t, flags) {
                    Ok(x) => *slot = Some(x),
                    Err(_) => {
                        msgs.error(m::regex_syntax(t));
                        return fail(msgs);
                    }
                }
            }
        }
        if let Some(t) = &regex {
            match Expression::compile(regex_type, t, OS_RETURN_SUBSTRING) {
                Ok(x) => {
                    if let ExpressionKind::OsRegex(r) = &x.kind {
                        if !r.has_sub_strings() {
                            msgs.error(m::regex_without_groups(t));
                            return Err(());
                        }
                    }
                    d.regex = Some(x);
                }
                Err(_) => {
                    msgs.error(m::regex_syntax(t));
                    return fail(msgs);
                }
            }
        }
        if d.plugin.is_some() && (d.regex.is_some() || d.order.is_some()) {
            msgs.error(m::plugin_with_data(&name));
            return Err(());
        }
        self.decoders.push(d);
        let id = self.decoders.len() - 1;
        if self.place(id, msgs) < 1 {
            msgs.error(m::PLUGIN_FAILED);
            return Err(());
        }
        Ok(())
    }

    /// Gives ids to the decoders of one tree: a top decoder its name's id, a child its
    /// parent's id and name (or its own with `use_own_name`).
    fn set_ids(&mut self, with_program: bool) -> bool {
        let plan: Vec<(DecoderId, Vec<DecoderId>)> = self.tree(with_program).iter().map(|n| (n.decoder, n.children.iter().map(|c| c.decoder).collect())).collect();
        for (top, children) in plan {
            let name = self.decoders[top].name.clone().unwrap_or_default();
            let id = self.id_of(&name);
            self.decoders[top].id = id;
            if id == 0 {
                return false;
            }
            for c in children {
                if self.decoders[c].use_own_name {
                    let own = self.decoders[c].name.clone().unwrap_or_default();
                    self.decoders[c].id = self.id_of(&own);
                } else {
                    self.decoders[c].id = id;
                    self.decoders[c].name = Some(name.clone());
                }
                if self.decoders[c].id == 0 {
                    return false;
                }
            }
        }
        true
    }

    /// After all files: the built-in names, then the ids.
    pub fn finish(&mut self, msgs: &mut Messages) -> bool {
        for n in BUILT_IN {
            self.remember(n);
        }
        if !self.set_ids(false) || !self.set_ids(true) {
            msgs.error(m::PLUGIN_FAILED);
            return false;
        }
        true
    }
}

/// Stores a decoded value where the `order` says.
pub fn store(ev: &mut Event, target: Target, value: Bytes, name: Option<&str>) {
    match target {
        Target::Fixed(f) => ev.f[f] = Some(value),
        Target::Named => ev.fields.push(DynamicField { key: name.map(|n| n.as_bytes().to_vec()).unwrap_or_default(), value: Some(value) }),
    }
}

/// What decoding needs besides the decoders.
pub struct Context<'a> {
    pub order_size: usize,
    /// Rule ids by their number as text, for alerts read back from other managers.
    pub rules: &'a HashMap<String, RuleId>,
}

/// Matches `x` on the text at `at`; (matched, end position).
fn run(x: Option<&Expression>, buf: &[u8], at: Option<isize>, groups: &mut Vec<Bytes>) -> (bool, Option<isize>) {
    match (x, at) {
        (Some(x), Some(at)) if at >= 0 => {
            let (ok, end) = x.match_bytes(text_at(buf, at as usize), Some(groups));
            (ok, end.map(|e| at + e))
        }
        _ => (false, None),
    }
}

/// Past the end of a match, unless at the end of the text.
fn step(buf: &[u8], p: Option<isize>) -> Option<isize> {
    p.map(|p| if byte(buf, p) != 0 { p + 1 } else { p })
}

/// Decodes `ev`: the first top decoder whose program name and prematch match, then its first
/// matching child, then the regex (or plugin) of it and of its same-named siblings.
pub fn decode(set: &mut DecoderSet, ev: &mut Event, groups: &mut Vec<Bytes>, cx: &Context<'_>, with_program: bool) {
    let DecoderSet { decoders, with_program: wp, without_program: np, .. } = set;
    let top: &[Node] = if with_program { wp } else { np };
    // these carry over from one top decoder to the next, as in the original
    let (mut pmatch, mut cmatch, mut start, mut prev): (Option<isize>, Option<isize>, Option<isize>, Option<isize>) = (None, None, None, None);

    for (ti, node) in top.iter().enumerate() {
        let d = &decoders[node.decoder];
        if let Some(pn) = ev.program_name.clone() {
            if !d.program_name.as_ref().is_some_and(|x| x.match_bytes(&pn, Some(groups)).0) {
                continue;
            }
            pmatch = Some(ev.log_start as isize);
        }
        if d.prematch.is_some() {
            let (ok, end) = run(d.prematch.as_ref(), &ev.buf, Some(ev.log_start as isize), groups);
            if !ok {
                continue;
            }
            if end.is_some() {
                pmatch = end;
            }
            pmatch = step(&ev.buf, pmatch);
        }
        ev.decoder = node.decoder;
        ev.after_prematch = pmatch;

        // the list being walked and the position in it
        let (mut list, mut i): (&[Node], usize) = (top, ti);
        let mut current = Some(node.decoder);
        if !node.children.is_empty() {
            (list, i) = (&node.children, 0);
            current = None;
            while let Some(c) = list.get(i) {
                let cd = &decoders[c.decoder];
                if cd.prematch.is_none() {
                    cmatch = pmatch;
                    current = Some(c.decoder);
                    break;
                }
                let from = if cd.prematch_offset & AFTER_PARENT != 0 { pmatch } else { Some(ev.log_start as isize) };
                let (ok, end) = run(cd.prematch.as_ref(), &ev.buf, from, groups);
                if ok {
                    if end.is_some() {
                        cmatch = end;
                    }
                    cmatch = step(&ev.buf, cmatch);
                    ev.decoder = c.decoder;
                    ev.after_parent = pmatch;
                    ev.after_prematch = cmatch;
                    current = Some(c.decoder);
                    break;
                }
                // a group of same-named regex decoders is skipped together
                if cd.get_next {
                    i += 1;
                    while list.get(i).is_some_and(|n| decoders[n.decoder].get_next) {
                        i += 1;
                    }
                    if i >= list.len() {
                        return;
                    }
                }
                i += 1;
            }
        }
        let Some(mut cur) = current else { return };

        while i < list.len() {
            let d = &decoders[cur];
            if let Some(p) = d.plugin {
                plugins::run(p, decoders, ev, groups, cx);
            } else if d.regex.is_some() {
                start = match d.regex_offset {
                    0 => Some(ev.log_start as isize),
                    o if o & AFTER_PARENT != 0 => pmatch,
                    o if o & AFTER_PREMATCH != 0 => cmatch,
                    o if o & AFTER_PREVREGEX != 0 => prev.or(cmatch),
                    _ => start,
                };
                let (ok, end) = run(d.regex.as_ref(), &ev.buf, start, groups);
                if !ok {
                    if d.get_next && i + 1 < list.len() {
                        i += 1;
                        cur = list[i].decoder;
                        continue;
                    }
                    return;
                }
                prev = step(&ev.buf, end);
                if ev.fields.len() >= cx.order_size {
                    return;
                }
                let values = std::mem::take(groups);
                let order = d.order.as_deref().unwrap_or(&[]);
                let names = d.field_names.as_deref().unwrap_or(&[]);
                for (k, v) in values.into_iter().enumerate() {
                    if let Some(Some(t)) = order.get(k) {
                        store(ev, *t, v, names.get(k).and_then(|n| n.as_deref()));
                    }
                }
            } else {
                return;
            }
            if decoders[cur].get_next && i + 1 < list.len() {
                i += 1;
                cur = list[i].decoder;
            } else {
                return;
            }
        }
        return;
    }
}
