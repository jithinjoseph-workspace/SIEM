//! Reading the XML rule and decoder format, and checking one rule or decoder.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use regex::Regex;

/// One element of a loosely parsed XML text.
struct Node {
    name: String,
    attrs: Vec<(String, String)>,
    text: String,
    children: Vec<Node>,
}

impl Node {
    fn open(e: &BytesStart) -> Node {
        let attrs = e
            .attributes()
            .flatten()
            .map(|a| {
                let key = String::from_utf8_lossy(a.key.as_ref()).into_owned();
                let value = a
                    .unescape_value()
                    .map(|v| v.into_owned())
                    .unwrap_or_else(|_| String::from_utf8_lossy(&a.value).into_owned());
                (key, value)
            })
            .collect();
        Node { name: String::from_utf8_lossy(e.name().as_ref()).into_owned(), attrs, text: String::new(), children: Vec::new() }
    }

    fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    fn text(&self) -> &str {
        self.text.trim()
    }
}

/// Every top-level element of `xml`. Rule files hold several roots and may be cut short; a
/// parse error keeps what was read before it.
fn parse_tree(xml: &str) -> Vec<Node> {
    fn attach(stack: &mut [Node], roots: &mut Vec<Node>, node: Node) {
        match stack.last_mut() {
            Some(parent) => parent.children.push(node),
            None => roots.push(node),
        }
    }
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = false;
    let mut stack: Vec<Node> = Vec::new();
    let mut roots = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => stack.push(Node::open(&e)),
            Ok(Event::Empty(e)) => attach(&mut stack, &mut roots, Node::open(&e)),
            Ok(Event::End(_)) => {
                if let Some(node) = stack.pop() {
                    attach(&mut stack, &mut roots, node);
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(node) = stack.last_mut() {
                    match t.unescape() {
                        Ok(s) => node.text.push_str(&s),
                        Err(_) => node.text.push_str(&String::from_utf8_lossy(&t)),
                    }
                }
            }
            Ok(Event::CData(t)) => {
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&String::from_utf8_lossy(&t));
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            Ok(_) => {}
        }
    }
    while let Some(node) = stack.pop() {
        attach(&mut stack, &mut roots, node);
    }
    roots
}

fn split_list(s: &str) -> impl Iterator<Item = String> + '_ {
    s.split(|c: char| c == ',' || c == '|' || c.is_whitespace()).filter(|p| !p.is_empty()).map(str::to_string)
}

/// A rule in the XML format.
#[derive(Debug, Clone)]
pub struct XmlRule {
    pub id: u32,
    pub level: u8,
    pub description: String,
    pub groups: Vec<String>,
    /// matches but never alerts
    pub noalert: bool,
    pub frequency: Option<u32>,
    /// seconds
    pub timeframe: Option<u64>,
    pub mitre_ids: Vec<String>,
    if_sid: Vec<u32>,
    if_group: Vec<String>,
    if_matched_sid: Vec<u32>,
    if_matched_group: Vec<String>,
    same_source_ip: bool,
    same_user: bool,
    decoded_as: Vec<String>,
    /// each entry is one `<match>`: lower-case alternatives
    matches: Vec<Vec<String>>,
    regexes: Vec<Regex>,
    fields: Vec<(String, Regex)>,
}

/// One match kept for correlation.
pub(crate) struct Hit {
    pub at: DateTime<Utc>,
    /// when it was stored: the memory is in this order
    pub stored: DateTime<Utc>,
    pub agent: String,
    pub rule_id: u32,
    pub groups: Vec<String>,
    pub src_ip: String,
    pub user: Option<String>,
}

pub(crate) struct History<'a> {
    /// locked only to count, so events are checked side by side
    pub hits: &'a Mutex<VecDeque<Hit>>,
    pub now: DateTime<Utc>,
    pub stored_now: DateTime<Utc>,
    pub agent: &'a str,
    pub src_ip: &'a str,
    pub user: Option<&'a str>,
}

/// What a rule is checked against.
pub(crate) struct EventCtx<'a> {
    pub log: &'a str,
    pub lower: &'a str,
    /// names of the decoders that recognised the event (with their parents)
    pub decoders: &'a [String],
    pub fields: &'a HashMap<String, String>,
    pub matched_ids: &'a [u32],
    pub matched_groups: &'a HashSet<String>,
    pub history: Option<History<'a>>,
}

/// Field `name`, or a field whose last dotted part is the same.
fn field<'a>(fields: &'a HashMap<String, String>, name: &str) -> Option<&'a String> {
    fields.get(name).or_else(|| {
        let last = name.rsplit('.').next().unwrap_or(name);
        fields.iter().find(|(k, _)| k.rsplit('.').next() == Some(last)).map(|(_, v)| v)
    })
}

impl XmlRule {
    /// True when the rule matches `log` with no other context: no parent rule, no
    /// decoder, no fields, no history.
    pub fn matches_log(&self, log: &str) -> bool {
        let lower = log.to_lowercase();
        let fields = HashMap::new();
        let groups = HashSet::new();
        self.eval(&EventCtx {
            log,
            lower: &lower,
            decoders: &[],
            fields: &fields,
            matched_ids: &[],
            matched_groups: &groups,
            history: None,
        })
    }

    /// The pattern shown in the console's rule list.
    pub(crate) fn pattern_text(&self) -> String {
        let mut parts: Vec<String> = self.matches.iter().map(|m| m.join("|")).collect();
        parts.extend(self.regexes.iter().map(|r| r.as_str().to_string()));
        parts.join(" ")
    }

    fn correlates(&self) -> bool {
        !self.if_matched_sid.is_empty() || !self.if_matched_group.is_empty()
    }

    pub(crate) fn eval(&self, ctx: &EventCtx) -> bool {
        let has_condition = !self.if_sid.is_empty()
            || !self.if_group.is_empty()
            || self.correlates()
            || !self.decoded_as.is_empty()
            || !self.matches.is_empty()
            || !self.regexes.is_empty()
            || !self.fields.is_empty();
        if !has_condition {
            return false;
        }
        if !self.if_sid.is_empty() && !self.if_sid.iter().any(|s| ctx.matched_ids.contains(s)) {
            return false;
        }
        if !self.if_group.is_empty() && !self.if_group.iter().any(|g| ctx.matched_groups.contains(g)) {
            return false;
        }
        if !self.decoded_as.is_empty() && !self.decoded_as.iter().any(|d| ctx.decoders.contains(d)) {
            return false;
        }
        if !self.matches.iter().all(|alts| alts.iter().any(|a| ctx.lower.contains(a.as_str()))) {
            return false;
        }
        if !self.regexes.iter().all(|r| r.is_match(ctx.log)) {
            return false;
        }
        if !self.fields.iter().all(|(name, re)| field(ctx.fields, name).is_some_and(|v| re.is_match(v))) {
            return false;
        }
        if self.correlates() {
            let Some(h) = &ctx.history else { return false };
            // without its own parent the rule is a child of the rules it counts: the event must
            // be one of them (else every later event of the agent would fire it, and scan)
            let counted = self.if_matched_sid.iter().any(|s| ctx.matched_ids.contains(s))
                || self.if_matched_group.iter().any(|g| ctx.matched_groups.contains(g));
            if self.if_sid.is_empty() && self.if_group.is_empty() && !counted {
                return false;
            }
            let timeframe = Duration::seconds(self.timeframe.unwrap_or(360) as i64);
            let since = h.now - timeframe;
            // newest first, stopping at hits stored before the window: an event sent late (an
            // agent's backlog) still finds its partners, which were stored with it
            let count = crate::lock(h.hits)
                .iter()
                .rev()
                .take_while(|hit| hit.stored >= h.stored_now - timeframe)
                .filter(|hit| hit.at >= since && hit.at <= h.now && hit.agent == h.agent)
                .filter(|hit| {
                    self.if_matched_sid.contains(&hit.rule_id)
                        || hit.groups.iter().any(|g| self.if_matched_group.contains(g))
                })
                .filter(|hit| !self.same_source_ip || hit.src_ip == h.src_ip)
                .filter(|hit| !self.same_user || (h.user.is_some() && hit.user.as_deref() == h.user))
                .count();
            if count < self.frequency.unwrap_or(1) as usize {
                return false;
            }
        }
        true
    }

    fn from_node(node: &Node, inherited: &[String]) -> Option<XmlRule> {
        let id = node.attr("id")?.trim().parse().ok()?;
        let mut rule = XmlRule {
            id,
            level: node.attr("level").and_then(|l| l.trim().parse().ok()).unwrap_or(0),
            description: String::new(),
            groups: inherited.to_vec(),
            noalert: node.attr("noalert").is_some_and(|v| v.trim() == "1"),
            frequency: node.attr("frequency").and_then(|v| v.trim().parse().ok()),
            timeframe: node.attr("timeframe").and_then(|v| v.trim().parse().ok()),
            mitre_ids: Vec::new(),
            if_sid: Vec::new(),
            if_group: Vec::new(),
            if_matched_sid: Vec::new(),
            if_matched_group: Vec::new(),
            same_source_ip: false,
            same_user: false,
            decoded_as: Vec::new(),
            matches: Vec::new(),
            regexes: Vec::new(),
            fields: Vec::new(),
        };
        for child in &node.children {
            let text = child.text();
            match child.name.as_str() {
                "if_sid" => rule.if_sid.extend(split_list(text).filter_map(|s| s.parse::<u32>().ok())),
                "if_group" => rule.if_group.extend(split_list(text)),
                "if_matched_sid" => rule.if_matched_sid.extend(split_list(text).filter_map(|s| s.parse::<u32>().ok())),
                "if_matched_group" => rule.if_matched_group.extend(split_list(text)),
                "same_source_ip" | "same_srcip" => rule.same_source_ip = true,
                "same_user" => rule.same_user = true,
                "decoded_as" => rule.decoded_as.push(text.to_string()),
                "match" => {
                    let alts: Vec<String> =
                        text.split('|').filter(|a| !a.is_empty()).map(str::to_lowercase).collect();
                    if !alts.is_empty() {
                        rule.matches.push(alts);
                    }
                }
                "regex" => rule.regexes.push(Regex::new(text).ok()?),
                "field" => rule.fields.push((child.attr("name")?.to_string(), Regex::new(text).ok()?)),
                "description" => rule.description = text.to_string(),
                "group" => rule.groups.extend(text.split(',').map(str::trim).filter(|g| !g.is_empty()).map(str::to_string)),
                "mitre" => rule
                    .mitre_ids
                    .extend(child.children.iter().filter(|c| c.name == "id").map(|c| c.text().to_string())),
                _ => {}
            }
        }
        Some(rule)
    }
}

/// Every rule in `xml` (in `<group name="...">` elements or bare). Rules with an invalid
/// pattern are left out.
pub fn parse_rules_xml(xml: &str) -> Vec<XmlRule> {
    fn walk(node: &Node, groups: &[String], out: &mut Vec<XmlRule>) {
        match node.name.as_str() {
            "rule" => out.extend(XmlRule::from_node(node, groups)),
            "group" => {
                let mut inner = groups.to_vec();
                inner.extend(node.attr("name").unwrap_or("").split(',').map(str::trim).filter(|g| !g.is_empty()).map(str::to_string));
                node.children.iter().for_each(|c| walk(c, &inner, out));
            }
            _ => node.children.iter().for_each(|c| walk(c, groups, out)),
        }
    }
    let mut out = Vec::new();
    parse_tree(xml).iter().for_each(|n| walk(n, &[], &mut out));
    out
}

/// A decoder in the XML format.
#[derive(Debug, Clone)]
pub(crate) struct XmlDecoder {
    pub name: String,
    pub parent: Option<String>,
    program_name: Option<Regex>,
    prematch: Option<Regex>,
    regex: Option<Regex>,
    order: Vec<String>,
}

impl XmlDecoder {
    fn from_node(node: &Node) -> Option<XmlDecoder> {
        let mut d = XmlDecoder {
            name: node.attr("name")?.trim().to_string(),
            parent: None,
            program_name: None,
            prematch: None,
            regex: None,
            order: Vec::new(),
        };
        for child in &node.children {
            let text = child.text();
            match child.name.as_str() {
                "parent" => d.parent = Some(text.to_string()),
                "program_name" => d.program_name = Some(Regex::new(text).ok()?),
                "prematch" => d.prematch = Some(Regex::new(text).ok()?),
                "regex" => d.regex = Some(Regex::new(text).ok()?),
                "order" => d.order = text.split(',').map(|s| s.trim().to_string()).collect(),
                _ => {}
            }
        }
        (d.program_name.is_some() || d.prematch.is_some() || d.regex.is_some()).then_some(d)
    }

    /// Program name and prematch must match when present; the regex only extracts, unless
    /// it is the decoder's only pattern.
    // shortcut: `offset` attributes are ignored (patterns run on the whole message), upgrade if offset-anchored decoders matter.
    fn recognises(&self, program: Option<&str>, log: &str) -> bool {
        if let Some(p) = &self.program_name {
            if !program.is_some_and(|prog| p.is_match(prog)) {
                return false;
            }
        }
        if let Some(p) = &self.prematch {
            if !p.is_match(log) {
                return false;
            }
        }
        match (&self.regex, self.program_name.is_none() && self.prematch.is_none()) {
            (Some(r), true) => r.is_match(log),
            _ => true,
        }
    }

    fn extract(&self, log: &str, out: &mut HashMap<String, String>) {
        let Some(caps) = self.regex.as_ref().and_then(|r| r.captures(log)) else { return };
        for (i, name) in self.order.iter().enumerate() {
            if let Some(m) = caps.get(i + 1).filter(|m| !m.as_str().is_empty() && !name.is_empty()) {
                out.entry(name.clone()).or_insert_with(|| m.as_str().to_string());
            }
        }
    }
}

pub(crate) fn parse_decoders_xml(xml: &str) -> Vec<XmlDecoder> {
    fn walk(node: &Node, out: &mut Vec<XmlDecoder>) {
        if node.name == "decoder" {
            out.extend(XmlDecoder::from_node(node));
        } else {
            node.children.iter().for_each(|c| walk(c, out));
        }
    }
    let mut out = Vec::new();
    parse_tree(xml).iter().for_each(|n| walk(n, &mut out));
    out
}

/// The first root decoder that recognises the message, then its children (and theirs).
/// Returns the names that matched (root first) and the fields they extracted.
pub(crate) fn decode_xml(
    decoders: &[XmlDecoder],
    program: Option<&str>,
    log: &str,
) -> Option<(Vec<String>, HashMap<String, String>)> {
    let root = decoders.iter().find(|d| d.parent.is_none() && d.recognises(program, log))?;
    let mut fields = HashMap::new();
    root.extract(log, &mut fields);
    let mut names = vec![root.name.clone()];
    let mut pending = vec![root.name.clone()];
    while let Some(parent) = pending.pop() {
        for d in decoders.iter().filter(|d| d.parent.as_deref() == Some(parent.as_str())) {
            if d.recognises(program, log) {
                d.extract(log, &mut fields);
                if !names.contains(&d.name) {
                    names.push(d.name.clone());
                    pending.push(d.name.clone());
                }
            }
        }
    }
    Some((names, fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_matches_log() {
        let rules = parse_rules_xml(
            r#"<group name="web,attack,">
                 <rule id="100001" level="8">
                   <match>select|union</match>
                   <regex>id=\d+</regex>
                   <description>SQL injection</description>
                   <group>sqli,</group>
                   <mitre><id>T1190</id><id>T1059</id></mitre>
                 </rule>
               </group>
               <rule id="100002" level="3"><if_sid>100001</if_sid></rule>"#,
        );
        assert_eq!(rules.len(), 2);
        let r = &rules[0];
        assert_eq!((r.id, r.level, r.description.as_str()), (100001, 8, "SQL injection"));
        assert_eq!(r.groups, ["web", "attack", "sqli"]);
        assert_eq!(r.mitre_ids[0], "T1190");
        assert!(r.matches_log("GET /?id=1 UNION all"));
        assert!(!r.matches_log("GET /?id=1 hello"));
        assert!(!r.matches_log("GET /?q=union"));
        // a parent rule is context, so it never holds here
        assert!(!rules[1].matches_log("GET /?id=1 UNION all"));
    }

    #[test]
    fn invalid_pattern_skipped_and_empty_rule_never_matches() {
        let rules = parse_rules_xml(
            r#"<group name="x"><rule id="1" level="5"><regex>([a-</regex></rule>
               <rule id="2" level="5"><field name="f">(</field></rule>
               <rule id="3" level="5"><description>nothing to check</description></rule>
               <rule id="4" level="5"><match>ok</match><unknown>x</unknown></rule></group>"#,
        );
        assert_eq!(rules.iter().map(|r| r.id).collect::<Vec<_>>(), [3, 4]);
        assert!(!rules[0].matches_log("anything"));
        assert!(rules[1].matches_log("all OK"));
        assert!(parse_rules_xml("<rule id=").is_empty());
    }

    #[test]
    fn decoders_parent_prematch_and_order() {
        let decoders = parse_decoders_xml(
            r#"<decoder name="webapp"><program_name>^webapp$</program_name></decoder>
               <decoder name="webapp-login"><parent>webapp</parent><prematch>^login</prematch>
                 <regex>user=(\S+) ip=(\S+) port=(\d+)</regex><order>user, srcip, srcport</order></decoder>
               <decoder name="orphan"><parent>nothing</parent><prematch>login</prematch></decoder>
               <decoder name="bad"><prematch>(</prematch></decoder>"#,
        );
        assert_eq!(decoders.len(), 3);
        let (names, fields) = decode_xml(&decoders, Some("webapp"), "login user=amy ip=10.0.0.9 port=4433").unwrap();
        assert_eq!(names, ["webapp", "webapp-login"]);
        assert_eq!(fields["user"], "amy");
        assert_eq!(fields["srcip"], "10.0.0.9");
        assert_eq!(fields["srcport"], "4433");
        // the child needs its prematch, the root its program name
        let (names, fields) = decode_xml(&decoders, Some("webapp"), "logout user=amy").unwrap();
        assert_eq!(names, ["webapp"]);
        assert!(fields.is_empty());
        assert!(decode_xml(&decoders, Some("other"), "login user=amy ip=1 port=2").is_none());
        assert!(decode_xml(&decoders, None, "login").is_none());
    }
}
