//! The `getconfig` sections of the analysis socket (spec section 2.22), quirks kept: the
//! decoder `fts` list holds only the first flag set (and for dynamic fields the 0/1 marks as
//! text), and a rule with `if_level` lists `if_group` twice.

use provigil_json::Json;
use provigil_regex::{Expression, ExpressionKind};

use crate::config::{Config, ALL_AGENTS, AS_ONLY, REMOTE_AGENT, SPECIFIC_AGENT};
use crate::decoders::{DecoderSet, Node, Target, AFTER_PARENT, AFTER_PREMATCH, AFTER_PREVREGEX};
use crate::event::*;
use crate::plugins::Plugin;
use crate::rules::{RuleNode, RuleSet, FIELD_DYNAMICS};

fn num(v: impl Into<f64>) -> Json {
    Json::number(v.into())
}

fn yes_no(b: bool) -> Json {
    Json::string(if b { "yes" } else { "no" })
}

fn wrap(key: &str, v: Json) -> Json {
    let mut root = Json::object();
    root.add(key, v);
    root
}

pub fn global(c: &Config) -> Json {
    let g = &c.global;
    let mut o = Json::object();
    o.add("email_notification", yes_no(g.mailnotify != 0));
    o.add("logall", yes_no(g.logall));
    o.add("logall_json", yes_no(g.logall_json));
    o.add("integrity_checking", num(g.integrity));
    o.add("rootkit_detection", num(g.rootcheck));
    o.add("host_information", num(g.hostinfo));
    o.add("prelude_output", yes_no(g.prelude));
    if let Some(p) = &g.prelude_profile {
        o.add("prelude_profile", Json::string(p));
    }
    if g.prelude {
        // the host information level is shown here, as before
        o.add("prelude_log_level", num(g.hostinfo));
    }
    if let Some(p) = &g.geoipdb {
        o.add("geoipdb", Json::string(p));
    }
    o.add("zeromq_output", yes_no(g.zeromq_output));
    for (k, v) in [("zeromq_uri", &g.zeromq_uri), ("zeromq_server_cert", &g.zeromq_server_cert), ("zeromq_client_cert", &g.zeromq_client_cert)] {
        if let Some(v) = v {
            o.add(k, Json::string(v));
        }
    }
    o.add("jsonout_output", yes_no(g.jsonout_output));
    o.add("alerts_log", yes_no(g.alerts_log));
    o.add("stats", num(g.stats));
    o.add("memory_size", num(g.memory_size));
    if !g.white_list.is_empty() {
        let mut l: Vec<Json> = g.white_list.iter().map(|ip| Json::string(&ip.ip)).collect();
        l.extend(g.hostname_white_list.iter().flat_map(|m| m.patterns().into_iter().map(Json::string)));
        o.add("white_list", Json::Array(l));
    }
    if let Some(f) = &g.custom_alert_output {
        o.add("custom_alert_output", Json::string(f));
    }
    o.add("rotate_interval", num(g.rotate_interval));
    o.add("max_output_size", Json::number(g.max_output_size as f64));
    let mut eps = Json::object();
    eps.add("maximum", num(g.eps_maximum));
    eps.add("timeframe", num(g.eps_timeframe));
    o.add("eps", eps);
    wrap("global", o)
}

pub fn active_response(c: &Config) -> Json {
    let list = c
        .ar
        .responses
        .iter()
        .map(|a| {
            let mut j = Json::object();
            j.add("command", Json::string(&a.command));
            for (k, v) in [("agent_id", &a.agent_id), ("rules_id", &a.rules_id), ("rules_group", &a.rules_group)] {
                if let Some(v) = v {
                    j.add(k, Json::string(v));
                }
            }
            j.add("timeout", num(a.timeout));
            j.add("level", num(a.level));
            let at = [(AS_ONLY, "AS_ONLY"), (REMOTE_AGENT, "REMOTE_AGENT"), (SPECIFIC_AGENT, "SPECIFIC_AGENT"), (ALL_AGENTS, "ALL_AGENTS")].iter().find(|(f, _)| a.location & f != 0);
            if let Some((_, l)) = at {
                j.add("location", Json::string(*l));
            }
            j
        })
        .collect();
    wrap("active-response", Json::Array(list))
}

pub fn commands(c: &Config) -> Json {
    let list = c
        .ar
        .commands
        .iter()
        .map(|x| {
            let mut j = Json::object();
            j.add("name", Json::string(&x.name));
            j.add("executable", Json::string(&x.executable));
            j.add("timeout_allowed", num(u8::from(x.timeout_allowed)));
            j
        })
        .collect();
    wrap("command", Json::Array(list))
}

pub fn alerts(c: &Config) -> Json {
    let mut a = Json::object();
    a.add("email_alert_level", num(c.global.mailbylevel));
    a.add("log_alert_level", num(c.global.logbylevel));
    wrap("alerts", a)
}

pub fn internal(c: &Config) -> Json {
    let i = &c.internal;
    let mut a = Json::object();
    for (k, v) in [
        ("debug", i.debug),
        ("default_timeframe", i.default_timeframe),
        ("stats_maxdiff", i.stats_maxdiff),
        ("stats_mindiff", i.stats_mindiff),
        ("stats_percent_diff", i.stats_percent_diff),
        ("fts_list_size", i.fts_list_size),
        ("fts_min_size_for_str", i.fts_min_size_for_str),
        ("log_fw", i.log_fw),
        ("decoder_order_size", i.decoder_order_size),
        ("label_cache_maxage", i.label_cache_maxage),
        ("show_hidden_labels", i.show_hidden_labels),
        ("rlimit_nofile", i.rlimit_nofile),
        ("min_rotate_interval", i.min_rotate_interval),
    ] {
        a.add(k, num(v));
    }
    wrap("internal", wrap("analysisd", a))
}

pub fn labels(c: &Config) -> Json {
    let list = c
        .labels
        .iter()
        .map(|l| {
            let mut j = Json::object();
            j.add("value", Json::string(&l.value));
            j.add("key", Json::string(&l.key));
            j.add("hidden", yes_no(l.hidden));
            j
        })
        .collect();
    wrap("labels", Json::Array(list))
}

pub fn rule_test(c: &Config) -> Json {
    let l = &c.logtest;
    let mut r = Json::object();
    r.add("enabled", yes_no(l.enabled));
    if l.threads != 0 {
        r.add("threads", num(l.threads));
    }
    if l.max_sessions != 0 {
        r.add("max_sessions", num(l.max_sessions));
    }
    if l.session_timeout != 0 {
        r.add("session_timeout", Json::number(l.session_timeout as f64));
    }
    wrap("rule_test", r)
}

/// `{"pattern", "type"[, "negate"]}` of a pattern (unset parts left out).
fn pattern(e: &Expression, negate: bool) -> Json {
    let mut j = Json::object();
    if let Some(p) = e.pattern() {
        j.add("pattern", Json::string(p));
    }
    if let Some(t) = e.type_str() {
        j.add("type", Json::string(t));
    }
    if negate {
        j.add("negate", Json::bool(e.negate));
    }
    j
}

fn kind_name(k: u8) -> Option<&'static str> {
    Some(match k {
        FIREWALL => "firewall",
        IDS => "ids",
        WEBLOG => "web-log",
        SYSLOG => "syslog",
        SQUID => "squid",
        DECODER_WINDOWS => "windows",
        HOST_INFO => "host-information",
        OSSEC_RL => "ossec",
        _ => return None,
    })
}

const FIXED_NAMES: [&str; 14] = ["srcip", "id", "dstip", "srcport", "dstport", "srcuser", "dstuser", "protocol", "action", "url", "data", "extra_data", "status", "system_name"];

fn decoder_list(set: &DecoderSet, list: &[Node], order: usize, out: &mut Vec<Json>) {
    for node in list {
        let d = &set.decoders[node.decoder];
        let mut j = Json::object();
        j.add("id", num(d.id));
        for (k, v) in [("name", &d.name), ("parent", &d.parent), ("ftscomment", &d.fts_comment)] {
            if let Some(v) = v {
                j.add(k, Json::string(v));
            }
        }
        if let (true, Some(targets)) = (order != 0, &d.order) {
            let mut l = Vec::new();
            for i in 0..order {
                let name = match targets.get(i) {
                    Some(Some(Target::Fixed(f))) => Some(FIXED_NAMES[*f]),
                    Some(Some(Target::Named)) => d.field_names.as_ref().and_then(|f| f.get(i)).and_then(|f| f.as_deref()),
                    _ => continue,
                };
                if let Some(n) = name {
                    l.push(Json::string(n));
                }
            }
            j.add("order", Json::Array(l));
        }
        if !node.children.is_empty() {
            let mut ch = Vec::new();
            decoder_list(set, &node.children, order, &mut ch);
            j.add("children", Json::Array(ch));
        }
        j.add("use_own_name", Json::string(if d.use_own_name { "true" } else { "false" }));
        j.add("accumulate", yes_no(d.accumulate != 0));
        if let Some(e) = &d.prematch {
            j.add("prematch", pattern(e, false));
        }
        if d.prematch_offset & AFTER_PARENT != 0 {
            j.add("prematch_offset", Json::string("after_parent"));
        }
        if let Some(e) = &d.regex {
            j.add("regex", pattern(e, false));
        }
        let offset = [(AFTER_PARENT, "after_parent"), (AFTER_PREVREGEX, "after_regex"), (AFTER_PREMATCH, "after_prematch")].iter().find(|(f, _)| d.regex_offset & f != 0);
        if let Some((_, t)) = offset {
            j.add("regex_offset", Json::string(*t));
        }
        if let Some(e) = &d.program_name {
            j.add("program_name", pattern(e, false));
        }
        if d.fts != 0 {
            let flags = [(FTS_DSTUSER, "dstuser"), (FTS_SRCUSER, "srcuser"), (FTS_SRCIP, "srcip"), (FTS_DSTIP, "dstip"), (FTS_ID, "id"), (FTS_LOCATION, "location"), (FTS_DATA, "data"), (FTS_SYSTEMNAME, "system_name"), (FTS_NAME, "name")];
            let first = match flags.iter().find(|(f, _)| d.fts & f != 0) {
                Some((_, n)) => Some(Json::string(*n)),
                // the marks up to the first unmarked one, as a text of 0x01 bytes
                None if d.fts & FTS_DYNAMIC != 0 => d.fts_fields.as_ref().map(|m| Json::String(m.iter().take_while(|&&b| b).map(|_| 1u8).collect())),
                None => None,
            };
            j.add("fts", Json::Array(first.into_iter().collect()));
        }
        if let Some(k) = kind_name(d.kind).filter(|_| d.kind != 0) {
            j.add("type", Json::string(k));
        }
        if let Some(p) = d.plugin {
            j.add(
                "plugin_decoder",
                Json::string(match p {
                    Plugin::Pf => "PF_Decoder",
                    Plugin::SymantecWs => "SymantecWS_Decoder",
                    Plugin::SonicWall => "SonicWall_Decoder",
                    Plugin::Alert => "OSSECAlert_Decoder",
                    Plugin::Json => "JSON_Decoder",
                }),
            );
        }
        out.push(j);
    }
}

/// The decoder trees (nothing when there is no decoder with a program name).
pub fn decoders(set: &DecoderSet, order: usize) -> Json {
    let mut list = Vec::new();
    if !set.with_program.is_empty() {
        decoder_list(set, &set.with_program, order, &mut list);
        decoder_list(set, &set.without_program, order, &mut list);
    }
    wrap("decoders", Json::Array(list))
}

const COMPARED: [&str; 17] = ["srcip", "id", "dstip", "srcport", "dstport", "srcuser", "user", "protocol", "action", "url", "data", "extra_data", "status", "system_name", "srcgeoip", "dstgeoip", "location"];

fn rule_list(set: &RuleSet, list: &[RuleNode], out: &mut Vec<Json>) {
    for node in list {
        let r = &set.rules[node.rule];
        let mut j = Json::object();
        if !node.children.is_empty() {
            let mut ch = Vec::new();
            rule_list(set, &node.children, &mut ch);
            j.add("children", Json::Array(ch));
        }
        j.add("sigid", num(r.sigid));
        j.add("level", num(r.level));
        j.add("maxsize", Json::number(r.maxsize as f64));
        j.add("frequency", num(if r.event_search.is_some() { r.frequency + 2 } else { r.frequency }));
        j.add("timeframe", num(r.timeframe));
        j.add("ignore_time", num(r.ignore_time));
        j.add("decoded_as", num(r.decoded_as));
        j.add("if_matched_sid", num(r.if_matched_sid));
        if let Some(g) = &r.group {
            j.add("group", Json::string(g));
        }
        if let Some(e) = &r.regex {
            j.add("regex", pattern(e, true));
        }
        if let Some(e) = &r.match_ {
            let mut m = Json::object();
            if let Some(p) = e.pattern() {
                m.add("pattern", Json::string(p));
            }
            m.add("negate", Json::bool(e.negate));
            j.add("match", m);
        }
        for (k, e) in [
            ("srcgeoip", &r.srcgeoip),
            ("dstgeoip", &r.dstgeoip),
            ("srcport", &r.srcport),
            ("dstport", &r.dstport),
            ("user", &r.user),
            ("url", &r.url),
            ("id", &r.id),
            ("system_name", &r.system_name),
            ("protocol", &r.protocol),
            ("data", &r.data),
            ("status", &r.status),
            ("hostname", &r.hostname),
            ("program_name", &r.program_name),
            ("extra_data", &r.extra_data),
            ("location", &r.location),
            ("action", &r.action),
        ] {
            if let Some(e) = e {
                j.add(k, pattern(e, true));
            }
        }
        for (k, v) in [("comment", &r.comment), ("info", &r.info), ("cve", &r.cve), ("if_sid", &r.if_sid)] {
            if let Some(v) = v {
                j.add(k, Json::string(v));
            }
        }
        if let (Some(_), Some(g)) = (&r.if_level, &r.if_group) {
            j.add("if_group", Json::string(g));
        }
        if let Some(g) = &r.if_group {
            j.add("if_group", Json::string(g));
        }
        if let Some(m) = &r.if_matched_regex {
            j.add("if_matched_regex", Json::string(m.raw()));
        }
        if let Some(m) = &r.if_matched_group {
            j.add("if_matched_group", Json::string(m.raw()));
        }
        if let Some(f) = &r.file {
            j.add("rule_file", Json::string(f));
        }
        if let Some(c) = kind_name(r.category).filter(|_| r.category != HOST_INFO) {
            j.add("category", Json::string(c));
        }
        if !r.fields.is_empty() {
            let l = r
                .fields
                .iter()
                .map(|f| {
                    let mut fj = Json::object();
                    if let Some(n) = &f.name {
                        fj.add("name", Json::string(n));
                    }
                    if let Some(p) = f.regex.pattern() {
                        fj.add("pattern", Json::string(p));
                    }
                    if let Some(t) = f.regex.type_str() {
                        fj.add("type", Json::string(t));
                    }
                    fj.add("negate", Json::bool(f.regex.negate));
                    fj
                })
                .collect();
            j.add("field", Json::Array(l));
        }
        for (k, e) in [("srcip", &r.srcip), ("dstip", &r.dstip)] {
            if let Some(Expression { kind: ExpressionKind::OsIpArray(ips), negate }) = e {
                if !ips.is_empty() {
                    let l = ips
                        .iter()
                        .map(|ip| {
                            let mut o = Json::object();
                            o.add("ip", Json::string(&ip.ip));
                            o.add("negate", Json::bool(*negate));
                            o
                        })
                        .collect();
                    j.add(k, Json::Array(l));
                }
            }
        }
        for (kind, mut bits, names) in [("same", r.same_field, &r.same_fields), ("different", r.different_field, &r.not_same_fields)] {
            if bits == 0 {
                continue;
            }
            if bits & FIELD_DYNAMICS == FIELD_DYNAMICS {
                j.add(format!("{kind}_field"), Json::Array(names.iter().flatten().map(Json::string).collect()));
                bits &= !FIELD_DYNAMICS;
            }
            for name in COMPARED {
                if bits == 0 {
                    break;
                }
                if bits & 1 == 1 {
                    j.add(format!("{kind}_{name}"), Json::string(""));
                }
                bits >>= 1;
            }
        }
        out.push(j);
    }
}

pub fn rules(set: &RuleSet) -> Json {
    let mut list = Vec::new();
    rule_list(set, &set.tree, &mut list);
    wrap("rules", Json::Array(list))
}
