//! `getconfig` sections of the analysis socket (analysisd/config.c,
//! analysisd/config_json.c, config/logtest-config.c), quirks included:
//! the `fts` list holds only the first flag of the if/else chain (and the
//! dynamic case prints `fts_fields` — a 0/1 byte array — as a string), and
//! a rule with `if_level` gets an extra `if_group` member.

use siem_cjson::Json;
use siem_config::active_response::{ALL_AGENTS, AS_ONLY, REMOTE_AGENT, SPECIFIC_AGENT};
use siem_regex::Expression;

use crate::daemon_config::AnalysisdConfig;
use crate::decoders::{DNode, Decoders, OrderFn, AFTER_PARENT, AFTER_PREMATCH, AFTER_PREVREGEX};
use crate::event::*;
use crate::plugins::Plugin;
use crate::rules::{RNode, Rules, FIELD_DYNAMICS};

fn num(v: impl Into<f64>) -> Json {
    Json::number(v.into())
}

fn yes_no(b: bool) -> Json {
    Json::string(if b { "yes" } else { "no" })
}

/// `getGlobalConfig`
pub fn global(cfg: &AnalysisdConfig) -> Json {
    let c = &cfg.global;
    let mut g = Json::object();
    g.add("email_notification", yes_no(c.mailnotify != 0));
    g.add("logall", yes_no(c.logall != 0));
    g.add("logall_json", yes_no(c.logall_json != 0));
    g.add("integrity_checking", num(c.integrity));
    g.add("rootkit_detection", num(c.rootcheck));
    g.add("host_information", num(c.hostinfo));
    g.add("prelude_output", yes_no(c.prelude != 0));
    if let Some(p) = &c.prelude_profile {
        g.add("prelude_profile", Json::string(p));
    }
    if c.prelude != 0 {
        // the C code reports hostinfo here
        g.add("prelude_log_level", num(c.hostinfo));
    }
    if let Some(p) = &c.geoipdb_file {
        g.add("geoipdb", Json::string(p));
    }
    g.add("zeromq_output", yes_no(c.zeromq_output != 0));
    if let Some(p) = &c.zeromq_output_uri {
        g.add("zeromq_uri", Json::string(p));
    }
    if let Some(p) = &c.zeromq_output_server_cert {
        g.add("zeromq_server_cert", Json::string(p));
    }
    if let Some(p) = &c.zeromq_output_client_cert {
        g.add("zeromq_client_cert", Json::string(p));
    }
    g.add("jsonout_output", yes_no(c.jsonout_output != 0));
    g.add("alerts_log", yes_no(c.alerts_log != 0));
    g.add("stats", num(c.stats));
    g.add("memory_size", num(c.memorysize));
    if !c.white_list.is_empty() {
        let mut l = Vec::new();
        for ip in &c.white_list {
            l.push(Json::string(&ip.ip));
        }
        for m in &c.hostname_white_list {
            for p in m.patterns() {
                l.push(Json::string(p));
            }
        }
        g.add("white_list", Json::Array(l));
    }
    if c.custom_alert_output != 0 {
        if let Some(f) = &c.custom_alert_output_format {
            g.add("custom_alert_output", Json::string(f));
        }
    }
    g.add("rotate_interval", num(c.rotate_interval));
    g.add("max_output_size", num(c.max_output_size as f64));
    let mut eps = Json::object();
    eps.add("maximum", num(c.eps.maximum));
    eps.add("timeframe", num(c.eps.timeframe));
    g.add("eps", eps);
    let mut root = Json::object();
    root.add("global", g);
    root
}

/// `getARManagerConfig`
pub fn active_response(cfg: &AnalysisdConfig) -> Json {
    let mut list = Vec::new();
    for a in &cfg.ar.responses {
        let mut j = Json::object();
        j.add("command", Json::string(&a.command));
        if let Some(v) = &a.agent_id {
            j.add("agent_id", Json::string(v));
        }
        if let Some(v) = &a.rules_id {
            j.add("rules_id", Json::string(v));
        }
        if let Some(v) = &a.rules_group {
            j.add("rules_group", Json::string(v));
        }
        j.add("timeout", num(a.timeout));
        j.add("level", num(a.level));
        let loc = if a.location & AS_ONLY != 0 {
            Some("AS_ONLY")
        } else if a.location & REMOTE_AGENT != 0 {
            Some("REMOTE_AGENT")
        } else if a.location & SPECIFIC_AGENT != 0 {
            Some("SPECIFIC_AGENT")
        } else if a.location & ALL_AGENTS != 0 {
            Some("ALL_AGENTS")
        } else {
            None
        };
        if let Some(l) = loc {
            j.add("location", Json::string(l));
        }
        list.push(j);
    }
    let mut root = Json::object();
    root.add("active-response", Json::Array(list));
    root
}

/// `getARCommandsConfig`
pub fn commands(cfg: &AnalysisdConfig) -> Json {
    let mut list = Vec::new();
    for c in &cfg.ar.commands {
        let mut j = Json::object();
        j.add("name", Json::string(&c.name));
        j.add("executable", Json::string(&c.executable));
        j.add("timeout_allowed", num(c.timeout_allowed as u8));
        list.push(j);
    }
    let mut root = Json::object();
    root.add("command", Json::Array(list));
    root
}

/// `getAlertsConfig`
pub fn alerts(cfg: &AnalysisdConfig) -> Json {
    let mut a = Json::object();
    a.add("email_alert_level", num(cfg.global.mailbylevel));
    a.add("log_alert_level", num(cfg.global.logbylevel));
    let mut root = Json::object();
    root.add("alerts", a);
    root
}

/// `getAnalysisInternalOptions`
pub fn internal(cfg: &AnalysisdConfig) -> Json {
    let i = &cfg.internal;
    let mut a = Json::object();
    a.add("debug", num(i.debug));
    a.add("default_timeframe", num(i.default_timeframe));
    a.add("stats_maxdiff", num(i.stats_maxdiff));
    a.add("stats_mindiff", num(i.stats_mindiff));
    a.add("stats_percent_diff", num(i.stats_percent_diff));
    a.add("fts_list_size", num(i.fts_list_size));
    a.add("fts_min_size_for_str", num(i.fts_min_size_for_str));
    a.add("log_fw", num(i.log_fw));
    a.add("decoder_order_size", num(i.decoder_order_size));
    a.add("label_cache_maxage", num(i.label_cache_maxage));
    a.add("show_hidden_labels", num(i.show_hidden_labels));
    a.add("rlimit_nofile", num(i.rlimit_nofile));
    a.add("min_rotate_interval", num(i.min_rotate_interval));
    let mut internals = Json::object();
    internals.add("analysisd", a);
    let mut root = Json::object();
    root.add("internal", internals);
    root
}

/// `getManagerLabelsConfig`
pub fn labels(cfg: &AnalysisdConfig) -> Json {
    let mut list = Vec::new();
    for l in &cfg.labels {
        let mut j = Json::object();
        j.add("value", Json::string(&l.value));
        j.add("key", Json::string(&l.key));
        j.add("hidden", Json::string(if l.flags.hidden { "yes" } else { "no" }));
        list.push(j);
    }
    let mut root = Json::object();
    root.add("labels", Json::Array(list));
    root
}

/// `getRuleTestConfig`
pub fn rule_test(cfg: &AnalysisdConfig) -> Json {
    let l = &cfg.logtest;
    let mut r = Json::object();
    r.add("enabled", yes_no(l.enabled));
    if l.threads != 0 {
        r.add("threads", num(l.threads));
    }
    if l.max_sessions != 0 {
        r.add("max_sessions", num(l.max_sessions));
    }
    if l.session_timeout != 0 {
        r.add("session_timeout", num(l.session_timeout as f64));
    }
    let mut root = Json::object();
    root.add("rule_test", r);
    root
}

/// `{"pattern", "type"}` of an expression (members whose value is NULL are
/// not added, like `cJSON_AddStringToObject(.., NULL)`).
fn expr(e: &Expression, negate: bool) -> Json {
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

/// `_getDecodersListJSON`
fn decoders_list(d: &Decoders, list: &[DNode], order_size: usize, out: &mut Vec<Json>) {
    for node in list {
        let dec = &d.infos[node.dec];
        let mut j = Json::object();
        j.add("id", num(dec.id));
        if let Some(v) = &dec.name {
            j.add("name", Json::string(v));
        }
        if let Some(v) = &dec.parent {
            j.add("parent", Json::string(v));
        }
        if let Some(v) = &dec.ftscomment {
            j.add("ftscomment", Json::string(v));
        }
        if order_size != 0 {
            if let Some(order) = &dec.order {
                let mut l = Vec::new();
                for i in 0..order_size {
                    let Some(Some(f)) = order.get(i) else { continue };
                    let name: Option<&str> = match f {
                        OrderFn::DstUser => Some("dstuser"),
                        OrderFn::SrcUser => Some("srcuser"),
                        OrderFn::SrcIp => Some("srcip"),
                        OrderFn::DstIp => Some("dstip"),
                        OrderFn::SrcPort => Some("srcport"),
                        OrderFn::DstPort => Some("dstport"),
                        OrderFn::Protocol => Some("protocol"),
                        OrderFn::Action => Some("action"),
                        OrderFn::Id => Some("id"),
                        OrderFn::Url => Some("url"),
                        OrderFn::Data => Some("data"),
                        OrderFn::ExtraData => Some("extra_data"),
                        OrderFn::Status => Some("status"),
                        OrderFn::SystemName => Some("system_name"),
                        OrderFn::Dynamic => dec.fields.as_ref().and_then(|f| f.get(i)).and_then(|f| f.as_deref()),
                    };
                    if let Some(n) = name {
                        l.push(Json::string(n));
                    }
                }
                j.add("order", Json::Array(l));
            }
        }
        if !node.children.is_empty() {
            let mut ch = Vec::new();
            decoders_list(d, &node.children, order_size, &mut ch);
            j.add("children", Json::Array(ch));
        }
        j.add("use_own_name", Json::string(if dec.use_own_name { "true" } else { "false" }));
        j.add("accumulate", Json::string(if dec.accumulate != 0 { "yes" } else { "no" }));
        if let Some(e) = &dec.prematch {
            j.add("prematch", expr(e, false));
        }
        if dec.prematch_offset & AFTER_PARENT != 0 {
            j.add("prematch_offset", Json::string("after_parent"));
        }
        if let Some(e) = &dec.regex {
            j.add("regex", expr(e, false));
        }
        if dec.regex_offset & AFTER_PARENT != 0 {
            j.add("regex_offset", Json::string("after_parent"));
        } else if dec.regex_offset & AFTER_PREVREGEX != 0 {
            j.add("regex_offset", Json::string("after_regex"));
        } else if dec.regex_offset & AFTER_PREMATCH != 0 {
            j.add("regex_offset", Json::string("after_prematch"));
        }
        if let Some(e) = &dec.program_name {
            j.add("program_name", expr(e, false));
        }
        if dec.fts != 0 {
            let f = dec.fts;
            let first: Option<Json> = if f & FTS_DSTUSER != 0 {
                Some(Json::string("dstuser"))
            } else if f & FTS_SRCUSER != 0 {
                Some(Json::string("srcuser"))
            } else if f & FTS_SRCIP != 0 {
                Some(Json::string("srcip"))
            } else if f & FTS_DSTIP != 0 {
                Some(Json::string("dstip"))
            } else if f & FTS_ID != 0 {
                Some(Json::string("id"))
            } else if f & FTS_LOCATION != 0 {
                Some(Json::string("location"))
            } else if f & FTS_DATA != 0 {
                Some(Json::string("data"))
            } else if f & FTS_SYSTEMNAME != 0 {
                Some(Json::string("system_name"))
            } else if f & FTS_NAME != 0 {
                Some(Json::string("name"))
            } else if f & FTS_DYNAMIC != 0 {
                // cJSON_CreateString(fts_fields): the 0/1 flags up to the first 0
                dec.fts_fields.as_ref().map(|ff| {
                    let s: Vec<u8> = ff.iter().take_while(|&&b| b).map(|_| 1u8).collect();
                    Json::String(s)
                })
            } else {
                None
            };
            j.add("fts", Json::Array(first.into_iter().collect()));
        }
        if dec.type_ != 0 {
            let t = match dec.type_ {
                FIREWALL => Some("firewall"),
                IDS => Some("ids"),
                WEBLOG => Some("web-log"),
                SYSLOG => Some("syslog"),
                SQUID => Some("squid"),
                DECODER_WINDOWS => Some("windows"),
                HOST_INFO => Some("host-information"),
                OSSEC_RL => Some("ossec"),
                _ => None,
            };
            if let Some(t) = t {
                j.add("type", Json::string(t));
            }
        }
        if let Some(p) = &dec.plugin {
            let n = match p {
                Plugin::Pf => "PF_Decoder",
                Plugin::SymantecWs => "SymantecWS_Decoder",
                Plugin::SonicWall => "SonicWall_Decoder",
                Plugin::OssecAlert => "OSSECAlert_Decoder",
                Plugin::Json => "JSON_Decoder",
            };
            j.add("plugin_decoder", Json::string(n));
        }
        out.push(j);
    }
}

/// `getDecodersConfig`
pub fn decoders(d: &Decoders, order_size: usize) -> Json {
    let mut list = Vec::new();
    if !d.pn.is_empty() {
        decoders_list(d, &d.pn, order_size, &mut list);
        decoders_list(d, &d.nopn, order_size, &mut list);
    }
    let mut root = Json::object();
    root.add("decoders", Json::Array(list));
    root
}

const SAME_FIELDS: [&str; 17] = [
    "srcip",
    "id",
    "dstip",
    "srcport",
    "dstport",
    "srcuser",
    "user",
    "protocol",
    "action",
    "url",
    "data",
    "extra_data",
    "status",
    "system_name",
    "srcgeoip",
    "dstgeoip",
    "location",
];

/// `_getRulesListJSON`
fn rules_list(r: &Rules, list: &[RNode], out: &mut Vec<Json>) {
    for node in list {
        let ri = &r.infos[node.rule];
        let mut j = Json::object();
        if !node.children.is_empty() {
            let mut ch = Vec::new();
            rules_list(r, &node.children, &mut ch);
            j.add("children", Json::Array(ch));
        }
        j.add("sigid", num(ri.sigid));
        j.add("level", num(ri.level));
        j.add("maxsize", num(ri.maxsize as f64));
        j.add("frequency", num(if ri.event_search.is_some() { ri.frequency + 2 } else { ri.frequency }));
        j.add("timeframe", num(ri.timeframe));
        j.add("ignore_time", num(ri.ignore_time));
        j.add("decoded_as", num(ri.decoded_as));
        j.add("if_matched_sid", num(ri.if_matched_sid));
        if let Some(g) = &ri.group {
            j.add("group", Json::string(g));
        }
        if let Some(e) = &ri.regex {
            j.add("regex", expr(e, true));
        }
        if let Some(e) = &ri.match_ {
            // match->match->raw (the union member at the same offset)
            let mut m = Json::object();
            if let Some(p) = e.pattern() {
                m.add("pattern", Json::string(p));
            }
            m.add("negate", Json::bool(e.negate));
            j.add("match", m);
        }
        for (name, e) in [
            ("srcgeoip", &ri.srcgeoip),
            ("dstgeoip", &ri.dstgeoip),
            ("srcport", &ri.srcport),
            ("dstport", &ri.dstport),
            ("user", &ri.user),
            ("url", &ri.url),
            ("id", &ri.id),
            ("system_name", &ri.system_name),
            ("protocol", &ri.protocol),
            ("data", &ri.data),
            ("status", &ri.status),
            ("hostname", &ri.hostname),
            ("program_name", &ri.program_name),
            ("extra_data", &ri.extra_data),
            ("location", &ri.location),
            ("action", &ri.action),
        ] {
            if let Some(e) = e {
                j.add(name, expr(e, true));
            }
        }
        for (name, v) in [("comment", &ri.comment), ("info", &ri.info), ("cve", &ri.cve), ("if_sid", &ri.if_sid)] {
            if let Some(v) = v {
                j.add(name, Json::string(v));
            }
        }
        if ri.if_level.is_some() {
            if let Some(g) = &ri.if_group {
                j.add("if_group", Json::string(g));
            }
        }
        if let Some(g) = &ri.if_group {
            j.add("if_group", Json::string(g));
        }
        if let Some(m) = &ri.if_matched_regex {
            j.add("if_matched_regex", Json::string(m.raw()));
        }
        if let Some(m) = &ri.if_matched_group {
            j.add("if_matched_group", Json::string(m.raw()));
        }
        if let Some(f) = &ri.file {
            j.add("rule_file", Json::string(f));
        }
        let cat = match ri.category {
            FIREWALL => Some("firewall"),
            IDS => Some("ids"),
            SYSLOG => Some("syslog"),
            WEBLOG => Some("web-log"),
            SQUID => Some("squid"),
            DECODER_WINDOWS => Some("windows"),
            OSSEC_RL => Some("ossec"),
            _ => None,
        };
        if let Some(c) = cat {
            j.add("category", Json::string(c));
        }
        if !ri.fields.is_empty() {
            let mut l = Vec::new();
            for f in &ri.fields {
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
                l.push(fj);
            }
            j.add("field", Json::Array(l));
        }
        for (name, e) in [("srcip", &ri.srcip), ("dstip", &ri.dstip)] {
            if let Some(e) = e {
                if let siem_regex::ExpressionKind::OsIpArray(ips) = &e.kind {
                    if !ips.is_empty() {
                        let mut l = Vec::new();
                        for ip in ips {
                            let mut ij = Json::object();
                            ij.add("ip", Json::string(&ip.ip));
                            ij.add("negate", Json::bool(e.negate));
                            l.push(ij);
                        }
                        j.add(name, Json::Array(l));
                    }
                }
            }
        }
        for (kind, mut bits, dynamics) in [
            ("same", ri.same_field, &ri.same_fields),
            ("different", ri.different_field, &ri.not_same_fields),
        ] {
            if bits == 0 {
                continue;
            }
            if bits & FIELD_DYNAMICS == FIELD_DYNAMICS {
                let l = dynamics.iter().flatten().map(Json::string).collect();
                j.add(format!("{kind}_field"), Json::Array(l));
                bits &= !FIELD_DYNAMICS;
            }
            let mut i = 0;
            while i < SAME_FIELDS.len() && bits != 0 {
                if bits & 1 == 1 {
                    j.add(format!("{kind}_{}", SAME_FIELDS[i]), Json::string(""));
                }
                bits >>= 1;
                i += 1;
            }
        }
        out.push(j);
    }
}

/// `getRulesConfig`
pub fn rules(r: &Rules) -> Json {
    let mut list = Vec::new();
    rules_list(r, &r.tree, &mut list);
    let mut root = Json::object();
    root.add("rules", Json::Array(list));
    root
}
