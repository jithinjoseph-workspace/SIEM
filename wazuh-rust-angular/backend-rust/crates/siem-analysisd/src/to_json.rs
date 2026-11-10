//! Alert JSON: `Eventinfo_to_jsonstr` (format/to_json.c) and `W_ParseJSON`
//! (format/json_extended.c).

use std::sync::OnceLock;

use siem_cjson::Json;

use crate::engine::Engine;
use crate::event::*;
use crate::labels::labels_get;
use crate::logmsg::LogList;
use crate::rules::*;

const MAX_STRING: usize = 1024;
const MAX_MATCHES: usize = 10;
const MAX_STRING_LESS: usize = 30;

fn s(b: &[u8]) -> Json {
    Json::String(b.to_vec())
}

/// `W_JSON_AddField`: add `key` (dots create nested objects) unless present.
pub fn w_json_add_field(root: &mut Json, key: &[u8], value: &[u8]) {
    if let Some(dot) = key.iter().position(|&c| c == b'.') {
        let cur = &key[..dot];
        if root.get_bytes(cur).is_some() {
            if let Some(obj) = root.get_mut_bytes(cur) {
                if obj.is_object() {
                    w_json_add_field(obj, &key[dot + 1..], value);
                }
            }
        } else {
            let mut obj = Json::object();
            w_json_add_field(&mut obj, &key[dot + 1..], value);
            root.add(cur, obj);
        }
    } else if root.get_bytes(key).is_none() {
        if value.first() == Some(&b'[') {
            if let Ok((j, end)) = siem_cjson::parse_with_opts(value, false) {
                if end == value.len() {
                    root.add(key, j);
                    return;
                }
            }
        }
        root.add(key, s(value));
    }
}

fn local_time(sec: i64) -> chrono::DateTime<chrono::FixedOffset> {
    crate::localtime::at(sec)
}

/// `W_JSON_AddTimestamp`
fn add_timestamp(root: &mut Json, ev: &Event) {
    if ev.time.sec != 0 {
        let t = local_time(ev.time.sec);
        let ts = format!("{}.{:03}{}", t.format("%Y-%m-%dT%H:%M:%S"), ev.time.nsec / 1_000_000, t.format("%z"));
        root.add("timestamp", Json::string(ts));
    }
}

/// `Eventinfo_to_jsonstr`
pub fn eventinfo_to_json(eng: &Engine, ev: &Event, force_full_log: bool, log: &mut LogList) -> Vec<u8> {
    let rule = ev.generated_rule.map(|r| &eng.rules.infos[r]);
    let dec = &eng.decoders.infos[ev.decoder];
    let mut root = Json::object();

    add_timestamp(&mut root, ev);

    let mut rule_j = rule.map(|_| Json::object());
    let mut agent = Json::object();
    let mut manager = Json::object();
    let mut data = Json::object();
    // Keys are inserted in C order; the objects are filled and placed at the end.
    let mut order: Vec<&'static str> = Vec::new();
    if rule.is_some() {
        order.push("rule");
    }
    order.push("agent");
    order.push("manager");

    let mut tail: Vec<(Vec<u8>, Json)> = Vec::new();
    if ev.time.sec != 0 {
        let id = format!("{}.{}", ev.time.sec, eng.alert_second_id);
        tail.push((b"id".to_vec(), Json::string(id)));
    }
    if !eng.cfg.hide_cluster_info {
        let mut cluster = Json::object();
        cluster.add("name", Json::string(eng.cfg.cluster_name.clone().unwrap_or_else(|| "wazuh".into())));
        if let Some(n) = &eng.cfg.node_name {
            cluster.add("node", Json::string(n));
        }
        tail.push((b"cluster".to_vec(), cluster));
    }
    manager.add("name", s(&eng.cfg.manager_name));

    if let (Some(r), Some(rj)) = (rule, rule_j.as_mut()) {
        if r.level != 0 {
            rj.add("level", Json::number(r.level as f64));
        }
        if let Some(c) = &ev.comment {
            rj.add("description", s(c));
        }
        if r.sigid != 0 {
            rj.add("id", Json::string(r.sigid.to_string()));
        }
        add_mitre(eng, r, rj, log);
        if let Some(c) = &r.cve {
            rj.add("cve", Json::string(c));
        }
        if let Some(i) = &r.info {
            rj.add("info", Json::string(i));
        }
        if r.event_search.is_some() {
            rj.add("frequency", Json::number((r.frequency + 2) as f64));
        }
        if ev.r_firedtimes != -1 && r.alert_opts & NO_COUNTER == 0 {
            rj.add("firedtimes", Json::number(ev.r_firedtimes as f64));
        }
        rj.add("mail", Json::bool(r.alert_opts & DO_MAILALERT != 0));
        if let Some(le) = &ev.last_events {
            if le.len() >= 2 && !le[1].is_empty() {
                tail.push((b"previous_output".to_vec(), s(&le.join(&b'\n'))));
            }
        }
    }

    for (key, idx) in [
        ("protocol", F_PROTOCOL),
        ("action", F_ACTION),
        ("srcip", F_SRCIP),
    ] {
        if let Some(v) = &ev.f[idx] {
            data.add(key, s(v));
        }
    }
    if crate::GEOIP_ENABLED {
        if let Some(v) = &ev.f[F_SRCGEOIP] {
            tail.push((b"srcgeoip".to_vec(), s(v)));
        }
    }
    for (key, idx) in [("srcport", F_SRCPORT), ("srcuser", F_SRCUSER), ("dstip", F_DSTIP)] {
        if let Some(v) = &ev.f[idx] {
            data.add(key, s(v));
        }
    }
    if crate::GEOIP_ENABLED {
        if let Some(v) = &ev.f[F_DSTGEOIP] {
            tail.push((b"dstgeoip".to_vec(), s(v)));
        }
    }
    for (key, idx) in [("dstport", F_DSTPORT), ("dstuser", F_DSTUSER)] {
        if let Some(v) = &ev.f[idx] {
            data.add(key, s(v));
        }
    }
    let full_log = ev.full_log();
    if !ev.buf.is_empty() && (force_full_log || !rule.map_or(false, |r| r.alert_opts & NO_FULL_LOG != 0)) {
        tail.push((b"full_log".to_vec(), s(full_log)));
    }
    if let Some(a) = &ev.agent_id {
        agent.add("id", s(a));
    }

    // The syscheck section (decoder names starting with "syscheck_") is
    // produced by the FIM decoder port (crate::syscheck).
    let is_syscheck = dec.name.as_deref().map_or(false, |n| n.starts_with("syscheck_"));
    if is_syscheck {
        if let Some(sc) = crate::syscheck_json::syscheck_section(ev, eng.cfg.rule.decoder_order_size, log) {
            tail.push((b"syscheck".to_vec(), sc));
        }
    }

    if ev.program_name.is_some() || ev.dec_timestamp.is_some() {
        let mut pre = Json::object();
        if let Some(p) = &ev.program_name {
            pre.add("program_name", s(p));
        }
        if let Some(t) = &ev.dec_timestamp {
            pre.add("timestamp", s(t));
        }
        tail.push((b"predecoder".to_vec(), pre));
    }

    for (key, idx) in [
        ("id", F_ID),
        ("status", F_STATUS),
        ("url", F_URL),
        ("data", F_DATA),
        ("extra_data", F_EXTRA_DATA),
        ("system_name", F_SYSTEMNAME),
    ] {
        if let Some(v) = &ev.f[idx] {
            data.add(key, s(v));
        }
    }

    if is_syscheck {
        if let Some(audit) = crate::syscheck_json::audit_section(ev) {
            if let Some((_, sc)) = tail.iter_mut().find(|(k, _)| k == b"syscheck") {
                sc.add("audit", audit);
            }
        }
    }

    // DecoderInfo
    if dec.name.is_some() && !is_syscheck {
        for f in &ev.fields {
            if let Some(v) = &f.value {
                if !v.is_empty() {
                    w_json_add_field(&mut data, &f.key, v);
                }
            }
        }
    }
    let mut decoder = Json::object();
    if dec.accumulate != 0 {
        decoder.add("accumulate", Json::number(dec.accumulate as f64));
    }
    if let Some(p) = &dec.parent {
        decoder.add("parent", Json::string(p));
    }
    if let Some(n) = &dec.name {
        decoder.add("name", Json::string(n));
    }
    if let Some(f) = &dec.ftscomment {
        decoder.add("ftscomment", Json::string(f));
    }
    tail.push((b"decoder".to_vec(), decoder));

    if let Some(p) = &ev.previous {
        tail.push((b"previous_log".to_vec(), s(p)));
    }

    // Assemble root in C insertion order.
    for k in order {
        match k {
            "rule" => {
                root.add("rule", rule_j.take().unwrap());
            }
            "agent" => {
                root.add("agent", std::mem::replace(&mut agent, Json::Null));
            }
            "manager" => {
                root.add("manager", std::mem::replace(&mut manager, Json::Null));
            }
            _ => {}
        }
    }
    for (k, v) in tail {
        root.add(k, v);
    }
    if !data.is_empty() {
        root.add("data", data);
    }

    w_parse_json(eng, &mut root, ev);
    root.print_unformatted()
}

/// MITRE section of the rule object.
fn add_mitre(eng: &Engine, r: &RuleInfo, rj: &mut Json, log: &mut LogList) {
    let empty = crate::mitre::MitreDb::default();
    let db: &crate::mitre::MitreDb = eng.mitre.as_deref().unwrap_or(&empty);
    if let (Some(techs), Some(tacs)) = (&r.mitre_technique_id, &r.mitre_tactic_id) {
        let mut ids: Vec<Json> = Vec::new();
        let mut tactic_arr: Vec<Vec<u8>> = Vec::new();
        let mut tech_arr: Vec<Vec<u8>> = Vec::new();
        for (i, tid) in techs.iter().enumerate() {
            let Some(t) = db.get_attack(tid) else {
                log.warn(format!("Mitre Technique ID '{tid}' not found in database."));
                continue;
            };
            let want = tacs.get(i).cloned().unwrap_or_default();
            let mut tactic_exist = false;
            for ta in &t.tactics {
                if ta.tactic_id == want {
                    tactic_exist = true;
                    if !tactic_arr.iter().any(|x| x == ta.tactic_name.as_bytes()) {
                        tactic_arr.push(ta.tactic_name.as_bytes().to_vec());
                        break;
                    }
                }
            }
            if tactic_exist {
                if !tech_arr.iter().any(|x| x == t.technique_name.as_bytes()) {
                    ids.push(Json::string(&t.technique_id));
                    tech_arr.push(t.technique_name.as_bytes().to_vec());
                }
            } else {
                log.warn(format!("Mitre Tactic ID '{want}' is not a tactic of '{tid}'."));
            }
        }
        if !tactic_arr.is_empty() {
            let mut m = Json::object();
            m.add("id", Json::Array(ids));
            m.add("tactic", Json::Array(tactic_arr.into_iter().map(Json::String).collect()));
            m.add("technique", Json::Array(tech_arr.into_iter().map(Json::String).collect()));
            rj.add("mitre", m);
        }
    } else if let Some(mids) = &r.mitre_id {
        let mut tactic_arr: Vec<Vec<u8>> = Vec::new();
        let mut tech_arr: Vec<Json> = Vec::new();
        for mid in mids {
            match db.get_attack(mid) {
                None => log.warn(format!("Mitre Technique ID '{mid}' not found in database.")),
                Some(t) => {
                    for ta in &t.tactics {
                        if !tactic_arr.iter().any(|x| x == ta.tactic_name.as_bytes()) {
                            tactic_arr.push(ta.tactic_name.as_bytes().to_vec());
                        }
                    }
                    tech_arr.push(Json::string(&t.technique_name));
                }
            }
        }
        if !tactic_arr.is_empty() {
            let mut m = Json::object();
            m.add("id", Json::Array(mids.iter().map(Json::string).collect()));
            m.add("tactic", Json::Array(tactic_arr.into_iter().map(Json::String).collect()));
            m.add("technique", Json::Array(tech_arr));
            rj.add("mitre", m);
        }
    }
}

/// `W_ParseJSON`
pub fn w_parse_json(eng: &Engine, root: &mut Json, ev: &Event) {
    if !ev.buf.is_empty() && ev.hostname.is_some() {
        parse_hostname(root, ev);
        parse_agent_ip(root, ev);
    }
    if ev.f[F_LOCATION].is_some() {
        parse_location(root, ev, false);
        parse_agentless(root, ev);
    }
    if let Some(r) = ev.generated_rule.map(|r| &eng.rules.infos[r]) {
        if let Some(g) = &r.group {
            parse_groups(root, g.as_bytes());
        }
    }
    if !ev.buf.is_empty() && is_rootcheck(root) {
        parse_rootcheck(root, ev);
    }
    if ev.labels.iter().any(|l| !l.flags.system) {
        let mut labels = Json::object();
        for l in &ev.labels {
            if !l.flags.system && (!l.flags.hidden || eng.cfg.show_hidden_labels) {
                w_json_add_field(&mut labels, &l.key, &l.value);
            }
        }
        if let Some(agent) = root.get_mut("agent") {
            agent.add("labels", labels);
        }
    }
}

fn hostname_regex() -> &'static regex::bytes::Regex {
    static R: OnceLock<regex::bytes::Regex> = OnceLock::new();
    R.get_or_init(|| {
        regex::bytes::Regex::new(r"(?-u)^[A-Z][a-z][a-z] [ 0123][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] ([^ ]+)").unwrap()
    })
}

/// `W_JSON_ParseHostname`
fn parse_hostname(root: &mut Json, ev: &Event) {
    let loc = ev.f[F_LOCATION].as_deref().unwrap_or(b"");
    if loc.first() == Some(&b'(') {
        if let Some(agent) = root.get_mut("agent") {
            agent.add("name", s(ev.hostname.as_deref().unwrap_or(b"")));
        }
    } else if ev.agent_id.as_deref() == Some(b"000") {
        let name = root.get("manager").and_then(|m| m.get("name")).cloned();
        if let (Some(n), Some(agent)) = (name, root.get_mut("agent")) {
            agent.add("name", n);
        }
    }
    if let Some(c) = hostname_regex().captures(ev.full_log()) {
        let h = c.get(1).unwrap().as_bytes().to_vec();
        if root.get("predecoder").is_none() {
            root.add("predecoder", Json::object());
        }
        if let Some(p) = root.get_mut("predecoder") {
            p.add("hostname", Json::String(h));
        }
    }
}

/// `W_JSON_ParseAgentIP`
fn parse_agent_ip(root: &mut Json, ev: &Event) {
    let mut ip: Option<Vec<u8>> = labels_get(&ev.labels, b"_agent_ip").map(|v| v.to_vec());
    if ip.is_none() {
        let loc = ev.f[F_LOCATION].as_deref().unwrap_or(b"");
        if loc.first() == Some(&b'(') {
            if let Some(p) = loc.iter().position(|&c| c == b')') {
                let start = (p + 2).min(loc.len());
                let mut v = loc[start..].to_vec();
                if let Some(d) = v.iter().position(|&c| c == b'-') {
                    v.truncate(d);
                }
                ip = Some(v);
            }
        }
    }
    if let Some(ip) = ip {
        if ip != b"any" {
            if let Some(agent) = root.get_mut("agent") {
                agent.add("ip", Json::String(ip));
            }
        }
    }
}

/// `W_JSON_ParseLocation`
pub fn parse_location(root: &mut Json, ev: &Event, archives: bool) {
    let key = if archives { "location_desc" } else { "location" };
    let loc = ev.f[F_LOCATION].as_deref().unwrap_or(b"");
    if loc.first() == Some(&b'(') {
        let string = &loc[..loc.len().min(MAX_STRING - 1)];
        if let Some(p) = string.iter().position(|&c| c == b'>') {
            root.add(key, s(&string[p + 1..]));
        }
    } else {
        root.add(key, s(loc));
    }
}

/// `W_JSON_ParseAgentless`
fn parse_agentless(root: &mut Json, ev: &Event) {
    let loc = ev.f[F_LOCATION].as_deref().unwrap_or(b"");
    if loc.first() == Some(&b'(') && ev.agent_id.as_deref() == Some(b"000") {
        let script_all = &loc[1..];
        let Some(u) = find_sub(script_all, b") ") else {
            return;
        };
        let script = &script_all[..u];
        let user_all = &script_all[u + 2..];
        let Some(h) = user_all.iter().position(|&c| c == b'@') else {
            return;
        };
        let user = &user_all[..h];
        let host_all = &user_all[h + 1..];
        let Some(e) = find_sub(host_all, b"->") else {
            return;
        };
        let host = &host_all[..e];
        let mut al = Json::object();
        al.add("script", s(script));
        al.add("user", s(user));
        al.add("host", s(host));
        root.add("agentless", al);
        root.remove("agent");
    }
}

fn starts_with(pre: &[u8], s: &[u8]) -> bool {
    s.len() >= pre.len() && &s[..pre.len()] == pre
}

/// C `isspace` in the C locale.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `trim` (json_extended.c)
fn trim(v: &[u8]) -> Vec<u8> {
    let mut a = 0;
    let mut b = v.len();
    while b > 0 && is_space(v[b - 1]) {
        b -= 1;
    }
    while a < b && is_space(v[a]) {
        a += 1;
    }
    v[a..b].to_vec()
}

/// `W_JSON_ParseGroups`
fn parse_groups(root: &mut Json, group: &[u8]) {
    let Some(rule) = root.get_mut("rule") else {
        return;
    };
    let mut groups: Vec<Json> = Vec::new();
    let buffer = &group[..group.len().min(MAX_STRING - 1)];
    // groups first so that it precedes the compliance arrays
    rule.add("groups", Json::array());
    const PREFIXES: [(&[u8], &str); 7] = [
        (b"pci_dss_", "pci_dss"),
        (b"cis_", "cis"),
        (b"gdpr_", "gdpr"),
        (b"gpg13_", "gpg13"),
        (b"hipaa_", "hipaa"),
        (b"nist_800_53_", "nist_800_53"),
        (b"tsc_", "tsc"),
    ];
    let mut first = [true; 7];
    for tok in buffer.split(|&c| c == b',').filter(|t| !t.is_empty()) {
        let mut done = false;
        for (i, (pre, key)) in PREFIXES.iter().enumerate() {
            if starts_with(pre, tok) {
                let v = Json::String(tok[pre.len()..].to_vec());
                if first[i] {
                    rule.add(*key, Json::Array(vec![v]));
                    first[i] = false;
                } else if let Some(arr) = rule.get_mut(key) {
                    arr.push(v);
                }
                done = true;
                break;
            }
        }
        if !done {
            groups.push(Json::String(tok.to_vec()));
        }
    }
    if let Some(g) = rule.get_mut("groups") {
        *g = Json::Array(groups);
    }

    // Add SCA compliance groups
    let compliance: Option<Vec<(Vec<u8>, Option<Vec<u8>>)>> = root
        .get("data")
        .and_then(|d| d.get("sca"))
        .and_then(|sca| sca.get("check"))
        .and_then(|c| c.get("compliance"))
        .map(|c| match c {
            Json::Object(m) => m.iter().map(|(k, v)| (k.clone(), v.as_bytes().map(|b| b.to_vec()))).collect(),
            Json::Array(a) => a.iter().map(|v| (Vec::new(), v.as_bytes().map(|b| b.to_vec()))).collect(),
            _ => Vec::new(),
        });
    if let Some(list) = compliance {
        if let Some(rule) = root.get_mut("rule") {
            for (k, v) in list {
                add_sca_groups(rule, &k, v.as_deref());
            }
        }
    }
}

/// `add_SCA_groups`
fn add_sca_groups(rule: &mut Json, compliance: &[u8], value: Option<&[u8]>) {
    let Some(value) = value else {
        return;
    };

    let items: Vec<Json> =
        value.split(|&c| c == b',').filter(|t| !t.is_empty()).map(trim).filter(|t| !t.is_empty()).map(Json::String).collect();
    if let Some(g) = rule.get_mut_bytes(compliance) {
        for i in items {
            g.push(i);
        }
    } else if !items.is_empty() {
        rule.add(compliance, Json::Array(items));
    }
}

/// `W_isRootcheck`
fn is_rootcheck(root: &Json) -> bool {
    root.get("rule")
        .and_then(|r| r.get("groups"))
        .map_or(false, |g| g.children().iter().any(|x| x.print() == b"\"rootcheck\""))
}

fn rootcheck_regex() -> &'static regex::bytes::Regex {
    static R: OnceLock<regex::bytes::Regex> = OnceLock::new();
    R.get_or_init(|| regex::bytes::Regex::new(r"(?-u)\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\}").unwrap())
}

/// `W_JSON_ParseRootcheck`
fn parse_rootcheck(root: &mut Json, ev: &Event) {
    let full = ev.full_log();
    let fullog = &full[..full.len().min(MAX_STRING - 1)];
    // match_regex: REG_NEWLINE, one result per capture group, max 10
    let mut results: Vec<Vec<u8>> = Vec::new();
    let mut p = 0;
    let re = rootcheck_regex();
    'outer: while results.len() < MAX_MATCHES {
        let hay = &fullog[p..];
        // REG_NEWLINE: '.' and [^...] do not cross lines; the class here has no '\n'.
        let Some(c) = re.captures(hay) else {
            break;
        };
        for i in 1..c.len() {
            let Some(g) = c.get(i) else {
                break;
            };
            let mut t = g.as_bytes().to_vec();
            t.truncate(MAX_STRING_LESS - 1);
            results.push(t);
            if results.len() >= MAX_MATCHES {
                break 'outer;
            }
        }
        let end = c.get(0).unwrap().end();
        if end == 0 {
            break;
        }
        p += end;
    }
    let Some(rule) = root.get_mut("rule") else {
        return;
    };
    for r in results {
        let mut parts = r.split(|&c| c == b':').filter(|t| !t.is_empty());
        let Some(tok) = parts.next() else {
            continue;
        };
        let name: Vec<u8> = trim(tok).iter().map(|c| c.to_ascii_lowercase()).collect();
        let mut arr: Vec<Json> = Vec::new();
        if let Some(rest) = parts.next() {
            let rest = trim(rest);
            for t2 in rest.split(|&c| c == b',').filter(|t| !t.is_empty()) {
                arr.push(Json::String(trim(t2)));
            }
        }
        rule.add(name, Json::Array(arr));
    }
}
