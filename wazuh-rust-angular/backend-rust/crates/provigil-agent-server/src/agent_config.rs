//! Central configuration for the ProVigil agent: the `agent.conf` of each of the agent's groups
//! (the console's Groups page) turned into the agent's own JSON settings. Blocks meant for
//! another OS or another agent name are skipped; later groups extend earlier ones.
//!
//! `GET /api/v1/agents/:id/config` (the agent's own key): `{"version": <sha>, "config": {...}}`.
//! The agent polls it and applies what changed.

use quick_xml::events::Event;
use quick_xml::Reader;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use std::path::Path;

/// One element: name, attributes, text, children.
#[derive(Debug, Default, Clone)]
struct El {
    name: String,
    attrs: Vec<(String, String)>,
    text: String,
    kids: Vec<El>,
}

impl El {
    fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
    fn kid(&self, k: &str) -> Option<&El> {
        self.kids.iter().find(|e| e.name.eq_ignore_ascii_case(k))
    }
    fn kid_text(&self, k: &str) -> Option<String> {
        self.kid(k).map(|e| e.text.trim().to_string()).filter(|t| !t.is_empty())
    }
    fn all<'a>(&'a self, k: &'a str) -> impl Iterator<Item = &'a El> {
        self.kids.iter().filter(move |e| e.name.eq_ignore_ascii_case(k))
    }
}

/// The top-level elements of an agent.conf (it has several `<agent_config>` roots).
fn parse(xml: &str) -> Vec<El> {
    let mut r = Reader::from_str(xml);
    r.config_mut().trim_text(false);
    let mut stack: Vec<El> = Vec::new();
    let mut roots = Vec::new();
    let open = |e: &quick_xml::events::BytesStart| El {
        name: String::from_utf8_lossy(e.name().as_ref()).into_owned(),
        attrs: e.attributes().flatten().map(|a| (String::from_utf8_lossy(a.key.as_ref()).into_owned(), a.unescape_value().map(|v| v.into_owned()).unwrap_or_default())).collect(),
        ..Default::default()
    };
    loop {
        match r.read_event() {
            Ok(Event::Start(e)) => stack.push(open(&e)),
            Ok(Event::Empty(e)) => {
                let el = open(&e);
                match stack.last_mut() {
                    Some(p) => p.kids.push(el),
                    None => roots.push(el),
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(p) = stack.last_mut() {
                    p.text.push_str(&t.unescape().map(|s| s.into_owned()).unwrap_or_default());
                }
            }
            Ok(Event::CData(t)) => {
                if let Some(p) = stack.last_mut() {
                    p.text.push_str(&String::from_utf8_lossy(&t));
                }
            }
            Ok(Event::End(_)) => {
                if let Some(el) = stack.pop() {
                    match stack.last_mut() {
                        Some(p) => p.kids.push(el),
                        None => roots.push(el),
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    roots
}

fn yes(v: Option<&str>) -> Option<bool> {
    match v.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("yes") | Some("true") => Some(true),
        Some("no") | Some("false") => Some(false),
        _ => None,
    }
}

/// `30s`, `5m`, `2h`, `1d`, `1w` or plain seconds.
fn seconds(v: &str) -> Option<u64> {
    let v = v.trim();
    let (n, mult) = match v.chars().last()? {
        's' => (&v[..v.len() - 1], 1),
        'm' => (&v[..v.len() - 1], 60),
        'h' => (&v[..v.len() - 1], 3600),
        'd' => (&v[..v.len() - 1], 86400),
        'w' => (&v[..v.len() - 1], 604800),
        _ => (v, 1),
    };
    n.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// `1024`, `500B`, `64KB`, `10MB`, `1GB` (or `k`, `m`, `g`) in bytes.
fn bytes(v: &str) -> Option<u64> {
    let v = v.trim().to_ascii_lowercase();
    let v = v.strip_suffix('b').unwrap_or(&v);
    let (n, mult) = match v.chars().last()? {
        'k' => (&v[..v.len() - 1], 1 << 10),
        'm' => (&v[..v.len() - 1], 1 << 20),
        'g' => (&v[..v.len() - 1], 1 << 30),
        _ => (v, 1),
    };
    n.trim().parse::<u64>().ok()?.checked_mul(mult)
}

/// Whether a block applies to this agent: `os` contains "windows", `name` is its name.
fn applies(block: &El, agent_name: &str) -> bool {
    if let Some(os) = block.attr("os") {
        if !os.split('|').any(|o| o.trim().to_ascii_lowercase().contains("windows")) {
            return false;
        }
    }
    if let Some(n) = block.attr("name") {
        if !n.split('|').any(|x| x.trim().eq_ignore_ascii_case(agent_name)) {
            return false;
        }
    }
    true
}

fn push(cfg: &mut Map<String, Value>, k: &str, v: Value) {
    match cfg.entry(k).or_insert_with(|| json!([])) {
        Value::Array(a) => {
            if !a.contains(&v) {
                a.push(v)
            }
        }
        x => *x = json!([v]),
    }
}

/// Sets `k` in the object setting `obj` (other keys kept).
fn set(cfg: &mut Map<String, Value>, obj: &str, k: &str, v: Value) {
    if let Value::Object(o) = cfg.entry(obj).or_insert_with(|| json!({})) {
        o.insert(k.into(), v);
    }
}

/// The agent's settings from the agent.conf texts of its groups (in group order).
pub fn translate(confs: &[String], agent_name: &str) -> Value {
    let mut cfg = Map::new();
    let mut queries = Map::new();
    for text in confs {
        for block in parse(text).iter().filter(|b| b.name == "agent_config" && applies(b, agent_name)) {
            for lf in block.all("localfile") {
                let fmt = lf.kid_text("log_format").unwrap_or_else(|| "syslog".into());
                if fmt == "eventchannel" || fmt == "eventlog" {
                    if let Some(loc) = lf.kid_text("location") {
                        push(&mut cfg, "event_channels", json!(loc));
                        if let Some(q) = lf.kid_text("query") {
                            queries.insert(loc, json!(q));
                        }
                    }
                    continue;
                }
                let mut o = Map::new();
                o.insert("log_format".into(), json!(fmt));
                for k in ["location", "alias", "age", "exclude"] {
                    if let Some(v) = lf.kid_text(k) {
                        o.insert(k.into(), json!(v));
                    }
                }
                if let Some(f) = lf.kid_text("frequency").and_then(|v| seconds(&v)) {
                    o.insert("frequency".into(), json!(f));
                }
                if let Some(b) = yes(lf.kid_text("only-future-events").as_deref()) {
                    o.insert("only_future_events".into(), json!(b));
                }
                if let Some(b) = yes(lf.kid_text("ignore_binaries").as_deref()) {
                    o.insert("ignore_binaries".into(), json!(b));
                }
                for (k, out) in [("ignore", "ignore"), ("restrict", "restrict")] {
                    let v: Vec<String> = lf.all(k).map(|e| e.text.trim().to_string()).filter(|t| !t.is_empty()).collect();
                    if !v.is_empty() {
                        o.insert(out.into(), json!(v));
                    }
                }
                if let Some(m) = lf.kid("multiline_regex") {
                    o.insert(
                        "multiline_regex".into(),
                        json!({ "regex": m.text.trim(), "match": m.attr("match").unwrap_or("start"), "replace": m.attr("replace").unwrap_or("no-replace"), "timeout": m.attr("timeout").and_then(|t| t.parse::<u64>().ok()).unwrap_or(5) }),
                    );
                }
                // like the old agents: the agent runs a group's commands only when its own local
                // settings allow remote commands (`allow_remote_commands`, off by default)
                if let Some(c) = lf.kid_text("command") {
                    o.insert("command".into(), json!(c));
                }
                let labels: Map<String, Value> = lf.all("label").filter_map(|l| Some((l.attr("key")?.to_string(), json!(l.text.trim())))).collect();
                if !labels.is_empty() {
                    o.insert("labels".into(), Value::Object(labels));
                }
                if let Some(n) = lf.kid_text("max-size").and_then(|v| bytes(&v)) {
                    o.insert("max_size".into(), json!(n));
                }
                if o.contains_key("location") || o.contains_key("command") {
                    push(&mut cfg, "localfiles", Value::Object(o));
                }
            }
            for sc in block.all("syscheck") {
                if let Some(b) = yes(sc.kid_text("disabled").as_deref()) {
                    cfg.insert("fim_enabled".into(), json!(!b));
                }
                if let Some(f) = sc.kid_text("frequency").and_then(|v| seconds(&v)) {
                    cfg.insert("fim_scan_interval_secs".into(), json!(f));
                }
                for d in sc.all("directories") {
                    for p in d.text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                        push(&mut cfg, "fim_paths", json!(p));
                        if yes(d.attr("report_changes")) == Some(true) {
                            push(&mut cfg, "fim_report_changes", json!(p));
                        }
                        if yes(d.attr("whodata")) == Some(true) {
                            push(&mut cfg, "fim_whodata", json!(p));
                        } else if yes(d.attr("realtime")) == Some(true) {
                            push(&mut cfg, "fim_realtime", json!(p));
                        }
                    }
                    // the agent has one recursion limit: the deepest asked for
                    if let Some(r) = d.attr("recursion_level").and_then(|r| r.trim().parse::<u64>().ok()) {
                        let deepest = cfg.get("fim_recursion_level").and_then(Value::as_u64).map_or(r, |c| c.max(r));
                        cfg.insert("fim_recursion_level".into(), json!(deepest));
                    }
                }
                for i in sc.all("ignore") {
                    let t = i.text.trim();
                    push(&mut cfg, "fim_ignore", json!(if i.attr("type") == Some("sregex") { format!("regex:{t}") } else { t.to_string() }));
                }
                for n in sc.all("nodiff") {
                    push(&mut cfg, "fim_nodiff", json!(n.text.trim()));
                }
                for r in sc.all("windows_registry") {
                    let key = r.text.trim();
                    if !key.is_empty() {
                        for (a, out) in [("restrict_key", "registry_restrict_key"), ("restrict_value", "registry_restrict_value")] {
                            if let Some(v) = r.attr(a).filter(|v| !v.is_empty()) {
                                push(&mut cfg, out, json!(v));
                            }
                        }
                        if yes(r.attr("report_changes")) == Some(true) {
                            push(&mut cfg, "registry_report_changes", json!(key));
                        }
                        let arch = r.attr("arch").unwrap_or("").to_ascii_lowercase();
                        if arch != "32bit" {
                            push(&mut cfg, "registry_keys", json!(key));
                        }
                        if arch == "32bit" || arch == "both" {
                            push(&mut cfg, "registry_keys", json!(format!("{key} [x32]")));
                        }
                    }
                }
                for r in sc.all("registry_ignore") {
                    push(&mut cfg, "registry_ignore", json!(r.text.trim()));
                }
            }
            for rk in block.all("rootcheck") {
                if let Some(b) = yes(rk.kid_text("disabled").as_deref()) {
                    cfg.insert("rootcheck_enabled".into(), json!(!b));
                }
                if let Some(f) = rk.kid_text("frequency").and_then(|v| seconds(&v)) {
                    cfg.insert("rootcheck_interval_secs".into(), json!(f));
                }
                for (k, out) in [("check_files", "files"), ("check_trojans", "trojans")] {
                    if let Some(b) = yes(rk.kid_text(k).as_deref()) {
                        set(&mut cfg, "rootcheck_checks", out, json!(b));
                    }
                }
                // the agent has one switch for its policy lists: on while any of them is asked for
                let policies: Vec<bool> = ["check_winapps", "check_winmalware", "check_winaudit"].iter().filter_map(|k| yes(rk.kid_text(k).as_deref())).collect();
                if !policies.is_empty() {
                    set(&mut cfg, "rootcheck_checks", "policies", json!(policies.contains(&true)));
                }
                if let Some(d) = rk.kid_text("base_directory") {
                    cfg.insert("rootcheck_base_directory".into(), json!(d));
                }
            }
            for sca in block.all("sca") {
                if let Some(b) = yes(sca.kid_text("enabled").as_deref()) {
                    cfg.insert("sca_enabled".into(), json!(b));
                }
                if let Some(f) = sca.kid_text("interval").and_then(|v| seconds(&v)) {
                    cfg.insert("sca_interval_secs".into(), json!(f));
                }
            }
            for w in block.all("wodle").filter(|w| w.attr("name") == Some("syscollector")) {
                if let Some(f) = w.kid_text("interval").and_then(|v| seconds(&v)) {
                    cfg.insert("inventory_interval_secs".into(), json!(f));
                }
            }
            // like command log files, the agent runs these only when its local settings allow it
            for w in block.all("wodle").filter(|w| w.attr("name") == Some("command")) {
                let Some(command) = w.kid_text("command").filter(|_| yes(w.kid_text("disabled").as_deref()) != Some(true)) else { continue };
                let mut o = Map::new();
                o.insert("name".into(), json!(w.kid_text("tag").unwrap_or_else(|| command.clone())));
                o.insert("command".into(), json!(command));
                for (k, out) in [("interval", "interval_secs"), ("timeout", "timeout_secs")] {
                    if let Some(n) = w.kid_text(k).and_then(|v| seconds(&v)).filter(|&n| n > 0) {
                        o.insert(out.into(), json!(n));
                    }
                }
                for k in ["run_on_start", "ignore_output"] {
                    if let Some(b) = yes(w.kid_text(k).as_deref()) {
                        o.insert(k.into(), json!(b));
                    }
                }
                if let Some(h) = w.kid_text("verify_sha256") {
                    o.insert("sha256".into(), json!(h));
                }
                push(&mut cfg, "commands", Value::Object(o));
            }
            for w in block.all("wodle").filter(|w| w.attr("name") == Some("osquery")) {
                set(&mut cfg, "osquery", "enabled", json!(yes(w.kid_text("disabled").as_deref()) != Some(true)));
                if let Some(b) = yes(w.kid_text("run_daemon").as_deref()) {
                    set(&mut cfg, "osquery", "run_daemon", json!(b));
                }
                for k in ["bin_path", "log_path", "config_path"] {
                    if let Some(v) = w.kid_text(k) {
                        set(&mut cfg, "osquery", k, json!(v));
                    }
                }
            }
            for ar in block.all("active-response") {
                if let Some(r) = ar.kid_text("repeated_offenders") {
                    let minutes: Vec<u64> = r.split(',').filter_map(|m| m.trim().parse().ok()).collect();
                    cfg.insert("ar_repeated_offenders".into(), json!(minutes));
                }
            }
            for l in block.all("labels").flat_map(|ls| ls.all("label")) {
                if let Some(k) = l.attr("key") {
                    push(&mut cfg, "labels", json!({ "key": k, "value": l.text.trim(), "hidden": yes(l.attr("hidden")).unwrap_or(false) }));
                }
            }
            if let Some(b) = block.kid("client_buffer") {
                let mut o = Map::new();
                if let Some(d) = yes(b.kid_text("disabled").as_deref()) {
                    o.insert("disabled".into(), json!(d));
                }
                for (k, out) in [("queue_size", "queue_size"), ("events_per_second", "events_per_second"), ("min_eps", "min_eps")] {
                    if let Some(n) = b.kid_text(k).and_then(|v| v.parse::<u64>().ok()) {
                        o.insert(out.into(), json!(n));
                    }
                }
                cfg.insert("buffer".into(), Value::Object(o));
            }
        }
    }
    if !queries.is_empty() {
        cfg.insert("event_channel_queries".into(), Value::Object(queries));
    }
    Value::Object(cfg)
}

/// The agent's group names (`default` when none).
pub fn agent_groups(csv: &str) -> Vec<String> {
    let v: Vec<String> = csv.split(',').map(str::trim).filter(|g| !g.is_empty()).map(str::to_string).collect();
    if v.is_empty() {
        vec!["default".to_string()]
    } else {
        v
    }
}

fn valid_group(g: &str) -> bool {
    !g.is_empty() && g.len() <= 255 && !matches!(g, "." | ".." | "all") && g.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// `tenant`'s group `g` as the manager names it.
pub fn manager_name(tenant: &str, g: &str) -> Option<String> {
    if g == "default" {
        return Some(g.to_string());
    }
    // the first '.' splits tenant and group, so a tenant id must not contain one
    if tenant.is_empty() || !tenant.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')) {
        return None;
    }
    let m = format!("{tenant}.{g}");
    (valid_group(g) && m.len() <= 255).then_some(m)
}

/// `{"version", "config"}` of an agent: the `agent.conf` of each of its groups under
/// `<home>/etc/shared`; version = first 8 bytes of the SHA-256 of the settings, in hex.
pub fn for_agent(home: &Path, tenant: &str, name: &str, groups: &str) -> Value {
    let shared = home.join("etc").join("shared");
    let confs: Vec<String> = agent_groups(groups).iter().filter_map(|g| manager_name(tenant, g)).filter_map(|m| std::fs::read_to_string(shared.join(m).join("agent.conf")).ok()).collect();
    let config = translate(&confs, name);
    let version: String = Sha256::digest(config.to_string().as_bytes())[..8].iter().map(|b| format!("{b:02x}")).collect();
    json!({ "version": version, "config": config })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_conf_to_agent_settings() {
        let conf = r#"<agent_config>
  <labels><label key="site">Kochi</label><label key="owner" hidden="yes">it</label></labels>
</agent_config>
<agent_config os="Linux">
  <localfile><location>/var/log/syslog</location><log_format>syslog</log_format></localfile>
</agent_config>
<agent_config os="Windows">
  <localfile><location>Microsoft-Windows-Sysmon/Operational</location><log_format>eventchannel</log_format></localfile>
  <localfile><location>Windows PowerShell</location><log_format>eventchannel</log_format><query>Event/System[EventID=400]</query></localfile>
  <localfile><location>C:\inetpub\logs\LogFiles\W3SVC1\*.log</location><log_format>iis</log_format><ignore>healthcheck</ignore></localfile>
  <localfile><command>netstat -an</command><log_format>full_command</log_format><alias>netstat</alias><frequency>5m</frequency></localfile>
  <syscheck><disabled>yes</disabled><frequency>12h</frequency><directories realtime="yes" recursion_level="3">C:\Data, C:\Web</directories><directories whodata="yes" report_changes="yes" recursion_level="8">C:\Secret</directories>
    <windows_registry arch="32bit">HKEY_LOCAL_MACHINE\Software\Test</windows_registry><windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Both</windows_registry>
    <ignore>C:\Data\tmp</ignore><ignore type="sregex">\.log$</ignore><nodiff>C:\Secret\keys.txt</nodiff></syscheck>
  <sca><enabled>no</enabled></sca>
  <wodle name="syscollector"><interval>1h</interval></wodle>
  <client_buffer><queue_size>8000</queue_size><events_per_second>300</events_per_second></client_buffer>
</agent_config>
<agent_config name="other-pc"><rootcheck><disabled>yes</disabled></rootcheck></agent_config>"#;
        let c = translate(&[conf.to_string()], "pc-49");
        assert_eq!(c["event_channels"], json!(["Microsoft-Windows-Sysmon/Operational", "Windows PowerShell"]));
        assert_eq!(c["event_channel_queries"]["Windows PowerShell"], "Event/System[EventID=400]");
        let lfs = c["localfiles"].as_array().unwrap();
        assert_eq!(lfs.len(), 2, "the Linux block is skipped; the command is passed on (the agent decides)");
        assert!(lfs.iter().any(|l| l["command"] == "netstat -an" && l["log_format"] == "full_command"));
        assert_eq!(c["localfiles"][0]["ignore"], json!(["healthcheck"]));
        assert_eq!(c["fim_scan_interval_secs"], 43200);
        assert_eq!(c["fim_paths"], json!(["C:\\Data", "C:\\Web", "C:\\Secret"]));
        assert_eq!(c["fim_realtime"].as_array().unwrap().len(), 2);
        assert_eq!(c["fim_whodata"], json!(["C:\\Secret"]));
        assert_eq!(c["fim_ignore"], json!(["C:\\Data\\tmp", "regex:\\.log$"]));
        assert_eq!(c["fim_nodiff"], json!(["C:\\Secret\\keys.txt"]));
        assert_eq!(c["fim_report_changes"], json!(["C:\\Secret"]));
        assert_eq!(c["fim_recursion_level"], 8);
        assert_eq!((c["fim_enabled"].as_bool(), c["sca_enabled"].as_bool()), (Some(false), Some(false)));
        assert_eq!(c["inventory_interval_secs"], 3600);
        assert_eq!(c["registry_keys"], json!(["HKEY_LOCAL_MACHINE\\Software\\Test [x32]", "HKEY_LOCAL_MACHINE\\Software\\Both", "HKEY_LOCAL_MACHINE\\Software\\Both [x32]"]));
        assert_eq!(c["labels"][1], json!({ "key": "owner", "value": "it", "hidden": true }));
        assert_eq!(c["buffer"], json!({ "queue_size": 8000, "events_per_second": 300 }));
        assert!(c.get("rootcheck_enabled").is_none(), "a block for another agent name is skipped");
    }

    #[test]
    fn registry_restrict_report_changes_and_min_eps() {
        let conf = r#"<agent_config>
  <syscheck><windows_registry restrict_key="Run$" restrict_value="^evil" report_changes="yes">HKEY_LOCAL_MACHINE\Software\A</windows_registry>
    <windows_registry report_changes="no">HKEY_LOCAL_MACHINE\Software\B</windows_registry></syscheck>
  <client_buffer><min_eps>100</min_eps></client_buffer>
</agent_config>"#;
        let c = translate(&[conf.to_string()], "pc");
        assert_eq!(c["registry_restrict_key"], json!(["Run$"]));
        assert_eq!(c["registry_restrict_value"], json!(["^evil"]));
        assert_eq!(c["registry_report_changes"], json!(["HKEY_LOCAL_MACHINE\\Software\\A"]));
        assert_eq!(c["buffer"], json!({ "min_eps": 100 }));
    }

    #[test]
    fn commands_osquery_rootcheck_log_options_repeated_offenders() {
        let conf = r#"<agent_config os="Windows">
  <wodle name="command"><tag>users</tag><command>net user</command><interval>1h</interval><run_on_start>no</run_on_start><ignore_output>yes</ignore_output><timeout>30</timeout><verify_sha256>ab12</verify_sha256></wodle>
  <wodle name="command"><command>whoami</command></wodle>
  <wodle name="command"><disabled>yes</disabled><command>ipconfig</command></wodle>
  <wodle name="osquery"><run_daemon>no</run_daemon><log_path>D:\osq\results.log</log_path><config_path>D:\osq\osquery.conf</config_path><bin_path>D:\osq\osqueryd.exe</bin_path></wodle>
  <rootcheck><check_files>no</check_files><check_trojans>yes</check_trojans><check_winapps>no</check_winapps><check_winmalware>no</check_winmalware><base_directory>D:\</base_directory></rootcheck>
  <localfile><location>C:\sql\ERRORLOG</location><log_format>mssql_log</log_format><label key="app">sql</label><label key="tier">db</label><max-size>10MB</max-size></localfile>
  <localfile><location>C:\pg\pg.log</location><log_format>postgresql_log</log_format><max-size>4096</max-size></localfile>
  <active-response><repeated_offenders>30, 60,120</repeated_offenders></active-response>
</agent_config>
<agent_config><rootcheck><check_winaudit>yes</check_winaudit></rootcheck><wodle name="osquery"><disabled>yes</disabled></wodle></agent_config>"#;
        let c = translate(&[conf.to_string()], "pc");
        assert_eq!(
            c["commands"],
            json!([
                { "name": "users", "command": "net user", "interval_secs": 3600, "timeout_secs": 30, "run_on_start": false, "ignore_output": true, "sha256": "ab12" },
                { "name": "whoami", "command": "whoami" },
            ]),
            "a disabled one is left out"
        );
        assert_eq!(
            c["osquery"],
            json!({ "enabled": false, "run_daemon": false, "log_path": r"D:\osq\results.log", "config_path": r"D:\osq\osquery.conf", "bin_path": r"D:\osq\osqueryd.exe" }),
            "a later block disables it, keeping the rest"
        );
        assert_eq!(c["rootcheck_checks"], json!({ "files": false, "trojans": true, "policies": true }), "policies on while one list is asked for");
        assert_eq!(c["rootcheck_base_directory"], r"D:\");
        assert_eq!(c["localfiles"][0]["labels"], json!({ "app": "sql", "tier": "db" }));
        assert_eq!((c["localfiles"][0]["max_size"].as_u64(), c["localfiles"][1]["max_size"].as_u64()), (Some(10 << 20), Some(4096)));
        assert_eq!(c["localfiles"][1]["log_format"], "postgresql_log");
        assert_eq!(c["ar_repeated_offenders"], json!([30, 60, 120]));
        assert_eq!((bytes("64KB"), bytes("1g"), bytes("12 b"), bytes("x")), (Some(65536), Some(1 << 30), Some(12), None));
    }
}
