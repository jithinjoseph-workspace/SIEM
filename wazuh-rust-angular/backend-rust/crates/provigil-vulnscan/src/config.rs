//! Configuration: the file section, internal options, time texts, validation and the updater
//! parameters.

use crate::json::compact;
use crate::legacy_names::{CONSUMER_NAME, DEFAULT_CTI_URL, MAX_EPS_OPTION, UPDATER_DB_DIR};
use crate::log::Log;
use serde_json::{json, Map, Value};

pub const TOPIC: &str = "vulnerability_feed_manager";
pub const UPDATER_DIR: &str = "queue/vd_updater";
pub const UPDATER_OUTPUT: &str = "queue/vd_updater/tmp";

/// What the host passes to the scanner.
#[derive(Debug, Clone)]
pub struct ModuleConfig {
    /// The `<vulnerability-detection>` section as an object of texts.
    pub vd: Map<String, Value>,
    pub indexer: Value,
    pub wm_max_eps: u32,
    pub translation_lru_size: usize,
    pub osdata_lru_size: usize,
    pub remediation_lru_size: usize,
    pub manager_disabled_scan: bool,
    pub report_queue_size: usize,
    pub cluster_enabled: bool,
    pub cluster_name: String,
    pub cluster_node_name: String,
}

impl ModuleConfig {
    pub fn new(vd: Map<String, Value>, opts: &InternalOptions, host_name: &str) -> Self {
        ModuleConfig {
            vd,
            indexer: json!({"enabled":"yes"}),
            wm_max_eps: opts.max_eps,
            translation_lru_size: opts.translation_lru_size,
            osdata_lru_size: opts.osdata_lru_size,
            remediation_lru_size: opts.remediation_lru_size,
            manager_disabled_scan: opts.disable_scan_manager,
            report_queue_size: opts.report_queue_size,
            cluster_enabled: false,
            cluster_name: host_name.to_string(),
            cluster_node_name: "undefined".into(),
        }
    }

    /// The start debug line: fixed key order, the section's keys sorted.
    pub fn debug_json(&self) -> String {
        let q = |s: &str| Value::String(s.to_string()).to_string();
        format!(
            "{{\"vulnerability-detection\":{},\"wmMaxEps\":{},\"translationLRUSize\":{},\"osdataLRUSize\":{},\"remediationLRUSize\":{},\"managerDisabledScan\":{},\"reportQueueSize\":{},\"indexer\":{},\"clusterEnabled\":{},\"clusterName\":{},\"clusterNodeName\":{}}}",
            compact(&Value::Object(self.vd.clone())),
            self.wm_max_eps,
            self.translation_lru_size,
            self.osdata_lru_size,
            self.remediation_lru_size,
            u8::from(self.manager_disabled_scan),
            self.report_queue_size,
            compact(&self.indexer),
            self.cluster_enabled,
            q(&self.cluster_name),
            q(&self.cluster_node_name)
        )
    }

    pub fn get(&self, k: &str) -> Option<&str> {
        self.vd.get(k).and_then(Value::as_str)
    }
}

/// Time text in seconds; -1 when invalid.
pub fn parse_time(t: &str) -> i64 {
    let t = t.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    let (neg, t) = match t.as_bytes().first() {
        Some(b'+') => (false, &t[1..]),
        Some(b'-') => (true, &t[1..]),
        _ => (false, t),
    };
    let n = t.bytes().take_while(u8::is_ascii_digit).count();
    if n == 0 {
        return -1;
    }
    // Numbers that do not fit 64 bits are invalid; a negative value is invalid, `-0` is 0.
    let Ok(v) = t[..n].parse::<i64>() else { return -1 };
    if neg && v != 0 {
        return -1;
    }
    let mul = match t.as_bytes().get(n) {
        None | Some(b's') => 1,
        Some(b'm') => 60,
        Some(b'h') => 3600,
        Some(b'd') => 86400,
        Some(b'w') => 604800,
        _ => return -1,
    };
    v.checked_mul(mul).unwrap_or(-1)
}

/// Validates the configuration (fills the default interval) and builds the updater parameters.
pub fn validate(cfg: &mut ModuleConfig, log: &Log) -> Result<Value, String> {
    if !cfg.vd.contains_key("enabled") {
        return Err("Missing enabled field.".into());
    }
    if !cfg.vd.contains_key("index-status") {
        return Err("Missing index-status field.".into());
    }
    if let Some(v) = cfg.vd.get("feed-update-interval") {
        if parse_time(v.as_str().unwrap_or("")) < 0 {
            return Err("Invalid feed update interval.".into());
        }
    }
    if let Some(v) = cfg.vd.get("offline-url") {
        let v = v.as_str().unwrap_or("");
        if !(v.starts_with("file") || v.starts_with("http")) {
            return Err("Invalid URL provided.".into());
        }
    }
    let ix = match cfg.indexer.get("enabled") {
        None => return Err("Missing enabled field.".into()),
        Some(v) => v.as_str().unwrap_or(""),
    };
    if ix != "yes" && ix != "no" {
        return Err("Invalid input.".into());
    }
    if ix == "no" {
        let yn = |k: &str| match cfg.get(k) {
            Some("yes") => Ok(true),
            Some("no") => Ok(false),
            _ => Err("Invalid input.".to_string()),
        };
        if yn("enabled")? && yn("index-status")? {
            return Err("Indexer cannot be disabled while vulnerability detection index is enabled.".into());
        }
    }
    let Some(url) = cfg.get("cti-url").map(str::to_string) else {
        return Err("Missing URL setting.".into());
    };
    let mut interval = match cfg.get("feed-update-interval") {
        Some(v) => parse_time(v),
        None => {
            cfg.vd.insert("feed-update-interval".into(), "60m".into());
            3600
        }
    };
    if interval < 3600 {
        vs!(log, Warning, "The 'feed-update-interval' option at module 'vulnerability-detection' must be at least 1 hour. Automatically set to 60 minutes.");
        cfg.vd.insert("feed-update-interval".into(), "60m".into());
        interval = 3600;
    }
    let mut data = json!({
        "consumerName": CONSUMER_NAME,
        "compressionType": "raw",
        "deleteDownloadedContent": true,
        "outputFolder": UPDATER_OUTPUT,
        "databasePath": format!("{UPDATER_DIR}/{UPDATER_DB_DIR}"),
        "offset": 0,
    });
    match cfg.get("offline-url") {
        Some(off) => {
            data["contentSource"] = "offline".into();
            data["versionedContent"] = "offline".into();
            data["url"] = off.into();
        }
        None => {
            data["contentSource"] = "cti-offset".into();
            data["versionedContent"] = "cti-api".into();
            data["contentFileName"] = "api_file.json".into();
            data["url"] = url.into();
        }
    }
    Ok(json!({"topicName": TOPIC, "interval": interval, "ondemand": true, "configData": data}))
}

/// Internal options of the scanner.
#[derive(Debug, Clone)]
pub struct InternalOptions {
    pub translation_lru_size: usize,
    pub osdata_lru_size: usize,
    pub remediation_lru_size: usize,
    pub report_queue_size: usize,
    pub disable_scan_manager: bool,
    pub max_eps: u32,
}

impl Default for InternalOptions {
    fn default() -> Self {
        InternalOptions {
            translation_lru_size: 2048,
            osdata_lru_size: 1000,
            remediation_lru_size: 2048,
            report_queue_size: 262144,
            disable_scan_manager: true,
            max_eps: 100,
        }
    }
}

/// Reads `name=value` lines (later texts override earlier ones). Out-of-range values of the
/// scanner's own options fall back silently; an invalid max-eps value is fatal for the host.
pub fn internal_options(texts: &[&str]) -> Result<InternalOptions, String> {
    let mut m = std::collections::HashMap::new();
    for t in texts {
        for line in t.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                m.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    let num = |k: &str, lo: i64, hi: i64, def: i64| -> i64 {
        m.get(k).and_then(|v| v.parse::<i64>().ok()).filter(|v| (lo..=hi).contains(v)).unwrap_or(def)
    };
    let max_eps = match m.get(MAX_EPS_OPTION) {
        None => 100,
        Some(v) => match v.parse::<i64>() {
            Ok(n) if (1..=1000).contains(&n) => n as u32,
            _ => return Err(format!("Invalid value for option '{MAX_EPS_OPTION}': {v}")),
        },
    };
    Ok(InternalOptions {
        translation_lru_size: num("vulnerability-detection.translation_lru_size", 1, 100000, 2048) as usize,
        osdata_lru_size: num("vulnerability-detection.osdata_lru_size", 1, 100000, 1000) as usize,
        remediation_lru_size: num("vulnerability-detection.remediation_lru_size", 1, 100000, 2048) as usize,
        report_queue_size: num("vulnerability-detection.report_queue_size", 0, 2147483647, 262144) as usize,
        disable_scan_manager: num("vulnerability-detection.disable_scan_manager", 0, 1, 1) == 1,
        max_eps,
    })
}

// ---- configuration file -------------------------------------------------------------------

#[derive(Debug, Default)]
struct El {
    name: String,
    text: String,
    children: Vec<El>,
}

fn parse_xml(text: &str) -> Result<El, String> {
    use quick_xml::events::Event;
    let mut r = quick_xml::Reader::from_str(text);
    let mut stack = vec![El::default()];
    loop {
        match r.read_event().map_err(|e| e.to_string())? {
            Event::Start(s) => stack.push(El { name: String::from_utf8_lossy(s.name().as_ref()).into_owned(), ..Default::default() }),
            Event::Empty(s) => {
                let el = El { name: String::from_utf8_lossy(s.name().as_ref()).into_owned(), ..Default::default() };
                stack.last_mut().unwrap().children.push(el);
            }
            Event::End(_) => {
                let el = stack.pop().unwrap();
                match stack.last_mut() {
                    Some(p) => p.children.push(el),
                    None => return Err("unbalanced element".into()),
                }
            }
            Event::Text(t) => {
                let t = t.unescape().map_err(|e| e.to_string())?;
                stack.last_mut().unwrap().text.push_str(&t);
            }
            Event::CData(t) => stack.last_mut().unwrap().text.push_str(&String::from_utf8_lossy(&t)),
            Event::Eof => break,
            _ => {}
        }
    }
    if stack.len() != 1 {
        return Err("unbalanced element".into());
    }
    Ok(stack.pop().unwrap())
}

const VALID: [&str; 5] = ["enabled", "index-status", "feed-update-interval", "offline-url", "cti-url"];
const NEW_SECTION: &str = "vulnerability-detection";
const OLD_SECTION: &str = "vulnerability-detector";

fn read_children(el: &El, deprecated: bool, out: &mut Map<String, Value>, log: &Log) {
    for c in &el.children {
        if !VALID.contains(&c.name.as_str()) {
            host!(log, Warning, "(1230): Invalid element in the configuration: '{}'.", c.name);
            continue;
        }
        if deprecated && c.name != "enabled" {
            continue;
        }
        let v = if c.children.is_empty() {
            Value::String(c.text.trim().to_string())
        } else {
            let mut m = Map::new();
            read_children(c, deprecated, &mut m, log);
            Value::Object(m)
        };
        if deprecated && out.contains_key(&c.name) {
            continue;
        }
        out.remove(&c.name);
        out.insert(c.name.clone(), v);
    }
}

/// Reads the scanner section of the configuration file text. `None` when neither section
/// exists (the scanner is then not started at all).
pub fn read_section(text: &str, is_manager: bool, log: &Log) -> Option<Map<String, Value>> {
    let root = parse_xml(text).ok()?;
    let blocks: Vec<&El> = root.children.iter().collect();
    let mut out: Option<Map<String, Value>> = None;
    for b in &blocks {
        for s in &b.children {
            if s.name != NEW_SECTION && s.name != OLD_SECTION {
                continue;
            }
            let deprecated = s.name == OLD_SECTION;
            if deprecated {
                host!(log, Warning, "The 'vulnerability-detector' section is deprecated; use 'vulnerability-detection' instead (the values found are kept).");
            }
            if !is_manager {
                host!(log, Warning, "{} configuration is only set in the manager.", s.name);
                continue;
            }
            let obj = out.get_or_insert_with(Map::new);
            if s.children.is_empty() {
                host!(log, Debug, "Empty configuration for module 'vulnerability_scanner'");
                continue;
            }
            read_children(s, deprecated, obj, log);
            if !obj.contains_key("cti-url") {
                let u = global_in(&blocks).unwrap_or_else(|| DEFAULT_CTI_URL.to_string());
                obj.insert("cti-url".into(), u.into());
            }
        }
    }
    out
}

fn global_in(blocks: &[&El]) -> Option<String> {
    blocks
        .iter()
        .flat_map(|b| b.children.iter())
        .filter(|s| s.name == "global")
        .flat_map(|s| s.children.iter())
        .filter(|c| c.name == "cti-url" && !c.text.trim().is_empty())
        .map(|c| c.text.trim().to_string())
        .next_back()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::{Level, MemoryLogger};
    use std::sync::Arc;

    fn cfg(vd: Value) -> ModuleConfig {
        ModuleConfig::new(vd.as_object().unwrap().clone(), &InternalOptions::default(), "host")
    }

    #[test]
    fn times() {
        for (t, v) in [("60m", 3600), ("2h", 7200), ("3600", 3600), ("1w", 604800), ("10x", -1), ("abc", -1), ("-5m", -1), ("1d", 86400), ("30s", 30), ("10mx", 600), (" +5", 5), ("-0m", 0), ("	5", 5), ("99999999999999999999", -1)] {
            assert_eq!(parse_time(t), v, "{t}");
        }
    }

    #[test]
    fn validation_and_params() {
        let mut c = cfg(json!({"enabled":"yes","index-status":"yes","cti-url":"U"}));
        let p = validate(&mut c, &Log::null()).unwrap();
        assert_eq!(p["topicName"], "vulnerability_feed_manager");
        assert_eq!(p["interval"], 3600);
        let d = &p["configData"];
        assert_eq!((d["contentSource"].as_str(), d["versionedContent"].as_str(), d["contentFileName"].as_str(), d["url"].as_str()), (Some("cti-offset"), Some("cti-api"), Some("api_file.json"), Some("U")));
        assert_eq!((d["compressionType"].as_str(), d["outputFolder"].as_str(), d["databasePath"].as_str()), (Some("raw"), Some("queue/vd_updater/tmp"), Some(format!("queue/vd_updater/{UPDATER_DB_DIR}").as_str())));
        assert_eq!((d["consumerName"].as_str(), &d["deleteDownloadedContent"], &d["offset"]), (Some(CONSUMER_NAME), &json!(true), &json!(0)));

        let l = Arc::new(MemoryLogger::default());
        let mut c = cfg(json!({"enabled":"yes","index-status":"yes","cti-url":"U","feed-update-interval":"30m"}));
        assert_eq!(validate(&mut c, &Log::new(l.clone())).unwrap()["interval"], 3600);
        assert!(l.has(Level::Warning, "The 'feed-update-interval' option at module 'vulnerability-detection' must be at least 1 hour. Automatically set to 60 minutes."));

        let e = |v: Value| validate(&mut cfg(v), &Log::null()).unwrap_err();
        assert_eq!(e(json!({"enabled":"yes","index-status":"yes","cti-url":"U","feed-update-interval":"bogus"})), "Invalid feed update interval.");
        assert_eq!(e(json!({"enabled":"yes","index-status":"yes","cti-url":"U","offline-url":"ftp://x/f.json"})), "Invalid URL provided.");
        assert_eq!(e(json!({"enabled":"yes","index-status":"yes"})), "Missing URL setting.");
        assert_eq!(e(json!({"index-status":"yes"})), "Missing enabled field.");
        assert_eq!(e(json!({"enabled":"yes"})), "Missing index-status field.");
        let mut c = cfg(json!({"enabled":"yes","index-status":"yes","cti-url":"U","offline-url":"file:///tmp/f.json"}));
        let d = validate(&mut c, &Log::null()).unwrap()["configData"].clone();
        assert_eq!((d["contentSource"].as_str(), d["versionedContent"].as_str(), d["url"].as_str()), (Some("offline"), Some("offline"), Some("file:///tmp/f.json")));
        assert!(d.get("contentFileName").is_none());

        let mut c = cfg(json!({"enabled":"yes","index-status":"yes","cti-url":"U"}));
        c.indexer = json!({"enabled":"no"});
        assert_eq!(validate(&mut c, &Log::null()).unwrap_err(), "Indexer cannot be disabled while vulnerability detection index is enabled.");
        c.vd.insert("index-status".into(), "no".into());
        assert!(validate(&mut c, &Log::null()).is_ok());
    }

    #[test]
    fn debug_line_order() {
        let c = cfg(json!({"index-status":"yes","enabled":"yes"}));
        assert_eq!(c.debug_json(), r#"{"vulnerability-detection":{"enabled":"yes","index-status":"yes"},"wmMaxEps":100,"translationLRUSize":2048,"osdataLRUSize":1000,"remediationLRUSize":2048,"managerDisabledScan":1,"reportQueueSize":262144,"indexer":{"enabled":"yes"},"clusterEnabled":false,"clusterName":"host","clusterNodeName":"undefined"}"#);
    }

    #[test]
    fn file_section() {
        let l = Arc::new(MemoryLogger::default());
        let log = Log::new(l.clone());
        let o = read_section("<manager_config><vulnerability-detection><enabled>yes</enabled><foo>1</foo></vulnerability-detection></manager_config>", true, &log).unwrap();
        assert_eq!(Value::Object(o), json!({"enabled":"yes","cti-url":DEFAULT_CTI_URL}));
        assert!(l.has(Level::Warning, "(1230): Invalid element in the configuration: 'foo'."));
        let o = read_section("<manager_config><global><cti-url>G</cti-url></global></manager_config><manager_config><vulnerability-detector><enabled>no</enabled><enabled>yes</enabled><feed-update-interval>1h</feed-update-interval></vulnerability-detector></manager_config>", true, &log).unwrap();
        assert_eq!(Value::Object(o), json!({"enabled":"no","cti-url":"G"}));
        let o = read_section("<manager_config><vulnerability-detection/></manager_config>", true, &log).unwrap();
        assert!(o.is_empty());
        assert!(read_section("<manager_config><global/></manager_config>", true, &log).is_none());
        let mut c = cfg(Value::Object(o));
        c.vd.insert("enabled".into(), "yes".into());
        c.vd.insert("index-status".into(), "yes".into());
        assert_eq!(validate(&mut c, &Log::null()).unwrap_err(), "Missing URL setting.");
    }

    #[test]
    fn options() {
        let o = internal_options(&["vulnerability-detection.osdata_lru_size=0\nvulnerability-detection.report_queue_size=5", "vulnerability-detection.disable_scan_manager=0"]).unwrap();
        assert_eq!((o.osdata_lru_size, o.report_queue_size, o.disable_scan_manager, o.max_eps), (1000, 5, false, 100));
        assert!(internal_options(&[&format!("{MAX_EPS_OPTION}=0")]).is_err());
    }
}

/// `<home>/<folder>` as text: an empty home gives the folder itself; otherwise exactly one `/`
/// between them.
pub fn home_path(home: &str, folder: &str) -> String {
    let h = home.trim_end_matches('/');
    if home.is_empty() {
        folder.to_string()
    } else {
        format!("{h}/{folder}")
    }
}

#[cfg(test)]
mod home_path_tests {
    #[test]
    fn joins() {
        // D55
        assert_eq!(super::home_path("", "queue/vd_updater/tmp"), "queue/vd_updater/tmp");
        assert_eq!(super::home_path("/srv/manager/", "x"), "/srv/manager/x");
        assert_eq!(super::home_path("/srv/manager", "x"), "/srv/manager/x");
    }
}
