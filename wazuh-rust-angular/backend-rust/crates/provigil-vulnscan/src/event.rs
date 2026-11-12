//! Events: their encoding in the queues, classification, OS data and the scan context.

use crate::json::{compact, key_missing, opt_text, s, type_name, Error, Res};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Inventory delta (router `deltas-syscollector`).
    Delta,
    /// Inventory synchronisation message (router `rsync`).
    Rsync,
    /// JSON action (`wdb-agent-events`, `wdb-inventory-events`, policy and feed actions).
    Json,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub origin: Origin,
    pub body: Value,
}

impl Event {
    pub fn json(body: Value) -> Self {
        Event { origin: Origin::Json, body }
    }

    /// One type byte (`d`, `r`, `j`) followed by the compact sorted JSON.
    pub fn encode(&self) -> Vec<u8> {
        let b = match self.origin {
            Origin::Delta => b'd',
            Origin::Rsync => b'r',
            Origin::Json => b'j',
        };
        let mut v = vec![b];
        v.extend_from_slice(compact(&self.body).as_bytes());
        v
    }

    pub fn decode(b: &[u8]) -> Option<Event> {
        let origin = match b.first()? {
            b'd' => Origin::Delta,
            b'r' => Origin::Rsync,
            b'j' => Origin::Json,
            _ => return None,
        };
        Some(Event { origin, body: serde_json::from_slice(&b[1..]).ok()? })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    Unknown = 0,
    PackageInsert = 1,
    PackageDelete = 2,
    Os = 3,
    HotfixInsert = 4,
    HotfixDelete = 5,
    IntegrityClear = 6,
    RescanAll = 7,
    RescanOne = 8,
    CleanupAll = 9,
    CleanupOne = 10,
    GlobalSync = 11,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    Unknown = 0,
    Package = 1,
    Os = 2,
    Hotfix = 3,
    Agent = 4,
}

/// Agent ids are at least 3 digits, zero-padded; empty is the manager (`000`).
pub fn pad_agent(id: &str) -> String {
    if id.is_empty() {
        "000".into()
    } else {
        format!("{id:0>3}")
    }
}

/// Type and component of an event (7.2), without side effects.
pub fn classify(ev: &Event) -> Res<(EventType, Component)> {
    use Component as C;
    use EventType as T;
    let b = &ev.body;
    Ok(match ev.origin {
        Origin::Delta => {
            let op = b.get("operation").ok_or("Operation not found in delta.")?.as_str().unwrap_or("");
            match s(b, "data_type") {
                "dbsync_packages" => match op {
                    "INSERTED" => (T::PackageInsert, C::Package),
                    "DELETED" => (T::PackageDelete, C::Package),
                    _ => (T::Unknown, C::Package),
                },
                "dbsync_osinfo" => (T::Os, C::Os),
                "dbsync_hotfixes" => match op {
                    "INSERTED" => (T::HotfixInsert, C::Hotfix),
                    "DELETED" => (T::HotfixDelete, C::Hotfix),
                    _ => (T::Unknown, C::Hotfix),
                },
                _ => (T::Unknown, C::Unknown),
            }
        }
        Origin::Rsync => {
            let at = b.pointer("/data/attributes_type").and_then(Value::as_str).unwrap_or("");
            match (s(b, "data_type"), at) {
                ("state", "syscollector_osinfo") => (T::Os, C::Os),
                ("state", "syscollector_packages") => (T::PackageInsert, C::Package),
                ("state", "syscollector_hotfixes") => (T::HotfixInsert, C::Hotfix),
                ("integrity_clear", "syscollector_packages") => (T::IntegrityClear, C::Package),
                ("integrity_clear", "syscollector_osinfo") => (T::IntegrityClear, C::Os),
                ("integrity_check_global", "syscollector_packages" | "syscollector_osinfo") => (T::GlobalSync, C::Agent),
                _ => (T::Unknown, C::Unknown),
            }
        }
        Origin::Json => {
            if !b.is_object() {
                return Err("Unable to build scan context. Unknown JSON format".into());
            }
            let action = b.get("action").ok_or_else(|| key_missing("action"))?;
            match action.as_str() {
                Some("reboot") => (T::RescanAll, C::Agent),
                Some("cleanup") => (T::CleanupAll, C::Agent),
                Some("scanAgent") => (T::RescanOne, C::Agent),
                Some("upgradeAgentDB") => {
                    let v = b.pointer("/data/new_db_version").ok_or_else(|| key_missing("data"))?;
                    let n = match v {
                        Value::Number(n) => n.as_i64().unwrap_or_else(|| n.as_f64().unwrap_or(0.0) as i64),
                        Value::Bool(x) => i64::from(*x),
                        o => return Err(Error::Json { id: 302, text: format!("JSON value must be number, but is {}", type_name(o)) }),
                    };
                    if n == 15 {
                        (T::CleanupOne, C::Agent)
                    } else {
                        (T::Unknown, C::Agent)
                    }
                }
                Some("deletePackage") => (T::PackageDelete, C::Package),
                Some("deleteHotfix") => (T::HotfixDelete, C::Hotfix),
                Some("deleteAgent") => (T::CleanupOne, C::Agent),
                _ => return Err("Unable to build scan context. Unknown action".into()),
            }
        }
    })
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct OsData {
    pub hostname: String,
    pub architecture: String,
    pub name: String,
    pub codename: String,
    pub major: String,
    pub minor: String,
    pub patch: String,
    pub build: String,
    pub platform: String,
    pub version: String,
    pub release: String,
    pub display_version: String,
    pub sysname: String,
    pub kernel_version: String,
    pub kernel_release: String,
    pub cpe_name: String,
}

/// OS row fields as read from the agent database and from OS events.
pub const OS_FIELDS: [&str; 15] = [
    "hostname", "architecture", "os_name", "os_codename", "os_major", "os_minor", "os_patch", "os_build",
    "os_platform", "os_version", "os_release", "os_display_version", "sysname", "version", "release",
];

impl OsData {
    /// OS data of a row. `strict`: agent-database rows, where a non-text field is error 302;
    /// event rows read non-text fields as empty.
    pub fn from_row(r: &Value, strict: bool) -> Res<OsData> {
        let t = |k: &str| if strict { opt_text(r, k) } else { Ok(s(r, k).to_string()) };
        Ok(OsData {
            hostname: t("hostname")?,
            architecture: t("architecture")?,
            name: t("os_name")?,
            codename: t("os_codename")?,
            major: t("os_major")?,
            minor: t("os_minor")?,
            patch: t("os_patch")?,
            build: t("os_build")?,
            platform: t("os_platform")?,
            version: t("os_version")?,
            release: t("os_release")?,
            display_version: t("os_display_version")?,
            sysname: t("sysname")?,
            kernel_version: t("version")?,
            kernel_release: t("release")?,
            cpe_name: String::new(),
        })
    }

    /// CPE name from the OS CPE rules (9.1).
    pub fn build_cpe(&mut self, rules: &Value) {
        self.cpe_name = String::new();
        let Some(m) = rules.as_object() else { return };
        let mut keys: Vec<&String> = m.keys().collect();
        keys.sort();
        let hit = keys.iter().rev().find(|k| {
            k.as_str() == self.name || (!self.name.is_empty() && self.name.starts_with(k.as_str())) || k.as_str() == self.platform
        });
        let Some(k) = hit else { return };
        let t = m[k.as_str()].as_str().unwrap_or("");
        let t = t
            .replace("$(MAJOR_VERSION)", &self.major)
            .replace("$(MINOR_VERSION)", &self.minor)
            .replace("$(DISPLAY_VERSION)", &self.display_version)
            .replace("$(VERSION)", &self.version)
            .replace("$(RELEASE)", &self.release)
            .replace("$(VERSION_UPDATE_HYPHEN)", &self.version.replace('-', ":"));
        // An empty template result leaves the CPE name empty.
        if !t.is_empty() {
            self.cpe_name = format!("cpe:/o:{}", t.to_ascii_lowercase());
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Agent {
    pub id: String,
    pub ip: String,
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Cond {
    Equal(String),
    LessThan(String),
    LessOrEqual(String),
    Default,
}

impl Cond {
    pub fn text(&self) -> String {
        match self {
            Cond::Equal(v) => format!("Package equal to {v}"),
            Cond::LessThan(v) => format!("Package less than {v}"),
            Cond::LessOrEqual(v) => format!("Package less than or equal to {v}"),
            Cond::Default => "Package default status".into(),
        }
    }
}

/// Everything one event carries through its chain.
pub struct Ctx {
    pub origin: Origin,
    pub body: Value,
    pub ty: EventType,
    pub component: Component,
    pub agent: Agent,
    pub os: OsData,
    pub no_index: bool,
    pub full: bool,
    /// (CNA, expanded name) used for descriptions.
    pub vuln_source: (String, String),
    /// CVE -> element (object) or list of deletions (hotfix chain).
    pub elements: BTreeMap<String, Value>,
    pub conditions: HashMap<String, Cond>,
    pub detection: HashMap<String, String>,
    pub alerts: BTreeMap<String, Value>,
    pub first_os_scan: bool,
    pub hotfix: String,
}

impl Ctx {
    pub fn new(ev: &Event, ty: EventType, component: Component) -> Res<Ctx> {
        let ai = ev.body.get("agent_info").cloned().unwrap_or(Value::Null);
        let no_index = if ev.origin == Origin::Json {
            match ev.body.get("no-index") {
                None => false,
                Some(Value::Bool(b)) => *b,
                Some(o) => return Err(Error::Json { id: 302, text: format!("JSON value must be boolean, but is {}", type_name(o)) }),
            }
        } else {
            false
        };
        Ok(Ctx {
            origin: ev.origin,
            body: ev.body.clone(),
            ty,
            component,
            agent: Agent {
                id: pad_agent(s(&ai, "agent_id")),
                ip: s(&ai, "agent_ip").into(),
                name: s(&ai, "agent_name").into(),
                version: s(&ai, "agent_version").into(),
            },
            os: OsData::default(),
            no_index,
            full: ev.origin == Origin::Json && ev.body.get("full") == Some(&Value::Bool(true)),
            vuln_source: (String::new(), String::new()),
            elements: BTreeMap::new(),
            conditions: HashMap::new(),
            detection: HashMap::new(),
            alerts: BTreeMap::new(),
            first_os_scan: false,
            hotfix: String::new(),
        })
    }

    /// The inventory row of the event.
    pub fn row(&self) -> &Value {
        static NULL: Value = Value::Null;
        match self.origin {
            Origin::Rsync => self.body.pointer("/data/attributes").unwrap_or(&NULL),
            _ => self.body.get("data").unwrap_or(&NULL),
        }
    }

    /// A text field of the row. Delta and sync messages read non-text fields as empty; data of
    /// JSON actions must be texts (error 303).
    pub fn field(&self, k: &str) -> Res<String> {
        match self.row().get(k) {
            Some(Value::String(x)) => Ok(x.clone()),
            Some(o) if self.origin == Origin::Json => {
                Err(Error::Json { id: 303, text: format!("JSON value is not a text, actual type is {}", type_name(o)) })
            }
            _ => Ok(String::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encoding_and_padding() {
        let e = Event::json(json!({"action":"reboot"}));
        assert_eq!(e.encode(), b"j{\"action\":\"reboot\"}");
        assert_eq!(Event::decode(&e.encode()).unwrap(), e);
        assert!(Event::decode(b"x{}").is_none());
        assert_eq!((pad_agent("1"), pad_agent("1234"), pad_agent("")), ("001".into(), "1234".into(), "000".into()));
    }

    #[test]
    fn classification() {
        let d = |v: Value| classify(&Event { origin: Origin::Delta, body: v });
        assert_eq!(d(json!({"data_type":"dbsync_packages"})).unwrap_err(), Error::Other("Operation not found in delta.".into()));
        assert_eq!(d(json!({"data_type":"dbsync_packages","operation":"MODIFIED"})).unwrap(), (EventType::Unknown, Component::Package));
        assert_eq!(d(json!({"data_type":"dbsync_osinfo","operation":"DELETED"})).unwrap().0, EventType::Os);
        let j = |v: Value| classify(&Event::json(v));
        assert_eq!(j(json!({"foo":1})).unwrap_err(), Error::Json { id: 403, text: "JSON key 'action' not found".into() });
        assert_eq!(j(json!([1])).unwrap_err(), Error::Other("Unable to build scan context. Unknown JSON format".into()));
        assert_eq!(j(json!({"action":"bogus"})).unwrap_err(), Error::Other("Unable to build scan context. Unknown action".into()));
        assert_eq!(j(json!({"action":"upgradeAgentDB","data":{"new_db_version":15}})).unwrap().0, EventType::CleanupOne);
        assert_eq!(j(json!({"action":"upgradeAgentDB","data":{"new_db_version":true}})).unwrap().0, EventType::Unknown);
        assert_eq!(j(json!({"action":"upgradeAgentDB"})).unwrap_err(), Error::Json { id: 403, text: "JSON key 'data' not found".into() });
        assert!(matches!(j(json!({"action":"upgradeAgentDB","data":{"new_db_version":"x"}})).unwrap_err(), Error::Json { id: 302, .. }));
        let r = |v: Value| classify(&Event { origin: Origin::Rsync, body: v });
        assert_eq!(r(json!({"data_type":"integrity_check_global","data":{"attributes_type":"syscollector_osinfo"}})).unwrap(), (EventType::GlobalSync, Component::Agent));
        let e = Event::json(json!({"action":"reboot","no-index":1}));
        assert!(matches!(Ctx::new(&e, EventType::RescanAll, Component::Agent), Err(Error::Json { id: 302, .. })));
    }

    #[test]
    fn cpe_from_rules() {
        let mut os = OsData { name: "Microsoft Windows 10 Pro".into(), display_version: "22H2".into(), version: "10.0.19045.3803".into(), platform: "windows".into(), ..Default::default() };
        os.build_cpe(&json!({"Microsoft Windows 10": "microsoft:windows_10_$(DISPLAY_VERSION):$(VERSION)", "Microsoft": "x"}));
        assert_eq!(os.cpe_name, "cpe:/o:microsoft:windows_10_22h2:10.0.19045.3803");
        os.build_cpe(&json!({"Linux": "x"}));
        assert_eq!(os.cpe_name, "");
        // D30: an empty template result leaves the name empty.
        os.build_cpe(&json!({"Microsoft Windows 10": ""}));
        assert_eq!(os.cpe_name, "");
        // D31: event rows read non-text fields as empty; JSON action data must be texts.
        assert_eq!(OsData::from_row(&json!({"os_name":5}), false).unwrap().name, "");
        assert!(OsData::from_row(&json!({"os_name":5}), true).is_err());
        let d = Event { origin: Origin::Delta, body: json!({"data":{"name":1}}) };
        assert_eq!(Ctx::new(&d, EventType::PackageInsert, Component::Package).unwrap().field("name").unwrap(), "");
        let j = Event::json(json!({"action":"deletePackage","data":{"item_id":1}}));
        assert!(matches!(Ctx::new(&j, EventType::PackageDelete, Component::Package).unwrap().field("item_id"), Err(Error::Json { id: 303, .. })));
    }
}
