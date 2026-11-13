//! The `<agentless>` sections of `etc/ossec.conf`, the check every service makes of the other
//! sections, and the `getconfig` answers.

use std::path::Path;

use provigil_daemon::xml::{self, Node};
use provigil_json::Json;

use crate::{cut, SCRIPTS};

pub const CONNECTED: i32 = 0x001;
pub const PERIODIC: i32 = 0x002;
pub const DIFF: i32 = 0x004;

/// One `<agentless>` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub state: i32,
    pub frequency: i32,
    /// When the checks last ran.
    pub last_run: i64,
    pub port: i32,
    /// Failures so far; 99 once given up.
    pub errors: i32,
    /// The script under `agentless/`.
    pub kind: String,
    /// Hosts, each after a mark: ' ' plain, 's' with `su`, 'o' with `sudo`.
    pub hosts: Vec<String>,
    pub arguments: String,
    pub command: Option<String>,
}

/// A log line from reading the settings: (level, text).
pub type Note = (&'static str, String);

fn invalid_element(e: &str) -> String {
    format!("(1230): Invalid element in the configuration: '{e}'.")
}

fn invalid_value(e: &str, v: &str) -> String {
    format!("(1235): Invalid value for element '{e}': {v}.")
}

/// The sections a manager accepts in `<ossec_config>`: (name, must have child elements).
const SECTIONS: &[(&str, bool)] = &[
    ("global", true),
    ("email_alerts", true),
    ("database_output", true),
    ("syslog_output", true),
    ("integration", true),
    ("agentless", true),
    ("ruleset", true),
    ("syscheck", false),
    ("rootcheck", false),
    ("alerts", true),
    ("localfile", true),
    ("remote", true),
    ("client", true),
    ("anti_tampering", true),
    ("client_buffer", false),
    ("command", true),
    ("active-response", true),
    ("reports", true),
    ("wodle", false),
    ("sca", false),
    ("vulnerability-detection", false),
    ("vulnerability-detector", false),
    ("indexer", false),
    ("gcp-pubsub", false),
    ("gcp-bucket", false),
    ("fluent-forward", false),
    ("auth", false),
    ("labels", true),
    ("logging", false),
    ("cluster", true),
    ("socket", true),
    ("rule_test", true),
    ("agent-upgrade", true),
    ("task-manager", true),
    ("wdb", true),
    ("github", true),
    ("office365", true),
    ("ms-graph", true),
];

/// A whole number of a field (digits only).
fn number(e: &str, v: &str) -> Result<i32, String> {
    if !provigil_regex::str_is_num(v) {
        return Err(invalid_value(e, v));
    }
    Ok(v.trim().parse::<i32>().unwrap_or(0))
}

/// One `<agentless>` section. Err: the text of the first problem.
fn section(home: &Path, fields: &[Node], notes: &mut Vec<Note>) -> Result<Entry, String> {
    let mut e = Entry { state: 0, frequency: 86400, last_run: 0, port: 0, errors: 0, kind: String::new(), hosts: Vec::new(), arguments: String::new(), command: None };
    for f in fields {
        if f.name.is_empty() {
            return Err("(1231): Invalid NULL element in the configuration.".into());
        }
        let v = f.content.as_str();
        match f.name.as_str() {
            "frequency" => e.frequency = number(&f.name, v)?,
            "port" => e.port = number(&f.name, v)?,
            "host" => {
                let h = if let Some(r) = v.strip_prefix("use_su ") {
                    format!("s{r}")
                } else if let Some(r) = v.strip_prefix("use_sudo ") {
                    format!("o{r}")
                } else {
                    format!(" {v}")
                };
                e.hosts.push(cut(h));
            }
            "type" => {
                let script = cut(format!("{SCRIPTS}/{v}"));
                if provigil_fileop::ref_parent_folder(&script) {
                    return Err(format!("Invalid Agentless type '{v}': it contains references to parent folder."));
                }
                if provigil_fileop::mtime(&home.join(&script).to_string_lossy()).unwrap_or(-1) <= 0 {
                    notes.push(("ERROR", format!("Unable to find '{v}' at '{SCRIPTS}'.")));
                    return Err(invalid_value(&f.name, v));
                }
                e.kind = v.to_string();
            }
            "run_command" => e.command = Some(v.to_string()),
            "arguments" => e.arguments = v.to_string(),
            "state" => match v {
                "periodic" => e.state |= PERIODIC,
                "stay_connected" => e.state |= CONNECTED,
                "periodic_diff" => e.state |= PERIODIC | DIFF,
                _ => return Err(invalid_value(&f.name, v)),
            },
            other => return Err(invalid_element(other)),
        }
    }
    if e.hosts.is_empty() || e.state == 0 || e.kind.is_empty() {
        return Err("(7103): Missing agentless options.".into());
    }
    if e.state == PERIODIC && e.frequency == 0 {
        return Err("(7102): Frequency not set for the periodic option.".into());
    }
    Ok(e)
}

/// The `<agentless>` sections of `conf` (relative to `home`), after checking the document: only
/// `<ossec_config>` roots, and in them only known sections. None: the settings are not usable
/// (`notes` tells why).
pub fn read(home: &Path, conf: &str, notes: &mut Vec<Note>) -> Option<Vec<Entry>> {
    let roots = match xml::read_file(&home.join(conf)) {
        Ok(r) => r,
        Err(e) => {
            notes.push(("ERROR", format!("(1226): Error reading XML file '{conf}': {} (line {}).", e.message, e.line)));
            return None;
        }
    };
    let mut list = Vec::new();
    for root in &roots {
        if root.name != "ossec_config" {
            notes.push(("ERROR", invalid_element(&root.name)));
            return None;
        }
        for s in &root.children {
            let has = !s.children.is_empty();
            let known = SECTIONS.iter().any(|(n, needs)| *n == s.name && (has || !needs));
            let outcome = if !known {
                Err(invalid_element(&s.name))
            } else if s.name == "agentless" {
                section(home, &s.children, notes).map(|e| list.push(e))
            } else {
                if s.name == "database_output" {
                    notes.push(("WARNING", "The 'database_output' configuration is deprecated and no longer supported. This configuration will be ignored.".into()));
                }
                Ok(())
            };
            if let Err(m) = outcome {
                notes.push(("ERROR", m));
                notes.push(("ERROR", format!("(1202): Configuration error at '{conf}'.")));
                return None;
            }
        }
    }
    Some(list)
}

/// `{"agentless":[{..}, ..]}`
pub fn to_json(list: &[Entry]) -> Json {
    let items = list
        .iter()
        .map(|e| {
            let mut o = Json::object();
            o.add("host", Json::Array(e.hosts.iter().map(Json::string).collect()));
            o.add("port", Json::number(e.port as f64));
            o.add("frequency", Json::number(e.frequency as f64));
            let state = if e.state & PERIODIC != 0 && e.state & DIFF != 0 {
                Some("periodic_diff")
            } else if e.state & CONNECTED != 0 {
                Some("stay_connected")
            } else if e.state & PERIODIC != 0 {
                Some("periodic")
            } else {
                None
            };
            if let Some(s) = state {
                o.add("state", Json::string(s));
            }
            o.add("arguments", Json::string(&e.arguments));
            if let Some(c) = &e.command {
                o.add("run_command", Json::string(c));
            }
            o.add("type", Json::string(&e.kind));
            o
        })
        .collect();
    let mut root = Json::object();
    root.add("agentless", Json::Array(items));
    root
}

/// The answer to a request on `queue/sockets/agentless` (`getconfig agentless`).
pub fn dispatch(list: &[Entry], request: &[u8], debug: &dyn Fn(String)) -> String {
    let request = String::from_utf8_lossy(&request[..request.iter().position(|&c| c == 0).unwrap_or(request.len())]).into_owned();
    let (command, args) = match request.split_once(' ') {
        Some((c, a)) => (c, Some(a)),
        None => (request.as_str(), None),
    };
    if command != "getconfig" {
        debug(format!("LESSDCOM Unrecognized command '{command}'."));
        return "err Unrecognized command".into();
    }
    match args {
        None => {
            debug("LESSDCOM getconfig needs arguments.".into());
            "err LESSDCOM getconfig needs arguments".into()
        }
        Some("agentless") => format!("ok {}", String::from_utf8_lossy(&to_json(list).print_unformatted())),
        Some(s) => {
            debug(format!("At LESSDCOM getconfig: Could not get '{s}' section"));
            "err Could not get requested section".into()
        }
    }
}
