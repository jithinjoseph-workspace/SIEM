//! `<command>` and `<active-response>` (config/active-response.c):
//! `ReadActiveCommands` / `ReadActiveResponses`, as used by `AR_ReadConfig`.

use crate::messages;
use crate::{ConfigError, Result};
use siem_xml::XmlNode;

/* ar.h */
pub const ALL_AGENTS: i32 = 0o0000001;
pub const REMOTE_AGENT: i32 = 0o0000002;
pub const SPECIFIC_AGENT: i32 = 0o0000004;
pub const AS_ONLY: i32 = 0o0000010;
pub const REMOTE_AGENT_C: u8 = b'R';
pub const SPECIFIC_AGENT_C: u8 = b'S';
pub const NONE_C: u8 = b'N';
pub const REMOTE_AR: i32 = 0o00001;
pub const LOCAL_AR: i32 = 0o00002;

/// Lines `AR_ReadConfig` writes first to `etc/shared/ar.conf`.
pub const AR_CONF_HEADER: &str = "restart-ossec0 - restart-ossec.sh - 0\nrestart-ossec0 - restart-ossec.cmd - 0\n\
restart-wazuh0 - restart-ossec.sh - 0\nrestart-wazuh0 - restart-ossec.cmd - 0\n\
restart-wazuh0 - restart-wazuh - 0\nrestart-wazuh0 - restart-wazuh.exe - 0\n";

/// `ar_command`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArCommand {
    pub timeout_allowed: bool,
    pub name: String,
    pub executable: String,
    pub extra_args: Option<String>,
}

/// `active_response`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActiveResponse {
    pub timeout: i32,
    pub location: i32,
    pub level: i32,
    /// `<cmd name><timeout>`
    pub name: String,
    pub command: String,
    pub agent_id: Option<String>,
    pub rules_id: Option<String>,
    pub rules_group: Option<String>,
    /// Index into the command list.
    pub ar_cmd: usize,
}

/// State `ReadConfig(CAR)` fills: the command list, the responses, `ar_flag`
/// and the text appended to `ar.conf`.
#[derive(Debug, Clone, Default)]
pub struct ArConfig {
    pub commands: Vec<ArCommand>,
    pub responses: Vec<ActiveResponse>,
    pub ar_flag: i32,
    pub ar_conf: String,
    /// Debug / info messages the C code logs (`mdebug1`, `minfo`).
    pub notes: Vec<String>,
}

fn content(n: &XmlNode) -> Result<&str> {
    n.content.as_deref().ok_or_else(|| ConfigError::new(messages::xml_valuenull(&n.element)))
}

/// C `atoi`
fn atoi(s: &str) -> i32 {
    crate::util::atoi(s)
}

/// `ReadActiveCommands`
pub fn read_active_commands(nodes: &[XmlNode], cfg: &mut ArConfig) -> Result<()> {
    let mut name: Option<String> = None;
    let mut executable: Option<String> = None;
    let mut timeout_allowed = false;
    let mut extra_args: Option<String> = None;
    for n in nodes {
        let c = content(n)?;
        match n.element.as_str() {
            "name" => {
                if c.starts_with('!') {
                    return Err(ConfigError::new(messages::xml_valueerr(&n.element, c)));
                }
                name = Some(c.to_string());
            }
            "expect" => cfg.notes.push("The <expect> tag is deprecated since version 4.2.0.".into()),
            "executable" => executable = Some(c.to_string()),
            "timeout_allowed" => {
                timeout_allowed = match c {
                    "yes" => true,
                    "no" => false,
                    _ => return Err(ConfigError::new(messages::xml_valueerr(&n.element, c))),
                }
            }
            "extra_args" => extra_args = Some(c.to_string()),
            e => return Err(ConfigError::new(messages::xml_invelem(e))),
        }
    }
    let (Some(name), Some(executable)) = (name, executable) else {
        return Err(ConfigError::new("(1280): Missing command options. You must specify a 'name' and 'executable'."));
    };
    cfg.commands.push(ArCommand { timeout_allowed, name, executable, extra_args });
    Ok(())
}

/// `ReadActiveResponses`. Disabled responses (and some invalid ones) are
/// skipped without error, as in C.
pub fn read_active_responses(nodes: &[XmlNode], cfg: &mut ArConfig) -> Result<()> {
    let mut ar = ActiveResponse::default();
    let mut command: Option<String> = None;
    let mut location: Option<String> = None;
    let mut rpt = false;
    for n in nodes {
        let c = content(n)?;
        match n.element.as_str() {
            "command" => command = Some(c.to_string()),
            "location" => location = Some(c.to_string()),
            "agent_id" => ar.agent_id = Some(c.to_string()),
            "rules_id" => ar.rules_id = Some(c.to_string()),
            "rules_group" => ar.rules_group = Some(c.to_string()),
            "level" => {
                if !siem_regex::str_is_num(c) {
                    return Err(ConfigError::new(messages::xml_valueerr(&n.element, c)));
                }
                ar.level = atoi(c);
                if !(0..=20).contains(&ar.level) {
                    return Err(ConfigError::new(messages::xml_valueerr(&n.element, c)));
                }
            }
            "timeout" => ar.timeout = atoi(c),
            "disabled" => match c {
                "yes" => cfg.ar_flag = -1,
                "no" => {}
                _ => return Err(ConfigError::new(messages::xml_valueerr(&n.element, c))),
            },
            "repeated_offenders" => rpt = true,
            "ca_store" => {}
            e => return Err(ConfigError::new(messages::xml_invelem(e))),
        }
    }

    if cfg.ar_flag == -1 {
        cfg.ar_flag = 0;
        if let Some(c) = &command {
            cfg.notes.push(format!("active response command '{c}' is disabled"));
        }
        return Ok(());
    }

    let (Some(cmd), Some(loc)) = (command.filter(|c| !c.is_empty()), location.filter(|l| !l.is_empty())) else {
        cfg.notes.push("Command or location missing".into());
        if rpt {
            return Ok(());
        }
        return Err(ConfigError::new("(1281): Missing options in the active response configuration. "));
    };
    ar.command = cmd;

    if siem_regex::os_regex("AS|analysisd|analysis-server|server", &loc) {
        ar.location |= AS_ONLY;
    }
    if siem_regex::os_regex("local", &loc) {
        ar.location |= REMOTE_AGENT;
    }
    if siem_regex::os_regex("defined-agent", &loc) {
        let Some(id) = &ar.agent_id else {
            cfg.notes.push("'defined-agent' agent_id not defined".into());
            return Err(ConfigError::new("(1304): No agent defined for response."));
        };
        if atoi(id) == 0 {
            cfg.notes.push("'defined-agent' is 0".into());
            cfg.notes.push("(1306): Invalid agent ID. Use location=server to run AR on the manager.".into());
            return Ok(());
        }
        ar.location |= SPECIFIC_AGENT;
    }
    if siem_regex::os_regex("all|any", &loc) {
        ar.location |= ALL_AGENTS;
    }
    if ar.location == 0 {
        cfg.notes.push("No location defined".into());
        return Err(ConfigError::new(format!("(1302): Invalid active response location: '{loc}'.")));
    }

    let Some(idx) = cfg.commands.iter().position(|c| c.name == ar.command) else {
        cfg.notes.push("Invalid command".into());
        return Err(ConfigError::new(format!("(1303): Invalid command '{}' in the active response.", ar.command)));
    };
    ar.ar_cmd = idx;
    let c = &cfg.commands[idx];
    if ar.timeout != 0 && !c.timeout_allowed {
        cfg.notes.push(format!("(1305): Timeout not allowed for command: '{}'.", c.name));
        ar.timeout = 0;
    }

    // snprintf(name, OS_FLSIZE, "%s%d")
    let mut name = format!("{}{}", c.name, ar.timeout);
    name.truncate(255);
    ar.name = name;
    cfg.ar_conf.push_str(&format!("{} - {} - {}\n", ar.name, c.executable, ar.timeout));

    let (mut l_ar, mut r_ar) = (false, false);
    if ar.location & AS_ONLY != 0 {
        l_ar = true;
    }
    if ar.location & ALL_AGENTS != 0 {
        r_ar = true;
    }
    if ar.location & REMOTE_AGENT != 0 {
        r_ar = true;
        l_ar = true;
    }
    if ar.location & SPECIFIC_AGENT != 0 {
        r_ar = true;
    }
    if r_ar {
        cfg.ar_flag |= REMOTE_AR;
    }
    if l_ar {
        cfg.ar_flag |= LOCAL_AR;
    }
    cfg.responses.push(ar);
    Ok(())
}
