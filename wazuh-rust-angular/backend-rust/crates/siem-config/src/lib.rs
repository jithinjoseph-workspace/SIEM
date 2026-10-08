//! `siem-config`: port of Wazuh's configuration layer (`src/config/`).
//!
//! * [`read_config`] is `ReadConfig` + `read_main_elements`: it walks
//!   `<ossec_config>` (or `<agent_config>` in shared `agent.conf`) and hands each
//!   section to a [`ConfigHandler`] when the caller asked for that module.
//!   Unknown sections, and empty sections that Wazuh requires to have children,
//!   are rejected exactly as Wazuh rejects them.
//! * [`internal_options`] is `getDefine_Int` (`internal_options.conf` and
//!   `local_internal_options.conf`).
//! * Section readers live in their own modules (`global`, `remote`, ...).

pub mod active_response;
pub mod cluster;
pub mod global;
pub mod internal_options;
pub mod labels;
pub mod logtest;
pub mod messages;
pub mod remote;
pub mod socket;
pub mod util;

use siem_xml::{OsXml, XmlNode};
use std::path::Path;

/// Module flags (`config.h`).
pub mod modules {
    pub const CGLOBAL: u32 = 0o0000000001;
    pub const CRULES: u32 = 0o0000000002;
    pub const CSYSCHECK: u32 = 0o0000000004;
    pub const CROOTCHECK: u32 = 0o0000000010;
    pub const CALERTS: u32 = 0o0000000020;
    pub const CLOCALFILE: u32 = 0o0000000040;
    pub const CREMOTE: u32 = 0o0000000100;
    pub const CCLIENT: u32 = 0o0000000200;
    pub const CMAIL: u32 = 0o0000000400;
    pub const CAR: u32 = 0o0000001000;
    pub const CSYSLOGD: u32 = 0o0000004000;
    pub const CAGENT_CONFIG: u32 = 0o0000010000;
    pub const CAGENTLESS: u32 = 0o0000020000;
    pub const CREPORTS: u32 = 0o0000040000;
    pub const CINTEGRATORD: u32 = 0o0000100000;
    pub const CWMODULE: u32 = 0o0000200000;
    pub const CLABELS: u32 = 0o0000400000;
    pub const CAUTHD: u32 = 0o0001000000;
    pub const CBUFFER: u32 = 0o0002000000;
    pub const CCLUSTER: u32 = 0o0004000000;
    pub const CLGCSOCKET: u32 = 0o0010000000;
    pub const CANDSOCKET: u32 = 0o0020000000;
    pub const WAZUHDB: u32 = 0o0040000000;
    pub const CLOGTEST: u32 = 0o0100000000;
    pub const ATAMPERING: u32 = 0o0200000000;
}
use modules::*;

/// A configuration error, carrying the message Wazuh would log with `merror`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

impl ConfigError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, ConfigError>;

/// Build flavour, mirroring the C `#ifdef`s that change parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Platform {
    /// `CLIENT` (agent build).
    pub client: bool,
    /// `WIN32`.
    pub windows: bool,
}

impl Platform {
    pub const MANAGER: Platform = Platform { client: false, windows: false };
    pub const LINUX_AGENT: Platform = Platform { client: true, windows: false };
    pub const WINDOWS_AGENT: Platform = Platform { client: true, windows: true };
}

/// Identity of the agent evaluating `<agent_config name/os/profile>` filters
/// (only consulted on [`Platform::client`]).
#[derive(Debug, Clone, Default)]
pub struct AgentIdentity {
    pub name: Option<String>,
    pub uname: Option<String>,
    pub profile: Option<String>,
}

/// Warnings collected while parsing (Wazuh `mwarn`), plus context.
#[derive(Debug, Clone)]
pub struct ConfigContext {
    pub platform: Platform,
    pub agent: AgentIdentity,
    pub warnings: Vec<String>,
}

impl ConfigContext {
    pub fn new(platform: Platform) -> Self {
        Self { platform, agent: AgentIdentity::default(), warnings: Vec::new() }
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        let m = msg.into();
        tracing::warn!("{m}");
        self.warnings.push(m);
    }
}

/// Every section `read_main_elements` knows about. Some sections reach the
/// handler twice under different names, because Wazuh calls two readers for
/// them: `syscheck` arrives as [`Section::Syscheck`] and [`Section::GlobalSyscheck`],
/// and `socket` as [`Section::LogcollectorSocket`] and [`Section::AnalysisdSocket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Section {
    Global,
    EmailAlerts,
    SyslogOutput,
    Integration,
    Agentless,
    Ruleset,
    Syscheck,
    /// `Read_GlobalSK` (the `<syscheck>` options analysisd reads under CGLOBAL).
    GlobalSyscheck,
    Rootcheck,
    Alerts,
    Localfile,
    Remote,
    Client,
    /// `Read_Client_Shared` (`<client>` inside `agent.conf`).
    ClientShared,
    AntiTampering,
    ClientBuffer,
    Command,
    ActiveResponse,
    Reports,
    Wodle,
    /// Deprecated `<wodle name="agent-key-polling">` read by authd.
    AuthdKeyRequest,
    Sca,
    VulnerabilityDetection,
    /// Deprecated `<vulnerability-detector>`.
    VulnerabilityDetector,
    Indexer,
    GcpPubsub,
    GcpBucket,
    FluentForward,
    Auth,
    Labels,
    Cluster,
    LogcollectorSocket,
    AnalysisdSocket,
    RuleTest,
    AgentUpgrade,
    TaskManager,
    WazuhDb,
    Github,
    Office365,
    MsGraph,
}

/// Receives the sections a daemon asked for.
pub trait ConfigHandler {
    /// `node` is the section element itself (attributes included), and
    /// `children` its child elements (`None` for an empty section).
    fn section(
        &mut self,
        ctx: &mut ConfigContext,
        xml: &OsXml,
        section: Section,
        node: &XmlNode,
        children: Option<&[XmlNode]>,
    ) -> Result<()>;
}

/// `read_main_elements`
fn read_main_elements(
    ctx: &mut ConfigContext,
    xml: &OsXml,
    mods: u32,
    nodes: &[XmlNode],
    h: &mut dyn ConfigHandler,
) -> Result<()> {
    let win = ctx.platform.windows;
    let client = ctx.platform.client;
    let gh_ms = true; // WIN32 || __linux__ || __MACH__

    for node in nodes {
        let children = xml.get_elements_by_node(Some(node));
        let ch = children.as_deref();
        let has = ch.is_some();
        let el = node.element.as_str();
        let mut call = |ctx: &mut ConfigContext, s: Section| h.section(ctx, xml, s, node, ch);

        if has && el == "global" {
            if mods & CGLOBAL != 0 || mods & CMAIL != 0 {
                call(ctx, Section::Global)?;
            }
        } else if has && el == "email_alerts" {
            if mods & CMAIL != 0 {
                call(ctx, Section::EmailAlerts)?;
            }
        } else if has && el == "database_output" {
            ctx.warn("The 'database_output' configuration is deprecated and no longer supported. This configuration will be ignored.");
        } else if has && el == "syslog_output" {
            if mods & CSYSLOGD != 0 {
                call(ctx, Section::SyslogOutput)?;
            }
        } else if has && el == "integration" {
            if mods & CINTEGRATORD != 0 {
                call(ctx, Section::Integration)?;
            }
        } else if has && el == "agentless" {
            if mods & CAGENTLESS != 0 {
                call(ctx, Section::Agentless)?;
            }
        } else if !win && has && el == "ruleset" {
            if mods & CRULES != 0 {
                call(ctx, Section::Ruleset)?;
            }
        } else if el == "syscheck" {
            if mods & CSYSCHECK != 0 {
                call(ctx, Section::Syscheck)?;
            }
            if mods & CGLOBAL != 0 {
                call(ctx, Section::GlobalSyscheck)?;
            }
        } else if el == "rootcheck" {
            if mods & CROOTCHECK != 0 {
                call(ctx, Section::Rootcheck)?;
            }
        } else if has && el == "alerts" {
            if mods & CALERTS != 0 {
                call(ctx, Section::Alerts)?;
            }
        } else if has && el == "localfile" {
            if mods & CLOCALFILE != 0 {
                call(ctx, Section::Localfile)?;
            }
        } else if has && el == "remote" {
            if mods & CREMOTE != 0 {
                call(ctx, Section::Remote)?;
            }
        } else if has && el == "client" {
            if mods & CCLIENT != 0 {
                if mods & CAGENT_CONFIG != 0 {
                    call(ctx, Section::ClientShared)?;
                } else {
                    call(ctx, Section::Client)?;
                }
            }
        } else if !win && has && el == "anti_tampering" {
            if mods & ATAMPERING != 0 {
                call(ctx, Section::AntiTampering)?;
            }
        } else if el == "client_buffer" {
            if mods & CBUFFER != 0 {
                call(ctx, Section::ClientBuffer)?;
            }
        } else if has && el == "command" {
            if mods & CAR != 0 {
                call(ctx, Section::Command)?;
            }
        } else if has && el == "active-response" {
            if mods & CAR != 0 {
                call(ctx, Section::ActiveResponse)?;
            }
        } else if !win && has && el == "reports" {
            if mods & CREPORTS != 0 {
                call(ctx, Section::Reports)?;
            }
        } else if el == "wodle" {
            // if ((modules & CWMODULE) && Read_WModule() < 0) fail;
            // else if (!CLIENT && attributes[0] == "name" && values[0] == key_polling) ...
            if mods & CWMODULE != 0 {
                call(ctx, Section::Wodle)?;
            }
            if !client
                && node.attributes.first().map(String::as_str) == Some("name")
                && node.values.first().map(String::as_str) == Some("agent-key-polling")
                && mods & CAUTHD != 0
            {
                call(ctx, Section::AuthdKeyRequest)?;
            }
        } else if el == "sca" {
            if mods & CWMODULE != 0 {
                call(ctx, Section::Sca)?;
            }
        } else if el == "vulnerability-detection" {
            if !win && !client {
                if mods & CWMODULE != 0 {
                    call(ctx, Section::VulnerabilityDetection)?;
                }
            } else {
                ctx.warn(format!("{el} configuration is only set in the manager."));
            }
        } else if el == "vulnerability-detector" {
            if !win && !client {
                if mods & CWMODULE != 0 {
                    ctx.warn("The 'vulnerability-detector' configuration is deprecated, please update your settings to use the new 'vulnerability-detection' instead (default values will be used based on your previous configurations). See https://documentation.wazuh.com");
                    call(ctx, Section::VulnerabilityDetector)?;
                }
            } else {
                ctx.warn(format!("{el} configuration is only set in the manager."));
            }
        } else if el == "indexer" {
            if !win && !client {
                if mods & CWMODULE != 0 {
                    call(ctx, Section::Indexer)?;
                }
            } else {
                ctx.warn(format!("{el} configuration is only set in the manager."));
            }
        } else if el == "gcp-pubsub" {
            if mods & CWMODULE != 0 {
                call(ctx, Section::GcpPubsub)?;
            }
        } else if el == "gcp-bucket" {
            if mods & CWMODULE != 0 {
                call(ctx, Section::GcpBucket)?;
            }
        } else if !win && el == "fluent-forward" {
            if mods & CWMODULE != 0 {
                call(ctx, Section::FluentForward)?;
            }
        } else if !win && el == "auth" {
            if mods & CAUTHD != 0 {
                call(ctx, Section::Auth)?;
            }
        } else if has && el == "labels" {
            if mods & CLABELS != 0 {
                call(ctx, Section::Labels)?;
            }
        } else if el == "logging" {
        } else if has && el == "cluster" {
            if mods & CCLUSTER != 0 {
                call(ctx, Section::Cluster)?;
            }
        } else if has && el == "socket" {
            if mods & CLGCSOCKET != 0 {
                call(ctx, Section::LogcollectorSocket)?;
            }
            if mods & CANDSOCKET != 0 {
                call(ctx, Section::AnalysisdSocket)?;
            }
        } else if has && el == "rule_test" {
            if mods & CLOGTEST != 0 {
                call(ctx, Section::RuleTest)?;
            }
        } else if has && el == "agent-upgrade" {
            if mods & CWMODULE != 0 && mods & CAGENT_CONFIG == 0 {
                call(ctx, Section::AgentUpgrade)?;
            }
        } else if has && el == "task-manager" {
            if !win && !client {
                if mods & CWMODULE != 0 {
                    call(ctx, Section::TaskManager)?;
                }
            } else {
                ctx.warn(format!("{el} configuration is only set in the manager."));
            }
        } else if has && el == "wdb" {
            if !client {
                if mods & WAZUHDB != 0 {
                    call(ctx, Section::WazuhDb)?;
                }
            } else {
                ctx.warn(format!("{el} configuration is only set in the manager."));
            }
        } else if gh_ms && has && el == "github" {
            if mods & CWMODULE != 0 {
                call(ctx, Section::Github)?;
            }
        } else if gh_ms && has && el == "office365" {
            if mods & CWMODULE != 0 {
                call(ctx, Section::Office365)?;
            }
        } else if gh_ms && has && el == "ms-graph" {
            if mods & CWMODULE != 0 {
                call(ctx, Section::MsGraph)?;
            }
        } else {
            return Err(ConfigError::new(messages::xml_invelem(el)));
        }
    }
    Ok(())
}

/// `ReadConfig`. `remote_conf` is the value of the internal option
/// `agent.remote_conf`, consulted only for `CAGENT_CONFIG` reads.
pub fn read_config(
    ctx: &mut ConfigContext,
    mods: u32,
    cfgfile: impl AsRef<Path>,
    remote_conf: Option<bool>,
    h: &mut dyn ConfigHandler,
) -> Result<()> {
    let cfgfile = cfgfile.as_ref();
    if mods & CAGENT_CONFIG != 0 && remote_conf == Some(false) {
        return Ok(());
    }
    let xml = OsXml::read_file(cfgfile, false)
        .map_err(|e| ConfigError::new(messages::xml_error(&cfgfile.display().to_string(), &e.message, e.line)))?;
    read_config_xml(ctx, mods, &xml, &cfgfile.display().to_string(), h)
}

/// The body of `ReadConfig` for an already parsed document.
pub fn read_config_xml(
    ctx: &mut ConfigContext,
    mods: u32,
    xml: &OsXml,
    cfgname: &str,
    h: &mut dyn ConfigHandler,
) -> Result<()> {
    let Some(nodes) = xml.get_elements_by_node(None) else { return Ok(()) };
    for node in &nodes {
        if mods & CAGENT_CONFIG == 0 && node.element == "ossec_config" {
            if let Some(ch) = xml.get_elements_by_node(Some(node)) {
                read_main_elements(ctx, xml, mods, &ch, h)?;
            }
        } else if mods & CAGENT_CONFIG != 0 && node.element == "agent_config" {
            let mut passed = true;
            if !node.attributes.is_empty() {
                for (a, v) in node.attributes.iter().zip(&node.values) {
                    match a.as_str() {
                        "name" => {
                            if ctx.platform.client {
                                passed &= agent_filter(ctx, "name", v, ctx.agent.name.clone());
                            }
                        }
                        "os" => {
                            if ctx.platform.client {
                                passed &= agent_filter(ctx, "OS", v, ctx.agent.uname.clone());
                            }
                        }
                        "profile" => {
                            if ctx.platform.client {
                                passed &= agent_filter(ctx, "profile", v, ctx.agent.profile.clone());
                            }
                        }
                        "overwrite" => {}
                        other => {
                            tracing::error!("{}", messages::xml_invattr(other, cfgname));
                        }
                    }
                }
            } else if ctx.platform.client && ctx.agent.profile.is_none() {
                // Generic block: only read when the agent has no profile... the C
                // code inverts this (passed = 0 when the agent has NO profile).
                passed = false;
            }
            if let Some(ch) = xml.get_elements_by_node(Some(node)) {
                if passed {
                    read_main_elements(ctx, xml, mods, &ch, h)
                        .map_err(|_| ConfigError::new(messages::config_error(cfgname)))?;
                }
            }
        } else {
            return Err(ConfigError::new(messages::xml_invelem(&node.element)));
        }
    }
    Ok(())
}

fn agent_filter(ctx: &mut ConfigContext, what: &str, pattern: &str, value: Option<String>) -> bool {
    match value {
        None => {
            let item = match what {
                "name" => "Unable to retrieve the agent name.",
                "OS" => "Unable to retrieve the agent OS.",
                _ => "Unable to retrieve agent profile.",
            };
            tracing::error!("Reading shared configuration. {item}");
            false
        }
        Some(v) => {
            if pattern.len() > siem_regex::OS_PATTERN_MAXSIZE {
                ctx.warn(format!(
                    "Agent {what} filter ({} bytes) exceeds the limit ({})",
                    pattern.len(),
                    siem_regex::OS_PATTERN_MAXSIZE
                ));
                false
            } else {
                siem_regex::os_match2(pattern, &v)
            }
        }
    }
}
