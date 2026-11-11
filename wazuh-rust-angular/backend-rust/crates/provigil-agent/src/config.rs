//! Dynamic Configuration for ProVigil Endpoint Agent.
//!
//! Fully configuration-driven: supports JSON configuration files,
//! environment variables, and command-line flags. Zero hardcoded parameters.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// URL of the ProVigil manager, as the installer wrote it (the address the console is
    /// hosted at, e.g. `https://siem.example.com` or `http://10.0.0.5:8088`). No default:
    /// an agent never guesses its manager.
    #[serde(default)]
    pub manager_url: String,
    /// The manager's gRPC address (`grpc://host:8089`, `grpcs://...`): used first for
    /// `manager_url`'s manager, HTTPS for 10 minutes after 3 failed gRPC connections.
    #[serde(default)]
    pub grpc_url: String,
    /// Accept any manager certificate (self-signed lab managers); off, it is verified.
    #[serde(default)]
    pub tls_insecure: bool,
    /// Tenant enrollment key provided in the ProVigil dashboard.
    #[serde(default)]
    pub tenant_key: String,
    /// Display name of the agent (defaults to local hostname if empty).
    #[serde(default)]
    pub agent_name: String,
    /// Keepalive heartbeat interval in seconds (default: 10s).
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
    /// Windows Event Log channels to monitor.
    #[serde(default = "default_event_channels")]
    pub event_channels: Vec<String>,
    /// XPath filter per channel name (a channel without an entry gets every event).
    #[serde(default = "default_event_channel_queries")]
    pub event_channel_queries: HashMap<String, String>,
    /// Seconds between attempts to subscribe again after a channel's subscription failed.
    #[serde(default = "default_event_channel_reconnect")]
    pub event_channel_reconnect_secs: u64,
    /// Directories monitored for File Integrity Monitoring (FIM).
    #[serde(default = "default_fim_paths")]
    pub fim_paths: Vec<PathBuf>,
    /// FIM baseline scan interval in seconds (default: 43200 s / 12 h).
    #[serde(default = "default_fim_interval")]
    pub fim_scan_interval_secs: u64,
    /// Folders watched in real time (also scanned on schedule).
    #[serde(default)]
    pub fim_realtime: Vec<String>,
    /// Folders watched in real time with who-data; a folder in both lists is who-data.
    #[serde(default)]
    pub fim_whodata: Vec<String>,
    /// Paths never reported: a file or folder (case-insensitive), or `regex:<pattern>`.
    #[serde(default)]
    pub fim_ignore: Vec<String>,
    /// Scan events sent per second at most (0 = no limit); real-time events are not paced.
    #[serde(default = "default_fim_max_files_per_second")]
    pub fim_max_files_per_second: u32,
    /// Files or folders (as `fim_ignore`) whose changes carry a diff (all files when `diff_enabled`).
    #[serde(default)]
    pub fim_report_changes: Vec<String>,
    /// Files or folders (as `fim_ignore`) never diffed.
    #[serde(default)]
    pub fim_nodiff: Vec<String>,
    /// Folder levels scanned below each monitored folder.
    #[serde(default = "default_fim_recursion_level")]
    pub fim_recursion_level: u32,
    /// Files monitored at most; new files past it are not.
    #[serde(default = "default_fim_file_limit")]
    pub fim_file_limit: usize,
    /// Windows Registry persistence keys to monitor.
    /// `HKLM\...` or `HKEY_LOCAL_MACHINE\...`; a ` [x32]` suffix means the 32-bit view.
    #[serde(default = "default_registry_keys")]
    pub registry_keys: Vec<String>,
    /// Key prefixes (case-insensitive) never walked.
    #[serde(default)]
    pub registry_ignore: Vec<String>,
    /// Depth walked below each configured key.
    #[serde(default = "default_registry_recursion_level")]
    pub registry_recursion_level: u32,
    #[serde(default = "default_registry_scan_interval")]
    pub registry_scan_interval_secs: u64,
    /// Regular expressions (case-insensitive) on the full key path: when set, only matching keys
    /// are monitored (the walk still goes through the others).
    #[serde(default)]
    pub registry_restrict_key: Vec<String>,
    /// Regular expressions (case-insensitive) on the value name: when set, only matching values
    /// are monitored.
    #[serde(default)]
    pub registry_restrict_value: Vec<String>,
    /// Key prefixes (as `registry_ignore`) whose value data is sent with changes; other keys send
    /// hashes only. By default the default `registry_keys`: their data shows what starts at boot.
    #[serde(default = "default_registry_keys")]
    pub registry_report_changes: Vec<String>,
    /// System hardware/software inventory scan interval in seconds (default: 3600s / 1 hr).
    #[serde(default = "default_inventory_interval")]
    pub inventory_interval_secs: u64,
    /// Security Configuration Assessment (SCA) scan interval in seconds (default: 43200 s / 12 h).
    #[serde(default = "default_sca_interval")]
    pub sca_interval_secs: u64,
    /// Run configuration assessment scans.
    #[serde(default = "default_true")]
    pub sca_enabled: bool,
    /// Ids of the policies not scanned.
    #[serde(default)]
    pub sca_disabled_policies: Vec<String>,
    /// A full configuration assessment or inventory send waits a random 0 to this many seconds,
    /// so a fleet does not send at once (the scan itself runs at once). Unset: 300 for the first
    /// send of an install, 3600 for later ones (a new policy text, the manager asking).
    #[serde(default)]
    pub full_send_splay_secs: Option<u64>,
    /// Diffs for every monitored file's changes (off: only `fim_report_changes`).
    #[serde(default)]
    pub diff_enabled: bool,
    /// Maximum size of generated diff before truncation.
    #[serde(default = "default_max_diff")]
    pub diff_max_size: usize,
    /// Enable Windows Security Audit event correlation (Whodata) for FIM.
    #[serde(default = "default_true")]
    pub whodata_enabled: bool,
    /// Enable local Rootcheck and driver hook scanner.
    #[serde(default = "default_true")]
    pub rootcheck_enabled: bool,
    /// Rootcheck scan interval in seconds (default: 43200s / 12 hrs).
    #[serde(default = "default_rootcheck_interval")]
    pub rootcheck_interval_secs: u64,
    /// Extra rootcheck lists, added to the built-in ones (formats in `rootcheck_signatures.rs`):
    /// a files list, a trojans list and policy files.
    #[serde(default)]
    pub rootcheck_files_list: Option<PathBuf>,
    #[serde(default)]
    pub rootcheck_trojans_list: Option<PathBuf>,
    #[serde(default)]
    pub rootcheck_policies: Vec<PathBuf>,
    /// Which rootcheck checks run.
    #[serde(default)]
    pub rootcheck_checks: crate::rootcheck::RootcheckChecks,
    /// Where file names of the files list are searched.
    #[serde(default = "default_rootcheck_base_directory")]
    pub rootcheck_base_directory: String,
    /// Enable manager-orchestrated remote agent self-upgrade.
    #[serde(default = "default_true")]
    pub upgrade_enabled: bool,
    /// Maximum number of events to retain in offline ring buffer before dropping (default: 10,000).
    #[serde(default = "default_buffer_size")]
    pub buffer_max_events: usize,
    /// Log level (`trace`, `debug`, `info`, `warn`, `error`).
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Labels sent with every keepalive; the manager stores them.
    #[serde(default)]
    pub labels: Vec<Label>,
    /// Event buffer limits: queue size and sending pace.
    #[serde(default)]
    pub buffer: BufferConfig,
    /// Managers in failover order; empty means `[manager_url]`.
    #[serde(default)]
    pub manager_urls: Vec<String>,
    /// Consecutive failed requests before switching to the next manager.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Seconds to wait before switching to the next manager.
    #[serde(default = "default_retry_interval")]
    pub retry_interval_secs: u64,
    /// Log files and commands whose lines / output are sent to the manager (`logfiles.rs`).
    #[serde(default)]
    pub localfiles: Vec<LocalFile>,
    /// Command entries (`command`, `full_command`) from the group configuration are run only
    /// when this is set in the local file; local ones always are.
    #[serde(default)]
    pub allow_remote_commands: bool,
    /// Commands run on a schedule (`commands.rs`); the group's need `allow_remote_commands`.
    #[serde(default)]
    pub commands: Vec<crate::commands::ScheduledCommand>,
    #[serde(default)]
    pub osquery: crate::osquery::OsqueryConfig,
    /// Minutes: a timed response for a key that already ran N times in the last 24 h gets the
    /// N-th entry as its timeout (the last one when more).
    #[serde(default)]
    pub ar_repeated_offenders: Vec<u64>,
    /// A PEM file of CA certificates trusted for the manager, besides the built-in ones.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Run the manager's response commands.
    #[serde(default = "default_true")]
    pub active_response_enabled: bool,
    /// Groups asked for at enrollment, comma-separated.
    #[serde(default)]
    pub groups: String,
    /// The first enrollment after an install asks for a new key, even for a removed name (the
    /// install script sets it; see `identity::force_allowed`).
    #[serde(default)]
    pub force_enroll: bool,
}

/// One entry of `localfiles`: a log file (wildcards allowed) or a periodic command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalFile {
    /// File path; `*` and `?` allowed in file and folder names. Empty for commands.
    pub location: String,
    /// `syslog` (and its plain-line aliases), `json`, `multi-line:<n>`, `multi-line-regex`,
    /// `command`, `full_command`.
    pub log_format: String,
    pub command: String,
    pub alias: String,
    /// Seconds between command runs.
    pub frequency: u64,
    /// A file seen for the first time is read from its current end.
    pub only_future_events: bool,
    /// Files not modified for longer (`1d`, `12h`, `30m`, `90s`) are skipped.
    pub age: Option<String>,
    /// Wildcard pattern: matching files of a wildcard location are skipped.
    pub exclude: Option<String>,
    pub ignore_binaries: bool,
    /// Regular expressions: matching lines are dropped.
    pub ignore: Vec<String>,
    /// Regular expressions: when set, only lines matching one are kept.
    pub restrict: Vec<String>,
    pub multiline_regex: Option<MultilineRegex>,
    /// Bytes: a file read from its start begins at its last `max_size` bytes.
    pub max_size: Option<u64>,
    /// Added to each event of this entry as `labels`.
    pub labels: BTreeMap<String, String>,
}

impl Default for LocalFile {
    fn default() -> Self {
        Self {
            location: String::new(),
            log_format: "syslog".into(),
            command: String::new(),
            alias: String::new(),
            frequency: 360,
            only_future_events: true,
            age: None,
            exclude: None,
            ignore_binaries: false,
            ignore: Vec::new(),
            restrict: Vec::new(),
            multiline_regex: None,
            max_size: None,
            labels: BTreeMap::new(),
        }
    }
}

/// How `multi-line-regex` joins lines into one message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MultilineRegex {
    pub regex: String,
    /// `start`, `end` or `all`.
    #[serde(rename = "match")]
    pub match_at: String,
    /// `no-replace`, `none`, `wspace` or `tab`.
    pub replace: String,
    /// Seconds without new lines before a message still being written is sent.
    pub timeout: u64,
}

impl Default for MultilineRegex {
    fn default() -> Self {
        Self { regex: String::new(), match_at: "start".into(), replace: "no-replace".into(), timeout: 5 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Label {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub hidden: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default)]
pub struct BufferConfig {
    /// No pacing and no `queue_size` limit (`buffer_max_events` still applies).
    pub disabled: bool,
    pub queue_size: usize,
    pub events_per_second: u32,
    /// `events_per_second` is never below this.
    pub min_eps: u32,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self { disabled: false, queue_size: 5000, events_per_second: 500, min_eps: 50 }
    }
}

impl BufferConfig {
    /// `queue_size` into 1–100000, `min_eps` into 1–1000, `events_per_second` into `min_eps`–1000,
    /// with a warning when out.
    pub fn clamped(mut self) -> Self {
        let q = self.queue_size.clamp(1, 100_000);
        if q != self.queue_size {
            tracing::warn!(configured = self.queue_size, used = q, "buffer.queue_size out of range 1-100000");
            self.queue_size = q;
        }
        self.min_eps = self.min_eps.clamp(1, 1000);
        let e = self.events_per_second.clamp(self.min_eps, 1000);
        if e != self.events_per_second {
            tracing::warn!(configured = self.events_per_second, used = e, min_eps = self.min_eps, "buffer.events_per_second out of range");
            self.events_per_second = e;
        }
        self
    }
}

fn default_max_retries() -> u32 { 5 }
fn default_retry_interval() -> u64 { 10 }
fn default_heartbeat_interval() -> u64 { 10 }
fn default_event_channel_reconnect() -> u64 { 5 }
fn default_fim_interval() -> u64 { 43200 }
fn default_fim_recursion_level() -> u32 { 256 }
fn default_fim_file_limit() -> usize { 100_000 }
fn default_fim_max_files_per_second() -> u32 { 50 }
fn default_registry_recursion_level() -> u32 { 512 }
fn default_registry_scan_interval() -> u64 { 3600 }
fn default_inventory_interval() -> u64 { 3600 }
fn default_sca_interval() -> u64 { 43200 }
fn default_rootcheck_interval() -> u64 { 43200 }
fn default_rootcheck_base_directory() -> String { "C:\\".into() }
fn default_buffer_size() -> usize { 10_000 }
fn default_max_diff() -> usize { 59_392 }
fn default_log_level() -> String { "info".into() }
fn default_true() -> bool { true }

fn default_event_channels() -> Vec<String> {
    vec![
        "Security".into(),
        "System".into(),
        "Application".into(),
        "Microsoft-Windows-Sysmon/Operational".into(),
        "Microsoft-Windows-PowerShell/Operational".into(),
        "Windows PowerShell".into(),
        "Microsoft-Windows-Windows Defender/Operational".into(),
        "Microsoft-Windows-TaskScheduler/Operational".into(),
    ]
}

/// The Security channel without its high-volume object access and handle events.
pub const SECURITY_QUERY: &str = "Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and EventID != 4656 and EventID != 4658 and EventID != 4663 and EventID != 4660 and EventID != 4670 and EventID != 4690 and EventID != 4703 and EventID != 4907 and EventID != 5152 and EventID != 5157]";

fn default_event_channel_queries() -> HashMap<String, String> {
    HashMap::from([
        ("Microsoft-Windows-PowerShell/Operational".into(), "Event/System[EventID=4103 or EventID=4104]".into()),
        ("Windows PowerShell".into(), "Event/System[EventID=400 or EventID=600 or EventID=800]".into()),
        // like the old agent's default: object access and handle events flood the channel (who-data reads
        // them on its own subscription)
        ("Security".into(), SECURITY_QUERY.into()),
    ])
}

fn default_fim_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("C:\\Windows\\System32\\drivers\\etc"),
        PathBuf::from("C:\\ProgramData\\ProVigil"),
    ]
}

fn default_registry_keys() -> Vec<String> {
    vec![
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce".into(),
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
        "HKLM\\System\\CurrentControlSet\\Services".into(),
    ]
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            manager_url: String::new(),
            grpc_url: String::new(),
            tls_insecure: false,
            tenant_key: String::new(),
            agent_name: String::new(),
            heartbeat_interval_secs: default_heartbeat_interval(),
            event_channels: default_event_channels(),
            event_channel_queries: default_event_channel_queries(),
            event_channel_reconnect_secs: default_event_channel_reconnect(),
            fim_paths: default_fim_paths(),
            fim_scan_interval_secs: default_fim_interval(),
            fim_realtime: Vec::new(),
            fim_whodata: Vec::new(),
            fim_ignore: Vec::new(),
            fim_max_files_per_second: default_fim_max_files_per_second(),
            fim_report_changes: Vec::new(),
            fim_nodiff: Vec::new(),
            fim_recursion_level: default_fim_recursion_level(),
            fim_file_limit: default_fim_file_limit(),
            registry_keys: default_registry_keys(),
            registry_ignore: Vec::new(),
            registry_recursion_level: default_registry_recursion_level(),
            registry_scan_interval_secs: default_registry_scan_interval(),
            registry_restrict_key: Vec::new(),
            registry_restrict_value: Vec::new(),
            registry_report_changes: default_registry_keys(),
            inventory_interval_secs: default_inventory_interval(),
            sca_interval_secs: default_sca_interval(),
            sca_enabled: default_true(),
            sca_disabled_policies: Vec::new(),
            full_send_splay_secs: None,
            diff_enabled: false,
            diff_max_size: default_max_diff(),
            whodata_enabled: default_true(),
            rootcheck_enabled: default_true(),
            rootcheck_interval_secs: default_rootcheck_interval(),
            rootcheck_files_list: None,
            rootcheck_trojans_list: None,
            rootcheck_policies: Vec::new(),
            rootcheck_checks: Default::default(),
            rootcheck_base_directory: default_rootcheck_base_directory(),
            upgrade_enabled: default_true(),
            buffer_max_events: default_buffer_size(),
            log_level: default_log_level(),
            labels: Vec::new(),
            buffer: BufferConfig::default(),
            manager_urls: Vec::new(),
            max_retries: default_max_retries(),
            retry_interval_secs: default_retry_interval(),
            localfiles: Vec::new(),
            allow_remote_commands: false,
            commands: Vec::new(),
            osquery: Default::default(),
            ar_repeated_offenders: Vec::new(),
            ca_file: None,
            active_response_enabled: default_true(),
            groups: String::new(),
            force_enroll: false,
        }
    }
}

/// The agent's configuration file, next to the program (the installer writes it).
pub const CONFIG_FILE: &str = "provigil-agent.json";

impl AgentConfig {
    /// Loads configuration from file with environment variable overrides.
    pub fn load_or_default(config_path: Option<&Path>) -> Self {
        let possible_json_paths = [
            config_path.unwrap_or_else(|| Path::new(CONFIG_FILE)),
            Path::new("C:\\Program Files (x86)\\ProVigil Agent\\provigil-agent.json"),
            Path::new("C:\\Program Files\\ProVigil Agent\\provigil-agent.json"),
        ];
        let mut cfg = Self::default();
        if let Some(c) = possible_json_paths.into_iter().find_map(Self::from_file) {
            cfg = c;
        }

        // Environment variable overrides (highest priority for container / cloud deployment)
        if let Ok(url) = std::env::var("PROVIGIL_MANAGER_URL") {
            if !url.trim().is_empty() {
                cfg.manager_url = url;
            }
        }
        if let Ok(key) = std::env::var("PROVIGIL_TENANT_KEY") {
            if !key.trim().is_empty() {
                cfg.tenant_key = key;
            }
        }
        if let Ok(name) = std::env::var("PROVIGIL_AGENT_NAME") {
            if !name.trim().is_empty() {
                cfg.agent_name = name;
            }
        }

        if cfg.agent_name.is_empty() {
            cfg.agent_name = sysinfo::System::host_name().unwrap_or_else(|| "win-agent".into());
        }
        cfg.buffer = cfg.buffer.clamped();

        cfg
    }

    /// The settings in a configuration file; None when it is missing or not valid (logged).
    fn from_file(path: &Path) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content)
            .map_err(|e| warn!(file = %path.display(), error = %e, "Configuration file not valid: not used"))
            .ok()
    }

    /// The managers in failover order: `manager_urls` when not empty, else `[manager_url]`.
    pub fn manager_list(&self) -> Vec<String> {
        let tidy = |u: &String| u.trim().trim_end_matches('/').to_string();
        let list: Vec<String> = self.manager_urls.iter().map(tidy).filter(|u| !u.is_empty()).collect();
        if list.is_empty() { vec![tidy(&self.manager_url)] } else { list }
    }

    /// These settings overlaid by a group `config`: a group list is added to the local one
    /// (duplicates left out), channel queries are merged per channel, other values replace
    /// the local one. Fields outside `GROUP_FIELDS` are ignored.
    pub fn overlay(&self, group: &Value) -> Result<AgentConfig, String> {
        let Value::Object(given) = group else { return Err("config is not an object".into()) };
        // typed round trip: checks the types and gives group entries the form local ones have
        let typed: AgentConfig = serde_json::from_value(group.clone()).map_err(|e| e.to_string())?;
        let mut typed = serde_json::to_value(typed).map_err(|e| e.to_string())?;
        if let Some(list) = typed["localfiles"].as_array_mut().filter(|_| !self.allow_remote_commands) {
            let before = list.len();
            list.retain(|l| !matches!(l["log_format"].as_str().map(|f| f.trim().to_ascii_lowercase()).as_deref(), Some("command" | "full_command")));
            if list.len() < before {
                warn!(dropped = before - list.len(), "Command entries from the group configuration not run: set allow_remote_commands in provigil-agent.json to allow them");
            }
        }
        if !self.allow_remote_commands {
            if let Some(list) = typed["commands"].as_array_mut().filter(|l| !l.is_empty()) {
                warn!(dropped = list.len(), "Scheduled commands from the group configuration not run: set allow_remote_commands in provigil-agent.json to allow them");
                list.clear();
            }
            // the program the agent starts is a command too
            if given.get("osquery").is_some_and(|o| o.get("bin_path").is_some()) {
                warn!("osquery bin_path from the group configuration not used: set allow_remote_commands in provigil-agent.json to allow it");
                typed["osquery"]["bin_path"] = Value::String(self.osquery.bin_path.clone());
            }
        }
        let mut out = serde_json::to_value(self).map_err(|e| e.to_string())?;
        for k in GROUP_FIELDS.into_iter().filter(|k| given.contains_key(*k)) {
            match (&mut out[k], typed[k].clone()) {
                // like the old agent's central agent.conf: lists add to the local ones (but a
                // sequence, which the group's replaces)
                (Value::Array(local), Value::Array(add)) if k != "ar_repeated_offenders" => {
                    for x in add {
                        if !local.contains(&x) {
                            local.push(x);
                        }
                    }
                }
                // a query per channel: the group's are added (or replace that channel's)
                (Value::Object(local), Value::Object(add)) if k == "event_channel_queries" => local.extend(add),
                (slot, v) => *slot = v,
            }
        }
        let mut cfg: AgentConfig = serde_json::from_value(out).map_err(|e| e.to_string())?;
        cfg.buffer = cfg.buffer.clamped();
        Ok(cfg)
    }
}

/// The settings an agent's groups can set (the console's Groups page).
pub const GROUP_FIELDS: [&str; 29] = [
    "event_channels", "event_channel_queries", "localfiles", "fim_paths", "fim_realtime", "fim_whodata", "fim_ignore",
    "fim_scan_interval_secs", "fim_report_changes", "fim_nodiff", "fim_recursion_level", "registry_keys", "registry_ignore", "rootcheck_enabled", "rootcheck_interval_secs",
    "sca_interval_secs", "sca_enabled", "sca_disabled_policies", "labels", "buffer",
    "commands", "osquery", "rootcheck_checks", "rootcheck_base_directory", "ar_repeated_offenders",
    "registry_restrict_key", "registry_restrict_value", "registry_report_changes", "full_send_splay_secs",
];

/// The last group answer the agent received, used at the next start.
pub const GROUP_CONFIG_FILE: &str = "data/group_config.json";

/// The group configuration in use: the local settings, the group version applied and the
/// effective settings.
pub struct GroupConfig {
    local: AgentConfig,
    version: Option<String>,
    pub effective: AgentConfig,
    saved: PathBuf,
}

impl GroupConfig {
    /// The local settings overlaid by the saved group answer, when there is a usable one.
    pub fn start(local: AgentConfig, saved: impl Into<PathBuf>) -> Self {
        let mut g = GroupConfig { effective: local.clone(), local, version: None, saved: saved.into() };
        if let Some(answer) = fs::read_to_string(&g.saved).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()) {
            g.on_answer(&answer);
        }
        g
    }

    /// The group configuration version applied (None before the first).
    pub fn version(&self) -> Option<String> {
        self.version.clone()
    }

    /// A manager answer (`{"version", "config"}`): the new effective settings when the
    /// collection loops must restart with them.
    pub fn on_answer(&mut self, answer: &Value) -> Option<AgentConfig> {
        let version = answer["version"].as_str().unwrap_or_default();
        if self.version.as_deref() == Some(version) {
            return None;
        }
        let effective = match self.local.overlay(&answer["config"]) {
            Ok(c) if !version.is_empty() => c,
            r => {
                warn!(error = ?r.err(), "Group configuration not understood; ignored, the current settings stay");
                return None;
            }
        };
        info!("Group configuration changed (version {version}); applying.");
        let saved = self.saved.parent().map_or(Ok(()), fs::create_dir_all).and_then(|_| fs::write(&self.saved, answer.to_string()));
        if let Err(e) = saved {
            warn!(error = %e, "Group configuration not saved");
        }
        self.version = Some(version.to_string());
        let (old, new) = (serde_json::to_value(&self.effective).unwrap_or_default(), serde_json::to_value(&effective).unwrap_or_default());
        let changed: Vec<&str> = GROUP_FIELDS.into_iter().filter(|k| old[k] != new[k]).collect();
        for k in &changed {
            info!("Setting {k} = {}", new[k]);
        }
        self.effective = effective;
        (!changed.is_empty()).then(|| self.effective.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn local() -> AgentConfig {
        AgentConfig {
            fim_paths: vec![PathBuf::from(r"C:\A")],
            event_channels: vec!["Security".into()],
            fim_ignore: vec![r"C:\A\tmp".into()],
            labels: vec![Label { key: "site".into(), value: "Kochi".into(), hidden: false }],
            localfiles: vec![LocalFile { location: r"C:\x.log".into(), ..LocalFile::default() }],
            ..AgentConfig::default()
        }
    }

    #[test]
    fn overlay_replaces_or_adds_per_field() {
        let g = json!({
            "fim_paths": [r"C:\A", r"C:\B"],
            "event_channels": ["System"],
            "fim_ignore": [],
            "labels": [{"key": "site", "value": "Kochi", "hidden": false}, {"key": "env", "value": "prod", "hidden": false}],
            "localfiles": [{"location": r"C:\x.log"}, {"location": r"C:\y.log", "log_format": "json"}],
            "rootcheck_enabled": false,
            "sca_interval_secs": 600,
            "sca_enabled": false,
            "sca_disabled_policies": ["provigil_win10"],
            "buffer": {"queue_size": 8000},
            "manager_url": "http://elsewhere",
        });
        let c = local().overlay(&g).unwrap();
        assert_eq!(c.fim_paths, vec![PathBuf::from(r"C:\A"), PathBuf::from(r"C:\B")], "union, local first, no duplicate");
        assert_eq!(c.event_channels, vec!["Security".to_string(), "System".to_string()], "a group list adds to the local one");
        assert_eq!(c.fim_ignore, vec![r"C:\A\tmp".to_string()], "an empty group list keeps the local one");
        assert_eq!(c.labels.len(), 2);
        assert_eq!(c.localfiles.iter().map(|l| l.location.as_str()).collect::<Vec<_>>(), [r"C:\x.log", r"C:\y.log"]);
        assert!(!c.rootcheck_enabled);
        assert_eq!(c.sca_interval_secs, 600);
        assert_eq!((c.sca_enabled, c.sca_disabled_policies.as_slice()), (false, ["provigil_win10".to_string()].as_slice()));
        assert_eq!((local().sca_enabled, local().sca_interval_secs), (true, 43200), "defaults");
        assert_eq!((c.buffer.queue_size, c.buffer.events_per_second, c.buffer.min_eps), (8000, 500, 50), "an object replaces");
        assert_eq!(c.manager_url, "", "not a group setting");
        assert_eq!(c.registry_keys, local().registry_keys, "absent: unchanged");
        assert!(local().overlay(&json!({"fim_paths": 5})).is_err());
        assert!(local().overlay(&json!([1])).is_err());
    }

    #[test]
    fn saved_answer_used_at_start_then_versions_applied() {
        let dir = tempfile::tempdir().unwrap();
        let saved = dir.path().join("data").join("group_config.json");
        fs::create_dir_all(saved.parent().unwrap()).unwrap();
        fs::write(&saved, json!({"version": "v1", "config": {"fim_paths": [r"C:\B"]}}).to_string()).unwrap();
        // before the manager answers: the saved group settings
        let mut g = GroupConfig::start(local(), &saved);
        assert_eq!(g.effective.fim_paths.len(), 2);

        // the manager's answers stand in for the transport; a restart applies them as lib.rs does
        let buffer = crate::buffer::EventBuffer::with_limits(100, &BufferConfig::default(), json!({}));
        buffer.push(json!({"id": 1}));
        let mut restarts = 0;
        let mut poll = |g: &mut GroupConfig, answer: Value| {
            if let Some(cfg) = g.on_answer(&answer) {
                buffer.set_limits(&cfg.buffer);
                restarts += 1;
            }
        };
        poll(&mut g, json!({"version": "v1", "config": {"fim_paths": [r"C:\B"]}}));
        poll(&mut g, json!({"version": "v2", "config": {"fim_paths": 7}}));
        assert_eq!(g.effective.fim_paths.len(), 2, "not understood: the current settings stay");
        let v3 = json!({"version": "v3", "config": {"fim_paths": [r"C:\C"], "buffer": {"queue_size": 50}}});
        poll(&mut g, v3.clone());
        poll(&mut g, v3);
        assert_eq!(restarts, 1, "same version: nothing restarted");
        assert_eq!(g.effective.fim_paths, vec![PathBuf::from(r"C:\A"), PathBuf::from(r"C:\C")]);
        assert_eq!(buffer.len(), 1, "the buffer keeps its events");
        assert!(fs::read_to_string(&saved).unwrap().contains("v3"));
        assert_eq!(g.version().as_deref(), Some("v3"), "the version applied, sent with the keepalive");
    }

    #[test]
    fn group_scheduled_commands_osquery_program_and_repeated_offenders() {
        let g = json!({
            "commands": [{"name": "users", "command": "net user"}],
            "osquery": {"enabled": true, "bin_path": r"C:\other\osqueryd.exe", "log_path": r"D:\r.log"},
            "rootcheck_checks": {"files": false},
            "rootcheck_base_directory": r"D:\",
            "ar_repeated_offenders": [30, 60, 120],
        });
        let mut mine = local();
        mine.ar_repeated_offenders = vec![5];
        let c = mine.overlay(&g).unwrap();
        assert!(c.commands.is_empty(), "not allowed locally");
        assert_eq!((c.osquery.enabled, c.osquery.log_path.as_str()), (true, r"D:\r.log"));
        assert_eq!(c.osquery.bin_path, crate::osquery::OsqueryConfig::default().bin_path, "the program stays the local one");
        assert_eq!((c.rootcheck_checks.files, c.rootcheck_checks.trojans, c.rootcheck_base_directory.as_str()), (false, true, r"D:\"));
        assert_eq!(c.ar_repeated_offenders, [30, 60, 120], "the group's sequence replaces the local one");

        mine.allow_remote_commands = true;
        let c = mine.overlay(&g).unwrap();
        assert_eq!((c.commands.len(), c.commands[0].timeout_secs, c.commands[0].run_on_start), (1, 600, true));
        assert_eq!(c.osquery.bin_path, r"C:\other\osqueryd.exe");
    }

    #[test]
    fn group_commands_need_allow_remote_commands() {
        let g = json!({ "localfiles": [
            {"location": r"C:\y.log"},
            {"log_format": "command", "command": "whoami"},
            {"log_format": " Full_Command ", "command": "net user"},
        ], "allow_remote_commands": true });
        let c = local().overlay(&g).unwrap();
        assert_eq!(c.localfiles.iter().map(|l| l.location.as_str()).collect::<Vec<_>>(), [r"C:\x.log", r"C:\y.log"], "the group cannot allow itself");
        let mut mine = local();
        mine.localfiles.push(LocalFile { log_format: "command".into(), command: "ipconfig".into(), ..LocalFile::default() });
        assert_eq!(mine.overlay(&g).unwrap().localfiles.iter().filter(|l| !l.command.is_empty()).count(), 1, "local commands stay");
        mine.allow_remote_commands = true;
        assert_eq!(mine.overlay(&g).unwrap().localfiles.len(), 5);
    }

    #[test]
    fn events_per_second_never_below_min_eps() {
        let c = BufferConfig { events_per_second: 10, ..BufferConfig::default() }.clamped();
        assert_eq!((c.events_per_second, c.min_eps), (50, 50), "the default floor");
        let c = BufferConfig { events_per_second: 10, min_eps: 5, ..BufferConfig::default() }.clamped();
        assert_eq!(c.events_per_second, 10, "a lower floor allows it");
        let c = BufferConfig { events_per_second: 10, min_eps: 5000, ..BufferConfig::default() }.clamped();
        assert_eq!((c.events_per_second, c.min_eps), (1000, 1000), "the floor stays in range");
        let c = local().overlay(&json!({"buffer": {"events_per_second": 1, "min_eps": 20}})).unwrap();
        assert_eq!(c.buffer.events_per_second, 20, "group settings too");
    }

    #[test]
    fn invalid_file_not_used_and_no_default_manager() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("provigil-agent.json");
        fs::write(&p, "{ not json").unwrap();
        assert!(AgentConfig::from_file(&p).is_none());
        fs::write(&p, "{}").unwrap();
        let c = AgentConfig::from_file(&p).unwrap();
        assert!(c.manager_url.is_empty() && c.active_response_enabled && !c.allow_remote_commands && c.ca_file.is_none());
    }
}

