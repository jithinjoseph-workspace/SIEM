//! The manager side of the agent-upgrade module
//! (`wazuh_modules/agent_upgrade/manager/*.c`, the manager branch of
//! `config/wmodules-agent-upgrade.c`): the `queue/tasks/upgrade` socket,
//! request parsing, agent validation, the task manager callbacks, WPK
//! download and the transfer to the agents through remoted.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use siem_cjson::Json;
use siem_config::ConfigContext;
use siem_ipc::local::{LocalStream, StreamListener};
use siem_ipc::wdbc::{parse_result, WdbQuery, WdbcResult};
use siem_log::WLog;
use siem_xml::XmlNode;
use tokio::sync::{mpsc, Semaphore};

use crate::task_general::*;

/// `AGENT_UPGRADE_WM_NAME`
pub const NAME: &str = "agent-upgrade";
/// `WM_AGENT_UPGRADE_LOGTAG`
const LOGTAG: &str = "wazuh-modulesd:agent-upgrade";
/// `WM_UPGRADE_SOCK`, `WM_TASK_MODULE_SOCK`, `REMOTE_LOCAL_SOCK`, `CLUSTER_SOCK`
pub const WM_UPGRADE_SOCK: &str = "queue/tasks/upgrade";
const WM_TASK_MODULE_SOCK: &str = "queue/tasks/task";
const REMOTE_LOCAL_SOCK: &str = "queue/sockets/remote";
#[cfg(unix)]
const CLUSTER_SOCK: &str = "queue/cluster/c-internal.sock";
/// `__ossec_version`
const OSSEC_VERSION: &str = "v4.14.7";
const MINIMAL_VERSION_SUPPORT: &str = "v3.0.0";
const MINIMAL_VERSION_SUPPORT_MACOS: &str = "v4.3.0";
const NEW_LINUX_VERSION_REPOSITORY: &str = "v3.4.0";
const NEW_VERSION_STRUCTURE_REPOSITORY: &str = "v4.9.0";
const NEW_UPGRADE_MECHANISM: &str = "v4.1.0";
const WPK_DEFAULT_PATH: &str = "var/upgrade/";
const WPK_REPO_URL_3_X: &str = "packages.wazuh.com/wpk/";
/// `WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT` (handed to the download module as is)
const WPK_DOWNLOAD_TIMEOUT: i64 = 60000;
const WPK_DOWNLOAD_ATTEMPTS: u64 = 5;
const WPK_OPEN_ATTEMPTS: usize = 10;
const MAX_RESPONSE_SIZE: usize = 1048576;
const DEFAULT_REQUEST_TIMEOUT: i64 = 20;
/// `WM_AGENT_UPGRADE_START_WAIT_TIME`
const START_WAIT_TIME: u64 = 30;
const MANAGER_ID: i32 = 0;

/// `wm_manager_configs`
#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    pub max_threads: u32,
    pub chunk_size: u32,
    pub wpk_repository: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        // WM_UPGRADE_MAX_THREADS, WM_UPGRADE_CHUNK_SIZE
        Config { enabled: true, max_threads: 8, chunk_size: 32768, wpk_repository: None }
    }
}

/// `get_nproc`
fn nproc() -> u32 {
    std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1)
}

/// `wm_agent_upgrade_read` (manager build) for the `<agent-upgrade>` children.
pub fn read(ctx: &mut ConfigContext, nodes: Option<&[XmlNode]>, data: &mut Config) -> Result<(), ()> {
    for n in nodes.unwrap_or_default() {
        let content = n.content.as_deref().unwrap_or("");
        let invalid = |ctx: &mut ConfigContext| ctx.error(format!("Invalid content for tag '{}' at module '{NAME}'.", n.element));
        match n.element.as_str() {
            "chunk_size" => {
                let chunk = siem_config::util::atoi(content);
                if !siem_config::util::str_is_num(content) || !(64..=60000).contains(&chunk) {
                    invalid(ctx);
                    return Err(());
                }
                data.chunk_size = chunk as u32;
            }
            "max_threads" => {
                if !siem_config::util::str_is_num(content) {
                    invalid(ctx);
                    return Err(());
                }
                match siem_config::util::atoi(content) {
                    0 => data.max_threads = nproc(),
                    t if t <= 256 => data.max_threads = t as u32,
                    _ => {
                        invalid(ctx);
                        return Err(());
                    }
                }
            }
            "wpk_repository" => data.wpk_repository = Some(content.to_string()),
            other => ctx.warn(format!("No such tag <{other}> at module '{NAME}'.")),
        }
    }
    Ok(())
}

// wm_upgrade_error_code / upgrade_error_codes
const SUCCESS: i32 = 0;
const PARSING_ERROR: i32 = 1;
const PARSING_REQUIRED_PARAMETER: i32 = 2;
const TASK_CONFIGURATIONS: i32 = 3;
const TASK_MANAGER_COMMUNICATION: i32 = 4;
const TASK_MANAGER_FAILURE: i32 = 5;
const GLOBAL_DB_FAILURE: i32 = 6;
const INVALID_ACTION_FOR_MANAGER: i32 = 7;
const AGENT_IS_NOT_ACTIVE: i32 = 8;
const SYSTEM_NOT_SUPPORTED: i32 = 9;
const UPGRADE_ALREADY_IN_PROGRESS: i32 = 10;
const NOT_MINIMAL_VERSION_SUPPORTED: i32 = 11;
const NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT: i32 = 12;
const NEW_VERSION_GREATER_MASTER: i32 = 13;
const URL_NOT_FOUND: i32 = 14;
const WPK_VERSION_DOES_NOT_EXIST: i32 = 15;
const WPK_FILE_DOES_NOT_EXIST: i32 = 16;
const WPK_SHA1_DOES_NOT_MATCH: i32 = 17;
const SEND_LOCK_RESTART_ERROR: i32 = 18;
const SEND_OPEN_ERROR: i32 = 19;
const SEND_WRITE_ERROR: i32 = 20;
const SEND_CLOSE_ERROR: i32 = 21;
const SEND_SHA1_ERROR: i32 = 22;
const SEND_UPGRADE_ERROR: i32 = 23;
const UPGRADE_ERROR: i32 = 24;
const UPGRADE_ERROR_MISSING_PACKAGE: i32 = 25;
const ERROR_CODES: [&str; 27] = [
    "Success",
    "Could not parse message JSON",
    "Required parameters in json message where not found",
    "JSON parameter not recognized",
    "Task manager communication error",
    "",
    "Agent information not found in database",
    "Action not available for Manager (agent 000)",
    "Agent is not active",
    "The WPK for this platform is not available",
    "Upgrade procedure could not start. Agent already upgrading",
    "Remote upgrade is not available for this agent version",
    "Current agent version is greater or equal",
    "Upgrading an agent to a version higher than the manager requires the force flag",
    "The repository is not reachable",
    "The version of the WPK does not exist in the repository",
    "The WPK file does not exist",
    "The WPK sha1 of the file is not valid",
    "Send lock restart error",
    "Send open file error",
    "Send write file error",
    "Send close file error",
    "Send verify sha1 error",
    "Send upgrade command error",
    "Upgrade procedure exited with error code",
    "Upgrade procedure exited with error code, missing dependency in agent",
    "Upgrade procedure could not start",
];

/// `wm_upgrade_task`
#[derive(Debug, Clone, Default)]
struct UpgradeTask {
    wpk_repository: Option<String>,
    custom_version: Option<String>,
    use_http: bool,
    force_upgrade: bool,
    wpk_version: Option<String>,
    wpk_file: Option<String>,
    wpk_sha1: Option<String>,
    package_type: Option<String>,
}

/// `wm_upgrade_custom_task`
#[derive(Debug, Clone, Default)]
struct CustomTask {
    custom_file_path: Option<String>,
    custom_installer: Option<String>,
}

/// `wm_upgrade_agent_status_task`
#[derive(Debug, Default)]
struct StatusTask {
    error_code: i32,
    message: Option<Vec<u8>>,
    status: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
enum TaskKind {
    Upgrade(UpgradeTask),
    Custom(CustomTask),
}

/// `wm_agent_info`
#[derive(Debug, Clone, Default)]
struct AgentInfo {
    agent_id: i32,
    platform: Option<String>,
    major_version: Option<String>,
    minor_version: Option<String>,
    architecture: Option<String>,
    wazuh_version: Option<String>,
    connection_status: Option<String>,
    package_type: Option<String>,
}

/// `wm_agent_task`
#[derive(Debug, Clone)]
struct AgentTask {
    info: AgentInfo,
    task: TaskKind,
}

/// What `wm_agent_upgrade_parse_message` found.
enum Parsed {
    Upgrade(UpgradeTask),
    Custom(CustomTask),
    UpdateStatus(StatusTask),
    Result,
}

/// `compare_wazuh_versions(a, b, true)`
fn cmpv(a: &str, b: &str) -> i32 {
    siem_remoted::config::compare_wazuh_versions(Some(a), Some(b), true)
}

/// `%.3d`
fn pad3(n: i32) -> String {
    if n < 0 {
        format!("-{:03}", -(n as i64))
    } else {
        format!("{n:03}")
    }
}

/// `encode_base64`
fn base64(src: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(src.len().div_ceil(3) * 4);
    for c in src.chunks(3) {
        let (b1, b2, b3) = (c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0));
        out.push(T[(b1 >> 2) as usize] as char);
        out.push(T[(((b1 & 3) << 4) | (b2 >> 4)) as usize] as char);
        out.push(if c.len() > 1 { T[(((b2 & 0xf) << 2) | (b3 >> 6)) as usize] as char } else { '=' });
        out.push(if c.len() > 2 { T[(b3 & 0x3f) as usize] as char } else { '=' });
    }
    out
}

/// A number's `valueint`.
fn num(j: &Json) -> Option<i32> {
    match j {
        Json::Number { int, .. } => Some(*int),
        _ => None,
    }
}

/// `wm_agent_upgrade_parse_data_response`
fn data_response(error_id: i32, message: Option<&[u8]>, agent_id: Option<i32>) -> Json {
    let mut r = Json::object();
    r.add("error", Json::number(error_id as f64));
    if let Some(m) = message {
        r.add("message", Json::string(m));
    }
    if let Some(a) = agent_id {
        r.add("agent", Json::number(a as f64));
    }
    r
}

/// `wm_agent_upgrade_parse_response`
fn response(error_id: i32, data: Json) -> Json {
    let mut r = Json::object();
    r.add("error", Json::number(error_id as f64));
    let data = if data.is_array() { data } else { Json::Array(vec![data]) };
    r.add("data", data);
    r.add("message", Json::string(ERROR_CODES[error_id as usize]));
    r
}

/// The error answer for `error_id` with its own text.
fn error_answer(error_id: i32) -> Vec<u8> {
    response(error_id, data_response(error_id, Some(ERROR_CODES[error_id as usize].as_bytes()), None)).print_unformatted()
}

/// `wm_agent_upgrade_parse_task_module_request`
fn task_module_request(command: &str, agents: Option<Json>, status: Option<&[u8]>, error: Option<&[u8]>) -> Json {
    let mut origin = Json::object();
    origin.add("name", Json::string(node_name().unwrap_or_default()));
    origin.add("module", Json::string(UPGRADE_MODULE));
    let mut params = Json::object();
    if let Some(a) = agents {
        params.add("agents", a);
    }
    if let Some(s) = status {
        params.add("status", Json::string(s));
    }
    if let Some(e) = error {
        params.add("error_msg", Json::string(e));
    }
    let mut r = Json::object();
    r.add("origin", origin);
    r.add("command", Json::string(command));
    r.add("parameters", params);
    r
}

fn agents_json(ids: &[i32]) -> Json {
    Json::Array(ids.iter().map(|&i| Json::number(i as f64)).collect())
}

/// Which `error_callback` the task module callback runs.
#[derive(Clone, Copy, PartialEq)]
enum Success {
    None,
    Upgrade,
    GetStatus,
    UpdateStatus,
}

pub struct UpgradeManager {
    cfg: Config,
    log: Arc<WLog>,
    db: Arc<dyn WdbQuery>,
    /// `task_table_by_agent_id` (C iterates a time-seeded hash; insertion order here)
    tasks: Mutex<Vec<(i32, AgentTask)>>,
    /// `upgrade_queue`
    queue: mpsc::UnboundedSender<AgentTask>,
    queue_rx: Mutex<Option<mpsc::UnboundedReceiver<AgentTask>>>,
    /// `download_mutex`
    download: tokio::sync::Mutex<()>,
}

impl UpgradeManager {
    pub fn new(cfg: Config, log: Arc<WLog>, db: Arc<dyn WdbQuery>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        UpgradeManager { cfg, log, db, tasks: Mutex::new(Vec::new()), queue: tx, queue_rx: Mutex::new(Some(rx)), download: tokio::sync::Mutex::new(()) }
    }

    fn tlog(&self, level: &str, m: impl AsRef<[u8]>) {
        self.log.tagged(LOGTAG, level, m);
    }

    /// `wm_agent_upgrade_start_manager_module`
    pub async fn main(self: Arc<Self>) {
        if !self.cfg.enabled {
            self.tlog("INFO", "(8152): Module Agent Upgrade disabled. Exiting...");
            return;
        }
        self.tlog("INFO", "(8153): Module Agent Upgrade started.");
        self.listen_messages().await;
    }

    /// `wm_agent_upgrade_listen_messages`
    async fn listen_messages(self: &Arc<Self>) {
        let listener = match StreamListener::bind(WM_UPGRADE_SOCK).await {
            Ok(l) => l,
            Err(e) => {
                self.tlog("ERROR", format!("(8108): Unable to bind to socket '{WM_UPGRADE_SOCK}': '{}'", crate::wdb::errno_text(&e)));
                return;
            }
        };
        // Wait a few seconds until the task manager starts
        tokio::time::sleep(Duration::from_secs(START_WAIT_TIME)).await;
        self.cancel_pending_upgrades().await;
        let me = self.clone();
        tokio::spawn(async move { me.dispatch_upgrades().await });
        loop {
            let mut peer = match listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    self.tlog("ERROR", format!("(8110): Error in accept(): '{}'", crate::wdb::errno_text(&e)));
                    continue;
                }
            };
            match siem_ipc::framing::recv(&mut peer, OS_MAXSTR).await {
                Err(siem_ipc::framing::FrameError::TooBig(..)) => self.tlog("ERROR", "(8112): Response size is bigger than expected."),
                Err(siem_ipc::framing::FrameError::Closed) => self.tlog("DEBUG", "(8159): Empty message from local client."),
                Err(e) => self.tlog("ERROR", format!("(8111): Error in recv(): '{e}'")),
                Ok(b) if b.is_empty() => self.tlog("DEBUG", "(8159): Empty message from local client."),
                Ok(b) => {
                    let message = self.process_request(&b).await;
                    self.tlog("DEBUG", cat(&[b"(8156): Response message: '", &message, b"'"]));
                    let _ = siem_ipc::framing::send(&mut peer, &message).await;
                }
            }
        }
    }

    /// The `default:` branch of the listener: one request, one answer.
    pub async fn process_request(&self, b: &[u8]) -> Vec<u8> {
        let buffer = cstr(b);
        self.tlog("DEBUG", cat(&[b"(8155): Incomming message: '", buffer, b"'"]));
        match self.parse_message(buffer) {
            Ok((Parsed::Upgrade(t), ids)) => self.process_upgrade_command(&ids, TaskKind::Upgrade(t)).await,
            Ok((Parsed::Custom(t), ids)) => self.process_upgrade_command(&ids, TaskKind::Custom(t)).await,
            Ok((Parsed::UpdateStatus(t), ids)) => self.process_agent_result_command(&ids, &t).await,
            Ok((Parsed::Result, ids)) => self.process_upgrade_result_command(&ids).await,
            Err(m) => m,
        }
    }

    /// `wm_agent_upgrade_parse_message`: the task and agent ids, or the error answer.
    fn parse_message(&self, buffer: &[u8]) -> Result<(Parsed, Vec<i32>), Vec<u8>> {
        let Some(mut root) = parse(buffer) else {
            self.tlog("ERROR", cat(&[b"(8101): Cannot parse JSON: '", buffer, b"'"]));
            return Err(error_answer(PARSING_ERROR));
        };
        let command = root.get("command").and_then(|c| c.as_bytes()).map(|c| c.to_vec());
        let params_ok = root.get("parameters").is_some_and(|p| p.is_object());
        let (Some(command), true) = (command, params_ok) else {
            self.tlog("ERROR", "(8107): Required parameters in message are missing.");
            return Err(error_answer(PARSING_REQUIRED_PARAMETER));
        };
        let params = root.get_mut("parameters").unwrap();
        // cJSON_DetachItemFromObject
        let agents = params.remove("agents");
        let params = &*params;
        let agents = match agents {
            Some(a @ Json::Array(_)) if !a.is_empty() => a,
            _ => {
                self.tlog("ERROR", "(8107): Required parameters in message are missing.");
                return Err(error_answer(PARSING_REQUIRED_PARAMETER));
            }
        };
        let config_error = |m: String| response(TASK_CONFIGURATIONS, data_response(TASK_CONFIGURATIONS, Some(m.as_bytes()), None)).print_unformatted();
        let parsed = match command.as_slice() {
            b"upgrade" | b"upgrade_custom" | b"upgrade_update_status" | b"upgrade_result" => {
                let ids = self.parse_agents(&agents).map_err(config_error)?;
                let task = match command.as_slice() {
                    b"upgrade" => Parsed::Upgrade(self.parse_upgrade_command(params).map_err(config_error)?),
                    b"upgrade_custom" => Parsed::Custom(self.parse_upgrade_custom_command(params).map_err(config_error)?),
                    b"upgrade_update_status" => Parsed::UpdateStatus(self.parse_upgrade_agent_status(params).map_err(config_error)?),
                    _ => Parsed::Result,
                };
                (task, ids)
            }
            other => {
                self.tlog("ERROR", cat(&[b"(8102): No action defined for command: '", other, b"'"]));
                return Err(error_answer(TASK_CONFIGURATIONS));
            }
        };
        Ok(parsed)
    }

    fn parse_error(&self, m: &str) -> String {
        self.tlog("ERROR", format!("(8103): Error parsing command: '{m}'"));
        m.to_string()
    }

    /// `wm_agent_upgrade_parse_agents` (the list ends at a -1, as the C array)
    fn parse_agents(&self, agents: &Json) -> Result<Vec<i32>, String> {
        let mut ids = Vec::new();
        for a in agents.children() {
            match num(a) {
                Some(i) => ids.push(i),
                None => return Err(self.parse_error("Agent id not recognized")),
            }
        }
        if let Some(p) = ids.iter().position(|&i| i == OS_INVALID) {
            ids.truncate(p);
        }
        Ok(ids)
    }

    fn members(params: &Json) -> &[(Vec<u8>, Json)] {
        match params {
            Json::Object(m) => m,
            _ => &[],
        }
    }

    /// `wm_agent_upgrade_parse_upgrade_command`
    fn parse_upgrade_command(&self, params: &Json) -> Result<UpgradeTask, String> {
        let mut t = UpgradeTask::default();
        for (k, v) in Self::members(params) {
            let key = String::from_utf8_lossy(k);
            let string = |v: &Json| v.as_str().map(|s| s.into_owned()).ok_or_else(|| self.parse_error(&format!("Parameter \"{key}\" should be a string")));
            let boolean = |v: &Json| match v {
                Json::True => Ok(true),
                Json::False => Ok(false),
                _ => Err(self.parse_error(&format!("Parameter \"{key}\" should be true or false"))),
            };
            match k.as_slice() {
                b"wpk_repo" => t.wpk_repository = Some(string(v)?),
                b"version" => t.custom_version = Some(string(v)?),
                b"use_http" => t.use_http = boolean(v)?,
                b"force_upgrade" => t.force_upgrade = boolean(v)?,
                b"package_type" => {
                    let s = string(v)?;
                    if s != "rpm" && s != "deb" {
                        return Err(self.parse_error(&format!("Invalid parameter \"{key}\", value should be \"rpm\" or \"deb\"")));
                    }
                    t.package_type = Some(s);
                }
                _ => {}
            }
        }
        Ok(t)
    }

    /// `wm_agent_upgrade_parse_upgrade_custom_command`
    fn parse_upgrade_custom_command(&self, params: &Json) -> Result<CustomTask, String> {
        let mut t = CustomTask::default();
        for (k, v) in Self::members(params) {
            let key = String::from_utf8_lossy(k);
            let string = |v: &Json| v.as_str().map(|s| s.into_owned()).ok_or_else(|| self.parse_error(&format!("Parameter \"{key}\" should be a string")));
            match k.as_slice() {
                b"file_path" => t.custom_file_path = Some(string(v)?),
                b"installer" => t.custom_installer = Some(string(v)?),
                _ => {}
            }
        }
        Ok(t)
    }

    /// `wm_agent_upgrade_parse_upgrade_agent_status`
    fn parse_upgrade_agent_status(&self, params: &Json) -> Result<StatusTask, String> {
        let mut t = StatusTask::default();
        for (k, v) in Self::members(params) {
            let key = String::from_utf8_lossy(k);
            let string = |v: &Json| v.as_bytes().map(|s| s.to_vec()).ok_or_else(|| self.parse_error(&format!("Parameter \"{key}\" should be a string")));
            match k.as_slice() {
                b"error" => t.error_code = num(v).ok_or_else(|| self.parse_error(&format!("Parameter \"{key}\" should be a number")))?,
                b"message" => t.message = Some(string(v)?),
                b"status" => t.status = Some(string(v)?),
                _ => {}
            }
        }
        Ok(t)
    }

    /// `wm_agent_upgrade_cancel_pending_upgrades`
    async fn cancel_pending_upgrades(&self) {
        let req = task_module_request(UPGRADE_CANCEL_TASKS, None, None, None);
        let mut out = Vec::new();
        self.task_module_callback(&mut out, &req, Success::None, false).await;
    }

    /// `wm_agent_upgrade_process_upgrade_command` / `_custom_command`
    async fn process_upgrade_command(&self, ids: &[i32], task: TaskKind) -> Vec<u8> {
        let custom = matches!(task, TaskKind::Custom(_));
        let mut data = Vec::new();
        for &id in ids {
            // each agent gets its own copy of the request parameters
            let task = match &task {
                TaskKind::Upgrade(t) => TaskKind::Upgrade(UpgradeTask {
                    wpk_repository: t.wpk_repository.clone(),
                    custom_version: t.custom_version.clone(),
                    use_http: t.use_http,
                    force_upgrade: t.force_upgrade,
                    package_type: t.package_type.clone(),
                    ..Default::default()
                }),
                TaskKind::Custom(t) => TaskKind::Custom(t.clone()),
            };
            let ec = self.analyze_agent(id, task).await;
            if ec != SUCCESS {
                data.push(data_response(ec, Some(ERROR_CODES[ec as usize].as_bytes()), Some(id)));
            }
        }
        let command = if custom { UPGRADE_CUSTOM } else { UPGRADE };
        if !self.create_upgrade_tasks(&mut data, command).await {
            self.tlog("WARNING", "(8160): There are no valid agents to upgrade.");
        }
        response(SUCCESS, Json::Array(data)).print_unformatted()
    }

    /// `wm_agent_upgrade_process_agent_result_command`
    async fn process_agent_result_command(&self, ids: &[i32], task: &StatusTask) -> Vec<u8> {
        for &id in ids {
            self.tlog(
                "INFO",
                cat(&[
                    format!("(8164): Received upgrade notification from agent '{id}'. Error code: '{}', message: '", task.error_code).as_bytes(),
                    task.message.as_deref().unwrap_or(b""),
                    b"'",
                ]),
            );
        }
        let error = match task.error_code {
            0 => None,
            1 => Some(ERROR_CODES[UPGRADE_ERROR_MISSING_PACKAGE as usize].as_bytes()),
            _ => Some(ERROR_CODES[UPGRADE_ERROR as usize].as_bytes()),
        };
        let req = task_module_request(UPGRADE_UPDATE_STATUS, Some(agents_json(ids)), task.status.as_deref(), error);
        let mut data = Vec::new();
        self.task_module_callback(&mut data, &req, Success::UpdateStatus, false).await;
        response(SUCCESS, Json::Array(data)).print_unformatted()
    }

    /// `wm_agent_upgrade_process_upgrade_result_command`
    async fn process_upgrade_result_command(&self, ids: &[i32]) -> Vec<u8> {
        let req = task_module_request(UPGRADE_RESULT, Some(agents_json(ids)), None, None);
        let mut data = Vec::new();
        self.task_module_callback(&mut data, &req, Success::None, false).await;
        response(SUCCESS, Json::Array(data)).print_unformatted()
    }

    /// `wdb_get_agent_info` (+ `wdbc_query_parse_json`)
    async fn get_agent_info(&self, id: i32) -> Option<Json> {
        let root = match crate::wdb::query_ex(&*self.db, &self.log, &format!("global get-agent-info {id}")).await {
            Ok(r) => match parse_result(&r) {
                (WdbcResult::Ok, arg) => parse(arg.as_bytes()),
                (WdbcResult::Error, arg) => {
                    self.log.error(format!("Bad response from wazuh-db: {arg}"));
                    None
                }
                _ => None,
            },
            Err(-2) => {
                self.log.error(format!("Unable to connect to socket '{}'", crate::wdb::WDB_LOCAL_SOCK));
                None
            }
            Err(_) => {
                self.log.error("No response from wazuh-db.");
                None
            }
        };
        if root.is_none() {
            self.log.error(format!("Error querying Wazuh DB to get the agent's {id} information."));
        }
        root
    }

    /// `wm_agent_upgrade_analyze_agent`
    async fn analyze_agent(&self, id: i32, task: TaskKind) -> i32 {
        let root = self.get_agent_info(id).await;
        let Some(first) = root.as_ref().and_then(|r| r.children().into_iter().next().cloned()) else {
            return GLOBAL_DB_FAILURE;
        };
        let s = |k: &str| first.get(k).and_then(|v| v.as_str()).map(|v| v.into_owned());
        let mut at = AgentTask {
            info: AgentInfo {
                agent_id: id,
                platform: s("os_platform"),
                major_version: s("os_major"),
                minor_version: s("os_minor"),
                architecture: s("os_arch"),
                wazuh_version: s("version"),
                connection_status: s("connection_status"),
                package_type: None,
            },
            task,
        };
        let mut r = validate_agent_task(&mut at);
        if r == SUCCESS {
            // OSHash_Add_ex
            let mut tasks = self.tasks.lock().unwrap();
            if tasks.iter().any(|(k, _)| *k == id) {
                r = UPGRADE_ALREADY_IN_PROGRESS;
            } else {
                tasks.push((id, at));
            }
        }
        r
    }

    /// `wm_agent_upgrade_get_agent_ids`
    fn get_agent_ids(&self) -> Option<Json> {
        let tasks = self.tasks.lock().unwrap();
        (!tasks.is_empty()).then(|| agents_json(&tasks.iter().map(|(k, _)| *k).collect::<Vec<_>>()))
    }

    /// `wm_agent_upgrade_remove_entry`
    fn remove_entry(&self, id: i32) -> Option<AgentTask> {
        let mut tasks = self.tasks.lock().unwrap();
        let p = tasks.iter().position(|(k, _)| *k == id)?;
        Some(tasks.remove(p).1)
    }

    /// `wm_agent_upgrade_create_upgrade_tasks`
    async fn create_upgrade_tasks(&self, data: &mut Vec<Json>, command: &str) -> bool {
        let Some(agents) = self.get_agent_ids() else { return false };
        let status_req = task_module_request(UPGRADE_GET_STATUS, Some(agents), None, None);
        if self.task_module_callback(data, &status_req, Success::GetStatus, true).await != 0 {
            return false;
        }
        let Some(agents) = self.get_agent_ids() else { return false };
        let upgrade_req = task_module_request(command, Some(agents), None, None);
        if self.task_module_callback(data, &upgrade_req, Success::Upgrade, true).await != 0 {
            return false;
        }
        self.prepare_upgrades();
        true
    }

    /// `wm_agent_upgrade_prepare_upgrades`
    fn prepare_upgrades(&self) {
        let all: Vec<(i32, AgentTask)> = std::mem::take(&mut *self.tasks.lock().unwrap());
        for (_, t) in all {
            let _ = self.queue.send(t);
        }
    }

    /// `wm_agent_upgrade_send_tasks_information`
    async fn send_tasks_information(&self, msg: &Json) -> Option<Json> {
        if is_worker() {
            return self.send_task_information_worker(msg).await;
        }
        let mut sock = match LocalStream::connect(WM_TASK_MODULE_SOCK).await {
            Ok(s) => s,
            Err(_) => {
                self.tlog("ERROR", format!("(8104): Cannot connect to '{WM_TASK_MODULE_SOCK}'. Could not reach task manager module."));
                return None;
            }
        };
        let m = msg.print_unformatted();
        self.tlog("DEBUG", cat(&[b"(8157): Sending message to task_manager module: '", &m, b"'"]));
        let _ = siem_ipc::framing::send(&mut sock, &m).await;
        match siem_ipc::framing::recv(&mut sock, OS_MAXSTR).await {
            Err(siem_ipc::framing::FrameError::TooBig(..)) => {
                self.tlog("ERROR", "(8112): Response size is bigger than expected.");
                None
            }
            Err(siem_ipc::framing::FrameError::Closed) => {
                self.tlog("ERROR", "(8105): Response from task manager does not have a valid JSON format.");
                None
            }
            Err(e) => {
                self.tlog("ERROR", format!("(8111): Error in recv(): '{e}'"));
                None
            }
            Ok(b) => {
                let r = parse(&b);
                match &r {
                    None => self.tlog("ERROR", "(8105): Response from task manager does not have a valid JSON format."),
                    Some(_) => self.tlog("DEBUG", cat(&[b"(8158): Receiving message from task_manager module: '", cstr(&b), b"'"])),
                }
                r
            }
        }
    }

    /// `wm_agent_send_task_information_worker`: through the cluster to the master.
    async fn send_task_information_worker(&self, msg: &Json) -> Option<Json> {
        let mut payload = Json::object();
        payload.add("daemon_name", Json::string(crate::task_manager::NAME));
        payload.add("message", msg.clone());
        let m = payload.print_unformatted();
        self.tlog("DEBUG", cat(&[b"(8168): Sending sendsync message to task manager in master node: '", &m, b"'"]));
        let log = self.log.clone();
        let resp = tokio::task::spawn_blocking(move || send_clustered_message(&log, b"sendsync", &m)).await.unwrap_or_default();
        if !resp.is_empty() {
            self.tlog("DEBUG", cat(&[b"(8158): Receiving message from task_manager module: '", &resp, b"'"]));
        }
        parse(&resp)
    }

    /// `wm_agent_upgrade_task_module_callback`: 0 or -1. `remove` is the
    /// `wm_agent_upgrade_remove_entry` error callback.
    async fn task_module_callback(&self, data: &mut Vec<Json>, req: &Json, success: Success, remove: bool) -> i32 {
        let mut error = 0;
        let mut temp = Vec::new();
        let resp = self.send_tasks_information(req).await;
        let ok = resp.as_ref().and_then(|r| r.get("error")).and_then(num) == Some(SUCCESS);
        if ok {
            let items: Vec<Json> = resp.as_ref().and_then(|r| r.get("data")).map(|d| d.children().into_iter().cloned().collect()).unwrap_or_default();
            for item in items {
                if error != 0 {
                    break;
                }
                let out = match success {
                    Success::None => Some(item),
                    Success::Upgrade => self.upgrade_success_callback(&mut error, item),
                    Success::GetStatus => self.get_status_success_callback(&mut error, item),
                    Success::UpdateStatus => self.update_status_success_callback(&mut error, item).await,
                };
                if let Some(o) = out {
                    temp.push(o);
                }
            }
        } else {
            error = OS_INVALID;
        }
        if error != 0 {
            let agents = req.get("parameters").and_then(|p| p.get("agents")).map(|a| a.children().into_iter().cloned().collect::<Vec<_>>()).unwrap_or_default();
            for a in agents {
                if let Some(id) = num(&a) {
                    if remove {
                        self.remove_entry(id);
                    }
                    data.push(data_response(TASK_MANAGER_COMMUNICATION, Some(ERROR_CODES[TASK_MANAGER_COMMUNICATION as usize].as_bytes()), Some(id)));
                }
            }
            let m = "(8123): There has been an error executing the request in the tasks manager.";
            if req.get("command").and_then(|c| c.as_bytes()) == Some(UPGRADE_CANCEL_TASKS.as_bytes()) {
                self.tlog("DEBUG", m);
            } else {
                self.tlog("ERROR", m);
            }
        } else {
            data.extend(temp);
        }
        error
    }

    /// `wm_agent_upgrade_upgrade_success_callback`
    fn upgrade_success_callback(&self, error: &mut i32, input: Json) -> Option<Json> {
        match validate_task_ids_message(&input) {
            Some((agent, task_id, data)) => {
                if task_id == 0 {
                    self.remove_entry(agent);
                    Some(data_response(TASK_MANAGER_FAILURE, Some(&data), Some(agent)))
                } else {
                    Some(input)
                }
            }
            None => {
                *error = OS_INVALID;
                None
            }
        }
    }

    /// `wm_agent_upgrade_get_status_success_callback`
    fn get_status_success_callback(&self, error: &mut i32, input: Json) -> Option<Json> {
        let mut agent = 0;
        match self.validate_task_status_message(Some(&input), &mut agent) {
            Some(status) => {
                if matches!(status.as_deref(), Some(b"Pending") | Some(b"In progress")) {
                    self.remove_entry(agent);
                    Some(data_response(UPGRADE_ALREADY_IN_PROGRESS, Some(ERROR_CODES[UPGRADE_ALREADY_IN_PROGRESS as usize].as_bytes()), Some(agent)))
                } else {
                    None
                }
            }
            None => {
                *error = OS_INVALID;
                None
            }
        }
    }

    /// `wm_agent_upgrade_update_status_success_callback`
    async fn update_status_success_callback(&self, error: &mut i32, input: Json) -> Option<Json> {
        let mut agent = 0;
        // only the agent id decides, as in C
        let _ = self.validate_task_status_message(Some(&input), &mut agent);
        if agent > 0 {
            // Tell agent to erase results file
            let mut ci = Json::object();
            ci.add("command", Json::string("clear_upgrade_result"));
            ci.add("parameters", Json::object());
            let mut cmd = format!("{} upgrade ", pad3(agent)).into_bytes();
            cmd.extend_from_slice(&ci.print_unformatted());
            cmd.truncate(OS_MAXSTR - 1);
            let r = self.send_command_to_agent(&cmd).await;
            if self.parse_agent_upgrade_command_response(r.as_deref(), &mut None) == 0 {
                self.tlog("DEBUG", "(8167): Upgrade result file has been successfully erased from the agent.");
            }
            Some(input)
        } else {
            *error = OS_INVALID;
            None
        }
    }

    /// `wm_agent_upgrade_validate_task_status_message`: Some(status) when the
    /// task manager reported success; sets `agent` when the fields exist.
    fn validate_task_status_message(&self, input: Option<&Json>, agent: &mut i32) -> Option<Option<Vec<u8>>> {
        let input = input?;
        let err = input.get("error").and_then(num);
        let data = input.get("message").and_then(|m| m.as_bytes());
        let a = input.get("agent").and_then(num);
        match (err, data, a) {
            (Some(e), Some(d), Some(a)) => {
                *agent = a;
                if e == SUCCESS {
                    Some(input.get("status").and_then(|s| s.as_bytes()).map(|s| s.to_vec()))
                } else {
                    self.tlog("ERROR", cat(&[format!("(8119): There has been an error updating task state. Error code: '{e}', message: '").as_bytes(), d, b"'"]));
                    None
                }
            }
            _ => {
                self.tlog("ERROR", "(8107): Required parameters in message are missing.");
                None
            }
        }
    }

    /// `wm_agent_upgrade_dispatch_upgrades`
    async fn dispatch_upgrades(self: Arc<Self>) {
        let Some(mut rx) = self.queue_rx.lock().unwrap().take() else { return };
        let sem = Arc::new(Semaphore::new(self.cfg.max_threads as usize));
        loop {
            // Blocks until an available thread is ready
            let Ok(permit) = sem.clone().acquire_owned().await else { return };
            let Some(task) = rx.recv().await else { return };
            let me = self.clone();
            tokio::spawn(async move {
                me.start_upgrade(task).await;
                drop(permit);
            });
        }
    }

    /// Update the task status and check the answer (`validate_task_status_message` of item 0).
    async fn update_status(&self, id: i32, status: &str, error: Option<&str>) -> bool {
        let req = task_module_request(UPGRADE_UPDATE_STATUS, Some(agents_json(&[id])), Some(status.as_bytes()), error.map(|e| e.as_bytes()));
        let mut out = Vec::new();
        self.task_module_callback(&mut out, &req, Success::None, false).await;
        let mut a = 0;
        self.validate_task_status_message(out.first(), &mut a).is_some()
    }

    /// `wm_agent_upgrade_start_upgrade`
    async fn start_upgrade(&self, mut task: AgentTask) {
        let id = task.info.agent_id;
        if !self.update_status(id, STATUS_IN_PROGRESS, None).await {
            return;
        }
        let ec = self.send_wpk_to_agent(&mut task).await;
        if ec == SUCCESS {
            if let TaskKind::Upgrade(t) = &task.task {
                if t.custom_version.as_deref().is_some_and(|v| cmpv(v, NEW_UPGRADE_MECHANISM) < 0) {
                    // The agent won't report the result of the upgrade task
                    self.update_status(id, STATUS_LEGACY, None).await;
                }
            }
        } else {
            self.update_status(id, STATUS_FAILED, Some(ERROR_CODES[ec as usize])).await;
        }
    }

    /// `wm_agent_upgrade_send_wpk_to_agent`
    async fn send_wpk_to_agent(&self, at: &mut AgentTask) -> i32 {
        let r = match &mut at.task {
            TaskKind::Upgrade(t) => {
                let r = validate_wpk_version(&self.log, &mut at.info, t, self.cfg.wpk_repository.as_deref()).await;
                if r == SUCCESS {
                    self.validate_wpk(t).await
                } else {
                    r
                }
            }
            TaskKind::Custom(t) => validate_wpk_custom(t),
        };
        if r != SUCCESS {
            return r;
        }
        let id = at.info.agent_id;
        self.tlog("DEBUG", format!("(8162): Sending WPK to agent: '{}'", pad3(id)));
        let (file_path, file_sha1, mut installer) = match &at.task {
            TaskKind::Upgrade(t) => (format!("{WPK_DEFAULT_PATH}{}", t.wpk_file.as_deref().unwrap_or("")), t.wpk_sha1.clone().unwrap_or_default(), None),
            TaskKind::Custom(t) => {
                let p = t.custom_file_path.clone().unwrap_or_default();
                let sha1 = siem_crypto::hashes::sha1_file(&p).unwrap_or_default();
                (p, sha1, t.custom_installer.clone())
            }
        };
        if installer.is_none() {
            installer = Some(if at.info.platform.as_deref() == Some("windows") { "upgrade.bat" } else { "upgrade.sh" }.to_string());
        }
        let installer = installer.unwrap();
        // basename (a manager hosted on Windows also gets '\' separated paths)
        let sep = |c: char| c == '/' || (cfg!(windows) && c == '\\');
        let trimmed = file_path.trim_end_matches(sep);
        let wpk = trimmed.rsplit(sep).next().unwrap_or(trimmed).to_string();
        let mut result = SUCCESS;
        if self.send_lock_restart(id).await != 0 {
            result = SEND_LOCK_RESTART_ERROR;
        }
        let ver = at.info.wazuh_version.as_deref().unwrap_or("");
        let fmt = cmpv(ver.find('v').map(|p| &ver[p..]).unwrap_or(""), NEW_UPGRADE_MECHANISM);
        if result == SUCCESS && self.send_open(id, fmt, &wpk).await != 0 {
            result = SEND_OPEN_ERROR;
        }
        if result == SUCCESS && self.send_write(id, fmt, &wpk, &file_path).await != 0 {
            result = SEND_WRITE_ERROR;
        }
        if result == SUCCESS && self.send_simple(id, fmt, "close", &wpk, None).await != 0 {
            result = SEND_CLOSE_ERROR;
        }
        if result == SUCCESS && self.send_sha1(id, fmt, &wpk, &file_sha1).await != 0 {
            result = SEND_SHA1_ERROR;
        }
        if result == SUCCESS && self.send_upgrade(id, fmt, &wpk, &installer).await != 0 {
            result = SEND_UPGRADE_ERROR;
        }
        result
    }

    /// `%.3d upgrade {"command":..,"parameters":{..}}` in an OS_MAXSTR buffer.
    fn upgrade_command(id: i32, command: &str, params: Json) -> Vec<u8> {
        let mut ci = Json::object();
        ci.add("command", Json::string(command));
        ci.add("parameters", params);
        let mut c = format!("{} upgrade ", pad3(id)).into_bytes();
        c.extend_from_slice(&ci.print_unformatted());
        c.truncate(OS_MAXSTR - 1);
        c
    }

    /// Parse an agent answer in the format `fmt` selects.
    fn agent_result(&self, fmt: i32, r: Option<&[u8]>, data: &mut Option<Vec<u8>>) -> i32 {
        if fmt >= 0 {
            self.parse_agent_upgrade_command_response(r, data)
        } else {
            self.parse_agent_response(r, data)
        }
    }

    /// `wm_agent_upgrade_send_lock_restart`
    async fn send_lock_restart(&self, id: i32) -> i32 {
        let c = format!("{} com lock_restart -1", pad3(id));
        let r = self.send_command_to_agent(c.as_bytes()).await;
        self.parse_agent_response(r.as_deref(), &mut None)
    }

    /// `wm_agent_upgrade_send_open`
    async fn send_open(&self, id: i32, fmt: i32, wpk: &str) -> i32 {
        let c = if fmt >= 0 {
            let mut p = Json::object();
            p.add("mode", Json::string("wb"));
            p.add("file", Json::string(wpk));
            Self::upgrade_command(id, "open", p)
        } else {
            format!("{} com open wb {wpk}", pad3(id)).into_bytes()
        };
        let mut result = OS_INVALID;
        for _ in 0..WPK_OPEN_ATTEMPTS {
            let r = self.send_command_to_agent(&c).await;
            result = self.agent_result(fmt, r.as_deref(), &mut None);
            if result == 0 {
                break;
            }
        }
        result
    }

    /// `wm_agent_upgrade_send_write`
    async fn send_write(&self, id: i32, fmt: i32, wpk: &str, file_path: &str) -> i32 {
        let Ok(data) = std::fs::read(file_path) else { return OS_INVALID };
        let mut result = OS_INVALID;
        for chunk in data.chunks(self.cfg.chunk_size.max(1) as usize) {
            let c = if fmt >= 0 {
                let mut p = Json::object();
                p.add("buffer", Json::string(base64(chunk)));
                p.add("length", Json::number(chunk.len() as f64));
                p.add("file", Json::string(wpk));
                Self::upgrade_command(id, "write", p)
            } else {
                let mut c = format!("{} com write {} {wpk} ", pad3(id), chunk.len()).into_bytes();
                c.extend_from_slice(chunk);
                c
            };
            let r = self.send_command_to_agent(&c).await;
            result = self.agent_result(fmt, r.as_deref(), &mut None);
            if result != 0 {
                break;
            }
        }
        result
    }

    /// `wm_agent_upgrade_send_close` (and the command part of sha1/upgrade).
    async fn send_simple(&self, id: i32, fmt: i32, command: &str, wpk: &str, data: Option<&mut Option<Vec<u8>>>) -> i32 {
        let c = if fmt >= 0 {
            let mut p = Json::object();
            p.add("file", Json::string(wpk));
            Self::upgrade_command(id, command, p)
        } else {
            format!("{} com {command} {wpk}", pad3(id)).into_bytes()
        };
        let r = self.send_command_to_agent(&c).await;
        let mut none = None;
        self.agent_result(fmt, r.as_deref(), data.unwrap_or(&mut none))
    }

    /// `wm_agent_upgrade_send_sha1`
    async fn send_sha1(&self, id: i32, fmt: i32, wpk: &str, file_sha1: &str) -> i32 {
        let mut data = None;
        let mut result = self.send_simple(id, fmt, "sha1", wpk, Some(&mut data)).await;
        if result == 0 && data.as_deref() != Some(file_sha1.as_bytes()) {
            self.tlog("ERROR", "(8118): The SHA1 of the file doesn't match in the agent.");
            result = OS_INVALID;
        }
        result
    }

    /// `wm_agent_upgrade_send_upgrade`
    async fn send_upgrade(&self, id: i32, fmt: i32, wpk: &str, installer: &str) -> i32 {
        let c = if fmt >= 0 {
            let mut p = Json::object();
            p.add("file", Json::string(wpk));
            p.add("installer", Json::string(installer));
            Self::upgrade_command(id, "upgrade", p)
        } else {
            format!("{} com upgrade {wpk} {installer}", pad3(id)).into_bytes()
        };
        let r = self.send_command_to_agent(&c).await;
        let mut data = None;
        let mut result = self.agent_result(fmt, r.as_deref(), &mut data);
        if result == 0 && !data.as_deref().is_some_and(|d| d.starts_with(b"0")) {
            self.tlog("ERROR", "(8121): Script execution failed in the agent.");
            result = OS_INVALID;
        }
        result
    }

    /// `wm_agent_upgrade_send_command_to_agent`: None when remoted is not
    /// reachable, else the answer (empty after a receive error).
    async fn send_command_to_agent(&self, command: &[u8]) -> Option<Vec<u8>> {
        let mut sock = match LocalStream::connect(REMOTE_LOCAL_SOCK).await {
            Ok(s) => s,
            Err(_) => {
                self.tlog("ERROR", format!("(8114): Cannot connect to '{REMOTE_LOCAL_SOCK}'. Could not reach agent."));
                return None;
            }
        };
        self.tlog("DEBUG2", cat(&[b"(8165): Sending message to agent: '", cstr(command), b"'"]));
        let _ = siem_ipc::framing::send(&mut sock, command).await;
        match siem_ipc::framing::recv(&mut sock, OS_MAXSTR).await {
            Err(siem_ipc::framing::FrameError::TooBig(..)) => {
                self.tlog("ERROR", "(8112): Response size is bigger than expected.");
                Some(Vec::new())
            }
            Err(siem_ipc::framing::FrameError::Closed) => {
                self.tlog("DEBUG2", "(8166): Receiving message from agent: ''");
                Some(Vec::new())
            }
            Err(e) => {
                self.tlog("ERROR", format!("(8111): Error in recv(): '{e}'"));
                Some(Vec::new())
            }
            Ok(b) => {
                let b = cstr(&b).to_vec();
                self.tlog("DEBUG2", cat(&[b"(8166): Receiving message from agent: '", &b, b"'"]));
                Some(b)
            }
        }
    }

    /// `wm_agent_upgrade_parse_agent_response` (`ok <data>` / `err <msg>`)
    fn parse_agent_response(&self, r: Option<&[u8]>, data: &mut Option<Vec<u8>>) -> i32 {
        let Some(r) = r else { return OS_INVALID };
        if r.starts_with(b"ok") {
            if let Some(p) = r.iter().position(|&c| c == b' ') {
                *data = Some(r[p + 1..].to_vec());
            }
            0
        } else {
            if r.starts_with(b"err") {
                if let Some(p) = r.iter().position(|&c| c == b' ') {
                    self.tlog("ERROR", cat(&[b"(8116): Error response from agent: '", &r[p + 1..], b"'"]));
                }
            }
            OS_INVALID
        }
    }

    /// `wm_agent_upgrade_parse_agent_upgrade_command_response` (the JSON ack)
    fn parse_agent_upgrade_command_response(&self, r: Option<&[u8]>, data: &mut Option<Vec<u8>>) -> i32 {
        let mut code = OS_INVALID;
        let mut msg = None;
        if let Some(j) = r.and_then(parse) {
            if let Some(e) = j.get("error").and_then(num) {
                code = e;
            }
            if let Some(m) = j.get("message").and_then(|m| m.as_bytes()) {
                *data = Some(m.to_vec());
                msg = Some(m.to_vec());
            }
        }
        if code != 0 {
            match &msg {
                Some(m) => self.tlog("ERROR", cat(&[b"(8116): Error response from agent: '", m, b"'"])),
                None => self.tlog("ERROR", "(8117): Unknown error from agent."),
            }
            *data = None;
        }
        code
    }

    /// `wm_agent_upgrade_validate_wpk`: download the WPK into var/upgrade unless
    /// a file with its sha1 is there.
    async fn validate_wpk(&self, t: &UpgradeTask) -> i32 {
        let (Some(repo), Some(file), Some(sha1)) = (&t.wpk_repository, &t.wpk_file, &t.wpk_sha1) else {
            return WPK_FILE_DOES_NOT_EXIST;
        };
        let _guard = self.download.lock().await;
        let file_url = format!("{repo}{file}");
        let file_path = format!("{WPK_DEFAULT_PATH}{file}");
        let same = |p: &str| siem_crypto::hashes::sha1_file(p).is_ok_and(|h| h.eq_ignore_ascii_case(sha1));
        if same(&file_path) {
            return SUCCESS;
        }
        self.tlog("DEBUG", format!("(8161): Downloading WPK file from: '{file_url}'"));
        let mut attempts = 0;
        loop {
            attempts += 1;
            if attempts > WPK_DOWNLOAD_ATTEMPTS {
                return SUCCESS;
            }
            if crate::download::wurl_request(&self.log, &file_url, &file_path, None, None, WPK_DOWNLOAD_TIMEOUT).await == 0 {
                return if same(&file_path) { SUCCESS } else { WPK_SHA1_DOES_NOT_MATCH };
            } else if attempts == WPK_DOWNLOAD_ATTEMPTS {
                return WPK_FILE_DOES_NOT_EXIST;
            }
            tokio::time::sleep(Duration::from_secs(attempts)).await;
        }
    }
}

/// `wm_agent_upgrade_validate_task_ids_message`: (agent, task_id, message)
fn validate_task_ids_message(input: &Json) -> Option<(i32, i32, Vec<u8>)> {
    let agent = input.get("agent").and_then(num)?;
    let data = input.get("message").and_then(|m| m.as_bytes())?.to_vec();
    let task_id = input.get("task_id").and_then(num).unwrap_or(0);
    Some((agent, task_id, data))
}

/// `wm_agent_upgrade_validate_agent_task`
fn validate_agent_task(at: &mut AgentTask) -> i32 {
    let i = &mut at.info;
    // wm_agent_upgrade_validate_id
    if i.agent_id == MANAGER_ID {
        return INVALID_ACTION_FOR_MANAGER;
    }
    // wm_agent_upgrade_validate_status (AGENT_CS_ACTIVE)
    if i.connection_status.as_deref() != Some("active") {
        return AGENT_IS_NOT_ACTIVE;
    }
    let r = validate_system(i.platform.as_deref(), i.major_version.as_deref(), i.minor_version.as_deref(), i.architecture.as_deref(), &mut i.package_type);
    if r != SUCCESS {
        return r;
    }
    validate_version(i.wazuh_version.as_deref(), i.platform.as_deref().unwrap_or(""), &mut at.task)
}

/// `wm_agent_upgrade_validate_system`
fn validate_system(platform: Option<&str>, major: Option<&str>, minor: Option<&str>, arch: Option<&str>, package_type: &mut Option<String>) -> i32 {
    const INVALID: [&str; 5] = ["solaris", "sunos", "aix", "hp-ux", "bsd"];
    const ROLLING: [&str; 2] = ["opensuse-tumbleweed", "arch"];
    const DEB: [&str; 2] = ["debian", "ubuntu"];
    const RPM: [&str; 12] = ["amzn", "centos", "fedora", "ol", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "rhel", "sles", "suse", "rocky", "almalinux"];
    let Some(p) = platform else { return GLOBAL_DB_FAILURE };
    if INVALID.contains(&p) {
        return SYSTEM_NOT_SUPPORTED;
    }
    let mut r = GLOBAL_DB_FAILURE;
    if p == "windows" {
        *package_type = Some("msi".into());
        return SUCCESS;
    }
    if p == "darwin" && arch.is_some() {
        *package_type = Some("pkg".into());
        return SUCCESS;
    }
    if arch.is_some() {
        match major {
            Some(m) if p != "ubuntu" || minor.is_some() => {
                r = SUCCESS;
                // Unsupported Linux versions
                if matches!((p, m), ("sles", "11") | ("suse", "11") | ("ol", "5") | ("rhel", "5") | ("centos", "5")) {
                    r = SYSTEM_NOT_SUPPORTED;
                }
            }
            _ => {
                if ROLLING.contains(&p) {
                    r = SUCCESS;
                }
            }
        }
        if r == SUCCESS {
            if DEB.contains(&p) {
                *package_type = Some("deb".into());
            } else if RPM.contains(&p) {
                *package_type = Some("rpm".into());
            }
        }
    }
    r
}

/// `wm_agent_upgrade_validate_version`
fn validate_version(wazuh_version: Option<&str>, platform: &str, task: &mut TaskKind) -> i32 {
    let Some(v) = wazuh_version else { return GLOBAL_DB_FAILURE };
    let Some(p) = v.find('v') else { return GLOBAL_DB_FAILURE };
    let agent = &v[p..];
    if cmpv(agent, MINIMAL_VERSION_SUPPORT) < 0 {
        return NOT_MINIMAL_VERSION_SUPPORTED;
    }
    if cmpv(agent, MINIMAL_VERSION_SUPPORT_MACOS) < 0 && platform == "darwin" {
        return NOT_MINIMAL_VERSION_SUPPORTED;
    }
    match task {
        TaskKind::Upgrade(t) => {
            let manager = OSSEC_VERSION;
            let wpk = t.custom_version.clone().unwrap_or_else(|| manager.to_string());
            t.wpk_version = Some(wpk.clone());
            if !t.force_upgrade {
                if cmpv(agent, &wpk) >= 0 {
                    return NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT;
                } else if cmpv(&wpk, manager) > 0 {
                    return NEW_VERSION_GREATER_MASTER;
                }
            }
            SUCCESS
        }
        TaskKind::Custom(_) => SUCCESS,
    }
}

/// `wm_agent_upgrade_translate_arch`
fn translate_arch<'a>(platform: &str, package_type: &str, arch: &'a str) -> &'a str {
    match (arch, platform == "darwin", package_type) {
        ("x86_64", true, "pkg") => "intel64",
        ("x86_64", false, "deb") => "amd64",
        ("aarch64", true, "pkg") => "arm64",
        ("aarch64", false, "deb") => "arm64",
        _ => arch,
    }
}

/// `sscanf(v, "v%d.%*d.%*d")` / `"%d.%*d.%*d"`: the major number.
fn scan_major(v: &str) -> Option<i64> {
    let s = v.strip_prefix('v').unwrap_or(v);
    let (n, end) = siem_config::util::strtol(s);
    (end > 0).then_some(n)
}

/// `wm_agent_upgrade_validate_wpk_version`: find the WPK and its sha1 in the
/// repository's `versions` file.
async fn validate_wpk_version(log: &Arc<WLog>, info: &mut AgentInfo, t: &mut UpgradeTask, repo_config: Option<&str>) -> i32 {
    let tlog = |level: &str, m: String| log.tagged(LOGTAG, level, m);
    let Some(wpk_version) = t.wpk_version.clone() else { return WPK_VERSION_DOES_NOT_EXIST };
    if t.wpk_repository.is_none() {
        if let Some(r) = repo_config {
            t.wpk_repository = Some(r.to_string());
        } else if cmpv(&wpk_version, "v4.0.0") < 0 {
            t.wpk_repository = Some(WPK_REPO_URL_3_X.to_string());
        } else {
            let Some(ver) = scan_major(&wpk_version) else { return WPK_VERSION_DOES_NOT_EXIST };
            t.wpk_repository = Some(format!("packages.wazuh.com/{}.x/wpk/", ver as i32));
        }
    }
    let repo = t.wpk_repository.clone().unwrap_or_default();
    let mut repository_url = String::new();
    if !repo.contains("http://") && !repo.contains("https://") {
        repository_url.push_str(if t.use_http { "http://" } else { "https://" });
    }
    // strncat(.., OS_SIZE_512)
    repository_url.push_str(&repo.chars().take(512).collect::<String>());
    if !repo.ends_with('/') {
        repository_url.push('/');
    }
    let platform = info.platform.clone().unwrap_or_default();
    let arch = info.architecture.clone().unwrap_or_default();
    let (path_url, file_url) = if platform == "windows" {
        (format!("{repository_url}windows/"), format!("wazuh_agent_{wpk_version}_windows.wpk"))
    } else if platform == "darwin" {
        if cmpv(&wpk_version, NEW_VERSION_STRUCTURE_REPOSITORY) >= 0 {
            let pt = info.package_type.clone().unwrap_or_default();
            let pa = translate_arch(&platform, &pt, &arch);
            (format!("{repository_url}macos/{pt}/{pa}/"), format!("wazuh_agent_{wpk_version}_macos_{pa}.{pt}.wpk"))
        } else {
            let pt = info.package_type.clone().unwrap_or_default();
            (format!("{repository_url}macos/{arch}/{pt}/"), format!("wazuh_agent_{wpk_version}_macos_{arch}.wpk"))
        }
    } else if cmpv(&wpk_version, NEW_LINUX_VERSION_REPOSITORY) >= 0 {
        if cmpv(&wpk_version, NEW_VERSION_STRUCTURE_REPOSITORY) >= 0 {
            let id = info.agent_id;
            if let Some(tp) = &t.package_type {
                match &info.package_type {
                    Some(ap) if ap != tp => {
                        if t.force_upgrade {
                            tlog("DEBUG", format!("(8170): Agent '{id}' with platform '{platform}' will be upgraded using package '{tp}'"));
                            info.package_type = Some(tp.clone());
                        } else {
                            tlog("WARNING", format!("(8169): Agent '{id}' with platform '{platform}' won't be upgraded using package '{tp}' without the force option. Ignoring..."));
                        }
                    }
                    Some(_) => {}
                    None => {
                        tlog("DEBUG", format!("(8172): Agent '{id}' with unsupported platform '{platform}' will be upgraded with package '{tp}'"));
                        info.package_type = Some(tp.clone());
                    }
                }
            } else if info.package_type.is_none() {
                tlog("WARNING", format!("(8171): Agent '{id}' with unsupported platform '{platform}' won't be upgraded without a default package."));
                return SYSTEM_NOT_SUPPORTED;
            }
            let pt = info.package_type.clone().unwrap_or_default();
            let pa = translate_arch(&platform, &pt, &arch);
            (format!("{repository_url}linux/{pt}/{pa}/"), format!("wazuh_agent_{wpk_version}_linux_{pa}.{pt}.wpk"))
        } else {
            (format!("{repository_url}linux/{arch}/"), format!("wazuh_agent_{wpk_version}_linux_{arch}.wpk"))
        }
    } else {
        let major = info.major_version.clone().unwrap_or_default();
        if platform == "ubuntu" {
            let minor = info.minor_version.clone().unwrap_or_default();
            (format!("{repository_url}{platform}/{major}.{minor}/{arch}/"), format!("wazuh_agent_{wpk_version}_{platform}_{major}.{minor}_{arch}.wpk"))
        } else {
            (format!("{repository_url}{platform}/{major}/{arch}/"), format!("wazuh_agent_{wpk_version}_{platform}_{major}_{arch}.wpk"))
        }
    };
    let versions_url = format!("{path_url}versions");
    let Some(versions) = crate::download::wurl_http_get(log, &versions_url, MAX_RESPONSE_SIZE, DEFAULT_REQUEST_TIMEOUT).await else {
        return URL_NOT_FOUND;
    };
    // "<version> <sha1>" lines; the first matching version wins
    let text = String::from_utf8_lossy(cstr(&versions)).into_owned();
    for line in text.split('\n') {
        if let Some((v, sha1)) = line.split_once(' ') {
            if cmpv(&wpk_version, v) == 0 {
                t.wpk_sha1 = Some(sha1.to_string());
                t.wpk_file = Some(file_url.clone());
                t.wpk_repository = Some(path_url.clone());
                break;
            }
        }
    }
    if t.wpk_repository.is_none() || t.wpk_file.is_none() || t.wpk_sha1.is_none() {
        return WPK_VERSION_DOES_NOT_EXIST;
    }
    SUCCESS
}

/// `wm_agent_upgrade_validate_wpk_custom`
fn validate_wpk_custom(t: &CustomTask) -> i32 {
    match &t.custom_file_path {
        Some(p) if std::fs::File::open(p).is_ok() => SUCCESS,
        _ => WPK_FILE_DOES_NOT_EXIST,
    }
}

/// `w_send_clustered_message`: the response (empty when there is none).
#[cfg(unix)]
fn send_clustered_message(log: &WLog, command: &[u8], payload: &[u8]) -> Vec<u8> {
    const ATTEMPTS: usize = 10;
    let mut response = Vec::new();
    for attempt in 0..ATTEMPTS {
        let mut send_error = false;
        let sock = siem_ipc::os_net::connect_unix_domain(CLUSTER_SOCK, siem_ipc::os_net::SOCK_STREAM, OS_MAXSTR as i32);
        if sock >= 0 {
            if siem_execd::wcom::send_secure_tcp_cluster(sock, command, payload) >= 0 {
                let n = siem_execd::wcom::recv_secure_cluster_tcp(sock, &mut response, OS_MAXSTR);
                match n {
                    -2 => {
                        log.debug1("Cluster error detected");
                        send_error = true;
                    }
                    -1 => {
                        log.debug1(format!("OS_RecvSecureClusterTCP(): {}", siem_ipc::os_net::strerror(siem_ipc::os_net::errno())));
                        send_error = true;
                    }
                    0 => log.debug1("Empty message from local client."),
                    _ => {}
                }
                if n <= 0 {
                    response.clear();
                }
            } else {
                log.debug1(format!("OS_SendSecureTCPCluster(): {}", siem_ipc::os_net::strerror(siem_ipc::os_net::errno())));
                send_error = true;
            }
            siem_ipc::os_net::close_fd(sock);
        } else {
            let e = siem_ipc::os_net::errno();
            log.debug1(format!("Could not connect to socket '{CLUSTER_SOCK}': {} ({e}).", siem_ipc::os_net::strerror(e)));
            send_error = true;
        }
        if !send_error {
            break;
        } else if attempt == ATTEMPTS - 1 {
            log.warn(format!("Could not send message through the cluster after '{ATTEMPTS}' attempts."));
        } else {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    response
}

/// No cluster daemon on Windows: the worker path gets no answer.
#[cfg(windows)]
fn send_clustered_message(_log: &WLog, _command: &[u8], _payload: &[u8]) -> Vec<u8> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn um() -> UpgradeManager {
        struct NoDb;
        #[async_trait::async_trait]
        impl WdbQuery for NoDb {
            async fn query(&self, _q: &str) -> Result<String, siem_ipc::wdbc::WdbcError> {
                Ok("ok []".into())
            }
        }
        UpgradeManager::new(Config::default(), crate::task_general::test_log(), Arc::new(NoDb))
    }

    #[tokio::test]
    async fn parse_errors_like_c() {
        let u = um();
        assert_eq!(u.process_request(b"x").await, br#"{"error":1,"data":[{"error":1,"message":"Could not parse message JSON"}],"message":"Could not parse message JSON"}"#);
        assert_eq!(
            u.process_request(br#"{"command":"upgrade","parameters":{}}"#).await,
            br#"{"error":2,"data":[{"error":2,"message":"Required parameters in json message where not found"}],"message":"Required parameters in json message where not found"}"#
        );
        assert_eq!(
            u.process_request(br#"{"command":"nope","parameters":{"agents":[1]}}"#).await,
            br#"{"error":3,"data":[{"error":3,"message":"JSON parameter not recognized"}],"message":"JSON parameter not recognized"}"#
        );
        assert_eq!(
            u.process_request(br#"{"command":"upgrade","parameters":{"agents":[1],"use_http":"x"}}"#).await,
            br#"{"error":3,"data":[{"error":3,"message":"Parameter \"use_http\" should be true or false"}],"message":"JSON parameter not recognized"}"#
        );
    }

    #[test]
    fn system_and_version_rules() {
        let mut pt = None;
        assert_eq!(validate_system(Some("ubuntu"), Some("22"), Some("04"), Some("x86_64"), &mut pt), SUCCESS);
        assert_eq!(pt.as_deref(), Some("deb"));
        let mut pt = None;
        assert_eq!(validate_system(Some("centos"), Some("5"), None, Some("x86_64"), &mut pt), SYSTEM_NOT_SUPPORTED);
        let mut t = TaskKind::Upgrade(UpgradeTask::default());
        assert_eq!(validate_version(Some("Wazuh v4.14.7"), "windows", &mut t), NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT);
        assert_eq!(validate_version(Some("Wazuh v4.13.0"), "windows", &mut t), SUCCESS);
        assert_eq!(base64(b"hello"), "aGVsbG8=");
        assert_eq!(pad3(7), "007");
    }
}
