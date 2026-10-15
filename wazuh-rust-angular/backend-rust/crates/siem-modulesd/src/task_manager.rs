//! The task manager module (`wazuh_modules/task_manager/*.c`,
//! `config/wmodules-task-manager.c`): the `queue/tasks/task` socket that
//! keeps the upgrade tasks in wazuh-db's tasks database.

use std::sync::Arc;
use std::time::Duration;

use siem_cjson::Json;
use siem_config::ConfigContext;
use siem_ipc::local::StreamListener;
use siem_ipc::wdbc::{parse_result, WdbQuery, WdbcResult};
use siem_log::WLog;
use siem_xml::XmlNode;

use crate::task_general::*;

/// `TASK_MANAGER_WM_NAME`
pub const NAME: &str = "task-manager";
/// `WM_TASK_MANAGER_LOGTAG`
const LOGTAG: &str = "wazuh-modulesd:task-manager";
/// `TASK_QUEUE`
pub const TASK_QUEUE: &str = "queue/tasks/task";
/// `WM_TASK_CLEANUP_DB_SLEEP_TIME`
const CLEANUP_DB_SLEEP_TIME: i64 = 86400;
/// `WDBQUERY_SIZE` (OS_BUFFER_SIZE): `snprintf` keeps 2047 bytes.
const WDBQUERY_SIZE: usize = 2048;

/// `wm_task_manager`
#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    pub cleanup_time: i32,
    pub task_timeout: i32,
}

impl Default for Config {
    fn default() -> Self {
        // WM_TASK_DEFAULT_CLEANUP_TIME, WM_TASK_MAX_IN_PROGRESS_TIME
        Config { enabled: true, cleanup_time: 604800, task_timeout: 900 }
    }
}

/// `wm_task_manager_read` for the `<task-manager>` children.
pub fn read(ctx: &mut ConfigContext, nodes: Option<&[XmlNode]>, data: &mut Config) -> Result<(), ()> {
    let Some(nodes) = nodes else { return Ok(()) };
    for n in nodes {
        let tag = n.element.as_str();
        if tag == "cleanup_time" || tag == "task_timeout" {
            let (v, end) = strtol0(n.content.as_deref().unwrap_or(""));
            // the long is stored in an int
            let v = v as i32;
            if v == 0 || v == i32::MAX {
                ctx.error(format!("Invalid {tag} at module '{NAME}'"));
                return Err(());
            }
            let v = match end {
                b'd' => v.wrapping_mul(86400),
                b'h' => v.wrapping_mul(3600),
                b'm' => v.wrapping_mul(60),
                b's' | 0 => v,
                _ => {
                    ctx.error(format!("Invalid {tag} at module '{NAME}'"));
                    return Err(());
                }
            };
            if tag == "cleanup_time" {
                data.cleanup_time = v;
            } else {
                data.task_timeout = v;
            }
        } else {
            ctx.warn(format!("No such tag <{tag}> at module '{NAME}'."));
        }
    }
    if data.cleanup_time < data.task_timeout {
        ctx.error(format!("Too short cleanup_time at module '{NAME}'"));
        return Err(());
    }
    Ok(())
}

/// `error_code` and `error_codes`
const SUCCESS: i32 = 0;
const INVALID_MESSAGE: i32 = 1;
const INVALID_COMMAND: i32 = 2;
const DATABASE_NO_TASK: i32 = 3;
const DATABASE_ERROR: i32 = 4;
const DATABASE_PARSE_ERROR: i32 = 5;
const DATABASE_REQUEST_ERROR: i32 = 6;
const ERROR_CODES: [&str; 8] = [
    "Success",
    "Invalid message",
    "Invalid command",
    "No task in DB",
    "Database error",
    "Parse DB response error",
    "Error in DB request",
    "Unknown error",
];

/// `wm_task_manager_task`
enum Task {
    Upgrade { custom: bool, node: Vec<u8>, module: Vec<u8>, agents: Vec<i32> },
    GetStatus { node: Vec<u8>, agents: Vec<i32> },
    UpdateStatus { node: Vec<u8>, agents: Vec<i32>, status: Vec<u8>, error_msg: Option<Vec<u8>> },
    Result { agents: Vec<i32> },
    CancelTasks { node: Vec<u8> },
    Unknown,
}

pub struct TaskManager {
    cfg: Config,
    log: Arc<WLog>,
    db: Arc<dyn WdbQuery>,
}

impl TaskManager {
    pub fn new(cfg: Config, log: Arc<WLog>, db: Arc<dyn WdbQuery>) -> Self {
        TaskManager { cfg, log, db }
    }

    fn tlog(&self, level: &str, m: impl AsRef<[u8]>) {
        self.log.tagged(LOGTAG, level, m);
    }

    /// `wm_task_manager_main`
    pub async fn main(self: Arc<Self>) {
        if is_worker() {
            self.tlog("INFO", "(8207): Module Task Manager only runs on Master nodes in cluster configuration.");
            return;
        }
        // wm_task_manager_init
        if !self.cfg.enabled {
            self.tlog("INFO", "(8202): Module disabled. Exiting...");
            return;
        }
        let me = self.clone();
        tokio::spawn(async move { me.clean_tasks().await });
        let listener = match StreamListener::bind(TASK_QUEUE).await {
            Ok(l) => l,
            Err(e) => {
                self.tlog("ERROR", format!("(8251): Queue '{TASK_QUEUE}' not accessible: '{}'. Exiting...", crate::wdb::errno_text(&e)));
                return;
            }
        };
        self.tlog("INFO", "(8200): Module Task Manager started.");
        loop {
            let mut peer = match listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    self.tlog("ERROR", format!("(8253): Error in accept(): '{}'", crate::wdb::errno_text(&e)));
                    continue;
                }
            };
            match siem_ipc::framing::recv(&mut peer, OS_MAXSTR).await {
                Err(siem_ipc::framing::FrameError::TooBig(..)) => self.tlog("ERROR", "(8255): Response size is bigger than expected."),
                Err(siem_ipc::framing::FrameError::Closed) => self.tlog("DEBUG", "(8203): Empty message from local client."),
                Err(e) => self.tlog("ERROR", format!("(8254): Error in recv(): '{e}'")),
                Ok(b) if b.is_empty() => self.tlog("DEBUG", "(8203): Empty message from local client."),
                Ok(b) => {
                    let response = self.dispatch(&b).await;
                    let _ = siem_ipc::framing::send(&mut peer, &response).await;
                }
            }
        }
    }

    /// `wm_task_manager_dispatch`
    pub async fn dispatch(&self, msg: &[u8]) -> Vec<u8> {
        let msg = cstr(msg);
        self.tlog("DEBUG", cat(&[b"(8204): Incomming message: '", msg, b"'"]));
        let Some(task) = self.parse_message(msg) else {
            let e = data_response(INVALID_MESSAGE, OS_INVALID, OS_INVALID, None);
            return response(INVALID_MESSAGE, Some(e)).print_unformatted();
        };
        let (mut data, error_code) = self.process_task(&task).await;
        match error_code {
            INVALID_COMMAND => {
                self.tlog("ERROR", "(8258): No action defined for command provided.");
                data = Some(data_response(INVALID_COMMAND, OS_INVALID, OS_INVALID, None));
            }
            DATABASE_ERROR | DATABASE_PARSE_ERROR | DATABASE_REQUEST_ERROR => {
                self.tlog("ERROR", "(8261): Database error.");
                data = Some(data_response(error_code, OS_INVALID, OS_INVALID, None));
            }
            _ => {}
        }
        let out = response(error_code, data).print_unformatted();
        self.tlog("DEBUG", cat(&[b"(8205): Response to message: '", &out, b"'"]));
        out
    }

    /// `wm_task_manager_parse_message`
    fn parse_message(&self, msg: &[u8]) -> Option<Task> {
        let Some(event) = parse(msg) else {
            self.tlog("ERROR", cat(&[b"(8257): Error parsing JSON event: '", msg, b"'"]));
            return None;
        };
        let key_error = |k: &str| self.tlog("ERROR", format!("(8259): Invalid message. '{k}' not found."));
        let Some(origin) = event.get("origin").filter(|o| o.is_object()) else {
            key_error("origin");
            return None;
        };
        let Some(command) = event.get("command").and_then(|c| c.as_bytes()) else {
            key_error("command");
            return None;
        };
        let Some(params) = event.get("parameters").filter(|o| o.is_object()) else {
            key_error("parameters");
            return None;
        };
        let name = || match origin.get("name").and_then(|n| n.as_bytes()) {
            Some(n) => Some(n.to_vec()),
            None => {
                key_error("name");
                None
            }
        };
        let agents = || match self.parse_ids(params.get("agents")) {
            Some(a) => Some(a),
            None => {
                key_error("agents");
                None
            }
        };
        let task = match command {
            b"upgrade" | b"upgrade_custom" => {
                let node = name()?;
                let Some(module) = origin.get("module").and_then(|n| n.as_bytes()) else {
                    key_error("module");
                    return None;
                };
                Task::Upgrade { custom: command == b"upgrade_custom", node, module: module.to_vec(), agents: agents()? }
            }
            b"upgrade_get_status" => {
                let node = name()?;
                Task::GetStatus { node, agents: agents()? }
            }
            b"upgrade_update_status" => {
                let node = name()?;
                let Some(status) = params.get("status").and_then(|n| n.as_bytes()) else {
                    key_error("status");
                    return None;
                };
                let error_msg = params.get("error_msg").and_then(|n| n.as_bytes()).map(|e| e.to_vec());
                Task::UpdateStatus { node, agents: agents()?, status: status.to_vec(), error_msg }
            }
            b"upgrade_result" => Task::Result { agents: agents()? },
            b"upgrade_cancel_tasks" => Task::CancelTasks { node: name()? },
            _ => Task::Unknown,
        };
        Some(task)
    }

    /// `wm_task_manager_parse_ids`: None when empty or with a non-number.
    fn parse_ids(&self, ids: Option<&Json>) -> Option<Vec<i32>> {
        let mut out = Vec::new();
        for id in ids.map(|i| i.children()).unwrap_or_default() {
            match id {
                Json::Number { int, .. } => out.push(*int),
                _ => {
                    self.tlog("ERROR", "(8260): Invalid element in array.");
                    return None;
                }
            }
        }
        // the list ends at the first -1, as in the C array
        if let Some(p) = out.iter().position(|&i| i == OS_INVALID) {
            out.truncate(p);
        }
        (!out.is_empty()).then_some(out)
    }

    /// `wm_task_manager_process_task`: (data, error code)
    async fn process_task(&self, task: &Task) -> (Option<Json>, i32) {
        let mut ec = SUCCESS;
        let data = match task {
            Task::Upgrade { custom, node, module, agents } => {
                let cmd = if *custom { UPGRADE_CUSTOM } else { UPGRADE };
                let mut out = Json::array();
                let mut failed = false;
                for &id in agents {
                    let mut p = Json::object();
                    p.add("agent", Json::number(id as f64));
                    p.add("node", Json::string(node));
                    p.add("module", Json::string(module));
                    let Some(r) = self.send_message_to_wdb(cmd, &p, &mut ec).await else {
                        failed = true;
                        break;
                    };
                    if wdb_error(&r) == Some(0) {
                        let task_id = r.get("task_id").and_then(num).unwrap_or(OS_INVALID);
                        out.push(data_response(SUCCESS, id, task_id, None));
                    } else {
                        ec = DATABASE_ERROR;
                        failed = true;
                        break;
                    }
                }
                (!failed).then_some(out)
            }
            Task::GetStatus { node, agents } => {
                let mut out = Json::array();
                let mut failed = false;
                for &id in agents {
                    let mut p = Json::object();
                    p.add("agent", Json::number(id as f64));
                    p.add("node", Json::string(node));
                    let Some(r) = self.send_message_to_wdb(UPGRADE_GET_STATUS, &p, &mut ec).await else {
                        failed = true;
                        break;
                    };
                    if wdb_error(&r) == Some(0) {
                        let status = r.get("status").and_then(|s| s.as_bytes());
                        out.push(data_response(SUCCESS, id, OS_INVALID, status));
                    } else {
                        ec = DATABASE_ERROR;
                        failed = true;
                        break;
                    }
                }
                (!failed).then_some(out)
            }
            Task::UpdateStatus { node, agents, status, error_msg } => {
                let mut out = Json::array();
                let mut failed = false;
                for &id in agents {
                    let mut p = Json::object();
                    p.add("agent", Json::number(id as f64));
                    p.add("node", Json::string(node));
                    p.add("status", Json::string(status));
                    if let Some(e) = error_msg {
                        p.add("error_msg", Json::string(e));
                    }
                    let Some(r) = self.send_message_to_wdb(UPGRADE_UPDATE_STATUS, &p, &mut ec).await else {
                        failed = true;
                        break;
                    };
                    match wdb_error(&r) {
                        Some(0) => {
                            out.push(data_response(SUCCESS, id, OS_INVALID, None));
                        }
                        // OS_NOTFOUND
                        Some(-2) => {
                            out.push(data_response(DATABASE_NO_TASK, id, OS_INVALID, None));
                        }
                        _ => {
                            ec = DATABASE_ERROR;
                            failed = true;
                            break;
                        }
                    }
                }
                (!failed).then_some(out)
            }
            Task::Result { agents } => {
                let mut out = Json::array();
                let mut failed = false;
                for &id in agents {
                    let mut p = Json::object();
                    p.add("agent", Json::number(id as f64));
                    let Some(r) = self.send_message_to_wdb(UPGRADE_RESULT, &p, &mut ec).await else {
                        failed = true;
                        break;
                    };
                    match wdb_error(&r) {
                        Some(0) => {
                            let s = |k: &str| r.get(k).and_then(|v| v.as_bytes());
                            let task_id = r.get("task_id").and_then(num).unwrap_or(OS_INVALID);
                            let create = r.get("create_time").and_then(num).unwrap_or(OS_INVALID);
                            let update = r.get("update_time").and_then(num).unwrap_or(OS_INVALID);
                            let mut d = data_response(SUCCESS, id, task_id, None);
                            data_result(&mut d, s("node"), s("module"), s("command"), s("status"), s("error_msg"), create, update, Some(UPGRADE_RESULT));
                            out.push(d);
                        }
                        Some(-2) => {
                            out.push(data_response(DATABASE_NO_TASK, id, OS_INVALID, None));
                        }
                        _ => {
                            ec = DATABASE_ERROR;
                            failed = true;
                            break;
                        }
                    }
                }
                (!failed).then_some(out)
            }
            Task::CancelTasks { node } => {
                let mut p = Json::object();
                p.add("node", Json::string(node));
                match self.send_message_to_wdb(UPGRADE_CANCEL_TASKS, &p, &mut ec).await {
                    Some(r) if wdb_error(&r) == Some(0) => Some(data_response(SUCCESS, OS_INVALID, OS_INVALID, None)),
                    Some(_) => {
                        ec = DATABASE_ERROR;
                        None
                    }
                    None => None,
                }
            }
            Task::Unknown => {
                ec = INVALID_COMMAND;
                None
            }
        };
        (data, ec)
    }

    /// `wm_task_manager_clean_tasks`
    async fn clean_tasks(&self) {
        let now_s = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let mut next_clean = now_s();
        let mut next_timeout = now_s();
        loop {
            let now = now_s();
            if now >= next_timeout {
                // Set the status of old tasks IN PROGRESS to TIMEOUT
                let mut p = Json::object();
                p.add("now", Json::number(now as f64));
                p.add("interval", Json::number(self.cfg.task_timeout as f64));
                next_timeout = now + self.cfg.task_timeout as i64;
                let mut ec = SUCCESS;
                if let Some(r) = self.send_message_to_wdb(SET_TIMEOUT, &p, &mut ec).await {
                    if wdb_error(&r) == Some(0) {
                        if let Some(t) = r.get("timestamp").and_then(num) {
                            next_timeout = t as i64;
                        }
                    }
                }
            }
            if now >= next_clean {
                // Delete entries older than cleanup_time
                let mut p = Json::object();
                p.add("timestamp", Json::number((now - self.cfg.cleanup_time as i64) as f64));
                next_clean = now + CLEANUP_DB_SLEEP_TIME;
                let mut ec = SUCCESS;
                let _ = self.send_message_to_wdb(DELETE_OLD, &p, &mut ec).await;
            }
            // w_sleep_until
            let until = next_timeout.min(next_clean);
            let wait = until - now_s();
            if wait > 0 {
                tokio::time::sleep(Duration::from_secs(wait as u64)).await;
            }
        }
    }

    /// `wm_task_manager_send_message_to_wdb`
    async fn send_message_to_wdb(&self, command: &str, params: &Json, ec: &mut i32) -> Option<Json> {
        let mut q = cat(&[b"task ", command.as_bytes(), b" ", &params.print_unformatted()]);
        q.truncate(WDBQUERY_SIZE - 1);
        let resp = match crate::wdb::query_ex(&*self.db, &self.log, &String::from_utf8_lossy(&q)).await {
            Ok(r) => r,
            Err(_) => {
                self.tlog("ERROR", "(8209): Tasks DB Cannot execute SQL query: err database 'queue/tasks/tasks.db'");
                *ec = DATABASE_ERROR;
                return None;
            }
        };
        match parse_result(&resp) {
            (WdbcResult::Ok, payload) => {
                let r = parse(payload.as_bytes());
                if r.is_none() {
                    self.tlog("ERROR", format!("(8257): Error parsing JSON event: '{payload}'"));
                    *ec = DATABASE_PARSE_ERROR;
                }
                r
            }
            (_, payload) => {
                self.tlog("ERROR", format!("(8208): Tasks DB Error reported in the result of the query, message: '{payload}'"));
                *ec = DATABASE_REQUEST_ERROR;
                None
            }
        }
    }
}

/// A number's `valueint`.
fn num(j: &Json) -> Option<i32> {
    match j {
        Json::Number { int, .. } => Some(*int),
        _ => None,
    }
}

/// The "error" number of a wazuh-db reply.
fn wdb_error(r: &Json) -> Option<i32> {
    r.get("error").and_then(num)
}

/// `wm_task_manager_parse_data_response`
fn data_response(error_code: i32, agent_id: i32, task_id: i32, status: Option<&[u8]>) -> Json {
    let mut r = Json::object();
    r.add("error", Json::number(error_code as f64));
    r.add("message", Json::string(ERROR_CODES[error_code as usize]));
    if agent_id != OS_INVALID {
        r.add("agent", Json::number(agent_id as f64));
    }
    if task_id != OS_INVALID {
        r.add("task_id", Json::number(task_id as f64));
    }
    if let Some(s) = status {
        r.add("status", Json::string(s));
    }
    r
}

/// `wm_task_manager_parse_response`
fn response(error_code: i32, data: Option<Json>) -> Json {
    let mut r = Json::object();
    r.add("error", Json::number(error_code as f64));
    let data = match data {
        Some(d @ Json::Array(_)) => d,
        Some(d) => Json::Array(vec![d]),
        None => Json::array(),
    };
    r.add("data", data);
    r.add("message", Json::string(ERROR_CODES[error_code as usize]));
    r
}

/// `wm_task_manager_decode_status`
fn decode_status(status: &[u8]) -> Option<&'static str> {
    Some(match status {
        b"Pending" => "In queue",
        b"In progress" => "Updating",
        b"Done" => "Updated",
        b"Failed" => "Error",
        b"Cancelled" => "Task cancelled since the manager was restarted",
        b"Timeout" => "Timeout reached while waiting for the response from the agent, check the result manually on the agent for more information",
        b"Legacy" => "Legacy upgrade: check the result manually since the agent cannot report the result of the task",
        _ => return None,
    })
}

/// `wm_task_manager_parse_data_result`
#[allow(clippy::too_many_arguments)]
fn data_result(
    r: &mut Json,
    node: Option<&[u8]>,
    module: Option<&[u8]>,
    command: Option<&[u8]>,
    status: Option<&[u8]>,
    error: Option<&[u8]>,
    create_time: i32,
    last_update_time: i32,
    request_command: Option<&str>,
) {
    if let Some(n) = node {
        r.add("node", Json::string(n));
    }
    if let Some(m) = module {
        r.add("module", Json::string(m));
    }
    if let Some(c) = command {
        r.add("command", Json::string(c));
    }
    if let Some(s) = status {
        if request_command == Some(UPGRADE_RESULT) {
            // cJSON_AddStringToObject(.., NULL) adds nothing
            if let Some(d) = decode_status(s) {
                r.add("status", Json::string(d));
            }
        } else {
            r.add("status", Json::string(s));
        }
    }
    if let Some(e) = error {
        r.add("error_msg", Json::string(e));
    }
    if create_time != OS_INVALID {
        r.add("create_time", Json::string(timestamp(create_time as i64)));
    }
    if last_update_time != OS_INVALID && last_update_time > 0 {
        r.add("update_time", Json::string(timestamp(last_update_time as i64)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoDb;
    #[async_trait::async_trait]
    impl WdbQuery for NoDb {
        async fn query(&self, q: &str) -> Result<String, siem_ipc::wdbc::WdbcError> {
            Ok(match q {
                q if q.starts_with("task upgrade ") => r#"ok {"error":0,"task_id":7}"#.into(),
                q if q.starts_with("task upgrade_result ") => r#"ok {"error":0,"task_id":7,"node":"n1","module":"upgrade_module","command":"upgrade","status":"In progress","error_msg":"","create_time":0,"update_time":0}"#.into(),
                _ => "err nope".into(),
            })
        }
    }

    fn tm() -> TaskManager {
        TaskManager::new(Config::default(), crate::task_general::test_log(), Arc::new(NoDb))
    }

    #[tokio::test]
    async fn responses_like_c() {
        let t = tm();
        assert_eq!(t.dispatch(b"nope").await, br#"{"error":1,"data":[{"error":1,"message":"Invalid message"}],"message":"Invalid message"}"#);
        let r = t.dispatch(br#"{"origin":{"name":"n1","module":"upgrade_module"},"command":"upgrade","parameters":{"agents":[1,2]}}"#).await;
        assert_eq!(r, br#"{"error":0,"data":[{"error":0,"message":"Success","agent":1,"task_id":7},{"error":0,"message":"Success","agent":2,"task_id":7}],"message":"Success"}"#);
        let r = t.dispatch(br#"{"origin":{"name":"n1"},"command":"bogus","parameters":{}}"#).await;
        assert_eq!(r, br#"{"error":2,"data":[{"error":2,"message":"Invalid command"}],"message":"Invalid command"}"#);
        let r = t.dispatch(br#"{"origin":{"name":"n1"},"command":"upgrade_cancel_tasks","parameters":{}}"#).await;
        assert_eq!(r, br#"{"error":6,"data":[{"error":6,"message":"Error in DB request"}],"message":"Error in DB request"}"#);
        let r = t.dispatch(br#"{"origin":{},"command":"upgrade_result","parameters":{"agents":[3]}}"#).await;
        assert!(String::from_utf8_lossy(&r).contains(r#""status":"Updating","error_msg":"","create_time":"#), "{}", String::from_utf8_lossy(&r));
    }
}
