//! wazuh-logtest service (analysisd/logtest.c): sessions and the JSON
//! request/response protocol spoken on `queue/sockets/logtest`.

use std::collections::HashMap;
use std::path::PathBuf;

use siem_cjson::Json;

use crate::engine::{Engine, EngineConfig};
use crate::logmsg::{LogLevel, LogList};
use crate::ruleset::{load_from_ossec_conf, RulesetConfig};

pub const W_LOGTEST_TOKEN_LENGH: usize = 8;
pub const W_LOGTEST_ERROR_JSON_PARSE_NSTR: usize = 20;

pub const W_LOGTEST_RCODE_ERROR_INPUT: i32 = -2;
pub const W_LOGTEST_RCODE_ERROR_PROCESS: i32 = -1;
pub const W_LOGTEST_RCODE_SUCCESS: i32 = 0;
pub const W_LOGTEST_RCODE_WARNING: i32 = 1;

pub const W_LOGTEST_CODE_SUCCESS: i32 = 0;
pub const W_LOGTEST_CODE_ERROR_PARSING: i32 = 1;
pub const W_LOGTEST_CODE_INVALID_JSON: i32 = 2;
pub const W_LOGTEST_CODE_COMMAND_NOT_ALLOWED: i32 = 3;
pub const W_LOGTEST_CODE_INVALID_TOKEN: i32 = 4;
pub const W_LOGTEST_CODE_MSG_TOO_LARGE: i32 = 5;

pub const LOGTEST_ERROR_RECV_MSG_OVERSIZE: &str = "(7315): Failure to receive message: size is bigger than expected";

/// `w_logtest_session_t`
pub struct Session {
    pub token: String,
    pub engine: Engine,
    pub logbylevel: i32,
    pub last_connection: i64,
}

impl Session {
    /// A session over an already loaded ruleset.
    pub fn with_engine(token: String, engine: Engine, logbylevel: i32) -> Session {
        Session { token, engine, logbylevel, last_connection: now() }
    }

    /// `w_logtest_initialize_session` body: load the ruleset from scratch.
    pub fn initialize(token: String, cfg: EngineConfig, ruleset: &RulesetConfig, log: &mut LogList) -> Option<Session> {
        let mut engine = Engine::new(cfg);
        if !engine.load_ruleset(&ruleset.decoders, &ruleset.lists, &ruleset.includes, None, log) {
            return None;
        }
        Some(Session::with_engine(token, engine, ruleset.logbylevel.map(|v| v as i32).unwrap_or(0)))
    }
}

fn now() -> i64 {
    crate::event::TimeSpec::now().sec
}

/// `w_logtest_conf` + what a session needs to load the ruleset.
#[derive(Debug, Clone)]
pub struct LogtestConfig {
    pub enabled: bool,
    pub threads: u16,
    pub max_sessions: u16,
    pub session_timeout: i64,
    /// `OSSECCONF` (`etc/ossec.conf`), read again for every new session.
    pub ossec_conf: PathBuf,
    pub engine: EngineConfig,
}

/// The logtest service: the session table (`w_logtest_sessions`) and the
/// connection counter (`active_client`).
pub struct Logtest {
    pub conf: LogtestConfig,
    pub sessions: HashMap<String, Session>,
    pub active_client: i32,
    /// Load the global rules hash into new sessions (`Config.g_rules_hash`).
    pub g_rules_hash: HashMap<String, crate::rules::RuleId>,
    /// Token source (`randombytes`); replaceable for tests.
    pub token_source: Box<dyn FnMut() -> u32 + Send>,
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    if getrandom_fill(&mut b) {
        u32::from_ne_bytes(b)
    } else {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        (t.as_nanos() as u32) ^ std::process::id().rotate_left(16)
    }
}

/// Fill from the OS random source when available.
fn getrandom_fill(b: &mut [u8]) -> bool {
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            return f.read_exact(b).is_ok();
        }
        false
    }
    #[cfg(not(unix))]
    {
        let _ = b;
        false
    }
}

fn err_obj_get<'a>(root: &'a Json, key: &str) -> Option<&'a Json> {
    root.get_exact(key)
}

fn is_nonempty_string(j: Option<&Json>) -> bool {
    matches!(j, Some(Json::String(s)) if !s.is_empty() && s[0] != 0)
}

/// `cJSON_GetStringValue`
fn string_value(j: Option<&Json>) -> Option<&[u8]> {
    match j {
        Some(Json::String(s)) => Some(siem_cjson_cstr(s)),
        _ => None,
    }
}

fn siem_cjson_cstr(s: &[u8]) -> &[u8] {
    crate::event::cstr(s, 0)
}

impl Logtest {
    pub fn new(conf: LogtestConfig) -> Self {
        Logtest {
            conf,
            sessions: HashMap::new(),
            active_client: 0,
            g_rules_hash: HashMap::new(),
            token_source: Box::new(rand_u32),
        }
    }

    /// `w_logtest_generate_token`: "%08x" of a random int32, unique.
    fn generate_token(&mut self) -> String {
        loop {
            let t = format!("{:08x}", (self.token_source)());
            if !self.sessions.contains_key(&t) {
                return t;
            }
        }
    }

    /// `w_logtest_initialize_session`
    pub fn initialize_session(&mut self, log: &mut LogList) -> Option<Session> {
        let token = self.generate_token();
        let home = self.conf.engine.rule.home.clone();
        let ruleset = load_from_ossec_conf(&crate::rules::resolve(&home, &self.conf.ossec_conf.to_string_lossy()), &home, log)?;
        let mut s = Session::initialize(token, self.conf.engine.clone(), &ruleset, log)?;
        for (k, v) in &self.g_rules_hash {
            s.engine.g_rules_hash.entry(k.clone()).or_insert(*v);
        }
        Some(s)
    }

    /// `w_logtest_register_session` (+ `w_logtest_remove_old_session`)
    fn register_session(&mut self, s: Session) {
        self.active_client += 1;
        if self.active_client > self.conf.max_sessions as i32 {
            let old = self
                .sessions
                .values()
                .min_by(|a, b| a.last_connection.cmp(&b.last_connection).then(a.token.cmp(&b.token)))
                .map(|s| s.token.clone());
            if let Some(t) = old {
                self.remove_session(&t);
                self.active_client -= 1;
            }
        }
        self.sessions.insert(s.token.clone(), s);
    }

    /// `w_logtest_remove_session`
    pub fn remove_session(&mut self, token: &str) -> bool {
        self.sessions.remove(token).is_some()
    }

    /// `w_logtest_check_inactive_sessions` (one pass).
    pub fn expire_sessions(&mut self) {
        let t = now();
        let expired: Vec<String> = self
            .sessions
            .values()
            .filter(|s| t - s.last_connection >= self.conf.session_timeout)
            .map(|s| s.token.clone())
            .collect();
        for k in expired {
            self.remove_session(&k);
            self.active_client -= 1;
        }
    }

    /// `w_logtest_generate_error_response`
    pub fn error_response(msg: &str) -> Vec<u8> {
        let mut r = Json::object();
        r.add("message", Json::string(msg));
        r.add("error", Json::number(W_LOGTEST_CODE_MSG_TOO_LARGE as f64));
        r.print_unformatted()
    }

    /// `w_logtest_add_msg_response`
    fn add_msg_response(data: &mut Json, list: &mut LogList, code: &mut i32) {
        let msgs = list.take();
        if msgs.is_empty() {
            return;
        }
        let mut ret = *code;
        if data.get_exact("messages").is_none() {
            data.add("messages", Json::array());
        }
        let mut items = Vec::new();
        for m in msgs {
            let head = match m.level {
                LogLevel::Error => {
                    ret = W_LOGTEST_RCODE_ERROR_PROCESS;
                    "ERROR: "
                }
                LogLevel::Warning => {
                    if ret != W_LOGTEST_RCODE_ERROR_PROCESS {
                        ret = W_LOGTEST_RCODE_WARNING;
                    }
                    "WARNING: "
                }
                LogLevel::Info => "INFO: ",
            };
            items.push(Json::string(format!("{head}{}", m.msg)));
        }
        if let Json::Object(mm) = data {
            if let Some((_, Json::Array(a))) = mm.iter_mut().find(|(k, _)| k == b"messages") {
                a.extend(items);
            }
        }
        *code = ret;
    }

    /// `w_logtest_check_input`: returns (code, request, command, message).
    fn check_input(input: &[u8], list: &mut LogList) -> (i32, Option<Json>, Option<Vec<u8>>, Option<String>) {
        let root = match siem_cjson::parse_with_opts(input, false) {
            Ok((j, _)) => j,
            Err(pos) => {
                let start = pos.saturating_sub(W_LOGTEST_ERROR_JSON_PARSE_NSTR / 2);
                let slice = crate::event::cstr(input, start);
                let slice = &slice[..slice.len().min(W_LOGTEST_ERROR_JSON_PARSE_NSTR)];
                let msg = format!(
                    "(7307): Error parsing JSON in position {}, ... {} ...",
                    pos as i32,
                    String::from_utf8_lossy(slice)
                );
                return (W_LOGTEST_CODE_ERROR_PARSING, None, None, Some(msg));
            }
        };
        let Some(params) = err_obj_get(&root, "parameters") else {
            return (W_LOGTEST_CODE_INVALID_JSON, Some(root), None, Some("(7313): 'parameters' JSON field not found".into()));
        };
        if !params.is_object() {
            return (W_LOGTEST_CODE_INVALID_JSON, Some(root), None, Some("(7317): 'parameters' JSON field value is not valid".into()));
        }
        let Some(command) = err_obj_get(&root, "command") else {
            return (W_LOGTEST_CODE_INVALID_JSON, Some(root), None, Some("(7313): 'command' JSON field not found".into()));
        };
        let Some(cmd) = string_value(Some(command)).map(|c| c.to_vec()) else {
            return (W_LOGTEST_CODE_INVALID_JSON, Some(root), None, Some("(7317): 'command' JSON field value is not valid".into()));
        };
        let mut root = root;
        let (code, msg) = if cmd == b"remove_session" {
            Self::check_input_remove_session(err_obj_get(&root, "parameters").unwrap())
        } else if cmd == b"log_processing" {
            let params = match &mut root {
                Json::Object(m) => &mut m.iter_mut().find(|(k, _)| k == b"parameters").unwrap().1,
                _ => unreachable!(),
            };
            Self::check_input_request(params, list)
        } else {
            (W_LOGTEST_CODE_COMMAND_NOT_ALLOWED, Some("(7306): Unable to process command".to_string()))
        };
        (code, Some(root), Some(cmd), msg)
    }

    /// `w_logtest_check_input_remove_session`
    fn check_input_remove_session(params: &Json) -> (i32, Option<String>) {
        match params.get_exact("token") {
            Some(Json::String(t)) => {
                let t = siem_cjson_cstr(t);
                if t.len() != W_LOGTEST_TOKEN_LENGH {
                    return (
                        W_LOGTEST_CODE_INVALID_TOKEN,
                        Some(format!("(7309): '{}' is not a valid token", String::from_utf8_lossy(t))),
                    );
                }
                (W_LOGTEST_CODE_SUCCESS, None)
            }
            _ => (
                W_LOGTEST_CODE_INVALID_TOKEN,
                Some("(7316): Failure to remove session. token JSON field must be a string".into()),
            ),
        }
    }

    /// `w_logtest_check_input_request`
    fn check_input_request(params: &mut Json, list: &mut LogList) -> (i32, Option<String>) {
        if !is_nonempty_string(params.get_exact("location")) {
            return (W_LOGTEST_CODE_INVALID_JSON, Some("(7308): 'location' JSON field is required and must be a string".into()));
        }
        if !is_nonempty_string(params.get_exact("log_format")) {
            return (W_LOGTEST_CODE_INVALID_JSON, Some("(7308): 'log_format' JSON field is required and must be a string".into()));
        }
        let Some(event) = params.get_exact("event") else {
            return (W_LOGTEST_CODE_INVALID_JSON, Some("(7313): 'event' JSON field not found".into()));
        };
        let ok_event = is_nonempty_string(Some(event)) || matches!(event, Json::Object(m) if !m.is_empty());
        if !ok_event {
            return (W_LOGTEST_CODE_INVALID_JSON, Some("(7317): 'event' JSON field value is not valid".into()));
        }
        if let Some(token) = params.get_exact("token") {
            let valid = matches!(token, Json::String(t) if siem_cjson_cstr(t).len() == W_LOGTEST_TOKEN_LENGH);
            if !valid {
                let s = match token {
                    Json::String(t) => String::from_utf8_lossy(siem_cjson_cstr(t)).into_owned(),
                    other => other.to_string_unformatted(),
                };
                list.warn(format!("(7309): '{s}' is not a valid token"));
                if let Json::Object(m) = params {
                    if let Some(p) = m.iter().position(|(k, _)| k == b"token") {
                        m.remove(p);
                    }
                }
            }
        }
        if let Some(opt) = params.get_exact("options") {
            if !opt.is_object() {
                if let Json::Object(m) = params {
                    if let Some(p) = m.iter().position(|(k, _)| k == b"options") {
                        m.remove(p);
                    }
                }
                list.warn("(7005): 'options' field must be a JSON object. The parameter will be ignored");
            }
        }
        (W_LOGTEST_CODE_SUCCESS, None)
    }

    /// `w_logtest_process_request`
    pub fn process_request(&mut self, raw: &[u8]) -> Vec<u8> {
        let mut list = LogList::bounded();
        let mut response = Json::object();
        let mut data = Json::object();
        let (retval, req, cmd, msg) = Self::check_input(raw, &mut list);
        if retval == W_LOGTEST_CODE_SUCCESS {
            let req = req.unwrap();
            let params = req.get_exact("parameters").cloned().unwrap_or(Json::object());
            let codemsg = if cmd.as_deref() == Some(&b"remove_session"[..]) {
                self.request_remove_session(&params, &mut data, &mut list)
            } else {
                self.request_log_processing(&params, &mut data, &mut list)
            };
            data.add("codemsg", Json::number(codemsg as f64));
        }
        if let Some(m) = msg {
            response.add("message", Json::string(m));
        }
        response.add("error", Json::number(retval as f64));
        response.add("data", data);
        response.print_unformatted()
    }

    /// `w_logtest_process_request_log_processing`
    fn request_log_processing(&mut self, params: &Json, data: &mut Json, list: &mut LogList) -> i32 {
        let mut retval = W_LOGTEST_RCODE_SUCCESS;
        let token = string_value(params.get_exact("token")).map(|t| String::from_utf8_lossy(t).into_owned());
        let mut session_token: Option<String> = None;
        if let Some(t) = &token {
            if let Some(s) = self.sessions.get_mut(t) {
                s.last_connection = now();
                session_token = Some(t.clone());
            } else {
                list.warn(format!("(7003): '{t}' token expires"));
            }
        }
        if session_token.is_none() {
            match self.initialize_session(list) {
                Some(s) => {
                    let t = s.token.clone();
                    self.register_session(s);
                    list.info(format!("(7202): Session initialized with token '{t}'"));
                    session_token = Some(t);
                }
                None => list.error("(7311): Failure to initializing session"),
            }
        }
        Self::add_msg_response(data, list, &mut retval);
        let Some(token) = session_token else {
            return retval;
        };
        if retval < W_LOGTEST_RCODE_SUCCESS {
            return retval;
        }
        data.add("token", Json::string(&token));

        let mut debug: Option<Vec<String>> = None;
        if let Some(opt) = params.get_exact("options") {
            if let Some(v) = opt.get_exact("rules_debug") {
                match v {
                    Json::True => debug = Some(Vec::new()),
                    Json::False => {}
                    _ => list.warn("(7006): 'rules_debug' field must be a boolean. The parameter will be ignored"),
                }
            }
        }

        // w_logtest_preprocessing_phase: an object event is printed unformatted.
        let event = params.get_exact("event").unwrap();
        let ev_bytes: Vec<u8> = match event {
            Json::Object(m) if !m.is_empty() => event.print_unformatted(),
            Json::String(s) => siem_cjson_cstr(s).to_vec(),
            _ => Vec::new(),
        };
        let location = string_value(params.get_exact("location")).unwrap_or(b"").to_vec();

        let session = self.sessions.get_mut(&token).unwrap();
        let logbylevel = session.logbylevel;
        let out = session.engine.logtest_process(&ev_bytes, &location, logbylevel, debug.as_mut(), list);
        let mut alert = false;
        match out {
            Some((j, a)) => {
                alert = a;
                data.add("output", j);
            }
            None => list.error("(7312): Failed to process the event"),
        }
        if let Some(d) = debug {
            data.add("rules_debug", Json::Array(d.into_iter().map(Json::string).collect()));
        }
        Self::add_msg_response(data, list, &mut retval);
        if retval >= W_LOGTEST_RCODE_SUCCESS {
            data.add("alert", Json::bool(alert));
        }
        retval
    }

    /// `w_logtest_process_request_remove_session`
    fn request_remove_session(&mut self, params: &Json, data: &mut Json, list: &mut LogList) -> i32 {
        let mut retval = W_LOGTEST_RCODE_SUCCESS;
        match string_value(params.get_exact("token")) {
            Some(t) => {
                let t = String::from_utf8_lossy(t).into_owned();
                if self.remove_session(&t) {
                    self.active_client -= 1;
                    list.info(format!("(7206): The session '{t}' was closed successfully"));
                } else {
                    list.error(format!("(7004): No session found for token '{t}'"));
                }
            }
            None => list.error("(7316): Failure to remove session. token JSON field must be a string"),
        }
        Self::add_msg_response(data, list, &mut retval);
        retval
    }
}
