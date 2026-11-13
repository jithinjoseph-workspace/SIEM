//! Logtest (spec section 2.17): sessions with their own ruleset and state, and the JSON
//! request/answer protocol of `queue/sockets/logtest`.

use std::collections::HashMap;
use std::path::PathBuf;

use provigil_json::Json;

use crate::config::{ruleset_from_file, Ruleset};
use crate::engine::{Engine, EngineSettings};
use crate::messages::{Level, Messages};

const TOKEN_LENGTH: usize = 8;

pub const ERROR_INPUT: i32 = -2;
pub const ERROR_PROCESS: i32 = -1;
pub const SUCCESS: i32 = 0;
pub const WARNING: i32 = 1;

pub const CODE_SUCCESS: i32 = 0;
pub const CODE_PARSING: i32 = 1;
pub const CODE_INVALID_JSON: i32 = 2;
pub const CODE_COMMAND: i32 = 3;
pub const CODE_TOKEN: i32 = 4;
pub const CODE_TOO_LARGE: i32 = 5;

pub const TOO_LARGE: &str = "(7315): Failure to receive message: size is bigger than expected";

pub struct Session {
    pub token: String,
    pub engine: Engine,
    pub log_level: i32,
    pub last_use: i64,
}

fn now() -> i64 {
    crate::event::Instant::now().sec
}

impl Session {
    pub fn new(token: String, engine: Engine, log_level: i32) -> Session {
        Session { token, engine, log_level, last_use: now() }
    }

    /// A session loading `ruleset` from scratch.
    pub fn load(token: String, settings: EngineSettings, ruleset: &Ruleset, msgs: &mut Messages) -> Option<Session> {
        let mut engine = Engine::new(settings);
        if !engine.load_ruleset(&ruleset.decoders, &ruleset.lists, &ruleset.rules, None, msgs) {
            return None;
        }
        Some(Session::new(token, engine, ruleset.log_level.map_or(0, i32::from)))
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub enabled: bool,
    pub threads: u16,
    pub max_sessions: u16,
    pub session_timeout: i64,
    /// `etc/ossec.conf`, read again for each new session.
    pub config_file: PathBuf,
    pub engine: EngineSettings,
}

pub struct Logtest {
    pub settings: Settings,
    pub sessions: HashMap<String, Session>,
    pub clients: i32,
    /// The service's rule ids, added to each new session.
    pub rules_by_id: HashMap<String, crate::event::RuleId>,
    /// Where tokens come from (tests set a fixed one).
    pub token_source: Box<dyn FnMut() -> u32 + Send>,
}

/// A random 32-bit value from the system's hashing seed (new for each call).
fn random() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    h.finish() as u32
}

fn text(j: Option<&Json>) -> Option<&[u8]> {
    match j {
        Some(Json::String(s)) => Some(crate::event::text_at(s, 0)),
        _ => None,
    }
}

fn nonempty_text(j: Option<&Json>) -> bool {
    matches!(j, Some(Json::String(s)) if s.first().is_some_and(|&c| c != 0))
}

/// Removes the member named exactly `key`.
fn drop_member(o: &mut Json, key: &[u8]) {
    if let Json::Object(m) = o {
        if let Some(p) = m.iter().position(|(k, _)| k == key) {
            m.remove(p);
        }
    }
}

impl Logtest {
    pub fn new(settings: Settings) -> Logtest {
        Logtest { settings, sessions: HashMap::new(), clients: 0, rules_by_id: HashMap::new(), token_source: Box::new(random) }
    }

    fn token(&mut self) -> String {
        loop {
            let t = format!("{:08x}", (self.token_source)());
            if !self.sessions.contains_key(&t) {
                return t;
            }
        }
    }

    pub fn new_session(&mut self, msgs: &mut Messages) -> Option<Session> {
        let token = self.token();
        let home = self.settings.engine.rules.home.clone();
        let conf = crate::config::resolve(&home, &self.settings.config_file.to_string_lossy());
        let ruleset = ruleset_from_file(&conf, &conf.display().to_string(), &home, true, msgs)?;
        let mut s = Session::load(token, self.settings.engine.clone(), &ruleset, msgs)?;
        for (k, v) in &self.rules_by_id {
            s.engine.rules_by_id.entry(k.clone()).or_insert(*v);
        }
        Some(s)
    }

    /// Adds a session; past `max_sessions` the least recently used one goes.
    fn add(&mut self, s: Session) {
        self.clients += 1;
        if self.clients > i32::from(self.settings.max_sessions) {
            let oldest = self.sessions.values().min_by(|a, b| a.last_use.cmp(&b.last_use).then(a.token.cmp(&b.token))).map(|s| s.token.clone());
            if let Some(t) = oldest {
                self.sessions.remove(&t);
                self.clients -= 1;
            }
        }
        self.sessions.insert(s.token.clone(), s);
    }

    pub fn remove(&mut self, token: &str) -> bool {
        self.sessions.remove(token).is_some()
    }

    /// Removes the sessions idle for the session timeout.
    pub fn expire(&mut self) {
        let t = now();
        let old: Vec<String> = self.sessions.values().filter(|s| t - s.last_use >= self.settings.session_timeout).map(|s| s.token.clone()).collect();
        for k in old {
            self.sessions.remove(&k);
            self.clients -= 1;
        }
    }

    /// The answer to an oversized request.
    pub fn error_answer(msg: &str) -> Vec<u8> {
        let mut r = Json::object();
        r.add("message", Json::string(msg));
        r.add("error", Json::number(f64::from(CODE_TOO_LARGE)));
        r.print_unformatted()
    }

    /// The collected messages into `data.messages` ("ERROR: ...", "WARNING: ...",
    /// "INFO: ..."); errors and warnings set the code.
    fn take_messages(data: &mut Json, msgs: &mut Messages, code: &mut i32) {
        let list = msgs.take();
        if list.is_empty() {
            return;
        }
        if data.get_exact("messages").is_none() {
            data.add("messages", Json::array());
        }
        let mut c = *code;
        let mut items = Vec::new();
        for m in list {
            let head = match m.level {
                Level::Error => {
                    c = ERROR_PROCESS;
                    "ERROR: "
                }
                Level::Warning => {
                    if c != ERROR_PROCESS {
                        c = WARNING;
                    }
                    "WARNING: "
                }
                Level::Info => "INFO: ",
            };
            items.push(Json::string(format!("{head}{}", m.text)));
        }
        if let Json::Object(mm) = data {
            if let Some((_, Json::Array(a))) = mm.iter_mut().find(|(k, _)| k == b"messages") {
                a.extend(items);
            }
        }
        *code = c;
    }

    /// The request checks: (code, request, command, message).
    fn check(input: &[u8], msgs: &mut Messages) -> (i32, Option<Json>, Option<Vec<u8>>, Option<String>) {
        let mut root = match provigil_json::parse_with_opts(input, false) {
            Ok((j, _)) => j,
            Err(pos) => {
                let around = crate::event::text_at(input, pos.saturating_sub(10));
                let around = &around[..around.len().min(20)];
                return (CODE_PARSING, None, None, Some(format!("(7307): Error parsing JSON in position {}, ... {} ...", pos as i32, String::from_utf8_lossy(around))));
            }
        };
        let Some(params) = root.get_exact("parameters") else {
            return (CODE_INVALID_JSON, Some(root), None, Some("(7313): 'parameters' JSON field not found".into()));
        };
        if !matches!(params, Json::Object(_)) {
            return (CODE_INVALID_JSON, Some(root), None, Some("(7317): 'parameters' JSON field value is not valid".into()));
        }
        let Some(command) = root.get_exact("command") else {
            return (CODE_INVALID_JSON, Some(root), None, Some("(7313): 'command' JSON field not found".into()));
        };
        let Some(cmd) = text(Some(command)).map(<[u8]>::to_vec) else {
            return (CODE_INVALID_JSON, Some(root), None, Some("(7317): 'command' JSON field value is not valid".into()));
        };
        let (code, msg) = match cmd.as_slice() {
            b"remove_session" => Self::check_remove(root.get_exact("parameters").expect("checked")),
            b"log_processing" => {
                let Json::Object(m) = &mut root else { unreachable!("an object") };
                let params = &mut m.iter_mut().find(|(k, _)| k == b"parameters").expect("checked").1;
                Self::check_event(params, msgs)
            }
            _ => (CODE_COMMAND, Some("(7306): Unable to process command".to_string())),
        };
        (code, Some(root), Some(cmd), msg)
    }

    fn check_remove(params: &Json) -> (i32, Option<String>) {
        match params.get_exact("token") {
            Some(Json::String(t)) => {
                let t = crate::event::text_at(t, 0);
                if t.len() != TOKEN_LENGTH {
                    return (CODE_TOKEN, Some(format!("(7309): '{}' is not a valid token", String::from_utf8_lossy(t))));
                }
                (CODE_SUCCESS, None)
            }
            _ => (CODE_TOKEN, Some("(7316): Failure to remove session. token JSON field must be a string".into())),
        }
    }

    fn check_event(params: &mut Json, msgs: &mut Messages) -> (i32, Option<String>) {
        if !nonempty_text(params.get_exact("location")) {
            return (CODE_INVALID_JSON, Some("(7308): 'location' JSON field is required and must be a string".into()));
        }
        if !nonempty_text(params.get_exact("log_format")) {
            return (CODE_INVALID_JSON, Some("(7308): 'log_format' JSON field is required and must be a string".into()));
        }
        let Some(event) = params.get_exact("event") else {
            return (CODE_INVALID_JSON, Some("(7313): 'event' JSON field not found".into()));
        };
        if !(nonempty_text(Some(event)) || matches!(event, Json::Object(m) if !m.is_empty())) {
            return (CODE_INVALID_JSON, Some("(7317): 'event' JSON field value is not valid".into()));
        }
        if let Some(token) = params.get_exact("token") {
            let valid = matches!(token, Json::String(t) if crate::event::text_at(t, 0).len() == TOKEN_LENGTH);
            if !valid {
                let shown = match token {
                    Json::String(t) => String::from_utf8_lossy(crate::event::text_at(t, 0)).into_owned(),
                    other => String::from_utf8_lossy(&other.print_unformatted()).into_owned(),
                };
                msgs.warn(format!("(7309): '{shown}' is not a valid token"));
                drop_member(params, b"token");
            }
        }
        if params.get_exact("options").is_some_and(|o| !matches!(o, Json::Object(_))) {
            drop_member(params, b"options");
            msgs.warn("(7005): 'options' field must be a JSON object. The parameter will be ignored");
        }
        (CODE_SUCCESS, None)
    }

    /// One request; the answer.
    pub fn request(&mut self, raw: &[u8]) -> Vec<u8> {
        let mut msgs = Messages::bounded();
        let mut answer = Json::object();
        let mut data = Json::object();
        let (code, req, cmd, msg) = Self::check(raw, &mut msgs);
        if code == CODE_SUCCESS {
            let params = req.and_then(|r| r.get_exact("parameters").cloned()).unwrap_or_else(Json::object);
            let c = if cmd.as_deref() == Some(b"remove_session") { self.remove_request(&params, &mut data, &mut msgs) } else { self.event_request(&params, &mut data, &mut msgs) };
            data.add("codemsg", Json::number(f64::from(c)));
        }
        if let Some(m) = msg {
            answer.add("message", Json::string(m));
        }
        answer.add("error", Json::number(f64::from(code)));
        answer.add("data", data);
        answer.print_unformatted()
    }

    fn event_request(&mut self, params: &Json, data: &mut Json, msgs: &mut Messages) -> i32 {
        let mut code = SUCCESS;
        let mut token = None;
        if let Some(t) = text(params.get_exact("token")).map(|t| String::from_utf8_lossy(t).into_owned()) {
            match self.sessions.get_mut(&t) {
                Some(s) => {
                    s.last_use = now();
                    token = Some(t);
                }
                None => msgs.warn(format!("(7003): '{t}' token expires")),
            }
        }
        if token.is_none() {
            match self.new_session(msgs) {
                Some(s) => {
                    let t = s.token.clone();
                    self.add(s);
                    msgs.info(format!("(7202): Session initialized with token '{t}'"));
                    token = Some(t);
                }
                None => msgs.error("(7311): Failure to initializing session"),
            }
        }
        Self::take_messages(data, msgs, &mut code);
        let Some(token) = token else { return code };
        if code < SUCCESS {
            return code;
        }
        data.add("token", Json::string(&token));
        let mut debug = None;
        if let Some(v) = params.get_exact("options").and_then(|o| o.get_exact("rules_debug")) {
            match v {
                Json::True => debug = Some(Vec::new()),
                Json::False => {}
                _ => msgs.warn("(7006): 'rules_debug' field must be a boolean. The parameter will be ignored"),
            }
        }
        let event = match params.get_exact("event") {
            Some(e @ Json::Object(m)) if !m.is_empty() => e.print_unformatted(),
            Some(Json::String(s)) => crate::event::text_at(s, 0).to_vec(),
            _ => Vec::new(),
        };
        let location = text(params.get_exact("location")).unwrap_or(b"").to_vec();
        let session = self.sessions.get_mut(&token).expect("registered above");
        let level = session.log_level;
        let mut alert = false;
        match session.engine.logtest(&event, &location, level, debug.as_mut(), msgs) {
            Some((out, a)) => {
                alert = a;
                data.add("output", out);
            }
            None => msgs.error("(7312): Failed to process the event"),
        }
        if let Some(d) = debug {
            data.add("rules_debug", Json::Array(d.into_iter().map(Json::string).collect()));
        }
        Self::take_messages(data, msgs, &mut code);
        if code >= SUCCESS {
            data.add("alert", Json::bool(alert));
        }
        code
    }

    fn remove_request(&mut self, params: &Json, data: &mut Json, msgs: &mut Messages) -> i32 {
        let mut code = SUCCESS;
        match text(params.get_exact("token")).map(|t| String::from_utf8_lossy(t).into_owned()) {
            Some(t) => {
                if self.remove(&t) {
                    self.clients -= 1;
                    msgs.info(format!("(7206): The session '{t}' was closed successfully"));
                } else {
                    msgs.error(format!("(7004): No session found for token '{t}'"));
                }
            }
            None => msgs.error("(7316): Failure to remove session. token JSON field must be a string"),
        }
        Self::take_messages(data, msgs, &mut code);
        code
    }
}
