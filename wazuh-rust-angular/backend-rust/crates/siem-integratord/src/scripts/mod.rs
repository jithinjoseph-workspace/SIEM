//! The integration scripts (`integrations/*.py`) as Rust, run by
//! integratord as `integrations/<name>`. What they share: arguments,
//! `logs/integrations.log`, the alert/options files, HTTP (`requests`),
//! the analysisd queue, and how a Python exception ends the process.

pub mod maltiverse;
pub mod pagerduty;
pub mod shuffle;
pub mod slack;
pub mod virustotal;

use std::io::Write;
use std::path::PathBuf;

use crate::pyjson::{self, repr, Py};

/// A Python exception (or `sys.exit`).
#[derive(Debug)]
pub enum PyErr {
    Exit(i32),
    Key(String),
    Type(String),
    Value(String),
    /// `raise Exception(msg)`
    Exc(String),
    /// `requests.exceptions.<class>`
    Requests(&'static str, String),
}

impl PyErr {
    /// `str(e)`
    pub fn text(&self) -> String {
        match self {
            PyErr::Key(k) => pyjson::str_repr(k),
            PyErr::Type(m) | PyErr::Value(m) | PyErr::Exc(m) | PyErr::Requests(_, m) => m.clone(),
            PyErr::Exit(c) => c.to_string(),
        }
    }

    /// The last line of the traceback Python prints.
    pub fn last_line(&self) -> String {
        let (class, m) = match self {
            PyErr::Key(_) => ("KeyError".to_string(), self.text()),
            PyErr::Type(m) => ("TypeError".into(), m.clone()),
            PyErr::Value(m) => ("ValueError".into(), m.clone()),
            PyErr::Exc(m) => ("Exception".into(), m.clone()),
            PyErr::Requests(c, m) => (format!("requests.exceptions.{c}"), m.clone()),
            PyErr::Exit(_) => return String::new(),
        };
        if m.is_empty() {
            class
        } else {
            format!("{class}: {m}")
        }
    }
}

pub type R<T> = Result<T, PyErr>;

fn type_name(v: &Py) -> &'static str {
    match v {
        Py::None => "NoneType",
        Py::Bool(_) => "bool",
        Py::Int(_) => "int",
        Py::Float(_) => "float",
        Py::Str(_) => "str",
        Py::List(_) => "list",
        Py::Dict(_) => "dict",
    }
}

/// `v[k]`
pub fn idx<'a>(v: &'a Py, k: &str) -> R<&'a Py> {
    match v {
        Py::Dict(_) => v.get(k).ok_or_else(|| PyErr::Key(k.to_string())),
        Py::Str(_) => Err(PyErr::Type("string indices must be integers".into())),
        Py::List(_) => Err(PyErr::Type("list indices must be integers or slices, not str".into())),
        x => Err(PyErr::Type(format!("'{}' object is not subscriptable", type_name(x)))),
    }
}

/// `k in v`
pub fn contains(v: &Py, k: &str) -> R<bool> {
    match v {
        Py::Dict(_) => Ok(v.get(k).is_some()),
        Py::Str(s) => Ok(s.contains(k)),
        Py::List(l) => Ok(l.iter().any(|x| x.as_str() == Some(k))),
        x => Err(PyErr::Type(format!("argument of type '{}' is not iterable", type_name(x)))),
    }
}

/// `v.get(k)` on a dict
pub fn get<'a>(v: &'a Py, k: &str) -> R<Option<&'a Py>> {
    match v {
        Py::Dict(_) => Ok(v.get(k)),
        x => Err(PyErr::Type(format!("'{}' object has no attribute 'get'", type_name(x)))),
    }
}

/// A number for `<`, `<=`, ... comparisons with an int.
pub fn number(v: &Py, op: &str) -> R<f64> {
    v.num().ok_or_else(|| PyErr::Type(format!("'{op}' not supported between instances of '{}' and 'int'", type_name(v))))
}

/// `str.format` / f-string of a value.
pub fn fmt(v: &Py) -> String {
    pyjson::to_str(v)
}

/// `', '.join(list)`
pub fn join(v: &Py, sep: &str) -> R<String> {
    let items: Vec<Py> = match v {
        Py::List(l) => l.clone(),
        Py::Dict(d) => d.iter().map(|(k, _)| Py::Str(k.clone())).collect(),
        Py::Str(s) => s.chars().map(|c| Py::Str(c.to_string())).collect(),
        x => return Err(PyErr::Type(format!("can only join an iterable, not '{}'", type_name(x)))),
    };
    let mut out = Vec::new();
    for (i, x) in items.iter().enumerate() {
        match x {
            Py::Str(s) => out.push(s.clone()),
            o => return Err(PyErr::Type(format!("sequence item {i}: expected str instance, {} found", type_name(o)))),
        }
    }
    Ok(out.join(sep))
}

/// The script's environment.
pub struct Ctx {
    pub args: Vec<String>,
    pub debug_enabled: bool,
    /// `pwd`: the Wazuh home (two levels above the script).
    pub home: PathBuf,
}

impl Ctx {
    pub fn new(args: Vec<String>) -> Ctx {
        let exe = std::env::current_exe().ok().and_then(|p| p.canonicalize().ok()).unwrap_or_default();
        let home = exe.parent().and_then(|p| p.parent()).map(PathBuf::from).unwrap_or_default();
        Ctx { args, debug_enabled: false, home }
    }

    pub fn log_file(&self) -> PathBuf {
        self.home.join("logs").join("integrations.log")
    }

    /// `open(LOG_FILE, 'a').write(text)`
    pub fn append_log(&self, text: &str) -> R<()> {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(self.log_file()).map_err(|e| PyErr::Exc(e.to_string()))?;
        let _ = f.write_all(text.as_bytes());
        Ok(())
    }

    /// `debug(msg)`: stdout and the log, when debug is on.
    pub fn debug(&self, msg: &str) {
        if self.debug_enabled {
            println!("{msg}");
            let _ = std::io::stdout().flush();
            let _ = self.append_log(&format!("{msg}\n"));
        }
    }

    pub fn arg(&self, i: usize) -> &str {
        self.args.get(i).map(String::as_str).unwrap_or("")
    }

    /// The options file: the first argument from index 4 ending in "options".
    pub fn options_location(&self) -> String {
        self.args.iter().skip(4).find(|a| a.chars().rev().take(7).collect::<String>() == "snoitpo" && a.chars().count() >= 7).cloned().unwrap_or_default()
    }

    /// `get_json_alert` (missing file 6, bad JSON 7; maltiverse uses 3 and 4).
    pub fn json_alert(&self, path: &str, codes: (i32, i32), not_found: &str, bad: &str) -> R<Py> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                self.debug(&not_found.replace("{}", path));
                return Err(PyErr::Exit(codes.0));
            }
        };
        match pyjson::loads(&data) {
            Ok(v) => Ok(v),
            Err(e) => {
                self.debug(&bad.replace("{}", &python_decode_error(&data, &e)));
                Err(PyErr::Exit(codes.1))
            }
        }
    }

    /// `get_json_options`: `None` when the file is missing, exit 7 when unreadable.
    pub fn json_options(&self, path: &str) -> R<Py> {
        match std::fs::read(path) {
            Err(_) => {
                self.debug(&format!("# JSON file for options {path} doesn't exist"));
                Ok(Py::None)
            }
            Ok(d) => match pyjson::loads(&d) {
                Ok(v) => Ok(v),
                Err(e) => {
                    self.debug(&format!("Failed getting JSON options. Error: {}", python_decode_error(&d, &e)));
                    Err(PyErr::Exit(7))
                }
            },
        }
    }
}

/// `JSONDecodeError.__str__`: "<msg>: line L column C (char P)".
pub fn python_decode_error(doc: &[u8], e: &pyjson::ParseError) -> String {
    let (msg, pos) = e.0.rsplit_once(": char ").map(|(m, p)| (m.to_string(), p.parse::<usize>().unwrap_or(0))).unwrap_or((e.0.clone(), 0));
    let text = String::from_utf8_lossy(&doc[..pos.min(doc.len())]);
    let chars = text.chars().count();
    let line = text.matches('\n').count() + 1;
    let col = match text.rfind('\n') {
        Some(i) => text[i + 1..].chars().count() + 1,
        None => chars + 1,
    };
    format!("{msg}: line {line} column {col} (char {chars})")
}

/// `requests` with the `str(response.json)` the scripts log.
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    /// `'%s' % res.json`
    pub fn json_method_repr(&self) -> String {
        format!("<bound method Response.json of <Response [{}]>>", self.status)
    }

    /// `res.json()`
    pub fn json(&self) -> R<Py> {
        pyjson::loads(&self.body).map_err(|e| PyErr::Requests("JSONDecodeError", python_decode_error(&self.body, &e)))
    }
}

/// Test hook: `SIEM_INTEGRATIONS_URL_OVERRIDE=<from>=<to>` sends requests for
/// a fixed vendor URL (PagerDuty, VirusTotal) to a local test server.
pub fn effective_url(url: &str) -> String {
    if let Ok(o) = std::env::var("SIEM_INTEGRATIONS_URL_OVERRIDE") {
        if let Some((from, to)) = o.split_once('=') {
            if let Some(rest) = url.strip_prefix(from) {
                return format!("{to}{rest}");
            }
        }
    }
    url.to_string()
}

fn requests_error(url: &str, e: reqwest::Error) -> PyErr {
    if e.is_timeout() {
        PyErr::Requests("ReadTimeout", format!("HTTPConnectionPool: Read timed out. ({url})"))
    } else if e.is_connect() {
        PyErr::Requests("ConnectionError", format!("HTTPConnectionPool: Max retries exceeded with url: {url}"))
    } else {
        PyErr::Requests("RequestException", e.to_string())
    }
}

fn check_url(url: &str) -> R<reqwest::Url> {
    match reqwest::Url::parse(url) {
        Ok(u) if u.scheme() == "http" || u.scheme() == "https" => Ok(u),
        Ok(u) => Err(PyErr::Requests("InvalidSchema", format!("No connection adapters were found for {}", pyjson::str_repr(&u.to_string())))),
        Err(_) if !url.contains("://") => Err(PyErr::Requests("MissingSchema", format!("Invalid URL {}: No scheme supplied. Perhaps you meant https://{url}?", pyjson::str_repr(url)))),
        Err(_) => Err(PyErr::Requests("InvalidURL", format!("Invalid URL {}", pyjson::str_repr(url)))),
    }
}

/// requests' default `Accept-Encoding`, then the script's own headers (replacing).
fn header_map(headers: &[(&str, &str)]) -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderName, HeaderValue};
    let mut m = reqwest::header::HeaderMap::new();
    m.insert(reqwest::header::ACCEPT_ENCODING, HeaderValue::from_static("gzip, deflate"));
    for (k, v) in headers {
        if let (Ok(k), Ok(v)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
            m.insert(k, v);
        }
    }
    m
}

/// `requests.post(url, data=msg, headers=..., timeout=10)`
pub fn post(url: &str, body: String, headers: &[(&str, &str)], timeout: u64) -> R<Response> {
    let url = effective_url(url);
    let u = check_url(&url)?;
    let c = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(timeout)).build().map_err(|e| PyErr::Exc(e.to_string()))?;
    let r = c.post(u).body(body).headers(header_map(headers)).send().map_err(|e| requests_error(&url, e))?;
    let status = r.status().as_u16();
    Ok(Response { status, body: r.bytes().map(|b| b.to_vec()).unwrap_or_default() })
}

/// `requests.get(url, params=..., headers=..., timeout=...)`
pub fn get_url(url: &str, params: &[(&str, &str)], headers: &[(&str, &str)], timeout: Option<u64>) -> R<Response> {
    let url = effective_url(url);
    let mut u = check_url(&url)?;
    if !params.is_empty() {
        // requests: urlencode(params) with quote_plus
        let q: Vec<String> = params.iter().map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v))).collect();
        u.set_query(Some(&q.join("&")));
    }
    let mut b = reqwest::blocking::Client::builder();
    if let Some(t) = timeout {
        b = b.timeout(std::time::Duration::from_secs(t));
    }
    let c = b.build().map_err(|e| PyErr::Exc(e.to_string()))?;
    let r = c.get(u).headers(header_map(headers)).send().map_err(|e| requests_error(&url, e))?;
    let status = r.status().as_u16();
    Ok(Response { status, body: r.bytes().map(|b| b.to_vec()).unwrap_or_default() })
}

/// `urllib.parse.quote_plus`
pub fn quote_plus(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => o.push(b as char),
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// The analysisd queue (`{pwd}/queue/sockets/queue`): one datagram, no NUL.
/// Errors carry the errno (2 missing, 111 refused, 90 too long).
pub fn queue_send(ctx: &Ctx, msg: &[u8]) -> Result<(), i32> {
    let path = ctx.home.join("queue").join("sockets").join("queue");
    #[cfg(unix)]
    {
        let s = std::os::unix::net::UnixDatagram::unbound().map_err(|e| e.raw_os_error().unwrap_or(0))?;
        s.connect(&path).map_err(|e| e.raw_os_error().unwrap_or(0))?;
        s.send(msg).map_err(|e| e.raw_os_error().unwrap_or(0))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        // a manager on Windows: the queue's loopback port (see siem_ipc::local)
        let mut p = path.into_os_string();
        p.push(".port");
        let port: u16 = std::fs::read_to_string(p).ok().and_then(|s| s.trim().parse().ok()).ok_or(2)?;
        let s = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| e.raw_os_error().unwrap_or(0))?;
        s.send_to(msg, ("127.0.0.1", port)).map_err(|e| e.raw_os_error().unwrap_or(0))?;
        Ok(())
    }
}

/// The `location` part of a queue message for an agent.
pub fn agent_location(agent: &Py, tool: &str) -> R<Option<String>> {
    // `if not agent or agent['id'] == '000'`
    if !agent.truthy() || idx(agent, "id")?.as_str() == Some("000") {
        return Ok(None);
    }
    let ip = if contains(agent, "ip")? { fmt(idx(agent, "ip")?) } else { "any".into() };
    let loc = format!("[{}] ({}) {}", fmt(idx(agent, "id")?), fmt(idx(agent, "name")?), ip);
    Ok(Some(format!("{}->{tool}", loc.replace('|', "||").replace(':', "|:"))))
}

/// Runs a script: the process exit code (Python semantics).
pub fn run(name: &str, args: Vec<String>) -> i32 {
    let mut ctx = Ctx::new(args);
    let r = match name {
        "slack" => slack::main(&mut ctx),
        "pagerduty" => pagerduty::main(&mut ctx),
        "virustotal" => virustotal::main(&mut ctx),
        "shuffle" => shuffle::main(&mut ctx),
        "maltiverse" => maltiverse::main(&mut ctx),
        _ => {
            eprintln!("Unknown integration '{name}'");
            return 2;
        }
    };
    let _ = std::io::stdout().flush();
    match r {
        Ok(()) => 0,
        Err(PyErr::Exit(c)) => c,
        Err(e) => {
            // main()'s `except Exception as e: debug(str(e)); raise`
            ctx.debug(&e.text());
            eprintln!("Traceback (most recent call last):\n{}", e.last_line());
            1
        }
    }
}

/// `'%s' % args` of the argument list (the bad-arguments debug line).
pub fn args_repr(args: &[String]) -> String {
    repr(&Py::List(args.iter().map(|a| Py::Str(a.clone())).collect()))
}
