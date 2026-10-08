//! Daemon logging (shared/debug_op.c): `logs/ossec.log` (plain) and
//! `logs/ossec.json` (JSON) under the Wazuh home, the format chosen by
//! `<logging><log_format>` in `etc/ossec.conf`, plus stderr unless the
//! daemon went to the background.
//!
//! Plain line: `YYYY/MM/DD hh:mm:ss <tag>: <LEVEL>: <message>`; with debug
//! on, `<tag>[<pid>] <file>:<line> at <func>(): ` replaces `<tag>: `.
//! JSON: `{"timestamp","tag",["pid","file","line","routine"],"level","description"}`.
//! The C file/line/function become the Rust caller's location.

use std::fs::OpenOptions;
use std::io::Write;
use std::panic::Location;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Mutex;

use siem_cjson::Json;

/// `LOGFILE`
pub const LOGFILE: &str = "logs/ossec.log";
/// `LOGJSONFILE`
pub const LOGJSONFILE: &str = "logs/ossec.json";
const OS_MAXSTR: usize = 65536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl Level {
    fn plain(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warning => "WARNING",
            Level::Error => "ERROR",
            Level::Critical => "CRITICAL",
        }
    }
    fn json(self) -> &'static str {
        match self {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warning => "warning",
            Level::Error => "error",
            Level::Critical => "critical",
        }
    }
    /// From the names daemons pass around ("INFO", "ERROR", ...).
    pub fn from_name(s: &str) -> Level {
        match s {
            "DEBUG" | "DEBUG1" | "DEBUG2" => Level::Debug,
            "INFO" => Level::Info,
            "WARNING" => Level::Warning,
            "CRITICAL" => Level::Critical,
            _ => Level::Error,
        }
    }
}

/// One daemon's logger (`__local_name` + debug_op.c's static flags).
pub struct WLog {
    tag: String,
    home: PathBuf,
    dbg: AtomicI32,
    daemon: AtomicBool,
    plain: AtomicBool,
    json: AtomicBool,
    initialized: AtomicBool,
    pid: u32,
    lock: Mutex<()>,
}

/// `OS_StrBreak` (os_regex_strbreak.c; same as `siem_regex::str_break`,
/// kept here so the logger does not pull in the regex engines).
fn str_break(sep: u8, s: &str, size: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut prev: Option<u8> = None;
    for &c in s.as_bytes() {
        if out.len() < size - 1 && c == sep {
            if prev == Some(b'\\') {
                cur.pop();
                cur.push(c);
                prev = Some(c);
                continue;
            }
            out.push(String::from_utf8_lossy(&cur).into_owned());
            cur.clear();
            prev = Some(c);
            continue;
        }
        cur.push(c);
        prev = Some(c);
    }
    out.push(String::from_utf8_lossy(&cur).into_owned());
    out
}

/// `w_get_timestamp`
pub fn timestamp(now: chrono::DateTime<chrono::Local>) -> String {
    now.format("%Y/%m/%d %H:%M:%S").to_string()
}

impl WLog {
    pub fn new(tag: &str, home: &Path) -> WLog {
        WLog {
            tag: tag.to_string(),
            home: home.to_path_buf(),
            dbg: AtomicI32::new(0),
            daemon: AtomicBool::new(false),
            plain: AtomicBool::new(false),
            json: AtomicBool::new(false),
            initialized: AtomicBool::new(false),
            pid: std::process::id(),
            lock: Mutex::new(()),
        }
    }

    /// `nowDebug`
    pub fn now_debug(&self) {
        self.dbg.fetch_add(1, Ordering::SeqCst);
    }

    /// `isDebug`
    pub fn is_debug(&self) -> i32 {
        self.dbg.load(Ordering::SeqCst)
    }

    /// `nowDaemon`: stop printing to stderr.
    pub fn now_daemon(&self) {
        self.daemon.store(true, Ordering::SeqCst);
    }

    /// `w_logging_init` / `os_logging_config`. On a configuration error the
    /// C code logs it and exits; here the error message is returned (it has
    /// already been logged) and the caller exits.
    pub fn init(&self) -> Result<(), String> {
        self.initialized.store(true, Ordering::SeqCst);
        let conf = self.home.join("etc/ossec.conf");
        let mut xml = match siem_xml::OsXml::read_file(&conf, false) {
            Ok(x) => x,
            Err(e) => {
                self.set_format(true, false);
                let m = format!("(1226): Error reading XML file '{}': {} (line {}).", "etc/ossec.conf", e.message, e.line);
                self.log_at(Level::Error, m.as_bytes(), Location::caller());
                return Err(m);
            }
        };
        let format = xml.get_one_content_for_element(&["ossec_config", "logging", "log_format"]);
        match format.filter(|f| !f.is_empty()) {
            None => {
                self.set_format(true, false);
                self.debug1("(1228): Element 'log_format' without any option.");
            }
            Some(f) => {
                let (mut plain, mut json) = (false, false);
                for part in str_break(b',', &f, 2).into_iter() {
                    // w_strtrim: spaces only
                    let p = part.trim_matches(' ');
                    match p {
                        "plain" => plain = true,
                        "json" => json = true,
                        _ => {
                            self.set_format(true, false);
                            let m = format!("(1235): Invalid value for element '{}': {}.", "log_format", p);
                            self.log_at(Level::Error, m.as_bytes(), Location::caller());
                            return Err(m);
                        }
                    }
                }
                self.set_format(plain, json);
            }
        }
        Ok(())
    }

    fn set_format(&self, plain: bool, json: bool) {
        self.plain.store(plain, Ordering::SeqCst);
        self.json.store(json, Ordering::SeqCst);
    }

    /// `getLoggingConfig`
    pub fn config_json(&self) -> Json {
        let yn = |b: bool| Json::string(if b { "yes" } else { "no" });
        let mut l = Json::object();
        l.add("plain", yn(self.plain.load(Ordering::SeqCst)));
        l.add("json", yn(self.json.load(Ordering::SeqCst)));
        let mut root = Json::object();
        root.add("logging", l);
        root
    }

    #[track_caller]
    pub fn debug1(&self, msg: impl AsRef<[u8]>) {
        if self.is_debug() >= 1 {
            self.log_at(Level::Debug, msg.as_ref(), Location::caller());
        }
    }

    #[track_caller]
    pub fn debug2(&self, msg: impl AsRef<[u8]>) {
        if self.is_debug() >= 2 {
            self.log_at(Level::Debug, msg.as_ref(), Location::caller());
        }
    }

    #[track_caller]
    pub fn info(&self, msg: impl AsRef<[u8]>) {
        self.log_at(Level::Info, msg.as_ref(), Location::caller());
    }

    #[track_caller]
    pub fn warn(&self, msg: impl AsRef<[u8]>) {
        self.log_at(Level::Warning, msg.as_ref(), Location::caller());
    }

    #[track_caller]
    pub fn error(&self, msg: impl AsRef<[u8]>) {
        self.log_at(Level::Error, msg.as_ref(), Location::caller());
    }

    /// `merror_exit` without the exit (the caller decides).
    #[track_caller]
    pub fn critical(&self, msg: impl AsRef<[u8]>) {
        self.log_at(Level::Critical, msg.as_ref(), Location::caller());
    }

    /// `_mferror`: file only, never stderr.
    #[track_caller]
    pub fn ferror(&self, msg: impl AsRef<[u8]>) {
        self.write(Level::Error, msg.as_ref(), Location::caller(), false);
    }

    /// `_log_function`
    pub fn log_at(&self, level: Level, msg: &[u8], loc: &Location<'_>) {
        self.write(level, msg, loc, !self.daemon.load(Ordering::SeqCst));
    }

    /// The `_mt*` functions (`mterror(tag, ...)`, ...): `tag` replaces the
    /// daemon name. `level` is "ERROR", "WARNING", "INFO", "DEBUG" (shown
    /// with debug >= 1), "DEBUG2" (debug >= 2) or "CRITICAL".
    #[track_caller]
    pub fn tagged(&self, tag: &str, level: &str, msg: impl AsRef<[u8]>) {
        let lv = match level {
            "DEBUG" if self.is_debug() >= 1 => Level::Debug,
            "DEBUG2" if self.is_debug() >= 2 => Level::Debug,
            "DEBUG" | "DEBUG2" => return,
            other => Level::from_name(other),
        };
        let stderr = !self.daemon.load(Ordering::SeqCst);
        self.write_tag(tag, lv, msg.as_ref(), Location::caller(), stderr);
    }

    fn write(&self, level: Level, msg: &[u8], loc: &Location<'_>, stderr: bool) {
        let tag = self.tag.clone();
        self.write_tag(&tag, level, msg, loc, stderr)
    }

    fn write_tag(&self, tag: &str, level: Level, msg: &[u8], loc: &Location<'_>, stderr: bool) {
        if !self.initialized.load(Ordering::SeqCst) {
            // auto-initialisation (errors already logged; the C code exits)
            if self.init().is_err() {
                std::process::exit(1);
            }
            self.debug1("Logging module auto-initialized");
        }
        let ts = timestamp(chrono::Local::now());
        let file = loc.file().rsplit(['/', '\\']).next().unwrap_or("");
        let dbg = self.is_debug() > 0;
        let prefix = if dbg {
            format!("{}[{}] {}:{} at {}(): ", tag, self.pid, file, loc.line(), "main")
        } else {
            format!("{}: ", tag)
        };
        if self.json.load(Ordering::SeqCst) {
            let mut j = Json::object();
            j.add("timestamp", Json::string(&ts));
            j.add("tag", Json::string(tag));
            if dbg {
                j.add("pid", Json::number(self.pid as f64));
                j.add("file", Json::string(file));
                j.add("line", Json::number(loc.line() as f64));
                j.add("routine", Json::string("main"));
            }
            j.add("level", Json::string(level.json()));
            // vsnprintf into an OS_MAXSTR buffer
            j.add("description", Json::string(&msg[..msg.len().min(OS_MAXSTR - 1)]));
            let mut line = j.print_unformatted();
            line.push(b'\n');
            self.append(LOGJSONFILE, &line);
        }
        if self.plain.load(Ordering::SeqCst) {
            let mut line = format!("{ts} {prefix}{}: ", level.plain()).into_bytes();
            line.extend_from_slice(msg);
            line.push(b'\n');
            self.append(LOGFILE, &line);
        }
        if stderr {
            let mut line = format!("{ts} {prefix}{}: ", level.plain()).into_bytes();
            line.extend_from_slice(msg);
            line.push(b'\n');
            let _ = std::io::stderr().write_all(&line);
        }
    }

    /// Append to a log file (created 0660 when missing).
    fn append(&self, rel: &str, data: &[u8]) {
        let path = self.home.join(rel);
        let mut o = OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o660);
        }
        if let Ok(mut f) = o.open(&path) {
            let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
            let _ = f.write_all(data);
            let _ = f.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(conf: &str) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("etc")).unwrap();
        std::fs::create_dir_all(d.path().join("logs")).unwrap();
        std::fs::write(d.path().join("etc/ossec.conf"), conf).unwrap();
        d
    }

    #[test]
    fn plain_and_json() {
        let d = home("<ossec_config><logging><log_format>plain, json</log_format></logging></ossec_config>");
        let l = WLog::new("wazuh-analysisd", d.path());
        l.now_daemon();
        l.init().unwrap();
        l.warn("hello \"x\"");
        let plain = std::fs::read_to_string(d.path().join(LOGFILE)).unwrap();
        assert!(plain.ends_with(" wazuh-analysisd: WARNING: hello \"x\"\n"), "{plain}");
        let json = std::fs::read_to_string(d.path().join(LOGJSONFILE)).unwrap();
        assert!(json.contains(r#""tag":"wazuh-analysisd","level":"warning","description":"hello \"x\""}"#), "{json}");
        assert_eq!(l.config_json().print_unformatted(), br#"{"logging":{"plain":"yes","json":"yes"}}"#);
    }

    #[test]
    fn default_is_plain_and_bad_value_fails() {
        let d = home("<ossec_config></ossec_config>");
        let l = WLog::new("t", d.path());
        l.now_daemon();
        l.init().unwrap();
        assert_eq!(l.config_json().print_unformatted(), br#"{"logging":{"plain":"yes","json":"no"}}"#);
        let d = home("<ossec_config><logging><log_format>xml</log_format></logging></ossec_config>");
        let l = WLog::new("t", d.path());
        l.now_daemon();
        assert_eq!(l.init().unwrap_err(), "(1235): Invalid value for element 'log_format': xml.");
        // only json
        let d = home("<ossec_config><logging><log_format>json</log_format></logging></ossec_config>");
        let l = WLog::new("t", d.path());
        l.now_daemon();
        l.init().unwrap();
        l.info("x");
        assert!(!d.path().join(LOGFILE).exists());
        assert!(d.path().join(LOGJSONFILE).exists());
    }
}
