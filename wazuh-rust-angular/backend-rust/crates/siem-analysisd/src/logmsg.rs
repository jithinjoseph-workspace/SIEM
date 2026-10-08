//! `os_analysisd_log_msg_t` lists (`smwarn` / `smerror` / `sminfo`): messages
//! collected while loading a ruleset, returned to wazuh-logtest clients or
//! printed by analysisd.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogMsg {
    pub level: LogLevel,
    pub msg: String,
}

/// `OSList` of log messages (bounded by `ERRORLIST_MAXSIZE` in analysisd).
#[derive(Debug, Clone, Default)]
pub struct LogList {
    pub msgs: Vec<LogMsg>,
    /// `OSList_SetMaxSize` (`ERRORLIST_MAXSIZE` = 50 in analysisd); the
    /// oldest message is dropped when the list grows past it.
    pub max: Option<usize>,
    /// An error was added (even if it was dropped later).
    pub error_seen: bool,
}

/// `ERRORLIST_MAXSIZE`
pub const ERRORLIST_MAXSIZE: usize = 50;
/// Messages are formatted into an `OS_BUFFER_SIZE` (2048) buffer.
const OS_BUFFER_SIZE: usize = 2048;

impl LogList {
    /// A list with Wazuh's `ERRORLIST_MAXSIZE` limit.
    pub fn bounded() -> Self {
        LogList { max: Some(ERRORLIST_MAXSIZE), ..Default::default() }
    }
    fn push(&mut self, level: LogLevel, msg: String) {
        let mut b = msg.into_bytes();
        b.truncate(OS_BUFFER_SIZE - 1);
        let msg = String::from_utf8_lossy(&b).into_owned();
        if level == LogLevel::Error {
            self.error_seen = true;
        }
        self.msgs.push(LogMsg { level, msg });
        if let Some(m) = self.max {
            if m > 0 && self.msgs.len() > m && self.msgs.len() > 1 {
                self.msgs.remove(0);
            }
        }
    }
    pub fn warn(&mut self, msg: impl Into<String>) {
        self.push(LogLevel::Warning, msg.into());
    }
    pub fn error(&mut self, msg: impl Into<String>) {
        self.push(LogLevel::Error, msg.into());
    }
    pub fn info(&mut self, msg: impl Into<String>) {
        self.push(LogLevel::Info, msg.into());
    }
    pub fn has_errors(&self) -> bool {
        self.error_seen
    }
    /// Take every message out (the "drain and print" loops of analysisd).
    pub fn take(&mut self) -> Vec<LogMsg> {
        std::mem::take(&mut self.msgs)
    }
}

// Message formats (error_messages.h / analysisd/logmsg.h).
pub fn fopen_error(f: &str, errno: i32, err: &str) -> String {
    format!("(1103): Could not open file '{f}' due to [({errno})-({err})].")
}
pub fn xml_error(f: &str, e: &str, line: u32) -> String {
    format!("(1226): Error reading XML file '{f}': {e} (line {line}).")
}
pub fn xml_error_var(f: &str, e: &str) -> String {
    format!("(1227): Error applying XML variables '{f}': {e}.")
}
pub const XML_ELEMNULL: &str = "(1231): Invalid NULL element in the configuration.";
pub fn xml_invelem(e: &str) -> String {
    format!("(1230): Invalid element in the configuration: '{e}'.")
}
pub fn xml_valuenull(e: &str) -> String {
    format!("(1234): Invalid NULL content for element: {e}.")
}
pub fn inv_value_default(attr: &str, opt: &str, dec: &str) -> String {
    format!("(7601): Invalid value for attribute '{attr}' in '{opt}' option (decoder `{dec}`). Default value will be used.")
}
pub fn dec_deprecated_opt_value(v: &str, opt: &str, dec: &str) -> String {
    format!("(7603): Deprecated value '{v}' in '{opt}' option (decoder `{dec}`). Default value will be used.")
}
pub fn inv_opt_value_default(v: &str, opt: &str, dec: &str) -> String {
    format!("(7602): Invalid value '{v}' in '{opt}' option (decoder `{dec}`). Default value will be used.")
}
pub fn dup_regex(d: &str) -> String {
    format!("(2109): Duplicated offsets for same regex: '{d}'.")
}
pub fn dec_regex_error(d: &str) -> String {
    format!("(2107): Decoder configuration error: '{d}'.")
}
pub fn inv_decoption(e: &str, c: &str) -> String {
    format!("(2110): Invalid decoder argument for {e}: '{c}'.")
}
pub fn decode_nopre(d: &str) -> String {
    format!("(2108): No 'prematch' found in decoder: '{d}'.")
}
pub fn inv_offset(o: &str) -> String {
    format!("(2120): Invalid offset value: '{o}'")
}
pub fn regex_syntax(r: &str) -> String {
    format!("(1452): Syntax error on regex: '{r}'")
}
pub fn regex_subs(r: &str) -> String {
    format!("(1451): Missing sub_strings on regex: '{r}'.")
}
pub fn decode_add(d: &str) -> String {
    format!("(2111): Additional data to plugin decoder: '{d}'.")
}
pub const DECODER_ERROR: &str = "(2106): Error adding decoder plugin.";
pub fn size_error(s: &str) -> String {
    format!("(1104): Maximum string size reached for: {s}.")
}
pub fn pdup_inv(d: &str) -> String {
    format!("(2102): Duplicated decoder with prematch: '{d}'.")
}
pub fn pdupfts_inv(d: &str) -> String {
    format!("(2103): Duplicated decoder with fts set: '{d}'.")
}
pub fn dup_inv(d: &str) -> String {
    format!("(2104): Invalid duplicated decoder: '{d}'.")
}
pub const DEC_PLUGIN_ERR: &str = "(2105): Error loading decoder options.";
pub fn pplugin_inv(p: &str) -> String {
    format!("(2101): Parent decoder name invalid: '{p}'.")
}
pub fn config_error(f: &str) -> String {
    format!("(1202): Configuration error at '{f}'.")
}
pub const XML_READ_ERROR: &str = "(1232): Error reading XML. Unknown cause.";
pub const INVALID_RULE_ELEMENT: &str = "(1279): Invalid rule element.";
pub fn duplicated_sig_id(id: i32) -> String {
    format!("(7612): Rule ID '{id}' is duplicated. Only the first occurrence will be considered.")
}
pub fn overwrite_missing_rule(id: i32) -> String {
    format!("(7613): Rule ID '{id}' does not exist but 'overwrite' is set to 'yes'. Still, the rule will be loaded.")
}
pub fn invalid_config(e: &str, c: &str) -> String {
    format!("(1274): Invalid configuration. Element '{e}': {c}.")
}
pub fn invalid_day(d: &str) -> String {
    format!("(1241): Invalid day format: '{d}'.")
}
pub fn invalid_ip(ip: &str) -> String {
    format!("(1237): Invalid ip address: '{ip}'.")
}
pub fn rl_regex_syntax(tag: &str, id: i32) -> String {
    format!("(5107): Syntax error on tag '{tag}' in rule {id}")
}
pub fn regex_compile(r: &str, e: i32) -> String {
    format!("(1450): Syntax error on regex: '{r}': {e}.")
}
pub fn list_not_loaded(l: &str, id: i32) -> String {
    format!("(7616): List '{l}' could not be loaded. Rule '{id}' will be ignored.")
}
pub fn invalid_cat(c: &str) -> String {
    format!("(1273): Invalid category '{c}' chosen.")
}
pub fn inv_if_level(v: &str, id: i32) -> String {
    format!("(7609): Invalid 'if_level' value: '{v}'. Rule '{id}' will be ignored.")
}
pub fn inv_if_matched_sid(v: &str, id: i32) -> String {
    format!("(7615): Invalid 'if_matched_sid' value: '{v}'. Rule '{id}' will be ignored.")
}
pub fn xml_valueerr(e: &str, v: &str) -> String {
    format!("(1235): Invalid value for element '{e}': {v}.")
}
pub fn invalid_if_sid(v: &str, id: i32) -> String {
    format!("(7618): Invalid 'if_sid' value: '{v}'. Rule '{id}' will be ignored.")
}
pub fn inv_value_rule(v: &str, attr: &str, id: i32) -> String {
    format!("(7600): Invalid value '{v}' for attribute '{attr}' in rule {id}.")
}
pub const NULL_RULE: &str = "(7614): Rule pointer is NULL. Skipping.";
pub fn sig_id_not_found_mid(sid: i32, id: i32) -> String {
    format!("(7620): Signature ID '{sid}' was not found. Invalid 'if_matched_sid'.Rule '{id}' will be ignored.")
}
pub fn sig_id_not_found(sid: i32, id: i32) -> String {
    format!("(7617): Signature ID '{sid}' was not found and will be ignored in the 'if_sid' option of rule '{id}'.")
}
pub fn inv_sig_id(opt: &str, id: i32) -> String {
    format!("(7607): Invalid '{opt}'. Signature ID must be an integer. Rule '{id}' will be ignored.")
}
pub fn empty_sid(id: i32) -> String {
    format!("(7619): Empty 'if_sid' value. Rule '{id}' will be ignored.")
}
pub fn level_not_found(l: i32, id: i32) -> String {
    format!("(7608): Level ID '{l}' was not found. Invalid 'if_level'. Rule '{id}' will be ignored.")
}
pub fn group_not_found(g: &str, id: i32) -> String {
    format!("(7610): Group '{g}' was not found. Invalid 'if_group'. Rule '{id}' will be ignored.")
}
pub fn category_not_found(id: i32) -> String {
    format!("(7611): Category was not found. Invalid 'category'. Rule '{id}' will be ignored.")
}
pub fn inv_overwrite(field: &str, id: i32) -> String {
    format!("(7605): It is not possible to overwrite '{field}' value in rule '{id}'. The original value is retained.")
}
pub const FORMAT_ERROR: &str = "(1106): String not correctly formatted.";

/// `errno` and `strerror(errno)` (glibc wording) for an I/O error.
pub fn errno_text(e: &std::io::Error) -> (i32, &'static str) {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => (2, "No such file or directory"),
        PermissionDenied => (13, "Permission denied"),
        AlreadyExists => (17, "File exists"),
        InvalidInput => (22, "Invalid argument"),
        ConnectionRefused => (111, "Connection refused"),
        ConnectionReset => (104, "Connection reset by peer"),
        BrokenPipe => (32, "Broken pipe"),
        AddrInUse => (98, "Address already in use"),
        WouldBlock => (11, "Resource temporarily unavailable"),
        TimedOut => (110, "Connection timed out"),
        Interrupted => (4, "Interrupted system call"),
        OutOfMemory => (12, "Cannot allocate memory"),
        _ => match e.raw_os_error() {
            #[cfg(unix)]
            Some(n) => (n, "Input/output error"),
            _ => (5, "Input/output error"),
        },
    }
}
