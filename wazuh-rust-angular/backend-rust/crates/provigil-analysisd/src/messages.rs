//! Messages collected while loading decoders, rules and lists (spec section 2.18): shown by
//! the service and returned to logtest clients. The texts and codes are part of what users
//! see and stay as they are.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub level: Level,
    pub text: String,
}

/// The service keeps the last 50 messages; logtest sessions keep all.
pub const KEPT: usize = 50;

#[derive(Debug, Clone, Default)]
pub struct Messages {
    pub list: Vec<Message>,
    /// Oldest messages are dropped past this many.
    pub limit: Option<usize>,
    /// An error was added, even if it was dropped since.
    pub had_error: bool,
}

impl Messages {
    pub fn bounded() -> Messages {
        Messages { limit: Some(KEPT), ..Messages::default() }
    }

    fn add(&mut self, level: Level, text: String) {
        let mut b = text.into_bytes();
        b.truncate(2047);
        self.had_error |= level == Level::Error;
        self.list.push(Message { level, text: String::from_utf8_lossy(&b).into_owned() });
        if let Some(m) = self.limit {
            if m > 0 && self.list.len() > m.max(1) {
                self.list.remove(0);
            }
        }
    }
    pub fn info(&mut self, t: impl Into<String>) {
        self.add(Level::Info, t.into());
    }
    pub fn warn(&mut self, t: impl Into<String>) {
        self.add(Level::Warning, t.into());
    }
    pub fn error(&mut self, t: impl Into<String>) {
        self.add(Level::Error, t.into());
    }
    pub fn take(&mut self) -> Vec<Message> {
        std::mem::take(&mut self.list)
    }
    pub fn last_text(&self) -> String {
        self.list.last().map(|m| m.text.clone()).unwrap_or_default()
    }
}

pub fn open_failed(f: &str, errno: i32, err: &str) -> String {
    format!("(1103): Could not open file '{f}' due to [({errno})-({err})].")
}
pub fn xml_failed(f: &str, e: &str, line: u32) -> String {
    format!("(1226): Error reading XML file '{f}': {e} (line {line}).")
}
pub fn variables_failed(f: &str, e: &str) -> String {
    format!("(1227): Error applying XML variables '{f}': {e}.")
}
pub const NULL_ELEMENT: &str = "(1231): Invalid NULL element in the configuration.";
pub fn bad_element(e: &str) -> String {
    format!("(1230): Invalid element in the configuration: '{e}'.")
}
pub fn null_content(e: &str) -> String {
    format!("(1234): Invalid NULL content for element: {e}.")
}
pub fn bad_attribute_default(attr: &str, opt: &str, dec: &str) -> String {
    format!("(7601): Invalid value for attribute '{attr}' in '{opt}' option (decoder `{dec}`). Default value will be used.")
}
pub fn deprecated_value(v: &str, opt: &str, dec: &str) -> String {
    format!("(7603): Deprecated value '{v}' in '{opt}' option (decoder `{dec}`). Default value will be used.")
}
pub fn bad_value_default(v: &str, opt: &str, dec: &str) -> String {
    format!("(7602): Invalid value '{v}' in '{opt}' option (decoder `{dec}`). Default value will be used.")
}
pub fn duplicated_offsets(d: &str) -> String {
    format!("(2109): Duplicated offsets for same regex: '{d}'.")
}
pub fn decoder_failed(d: &str) -> String {
    format!("(2107): Decoder configuration error: '{d}'.")
}
pub fn bad_decoder_argument(e: &str, c: &str) -> String {
    format!("(2110): Invalid decoder argument for {e}: '{c}'.")
}
pub fn no_prematch(d: &str) -> String {
    format!("(2108): No 'prematch' found in decoder: '{d}'.")
}
pub fn bad_offset(o: &str) -> String {
    format!("(2120): Invalid offset value: '{o}'")
}
pub fn regex_syntax(r: &str) -> String {
    format!("(1452): Syntax error on regex: '{r}'")
}
pub fn regex_without_groups(r: &str) -> String {
    format!("(1451): Missing sub_strings on regex: '{r}'.")
}
pub fn plugin_with_data(d: &str) -> String {
    format!("(2111): Additional data to plugin decoder: '{d}'.")
}
pub const PLUGIN_FAILED: &str = "(2106): Error adding decoder plugin.";
pub fn too_long(s: &str) -> String {
    format!("(1104): Maximum string size reached for: {s}.")
}
pub fn duplicated_with_prematch(d: &str) -> String {
    format!("(2102): Duplicated decoder with prematch: '{d}'.")
}
pub fn duplicated_with_fts(d: &str) -> String {
    format!("(2103): Duplicated decoder with fts set: '{d}'.")
}
pub fn bad_duplicate(d: &str) -> String {
    format!("(2104): Invalid duplicated decoder: '{d}'.")
}
pub const DECODER_OPTIONS_FAILED: &str = "(2105): Error loading decoder options.";
pub fn bad_parent(p: &str) -> String {
    format!("(2101): Parent decoder name invalid: '{p}'.")
}
pub fn config_error(f: &str) -> String {
    format!("(1202): Configuration error at '{f}'.")
}
pub const XML_UNKNOWN: &str = "(1232): Error reading XML. Unknown cause.";
pub const BAD_RULE_ELEMENT: &str = "(1279): Invalid rule element.";
pub fn duplicated_rule(id: i32) -> String {
    format!("(7612): Rule ID '{id}' is duplicated. Only the first occurrence will be considered.")
}
pub fn overwrite_missing(id: i32) -> String {
    format!("(7613): Rule ID '{id}' does not exist but 'overwrite' is set to 'yes'. Still, the rule will be loaded.")
}
pub fn bad_configuration(e: &str, c: &str) -> String {
    format!("(1274): Invalid configuration. Element '{e}': {c}.")
}
pub fn bad_day(d: &str) -> String {
    format!("(1241): Invalid day format: '{d}'.")
}
pub fn bad_ip(ip: &str) -> String {
    format!("(1237): Invalid ip address: '{ip}'.")
}
pub fn rule_tag_syntax(tag: &str, id: i32) -> String {
    format!("(5107): Syntax error on tag '{tag}' in rule {id}")
}
pub fn regex_failed(r: &str, e: i32) -> String {
    format!("(1450): Syntax error on regex: '{r}': {e}.")
}
pub fn list_not_loaded(l: &str, id: i32) -> String {
    format!("(7616): List '{l}' could not be loaded. Rule '{id}' will be ignored.")
}
pub fn bad_category(c: &str) -> String {
    format!("(1273): Invalid category '{c}' chosen.")
}
pub fn bad_if_level(v: &str, id: i32) -> String {
    format!("(7609): Invalid 'if_level' value: '{v}'. Rule '{id}' will be ignored.")
}
pub fn bad_if_matched_sid(v: &str, id: i32) -> String {
    format!("(7615): Invalid 'if_matched_sid' value: '{v}'. Rule '{id}' will be ignored.")
}
pub fn bad_value(e: &str, v: &str) -> String {
    format!("(1235): Invalid value for element '{e}': {v}.")
}
pub fn bad_if_sid(v: &str, id: i32) -> String {
    format!("(7618): Invalid 'if_sid' value: '{v}'. Rule '{id}' will be ignored.")
}
pub fn bad_rule_attribute(v: &str, attr: &str, id: i32) -> String {
    format!("(7600): Invalid value '{v}' for attribute '{attr}' in rule {id}.")
}
pub const NULL_RULE: &str = "(7614): Rule pointer is NULL. Skipping.";
pub fn matched_sid_not_found(sid: i32, id: i32) -> String {
    format!("(7620): Signature ID '{sid}' was not found. Invalid 'if_matched_sid'.Rule '{id}' will be ignored.")
}
pub fn sid_not_found(sid: i32, id: i32) -> String {
    format!("(7617): Signature ID '{sid}' was not found and will be ignored in the 'if_sid' option of rule '{id}'.")
}
pub fn sid_not_number(opt: &str, id: i32) -> String {
    format!("(7607): Invalid '{opt}'. Signature ID must be an integer. Rule '{id}' will be ignored.")
}
pub fn empty_if_sid(id: i32) -> String {
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
pub fn cannot_overwrite(field: &str, id: i32) -> String {
    format!("(7605): It is not possible to overwrite '{field}' value in rule '{id}'. The original value is retained.")
}

/// The error number and system text of an I/O error, in the wording users know from logs.
pub fn os_error(e: &std::io::Error) -> (i32, &'static str) {
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
