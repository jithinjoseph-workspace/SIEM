//! `<localfile>` (config/localfile-config.c): `Read_Localfile`,
//! `Remove_Localfile`, the multiline_regex attribute readers, the journald
//! filter helpers and `w_logreader_journald_merge`.
//!
//! The C code keeps the entries in a NULL-terminated array and relies on
//! its quirks (an entry is appended at the first slot whose `file` is
//! NULL, an entry without `log_format` ends the list for the readers,
//! glob templates share pointers with the files they expand to). The
//! structures below keep those semantics: fields C shares between copies
//! are `Arc`s, and [`LogreaderConfig::config`] is a plain vector handled
//! the way C handles the array.

use std::sync::Arc;

use siem_regex::expression::{ExpType, Expression};
use siem_xml::XmlNode;

use crate::labels::{labels_add, Label, LabelFlags};
use crate::messages;
use crate::socket::SocketForwarder;
use crate::{ConfigContext, ConfigError, Result};

pub const EVENTLOG: &str = "eventlog";
pub const EVENTCHANNEL: &str = "eventchannel";
pub const MACOS: &str = "macos";
pub const JOURNALD_LOG: &str = "journald";
pub const MULTI_LINE_REGEX: &str = "multi-line-regex";
pub const MULTI_LINE_REGEX_TIMEOUT: u32 = 5;
pub const MULTI_LINE_REGEX_MAX_TIMEOUT: u32 = 120;
pub const DEFAULT_EVENTCHANNEL_REC_TIME: i32 = 5;
pub const DIFF_DEFAULT_SIZE: i64 = 10 * 1024 * 1024;
pub const DEFAULT_FREQUENCY_SECS: i32 = 360;
pub const DIFF_MAX_SIZE: i64 = 2 * 1024 * 1024 * 1024;
pub const MACOS_LOG_TYPE_ACTIVITY: i32 = 1;
pub const MACOS_LOG_TYPE_LOG: i32 = 2;
pub const MACOS_LOG_TYPE_TRACE: i32 = 4;
/// `OS_FLSIZE`
const OS_FLSIZE: usize = 256;
/// `PATH_MAX`
const PATH_MAX: usize = 4096;

/// `outformat`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutFormat {
    pub target: Option<String>,
    pub format: String,
}

/// `w_multiline_match_type_t`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlMatch {
    Start,
    All,
    End,
}

/// `w_multiline_replace_type_t`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlReplace {
    NoReplace,
    None,
    Wspace,
    Tab,
}

/// `multiline_attr_match_str`
pub fn multiline_attr_match_str(m: MlMatch) -> &'static str {
    match m {
        MlMatch::Start => "start",
        MlMatch::All => "all",
        MlMatch::End => "end",
    }
}

/// `multiline_attr_replace_str`
pub fn multiline_attr_replace_str(r: MlReplace) -> &'static str {
    match r {
        MlReplace::NoReplace => "no-replace",
        MlReplace::None => "none",
        MlReplace::Wspace => "wspace",
        MlReplace::Tab => "tab",
    }
}

/// `w_multiline_ctxt_t`
#[derive(Debug, Clone, Default)]
pub struct MultilineCtxt {
    pub lines_count: i32,
    pub buffer: Vec<u8>,
    pub timestamp: i64,
}

/// `w_multiline_config_t`
#[derive(Debug)]
pub struct MultilineConfig {
    pub regex: Arc<Expression>,
    pub match_type: MlMatch,
    pub replace_type: MlReplace,
    pub timeout: u32,
    pub ctxt: Option<MultilineCtxt>,
    pub offset_last_read: i64,
}

impl MultilineConfig {
    /// `w_multiline_log_config_clone`: same settings, no context.
    pub fn clone_config(&self) -> MultilineConfig {
        MultilineConfig {
            regex: Arc::clone(&self.regex),
            match_type: self.match_type,
            replace_type: self.replace_type,
            timeout: self.timeout,
            ctxt: None,
            offset_last_read: 0,
        }
    }
}

/// `_w_journal_filter_unit_t`
#[derive(Debug)]
pub struct JournalFilterUnit {
    pub field: String,
    pub exp: Arc<Expression>,
    pub ignore_if_missing: bool,
}

/// `w_journal_filter_t`
#[derive(Debug, Default)]
pub struct JournalFilter {
    pub units: Vec<JournalFilterUnit>,
}

/// `w_journal_log_config_t`. `filters` is the C NULL-terminated list:
/// `None` is a NULL list, a `None` item ends it.
#[derive(Debug, Default)]
pub struct JournalLogConfig {
    pub filters: Option<Vec<Option<JournalFilter>>>,
    pub disable_filters: bool,
}

impl JournalLogConfig {
    /// The filters up to the first NULL.
    pub fn active_filters(&self) -> Vec<&JournalFilter> {
        let mut v = Vec::new();
        if let Some(l) = &self.filters {
            for f in l {
                match f {
                    Some(f) => v.push(f),
                    None => break,
                }
            }
        }
        v
    }

    fn has_filters(&self) -> bool {
        matches!(&self.filters, Some(l) if matches!(l.first(), Some(Some(_))))
    }
}

/// The configuration fields of `logreader`.
#[derive(Debug, Default)]
pub struct Localfile {
    pub file: Option<String>,
    pub ffile: Option<String>,
    pub logformat: Option<String>,
    pub multiline: Option<MultilineConfig>,
    /// Only built on macOS (`w_macos_log_config_t`); a Linux agent never sets it.
    pub macos_log: bool,
    pub journal_log: Option<JournalLogConfig>,
    pub linecount: i64,
    pub djb_program_name: Option<String>,
    pub channel_str: Option<String>,
    /// C points `command` at `file`; the port keeps a copy.
    pub command: Option<String>,
    pub alias: Option<String>,
    pub reconnect_time: i32,
    pub future: i32,
    pub diff_max_size: i64,
    pub query: Option<String>,
    pub query_type: i32,
    pub query_level: Option<String>,
    pub filter_binary: i32,
    pub ucs2: i32,
    pub out_format: Option<Arc<Vec<OutFormat>>>,
    pub target: Option<Arc<Vec<String>>>,
    pub exclude: Option<String>,
    pub regex_ignore: Option<Arc<Vec<Expression>>>,
    pub regex_restrict: Option<Arc<Vec<Expression>>>,
    pub labels: Option<Arc<Vec<Label>>>,
    pub exists: i32,
    pub age: u32,
    pub age_str: Option<String>,
    pub ign: i32,
}

impl Localfile {
    /// A `memcpy` of the entry: shared fields are shared, the multiline
    /// configuration is moved to the copy (callers clone it as C does).
    pub fn shallow_copy(&self) -> Localfile {
        Localfile {
            file: self.file.clone(),
            ffile: self.ffile.clone(),
            logformat: self.logformat.clone(),
            multiline: self.multiline.as_ref().map(MultilineConfig::clone_config),
            macos_log: self.macos_log,
            journal_log: None,
            linecount: self.linecount,
            djb_program_name: self.djb_program_name.clone(),
            channel_str: self.channel_str.clone(),
            command: self.command.clone(),
            alias: self.alias.clone(),
            reconnect_time: self.reconnect_time,
            future: self.future,
            diff_max_size: self.diff_max_size,
            query: self.query.clone(),
            query_type: self.query_type,
            query_level: self.query_level.clone(),
            filter_binary: self.filter_binary,
            ucs2: self.ucs2,
            out_format: self.out_format.clone(),
            target: self.target.clone(),
            exclude: self.exclude.clone(),
            regex_ignore: self.regex_ignore.clone(),
            regex_restrict: self.regex_restrict.clone(),
            labels: self.labels.clone(),
            exists: self.exists,
            age: self.age,
            age_str: self.age_str.clone(),
            ign: self.ign,
        }
    }
}

/// `logreader_glob`
#[derive(Debug, Default)]
pub struct LocalfileGlob {
    pub gpath: String,
    pub exclude_path: Option<String>,
    pub num_files: i32,
    /// `gfiles`: the expanded files, then the template (C's end mark,
    /// `file == NULL`).
    pub gfiles: Vec<Localfile>,
}

/// `logreader_config` plus the `maximum_files` / `current_files` /
/// `total_files` globals of localfile-config.c.
#[derive(Debug, Default)]
pub struct LogreaderConfig {
    pub agent_cfg: bool,
    pub accept_remote: bool,
    pub globs: Vec<LocalfileGlob>,
    pub config: Vec<Localfile>,
    pub socket_list: Vec<SocketForwarder>,
    pub maximum_files: i32,
    pub current_files: i32,
    pub total_files: i32,
}

/// `strtoul(s, &end, 0)`: (value saturated at `u64::MAX`, rest).
pub fn strtoul0(s: &str) -> (u64, &str) {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && (b[i] == b' ' || (b'\t'..=b'\r').contains(&b[i])) {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let (base, start) = if b.get(i) == Some(&b'0') && matches!(b.get(i + 1), Some(b'x') | Some(b'X'))
        && b.get(i + 2).map(|c| c.is_ascii_hexdigit()).unwrap_or(false)
    {
        (16, i + 2)
    } else if b.get(i) == Some(&b'0') {
        (8, i)
    } else {
        (10, i)
    };
    let mut j = start;
    let mut v: u64 = 0;
    let mut overflow = false;
    while j < b.len() {
        let d = match b[j] {
            c @ b'0'..=b'9' => (c - b'0') as u64,
            c @ b'a'..=b'f' => (c - b'a' + 10) as u64,
            c @ b'A'..=b'F' => (c - b'A' + 10) as u64,
            _ => break,
        };
        if d >= base {
            break;
        }
        match v.checked_mul(base).and_then(|x| x.checked_add(d)) {
            Some(x) => v = x,
            None => overflow = true,
        }
        j += 1;
    }
    if j == start && base != 8 {
        return (0, s);
    }
    if overflow {
        return (u64::MAX, &s[j..]);
    }
    (if neg { v.wrapping_neg() } else { v }, &s[j..])
}

/// `w_validate_bytes`: "<n>[KkMmGg]" in bytes, -1 when invalid.
pub fn w_validate_bytes(content: &str) -> i64 {
    let (v, used) = crate::util::strtol(content);
    if v < 0 || v == i64::MAX || used == 0 {
        return -1;
    }
    match content.as_bytes().get(used) {
        Some(b'K') | Some(b'k') => v.wrapping_mul(1024),
        Some(b'M') | Some(b'm') => v.wrapping_mul(1024 * 1024),
        Some(b'G') | Some(b'g') => v.wrapping_mul(1024 * 1024 * 1024),
        _ => v,
    }
}

/// `strftime(buf, size, fmt, localtime(now))`: `None` when it returns 0.
pub fn strftime_now(fmt: &str, size: usize) -> Option<String> {
    #[cfg(unix)]
    {
        let c = std::ffi::CString::new(fmt).ok()?;
        let mut buf = vec![0u8; size];
        // SAFETY: localtime_r/strftime on valid buffers.
        let n = unsafe {
            let t = libc::time(std::ptr::null_mut());
            let mut tm: libc::tm = std::mem::zeroed();
            libc::localtime_r(&t, &mut tm);
            libc::strftime(buf.as_mut_ptr().cast(), size, c.as_ptr(), &tm)
        };
        if n == 0 {
            return None;
        }
        buf.truncate(n);
        Some(String::from_utf8_lossy(&buf).into_owned())
    }
    #[cfg(windows)]
    {
        win::strftime_now(fmt, size)
    }
}

/// msvcrt `localtime` / `strftime`, the C library of the Windows agent
/// (its conversions and its handling of unknown ones are not glibc's).
#[cfg(windows)]
pub mod win {
    #[repr(C)]
    struct Tm {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
        tm_yday: i32,
        tm_isdst: i32,
    }

    extern "C" {
        fn _localtime64_s(tm: *mut Tm, t: *const i64) -> i32;
        fn strftime(s: *mut u8, max: usize, fmt: *const u8, tm: *const Tm) -> usize;
        fn _time64(t: *mut i64) -> i64;
    }

    /// `strftime(buf, size, fmt, localtime(t))`: `None` when it returns 0.
    pub fn strftime_at(fmt: &str, size: usize, t: i64) -> Option<String> {
        let c = std::ffi::CString::new(fmt).ok()?;
        let mut buf = vec![0u8; size.max(1)];
        // SAFETY: valid tm/buffers; msvcrt functions.
        let n = unsafe {
            let mut tm: Tm = std::mem::zeroed();
            _localtime64_s(&mut tm, &t);
            strftime(buf.as_mut_ptr(), size, c.as_ptr().cast(), &tm)
        };
        if n == 0 {
            return None;
        }
        buf.truncate(n);
        Some(String::from_utf8_lossy(&buf).into_owned())
    }

    /// `strftime` of the current local time.
    pub fn strftime_now(fmt: &str, size: usize) -> Option<String> {
        // SAFETY: time(NULL)
        let t = unsafe { _time64(std::ptr::null_mut()) };
        strftime_at(fmt, size, t)
    }

    /// `ExpandEnvironmentStrings(content, newfile, OS_MAXSTR)`: the expanded
    /// string when the call returns a size in (0, OS_MAXSTR).
    pub fn expand_env(content: &str) -> Option<String> {
        use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsA;
        const OS_MAXSTR: u32 = 65536;
        let c = std::ffi::CString::new(content).ok()?;
        let mut buf = vec![0u8; OS_MAXSTR as usize + 1];
        // SAFETY: NUL-terminated source, buffer of OS_MAXSTR bytes.
        let r = unsafe { ExpandEnvironmentStringsA(c.as_ptr().cast(), buf.as_mut_ptr(), OS_MAXSTR) };
        if r > 0 && r < OS_MAXSTR {
            let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            Some(String::from_utf8_lossy(&buf[..n]).into_owned())
        } else {
            None
        }
    }
}

/// `NETWORK_PATH_CONFIGURED`
#[cfg(windows)]
fn network_path_configured(element: &str, content: &str) -> String {
    format!("(9801): Network path not allowed in configuration. '{element}': {content}.")
}

/// `glob(pattern, 0, NULL, &g)` result: `Ok(paths)` (empty on
/// `GLOB_NOMATCH`) or `Err(())` on any other error.
pub fn c_glob(pattern: &str) -> std::result::Result<Vec<String>, ()> {
    #[cfg(unix)]
    {
        let c = std::ffi::CString::new(pattern).map_err(|_| ())?;
        // SAFETY: glob/globfree with a zeroed glob_t.
        unsafe {
            let mut g: libc::glob_t = std::mem::zeroed();
            let err = libc::glob(c.as_ptr(), 0, None, &mut g);
            if err == libc::GLOB_NOMATCH {
                libc::globfree(&mut g);
                return Ok(Vec::new());
            }
            if err != 0 {
                libc::globfree(&mut g);
                return Err(());
            }
            let mut out = Vec::new();
            for i in 0..g.gl_pathc {
                let p = *g.gl_pathv.add(i);
                if !p.is_null() {
                    out.push(std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned());
                }
            }
            libc::globfree(&mut g);
            Ok(out)
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pattern;
        Ok(Vec::new())
    }
}

fn attr<'a>(n: &'a XmlNode, name: &str) -> Option<&'a str> {
    n.attributes.iter().position(|a| a == name).map(|i| n.values[i].as_str())
}

fn inv_value_default(v: &str, a: &str, opt: &str) -> String {
    format!("(8000): Invalid value '{v}' for attribute '{a}' in '{opt}' option. Default value will be used.")
}

fn inv_value_ignore(v: &str, a: &str, opt: &str) -> String {
    format!("(8003): Invalid value '{v}' for attribute '{a}' in '{opt}' option. Attribute will be ignored.")
}

fn option_ignored(fmt: &str, opt: &str) -> String {
    format!("(8004): log_format '{fmt}' does not support '{opt}' option. Option will be ignored.")
}

/// `w_get_attr_match`
pub fn get_attr_match(ctx: &mut ConfigContext, n: &XmlNode) -> MlMatch {
    let Some(s) = attr(n, "match") else { return MlMatch::Start };
    for m in [MlMatch::Start, MlMatch::All, MlMatch::End] {
        if s.eq_ignore_ascii_case(multiline_attr_match_str(m)) {
            return m;
        }
    }
    ctx.warn(inv_value_default(s, "match", "multiline_regex"));
    MlMatch::Start
}

/// `w_get_attr_replace`
pub fn get_attr_replace(ctx: &mut ConfigContext, n: &XmlNode) -> MlReplace {
    let Some(s) = attr(n, "replace") else { return MlReplace::NoReplace };
    for r in [MlReplace::NoReplace, MlReplace::Wspace, MlReplace::Tab, MlReplace::None] {
        if s.eq_ignore_ascii_case(multiline_attr_replace_str(r)) {
            return r;
        }
    }
    ctx.warn(inv_value_default(s, "replace", "multiline_regex"));
    MlReplace::NoReplace
}

/// `w_get_attr_timeout`
pub fn get_attr_timeout(ctx: &mut ConfigContext, n: &XmlNode) -> u32 {
    let Some(s) = attr(n, "timeout") else { return MULTI_LINE_REGEX_TIMEOUT };
    let (v, rest) = strtoul0(s);
    // retval is an unsigned int
    let v = v as u32;
    if !rest.is_empty() || v == 0 || v > MULTI_LINE_REGEX_MAX_TIMEOUT {
        ctx.warn(inv_value_default(s, "timeout", "multiline_regex"));
        return MULTI_LINE_REGEX_TIMEOUT;
    }
    v
}

/// `w_logcollector_get_macos_log_type`
fn macos_log_type(ctx: &mut ConfigContext, content: &str) -> i32 {
    let mut ret = 0;
    for item in siem_regex::str_break(',', content, 64).unwrap_or_default() {
        let mut s = item.trim_start_matches(' ').to_string();
        if s.split(' ').filter(|w| !w.is_empty()).count() == 1 {
            if let Some(p) = s.find(' ') {
                s.truncate(p);
            }
        }
        if s.eq_ignore_ascii_case("activity") {
            ret |= MACOS_LOG_TYPE_ACTIVITY;
        } else if s.eq_ignore_ascii_case("log") {
            ret |= MACOS_LOG_TYPE_LOG;
        } else if s.eq_ignore_ascii_case("trace") {
            ret |= MACOS_LOG_TYPE_TRACE;
        } else if !s.is_empty() {
            ctx.warn(inv_value_ignore(&s, "type", "query"));
        }
    }
    ret
}

/// `w_check_regex_type`
fn check_regex_type(ctx: &mut ConfigContext, n: &XmlNode, element: &str) -> ExpType {
    if let Some(v) = n.values.first() {
        if v.eq_ignore_ascii_case("osregex") {
            return ExpType::OsRegex;
        } else if v.eq_ignore_ascii_case("osmatch") {
            return ExpType::OsMatch;
        } else if v.eq_ignore_ascii_case("pcre2") {
            return ExpType::Pcre2;
        }
    }
    ctx.warn(format!(
        "(8007): Invalid type in '{element}' regex '{}', setting by default PCRE2 regex.",
        n.content.as_deref().unwrap_or("")
    ));
    ExpType::Pcre2
}

/// `w_journal_filter_add_condition`
pub fn journal_filter_add_condition(
    filter: &mut Option<JournalFilter>,
    field: &str,
    expression: &str,
    ignore_if_missing: bool,
) -> i32 {
    let Ok(exp) = Expression::compile(ExpType::Pcre2, expression, 0) else { return -1 };
    filter.get_or_insert_with(JournalFilter::default).units.push(JournalFilterUnit {
        field: field.to_string(),
        exp: Arc::new(exp),
        ignore_if_missing,
    });
    0
}

/// `journald_add_condition_to_filter`
fn journald_add_condition(ctx: &mut ConfigContext, n: &XmlNode, filter: &mut Option<JournalFilter>) -> bool {
    let field = attr(n, "field").unwrap_or("");
    let expression = n.content.as_deref().unwrap_or("");
    if field.is_empty() {
        ctx.warn("(8019): The field for the journal filter cannot be empty.");
        return false;
    }
    if expression.is_empty() {
        ctx.warn("(8020): The expression for the journal filter cannot be empty.");
        return false;
    }
    let mut ignore = false;
    if let Some(s) = attr(n, "ignore_if_missing") {
        if s.eq_ignore_ascii_case("yes") {
            ignore = true;
        } else if !s.eq_ignore_ascii_case("no") {
            ctx.warn(inv_value_default(s, "ignore_if_missing", "journal"));
        }
    }
    if journal_filter_add_condition(filter, field, expression, ignore) != 0 {
        ctx.warn(format!(
            "(8021): Error compiling the PCRE2 expression '{expression}' for field '{field}' in journal filter."
        ));
        return false;
    }
    true
}

/// `Remove_Localfile(&logf, i, gl, fr, globf)`: 0, or -1 when `i` is out of
/// range. `current_files` is decremented on success.
pub fn remove_localfile(
    logf: &mut Vec<Localfile>,
    i: usize,
    gl: bool,
    num_files: Option<&mut i32>,
    current_files: &mut i32,
) -> i32 {
    // size: entries while (file || (!gl && logformat))
    let size = logf.iter().take_while(|l| l.file.is_some() || (!gl && l.logformat.is_some())).count();
    if i < size {
        logf.remove(i);
        if gl {
            if let Some(n) = num_files {
                *n -= 1;
            }
        }
        *current_files -= 1;
        return 0;
    }
    -1
}

/// `w_logreader_journald_merge`: fold `src_index` into the first journald
/// entry before it.
pub fn journald_merge(cfg: &mut LogreaderConfig, src_index: usize) -> bool {
    let logr = &mut cfg.config;
    if src_index == 0 {
        return false;
    }
    let mut i = 0;
    while i < logr.len() && logr[i].file.is_some() {
        if i == src_index {
            break;
        }
        i += 1;
    }
    if logr.get(i).map(|l| l.journal_log.is_none()).unwrap_or(true) {
        return false;
    }
    let mut dst = None;
    for d in 0..src_index.min(logr.len()) {
        if logr[d].file.is_none() {
            break;
        }
        if logr[d].journal_log.is_some() {
            dst = Some(d);
            break;
        }
    }
    let Some(dst) = dst else { return false };
    let src_has = logr[src_index].journal_log.as_ref().map(JournalLogConfig::has_filters).unwrap_or(false);
    let dst_has = logr[dst].journal_log.as_ref().map(JournalLogConfig::has_filters).unwrap_or(false);
    // Only disable filters when BOTH blocks have none (the caller logs it)
    logr[dst].journal_log.as_mut().unwrap().disable_filters = !src_has && !dst_has;
    if src_has {
        let f = logr[src_index].journal_log.as_mut().unwrap().filters.as_mut().unwrap()[0].take();
        let dl = logr[dst].journal_log.as_mut().unwrap();
        let list = dl.filters.get_or_insert_with(Vec::new);
        // append before the terminator
        let end = list.iter().position(Option::is_none).unwrap_or(list.len());
        list.truncate(end);
        list.push(f);
    }
    logr[dst].future = logr[src_index].future;
    logr[dst].target = logr[src_index].target.take();
    let mut cur = cfg.current_files;
    remove_localfile(&mut cfg.config, src_index, false, None, &mut cur);
    cfg.current_files = cur;
    true
}

/// `Read_Localfile`
pub fn read_localfile(ctx: &mut ConfigContext, nodes: &[XmlNode], cfg: &mut LogreaderConfig) -> Result<()> {
    if cfg.maximum_files != 0 && cfg.current_files >= cfg.maximum_files {
        ctx.warn(format!(
            "(1960): File limit has been reached ({}). Please reduce the number of files or increase \"logcollector.max_files\".",
            cfg.maximum_files
        ));
        return Ok(());
    }

    // Append at the first entry without a file (C overwrites it and puts
    // the end mark right after it).
    let pl = cfg.config.iter().position(|l| l.file.is_none()).unwrap_or(cfg.config.len());
    cfg.config.truncate(pl);
    cfg.config.push(Localfile {
        ign: DEFAULT_FREQUENCY_SECS,
        exists: 1,
        future: 1,
        reconnect_time: DEFAULT_EVENTCHANNEL_REC_TIME,
        ..Default::default()
    });

    let r = read_localfile_body(ctx, nodes, cfg, pl);
    // An entry left without a file is the array end mark.
    r
}

fn read_localfile_body(ctx: &mut ConfigContext, nodes: &[XmlNode], cfg: &mut LogreaderConfig, pl: usize) -> Result<()> {
    let mut labels: Vec<Label> = Vec::new();
    macro_rules! lf {
        () => {
            cfg.config[pl]
        };
    }

    for n in nodes {
        let Some(content) = n.content.as_deref() else {
            return Err(ConfigError::new(messages::xml_valuenull(&n.element)));
        };
        let el = n.element.as_str();
        if el == "only-future-events" {
            lf!().diff_max_size = DIFF_DEFAULT_SIZE;
            for (a, v) in n.attributes.iter().zip(&n.values) {
                if a == "max-size" {
                    let value = w_validate_bytes(v);
                    if value == -1 || value > DIFF_MAX_SIZE {
                        ctx.warn(inv_value_default(v, "max-size", "only-future-events"));
                        continue;
                    }
                    lf!().diff_max_size = value;
                } else {
                    ctx.warn(messages::xml_invattr(a, el));
                }
            }
            match content {
                "yes" => lf!().future = 1,
                "no" => lf!().future = 0,
                _ => ctx.warn(messages::xml_valueerr(el, content)),
            }
        } else if el == "query" {
            if let Some(t) = attr(n, "type") {
                lf!().query_type = macos_log_type(ctx, t);
            }
            if let Some(l) = attr(n, "level") {
                if l != "default" && l != "info" && l != "debug" {
                    ctx.warn(inv_value_ignore(l, "level", "query"));
                } else {
                    lf!().query_level = Some(l.to_string());
                }
            }
            lf!().query = Some(content.to_string());
        } else if el == "target" {
            let count = content.matches(',').count() + 1;
            let t: Vec<String> = siem_regex::str_break(',', content, count)
                .unwrap_or_default()
                .into_iter()
                .map(|s| crate::util::strtrim(&s).to_string())
                .collect();
            lf!().target = Some(Arc::new(t));
        } else if el == "out_format" {
            let mut target = None;
            for (a, v) in n.attributes.iter().zip(&n.values) {
                if a == "target" {
                    target = Some(v.clone());
                } else {
                    ctx.warn(format!("Invalid attribute '{a}' for <out_format>"));
                }
            }
            let mut v: Vec<OutFormat> = lf!().out_format.as_deref().cloned().unwrap_or_default();
            v.push(OutFormat { target, format: content.to_string() });
            lf!().out_format = Some(Arc::new(v));
        } else if el == "reconnect_time" {
            let (v, rest) = strtoul0(content);
            let mut time = v as i32;
            if time != 0 {
                match rest.as_bytes().first() {
                    Some(b'w') => time = time.wrapping_mul(604800),
                    Some(b'd') => time = time.wrapping_mul(86400),
                    Some(b'h') => time = time.wrapping_mul(3600),
                    Some(b'm') => time = time.wrapping_mul(60),
                    Some(b's') => {}
                    _ => return Err(ConfigError::new(messages::xml_valueerr(el, content))),
                }
            }
            if time < 1 || time == i32::MAX {
                ctx.warn(format!(
                    "Invalid reconnection time value. Changed to {DEFAULT_EVENTCHANNEL_REC_TIME} seconds."
                ));
                time = DEFAULT_EVENTCHANNEL_REC_TIME;
            }
            lf!().reconnect_time = time;
        } else if el == "label" {
            let mut flags = LabelFlags::default();
            let mut key: Option<&str> = None;
            for (a, v) in n.attributes.iter().zip(&n.values) {
                if a == "key" {
                    if !v.is_empty() {
                        if v.starts_with('_') {
                            ctx.warn(format!(
                                "Labels starting with \"_\"  are reserved for internal use. Skipping label '{v}'."
                            ));
                            flags.system = true;
                        }
                        key = Some(v);
                    } else {
                        return Err(ConfigError::new("Label with empty key."));
                    }
                }
            }
            if flags.system {
                continue;
            }
            let Some(key) = key else {
                return Err(ConfigError::new("Expected 'key' attribute for label."));
            };
            labels_add(&mut labels, key, content, flags, true);
            lf!().labels = Some(Arc::new(labels.clone()));
        } else if el == "command" {
            if cfg.agent_cfg && !cfg.accept_remote {
                ctx.error("Remote commands are not accepted from the manager. Ignoring it on the agent.conf");
                let l = &mut lf!();
                l.file = None;
                l.ffile = None;
                l.command = None;
                l.alias = None;
                l.logformat = None;
                l.labels = None;
                return Ok(());
            }
            #[cfg(windows)]
            if siem_fileop::crt::is_network_path(content) {
                let l = &mut lf!();
                l.file = None;
                l.ffile = None;
                l.command = None;
                l.alias = None;
                l.logformat = None;
                l.labels = None;
                ctx.warn(network_path_configured(el, content));
                return Ok(());
            }
            lf!().file = Some(content.to_string());
            lf!().command = Some(content.to_string());
        } else if el == "frequency" {
            if content == "hourly" {
                lf!().ign = 3600;
            } else if content == "daily" {
                lf!().ign = 86400;
            } else {
                if !siem_regex::str_is_num(content) {
                    return Err(ConfigError::new(messages::xml_valueerr(el, content)));
                }
                lf!().ign = crate::util::atoi(content);
            }
        } else if el == "location" {
            // Expand variables on Windows
            #[cfg(windows)]
            let content: &str = &match content.contains('%').then(|| win::expand_env(content)).flatten() {
                Some(e) => e,
                None => content.to_string(),
            };
            #[cfg(windows)]
            if siem_fileop::crt::is_network_path(content) {
                let l = &mut lf!();
                l.file = None;
                l.ffile = None;
                l.command = None;
                l.alias = None;
                l.logformat = None;
                l.labels = None;
                ctx.warn(network_path_configured(el, content));
                return Ok(());
            }
            lf!().file = Some(content.to_string());
        } else if el.eq_ignore_ascii_case("log_format") {
            lf!().logformat = Some(content.to_string());
            match content {
                "syslog" | "generic" | "json" | "snort-full" | "snort-fast" | "apache" | "iis" | "squid"
                | "nmapg" | "mysql_log" | "ossecalert" | "mssql_log" | "postgresql_log" | "djb-multilog"
                | "syslog-pipe" | "command" | "full_command" | "audit" | MULTI_LINE_REGEX => {}
                f if f.starts_with("multi-line") => {
                    let p = f[10..].trim_start_matches(' ');
                    let Some(p) = p.strip_prefix(':') else {
                        return Err(ConfigError::new(messages::xml_valueerr(el, content)));
                    };
                    let (v, used) = crate::util::strtol(p);
                    lf!().linecount = v;
                    if used == 0 || v < 1 {
                        return Err(ConfigError::new(messages::xml_valueerr(el, content)));
                    }
                }
                EVENTLOG | EVENTCHANNEL | MACOS | JOURNALD_LOG => {}
                _ => return Err(ConfigError::new(messages::xml_valueerr(el, content))),
            }
        } else if el.eq_ignore_ascii_case("multiline_regex") {
            if content.is_empty() {
                ctx.warn("Empty tag 'multiline_regex' is ignored");
            } else if lf!().multiline.is_none() {
                let Ok(exp) = Expression::compile(ExpType::Pcre2, content, 0) else {
                    return Err(ConfigError::new(format!("(1967): Syntax error on multiline_regex: '{content}'")));
                };
                let match_type = get_attr_match(ctx, n);
                let replace_type = get_attr_replace(ctx, n);
                let timeout = get_attr_timeout(ctx, n);
                lf!().multiline = Some(MultilineConfig {
                    regex: Arc::new(exp),
                    match_type,
                    replace_type,
                    timeout,
                    ctxt: None,
                    offset_last_read: 0,
                });
            } else {
                ctx.warn("Duplicate tag 'multiline_regex' is ignored");
            }
        } else if el.eq_ignore_ascii_case("exclude") {
            lf!().exclude = Some(content.to_string());
        } else if el.eq_ignore_ascii_case("alias") {
            lf!().alias = Some(content.to_string());
        } else if el == "age" {
            let (v, rest) = strtoul0(content);
            let mut age = v as u32;
            if age == 0 || age == u32::MAX {
                return Err(ConfigError::new("Invalid age for localfile"));
            }
            match rest.as_bytes().first() {
                Some(b'w') => age = age.wrapping_mul(604800),
                Some(b'd') => age = age.wrapping_mul(86400),
                Some(b'h') => age = age.wrapping_mul(3600),
                Some(b'm') => age = age.wrapping_mul(60),
                Some(b's') | None => {}
                _ => return Err(ConfigError::new("Invalid age for localfile")),
            }
            lf!().age = age;
            lf!().age_str = Some(content.to_string());
        } else if el.eq_ignore_ascii_case("ignore_binaries") {
            match content {
                "yes" => lf!().filter_binary = 1,
                "no" => lf!().filter_binary = 0,
                _ => return Err(ConfigError::new(messages::xml_valueerr(el, content))),
            }
        } else if el.eq_ignore_ascii_case("ignore") || el.eq_ignore_ascii_case("restrict") {
            let which = if el.eq_ignore_ascii_case("ignore") { "ignore" } else { "restrict" };
            let mut ty = ExpType::Pcre2;
            if let Some(a0) = n.attributes.first() {
                if a0 == "type" {
                    ty = check_regex_type(ctx, n, which);
                } else {
                    return Err(ConfigError::new(format!("(1975): Syntax error on regex {which}: '{content}'")));
                }
            }
            let Ok(exp) = Expression::compile(ty, content, 0) else {
                return Err(ConfigError::new(format!("(1975): Syntax error on regex {which}: '{content}'")));
            };
            let slot = if which == "ignore" { &mut lf!().regex_ignore } else { &mut lf!().regex_restrict };
            match slot {
                // not shared yet while parsing
                Some(a) => Arc::make_mut(a).push(exp),
                None => *slot = Some(Arc::new(vec![exp])),
            }
        } else if el.eq_ignore_ascii_case("filter") {
            if lf!().journal_log.is_none() {
                lf!().journal_log = Some(JournalLogConfig { filters: Some(vec![None, None]), disable_filters: false });
            }
            let jl = lf!().journal_log.as_mut().unwrap();
            let list = jl.filters.get_or_insert_with(|| vec![None, None]);
            if list.is_empty() {
                list.push(None);
            }
            let mut f0 = list[0].take();
            let ok = journald_add_condition(ctx, n, &mut f0);
            lf!().journal_log.as_mut().unwrap().filters.as_mut().unwrap()[0] = f0;
            if !ok {
                ctx.warn("(8015): Cannot add filter, the block will be ignored.");
                // w_clean_logreader: the entry becomes all zeros (an end mark)
                lf!() = Localfile::default();
                return Ok(());
            }
        } else {
            return Err(ConfigError::new(messages::xml_invelem(el)));
        }
    }

    if lf!().target.is_none() {
        lf!().target = Some(Arc::new(vec!["agent".to_string()]));
    }

    let Some(logformat) = lf!().logformat.clone() else {
        return Err(ConfigError::new("(1901): Missing 'log_format' element."));
    };

    if lf!().file.is_none() {
        if logformat == MACOS {
            ctx.warn("(8006): Missing 'location' element when using 'macos' as 'log_format'. Default value will be used.");
            lf!().file = Some(MACOS.to_string());
        } else if logformat == JOURNALD_LOG {
            ctx.warn(format!(
                "(8016): Missing 'location' element when using '{JOURNALD_LOG}' as 'log_format'. Default value will be used."
            ));
            lf!().file = Some(JOURNALD_LOG.to_string());
        } else {
            lf!().file = Some(String::new());
            return Err(ConfigError::new("(1902): Missing 'location' element."));
        }
    }

    if logformat == JOURNALD_LOG {
        if lf!().journal_log.is_none() {
            lf!().journal_log = Some(JournalLogConfig::default());
        }
        let file = lf!().file.clone().unwrap_or_default();
        if file != JOURNALD_LOG {
            ctx.warn(format!(
                "(8017): Invalid location value '{file}' when using '{JOURNALD_LOG}' as 'log_format'. Default value will be used."
            ));
            lf!().file = Some(JOURNALD_LOG.to_string());
        }
        ignored_options(ctx, &lf!(), JOURNALD_LOG, true);
    } else if lf!().journal_log.is_some() {
        ctx.warn(format!("(8018): log_format '{logformat}' does not support filter option. Will be ignored."));
        lf!().journal_log = None;
    }

    if logformat == MACOS {
        let file = lf!().file.clone().unwrap_or_default();
        if file != MACOS {
            ctx.warn(format!(
                "(8005): Invalid location value '{file}' when using 'macos' as 'log_format'. Default value will be used."
            ));
            lf!().file = Some(MACOS.to_string());
        }
        ignored_options(ctx, &lf!(), MACOS, false);
    }

    if logformat == MULTI_LINE_REGEX {
        match &lf!().multiline {
            None => return Err(ConfigError::new("(1968): Missing 'multiline_regex' element.")),
            Some(m) => {
                if lf!().age != 0 && lf!().age <= m.timeout {
                    ctx.warn("(8002): 'age' cannot be less than 'timeout' in multiline_regex option. 'age' will be ignored.");
                    lf!().age = 0;
                    lf!().age_str = None;
                }
            }
        }
    } else if lf!().multiline.is_some() {
        ctx.warn(format!("(8001): log_format '{logformat}' does not support multiline_regex option. Will be ignored."));
        lf!().multiline = None;
    }

    if logformat == EVENTLOG {
        let f = lf!().file.clone().unwrap_or_default();
        if f != "Application" && f != "System" && f != "Security" {
            ctx.info(format!("(1907): Non-standard event log set: '{f}'."));
            return Ok(());
        }
    }

    if logformat == "command" || logformat == "full_command" {
        if lf!().command.is_none() {
            ctx.error("Missing 'command' argument. This option will be ignored.");
        }
        cfg.total_files += 1;
    } else {
        cfg.current_files += 1;
    }

    if lf!().command.is_none() {
        let file = lf!().file.clone().unwrap_or_default();
        // Windows: no '[' and no glob() test of the pattern
        let is_glob = file.contains('*') || file.contains('?') || (cfg!(unix) && file.contains('['));
        if is_glob {
            let mut created = false;
            #[cfg(unix)]
            let g = c_glob(&file).map(|_| ());
            #[cfg(windows)]
            let g: std::result::Result<(), ()> = Ok(());
            match g {
                Err(()) => ctx.error(format!("(1121): Glob error. Invalid pattern: '{file}'.")),
                Ok(_) => {
                    let mut tpl = lf!().shallow_copy();
                    // the template keeps the multiline configuration itself
                    tpl.multiline = lf!().multiline.take();
                    tpl.file = None;
                    cfg.globs.push(LocalfileGlob { gpath: file.clone(), exclude_path: None, num_files: 0, gfiles: vec![tpl] });
                    created = true;
                }
            }
            // Wildcard exclusion (date-expanded when it has '%'). Without a
            // new glob entry C writes it into the end-mark slot, where the
            // next <localfile> clears it.
            if let Some(ex) = lf!().exclude.clone() {
                let path = if ex.contains('%') { strftime_now(&ex, PATH_MAX) } else { Some(ex) };
                if let (Some(p), true) = (path, created) {
                    cfg.globs.last_mut().unwrap().exclude_path = Some(p);
                }
            }
            let mut cur = cfg.current_files;
            if remove_localfile(&mut cfg.config, pl, false, None, &mut cur) != 0 {
                cfg.current_files = cur;
                return Err(ConfigError::new(format!("(1956): Error removing '{file}' file.")));
            }
            cfg.current_files = cur;
            return Ok(());
        } else if file.contains('%') {
            if strftime_now(&file, OS_FLSIZE).is_some() {
                lf!().ffile = Some(file.clone());
            }
            // Wildcard exclusion: C stores it in the (unused) next glob slot
        }
    }

    if lf!().journal_log.is_some() && journald_merge_logged(ctx, cfg, pl) {
        ctx.info("Merge journald log configurations");
    }
    Ok(())
}

/// [`journald_merge`] with its warning logged in C order.
fn journald_merge_logged(ctx: &mut ConfigContext, cfg: &mut LogreaderConfig, src: usize) -> bool {
    // Pre-compute whether the merge disables the filters to log it first.
    let dst = (0..src.min(cfg.config.len()))
        .take_while(|&d| cfg.config[d].file.is_some())
        .find(|&d| cfg.config[d].journal_log.is_some());
    if src == 0 || dst.is_none() {
        return false;
    }
    let has = |i: usize| cfg.config[i].journal_log.as_ref().map(JournalLogConfig::has_filters).unwrap_or(false);
    if !has(src) && !has(dst.unwrap()) {
        ctx.warn("(8022): The filters of the journald log will be disabled in the merge, because one of the configuration does not have filters.");
    }
    journald_merge(cfg, src)
}

/// The `LOGCOLLECTOR_OPTION_IGNORED` checks for journald / macOS.
fn ignored_options(ctx: &mut ConfigContext, l: &Localfile, fmt: &str, journald: bool) {
    if l.reconnect_time != DEFAULT_EVENTCHANNEL_REC_TIME {
        ctx.warn(option_ignored(fmt, "reconnect_time"));
    }
    if l.age != 0 {
        ctx.warn(option_ignored(fmt, "age"));
    }
    if l.filter_binary != 0 {
        ctx.warn(option_ignored(fmt, "ignore_binaries"));
    }
    if l.exclude.is_some() {
        ctx.warn(option_ignored(fmt, "exclude"));
    }
    if l.multiline.is_some() {
        ctx.warn(option_ignored(fmt, "multiline_regex"));
    }
    if l.labels.is_some() {
        ctx.warn(option_ignored(fmt, "label"));
    }
    if l.ign != DEFAULT_FREQUENCY_SECS {
        ctx.warn(option_ignored(fmt, "frequency"));
    }
    if l.alias.is_some() {
        ctx.warn(option_ignored(fmt, "alias"));
    }
    if journald {
        if l.regex_ignore.is_some() {
            ctx.warn(option_ignored(fmt, "ignore"));
        }
        if l.regex_restrict.is_some() {
            ctx.warn(option_ignored(fmt, "restrict"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::*;
    use crate::{read_config_xml, ConfigHandler, Platform, Section};
    use siem_xml::OsXml;

    struct H<'a>(&'a mut LogreaderConfig);
    impl ConfigHandler for H<'_> {
        fn section(
            &mut self,
            ctx: &mut ConfigContext,
            _xml: &OsXml,
            s: Section,
            _node: &XmlNode,
            ch: Option<&[XmlNode]>,
        ) -> Result<()> {
            match s {
                Section::Localfile => read_localfile(ctx, ch.unwrap_or(&[]), self.0),
                Section::LogcollectorSocket => crate::socket::read_socket(ch.unwrap_or(&[]), &mut self.0.socket_list),
                _ => Ok(()),
            }
        }
    }

    fn parse(x: &str) -> (Result<()>, LogreaderConfig, ConfigContext) {
        let xml = OsXml::read_string(x, false).unwrap();
        let mut c = LogreaderConfig { maximum_files: 1000, ..Default::default() };
        let mut ctx = ConfigContext::new(Platform::LINUX_AGENT);
        let r = read_config_xml(&mut ctx, CLOCALFILE | CLGCSOCKET, &xml, "ossec.conf", &mut H(&mut c));
        (r, c, ctx)
    }

    #[test]
    fn basic_entries() {
        let (r, c, _) = parse(
            "<ossec_config><localfile><location>/var/log/syslog</location><log_format>syslog</log_format>\
             <only-future-events max-size=\"5M\">no</only-future-events><age>2h</age></localfile>\
             <localfile><command>df -P</command><log_format>command</log_format><frequency>30</frequency></localfile>\
             <localfile><location>/tmp/x/*.log</location><log_format>json</log_format><exclude>/tmp/x/a.log</exclude></localfile>\
             </ossec_config>",
        );
        r.unwrap();
        assert_eq!(c.config.len(), 2);
        assert_eq!(c.config[0].diff_max_size, 5 * 1024 * 1024);
        assert_eq!(c.config[0].future, 0);
        assert_eq!(c.config[0].age, 7200);
        assert_eq!(c.config[1].command.as_deref(), Some("df -P"));
        assert_eq!(c.config[1].ign, 30);
        assert_eq!(c.globs.len(), 1);
        assert_eq!(c.globs[0].exclude_path.as_deref(), Some("/tmp/x/a.log"));
        assert!(c.globs[0].gfiles[0].file.is_none());
        assert_eq!((c.current_files, c.total_files), (1, 1));
    }

    #[test]
    fn errors_and_warnings() {
        let (r, _, ctx) = parse("<ossec_config><localfile><location>/a</location></localfile></ossec_config>");
        assert!(r.is_err());
        assert_eq!(ctx.log[0].1, "(1901): Missing 'log_format' element.");
        let (r, c, ctx) = parse(
            "<ossec_config><localfile><location>/a</location><log_format>syslog</log_format>\
             <multiline_regex>^x</multiline_regex></localfile></ossec_config>",
        );
        r.unwrap();
        assert!(c.config[0].multiline.is_none());
        assert!(ctx.warnings[0].starts_with("(8001)"));
        assert_eq!(strtoul0("010"), (8, ""));
        assert_eq!(strtoul0("0x10m"), (16, "m"));
        assert_eq!(w_validate_bytes("2k"), 2048);
    }
}
