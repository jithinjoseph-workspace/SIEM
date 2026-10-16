//! Rootcheck as the Windows agent runs it inside the syscheck thread:
//! `rootcheck/rootcheck.c` (`rootcheck_init`, `check_ignore`),
//! `config/rootcheck-config.c` + `rootcheck/config.c` (the reader,
//! `getRootcheckConfig`), `run_rk_check.c` (scan + `w_rootcheck_thread`),
//! `common.c`, `common_rcl.c` (the `win_*_rcl.txt` policies),
//! `check_rc_files.c`, `check_rc_trojans.c`, `check_rc_sys.c` (Windows part),
//! `win-common.c` (ADS, registry) and `win-process.c` (via siem-sca).
//!
//! On Windows `check_rc_dev`, `check_rc_pids`, `check_rc_ports`, `check_rc_if`
//! and `check_open_ports` compile to empty functions; `os_string` returns 0.

use std::sync::atomic::{AtomicBool, Ordering};

use siem_cjson::Json;
use siem_config::{messages, ConfigContext, ConfigError, ConfigHandler, Result as CResult, Section};
use siem_regex::OsMatch;
use siem_xml::{OsXml, XmlNode};

use super::cfmt::{cfmt, A};

/// `ARGV0` of the rootcheck objects (`-DARGV0="rootcheck"`).
const TAG: &str = "rootcheck";
const RK_CONF_UNPARSED: i32 = -2;
const RK_CONF_UNDEFINED: i32 = -1;
const ROOTCHECK_WAIT: i32 = 43200;
const MAX_RK_SYS: usize = 512;
const ROOTCHECK_MQ: u8 = b'9';
const ALERT_SYSTEM_ERR: i32 = 1;
const ALERT_ROOTKIT_FOUND: i32 = 3;
const ALERT_POLICY_VIOLATION: i32 = 4;
const OS_SIZE_1024: usize = 1024;
const PATH_MAX: usize = 260;

/// `os_restart.rootcheck` (set by the syscom `restart`).
pub static RESTART_ROOTCHECK: AtomicBool = AtomicBool::new(false);

/// `rkconfig` (Windows fields)
#[derive(Debug)]
pub struct RkConfig {
    pub basedir: Option<String>,
    pub rootkit_files: Option<String>,
    pub rootkit_trojans: Option<String>,
    /// `ignore` + `ignore_sregex` (the regex when `type="sregex"`)
    pub ignore: Vec<(String, Option<OsMatch>)>,
    pub winaudit: Option<String>,
    pub winmalware: Option<String>,
    pub winapps: Option<String>,
    pub scanall: i32,
    pub readall: i32,
    pub disabled: i32,
    pub skip_nfs: i32,
    pub tsleep: i32,
    pub time: i32,
    pub rc_dev: i32,
    pub rc_files: i32,
    pub rc_if: i32,
    pub rc_pids: i32,
    pub rc_ports: i32,
    pub rc_sys: i32,
    pub rc_trojans: i32,
    pub rc_winaudit: i32,
    pub rc_winmalware: i32,
    pub rc_winapps: i32,
}

impl Default for RkConfig {
    /// The defaults set by `rootcheck_init`.
    fn default() -> Self {
        RkConfig {
            basedir: None,
            rootkit_files: None,
            rootkit_trojans: None,
            ignore: Vec::new(),
            winaudit: None,
            winmalware: None,
            winapps: None,
            scanall: 0,
            readall: 0,
            disabled: RK_CONF_UNPARSED,
            skip_nfs: 0,
            tsleep: 0,
            time: ROOTCHECK_WAIT,
            rc_dev: 1,
            rc_files: 0,
            rc_if: 1,
            rc_pids: 1,
            rc_ports: 1,
            rc_sys: 1,
            rc_trojans: 0,
            rc_winaudit: 0,
            rc_winmalware: 0,
            rc_winapps: 0,
        }
    }
}

fn log() -> Option<&'static std::sync::Arc<siem_log::WLog>> {
    super::log()
}

/// `mt*(ARGV0, ...)`
fn mt(level: &str, m: impl AsRef<[u8]>) {
    if let Some(l) = log() {
        l.tagged(TAG, level, m);
    }
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

// ───────────────────────── configuration ─────────────────────────

/// `eval_bool`
fn eval_bool(v: &str) -> Option<i32> {
    match v {
        "yes" => Some(1),
        "no" => Some(0),
        _ => None,
    }
}

/// `Read_Rootcheck`
pub fn read_rootcheck(ctx: &mut ConfigContext, nodes: Option<&[XmlNode]>, rk: &mut RkConfig) -> CResult<()> {
    if rk.disabled == RK_CONF_UNPARSED {
        rk.disabled = RK_CONF_UNDEFINED;
    }
    let Some(nodes) = nodes else { return Ok(()) };
    let fail = |ctx: &mut ConfigContext, m: String| -> CResult<()> {
        ctx.warn(m);
        Err(ConfigError::new(""))
    };
    for n in nodes {
        let Some(v) = n.content.as_deref() else { return fail(ctx, messages::xml_valuenull(&n.element)) };
        let el = n.element.as_str();
        let flag = |ctx: &mut ConfigContext| -> CResult<i32> {
            match eval_bool(v) {
                Some(b) => Ok(b),
                None => {
                    ctx.warn(messages::xml_valueerr(el, v));
                    Err(ConfigError::new(""))
                }
            }
        };
        match el {
            "frequency" => {
                if !siem_config::util::str_is_num(v) {
                    return fail(ctx, messages::xml_valueerr(el, v));
                }
                rk.time = siem_sca::crt::atoi(v.as_bytes());
            }
            "scanall" => rk.scanall = flag(ctx)?,
            "disabled" => rk.disabled = flag(ctx)?,
            "skip_nfs" => rk.skip_nfs = flag(ctx)?,
            "readall" => rk.readall = flag(ctx)?,
            "rootkit_files" => rk.rootkit_files = Some(v.to_string()),
            "rootkit_trojans" => rk.rootkit_trojans = Some(v.to_string()),
            "windows_audit" => {
                rk.rc_winaudit = 1;
                rk.winaudit = Some(v.to_string());
            }
            // the Windows agent keeps the paths but does not run system audits
            "system_audit" => {}
            "ignore" => {
                let mut re = None;
                if let (Some(a), Some(val)) = (n.attributes.first(), n.values.first()) {
                    if a != "type" {
                        return fail(ctx, format!("Invalid attribute for '{el}': '{a}'."));
                    } else if val != "sregex" {
                        return fail(ctx, format!("Invalid value for '{a}': '{val}'."));
                    }
                    match OsMatch::compile(v, siem_regex::OS_CASE_SENSITIVE) {
                        Ok(m) => re = Some(m),
                        Err(e) => {
                            ctx.error(format!("(1450): Syntax error on regex: '{v}': {}.", e as i32));
                            return Err(ConfigError::new(""));
                        }
                    }
                }
                rk.ignore.push((v.to_string(), re));
            }
            "windows_malware" => {
                rk.rc_winmalware = 1;
                rk.winmalware = Some(v.to_string());
            }
            "windows_apps" => {
                rk.rc_winapps = 1;
                rk.winapps = Some(v.to_string());
            }
            "base_directory" => rk.basedir = Some(v.to_string()),
            "check_dev" => rk.rc_dev = flag(ctx)?,
            "check_files" => rk.rc_files = flag(ctx)?,
            "check_if" => rk.rc_if = flag(ctx)?,
            "check_pids" => rk.rc_pids = flag(ctx)?,
            "check_ports" => rk.rc_ports = flag(ctx)?,
            "check_sys" => rk.rc_sys = flag(ctx)?,
            "check_trojans" => rk.rc_trojans = flag(ctx)?,
            // Unix only: accepted, not evaluated
            "check_unixaudit" => {}
            "check_winapps" => rk.rc_winapps = flag(ctx)?,
            "check_winaudit" => rk.rc_winaudit = flag(ctx)?,
            "check_winmalware" => rk.rc_winmalware = flag(ctx)?,
            _ => return fail(ctx, messages::xml_invelem(el)),
        }
    }
    Ok(())
}

struct Handler<'a>(&'a mut RkConfig);

impl ConfigHandler for Handler<'_> {
    fn section(&mut self, ctx: &mut ConfigContext, _xml: &OsXml, section: Section, _node: &XmlNode, children: Option<&[XmlNode]>) -> CResult<()> {
        if section == Section::Rootcheck {
            read_rootcheck(ctx, children, self.0)?;
        }
        Ok(())
    }
}

/// `Test_Rootcheck`: the `<rootcheck>` reader into a throw-away configuration.
#[derive(Default)]
pub struct RootcheckTest(pub RkConfig);

impl ConfigHandler for RootcheckTest {
    fn section(&mut self, ctx: &mut ConfigContext, xml: &OsXml, section: Section, node: &XmlNode, children: Option<&[XmlNode]>) -> CResult<()> {
        Handler(&mut self.0).section(ctx, xml, section, node, children)
    }
}

/// `Read_Rootcheck_Config`: false on a configuration error.
fn read_rootcheck_config(env: &super::syscheck::Env, rk: &mut RkConfig) -> bool {
    use siem_config::modules::{CAGENT_CONFIG, CROOTCHECK};
    use super::syscheck::{AGENTCONFIG, OSSECCONF};
    let mut ctx = ConfigContext::new(env.platform);
    ctx.agent = env.agent.clone();
    let r = siem_config::read_config(&mut ctx, CROOTCHECK, OSSECCONF, None, &mut Handler(rk));
    (env.flush)(&mut ctx);
    if r.is_err() {
        return false;
    }
    let mut ctx = ConfigContext::new(env.platform);
    ctx.agent = env.agent.clone();
    let _ = siem_config::read_config(&mut ctx, CROOTCHECK | CAGENT_CONFIG, AGENTCONFIG, Some(env.remote_conf), &mut Handler(rk));
    (env.flush)(&mut ctx);
    match rk.disabled {
        RK_CONF_UNPARSED => rk.disabled = 1,
        RK_CONF_UNDEFINED => rk.disabled = 0,
        _ => {}
    }
    true
}

/// `rootcheck_init(0)`: (configuration, 0 = run it).
pub fn rootcheck_init(env: &super::syscheck::Env) -> (RkConfig, i32) {
    use super::syscheck::OSSECCONF;
    let mut rk = RkConfig::default();
    if std::fs::metadata(OSSECCONF).is_err() {
        mt("ERROR", format!("Configuration file '{OSSECCONF}' not found"));
        return (rk, -1);
    }
    if !read_rootcheck_config(env, &mut rk) {
        env.log.warn(format!("(1207): {TAG} remote configuration in '{OSSECCONF}' is corrupted."));
        return (rk, 1);
    }
    if rk.rc_winaudit != 0 {
        env.log.warn("The check_winaudit option is deprecated in favor of the SCA module.");
    }
    rk.tsleep = (env.define_int)("rootcheck", "sleep", 0, 1000);
    if rk.disabled == 1 {
        mt("INFO", "Rootcheck disabled.");
        return (rk, 1);
    }
    mt("INFO", format!("Started (pid: {}).", std::process::id()));
    (rk, 0)
}

/// `getRootcheckConfig`
pub fn get_rootcheck_config(rk: &RkConfig) -> Json {
    let yn = |b: i32| if b != 0 { "yes" } else { "no" };
    let mut r = Json::object();
    r.add("disabled", Json::string(yn(rk.disabled)));
    if let Some(v) = &rk.basedir {
        r.add("base_directory", Json::string(v));
    }
    if let Some(v) = &rk.rootkit_files {
        r.add("rootkit_files", Json::string(v));
    }
    if let Some(v) = &rk.rootkit_trojans {
        r.add("rootkit_trojans", Json::string(v));
    }
    r.add("scanall", Json::string(yn(rk.scanall)));
    r.add("skip_nfs", Json::string(yn(rk.skip_nfs)));
    r.add("frequency", Json::number(rk.time as f64));
    for (k, v) in [("check_dev", rk.rc_dev), ("check_files", rk.rc_files), ("check_if", rk.rc_if), ("check_pids", rk.rc_pids), ("check_ports", rk.rc_ports), ("check_sys", rk.rc_sys), ("check_trojans", rk.rc_trojans)] {
        r.add(k, Json::string(yn(v)));
    }
    r.add("check_winaudit", Json::string(yn(rk.rc_winaudit)));
    r.add("check_winmalware", Json::string(yn(rk.rc_winmalware)));
    r.add("check_winapps", Json::string(yn(rk.rc_winapps)));
    for (k, v) in [("windows_apps", &rk.winapps), ("windows_malware", &rk.winmalware), ("windows_audit", &rk.winaudit)] {
        if let Some(v) = v {
            r.add(k, Json::string(v));
        }
    }
    if !rk.ignore.is_empty() {
        let (mut igns, mut regs) = (Json::array(), Json::array());
        for (p, re) in &rk.ignore {
            match re {
                Some(m) => regs.push(Json::string(m.raw())),
                None => igns.push(Json::string(p)),
            };
        }
        if igns.len() > 0 {
            r.add("ignore", igns);
        }
        if regs.len() > 0 {
            r.add("ignore_sregex", regs);
        }
    }
    let mut root = Json::object();
    root.add("rootcheck", r);
    root
}

// ───────────────────────── the scan ─────────────────────────

/// The scan state (`rootcheck.alert_msg`, `rk_sys_file` / `rk_sys_name`, the sys counters).
pub struct Scan<'a> {
    rk: &'a RkConfig,
    alert_msg: Vec<Vec<u8>>,
    rk_sys: Vec<(Vec<u8>, Vec<u8>)>,
    sys_errors: i32,
    sys_total: i32,
}

/// `notify_rk` (queue mode): only problems go to the manager.
fn notify_rk(rk_type: i32, msg: &[u8]) {
    if rk_type <= ALERT_SYSTEM_ERR {
        return;
    }
    if siem_ipc::mq_op::send_msg(0, msg, TAG, ROOTCHECK_MQ) < 0 {
        mt("DEBUG", "(1224): Error sending message to queue.");
        if siem_ipc::mq_op::send_msg(0, msg, TAG, ROOTCHECK_MQ) < 0 {
            mt("CRITICAL", "(1211): Unable to access queue: 'queue/sockets/queue'. Giving up.");
            siem_log::cexit::fatal_exit();
        }
    }
}

/// `snprintf(buf, OS_SIZE_1024, ...)`: at most 1023 bytes.
fn cap(mut b: Vec<u8>, size: usize) -> Vec<u8> {
    b.truncate(size - 1);
    b
}

/// `wfopen(path, "r")` + `fgets(buf, size)` pieces (text mode).
fn fgets_all(path: &[u8], size: usize) -> Option<Vec<Vec<u8>>> {
    let p = s(path);
    if siem_fileop::crt::is_network_path(&p) {
        if let Some(l) = log() {
            l.warn(siem_fileop::crt::network_path_executed(&p));
        }
        return None;
    }
    let data = siem_fileop::crt::read_text(super::win::auto_to_wide(path).map(|mut w| {
        w.pop();
        <std::ffi::OsString as std::os::windows::ffi::OsStringExt>::from_wide(&w)
    })?)
    .ok()?;
    let mut out = Vec::new();
    let mut rest: &[u8] = &data;
    while !rest.is_empty() {
        let lim = rest.len().min(size - 1);
        let end = rest[..lim].iter().position(|&c| c == b'\n').map(|i| i + 1).unwrap_or(lim);
        out.push(rest[..end].to_vec());
        rest = &rest[end..];
    }
    Some(out)
}

/// `ExpandEnvironmentStrings(src, dst, n)` (ANSI)
fn expand_env(src: &[u8], n: usize) -> Vec<u8> {
    use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsA;
    let c = siem_sca::crt::cstring(src);
    let mut buf = vec![0u8; n + 1];
    // SAFETY: a NUL-terminated source and a buffer of n bytes.
    let r = unsafe { ExpandEnvironmentStringsA(c.as_ptr() as *const u8, buf.as_mut_ptr(), n as u32) };
    if r == 0 || r as usize > n {
        return Vec::new();
    }
    buf.truncate(buf.iter().position(|&b| b == 0).unwrap_or(buf.len()));
    buf
}

/// `strncasecmp(a, b, n) == 0` / `strcasecmp`
fn eq_ic(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// `pt_check_negate`
fn pt_check_negate(pattern: &[u8]) -> bool {
    let all = split_and(pattern).iter().all(|p| p.first() == Some(&b'!'));
    if all {
        mt("DEBUG2", cfmt("Pattern: %s is fill_negate", &[A::B(pattern)]));
    }
    all
}

/// The minterms of `a && b && c` (split on the first `" && "` after each space, as `strchr(' ')` does).
fn split_and(pattern: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut cur = pattern;
    loop {
        match cur.iter().position(|&c| c == b' ') {
            Some(i) if cur.get(i + 1..i + 4) == Some(b"&& ") => {
                out.push(&cur[..i]);
                cur = &cur[i + 4..];
            }
            _ => {
                out.push(cur);
                return out;
            }
        }
    }
}

/// `pt_matches`
pub fn pt_matches(text: &[u8], pattern: &[u8]) -> bool {
    let mut ret = false;
    for term in split_and(pattern) {
        let (neg, p) = match term.first() {
            Some(b'!') => (true, &term[1..]),
            _ => (false, term),
        };
        let pre = p.get(..2).map(|x| x.to_ascii_lowercase());
        ret = match pre.as_deref() {
            Some(b"=:") => eq_ic(&p[2..], text),
            Some(b"r:") => {
                let m = siem_regex::os_regex(&s(&p[2..]), &s(text));
                if m {
                    mt("DEBUG2", cfmt("Pattern: %s matches %s.", &[A::B(&p[2..]), A::B(text)]));
                }
                m
            }
            Some(b"<:") => p[2..] < *text,
            Some(b">:") => p[2..] > *text,
            _ => {
                let lit = if p.first() == Some(&b'%') { expand_env(p, 2047) } else { p[..p.len().min(2047)].to_vec() };
                eq_ic(&lit, text)
            }
        };
        if neg {
            if ret {
                return false;
            }
        } else if !ret {
            return false;
        }
        ret = true;
    }
    ret
}

/// `is_file`: a directory, a file `stat` sees, or one that opens.
fn is_file(path: &[u8]) -> bool {
    siem_sca::crt::stat_mode(path).is_ok() || siem_sca::crt::read_dir(path).is_ok() || fgets_all(path, 2).is_some()
}

impl<'a> Scan<'a> {
    pub fn new(rk: &'a RkConfig) -> Scan<'a> {
        Scan { rk, alert_msg: Vec::new(), rk_sys: Vec::new(), sys_errors: 0, sys_total: 0 }
    }

    /// Adds `" File: x."` / `" Process: x."` to the alert details (256 slots, no duplicates).
    fn add_msg(&mut self, m: Vec<u8>) {
        let m = cap(m, OS_SIZE_1024 + 1);
        if !self.alert_msg.contains(&m) && self.alert_msg.len() < 256 {
            self.alert_msg.push(m);
        }
    }

    /// `check_ignore`
    fn check_ignore(&self, path: &[u8]) -> bool {
        for (p, re) in &self.rk.ignore {
            match re {
                Some(m) => {
                    if m.is_match_bytes(path) {
                        if let Some(l) = log() {
                            l.debug1(cfmt("'%s' matches the '%s' pattern, so it will be ignored.", &[A::B(path), A::S(m.raw())]));
                        }
                        return true;
                    }
                }
                None => {
                    if eq_ic(path, p.as_bytes()) {
                        if let Some(l) = log() {
                            l.debug1(cfmt("'%s' has been marked as ignored.", &[A::B(path)]));
                        }
                        return true;
                    }
                }
            }
        }
        false
    }

    /// `rk_check_file`: `file` is cut at its first comma, as the C string is.
    fn rk_check_file(&mut self, file: &mut Vec<u8>, pattern: Option<&[u8]>) -> bool {
        let orig = file.clone();
        let mut rest: Option<usize> = orig.iter().position(|&c| c == b',').map(|i| {
            file.truncate(i);
            i + 1
        });
        let mut cur: Vec<u8> = file.clone();
        loop {
            match pattern {
                None => {
                    if is_file(&cur) {
                        self.add_msg(cfmt(" File: %s.", &[A::B(&cur)]));
                        return true;
                    }
                }
                Some(pattern) => {
                    let mut full_negate = pt_check_negate(pattern);
                    mt("DEBUG2", cfmt("Checking file: %s", &[A::B(&cur)]));
                    if let Some(lines) = fgets_all(&cur, 2048 + 1) {
                        mt("DEBUG2", cfmt("Starting new file: %s", &[A::B(&cur)]));
                        for mut buf in lines {
                            if let Some(i) = buf.iter().position(|&c| c == b'\n') {
                                buf.truncate(i);
                            }
                            if let Some(i) = buf.iter().position(|&c| c == b'\r') {
                                buf.truncate(i);
                            }
                            let r = pt_matches(&buf, pattern);
                            mt("DEBUG2", cfmt("Buf == \"%s\"", &[A::B(&buf)]));
                            mt("DEBUG2", cfmt("Pattern == \"%s\"", &[A::B(pattern)]));
                            mt("DEBUG2", cfmt("pt_result == %d and full_negate == %d", &[A::I(r as i64), A::I(full_negate as i64)]));
                            if r && !full_negate {
                                mt("DEBUG", cfmt("Alerting file %s on line %s", &[A::B(&cur), A::B(&buf)]));
                                self.add_msg(cfmt(" File: %s.", &[A::B(&cur)]));
                                return true;
                            } else if !r && full_negate {
                                mt("DEBUG2", "Found a complete match for full_negate");
                                full_negate = false;
                                break;
                            }
                        }
                        if full_negate {
                            mt("DEBUG2", cfmt("Full_negate alerting - file %s", &[A::B(&cur)]));
                            self.add_msg(cfmt(" File: %s.", &[A::B(&cur)]));
                            return true;
                        }
                    }
                }
            }
            // the C keeps the rest of the list (with its commas) as the next file, and
            // stops when no comma follows: the last entry is never checked
            match rest {
                Some(i) => {
                    cur = orig[i..].to_vec();
                    rest = orig[i..].iter().position(|&c| c == b',').map(|j| i + j + 1);
                    if rest.is_none() {
                        return false;
                    }
                }
                None => return false,
            }
        }
    }

    /// `rk_check_dir`
    fn rk_check_dir(&mut self, dir: &[u8], file: &[u8], pattern: Option<&[u8]>) -> bool {
        let Ok(names) = siem_sca::crt::read_dir(dir) else { return false };
        let mut ret = false;
        for name in names {
            if name == b"." || name == b".." {
                continue;
            }
            let mut f_name = cap([dir, b"/", &name].concat(), PATH_MAX + 1);
            let hit = if file.len() >= 2 && eq_ic(&file[..2], b"r:") {
                siem_regex::os_regex(&s(&file[2..]), &s(&name))
            } else {
                siem_regex::os_match2(&s(file), &s(&name))
            };
            if hit && self.rk_check_file(&mut f_name, pattern) {
                ret = true;
            }
            if siem_sca::crt::stat_mode(&f_name).map(|m| m & siem_sca::crt::S_IFMT == siem_sca::crt::S_IFDIR).unwrap_or(false) && self.rk_check_dir(&f_name, file, pattern) {
                ret = true;
            }
        }
        ret
    }

    /// `is_process`
    fn is_process(&mut self, value: &[u8], plist: Option<&[Vec<u8>]>) -> bool {
        let Some(plist) = plist else { return false };
        for p in plist {
            if pt_matches(p, value) {
                self.add_msg(cfmt(" Process: %s.", &[A::B(p)]));
                return true;
            }
        }
        false
    }

    /// `rkcl_get_entry`: one policy file.
    fn rkcl_get_entry(&mut self, lines: Vec<Vec<u8>>, msg: &str, plist: Option<&[Vec<u8>]>) {
        let root_dir = {
            let w = expand_env(b"%WINDIR%", 2047);
            match w.iter().position(|&c| c == b'\\') {
                Some(i) => w[..i].to_vec(),
                None => Vec::new(),
            }
        };
        if root_dir.is_empty() {
            mt("ERROR", "(1253): Invalid rootdir (unable to retrieve).");
        }
        // _rkcl_getfp: the next non-empty, non-comment line (without its newline)
        let mut it = lines.into_iter();
        let mut getfp = move || -> Option<Vec<u8>> {
            for mut b in it.by_ref() {
                if let Some(i) = b.iter().position(|&c| c == b'\n') {
                    b.truncate(i);
                }
                let start = b.iter().position(|&c| c != b' ' && c != b'\t').unwrap_or(b.len());
                let n = b[start..].to_vec();
                if n.is_empty() || n[0] == b'#' {
                    continue;
                }
                return Some(n);
            }
            None
        };
        let mut vars: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let get_var = |vars: &[(Vec<u8>, Vec<u8>)], k: &[u8]| vars.iter().position(|(n, _)| n == k);
        let mut nbuf;
        loop {
            let Some(b) = getfp() else { return };
            nbuf = b;
            if nbuf[0] != b'$' {
                break;
            }
            // _rkcl_get_vars: "$name=value;"
            let Some(semi) = nbuf.iter().position(|&c| c == b';') else {
                mt("ERROR", cfmt("(1254): Invalid rk variable: '%s'.", &[A::B(&nbuf)]));
                return;
            };
            let body = &nbuf[..semi];
            let Some(eq) = body.iter().position(|&c| c == b'=') else {
                mt("ERROR", cfmt("(1254): Invalid rk variable: '%s'.", &[A::B(body)]));
                return;
            };
            let (k, v) = (body[..eq].to_vec(), body[eq + 1..].to_vec());
            match get_var(&vars, &k) {
                Some(i) => vars[i].1 = v,
                None => vars.push((k, v)),
            }
        }
        let mut refb: Vec<u8> = Vec::new();
        let (mut name, mut condition) = match get_name(&nbuf, &mut refb) {
            Some(v) => v,
            None => {
                mt("ERROR", cfmt("(1251): Invalid rk configuration name: '%s'.", &[A::B(&nbuf)]));
                return;
            }
        };
        loop {
            let (mut g_found, mut not_found) = (0i32, 0i32);
            let mut typ = 0;
            let mut next: Option<Vec<u8>>;
            mt("DEBUG2", cfmt("Checking entry: '%s'.", &[A::B(&name)]));
            loop {
                next = getfp();
                let Some(line) = next.clone() else { break };
                if is_name(&line) {
                    break;
                }
                // _rkcl_get_value: "type:value;"
                let Some((t, mut value)) = get_value(&line) else {
                    mt("ERROR", cfmt("(1252): Invalid rk configuration value: '%s'.", &[A::B(&line)]));
                    return;
                };
                typ = t;
                let negate = value.first() == Some(&b'!');
                if negate {
                    value.remove(0);
                }
                let mut found = false;
                let mut skipped = false;
                match typ {
                    RKCL_TYPE_FILE => {
                        let (v, pattern) = get_pattern(&value);
                        let mut f_value = if v.first() == Some(&b'$') {
                            match get_var(&vars, v) {
                                Some(i) => {
                                    // rk_check_file cuts the variable's own string at its first comma
                                    let mut fv = vars[i].1.clone();
                                    mt("DEBUG2", cfmt("Checking file: '%s'.", &[A::B(&fv)]));
                                    found = self.rk_check_file(&mut fv, pattern);
                                    vars[i].1 = fv;
                                    if found {
                                        mt("DEBUG2", "Found file.");
                                    }
                                    None
                                }
                                None => {
                                    mt("ERROR", cfmt("(1254): Invalid rk variable: '%s'.", &[A::B(v)]));
                                    skipped = true;
                                    None
                                }
                            }
                        } else if v.first() == Some(&b'\\') {
                            Some(cap([&root_dir[..], v].concat(), 2048 - 1))
                        } else {
                            Some(expand_env(v, 2048 - 2))
                        };
                        if let Some(fv) = f_value.as_mut() {
                            mt("DEBUG2", cfmt("Checking file: '%s'.", &[A::B(fv)]));
                            if self.rk_check_file(fv, pattern) {
                                mt("DEBUG2", "Found file.");
                                found = true;
                            }
                        }
                    }
                    RKCL_TYPE_REGISTRY => {
                        let (v, entry) = get_pattern(&value);
                        let (entry, pattern) = match entry {
                            Some(e) => {
                                let (e2, p) = get_pattern(e);
                                (Some(e2), p)
                            }
                            None => (None, None),
                        };
                        mt("DEBUG2", cfmt("Checking registry: '%s'.", &[A::B(v)]));
                        if is_registry(v, entry, pattern) {
                            mt("DEBUG2", "Found registry.");
                            found = true;
                        }
                    }
                    RKCL_TYPE_DIR => {
                        let (v, file) = get_pattern(&value);
                        match file {
                            None => {
                                mt("ERROR", cfmt("(1254): Invalid rk variable: '%s'.", &[A::B(v)]));
                                skipped = true;
                            }
                            Some(file) => {
                                let (file, pattern) = get_pattern(file);
                                let dirs: Option<Vec<u8>> = if v.first() == Some(&b'$') {
                                    match get_var(&vars, v) {
                                        Some(i) => Some(vars[i].1.clone()),
                                        None => {
                                            mt("ERROR", cfmt("(1254): Invalid rk variable: '%s'.", &[A::B(v)]));
                                            skipped = true;
                                            None
                                        }
                                    }
                                } else {
                                    Some(v.to_vec())
                                };
                                for dir in dirs.iter().flat_map(|d| d.split(|&c| c == b',')) {
                                    mt("DEBUG2", cfmt("Checking dir: %s", &[A::B(dir)]));
                                    // IsNFS on Windows
                                    if let Some(l) = log() {
                                        l.debug2(cfmt("Attempted to check NFS status for '%s', but we don't know how on this OS.", &[A::B(dir)]));
                                    }
                                    mt("DEBUG2", cfmt("%s => is_nfs=%d, skip_nfs=%d", &[A::B(dir), A::I(0), A::I(self.rk.skip_nfs as i64)]));
                                    if self.rk_check_dir(dir, file, pattern) {
                                        mt("DEBUG2", "Found dir.");
                                        found = true;
                                    }
                                }
                            }
                        }
                    }
                    RKCL_TYPE_PROCESS => {
                        mt("DEBUG2", cfmt("Checking process: '%s'.", &[A::B(&value)]));
                        if self.is_process(&value, plist) {
                            mt("DEBUG2", "Found process.");
                            found = true;
                        }
                    }
                    _ => {}
                }
                // `continue` in the C skips the condition update
                if skipped {
                    continue;
                }
                if negate {
                    found = !found;
                }
                if condition & RKCL_COND_ANY != 0 {
                    mt("DEBUG2", "Condition ANY.");
                    if found {
                        g_found = 1;
                    }
                } else if condition & RKCL_COND_NON != 0 {
                    mt("DEBUG2", "Condition NON.");
                    if !found && not_found != -1 {
                        mt("DEBUG2", "Condition NON setze not_found=1.");
                        not_found = 1;
                    } else {
                        not_found = -1;
                    }
                } else {
                    mt("DEBUG2", "Condition ALL.");
                    if found && g_found != -1 {
                        g_found = 1;
                    } else {
                        g_found = -1;
                    }
                }
            }
            if condition & RKCL_COND_NON != 0 {
                g_found = if not_found == -1 { 0 } else { 1 };
            }
            if g_found == 1 {
                let msgs = std::mem::take(&mut self.alert_msg);
                let mut j = 0;
                loop {
                    let detail: &[u8] = msgs.get(j).map(|v| v.as_slice()).unwrap_or(b"");
                    let op = if !refb.is_empty() {
                        cfmt("%s %s.%s Reference: %s .", &[A::S(msg), A::B(&name), A::B(detail), A::B(&refb)])
                    } else {
                        cfmt("%s %s.%s", &[A::S(msg), A::B(&name), A::B(detail)])
                    };
                    if typ == RKCL_TYPE_DIR || j == 0 {
                        notify_rk(ALERT_POLICY_VIOLATION, &cap(op, OS_SIZE_1024 + 1));
                    }
                    if j < msgs.len() {
                        j += 1;
                        if j >= msgs.len() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            } else {
                self.alert_msg.clear();
                if condition & RKCL_COND_REQ != 0 {
                    return;
                }
            }
            let Some(line) = next else { return };
            match get_name(&line, &mut refb) {
                Some((n, c)) => {
                    name = n;
                    condition = c;
                }
                None => {
                    mt("ERROR", cfmt("(1251): Invalid rk configuration name: '%s'.", &[A::B(&line)]));
                    return;
                }
            }
        }
    }

    /// `check_rc_files`
    fn check_rc_files(&mut self, basedir: &[u8], lines: Vec<Vec<u8>>) {
        mt("DEBUG", "Starting on check_rc_files");
        for buf in lines {
            let mut b = buf;
            if let Some(i) = b.iter().position(|&c| c == b'\n') {
                b.truncate(i);
            }
            let mut k = 0;
            while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
                k += 1;
            }
            if k >= b.len() || b[k] == b'#' {
                continue;
            }
            // the file, up to the first space or tab
            let fstart = k;
            while k < b.len() && b[k] != b' ' && b[k] != b'\t' {
                k += 1;
            }
            if k >= b.len() {
                continue;
            }
            let file = b[fstart..k].to_vec();
            k += 1;
            // spaces, then "! " and the rootkit name
            let mut name: Vec<u8> = file.clone();
            let mut ok = false;
            while k < b.len() {
                if b[k] == b'!' {
                    k += 1;
                    if k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
                        k += 1;
                        ok = true;
                        break;
                    }
                } else if b[k] == b' ' || b[k] == b'\t' {
                    k += 1;
                } else {
                    break;
                }
            }
            if !ok && k < b.len() {
                continue;
            }
            if ok {
                let mut n = b[k..].to_vec();
                // the link (after ':'), then the name ends at a space
                if let Some(i) = n.iter().position(|&c| c == b':') {
                    n.truncate(i);
                }
                if let Some(i) = n.iter().position(|&c| c == b' ') {
                    n.truncate(i);
                }
                name = n;
            }
            if file.first() == Some(&b'*') {
                if self.rk_sys.len() >= MAX_RK_SYS {
                    mt("ERROR", cfmt("(1255): Maximum number of global files reached: %d", &[A::I(MAX_RK_SYS as i64)]));
                } else {
                    let mut f = &file[1..];
                    if f.first() == Some(&b'/') {
                        f = &f[1..];
                    }
                    self.rk_sys.push((f.to_vec(), name));
                }
                continue;
            }
            let file_path = if file.len() > 3 && file[1] == b':' && file[2] == b'\\' { file.clone() } else { [basedir, b"\\", &file].concat() };
            if file_path.len() > OS_SIZE_1024 {
                mt("DEBUG2", cfmt("Path file was truncated (%s)\n", &[A::B(&file_path[..OS_SIZE_1024])]));
                continue;
            }
            if !file_path.contains(&b'\\') || self.check_ignore(&file_path) {
                continue;
            }
            if is_file(&file_path) {
                let m = cfmt("Rootkit '%s' detected by the presence of file '%s'.", &[A::B(&name), A::B(&file_path)]);
                notify_rk(ALERT_ROOTKIT_FOUND, &cap(m, 2048));
            }
        }
    }

    /// `check_rc_sys` (Windows: the entries of %basedir%\WINDOWS and \Program Files,
    /// or of C:\ with scanall; `_stat64` gives directories size 0, so they are not entered)
    fn check_rc_sys(&mut self, basedir: &[u8]) {
        mt("DEBUG", "Starting on check_rc_sys");
        self.sys_errors = 0;
        self.sys_total = 0;
        if self.rk.scanall != 0 {
            self.read_sys_dir(b"C:\\");
        } else {
            for d in [&b"WINDOWS"[..], b"Program Files"] {
                let p = cap([basedir, b"\\", d].concat(), OS_SIZE_1024 + 1);
                self.read_sys_dir(&p);
            }
        }
        // "No problem found on the system. Analyzed %d files." is an ALERT_OK: not sent
        let _ = (self.sys_errors, self.sys_total);
    }

    /// `read_sys_dir`
    fn read_sys_dir(&mut self, dir: &[u8]) {
        if dir.len() > PATH_MAX {
            mt("ERROR", "Invalid directory given.");
            return;
        }
        if self.rk.skip_nfs != 0 {
            if let Some(l) = log() {
                l.debug2(cfmt("Attempted to check NFS status for '%s', but we don't know how on this OS.", &[A::B(dir)]));
            }
        }
        match siem_sca::crt::stat_mode(dir) {
            Ok(m) if m & siem_sca::crt::S_IFMT == siem_sca::crt::S_IFDIR => {}
            _ => return,
        }
        let Ok(names) = siem_sca::crt::read_dir(dir) else { return };
        for name in names {
            if name == b"." || name == b".." {
                continue;
            }
            let f = cap(if dir.len() == 1 && dir[0] == b'\\' { [b"\\", &name[..]].concat() } else { [dir, b"\\", &name].concat() }, PATH_MAX + 1);
            if self.check_ignore(&f) || f == b"/proc" || f == b"/sys" {
                continue;
            }
            for (file, rk) in &self.rk_sys {
                if *file == name {
                    self.sys_errors += 1;
                    let m = cfmt("Rootkit '%s' detected by the presence of file '%s/%s'.", &[A::B(rk), A::B(dir), A::B(file)]);
                    notify_rk(ALERT_ROOTKIT_FOUND, &cap(m, OS_SIZE_1024 + 1));
                }
            }
            // read_sys_file(f, 0)
            self.sys_total += 1;
            os_check_ads(&f);
        }
        // skipFS on Windows
        if let Some(l) = log() {
            l.debug2(cfmt("Attempted to check FS status for '%s', but we don't know how on this OS.", &[A::B(dir)]));
        }
    }

    /// `run_rk_check`
    pub fn run_rk_check(&mut self) {
        let basedir: Vec<u8> = match self.rk.basedir.as_deref() {
            None | Some("") => b"C:".to_vec(),
            Some(b) => b.strip_suffix('/').unwrap_or(b).as_bytes().to_vec(),
        };
        self.rk_sys.clear();
        notify_rk(ALERT_POLICY_VIOLATION, b"Starting rootcheck scan.");
        mt("INFO", "Starting rootcheck scan.");
        let open = |label: &str, path: &Option<String>| -> Option<Vec<Vec<u8>>> {
            let p = path.as_deref()?;
            let r = fgets_all(p.as_bytes(), OS_SIZE_1024);
            if r.is_none() {
                mt("WARNING", format!("No {label} file: '{p}'"));
            }
            r
        };
        if self.rk.rc_files != 0 {
            if let Some(lines) = open("rootcheck_files", &self.rk.rootkit_files) {
                self.check_rc_files(&basedir, lines);
            }
        }
        if self.rk.rc_trojans != 0 {
            if open("rootcheck_trojans", &self.rk.rootkit_trojans).is_some() {
                // os_string() is a stub on Windows: no file is reported as trojaned
                mt("DEBUG", "Starting on check_rc_trojans");
            }
        }
        let plist = log().and_then(|l| siem_sca::proc::process_list_as(l, TAG, "os_win32_setdebugpriv"));
        for (on, label, path, msg) in [
            (self.rk.rc_winaudit, "winaudit", self.rk.winaudit.clone(), "Windows Audit:"),
            (self.rk.rc_winmalware, "winmalware", self.rk.winmalware.clone(), "Windows Malware:"),
            (self.rk.rc_winapps, "winapps", self.rk.winapps.clone(), "Application Found:"),
        ] {
            if on == 0 {
                continue;
            }
            if path.is_none() {
                mt("INFO", format!("No {label} file configured."));
            } else if let Some(lines) = open(label, &path) {
                mt("DEBUG", format!("Starting on check_rc_{label}"));
                self.rkcl_get_entry(lines, msg, plist.as_deref());
            }
        }
        if self.rk.rc_dev != 0 {
            mt("DEBUG", "Going into check_rc_dev");
        }
        if self.rk.rc_sys != 0 {
            mt("DEBUG", "Going into check_rc_sys");
            self.check_rc_sys(&basedir);
        }
        if self.rk.rc_pids != 0 {
            mt("DEBUG", "Going into check_rc_pids");
        }
        if self.rk.rc_ports != 0 {
            mt("DEBUG", "Going into check_rc_ports");
            mt("DEBUG", "Going into check_open_ports");
        }
        if self.rk.rc_if != 0 {
            mt("DEBUG", "Going into check_rc_if");
        }
        mt("DEBUG", "Completed with all checks.");
        std::thread::sleep(std::time::Duration::from_secs(5));
        notify_rk(ALERT_POLICY_VIOLATION, b"Ending rootcheck scan.");
        mt("INFO", "Ending rootcheck scan.");
        mt("DEBUG", "Leaving run_rk_check");
    }
}

const RKCL_TYPE_FILE: i32 = 1;
const RKCL_TYPE_REGISTRY: i32 = 2;
const RKCL_TYPE_PROCESS: i32 = 3;
const RKCL_TYPE_DIR: i32 = 4;
const RKCL_COND_ALL: i32 = 0x001;
const RKCL_COND_ANY: i32 = 0x002;
const RKCL_COND_REQ: i32 = 0x004;
const RKCL_COND_NON: i32 = 0x008;

/// `_rkcl_is_name`
fn is_name(b: &[u8]) -> bool {
    b.first() == Some(&b'[') && b.last() == Some(&b']')
}

/// `_rkcl_get_name`: (name, condition); the reference goes to `refb`.
fn get_name(buf: &[u8], refb: &mut Vec<u8>) -> Option<(Vec<u8>, i32)> {
    if !is_name(buf) {
        return None;
    }
    let b = &buf[1..];
    let close = b.iter().position(|&c| c == b']')?;
    let name = b[..close].to_vec();
    let mut t = &b[close + 1..];
    // the C test is "!= ' ' && [1] != '['": either one is enough
    if t.first() != Some(&b' ') && t.get(1) != Some(&b'[') {
        return None;
    }
    t = t.get(2..)?;
    let c2 = t.iter().position(|&c| c == b']')?;
    let cond = match &t[..c2] {
        b"all" => RKCL_COND_ALL,
        b"any" => RKCL_COND_ANY,
        b"none" => RKCL_COND_NON,
        b"any required" => RKCL_COND_ANY | RKCL_COND_REQ,
        b"all required" => RKCL_COND_ALL | RKCL_COND_REQ,
        _ => return None,
    };
    let t2 = &t[c2 + 1..];
    if t2.first() != Some(&b' ') && t2.get(1) != Some(&b'[') {
        return None;
    }
    let t2 = t2.get(2..)?;
    let c3 = t2.iter().position(|&c| c == b']')?;
    // strncpy(ref, .., 255) into a buffer that is reused between entries
    let r = &t2[..c3.min(255)];
    refb.clear();
    refb.extend_from_slice(r);
    Some((name, cond))
}

/// `_rkcl_get_pattern`: splits at the first `" -> "`.
fn get_pattern(v: &[u8]) -> (&[u8], Option<&[u8]>) {
    match v.windows(4).position(|w| w == b" -> ") {
        Some(i) => (&v[..i], Some(&v[i + 4..])),
        None => (v, None),
    }
}

/// `_rkcl_get_value`: (type, value) of `"type:value;"`.
fn get_value(buf: &[u8]) -> Option<(i32, Vec<u8>)> {
    let colon = buf.iter().position(|&c| c == b':')?;
    let mut t = &buf[..colon];
    let rest = &buf[colon + 1..];
    let semi = rest.iter().position(|&c| c == b';')?;
    if t.first() == Some(&b'!') {
        t = &t[1..];
    }
    let typ = match t {
        b"f" => RKCL_TYPE_FILE,
        b"r" => RKCL_TYPE_REGISTRY,
        b"p" => RKCL_TYPE_PROCESS,
        b"d" => RKCL_TYPE_DIR,
        _ => return None,
    };
    Some((typ, rest[..semi].to_vec()))
}

// ───────────────────────── Windows helpers ─────────────────────────

/// `os_check_ads`: alerts on every named NTFS stream.
fn os_check_ads(full_path: &[u8]) {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{BackupRead, BackupSeek, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_POSIX_SEMANTICS, FILE_SHARE_READ, OPEN_EXISTING};
    let p = s(full_path);
    if siem_fileop::crt::is_network_path(&p) {
        if let Some(l) = log() {
            l.warn(siem_fileop::crt::network_path_executed(&p));
        }
        return;
    }
    let Some(w) = super::win::auto_to_wide(full_path) else { return };
    // SAFETY: a handle and backup context opened and released here; buffers are sized for each read.
    unsafe {
        let h = CreateFileW(w.as_ptr(), 0x8000_0000, FILE_SHARE_READ, std::ptr::null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, std::ptr::null_mut());
        if h == INVALID_HANDLE_VALUE {
            return;
        }
        // WIN32_STREAM_ID: id, attributes, size (u64), name size; the header is 20 bytes
        let mut hdr = [0u8; 24];
        let mut ctx: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut name = vec![0u8; 0x10000];
        let mut name_size = 0u32;
        loop {
            let mut read = 0u32;
            if BackupRead(h, hdr.as_mut_ptr(), 20, &mut read, 0, 0, &mut ctx) == 0 || read == 0 {
                break;
            }
            name_size = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
            let size = u64::from_le_bytes(hdr[8..16].try_into().expect("8 bytes"));
            let mut nread = 0u32;
            if BackupRead(h, name.as_mut_ptr(), name_size.min(name.len() as u32), &mut nread, 0, 0, &mut ctx) != 0 && nread != 0 {
                // the UTF-16 name copied byte by byte, zero bytes skipped
                let mut final_name: Vec<u8> = full_path[..full_path.len().min(PATH_MAX - 1)].to_vec();
                for &c in &name[..nread as usize] {
                    if final_name.len() >= PATH_MAX {
                        break;
                    }
                    if c != 0 {
                        final_name.push(c);
                    }
                }
                if let Some(i) = final_name.iter().rposition(|&c| c == b':') {
                    final_name.truncate(i);
                }
                let m = cfmt("NTFS Alternate data stream found: '%s'. Possible hidden content.", &[A::B(&final_name)]);
                notify_rk(ALERT_ROOTKIT_FOUND, &cap(m, OS_SIZE_1024 + 1));
            }
            let (mut lo, mut hi) = (0u32, 0u32);
            if BackupSeek(h, size as u32, (size >> 32) as u32, &mut lo, &mut hi, &mut ctx) == 0 {
                break;
            }
        }
        let mut read = 0u32;
        BackupRead(h, name.as_mut_ptr(), name_size.min(name.len() as u32), &mut read, 1, 0, &mut ctx);
        CloseHandle(h);
    }
}

/// `is_registry`: the key in the 32-bit or the 64-bit view.
fn is_registry(entry: &[u8], option: Option<&[u8]>, value: Option<&[u8]>) -> bool {
    use windows_sys::Win32::System::Registry::*;
    // __os_winreg_getkey
    let (root, sub) = match entry.iter().position(|&c| c == b'\\') {
        Some(i) => (&entry[..i], Some(&entry[i + 1..])),
        None => (entry, None),
    };
    let tree: HKEY = match root {
        b"HKEY_LOCAL_MACHINE" | b"HKLM" => HKEY_LOCAL_MACHINE,
        b"HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
        b"HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG,
        b"HKEY_USERS" => HKEY_USERS,
        b"HKCU" | b"HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        _ => std::ptr::null_mut(),
    };
    let sub = sub.filter(|s| !s.is_empty());
    let (Some(sub), false) = (sub, tree.is_null()) else {
        mt("ERROR", cfmt("(1757): Invalid syscheck registry entry: '%s'.", &[A::B(entry)]));
        return false;
    };
    let open = |arch: u32| -> bool {
        let c = siem_sca::crt::cstring(sub);
        let mut k: HKEY = std::ptr::null_mut();
        // SAFETY: a NUL-terminated sub key; the key is closed below.
        if unsafe { RegOpenKeyExA(tree, c.as_ptr() as *const u8, 0, KEY_READ | arch, &mut k) } != 0 {
            return false;
        }
        let r = match option {
            Some(o) => query_key(k, o, value),
            None => true,
        };
        // SAFETY: opened above.
        unsafe { RegCloseKey(k) };
        r
    };
    open(KEY_WOW64_32KEY) || open(KEY_WOW64_64KEY)
}

/// `__os_winreg_querykey`: the first value named `option` (`@` = default) against `value`.
fn query_key(k: windows_sys::Win32::System::Registry::HKEY, option: &[u8], value: Option<&[u8]>) -> bool {
    use windows_sys::Win32::System::Registry::*;
    const MAX_VALUE_NAME: usize = 16383;
    let mut count = 0u32;
    let mut subkeys = 0u32;
    let mut class = [0u8; 261];
    let mut class_size = 260u32;
    let n = std::ptr::null_mut();
    // SAFETY: the counts of an open key.
    if unsafe { RegQueryInfoKeyA(k, class.as_mut_ptr(), &mut class_size, std::ptr::null(), &mut subkeys, n, n, &mut count, n, n, n, std::ptr::null_mut()) } != 0 {
        return false;
    }
    let mut vbuf = vec![0u8; MAX_VALUE_NAME + 1];
    let mut dbuf = vec![0u8; MAX_VALUE_NAME + 1];
    for i in 0..count {
        let mut vsize = MAX_VALUE_NAME as u32;
        let mut dsize = MAX_VALUE_NAME as u32;
        let mut dtype = 0u32;
        vbuf[0] = 0;
        dbuf[0] = 0;
        // SAFETY: buffers of the sizes passed.
        if unsafe { RegEnumValueA(k, i, vbuf.as_mut_ptr(), &mut vsize, std::ptr::null(), &mut dtype, dbuf.as_mut_ptr(), &mut dsize) } != 0 {
            break;
        }
        let mut vname = vbuf[..vbuf.iter().position(|&c| c == 0).unwrap_or(0)].to_vec();
        if vname.is_empty() {
            vname = b"@".to_vec();
        }
        if !eq_ic(&vname, option) {
            continue;
        }
        let Some(value) = value else { return true };
        let cstr = |b: &[u8]| b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())].to_vec();
        let storage: Vec<u8> = match dtype {
            REG_SZ | REG_EXPAND_SZ => cstr(&dbuf[..MAX_VALUE_NAME]),
            REG_MULTI_SZ => {
                let mut out = Vec::new();
                let mut avail = MAX_VALUE_NAME as i64;
                let mut p = 0;
                while p < dbuf.len() && dbuf[p] != 0 {
                    let part = cstr(&dbuf[p..]);
                    if avail >= part.len() as i64 + 1 {
                        out.extend_from_slice(&part);
                        avail -= part.len() as i64;
                        out.push(b' ');
                        avail -= 1;
                    }
                    p += part.len() + 1;
                }
                out
            }
            // "%x" of (unsigned int)*data_buffer: the first byte, sign-extended
            REG_DWORD => format!("{:x}", dbuf[0] as i8 as i32 as u32).into_bytes(),
            _ => {
                let mut out: Vec<u8> = Vec::new();
                let mut avail = MAX_VALUE_NAME as i64 - 2;
                for &b in &dbuf[..dsize as usize] {
                    // "%02x" of a sign-extended char
                    let t = format!("{:02x}", b as i8 as i32 as u32);
                    if avail > 2 {
                        let take = (avail as usize).min(t.len());
                        out.extend_from_slice(&t.as_bytes()[..take]);
                        avail = MAX_VALUE_NAME as i64 - (out.len() as i64 + 2);
                    }
                }
                out
            }
        };
        return pt_matches(&storage, value);
    }
    false
}

/// `w_rootcheck_thread`: runs the scan at start, then every `frequency` seconds
/// (or on a syscom `restart`), while `syscheck.rootcheck` is set.
pub fn start_thread(rk: std::sync::Arc<RkConfig>, enabled: bool) {
    let r = std::thread::Builder::new().name("rootcheck".into()).spawn(move || {
        let mut prev: i64 = 0;
        loop {
            let run_now = RESTART_ROOTCHECK.swap(false, Ordering::SeqCst);
            let now = chrono::Utc::now().timestamp();
            if enabled && (now - prev > rk.time as i64 || run_now) {
                Scan::new(&rk).run_rk_check();
                prev = chrono::Utc::now().timestamp();
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    });
    if r.is_err() {
        if let Some(l) = log() {
            l.error("(1109): Unable to create new pthread.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_values_patterns() {
        let mut r = Vec::new();
        assert_eq!(get_name(b"[Bad app] [any] [https://x]", &mut r), Some((b"Bad app".to_vec(), RKCL_COND_ANY)));
        assert_eq!(r, b"https://x");
        assert_eq!(get_name(b"[A] [all required] []", &mut r), Some((b"A".to_vec(), RKCL_COND_ALL | RKCL_COND_REQ)));
        assert_eq!(get_name(b"[A] [maybe] []", &mut r), None);
        assert_eq!(get_value(b"f:C:\\x.exe;"), Some((RKCL_TYPE_FILE, b"C:\\x.exe".to_vec())));
        assert_eq!(get_value(b"!p:r:evil;"), Some((RKCL_TYPE_PROCESS, b"r:evil".to_vec())));
        assert_eq!(get_value(b"x:y;"), None);
        assert_eq!(get_pattern(b"HKLM\\A -> v -> =:1"), (&b"HKLM\\A"[..], Some(&b"v -> =:1"[..])));
    }

    #[test]
    fn pattern_language() {
        assert!(pt_matches(b"Hello", b"=:hello"));
        assert!(pt_matches(b"abc", b"r:^a && !r:z"));
        assert!(!pt_matches(b"abc", b"r:^a && r:z"));
        assert!(pt_matches(b"b", b"<:a"));
        assert!(!pt_matches(b"b", b"!=:B"));
        assert!(pt_check_negate(b"!r:a && !=:b"));
        assert!(!pt_check_negate(b"!r:a && =:b"));
    }
}
