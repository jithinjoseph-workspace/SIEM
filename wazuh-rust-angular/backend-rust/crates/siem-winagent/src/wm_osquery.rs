//! The `osquery` wodle of `wazuh-agent.exe`: `wazuh_modules/wm_osquery_monitor.c`
//! and `config/wmodules-osquery-monitor.c` (Windows branches). Follows the
//! osquery results log, and (with `run_daemon`) runs osqueryd with the packs
//! and the agent labels added to its configuration.

use std::io::{BufRead, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use siem_cjson::Json;
use siem_config::labels::Label;
use siem_log::WLog;
use siem_xml::XmlNode;

/// `WM_OSQUERYMONITOR_CONTEXT.name` (also the module tag)
pub const NAME: &str = "osquery";
/// `WM_OSQUERYMONITOR_LOGTAG` (the module files are built with ARGV0 "wazuh-modulesd")
const LOGTAG: &str = "wazuh-modulesd:osquery";
const TMP_CONFIG_PATH: &str = "tmp/osquery.conf.tmp";
const OSQUERYD_BIN: &str = "osqueryd.exe";
/// `LOCALFILE_MQ`
const LOCALFILE_MQ: u8 = b'1';
/// `OS_MAXSTR`
const OS_MAXSTR: usize = 65536;
/// `JSON_MAX_FSIZE`
const JSON_MAX_FSIZE: u64 = 2_147_483_648;

/// `active` (a static of the C module)
static ACTIVE: AtomicBool = AtomicBool::new(true);

/// `wm_osquery_pack_t`
#[derive(Clone, Debug)]
pub struct Pack {
    pub name: String,
    pub path: String,
}

/// `wm_osquery_monitor_t`
#[derive(Clone, Debug)]
pub struct WmOsquery {
    pub bin_path: String,
    pub log_path: String,
    pub config_path: String,
    pub packs: Vec<Pack>,
    pub disable: bool,
    pub run_daemon: bool,
    pub add_labels: bool,
}

/// `eval_bool`
fn eval_bool(s: Option<&str>) -> Option<bool> {
    match s {
        Some("yes") => Some(true),
        Some("no") => Some(false),
        _ => None,
    }
}

/// `wm_osquery_monitor_read`
pub fn read(log: &WLog, nodes: Option<&[XmlNode]>) -> Result<WmOsquery, ()> {
    let mut o = WmOsquery {
        bin_path: r"C:\Program Files\osquery\osqueryd".into(),
        log_path: r"C:\Program Files\osquery\log\osqueryd.results.log".into(),
        config_path: r"C:\Program Files\osquery\osquery.conf".into(),
        packs: Vec::new(),
        disable: false,
        run_daemon: true,
        add_labels: false,
    };
    let Some(nodes) = nodes else { return Ok(o) };
    let invalid = |tag: &str| {
        log.error(format!("Invalid content for tag '{tag}' at module '{NAME}'."));
        Err(())
    };
    let network = |n: &XmlNode, content: &str| {
        let bad = siem_fileop::crt::is_network_path(content);
        if bad {
            log.warn(format!("(9801): Network path not allowed in configuration. '{}': {content}.", n.element));
        }
        bad
    };
    for n in nodes {
        let content = n.content.as_deref();
        match n.element.as_str() {
            "disabled" => match eval_bool(content) {
                Some(v) => o.disable = v,
                None => return invalid("disabled"),
            },
            "bin_path" => {
                if !network(n, content.unwrap_or("")) {
                    o.bin_path = content.unwrap_or("").to_string();
                }
            }
            "log_path" => {
                if !network(n, content.unwrap_or("")) {
                    o.log_path = content.unwrap_or("").to_string();
                    log.debug2(format!("Logpath read: {}", o.log_path));
                }
            }
            "config_path" => {
                if !network(n, content.unwrap_or("")) {
                    o.config_path = content.unwrap_or("").to_string();
                    log.debug2(format!("configPath read: {}", o.config_path));
                }
            }
            "pack" => {
                let Some(attr) = n.attributes.first() else { return Err(()) };
                if attr != "name" {
                    log.error(format!("No such attribute '{attr}' in osquery element <pack>"));
                    return Err(());
                }
                o.packs.push(Pack { name: n.values.first().cloned().unwrap_or_default(), path: content.unwrap_or("").to_string() });
            }
            "add_labels" => match eval_bool(content) {
                Some(v) => o.add_labels = v,
                None => return invalid("add_labels"),
            },
            "run_daemon" => match eval_bool(content) {
                Some(v) => o.run_daemon = v,
                None => return invalid("run_daemon"),
            },
            e => log.warn(format!("No such tag <{e}> at module '{NAME}'.")),
        }
    }
    Ok(o)
}

/// `wm_osquery_dump`
pub fn dump(o: &WmOsquery) -> Json {
    let yn = |b: bool| Json::string(if b { "yes" } else { "no" });
    let mut m = Json::object();
    m.add("disabled", yn(o.disable));
    m.add("run_daemon", yn(o.run_daemon));
    m.add("add_labels", yn(o.add_labels));
    m.add("bin_path", Json::string(&o.bin_path));
    m.add("log_path", Json::string(&o.log_path));
    m.add("config_path", Json::string(&o.config_path));
    if !o.packs.is_empty() {
        let mut packs = Json::array();
        for p in &o.packs {
            let mut j = Json::object();
            j.add("name", Json::string(&p.name));
            j.add("path", Json::string(&p.path));
            packs.push(j);
        }
        m.add("packs", packs);
    }
    let mut root = Json::object();
    root.add(NAME, m);
    root
}

/// What the module needs from the agent.
pub struct Env {
    pub log: Arc<WLog>,
    pub max_eps: i32,
    /// `ReadConfig(CLABELS, OSSECCONF)` then `ReadConfig(CLABELS | CAGENT_CONFIG, AGENTCONFIG)`;
    /// Err when the first read fails.
    pub read_labels: Box<dyn Fn() -> Result<Vec<Label>, ()> + Send + Sync>,
}

fn info(log: &WLog, m: impl AsRef<[u8]>) {
    log.tagged(LOGTAG, "INFO", m);
}
fn warn(log: &WLog, m: impl AsRef<[u8]>) {
    log.tagged(LOGTAG, "WARNING", m);
}
fn error(log: &WLog, m: impl AsRef<[u8]>) {
    log.tagged(LOGTAG, "ERROR", m);
}

/// `errno` and `strerror(errno)` for a failed file call.
fn errno(e: &std::io::Error) -> (i32, String) {
    let n = siem_fileop::wfopen_errno(e);
    (n, siem_fileop::strerror(n))
}

/// `errno` and `strerror(errno)` after a failed `waccess` (the CRT maps the Windows error).
fn access_errno(e: &std::io::Error) -> (i32, String) {
    let n = match e.raw_os_error() {
        // ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND -> ENOENT; ERROR_ACCESS_DENIED -> EACCES
        Some(2) | Some(3) => 2,
        Some(5) => 13,
        Some(n) => n,
        None => 0,
    };
    (n, siem_fileop::strerror(n))
}

/// `wm_sendmsg(msg_delay, queue, msg, "osquery", LOCALFILE_MQ)` with the module's error message.
fn send(log: &WLog, msg_delay: i32, msg: &[u8]) {
    std::thread::sleep(Duration::from_millis((msg_delay / 1000) as u64));
    if siem_ipc::mq_op::send_msg(0, msg, NAME, LOCALFILE_MQ) < 0 {
        let e = std::io::Error::last_os_error();
        log.debug1(format!("Unable to send message to queue: ({e})"));
        error(log, format!("(1210): Queue 'queue/sockets/queue' not accessible: '{e}'"));
    }
}

/// `get_fp_inode` / the file index of `path` (Windows `nFileIndexHigh << 32 | nFileIndexLow`).
fn file_index(f: &std::fs::File) -> Option<u64> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
    // SAFETY: a valid handle owned by `f`; the struct is written by the call.
    unsafe {
        let mut fi: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        (GetFileInformationByHandle(f.as_raw_handle() as _, &mut fi) != 0).then(|| ((fi.nFileIndexHigh as u64) << 32) | fi.nFileIndexLow as u64)
    }
}

/// `wm_osquery_check_logfile`: -1 error (errno), 0 unchanged, 1 truncated, 2 rotated.
fn check_logfile(path: &str, f: &std::fs::File, pos: u64) -> (i32, Option<std::io::Error>) {
    let Some(old_inode) = file_index(f) else { return (-1, Some(std::io::Error::last_os_error())) };
    let size = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) => return (-1, Some(e)),
    };
    let now = match std::fs::File::open(path) {
        Ok(h) => h,
        Err(e) => return (-1, Some(e)),
    };
    match file_index(&now) {
        Some(i) if i != old_inode => (2, None),
        Some(_) => ((size < pos) as i32, None),
        None => (-1, Some(std::io::Error::last_os_error())),
    }
}

/// One `{"osquery": ...}` event, with `pack`/`subquery` taken from a `pack_<pack>_<query>` name.
fn wrap(line: &[u8]) -> Option<Vec<u8>> {
    let (mut j, _) = siem_cjson::parse_with_opts(line, false).ok()?;
    if j.get("pack").is_none() {
        let split = match j.get("name") {
            Some(Json::String(name)) if name.windows(5).any(|w| w == b"pack_") => {
                // C: begin = name + 5, whatever the position of "pack_"
                let begin = name.get(5..).unwrap_or(&[]).to_vec();
                begin.iter().position(|&c| c == b'_').filter(|&p| p + 1 < begin.len()).map(|p| (begin[..p].to_vec(), begin[p + 1..].to_vec()))
            }
            _ => None,
        };
        if let Some((pack, sub)) = split {
            j.add("pack", Json::string(pack));
            j.add("subquery", Json::string(sub));
        }
    }
    let mut root = Json::object();
    root.add(NAME, j);
    Some(root.print_unformatted())
}

/// `fgets(line, OS_MAXSTR, fp)` on a text-mode stream: up to OS_MAXSTR - 1 bytes through '\n', CRLF read as LF.
fn fgets(r: &mut std::io::BufReader<std::fs::File>, pos: &mut u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let buf = r.fill_buf().ok()?;
        if buf.is_empty() {
            break;
        }
        let room = OS_MAXSTR - 1 - out.len();
        let take = buf.iter().take(room).position(|&c| c == b'\n').map(|p| p + 1).unwrap_or(buf.len().min(room));
        out.extend_from_slice(&buf[..take]);
        r.consume(take);
        *pos += take as u64;
        if out.last() == Some(&b'\n') || out.len() >= OS_MAXSTR - 1 {
            break;
        }
    }
    if out.ends_with(b"\r\n") {
        out.remove(out.len() - 2);
    }
    (!out.is_empty()).then_some(out)
}

/// `Read_Log`
fn read_log(log: &WLog, log_path: &str, msg_delay: i32) {
    let mut i = 0;
    let mut reported = false;
    while ACTIVE.load(Ordering::SeqCst) {
        let file = loop {
            match std::fs::File::open(log_path) {
                Ok(f) => break Some(f),
                Err(_) if !ACTIVE.load(Ordering::SeqCst) => break None,
                Err(e) => {
                    i += (i < 60) as u64;
                    let (n, s) = errno(&e);
                    warn(log, format!("Results file '{log_path}' not available: {s} ({n}). Retrying in {i} sec."));
                    std::thread::sleep(Duration::from_secs(i));
                }
            }
        };
        let Some(file) = file else { break };
        info(log, format!("Following osquery results file '{log_path}'."));
        let mut r = std::io::BufReader::new(file);
        let mut pos = match r.seek(SeekFrom::End(0)) {
            Ok(p) => p,
            Err(e) => {
                let (n, s) = errno(&e);
                error(log, format!("(1116): Could not set position in file '{log_path}' due to [({n})-({s})]."));
                continue;
            }
        };
        if file_index(r.get_ref()).is_none() {
            let (n, s) = errno(&std::io::Error::last_os_error());
            error(log, format!("Couldn't get inode of file '{log_path}': {s} ({n})"));
            continue;
        }
        'file: while ACTIVE.load(Ordering::SeqCst) {
            while let Some(mut line) = fgets(&mut r, &mut pos) {
                if let Some(nl) = line.iter().position(|&c| c == b'\n') {
                    line.truncate(nl);
                }
                match wrap(&line) {
                    Some(payload) => {
                        log.tagged(LOGTAG, "DEBUG2", [b"Sending... '".as_slice(), &payload, b"'"].concat());
                        send(log, msg_delay, &payload);
                    }
                    None if !reported => {
                        warn(log, format!("Result line not in JSON format: '{:>64}'...", String::from_utf8_lossy(&line)));
                        reported = true;
                    }
                    None => {}
                }
            }
            match check_logfile(log_path, r.get_ref(), pos) {
                (-1, e) => {
                    let e = e.unwrap_or_else(std::io::Error::last_os_error);
                    let (n, s) = errno(&e);
                    if e.kind() == std::io::ErrorKind::NotFound {
                        info(log, format!("Results file '{log_path}' was deleted."));
                    } else {
                        warn(log, format!("Couldn't access results file '{log_path}': {s} ({n})"));
                    }
                    break 'file;
                }
                (0, _) => std::thread::sleep(Duration::from_secs(1)),
                (1, _) => {
                    info(log, format!("Results file '{log_path}' truncated. Reloading."));
                    match r.seek(SeekFrom::Start(0)) {
                        Ok(_) => pos = 0,
                        Err(e) => {
                            let (n, s) = errno(&e);
                            error(log, format!("(1116): Could not set position in file '{log_path}' due to [({n})-({s})]."));
                            break 'file;
                        }
                    }
                }
                _ => {
                    info(log, format!("Results file '{log_path}' rotated. Reloading."));
                    break 'file;
                }
            }
        }
    }
}

/// `wm_osquery_already_running`: the pid in "osqueryd (pid) is already running", or "unknown".
fn already_running(text: &str) -> Option<String> {
    if let Some(b) = text.find("osqueryd (") {
        let rest = &text[b + "osqueryd (".len()..];
        if let Some(e) = rest.find(") is already running") {
            return Some(rest[..e].to_string());
        }
    }
    text.contains("Pidfile::Error::Busy").then(|| "unknown".to_string())
}

/// `Execute_Osquery`
fn execute(log: &WLog, o: &WmOsquery, msg_delay: i32) {
    let osqueryd = format!("{}/{OSQUERYD_BIN}", o.bin_path);
    log.tagged(LOGTAG, "DEBUG", format!("Launching '{osqueryd}' with config file '{}'", o.config_path));
    let config_arg = format!("--config_path=\"{}\"", o.config_path);
    let mut strpid: Option<String> = None;
    let mut running_count = 0;
    loop {
        // waccess(config_path, R_OK)
        if let Err(e) = std::fs::metadata(&o.config_path) {
            let (n, s) = access_errno(&e);
            warn(log, format!("The configuration file '{}' is not accessible: {s} ({n})", o.config_path));
            std::thread::sleep(Duration::from_secs(600));
            continue;
        }
        let Some(mut wfd) = siem_execd::wfd::wpopenv(log, &osqueryd, &[&osqueryd, &config_arg], siem_execd::wfd::W_BIND_STDERR) else {
            warn(log, format!("Couldn't execute osquery ({osqueryd}). Sleeping for 10 minutes."));
            std::thread::sleep(Duration::from_secs(600));
            continue;
        };
        let handle = wfd.process_handle();
        siem_execd::wm_exec::wm_append_handle(handle);
        let started = siem_sca::crt::now();
        // the pipe is read as is: a CRLF line keeps its '\r' (and an empty one is "\r")
        while let Some(buf) = wfd.fgets(4096) {
            // Filter Bash colors: \e[*m
            let mut text: &[u8] = &buf;
            if buf.starts_with(b"\x1b[") {
                if let Some(m) = buf[2..].iter().position(|&c| c == b'm') {
                    text = &buf[2 + m + 1..];
                }
            }
            if let Some(nl) = text.iter().position(|&c| c == b'\n') {
                text = &text[..nl];
            }
            // strlen(text): up to the first NUL
            let text = &text[..text.iter().position(|&c| c == 0).unwrap_or(text.len())];
            if text.is_empty() {
                continue;
            }
            let t = String::from_utf8_lossy(text);
            if t.contains("[Ref #1382]") {
                warn(log, "osqueryd has unsafe permissions.");
            } else if t.contains("[Ref #1629]") {
                warn(log, "osqueryd initialize failed: Could not initialize database.");
            } else if let Some(pid) = already_running(&t) {
                strpid = Some(pid);
                running_count += 1;
                // Don't report the first time
                if running_count == 1 {
                    continue;
                }
            } else {
                match text[0] {
                    b'E' | b'W' => warn(log, text),
                    _ => log.tagged(LOGTAG, "DEBUG2", text),
                }
            }
            send(log, msg_delay, text);
        }
        siem_execd::wm_exec::wm_remove_handle(log, handle);
        let wstatus = siem_execd::wfd::wpclose(log, wfd);
        if wstatus == 127 {
            error(log, format!("Couldn't execute osquery ({osqueryd}). Check file and permissions. Sleeping for 10 minutes."));
            std::thread::sleep(Duration::from_secs(600));
        } else if let Some(pid) = &strpid {
            if running_count == 1 {
                info(log, format!("osqueryd is already running with pid {pid}. Will run again in 1 minute."));
                std::thread::sleep(Duration::from_secs(60));
            } else {
                info(log, format!("osqueryd is already running with pid {pid}. Will run again in 10 minutes."));
                std::thread::sleep(Duration::from_secs(600));
            }
        } else if siem_sca::crt::now() - started < 10 {
            error(log, format!("Osquery exited with code {wstatus}. Closing module."));
            ACTIVE.store(false, Ordering::SeqCst);
            break;
        } else {
            warn(log, format!("Osquery exited with code {wstatus}. Restarting."));
        }
    }
}

/// `json_strip`: drops `//` lines and `/* */` blocks that start a line.
fn json_strip(json: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(json.len());
    let mut rest = json;
    while !rest.is_empty() {
        let ws = rest.iter().take_while(|&&c| c == b' ' || c == b'\t').count();
        let cursor = &rest[ws..];
        if cursor.starts_with(b"//") {
            match cursor.iter().position(|&c| c == b'\n') {
                // the line goes, its newline stays
                Some(nl) => {
                    out.extend_from_slice(&rest[..ws]);
                    rest = &cursor[nl..];
                    if rest.first() == Some(&b'\n') {
                        out.push(b'\n');
                        rest = &rest[1..];
                    }
                }
                None => {
                    out.extend_from_slice(&rest[..ws]);
                    return out;
                }
            }
        } else if cursor.starts_with(b"/*") {
            match cursor[2..].windows(2).position(|w| w == b"*/") {
                Some(p) => {
                    out.extend_from_slice(&rest[..ws]);
                    rest = &cursor[2 + p + 2..];
                }
                None => {
                    // unterminated comment: the rest is kept as it is
                    out.extend_from_slice(rest);
                    return out;
                }
            }
        } else {
            match rest.iter().position(|&c| c == b'\n') {
                Some(nl) => {
                    out.extend_from_slice(&rest[..=nl]);
                    rest = &rest[nl + 1..];
                }
                None => {
                    out.extend_from_slice(rest);
                    return out;
                }
            }
        }
    }
    out
}

/// `json_fread(path, 1)`: Err(Some(errno)) when the file cannot be read, Err(None) when it is not JSON.
fn json_fread(log: &WLog, path: &str) -> Result<Json, Option<std::io::Error>> {
    // w_get_file_content(path, JSON_MAX_FSIZE)
    let data = match std::fs::read(path) {
        Ok(d) if d.len() as u64 > JSON_MAX_FSIZE => {
            log.debug1(format!("Cannot load file '{path}': it exceeds {} MiB", JSON_MAX_FSIZE / (1024 * 1024)));
            log.debug1(format!("Cannot get the content of the file: {path}"));
            return Err(None);
        }
        Ok(d) => d,
        Err(e) => {
            let (n, s) = errno(&e);
            log.debug1(format!("(1103): Could not open file '{path}' due to [({n})-({s})]."));
            log.debug1(format!("Cannot get the content of the file: {path}"));
            return Err(Some(e));
        }
    };
    if let Ok((j, _)) = siem_cjson::parse_with_opts(&data, false) {
        return Ok(j);
    }
    log.debug1(format!("Couldn't parse JSON file '{path}'. Trying to clear comments."));
    match siem_cjson::parse_with_opts(&json_strip(&data), false) {
        Ok((j, _)) => Ok(j),
        Err(_) => {
            log.debug1(format!("Couldn't parse JSON file '{path}'."));
            Err(None)
        }
    }
}

fn load_config(log: &WLog, path: &str) -> Option<Json> {
    match json_fread(log, path) {
        Ok(j) => Some(j),
        Err(Some(e)) => {
            let (n, s) = errno(&e);
            error(log, format!("Couldn't load configuration file '{path}': {s} ({n})"));
            None
        }
        Err(None) => {
            error(log, format!("Couldn't load configuration file '{path}'. Maybe format is invalid."));
            None
        }
    }
}

/// `json_fwrite`
fn write_config(log: &WLog, path: &str, root: &Json) -> bool {
    match std::fs::write(path, root.print_unformatted()) {
        Ok(()) => true,
        Err(e) => {
            let (n, s) = errno(&e);
            log.debug1(format!("(1103): Could not open file '{path}' due to [({n})-({s})]."));
            error(log, format!("Couldn't write JSON content into configuration '{path}': {s} ({n})"));
            false
        }
    }
}

/// The object `key` of `root`, created when missing.
fn child<'a>(root: &'a mut Json, key: &str, make: fn() -> Json) -> &'a mut Json {
    if root.get(key).is_none() {
        root.add(key, make());
    }
    root.get_mut(key).unwrap()
}

/// `wm_osquery_packs`: false on error.
fn packs(log: &WLog, o: &mut WmOsquery) -> bool {
    if o.packs.is_empty() {
        return true;
    }
    let Some(mut root) = load_config(log, &o.config_path) else { return false };
    let packs = child(&mut root, "packs", Json::object);
    for p in &o.packs {
        if p.name != "*" {
            if let Err(e) = std::fs::metadata(&p.path) {
                let (n, s) = access_errno(&e);
                warn(log, format!("Possible invalid configuration: Pack file '{}' is not accessible: {s} ({n})", p.path));
            }
        } else if !p.path.contains('*') {
            warn(log, format!("Possible invalid configuration for pack '*' ({}): no such wildcards.", p.path));
        }
        packs.add(&p.name, Json::string(&p.path));
    }
    o.config_path = TMP_CONFIG_PATH.into();
    write_config(log, &o.config_path, &root)
}

/// `wm_osquery_decorators`: false on error.
fn decorators(log: &WLog, o: &mut WmOsquery, read_labels: &dyn Fn() -> Result<Vec<Label>, ()>) -> bool {
    if !o.add_labels {
        return true;
    }
    let Ok(labels) = read_labels() else { return false };
    if labels.is_empty() {
        return true;
    }
    let Some(mut root) = load_config(log, &o.config_path) else { return false };
    let always = child(child(&mut root, "decorators", Json::object), "always", Json::array);
    for l in labels.iter().filter(|l| !l.flags.hidden) {
        // Prevent SQL injection
        let (k, v) = (l.key.replace('\'', "''"), l.value.replace('\'', "''"));
        let q = format!("SELECT '{v}' AS '{k}';");
        if q.len() < OS_MAXSTR {
            log.tagged(LOGTAG, "DEBUG2", format!("Adding decorator: {q}"));
            always.push(Json::string(&q));
        } else {
            warn(log, format!("Label '{}' too long. Couldn't insert decorator.", l.key));
        }
    }
    o.config_path = TMP_CONFIG_PATH.into();
    write_config(log, &o.config_path, &root)
}

/// `wm_osquery_monitor_main`
pub fn main(mut o: WmOsquery, env: Env) {
    let log = env.log;
    if o.disable {
        info(&log, "Module disabled. Exiting...");
        return;
    }
    info(&log, "Module started.");
    let msg_delay = 1_000_000 / env.max_eps.max(1);
    let (rl, path) = (log.clone(), o.log_path.clone());
    let Ok(reader) = std::thread::Builder::new().name("osquery_read_log".into()).spawn(move || read_log(&rl, &path, msg_delay)) else {
        error(&log, "Error while creating Read_Log thread.");
        return;
    };
    if o.run_daemon {
        if !packs(&log, &mut o) || !decorators(&log, &mut o, &*env.read_labels) {
            return;
        }
        let (el, eo) = (log.clone(), o.clone());
        match std::thread::Builder::new().name("osquery_execute".into()).spawn(move || execute(&el, &eo, msg_delay)) {
            Ok(t) => {
                let _ = t.join();
            }
            Err(_) => {
                error(&log, "Error while creating Execute_Osquery thread.");
                return;
            }
        }
    } else {
        info(&log, "run_daemon disabled, finding detached osquery process results.");
    }
    let _ = reader.join();
    info(&log, "Closing module.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(already_running("E1016 osqueryd (1234) is already running"), Some("1234".into()));
        assert_eq!(already_running("Pidfile::Error::Busy"), Some("unknown".into()));
        assert_eq!(already_running("hello"), None);
        assert_eq!(wrap(br#"{"name":"pack_it_users","x":1}"#).unwrap(), br#"{"osquery":{"name":"pack_it_users","x":1,"pack":"it","subquery":"users"}}"#);
        assert_eq!(wrap(br#"{"name":"pack_x_"}"#).unwrap(), br#"{"osquery":{"name":"pack_x_"}}"#);
        assert!(wrap(b"not json").is_none());
        assert_eq!(json_strip(b"{\n  // c\n  \"a\": 1 /* x */\n}"), b"{\n  \n  \"a\": 1 /* x */\n}");
    }
}
