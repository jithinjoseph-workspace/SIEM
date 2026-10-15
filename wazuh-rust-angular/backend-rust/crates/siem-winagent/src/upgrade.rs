//! The agent-upgrade module of `wazuh-agent.exe` (wazuh_modules/agent_upgrade:
//! wm_agent_upgrade.c, agent/wm_agent_upgrade_agent.c, agent/wm_agent_upgrade_com.c,
//! config/wmodules-agent-upgrade.c and os_crypto/signature/signature.c as the
//! Windows agent builds them): the `<agent-upgrade>` reader, the upgrade
//! result notification and the `upgrade` request target.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use siem_cjson::Json;
use siem_config::{ConfigContext, LogLevel};
use siem_log::WLog;
use siem_xml::{OsXml, XmlNode};

/// `AGENT_UPGRADE_WM_NAME`
pub const NAME: &str = "agent-upgrade";
/// `WM_AGENT_UPGRADE_LOGTAG` (the module sources are built with ARGV0 "wazuh-modulesd")
const LOGTAG: &str = "wazuh-modulesd:agent-upgrade";
const OSSECCONF: &str = "ossec.conf";
const DEFAULTQUEUE: &str = "queue/sockets/queue";
const DEF_CA_STORE: &str = "wpk_root.pem";
const INCOMING_DIR: &str = "incoming";
const UPGRADE_DIR: &str = "upgrade";
const TMP_DIR: &str = "tmp";
/// `WM_AGENT_UPGRADE_RESULT_FILE`
const RESULT_FILE: &str = "upgrade\\upgrade_result";
/// `WM_AGENT_UPGRADE_RESULT_WAIT_TIME`
const RESULT_WAIT_TIME: u64 = 30;
const PATH_MAX: usize = 260;
/// `task_manager_modules_list[WM_TASK_UPGRADE_MODULE]`, `UPGRADE_MQ`
const UPGRADE_MODULE: &str = "upgrade_module";
const UPGRADE_MQ: u8 = b'u';

/// `upgrade_values`, `upgrade_messages`, `task_statuses_map`
const STATES: [(&str, &str, &str); 3] = [
    ("0", "Upgrade was successful", "Done"),
    ("1", "Upgrade failed due missing dependency", "Failed"),
    ("2", "Upgrade failed", "Failed"),
];

/// `wm_agent_upgrade` (agent side)
#[derive(Clone, Debug)]
pub struct Config {
    pub enabled: bool,
    wait_start: i32,
    wait_max: i32,
    wait_factor: f32,
    ca_verification: bool,
}

impl Default for Config {
    fn default() -> Self {
        // WM_UPGRADE_WAIT_START, WM_UPGRADE_WAIT_MAX, WM_UPGRADE_WAIT_FACTOR_INCREASE
        Config { enabled: true, wait_start: 30, wait_max: 3600, wait_factor: 2.0, ca_verification: true }
    }
}

/// `wcom_ca_store` (NULL is `None`)
static CA_STORE: Mutex<Option<Vec<String>>> = Mutex::new(None);
/// `allow_upgrades`
static ALLOW_UPGRADES: AtomicBool = AtomicBool::new(false);
/// The opened file (`file.path`, `file.fp`; text for mode "w").
static FILE: Mutex<Option<(String, std::io::BufWriter<std::fs::File>, bool)>> = Mutex::new(None);

fn tlog(log: &WLog, level: &str, m: impl AsRef<[u8]>) {
    log.tagged(LOGTAG, level, m);
}

/// `strtol(s, &end, 0)` with the 32-bit Windows `long`: (value, byte at end).
fn strtol0(s: &str) -> (i32, u8) {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let neg = i < b.len() && b[i] == b'-';
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let mut base = 10;
    if b.get(i) == Some(&b'0') {
        if matches!(b.get(i + 1), Some(b'x' | b'X')) && b.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit()) {
            base = 16;
            i += 2;
        } else {
            base = 8;
        }
    }
    let start = i;
    let mut v: i64 = 0;
    while let Some(d) = b.get(i).and_then(|&c| (c as char).to_digit(base)) {
        v = (v * base as i64 + d as i64).min(i64::from(i32::MAX) + 1);
        i += 1;
    }
    if i == start {
        return (0, b.first().copied().unwrap_or(0));
    }
    let v = if neg { (-v).max(i64::from(i32::MIN)) } else { v.min(i64::from(i32::MAX)) };
    (v as i32, b.get(i).copied().unwrap_or(0))
}

/// `merror_exit` from a reader: what the context holds first, as the C logs it before.
fn exit_with(ctx: &mut ConfigContext, log: &WLog, msg: String) -> ! {
    for (lv, m) in ctx.log.drain(..) {
        match lv {
            LogLevel::Debug1 => log.debug1(m),
            LogLevel::Debug2 => log.debug2(m),
            LogLevel::Info => log.info(m),
            LogLevel::Warn => log.warn(m),
            LogLevel::Error => log.error(m),
        }
    }
    log.critical(msg);
    siem_log::cexit::fatal_exit()
}

/// `wm_agent_upgrade_read`: `xml` and `nodes` are None for the default module.
pub fn read(ctx: &mut ConfigContext, log: &WLog, xml: Option<&OsXml>, nodes: Option<&[XmlNode]>, data: &mut Config) -> Result<(), ()> {
    // Read deprecated CA configuration
    if CA_STORE.lock().unwrap().is_none() {
        read_ca_verification_old(ctx, log, &mut data.ca_verification)?;
    }
    for n in nodes.unwrap_or_default() {
        let content = n.content.as_deref().unwrap_or("");
        match n.element.as_str() {
            "enabled" => match content {
                "yes" => data.enabled = true,
                "no" => data.enabled = false,
                _ => {
                    ctx.error(format!("Invalid content for tag 'enabled' at module '{NAME}'."));
                    return Err(());
                }
            },
            tag @ ("notification_wait_start" | "notification_wait_max") => {
                let (v, end) = strtol0(content);
                if v == 0 || v == i32::MAX {
                    ctx.error(format!("Invalid content for tag '{tag}' at module '{NAME}'."));
                    return Err(());
                }
                let v = match end {
                    b'h' => v.wrapping_mul(3600),
                    b'm' => v.wrapping_mul(60),
                    b's' | 0 => v,
                    _ if tag == "notification_wait_start" => {
                        ctx.error(format!("Invalid {tag} at module '{NAME}'"));
                        return Err(());
                    }
                    _ => {
                        ctx.error(format!("Invalid content for tag '{tag}' at module '{NAME}'"));
                        return Err(());
                    }
                };
                if tag == "notification_wait_start" {
                    data.wait_start = v;
                } else {
                    data.wait_max = v;
                }
            }
            "notification_wait_factor" => {
                let f = siem_config::util::strtol(content).0.clamp(i32::MIN.into(), i32::MAX.into()) as f32;
                if f > 1.0 {
                    data.wait_factor = f;
                } else {
                    ctx.error(format!("Invalid content for tag 'notification_wait_factor' at module '{NAME}'."));
                    return Err(());
                }
            }
            "ca_verification" => {
                let children = xml.and_then(|x| x.get_elements_by_node(Some(n)));
                match children {
                    Some(c) => read_ca_verification(ctx, &c, &mut data.ca_verification)?,
                    None => return Err(()),
                }
            }
            other => ctx.warn(format!("No such tag <{other}> at module '{NAME}'.")),
        }
    }
    let mut store = CA_STORE.lock().unwrap();
    if data.ca_verification {
        if store.as_ref().map_or(true, |s| s.is_empty()) {
            *store = Some(vec![DEF_CA_STORE.to_string()]);
        }
    } else {
        ctx.info("WPK verification with CA is disabled.");
        *store = None;
    }
    Ok(())
}

/// `wm_agent_upgrade_read_ca_verification`
fn read_ca_verification(ctx: &mut ConfigContext, nodes: &[XmlNode], flag: &mut bool) -> Result<(), ()> {
    let mut store = CA_STORE.lock().unwrap();
    if store.is_some() {
        *store = Some(Vec::new());
    }
    for n in nodes {
        let content = n.content.as_deref().unwrap_or("");
        if n.element == "enabled" {
            if content.eq_ignore_ascii_case("yes") {
                *flag = true;
            } else if content.eq_ignore_ascii_case("no") {
                *flag = false;
            } else {
                ctx.error(format!("Invalid content for tag <{}>", n.element));
                return Err(());
            }
        } else if n.element == "ca_store" {
            store.get_or_insert_with(Vec::new).push(content.to_string());
        }
    }
    Ok(())
}

/// `wm_agent_upgrade_read_ca_verification_old`: `<active-response>` ca_verification / ca_store.
fn read_ca_verification_old(ctx: &mut ConfigContext, log: &WLog, flag: &mut bool) -> Result<(), ()> {
    let mut xml = match OsXml::read_file(OSSECCONF, false) {
        Ok(x) => x,
        Err(e) => exit_with(ctx, log, siem_config::messages::xml_error(OSSECCONF, &e.message, e.line)),
    };
    if let Some(v) = xml.get_contents(Some(&["ossec_config", "active-response", "ca_verification"])) {
        for c in v {
            if c.eq_ignore_ascii_case("yes") {
                *flag = true;
            } else if c.eq_ignore_ascii_case("no") {
                *flag = false;
            } else {
                ctx.error(format!("Invalid content for tag <ca_verification>: '{c}'"));
                return Err(());
            }
        }
    }
    *CA_STORE.lock().unwrap() = xml.get_contents(Some(&["ossec_config", "active-response", "ca_store"]));
    Ok(())
}

/// `wm_agent_upgrade_dump`
pub fn dump(cfg: &Config) -> Json {
    let mut info = Json::object();
    info.add("enabled", Json::string(if cfg.enabled { "yes" } else { "no" }));
    info.add("ca_verification", Json::string(if cfg.ca_verification { "yes" } else { "no" }));
    if let Some(s) = CA_STORE.lock().unwrap().as_ref() {
        let mut a = Json::array();
        for c in s {
            a.push(Json::string(c));
        }
        info.add("ca_store", a);
    }
    let mut root = Json::object();
    root.add(NAME, info);
    root
}

/// `wm_agent_upgrade_main` -> `wm_agent_upgrade_start_agent_module`
pub fn main(cfg: &Config, log: &WLog, max_eps: i32) {
    if !cfg.enabled {
        ALLOW_UPGRADES.store(false, Ordering::SeqCst);
        return;
    }
    tlog(log, "INFO", "(8153): Module Agent Upgrade started.");
    // wm_agent_upgrade_check_status: StartMQ is 0 on Windows
    std::thread::sleep(Duration::from_secs(RESULT_WAIT_TIME));
    let mut wait_time = cfg.wait_start as u32;
    while search_upgrade_result(log, max_eps) {
        std::thread::sleep(Duration::from_secs(wait_time as u64));
        wait_time = (wait_time as f32 * cfg.wait_factor) as u32;
        if wait_time > cfg.wait_max as u32 {
            wait_time = cfg.wait_max as u32;
        }
    }
    ALLOW_UPGRADES.store(true, Ordering::SeqCst);
}

/// `wm_upgrade_agent_search_upgrade_result`
fn search_upgrade_result(log: &WLog, max_eps: i32) -> bool {
    let Ok(f) = std::fs::File::open(RESULT_FILE) else {
        return false;
    };
    // fgets(buffer, 20, ...): the first line, at most 19 bytes
    let mut line = Vec::new();
    for b in f.bytes() {
        let Ok(b) = b else { break };
        line.push(b);
        if b == b'\n' || line.len() == 19 {
            break;
        }
    }
    if line.is_empty() {
        return true;
    }
    let line = &line[..line.iter().position(|&c| c == 0).unwrap_or(line.len())];
    match STATES.iter().position(|s| line.contains(&s.0.as_bytes()[0])) {
        Some(state) => {
            send_ack_message(log, max_eps, state);
            true
        }
        None => false,
    }
}

/// `wm_upgrade_agent_send_ack_message`
fn send_ack_message(log: &WLog, max_eps: i32, state: usize) {
    let (value, message, status) = STATES[state];
    let mut params = Json::object();
    params.add("error", Json::number(siem_config::util::atoi(value) as f64));
    params.add("message", Json::string(message));
    params.add("status", Json::string(status));
    let mut root = Json::object();
    root.add("command", Json::string("upgrade_update_status"));
    root.add("parameters", params);
    let msg = root.print_unformatted();
    // wm_sendmsg: Sleep(usec / 1000), then SendMSG
    std::thread::sleep(Duration::from_millis((1_000_000 / max_eps.max(1) / 1000) as u64));
    if siem_ipc::mq_op::send_msg(0, &msg, UPGRADE_MODULE, UPGRADE_MQ) < 0 {
        let e = siem_ipc::os_net::strerror(siem_ipc::os_net::errno());
        log.debug1(format!("Unable to send message to queue: ({e})"));
        tlog(log, "ERROR", format!("(1210): Queue '{DEFAULTQUEUE}' not accessible: '{e}'"));
        // StartMQ never fails on Windows
    }
    let mut m = b"(8163): Sending upgrade ACK event: '".to_vec();
    m.extend_from_slice(&msg);
    m.push(b'\'');
    tlog(log, "DEBUG", m);
}

/// `wm_agent_upgrade_command_ack`
fn command_ack(error: i32, message: &str) -> Vec<u8> {
    let mut root = Json::object();
    root.add("error", Json::number(error as f64));
    root.add("message", Json::string(message));
    root.add("data", Json::array());
    root.print_unformatted()
}

// command_error_codes / error_messages
const ERROR_OK: (i32, &str) = (0, "ok");
const ERROR_UPGRADES_NOT_ALLOWED: (i32, &str) = (1, "Upgrade module is disabled or not ready yet");
const ERROR_UNKNOWN_COMMAND: (i32, &str) = (2, "Command not found");
const ERROR_PARAMETERS_NOT_FOUND: (i32, &str) = (3, "Required parameters were not found");
const ERROR_UNSOPPORTED_MODE: (i32, &str) = (4, "Unsupported file mode");
const ERROR_INVALID_FILE_NAME: (i32, &str) = (5, "Invalid file name");
const ERROR_FILE_OPEN: i32 = 6;
const ERROR_FILE_NOT_OPENED: (i32, &str) = (7, "File not opened. Agent might have been auto-restarted during upgrade");
const ERROR_FILE_NOT_OPENED2: (i32, &str) = (8, "No file opened");
const ERROR_TARGET_FILE_NOT_MATCH: (i32, &str) = (9, "The target file doesn't match the opened file");
const ERROR_WRITE_FILE: (i32, &str) = (10, "Cannot write file");
const ERROR_CLOSE: (i32, &str) = (11, "Cannot close file");
const ERROR_GEN_SHA1: (i32, &str) = (12, "Cannot generate SHA1");
const ERROR_SIGNATURE: (i32, &str) = (13, "Could not verify signature");
const ERROR_COMPRESS: (i32, &str) = (14, "Could not uncompress package");
const ERROR_CLEAN_DIRECTORY: (i32, &str) = (15, "Could not clean up upgrade directory");
const ERROR_UNMERGE: (i32, &str) = (16, "Error unmerging file");
const ERROR_EXEC: (i32, &str) = (18, "Error executing command");
const ERROR_CLEAR_UPGRADE_FILE: (i32, &str) = (19, "Could not erase upgrade_result file");

fn ack(e: (i32, &str)) -> Vec<u8> {
    command_ack(e.0, e.1)
}

/// `wm_agent_upgrade_process_command` (the `upgrade` request target)
pub fn process_command(log: &std::sync::Arc<WLog>, define_int: &dyn Fn(&str, &str, i32, i32) -> i32, buffer: &[u8]) -> Vec<u8> {
    let buffer = &buffer[..buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len())];
    let mut output = None;
    if let Some(obj) = siem_cjson::parse(buffer) {
        if let Some(command) = obj.get("command").filter(|c| c.is_string()).and_then(|c| c.as_str()) {
            if command == "clear_upgrade_result" {
                output = Some(com_clear_result(log));
            } else if ALLOW_UPGRADES.load(Ordering::SeqCst) {
                output = match obj.get("parameters") {
                    None => Some(ack(ERROR_PARAMETERS_NOT_FOUND)),
                    Some(p) => match &*command {
                        "open" => Some(com_open(log, p)),
                        "write" => Some(com_write(log, p)),
                        "close" => Some(com_close(log, p)),
                        "sha1" => Some(com_sha1(log, p)),
                        "upgrade" => Some(com_upgrade(log, define_int, p)),
                        _ => None,
                    },
                };
            } else {
                output = Some(ack(ERROR_UPGRADES_NOT_ALLOWED));
            }
        }
    }
    output.unwrap_or_else(|| ack(ERROR_UNKNOWN_COMMAND))
}

/// `_jailfile`
fn jailfile(basedir: &str, filename: &str) -> Option<String> {
    if siem_fileop::ref_parent_folder(filename) {
        return None;
    }
    let p = format!("{basedir}\\{filename}");
    (p.len() <= PATH_MAX).then_some(p)
}

/// The "file" parameter jailed in `basedir`.
fn file_param(p: &Json, basedir: &str) -> Option<String> {
    p.get("file").filter(|f| f.is_string()).and_then(|f| f.as_str()).and_then(|f| jailfile(basedir, &f))
}

/// The CRT's `errno` for an I/O error.
fn io_errno(e: &std::io::Error) -> i32 {
    match e.kind() {
        std::io::ErrorKind::NotFound => 2,
        std::io::ErrorKind::PermissionDenied => 13,
        std::io::ErrorKind::AlreadyExists => 17,
        _ => e.raw_os_error().unwrap_or(0),
    }
}

/// `wm_agent_upgrade_com_open`
fn com_open(log: &WLog, p: &Json) -> Vec<u8> {
    let mut file = FILE.lock().unwrap();
    if let Some((path, _, _)) = file.take() {
        tlog(log, "WARNING", format!("(8124): At open: File '{path}' was opened. Closing."));
    }
    let mode = p.get("mode").filter(|m| m.is_string()).and_then(|m| m.as_str()).map(|m| m.into_owned());
    let Some(mode) = mode.filter(|m| m == "w" || m == "wb") else {
        tlog(log, "ERROR", "(8125): At open: Unsupported mode.");
        return ack(ERROR_UNSOPPORTED_MODE);
    };
    let Some(final_path) = file_param(p, INCOMING_DIR) else {
        tlog(log, "ERROR", "(8126): At open: Invalid file name.");
        return ack(ERROR_INVALID_FILE_NAME);
    };
    match std::fs::File::create(&final_path) {
        Ok(f) => {
            // the stdio buffer of the C FILE (4096 bytes in msvcrt)
            *file = Some((final_path, std::io::BufWriter::with_capacity(4096, f), mode == "w"));
            ack(ERROR_OK)
        }
        Err(e) => {
            let no = siem_fileop::wfopen_errno(&e);
            let s = siem_fileop::strerror(no);
            let name = p.get("file").and_then(|f| f.as_str()).unwrap_or_default().into_owned();
            tlog(log, "ERROR", format!("(1103): Could not open file '{name}' due to [({no})-({s})]."));
            command_ack(ERROR_FILE_OPEN, &format!("File Open Error: {s}"))
        }
    }
}

/// `decode_base64`: None for an empty input; non-base64 bytes are skipped.
fn decode_base64(src: &[u8]) -> Option<Vec<u8>> {
    if src.is_empty() {
        return None;
    }
    let dec = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        _ => 63,
    };
    let buf: Vec<u8> = src.iter().copied().filter(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=')).collect();
    let mut out = Vec::new();
    for ch in buf.chunks(4) {
        let c = |i: usize| ch.get(i).copied().unwrap_or(b'A');
        let (b1, b2, b3, b4) = (dec(c(0)), dec(c(1)), dec(c(2)), dec(c(3)));
        out.push((b1 << 2) | (b2 >> 4));
        if c(2) != b'=' {
            out.push(((b2 & 0xf) << 4) | (b3 >> 2));
        }
        if c(3) != b'=' {
            out.push(((b3 & 0x3) << 6) | b4);
        }
    }
    Some(out)
}

/// `wm_agent_upgrade_com_write`
fn com_write(log: &WLog, p: &Json) -> Vec<u8> {
    let mut file = FILE.lock().unwrap();
    let Some((path, fp, text)) = file.as_mut() else {
        tlog(log, "ERROR", "(8127): At write: File not opened. Agent might have been auto-restarted during upgrade.");
        return ack(ERROR_FILE_NOT_OPENED);
    };
    let Some(final_path) = file_param(p, INCOMING_DIR) else {
        tlog(log, "ERROR", "(8126): At write: Invalid file name.");
        return ack(ERROR_INVALID_FILE_NAME);
    };
    if *path != final_path {
        tlog(log, "ERROR", format!("(8128): At write: The target file doesn't match the opened file '{path}'"));
        return ack(ERROR_TARGET_FILE_NOT_MATCH);
    }
    // shortcut: a missing "buffer" crashes the C agent (NULL valuestring); here it is a write error
    let data = p.get("buffer").and_then(|b| b.as_bytes()).and_then(decode_base64);
    let length = p.get("length").filter(|l| l.is_number()).and_then(|l| l.as_i32());
    let ok = match (data, length) {
        (Some(mut d), Some(len)) if len >= 0 => {
            // fwrite(.., length): the C buffer is zero-filled past the decoded bytes
            d.resize(len as usize, 0);
            let d = if *text { d.iter().flat_map(|&c| if c == b'\n' { vec![b'\r', b'\n'] } else { vec![c] }).collect() } else { d };
            fp.write_all(&d).is_ok()
        }
        _ => false,
    };
    if ok {
        ack(ERROR_OK)
    } else {
        tlog(log, "ERROR", format!("(8129): At write: Cannot write on '{final_path}'"));
        ack(ERROR_WRITE_FILE)
    }
}

/// `wm_agent_upgrade_com_close`
fn com_close(log: &WLog, p: &Json) -> Vec<u8> {
    let mut file = FILE.lock().unwrap();
    let Some((path, _, _)) = file.as_ref() else {
        tlog(log, "ERROR", "(8130): At close: No file is opened.");
        return ack(ERROR_FILE_NOT_OPENED2);
    };
    let Some(final_path) = file_param(p, INCOMING_DIR) else {
        tlog(log, "ERROR", "(8126): At close: Invalid file name.");
        return ack(ERROR_INVALID_FILE_NAME);
    };
    if *path != final_path {
        tlog(log, "ERROR", format!("(8128): At close: The target file doesn't match the opened file '{path}'"));
        return ack(ERROR_TARGET_FILE_NOT_MATCH);
    }
    let (_, mut fp, _) = file.take().unwrap();
    if let Err(e) = fp.flush() {
        tlog(log, "ERROR", format!("(8131): At close: '{}'", siem_ipc::os_net::strerror(io_errno(&e))));
        return ack(ERROR_CLOSE);
    }
    ack(ERROR_OK)
}

/// `wm_agent_upgrade_com_sha1`
fn com_sha1(log: &WLog, p: &Json) -> Vec<u8> {
    let Some(final_path) = file_param(p, INCOMING_DIR) else {
        tlog(log, "ERROR", "(8126): At sha1: Invalid file name.");
        return ack(ERROR_INVALID_FILE_NAME);
    };
    let Ok(data) = std::fs::read(&final_path) else {
        tlog(log, "ERROR", "(8132): At sha1: Error generating SHA1.");
        return ack(ERROR_GEN_SHA1);
    };
    let hex: String = openssl::sha::sha1(&data).iter().map(|b| format!("{b:02x}")).collect();
    command_ack(0, &hex)
}

/// `wm_agent_upgrade_com_upgrade`
fn com_upgrade(log: &std::sync::Arc<WLog>, define_int: &dyn Fn(&str, &str, i32, i32) -> i32, p: &Json) -> Vec<u8> {
    let req_timeout = define_int("execd", "request_timeout", 1, 3600);
    let package = p.get("file").filter(|f| f.is_string()).and_then(|f| f.as_str()).map(|f| f.into_owned());
    // Unsign
    let compressed = package.as_deref().and_then(|pk| unsign(log, pk));
    let (Some(package), Some(compressed)) = (package, compressed) else {
        tlog(log, "ERROR", format!("(8131): At upgrade: '{}'", ERROR_SIGNATURE.1));
        return ack(ERROR_SIGNATURE);
    };
    // Uncompress
    let Some(merged) = uncompress(log, &compressed, &package) else {
        let _ = std::fs::remove_file(&compressed);
        tlog(log, "ERROR", format!("(8131): At upgrade: '{}'", ERROR_COMPRESS.1));
        return ack(ERROR_COMPRESS);
    };
    // Clean up upgrade folder
    if siem_fileop::cldir_ex_ignore(UPGRADE_DIR, &[]).is_err() {
        tlog(log, "ERROR", format!("(8131): At upgrade: '{}'", ERROR_CLEAN_DIRECTORY.1));
        return ack(ERROR_CLEAN_DIRECTORY);
    }
    // Unmerge
    if !siem_fileop::unmerge_files_mode(&merged, Some(UPGRADE_DIR), false).0 {
        let _ = std::fs::remove_file(&merged);
        tlog(log, "ERROR", format!("(8133): At upgrade: Error unmerging file: '{merged}'"));
        return ack(ERROR_UNMERGE);
    }
    let _ = std::fs::remove_file(&merged);
    // Installer executable file
    let Some(installer) = p.get("installer").filter(|f| f.is_string()).and_then(|f| f.as_str()).and_then(|f| jailfile(UPGRADE_DIR, &f)) else {
        tlog(log, "ERROR", "(8126): At upgrade: Invalid file name.");
        return ack(ERROR_INVALID_FILE_NAME);
    };
    // Execute
    let r = siem_execd::wm_exec::wm_exec(log, &installer, req_timeout as u32);
    if r.retval < 0 {
        tlog(log, "ERROR", format!("(8135): At upgrade: Error executing command [{installer}]"));
        return ack(ERROR_EXEC);
    }
    command_ack(0, &r.status.unwrap_or(0).to_string())
}

/// `wm_agent_upgrade_com_clear_result`
fn com_clear_result(log: &WLog) -> Vec<u8> {
    if std::fs::remove_file(RESULT_FILE).is_ok() {
        ALLOW_UPGRADES.store(true, Ordering::SeqCst);
        ack(ERROR_OK)
    } else {
        tlog(log, "DEBUG", format!("(8136): At clear_upgrade_result: Could not erase file '{RESULT_FILE}'"));
        ack(ERROR_CLEAR_UPGRADE_FILE)
    }
}

/// `_unsign`: the unsigned (compressed) package in TMP_DIR.
fn unsign(log: &WLog, source: &str) -> Option<String> {
    let (Some(source_j), Some(dest)) = (jailfile(INCOMING_DIR, source), jailfile(TMP_DIR, source)) else {
        tlog(log, "ERROR", "(8126): At unsign(): Invalid file name.");
        return None;
    };
    if dest.len() + 10 > PATH_MAX {
        tlog(log, "ERROR", "(8137): At unsign(): Too long temp file.");
        return None;
    }
    let out = match siem_fileop::mktemp(&format!("{dest}.gz.XXXXXX")) {
        None => {
            tlog(log, "ERROR", "(8138): At unsign(): Could not create temporary compressed file.");
            None
        }
        Some(dest) => {
            let store = CA_STORE.lock().unwrap().clone();
            if wpk_unsign(log, &source_j, &dest, store.as_deref()).is_err() {
                let _ = std::fs::remove_file(&dest);
                tlog(log, "ERROR", format!("(8139): At unsign(): Could not unsign package file '{source_j}'"));
                None
            } else {
                Some(dest)
            }
        }
    };
    // unlink(source): the name as received, not the jailed path
    let _ = std::fs::remove_file(source);
    out
}

/// `_uncompress`: gunzip `source` (non-gzip data passes through) into TMP_DIR.
fn uncompress(log: &WLog, source: &str, package: &str) -> Option<String> {
    let Some(dest) = jailfile(TMP_DIR, package) else {
        tlog(log, "ERROR", "(8126): At uncompress(): Invalid file name.");
        return None;
    };
    if dest.len() + 10 > PATH_MAX {
        tlog(log, "ERROR", "(8137): At uncompress(): Too long temp file.");
        return None;
    }
    // the template is used as is (no mktemp)
    let dest = format!("{dest}.mg.XXXXXX");
    let Ok(raw) = std::fs::read(source) else {
        tlog(log, "ERROR", format!("(8140): At uncompress(): Unable to open '{source}'"));
        return None;
    };
    let Ok(mut target) = std::fs::File::create(&dest) else {
        tlog(log, "ERROR", format!("(8140): At uncompress(): Unable to open '{dest}'"));
        return None;
    };
    let data = if raw.starts_with(&[0x1f, 0x8b]) {
        let mut d = Vec::new();
        flate2::read::MultiGzDecoder::new(&raw[..]).read_to_end(&mut d).ok().map(|_| d)
    } else {
        Some(raw)
    };
    let Some(data) = data else {
        drop(target);
        let _ = std::fs::remove_file(&dest);
        tlog(log, "ERROR", format!("(8141): At uncompress(): Unable to read '{source}'"));
        return None;
    };
    if target.write_all(&data).is_err() {
        drop(target);
        let _ = std::fs::remove_file(&dest);
        tlog(log, "ERROR", format!("(8129): At uncompress(): Cannot write on '{source}'"));
        return None;
    }
    drop(target);
    let _ = std::fs::remove_file(source);
    Some(dest)
}

/// `w_wpk_unsign`: verify a WPK256 file (certificate against `ca_store`,
/// RSA-SHA256 signature of the content) and extract its content to `target`.
fn wpk_unsign(log: &WLog, source: &str, target: &str, ca_store: Option<&[String]>) -> Result<(), ()> {
    use openssl::pkey::Id;
    use openssl::pkey_ctx::PkeyCtx;
    const MAGIC: &[u8] = b"WPK256\0";
    const SIGNLEN: usize = 256;
    let data = match std::fs::read(source) {
        Ok(d) => d,
        Err(e) => {
            log.error(format!("opening input file: {}", siem_fileop::strerror(siem_fileop::wfopen_errno(&e))));
            return Err(());
        }
    };
    if data.len() < MAGIC.len() {
        log.error("Invalid input file (reading magic number).");
        return Err(());
    }
    if &data[..MAGIC.len()] != MAGIC {
        log.error("Invalid input file (bad magic number).");
        return Err(());
    }
    // w_wpk_cert: the PEM certificate up to a NUL byte
    let rest = &data[MAGIC.len()..];
    let cert = match rest.iter().position(|&c| c == 0) {
        None => {
            log.error("Couldn't get certificate from WPK file.");
            None
        }
        Some(n) => match openssl::x509::X509::from_pem(&rest[..n]) {
            Ok(c) => Some((c, MAGIC.len() + n + 1)),
            Err(_) => {
                log.error("Invalid certificate in WPK file.");
                None
            }
        },
    };
    let Some((cert, pos)) = cert else {
        log.error(format!("Couldn't extract certificate at file '{source}'."));
        return Err(());
    };
    match ca_store {
        Some(store) => {
            if !wpk_verify_cert(log, &cert, store) {
                log.error("Error verifying WPK certificate.");
                return Err(());
            }
        }
        None => log.warn(format!("No root CA defined to verify file '{source}'.")),
    }
    if data.len() < pos + SIGNLEN {
        log.error("Invalid input file (reading signature).");
        return Err(());
    }
    let signature = &data[pos..pos + SIGNLEN];
    let content = &data[pos + SIGNLEN..];
    let digest = openssl::sha::sha256(content);
    let Ok(pkey) = cert.public_key() else {
        log.error("Couldn't get public key from certificate.");
        return Err(());
    };
    if pkey.id() != Id::RSA {
        log.error("Public key is not RSA.");
        return Err(());
    }
    let Ok(mut ctx) = PkeyCtx::new(&pkey) else {
        log.error("Couldn't create public key context.");
        return Err(());
    };
    if ctx.verify_init().is_err() {
        log.error("Failed to initialize public key context.");
        return Err(());
    }
    if ctx.set_signature_md(openssl::md::Md::sha256()).is_err() {
        log.error("Failed to set signature digest type.");
        return Err(());
    }
    if !ctx.verify(&digest, signature).unwrap_or(false) {
        log.error("Failed to verify signature.");
        return Err(());
    }
    let mut out = match std::fs::File::create(target) {
        Ok(f) => f,
        Err(e) => {
            log.error(format!("Opening output file: {}", siem_fileop::strerror(siem_fileop::wfopen_errno(&e))));
            return Err(());
        }
    };
    if out.write_all(content).is_err() {
        log.error("writing output file.");
        return Err(());
    }
    Ok(())
}

/// `wpk_verify_cert`: true when one CA of the store verifies `cert`.
fn wpk_verify_cert(log: &WLog, cert: &openssl::x509::X509, ca_store: &[String]) -> bool {
    use openssl::ssl::SslFiletype;
    use openssl::x509::store::{X509Lookup, X509StoreBuilder};
    use openssl::x509::X509StoreContext;
    for ca in ca_store {
        if ca.is_empty() {
            continue;
        }
        let Ok(mut b) = X509StoreBuilder::new() else {
            log.error("Couldn't create new store.");
            return false;
        };
        let meta = match std::fs::metadata(ca) {
            Ok(m) => m,
            Err(e) => {
                let no = io_errno(&e);
                log.error(format!("(1118): Could not retrieve information of file '{ca}' due to [({no})-({})].", siem_ipc::os_net::strerror(no)));
                continue;
            }
        };
        // X509_STORE_load_locations: a load failure leaves the store empty
        if meta.is_dir() {
            if let Ok(l) = b.add_lookup(X509Lookup::hash_dir()) {
                let _ = l.add_dir(ca, SslFiletype::PEM);
            }
        } else if meta.is_file() {
            if let Ok(l) = b.add_lookup(X509Lookup::file()) {
                let _ = l.load_cert_file(ca, SslFiletype::PEM);
            }
        } else {
            log.error(format!("Loading CA '{ca}': it's neither file nor directory."));
            continue;
        }
        let store = b.build();
        let (Ok(mut ctx), Ok(chain)) = (X509StoreContext::new(), openssl::stack::Stack::new()) else {
            return false;
        };
        match ctx.init(&store, cert, &chain, |c| c.verify_cert().map(|ok| (ok, c.error()))) {
            Ok((true, _)) => return true,
            Ok((false, err)) => {
                log.debug1(format!("Certificate couldn't be verified by CA '{ca}': {} ({})", err.error_string(), err.as_raw()));
            }
            Err(stack) => {
                for e in stack.errors() {
                    log.debug1(format!("At wpk_verify_cert(): {} ({})", e.reason().unwrap_or("(null)"), e.code()));
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strtol_base0_like_msvcrt() {
        assert_eq!(strtol0("30"), (30, 0));
        assert_eq!(strtol0("5m"), (5, b'm'));
        assert_eq!(strtol0("0x10s"), (16, b's'));
        assert_eq!(strtol0("010"), (8, 0));
        assert_eq!(strtol0("99999999999"), (i32::MAX, 0));
        assert_eq!(strtol0("abc"), (0, b'a'));
    }

    #[test]
    fn base64_like_c() {
        assert_eq!(decode_base64(b"aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_base64(b"aGVs\nbG8h").unwrap(), b"hello!");
        assert!(decode_base64(b"").is_none());
    }

    #[test]
    fn ack_format() {
        assert_eq!(command_ack(0, "ok"), br#"{"error":0,"message":"ok","data":[]}"#);
    }
}
