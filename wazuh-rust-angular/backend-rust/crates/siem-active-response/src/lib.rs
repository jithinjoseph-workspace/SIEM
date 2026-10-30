//! `src/active-response/active_responses.c`: the protocol every active
//! response program speaks with execd (one JSON line on stdin, the
//! `check_keys` round trip for stateful responses), the debug log and the
//! helpers the programs share.

use std::io::{BufRead, Write};

use siem_cjson::Json;

pub mod edr;
pub mod yara;

/// `LOG_FILE`
#[cfg(unix)]
pub const LOG_FILE: &str = "logs/active-responses.log";
#[cfg(windows)]
pub const LOG_FILE: &str = "active-response\\active-responses.log";
/// `OS_MAXSTR`
const OS_MAXSTR: usize = 65536;
/// `COMMANDSIZE_4096`
const COMMANDSIZE_4096: usize = 4096;

/// `ar_command_list`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Add,
    Delete,
    Continue,
    Abort,
}

/// `w_get_timestamp(time(NULL))`
fn timestamp() -> String {
    chrono::Local::now().format("%Y/%m/%d %H:%M:%S").to_string()
}

/// `write_debug_file`
pub fn write_debug_file(ar_name: &str, msg: &[u8]) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(LOG_FILE) {
        let mut line = format!("{} {ar_name}: ", timestamp()).into_bytes();
        line.extend_from_slice(msg);
        line.push(b'\n');
        // wfopen(LOG_FILE, "a") is a binary stream on Windows too
        let _ = f.write_all(&line);
    }
}

/// A text-mode C stream (stdout) on Windows writes `\n` as `\r\n`.
fn text_out(b: Vec<u8>) -> Vec<u8> {
    if !cfg!(windows) {
        return b;
    }
    let mut o = Vec::with_capacity(b.len() + 4);
    for c in b {
        if c == b'\n' {
            o.push(b'\r');
        }
        o.push(c);
    }
    o
}

/// `fgets(input, OS_MAXSTR, stdin)`: one line (with its newline), None at EOF.
fn read_line() -> Option<Vec<u8>> {
    let mut b = Vec::new();
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    loop {
        let buf = lock.fill_buf().ok()?;
        if buf.is_empty() {
            break;
        }
        let room = OS_MAXSTR - 1 - b.len();
        let take = match buf.iter().position(|&c| c == b'\n') {
            Some(p) if p < room => p + 1,
            _ => buf.len().min(room),
        };
        b.extend_from_slice(&buf[..take]);
        lock.consume(take);
        if b.last() == Some(&b'\n') || b.len() >= OS_MAXSTR - 1 {
            break;
        }
    }
    // a text-mode C stream on Windows reads "\r\n" as "\n"
    if cfg!(windows) && b.ends_with(b"\r\n") {
        b.truncate(b.len() - 2);
        b.push(b'\n');
    }
    (!b.is_empty()).then_some(b)
}

/// `get_json_from_input`: the message, when it has version, origin, command and parameters.
pub fn get_json_from_input(input: &[u8]) -> Option<Json> {
    let s = &input[..input.iter().position(|&c| c == 0).unwrap_or(input.len())];
    let (j, _) = siem_cjson::parse_with_opts(s, false).ok()?;
    j.get("version").filter(|v| v.is_number())?;
    j.get("origin").filter(|v| v.is_object())?;
    j.get("command").filter(|v| v.is_string())?;
    j.get("parameters").filter(|v| v.is_object())?;
    Some(j)
}

/// `get_command_from_json`
pub fn get_command_from_json(input: &Json) -> Option<&[u8]> {
    input.get("command").and_then(|c| c.as_bytes())
}

/// `setup_and_check_message`: the action (add or delete) and the message.
pub fn setup_and_check_message(argv0: &str) -> Option<(Action, Json)> {
    write_debug_file(argv0, b"Starting");
    let Some(input) = read_line() else {
        write_debug_file(argv0, b"Cannot read input from stdin");
        return None;
    };
    write_debug_file(argv0, &input);
    let Some(j) = get_json_from_input(&input) else {
        write_debug_file(argv0, b"Invalid input format");
        return None;
    };
    let action = match get_command_from_json(&j) {
        None => {
            write_debug_file(argv0, b"Cannot read 'command' from json");
            return None;
        }
        Some(b"add") => Action::Add,
        Some(b"delete") => Action::Delete,
        Some(_) => {
            write_debug_file(argv0, b"Invalid value of 'command'");
            return None;
        }
    };
    Some((action, j))
}

/// `basename_ex`
pub fn basename(p: &str) -> &str {
    let t = if cfg!(windows) { p.rsplit(['/', '\\']).next() } else { p.trim_end_matches('/').rsplit('/').next() };
    t.unwrap_or(p)
}

/// `build_json_keys_message`
fn build_json_keys_message(ar_name: &str, keys: &[&str]) -> Vec<u8> {
    let mut origin = Json::object();
    origin.add("name", Json::string(ar_name));
    origin.add("module", Json::string("active-response"));
    let mut params = Json::object();
    params.add("keys", Json::Array(keys.iter().map(|k| Json::string(k)).collect()));
    let mut m = Json::object();
    m.add("version", Json::number(1.0));
    m.add("origin", origin);
    m.add("command", Json::string("check_keys"));
    m.add("parameters", params);
    m.print_unformatted()
}

/// `send_keys_and_check_message`: Continue or Abort from execd, None on errors.
pub fn send_keys_and_check_message(argv0: &str, keys: &[&str]) -> Option<Action> {
    let msg = build_json_keys_message(basename(argv0), keys);
    write_debug_file(argv0, &msg);
    let mut out = std::io::stdout();
    let _ = out.write_all(&text_out([msg.as_slice(), b"\n"].concat()));
    let _ = out.flush();
    let Some(input) = read_line() else {
        write_debug_file(argv0, b"Cannot read input from stdin");
        return None;
    };
    write_debug_file(argv0, &input);
    let Some(j) = get_json_from_input(&input) else {
        write_debug_file(argv0, b"Invalid input format");
        return None;
    };
    match get_command_from_json(&j) {
        None => {
            write_debug_file(argv0, b"Cannot read 'command' from json");
            None
        }
        Some(b"continue") => Some(Action::Continue),
        Some(b"abort") => Some(Action::Abort),
        Some(_) => {
            write_debug_file(argv0, b"Invalid value of 'command'");
            None
        }
    }
}

/// The add flow of a stateful response: send the keys, then continue or stop.
/// Err(exit code) when the program must end.
pub fn check_keys(argv0: &str, key: &str) -> Result<(), i32> {
    match send_keys_and_check_message(argv0, &[key]) {
        Some(Action::Continue) => Ok(()),
        Some(Action::Abort) => {
            write_debug_file(argv0, b"Aborted");
            Err(0)
        }
        _ => Err(-1),
    }
}

/// `get_srcip_from_json`: win.eventdata ipAddress / destinationIp, else
/// data.srcip, if it is a valid IP.
pub fn get_srcip_from_json(input: &Json) -> Option<String> {
    let data = input.get("parameters")?.get("alert")?.get("data").filter(|d| d.is_object())?;
    let win = data
        .get("win")
        .filter(|w| w.is_object())
        .and_then(|w| w.get("eventdata"))
        .filter(|e| e.is_object())
        .and_then(|e| e.get("ipAddress").filter(|v| v.is_string()).or_else(|| e.get("destinationIp").filter(|v| v.is_string())));
    let ip = match win {
        Some(v) => v,
        None => data.get("srcip").filter(|v| v.is_string())?,
    };
    let ip = String::from_utf8_lossy(ip.as_bytes()?).into_owned();
    get_ip_version(&ip).map(|_| ip)
}

/// `get_ip_version`: 4, 6, or None (`getaddrinfo` with `AI_NUMERICHOST`).
pub fn get_ip_version(ip: &str) -> Option<u8> {
    let c = std::ffi::CString::new(ip).ok()?;
    #[cfg(unix)]
    // SAFETY: getaddrinfo with a valid C string and hints; the result is freed.
    unsafe {
        let mut hint: libc::addrinfo = std::mem::zeroed();
        hint.ai_family = libc::AF_UNSPEC;
        hint.ai_flags = libc::AI_NUMERICHOST;
        let mut res: *mut libc::addrinfo = std::ptr::null_mut();
        if libc::getaddrinfo(c.as_ptr(), std::ptr::null(), &hint, &mut res) != 0 || res.is_null() {
            return None;
        }
        let fam = (*res).ai_family;
        libc::freeaddrinfo(res);
        match fam {
            libc::AF_INET => Some(4),
            libc::AF_INET6 => Some(6),
            _ => None,
        }
    }
    #[cfg(windows)]
    // SAFETY: getaddrinfo with a valid C string and hints; the result is freed.
    unsafe {
        use windows_sys::Win32::Networking::WinSock::{freeaddrinfo, getaddrinfo, WSAStartup, ADDRINFOA, AF_INET, AF_INET6, AF_UNSPEC, AI_NUMERICHOST, WSADATA};
        let mut wsa: WSADATA = std::mem::zeroed();
        WSAStartup(0x0202, &mut wsa);
        let mut hint: ADDRINFOA = std::mem::zeroed();
        hint.ai_family = AF_UNSPEC as i32;
        hint.ai_flags = AI_NUMERICHOST as i32;
        let mut res: *mut ADDRINFOA = std::ptr::null_mut();
        if getaddrinfo(c.as_ptr().cast(), std::ptr::null(), &hint, &mut res) != 0 || res.is_null() {
            return None;
        }
        let fam = (*res).ai_family;
        freeaddrinfo(res);
        if fam == AF_INET as i32 {
            Some(4)
        } else if fam == AF_INET6 as i32 {
            Some(6)
        } else {
            None
        }
    }
}

/// `get_extra_args_from_json`: the string items joined with spaces.
pub fn get_extra_args_from_json(input: &Json) -> Option<String> {
    let args = input.get("parameters")?.get("extra_args").filter(|a| a.is_array())?;
    let mut out = String::new();
    for a in args.children() {
        if let Some(s) = a.as_str() {
            if out.len() + s.len() + 2 > COMMANDSIZE_4096 {
                break;
            }
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&s);
        }
    }
    (!out.is_empty()).then_some(out)
}

/// `get_binary_path`: (found, the full path or the name itself).
pub fn get_binary_path(binary: &str) -> (bool, String) {
    let abs = if cfg!(windows) { binary.as_bytes().get(1) == Some(&b':') || binary.starts_with('\\') } else { binary.starts_with('/') };
    if abs {
        return (std::path::Path::new(binary).is_file(), binary.to_string());
    }
    let Ok(env) = std::env::var("PATH") else { return (false, binary.to_string()) };
    let (sep, slash) = if cfg!(windows) { (';', '\\') } else { (':', '/') };
    for dir in env.split(sep).filter(|d| !d.is_empty()) {
        let full = format!("{dir}{slash}{binary}");
        if std::path::Path::new(&full).is_file() {
            return (true, full);
        }
    }
    (false, binary.to_string())
}

/// The command `wpopenv` starts. Windows: the command line is `"path"`
/// and the arguments joined with spaces, unquoted, as C builds it.
fn command(path: &str, args: &[&str]) -> std::process::Command {
    let mut c = std::process::Command::new(path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        for a in args {
            c.raw_arg(a);
        }
        // CREATE_NO_WINDOW
        c.creation_flags(0x0800_0000);
    }
    #[cfg(unix)]
    c.args(args);
    c
}

/// `wpopenv(path, argv, W_BIND_STDERR)` + `wpclose`: run and wait; false
/// when it cannot start.
pub fn run(path: &str, args: &[&str]) -> bool {
    let mut c = command(path, args);
    c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    match c.spawn() {
        Ok(mut ch) => {
            let _ = ch.wait();
            true
        }
        Err(_) => false,
    }
}

/// `wpopenv(path, argv, W_BIND_STDOUT)`: the program's output lines, None
/// when it cannot start.
pub fn run_output(path: &str, args: &[&str]) -> Option<Vec<u8>> {
    let mut c = command(path, args);
    c.stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    c.output().ok().map(|o| o.stdout)
}

/// `lock`: the response's lock directory with its pid file (`mkdir` is the lock).
#[cfg(unix)]
pub fn lock(lock_path: &str, lock_pid_path: &str, log_path: &str, proc_name: &str) -> bool {
    use std::os::unix::fs::DirBuilderExt;
    let take = || std::fs::DirBuilder::new().mode(0o070).create(lock_path).is_ok();
    let write_pid = || match std::fs::write(lock_pid_path, std::process::id().to_string()) {
        Ok(()) => true,
        Err(_) => {
            write_debug_file(log_path, b"Cannot write pid file");
            false
        }
    };
    let max_iteration = 50;
    let mut i = 0;
    let mut saved_pid = -1;
    loop {
        let mut current_pid = -1;
        if take() {
            return write_pid();
        }
        match std::fs::read_to_string(lock_pid_path) {
            Err(_) => write_debug_file(log_path, b"Cannot read pid file"),
            Ok(t) => match t.trim_start().split(|c: char| !c.is_ascii_digit() && c != '-').next().and_then(|n| n.parse::<i32>().ok()) {
                Some(p) => {
                    current_pid = p;
                    if saved_pid == -1 {
                        saved_pid = p;
                    }
                    if p == saved_pid {
                        i += 1;
                    }
                }
                None => write_debug_file(log_path, b"Cannot read pid file"),
            },
        }
        std::thread::sleep(std::time::Duration::from_secs(i as u64));
        i += 1;
        if i >= max_iteration {
            let mut killed = false;
            let (found, pgrep) = get_binary_path("pgrep");
            if !found {
                write_debug_file(log_path, format!("Binary '{pgrep}' not found in default paths, the full path will not be used.").as_bytes());
            }
            match run_output(&pgrep, &["-f", proc_name]) {
                None => write_debug_file(log_path, b"Unable to run pgrep"),
                Some(out) => {
                    for line in out.split(|&c| c == b'\n') {
                        let pid = atoi(line);
                        if pid == current_pid {
                            let (found, kill) = get_binary_path("kill");
                            if !found {
                                write_debug_file(log_path, format!("Binary '{kill}' not found in default paths, the full path will not be used.").as_bytes());
                            }
                            if run_output(&kill, &["-9", &pid.to_string()]).is_none() {
                                write_debug_file(log_path, b"Unable to run kill");
                            } else {
                                write_debug_file(log_path, format!("Killed process {pid} holding lock.").as_bytes());
                                killed = true;
                                unlock(lock_path, log_path);
                                i = 0;
                                saved_pid = -1;
                            }
                            break;
                        }
                    }
                }
            }
            if !killed {
                write_debug_file(log_path, format!("Unable to kill process {current_pid} holding lock.").as_bytes());
                unlock(lock_path, log_path);
                if take() {
                    let _ = std::fs::write(lock_pid_path, std::process::id().to_string());
                    return true;
                }
                return false;
            }
        }
    }
}

/// `unlock`
#[cfg(unix)]
pub fn unlock(lock_path: &str, log_path: &str) {
    if std::fs::remove_dir_all(lock_path).is_err() {
        write_debug_file(log_path, b"Unable to remove lock folder");
    }
}

/// C `atoi` of the start of a line.
#[cfg(unix)]
fn atoi(b: &[u8]) -> i32 {
    let s = String::from_utf8_lossy(b);
    let t = s.trim_start();
    let end = t.char_indices().take_while(|(i, c)| c.is_ascii_digit() || (*i == 0 && (*c == '-' || *c == '+'))).count();
    t[..end].parse().unwrap_or(0)
}

/// The program name as execd started it (`argv[0]`).
pub fn argv0() -> String {
    std::env::args().next().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_and_ip_like_c() {
        let m = br#"{"version":1,"origin":{"name":"x","module":"wazuh-execd"},"command":"add","parameters":{"extra_args":["a","b"],"alert":{"data":{"srcip":"10.0.0.5"}}}}"#;
        let j = get_json_from_input(m).unwrap();
        assert_eq!(get_srcip_from_json(&j).as_deref(), Some("10.0.0.5"));
        assert_eq!(get_extra_args_from_json(&j).as_deref(), Some("a b"));
        assert!(get_json_from_input(br#"{"version":1,"command":"add","parameters":{}}"#).is_none());
        let w = br#"{"version":1,"origin":{},"command":"add","parameters":{"alert":{"data":{"srcip":"1.1.1.1","win":{"eventdata":{"ipAddress":"2001:db8::1"}}}}}}"#;
        assert_eq!(get_srcip_from_json(&get_json_from_input(w).unwrap()).as_deref(), Some("2001:db8::1"));
        assert_eq!(get_ip_version("10.0.0.300"), None);
        assert_eq!(build_json_keys_message("netsh.exe", &["1.2.3.4"]), br#"{"version":1,"origin":{"name":"netsh.exe","module":"active-response"},"command":"check_keys","parameters":{"keys":["1.2.3.4"]}}"#);
    }
}
