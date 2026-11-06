//! What every ProVigil response program shares: reading and checking the request the
//! agent writes on standard input, asking the agent before a block that can be undone,
//! the response log, finding and starting other programs, and a lock so that only one
//! copy of a response runs its critical part at a time.

pub mod edr;
pub mod live;
pub mod tamper;
pub mod yara;

#[cfg(windows)]
pub mod dll_guard;

use std::ffi::OsStr;
use std::io::{BufRead, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

/// The response log, relative to the agent's folder (the programs' working directory).
#[cfg(windows)]
pub const LOG_FILE: &str = "active-response\\active-responses.log";
#[cfg(not(windows))]
pub const LOG_FILE: &str = "logs/active-responses.log";

/// Longest request line read.
pub const MAX_LINE: usize = 64 * 1024;
/// Longest extra arguments text.
pub const MAX_EXTRA_ARGS: usize = 4 * 1024;

#[cfg(windows)]
const EOL: &str = "\r\n";
#[cfg(not(windows))]
const EOL: &str = "\n";

/// The program name as started.
pub fn argv0() -> String {
    std::env::args().next().unwrap_or_default()
}

fn debug_line(program: &str, message: &[u8]) -> String {
    format!("{} {program}: {}\n", chrono::Local::now().format("%Y/%m/%d %H:%M:%S"), String::from_utf8_lossy(message))
}

/// Appends one line to the response log; errors are ignored.
pub fn write_debug_file(program: &str, message: &[u8]) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(LOG_FILE) {
        let _ = f.write_all(debug_line(program, message).as_bytes());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Add,
    Delete,
    Continue,
    Abort,
}

/// One line (at most [`MAX_LINE`] bytes), its `\n` / `\r\n` end removed; None at end of input.
fn read_line<R: BufRead>(input: &mut R) -> Option<String> {
    let mut buf = Vec::new();
    let n = input.take(MAX_LINE as u64 + 2).read_until(b'\n', &mut buf).ok()?;
    if n == 0 {
        return None;
    }
    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// The command of a well-formed message, and the message.
fn check_message(line: &str) -> Result<(Action, Value), String> {
    if line.len() > MAX_LINE {
        return Err("Input too long".into());
    }
    let msg: Value = serde_json::from_str(line).map_err(|_| "Cannot parse input to json".to_string())?;
    if !msg.get("version").is_some_and(Value::is_number) {
        return Err("Invalid message: 'version' is missing or not a number".into());
    }
    if !msg.get("origin").is_some_and(Value::is_object) {
        return Err("Invalid message: 'origin' is missing or not an object".into());
    }
    let command = msg.get("command").and_then(Value::as_str).ok_or("Invalid message: 'command' is missing or not a text")?;
    if !msg.get("parameters").is_some_and(Value::is_object) {
        return Err("Invalid message: 'parameters' is missing or not an object".into());
    }
    let action = match command {
        "add" => Action::Add,
        "delete" => Action::Delete,
        "continue" => Action::Continue,
        "abort" => Action::Abort,
        c => return Err(format!("Invalid value of 'command': {c}")),
    };
    Ok((action, msg))
}

fn setup_from<R: BufRead>(program: &str, input: &mut R) -> Option<(Action, Value)> {
    write_debug_file(program, b"Starting");
    let Some(line) = read_line(input) else {
        write_debug_file(program, b"Cannot read input");
        return None;
    };
    write_debug_file(program, line.as_bytes());
    match check_message(&line) {
        Ok((a @ (Action::Add | Action::Delete), msg)) => Some((a, msg)),
        Ok(_) => {
            write_debug_file(program, b"Invalid value of 'command'");
            None
        }
        Err(e) => {
            write_debug_file(program, e.as_bytes());
            None
        }
    }
}

/// Reads and checks the request: `Add` or `Delete` and the whole message.
pub fn setup_and_check_message(program: &str) -> Option<(Action, Value)> {
    setup_from(program, &mut std::io::stdin().lock())
}

fn keys_line(program: &str, key: &str) -> String {
    let name = Path::new(program).file_name().map_or_else(|| program.to_string(), |n| n.to_string_lossy().into_owned());
    let m = json!({"version": 1, "origin": {"name": name, "module": "active-response"}, "command": "check_keys", "parameters": {"keys": [key]}});
    format!("{m}{EOL}")
}

fn check_keys_with<R: BufRead, W: Write>(program: &str, key: &str, input: &mut R, output: &mut W) -> Result<(), i32> {
    if output.write_all(keys_line(program, key).as_bytes()).and_then(|_| output.flush()).is_err() {
        write_debug_file(program, b"Cannot send the keys to check");
        return Err(-1);
    }
    let Some(line) = read_line(input) else {
        write_debug_file(program, b"Cannot read the answer to the keys check");
        return Err(-1);
    };
    write_debug_file(program, line.as_bytes());
    match check_message(&line) {
        Ok((Action::Continue, _)) => Ok(()),
        Ok((Action::Abort, _)) => {
            write_debug_file(program, b"Aborted");
            Err(0)
        }
        Ok(_) => {
            write_debug_file(program, b"Invalid value of 'command' in the keys check answer");
            Err(-1)
        }
        Err(e) => {
            write_debug_file(program, e.as_bytes());
            Err(-1)
        }
    }
}

/// Asks the agent whether `key` is already active: Ok to go on, Err(exit code) to stop.
pub fn check_keys(program: &str, key: &str) -> Result<(), i32> {
    check_keys_with(program, key, &mut std::io::stdin().lock(), &mut std::io::stdout().lock())
}

fn find_binary(name: &str, path_var: Option<&OsStr>) -> (bool, String) {
    let p = Path::new(name);
    if p.is_absolute() {
        return (p.is_file(), name.to_string());
    }
    for dir in path_var.map(|v| std::env::split_paths(v).collect::<Vec<PathBuf>>()).unwrap_or_default() {
        let full = dir.join(name);
        if full.is_file() {
            return (true, full.to_string_lossy().into_owned());
        }
    }
    (false, name.to_string())
}

/// Whether the program was found, and its full path (the name itself when not found).
pub fn get_binary_path(name: &str) -> (bool, String) {
    find_binary(name, std::env::var_os("PATH").as_deref())
}

fn command(path: &str, args: &[&str]) -> Command {
    let mut c = Command::new(path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
        // netsh, route and reg take their arguments as written: no quoting added
        for a in args {
            c.raw_arg(a);
        }
    }
    #[cfg(not(windows))]
    c.args(args);
    c.stdin(Stdio::null());
    c
}

/// Runs the program and waits; true when it could be started (whatever its exit code).
pub fn run(path: &str, args: &[&str]) -> bool {
    command(path, args).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
}

/// Runs the program and waits; what it printed on standard output.
pub fn run_output(path: &str, args: &[&str]) -> Option<Vec<u8>> {
    command(path, args).stdout(Stdio::piped()).stderr(Stdio::null()).output().ok().map(|o| o.stdout)
}

/// 4, 6, or None when `ip` is not an IP address.
pub fn ip_version(ip: &str) -> Option<u8> {
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(_) => Some(4),
        IpAddr::V6(_) => Some(6),
    }
}

/// The attacker IP of the alert: the Windows event's `ipAddress`, else its `destinationIp`,
/// else `srcip`; None when the field found is not a valid IP address.
pub fn alert_ip(msg: &Value) -> Option<String> {
    let data = &msg["parameters"]["alert"]["data"];
    let ev = &data["win"]["eventdata"];
    let ip = [&ev["ipAddress"], &ev["destinationIp"], &data["srcip"]].into_iter().find_map(Value::as_str)?;
    ip_version(ip).map(|_| ip.to_string())
}

/// The text items of `parameters.extra_args`, joined with spaces (at most [`MAX_EXTRA_ARGS`] bytes).
pub fn extra_args(msg: &Value) -> String {
    let items: Vec<&str> = msg["parameters"]["extra_args"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    let mut s = items.join(" ");
    if s.len() > MAX_EXTRA_ARGS {
        let mut end = MAX_EXTRA_ARGS;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

/// Lock waits: attempt `n` pauses `n * LOCK_WAIT_MS` (1..=10 s, 55 s in all).
static LOCK_WAIT_MS: AtomicU64 = AtomicU64::new(1000);
const LOCK_ATTEMPTS: u64 = 10;

fn read_pid(pid_file: &str) -> Option<u32> {
    std::fs::read_to_string(pid_file).ok()?.trim().parse().ok()
}

/// One attempt: Ok when the lock is ours, else the holder's pid (when readable).
fn try_lock(lock_dir: &str, pid_file: &str) -> Result<(), Option<u32>> {
    if let Some(parent) = Path::new(lock_dir).parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = std::fs::create_dir_all(parent);
    }
    // creating a folder is atomic: whoever creates it holds the lock
    match std::fs::create_dir(lock_dir) {
        Ok(()) => {
            let _ = std::fs::write(pid_file, std::process::id().to_string());
            Ok(())
        }
        Err(_) => Err(read_pid(pid_file)),
    }
}

/// Ends the stuck holder when it runs as `process_name`; true when it was ended.
#[cfg(target_os = "linux")]
fn end_holder(pid: u32, process_name: &str) -> bool {
    if pid == std::process::id() || pid == 0 {
        return false;
    }
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let arg0 = cmdline.split(|b| *b == 0).next().map(|a| String::from_utf8_lossy(a).into_owned()).unwrap_or_default();
    let base = Path::new(&arg0).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    // the kernel cuts comm to 15 characters
    let short: String = process_name.chars().take(15).collect();
    if base != process_name && comm.trim() != short {
        return false;
    }
    // SAFETY: a plain signal to a process id
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) == 0 }
}

#[cfg(not(target_os = "linux"))]
fn end_holder(_pid: u32, _process_name: &str) -> bool {
    false
}

/// Takes the lock, waiting for (or taking over from) a stuck holder; false when it cannot.
pub fn lock(lock_dir: &str, pid_file: &str, program: &str, process_name: &str) -> bool {
    let mut first: Option<Option<u32>> = None;
    let mut changed = false;
    for n in 1..=LOCK_ATTEMPTS + 1 {
        match try_lock(lock_dir, pid_file) {
            Ok(()) => return true,
            Err(holder) => changed |= *first.get_or_insert(holder) != holder,
        }
        if n <= LOCK_ATTEMPTS {
            std::thread::sleep(Duration::from_millis(n * LOCK_WAIT_MS.load(Ordering::Relaxed)));
        }
    }
    let holder = read_pid(pid_file);
    if changed || first != Some(holder) {
        write_debug_file(program, b"Unable to take lock: it keeps changing hands");
        return false;
    }
    let pid = holder.unwrap_or(0);
    if end_holder(pid, process_name) {
        write_debug_file(program, format!("Lock held too long by process {pid}: ended it and took the lock").as_bytes());
    } else {
        write_debug_file(program, format!("Lock held too long by process {pid}: removed the stale lock").as_bytes());
    }
    let _ = std::fs::remove_dir_all(lock_dir);
    if try_lock(lock_dir, pid_file).is_ok() {
        return true;
    }
    write_debug_file(program, b"Unable to take lock");
    false
}

pub fn unlock(lock_dir: &str, program: &str) {
    if let Err(e) = std::fs::remove_dir_all(lock_dir) {
        write_debug_file(program, format!("Unable to remove lock folder {lock_dir}: {e}").as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{"version":1,"origin":{"name":"node01","module":"wazuh-execd"},"command":"add","parameters":{"extra_args":["-a","b"],"alert":{"data":{"srcip":"10.0.0.5"}}}}"#;

    #[test]
    fn messages_checked() {
        let (a, m) = check_message(GOOD).unwrap();
        assert_eq!(a, Action::Add);
        assert_eq!(m["parameters"]["alert"]["data"]["srcip"], "10.0.0.5");
        assert_eq!(check_message(&GOOD.replace("\"add\"", "\"delete\"")).unwrap().0, Action::Delete);
        for bad in [
            "not json",
            r#"{"origin":{},"command":"add","parameters":{}}"#,
            r#"{"version":"1","origin":{},"command":"add","parameters":{}}"#,
            r#"{"version":1,"command":"add","parameters":{}}"#,
            r#"{"version":1,"origin":"x","command":"add","parameters":{}}"#,
            r#"{"version":1,"origin":{},"parameters":{}}"#,
            r#"{"version":1,"origin":{},"command":7,"parameters":{}}"#,
            r#"{"version":1,"origin":{},"command":"add"}"#,
            r#"{"version":1,"origin":{},"command":"add","parameters":[]}"#,
            r#"{"version":1,"origin":{},"command":"jump","parameters":{}}"#,
        ] {
            assert!(check_message(bad).is_err(), "{bad}");
        }
        // continue / abort are answers, not requests
        assert!(setup_from("t", &mut r#"{"version":1,"origin":{},"command":"continue","parameters":{}}"#.as_bytes()).is_none());
        let crlf = format!("{GOOD}\r\nsecond line\n");
        let mut input = crlf.as_bytes();
        assert_eq!(setup_from("t", &mut input).unwrap().0, Action::Add);
        assert_eq!(read_line(&mut input).as_deref(), Some("second line"));
        assert!(setup_from("t", &mut "".as_bytes()).is_none());
    }

    #[test]
    fn keys_round_trip() {
        let mut out = Vec::new();
        let answer = |c: &str| format!(r#"{{"version":1,"origin":{{"name":"node01","module":"wazuh-execd"}},"command":"{c}","parameters":{{}}}}"#);
        assert_eq!(check_keys_with("/var/ossec/active-response/bin/firewall-drop", "10.0.0.5", &mut answer("continue").as_bytes(), &mut out), Ok(()));
        let line = String::from_utf8(out).unwrap();
        assert!(line.ends_with(EOL) && line.matches('\n').count() == 1);
        let sent: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(sent, json!({"version":1,"origin":{"name":"firewall-drop","module":"active-response"},"command":"check_keys","parameters":{"keys":["10.0.0.5"]}}));
        let mut sink = Vec::new();
        assert_eq!(check_keys_with("t", "k", &mut format!("{}\r\n", answer("abort")).as_bytes(), &mut sink), Err(0));
        assert_eq!(check_keys_with("t", "k", &mut answer("add").as_bytes(), &mut sink), Err(-1));
        assert_eq!(check_keys_with("t", "k", &mut "garbage".as_bytes(), &mut sink), Err(-1));
        assert_eq!(check_keys_with("t", "k", &mut "".as_bytes(), &mut sink), Err(-1));
    }

    #[test]
    fn attacker_ip() {
        let msg = |data: Value| json!({"parameters": {"alert": {"data": data}}});
        let win = |ev: Value| msg(json!({"srcip": "10.0.0.3", "win": {"eventdata": ev}}));
        assert_eq!(alert_ip(&win(json!({"ipAddress": "10.0.0.1", "destinationIp": "10.0.0.2"}))).as_deref(), Some("10.0.0.1"));
        assert_eq!(alert_ip(&win(json!({"destinationIp": "10.0.0.2"}))).as_deref(), Some("10.0.0.2"));
        assert_eq!(alert_ip(&win(json!({}))).as_deref(), Some("10.0.0.3"));
        assert_eq!(alert_ip(&msg(json!({"srcip": "2001:db8::1"}))).as_deref(), Some("2001:db8::1"));
        assert_eq!(alert_ip(&msg(json!({"srcip": "10.0.0.300"}))), None);
        assert_eq!(alert_ip(&msg(json!({"srcip": "1.2.3.4; rm -rf /"}))), None);
        assert_eq!(alert_ip(&json!({"parameters": {}})), None);
        assert_eq!((ip_version("1.2.3.4"), ip_version("::1"), ip_version("x")), (Some(4), Some(6), None));
    }

    #[test]
    fn extra_args_joined() {
        assert_eq!(extra_args(&json!({"parameters": {"extra_args": ["-a", 3, "b", null, "c d"]}})), "-a b c d");
        assert_eq!(extra_args(&json!({"parameters": {}})), "");
        let long = extra_args(&json!({"parameters": {"extra_args": ["é".repeat(3000)]}}));
        assert!(long.len() <= MAX_EXTRA_ARGS && long.len() > MAX_EXTRA_ARGS - 2);
    }

    #[test]
    fn binary_path() {
        let dir = std::env::temp_dir().join(format!("ar-path-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let tool = dir.join("some-tool");
        std::fs::write(&tool, b"").unwrap();
        let abs = tool.to_string_lossy().into_owned();
        assert_eq!(find_binary(&abs, None), (true, abs.clone()));
        let path_var = std::env::join_paths([std::env::temp_dir().join("ar-none"), dir.clone()]).unwrap();
        assert_eq!(find_binary("some-tool", Some(&path_var)), (true, abs));
        assert_eq!(find_binary("other-tool", Some(&path_var)), (false, "other-tool".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn debug_line_format() {
        let l = debug_line("firewall-drop", b"Starting");
        let (time, rest) = l.split_at(19);
        assert!(chrono::NaiveDateTime::parse_from_str(time, "%Y/%m/%d %H:%M:%S").is_ok(), "{l}");
        assert_eq!(rest, " firewall-drop: Starting\n");
    }

    #[test]
    fn lock_is_exclusive() {
        LOCK_WAIT_MS.store(5, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("ar-lock-test-{}", std::process::id()));
        let dir = base.join("fw-drop").to_string_lossy().into_owned();
        let pid = format!("{dir}/pid");
        assert!(lock(&dir, &pid, "t", "no-such-process"));
        assert_eq!(read_pid(&pid), Some(std::process::id()));
        // a second attempt fails while the first is held
        assert_eq!(try_lock(&dir, &pid), Err(Some(std::process::id())));
        unlock(&dir, "t");
        assert!(try_lock(&dir, &pid).is_ok());
        unlock(&dir, "t");

        // a holder that keeps changing is not taken over
        assert!(try_lock(&dir, &pid).is_ok());
        let (d2, p2) = (dir.clone(), pid.clone());
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let s2 = stop.clone();
        let t = std::thread::spawn(move || {
            let mut n = 1_000_000u32;
            while !s2.load(Ordering::Relaxed) {
                n += 1;
                let _ = std::fs::create_dir_all(&d2);
                // whole pid files only: a half-written one reads as no holder
                let tmp = format!("{p2}.tmp");
                let _ = std::fs::write(&tmp, n.to_string());
                let _ = std::fs::rename(&tmp, &p2);
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        assert!(!lock(&dir, &pid, "t", "no-such-process"));
        stop.store(true, Ordering::Relaxed);
        t.join().unwrap();

        // a stuck holder (same pid all along) loses its stale lock
        std::fs::write(&pid, "4000000000").unwrap();
        assert!(lock(&dir, &pid, "t", "no-such-process"));
        assert_eq!(read_pid(&pid), Some(std::process::id()));
        unlock(&dir, "t");
        let _ = std::fs::remove_dir_all(&base);
    }
}
