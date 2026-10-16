//! The `command` wodle of `wazuh-agent.exe`: `wazuh_modules/wm_command.c`
//! and `config/wmodules-command.c` (Windows branches). Runs a command on a
//! schedule and sends each output line to the manager.

use std::sync::Arc;

use siem_cjson::Json;
use siem_log::WLog;
use siem_sca::sched::{is_sched_tag, sleep_until, timestamp, SchedScan};
use siem_xml::XmlNode;

/// `WM_COMMAND_CONTEXT.name`
pub const NAME: &str = "command";
/// `WM_COMMAND_LOGTAG` (ARGV0 ":command"; the module files are built with ARGV0 "wazuh-modulesd")
const LOGTAG: &str = "wazuh-modulesd:command";
/// `WM_COMMAND_DEFAULT_INTERVAL`
const DEFAULT_INTERVAL: u32 = 2;
/// `LOCALFILE_MQ`
const LOCALFILE_MQ: u8 = b'1';

/// `wm_command_t`
#[derive(Clone, Debug)]
pub struct WmCommand {
    pub tag: Option<String>,
    pub command: Option<String>,
    pub md5_hash: Option<String>,
    pub sha1_hash: Option<String>,
    pub sha256_hash: Option<String>,
    pub enabled: bool,
    pub run_on_start: bool,
    pub ignore_output: bool,
    pub agent_cfg: bool,
    pub skip_verification: bool,
    pub timeout: i32,
    pub scan_config: SchedScan,
}

fn yes_no(content: &str) -> Option<bool> {
    match content {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// `wm_command_read`. `module_tag` is the module's tag (`command:<tag>`,
/// `command` for an empty one). Err: a configuration error (logged here).
pub fn read(log: &WLog, nodes: Option<&[XmlNode]>, agent_cfg: bool, module_tag: &mut Option<String>) -> Result<WmCommand, ()> {
    let Some(nodes) = nodes else {
        log.error(format!("Tag <command> not found at module '{NAME}'."));
        return Err(());
    };
    let mut c = WmCommand {
        tag: None,
        command: None,
        md5_hash: None,
        sha1_hash: None,
        sha256_hash: None,
        enabled: true,
        run_on_start: true,
        ignore_output: false,
        agent_cfg,
        skip_verification: false,
        timeout: 0,
        scan_config: SchedScan { interval: DEFAULT_INTERVAL, ..SchedScan::default() },
    };
    let invalid = |tag: &str| {
        log.error(format!("Invalid content for tag '{tag}' at module '{NAME}'."));
        Err(())
    };
    for n in nodes {
        let content = n.content.as_deref().unwrap_or("");
        match n.element.as_str() {
            "disabled" => match yes_no(content) {
                Some(v) => c.enabled = !v,
                None => return invalid("disabled"),
            },
            "tag" => {
                if content.is_empty() {
                    log.warn(format!("Empty content for tag 'tag' at module '{NAME}'."));
                    *module_tag = Some(NAME.to_string());
                } else {
                    *module_tag = Some(format!("{NAME}:{content}"));
                }
                c.tag = Some(content.to_string());
            }
            "command" => {
                if content.is_empty() {
                    log.error(format!("Empty content for tag 'command' at module '{NAME}'."));
                    return Err(());
                }
                if siem_fileop::crt::is_network_path(content) {
                    log.error(format!("(9801): Network path not allowed in configuration. '{}': {content}.", n.element));
                    c.enabled = false;
                    return Ok(c);
                }
                c.command = Some(content.to_string());
            }
            "run_on_start" => match yes_no(content) {
                Some(v) => c.run_on_start = v,
                None => return invalid("run_on_start"),
            },
            "ignore_output" => match yes_no(content) {
                Some(v) => c.ignore_output = v,
                None => return invalid("ignore_output"),
            },
            "timeout" => {
                // strtol(content, &endptr, 0): the whole content must be a number
                let (v, used) = siem_sca::crt::strtol0(content.as_bytes());
                c.timeout = v as i32;
                if used != content.len() || c.timeout < 0 {
                    return invalid("timeout");
                }
            }
            "verify_md5" => {
                if content.len() != 32 {
                    return invalid("verify_md5");
                }
                c.md5_hash = Some(content.to_string());
            }
            "verify_sha1" => {
                if content.len() != 40 {
                    return invalid("verify_sha1");
                }
                c.sha1_hash = Some(content.to_string());
            }
            "verify_sha256" => {
                if content.len() != 64 {
                    return invalid("verify_sha256");
                }
                c.sha256_hash = Some(content.to_string());
            }
            "skip_verification" => match yes_no(content) {
                Some(v) => c.skip_verification = v,
                None => return invalid("skip_verification"),
            },
            e if is_sched_tag(e) => {}
            e => {
                log.error(format!("No such tag '{e}' at module '{NAME}'."));
                return Err(());
            }
        }
    }
    c.scan_config.read(log, nodes, NAME)?;
    if c.tag.is_none() {
        log.warn(format!("Option <tag> not found at module '{NAME}'."));
        c.tag = Some(String::new());
    }
    if c.command.is_none() {
        log.error(format!("Tag <command> not found at module '{NAME}'."));
        return Err(());
    }
    Ok(c)
}

/// `wm_command_dump`
pub fn dump(c: &WmCommand) -> Json {
    let mut m = Json::object();
    c.scan_config.dump(&mut m);
    let yn = |b: bool| Json::string(if b { "yes" } else { "no" });
    m.add("disabled", yn(!c.enabled));
    m.add("run_on_start", yn(c.run_on_start));
    m.add("ignore_output", yn(c.ignore_output));
    m.add("skip_verification", yn(c.skip_verification));
    for (k, v) in [("tag", &c.tag), ("command", &c.command), ("verify_md5", &c.md5_hash), ("verify_sha1", &c.sha1_hash), ("verify_sha256", &c.sha256_hash)] {
        if let Some(v) = v {
            m.add(k, Json::string(v));
        }
    }
    let mut root = Json::object();
    root.add(NAME, m);
    root
}

/// `w_strtok`: split on spaces, with "double quotes" and `\` escapes.
fn w_strtok(s: &str) -> Vec<String> {
    let s = s.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut accum: Option<Vec<u8>> = None;
    let mut quoting = false;
    let cat = |a: &mut Option<Vec<u8>>, b: &[u8]| a.get_or_insert_with(Vec::new).extend_from_slice(b);
    let mut i = 0;
    while let Some(off) = s[i..].iter().position(|&c| c == b' ' || c == b'"' || c == b'\\') {
        let mut j = i + off;
        match s[j] {
            b' ' => {
                if quoting {
                    cat(&mut accum, &s[i..=j]);
                } else {
                    if j > i {
                        cat(&mut accum, &s[i..j]);
                    }
                    if let Some(a) = accum.take() {
                        out.push(String::from_utf8_lossy(&a).into_owned());
                    }
                }
            }
            b'"' => {
                if j > i || quoting {
                    cat(&mut accum, &s[i..j]);
                }
                quoting = !quoting;
            }
            _ => {
                if j > i {
                    cat(&mut accum, &s[i..j]);
                }
                if j + 1 < s.len() {
                    j += 1;
                    cat(&mut accum, &s[j..=j]);
                }
            }
        }
        i = j + 1;
    }
    if i < s.len() {
        cat(&mut accum, &s[i..]);
    }
    if let Some(a) = accum {
        out.push(String::from_utf8_lossy(&a).into_owned());
    }
    out
}

/// `IsFile`: a regular file.
fn is_file(p: &str) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// `isabspath` (Windows): `X:\` or `X:/`.
fn isabspath(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// `get_binary_path` (Windows): the full path, Err when not found.
fn get_binary_path(binary: &str) -> Result<String, ()> {
    if isabspath(binary) {
        return if is_file(binary) { Ok(binary.to_string()) } else { Err(()) };
    }
    let path = std::env::var("PATH").map_err(|_| ())?;
    for dir in path.split(';').filter(|d| !d.is_empty()) {
        let full = format!("{dir}\\{binary}");
        if is_file(&full) {
            return Ok(full);
        }
    }
    Err(())
}

/// `wm_validate_command`: 1 when the digest of `path` matches.
fn validate_command(log: &WLog, path: &str, digest: &str, kind: &str) -> bool {
    use sha1::Digest;
    // OS_*_File(.., OS_BINARY); an unreadable file never matches
    let Ok(data) = std::fs::read(path) else { return false };
    let hex = |d: &[u8]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let sum = match kind {
        "MD5" => hex(&md5::Md5::digest(&data)),
        "SHA1" => hex(&sha1::Sha1::digest(&data)),
        _ => hex(&sha2::Sha256::digest(&data)),
    };
    log.debug2(format!("Comparing {kind} hash: '{sum}' | '{digest}'"));
    sum.eq_ignore_ascii_case(digest)
}

/// `validate_command_checksums`: false stops the module.
fn validate_checksums(log: &WLog, c: &WmCommand, full_path: &str, full_command: &str) -> bool {
    for (kind, hash) in [("MD5", &c.md5_hash), ("SHA1", &c.sha1_hash), ("SHA256", &c.sha256_hash)] {
        let Some(h) = hash.as_deref().filter(|h| !h.is_empty()) else { continue };
        if !validate_command(log, full_path, h, kind) {
            if c.skip_verification {
                log.tagged(LOGTAG, "WARNING", format!("{kind} checksum verification failed for command '{full_command}'. Skipping..."));
                return true;
            }
            log.tagged(LOGTAG, "ERROR", format!("{kind} checksum verification failed for command '{full_command}'."));
            return false;
        }
        log.tagged(LOGTAG, "DEBUG", format!("{kind} checksum verification was successful for command '{full_command}'."));
    }
    true
}

/// `wm_command_main`. `remote_commands`: `wazuh_command.remote_commands`.
pub fn main(mut c: WmCommand, log: Arc<WLog>, max_eps: i32, remote_commands: bool) {
    let tag = c.tag.clone().unwrap_or_default();
    let command = c.command.clone().unwrap_or_default();
    let usec = 1_000_000 / max_eps.max(1);
    let verify = c.md5_hash.is_some() || c.sha1_hash.is_some() || c.sha256_hash.is_some();
    if !c.enabled {
        log.tagged(LOGTAG, "INFO", format!("Module command:{tag} is disabled. Exiting."));
        return;
    }
    if !remote_commands && c.agent_cfg {
        log.tagged(LOGTAG, "WARNING", format!("Remote commands are disabled. Ignoring '{tag}'."));
        return;
    }
    let mut full_path: Option<String> = None;
    let full_command = if verify {
        let argv = w_strtok(&command);
        let Some(binary) = argv.first() else {
            log.error(format!("Could not split command: {command}"));
            return;
        };
        let Ok(path) = get_binary_path(binary) else {
            log.tagged(LOGTAG, "ERROR", format!("Cannot check binary: '{binary}'. Cannot stat binary file."));
            return;
        };
        // snprintf(.., strlen(full_path) + strlen(command) - strlen(binary) + 1, "%s %s", full_path, command + strlen(binary) + 1)
        let rest = command.get(binary.len() + 1..).unwrap_or("");
        let mut fc = format!("{path} {rest}");
        fc.truncate((path.len() + command.len()).saturating_sub(binary.len()));
        if !validate_checksums(&log, &c, &path, &fc) {
            return;
        }
        full_path = Some(path);
        fc
    } else {
        command.clone()
    };
    log.tagged(LOGTAG, "INFO", format!("Module command:{tag} started"));
    let extag = format!("{NAME}_{tag}");
    // shortcut: the state file (wm_state_io "wodles\command_<tag>") is not read; the C only stores next_time, which nothing uses.
    loop {
        let time_sleep = c.scan_config.time_until_next_scan(&log, LOGTAG, c.run_on_start);
        if time_sleep != 0 {
            let next = c.scan_config.next_scheduled_scan_time;
            log.tagged(LOGTAG, "DEBUG2", format!("Sleeping until: {}", timestamp(next)));
            sleep_until(next);
        }
        if let Some(p) = &full_path {
            if !c.skip_verification {
                log.tagged(LOGTAG, "INFO", format!("Verifying command checksum '{tag}'."));
                if !validate_checksums(&log, &c, p, &full_command) {
                    return;
                }
            }
        }
        log.tagged(LOGTAG, "INFO", format!("Starting command '{tag}'."));
        let e = siem_execd::wm_exec::wm_exec(&log, &full_command, c.timeout.max(0) as u32);
        let output = if c.ignore_output { None } else { e.output };
        match e.retval {
            0 => {
                let status = e.status.unwrap_or(0);
                if status > 0 {
                    log.tagged(LOGTAG, "WARNING", format!("Command '{tag}' returned exit code {status}."));
                    if let Some(o) = &output {
                        log.tagged(LOGTAG, "DEBUG2", [b"OUTPUT: ".as_slice(), o].concat());
                    }
                }
            }
            siem_execd::wm_exec::WM_ERROR_TIMEOUT => {
                log.tagged(LOGTAG, "ERROR", format!("{tag}: Timeout overtaken. You can modify your command timeout at 'ossec.conf'. Exiting..."));
            }
            _ => log.tagged(LOGTAG, "ERROR", format!("Command '{tag}' failed.")),
        }
        if let Some(o) = output {
            // strtok_r(output, "\n"): empty lines are skipped
            for line in o.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                // wm_sendmsg: Sleep(usec / 1000), then SendMSG
                std::thread::sleep(std::time::Duration::from_millis((usec / 1000) as u64));
                if siem_ipc::mq_op::send_msg(0, line, &extag, LOCALFILE_MQ) < 0 {
                    log.debug1(format!("Unable to send message to queue: ({})", std::io::Error::last_os_error()));
                }
            }
        }
        log.tagged(LOGTAG, "DEBUG", format!("Command '{tag}' finished."));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strtok_and_paths() {
        assert_eq!(w_strtok(r#"cmd /c "dir C:\" x"#), vec!["cmd", "/c", "dir C:\" x"]);
        assert_eq!(w_strtok("a  b"), vec!["a", "b"]);
        assert_eq!(w_strtok(r"C:\Windows\cmd.exe /c"), vec!["C:Windowscmd.exe", "/c"]);
        assert!(isabspath(r"C:\x") && isabspath("c:/x") && !isabspath("C:x") && !isabspath(r"\\srv\x"));
    }
}
