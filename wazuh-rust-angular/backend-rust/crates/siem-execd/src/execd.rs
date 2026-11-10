//! `os_execd/execd.c`: the timeout list (`ExecdTimeoutRun`,
//! `ExecdShutdown`), one active response (`ExecdRun`), the Unix main loop
//! (`ExecdStart`) and the Windows start-up (`WinExecdStart`).

use std::sync::Arc;

use siem_cjson::Json;

use crate::wfd::{wpclose, wpopenv, W_BIND_STDIN, W_BIND_STDOUT};
use crate::*;

/// `EXEC_CMD_FAIL`
fn cmd_fail() -> String {
    let e = errno();
    format!("(1317): Could not launch command {} ({e})", strerror(e))
}

/// Run `command` with `parameters` on its stdin and wait (the timeout and
/// shutdown "delete" calls).
fn run_delete(ex: &Execd, command: &str, parameters: &[u8]) {
    match wpopenv(&ex.log, command, &[command], W_BIND_STDIN) {
        Some(mut w) => {
            w.write_line(parameters);
            wpclose(&ex.log, w);
        }
        None => ex.log.error(cmd_fail()),
    }
}

/// `ExecdShutdown`: run the pending deletes.
pub fn execd_shutdown(ex: &Execd) {
    ex.log.info(EXEC_SHUTDOWN);
    let pending = ex.timeout_list.lock().unwrap().as_mut().map(std::mem::take).unwrap_or_default();
    for e in pending {
        ex.log.debug2(format!("Delete pending AR: '{}' '{}'", e.command, String::from_utf8_lossy(&e.parameters)));
        run_delete(ex, &e.command, &e.parameters);
    }
}

/// `ExecdTimeoutRun`: run the deletes whose timeout passed. Returns the
/// number of children started (`childcount`).
pub fn execd_timeout_run(ex: &Execd) -> i32 {
    let curr_time = now();
    let mut started = 0;
    let mut list = ex.timeout_list.lock().unwrap();
    let Some(l) = list.as_mut() else { return 0 };
    let mut i = 0;
    while i < l.len() {
        if curr_time - l[i].time_of_addition > l[i].time_to_block as i64 {
            let e = l.remove(i);
            ex.log.debug1(format!(
                "Executing command '{} {}' after a timeout of '{}s'",
                e.command,
                String::from_utf8_lossy(&e.parameters),
                e.time_to_block
            ));
            run_delete(ex, &e.command, &e.parameters);
            started += 1;
        } else {
            i += 1;
        }
    }
    started
}

/// `get_json_from_input` (`active-response/active_responses.c`)
fn get_json_from_input(input: &[u8]) -> Option<Json> {
    let (j, _) = siem_cjson::parse_with_opts(input, false).ok()?;
    if !j.get("version").map(|v| v.is_number()).unwrap_or(false)
        || !j.get("origin").map(|v| v.is_object()).unwrap_or(false)
        || !j.get("command").map(|v| v.is_string()).unwrap_or(false)
        || !j.get("parameters").map(|v| v.is_object()).unwrap_or(false)
    {
        return None;
    }
    Some(j)
}

/// `get_keys_from_json`: `-key1-key2...` (at most `COMMANDSIZE_4096 - 1`).
fn get_keys_from_json(j: &Json) -> Option<String> {
    let p = j.get("parameters").filter(|p| p.is_object())?;
    let keys = p.get("keys").filter(|k| k.is_array())?;
    let mut args = String::new();
    for k in keys.children() {
        if k.is_string() {
            let s = k.as_str().unwrap_or_default();
            if args.len() + s.len() + 2 > OS_SIZE_4096 {
                break;
            }
            args.push('-');
            args.push_str(&s);
        }
    }
    (!args.is_empty()).then_some(args)
}

/// `ExecdRun`: run the active response of `exec_msg`. Returns the number of
/// children started.
pub fn execd_run(ex: &Execd, exec_msg: &[u8]) -> i32 {
    let curr_time = now();
    let Some(mut root) = siem_cjson::parse(exec_msg) else {
        ex.log.error(format!("(1315): Invalid JSON message: '{}'", String::from_utf8_lossy(exec_msg)));
        return 0;
    };
    let name = match root.get("command") {
        Some(c) if c.is_string() => c.as_str().unwrap_or_default().into_owned(),
        _ => {
            ex.log.error(format!("(1316): Invalid AR command: '{}'", String::from_utf8_lossy(exec_msg)));
            return 0;
        }
    };

    #[cfg(unix)]
    if name == "restart-wazuh" {
        crate::exec::exec_cmd(ex, &["active-response/bin/restart.sh", "agent"]);
        return 0;
    }

    // Get the command to execute
    let (cmd0, mut timeout_value) = match crate::exec::get_command_by_name(ex, &name) {
        Some(c) => c,
        None => {
            crate::exec::read_exec_config(ex);
            match crate::exec::get_command_by_name(ex, &name) {
                Some(c) => c,
                None => {
                    ex.log.error(format!("(1311): Invalid command name '{name}' provided."));
                    return 0;
                }
            }
        }
    };
    if cmd0.is_empty() {
        return 0;
    }

    // Command parameters
    json_replace(Some(&mut root), "command", Json::string(ADD_ENTRY));
    json_replace(root.get_mut("origin"), "module", Json::string(EXECD_NAME));
    if let Some(p) = root.get_mut("parameters") {
        p.add("program", Json::string(&cmd0));
    }
    let cmd_parameters = root.print_unformatted();

    ex.log.debug1(format!("Executing command '{cmd0} {}'", String::from_utf8_lossy(&cmd_parameters)));

    let Some(mut w) = wpopenv(&ex.log, &cmd0, &[&cmd0], W_BIND_STDIN | W_BIND_STDOUT) else {
        ex.log.error(cmd_fail());
        return 0;
    };
    w.write_line(&cmd_parameters);

    // Receive the alert keys from the AR script to check the timeout list
    let Some(response) = w.fgets(OS_SIZE_8192) else {
        ex.log.debug1(format!(
            "Active response won't be added to timeout list. Message not received with alert keys from script '{cmd0}'"
        ));
        wpclose(&ex.log, w);
        return 0;
    };

    // Set rkey initially with the name of the AR
    let mut rkey = trunc(basename_ex(&cmd0), OS_SIZE_4096 - 1);
    if let Some(kj) = get_json_from_input(&response) {
        let action = kj.get("command").and_then(|c| c.as_str()).map(|c| c.into_owned());
        if action.as_deref() == Some(CHECK_KEYS_ENTRY) {
            if let Some(keys) = get_keys_from_json(&kj) {
                if rkey.len() + keys.len() >= OS_SIZE_4096 {
                    ex.log.warn(format!("Active response key exceeds maximum size ({OS_SIZE_4096}). Truncating keys."));
                }
                // strncat(rkey, keys, OS_SIZE_4096 - rkey_len - 1)
                let room = OS_SIZE_4096 - rkey.len() - 1;
                rkey.push_str(&trunc(&keys, room + 1));
            }
        }
    }

    let mut added_before = false;
    if timeout_value != 0 {
        let rot = *ex.repeated_offenders_timeout.lock().unwrap();
        let mut rh = ex.repeated_hash.lock().unwrap();
        if let Some(h) = rh.as_mut() {
            if let Some(ntimes) = h.get(&rkey).cloned() {
                let ntimes_int = siem_config::util::atoi(&ntimes);
                let i2 = rot.iter().take_while(|&&v| v != 0).count() as i32;
                let new_timeout = if ntimes_int >= i2 {
                    rot[(i2 - 1).max(0) as usize] * 60
                } else {
                    let t = rot[ntimes_int.max(0) as usize] * 60;
                    h.insert(rkey.clone(), (ntimes_int + 1).to_string());
                    t
                };
                ex.log.debug1(format!("Repeated offender. Setting timeout to '{new_timeout}s'"));
                timeout_value = new_timeout;
            } else {
                h.insert(rkey.clone(), "0".to_string());
            }
        }
        drop(rh);

        // Check if this command was already executed
        {
            let mut list = ex.timeout_list.lock().unwrap();
            if let Some(l) = list.as_mut() {
                if let Some(e) = l.iter_mut().find(|e| e.rkey == rkey) {
                    added_before = true;
                    ex.log.debug1("Command already received, updating time of addition to now.");
                    e.time_of_addition = curr_time;
                    e.time_to_block = timeout_value;
                }
            }
        }

        // If it was not added before, do it now
        if !added_before {
            json_replace(Some(&mut root), "command", Json::string(DELETE_ENTRY));
            let entry = TimeoutData {
                command: cmd0.clone(),
                parameters: root.print_unformatted(),
                rkey: rkey.clone(),
                time_of_addition: curr_time,
                time_to_block: timeout_value,
            };
            ex.log.debug1(format!(
                "Adding command '{} {}' to the timeout list, with a timeout of '{}s'.",
                entry.command,
                String::from_utf8_lossy(&entry.parameters),
                entry.time_to_block
            ));
            if let Some(l) = ex.timeout_list.lock().unwrap().as_mut() {
                l.push(entry);
            }
        }
    }

    // Continue, or abort a command already in the list
    let c = if !added_before { CONTINUE_ENTRY } else { ABORT_ENTRY };
    json_replace(Some(&mut root), "command", Json::string(c));
    let cmd_parameters = root.print_unformatted();
    w.write_line(&cmd_parameters);
    wpclose(&ex.log, w);
    1
}

/// `ExecdStart`: the Unix main loop on the exec queue.
#[cfg(unix)]
pub fn execd_start(ex: &Execd, q: i32) -> ! {
    *ex.timeout_list.lock().unwrap() = Some(Vec::new());
    if ex.repeated_offenders_timeout.lock().unwrap()[0] != 0 {
        *ex.repeated_hash.lock().unwrap() = Some(Default::default());
    }
    let mut childcount = 0;
    loop {
        // Clean up any children
        while childcount > 0 {
            // SAFETY: reaping our own children.
            let wp = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
            if wp < 0 && errno() != libc::ECHILD {
                let e = errno();
                ex.log.error(format!("(1111): Error during waitpid()-call due to [({e})-({})].", strerror(e)));
                break;
            } else if wp == 0 {
                break;
            } else {
                childcount -= 1;
            }
        }
        childcount += execd_timeout_run(ex);

        match siem_ipc::os_net::wnet_select(q, EXECD_TIMEOUT) {
            0 => continue,
            r if r < 0 => {
                let e = errno();
                ex.log.error(format!("(1114): Error during select()-call due to [({e})-({})].", strerror(e)));
                continue;
            }
            _ => {}
        }
        let mut buf = Vec::new();
        if siem_ipc::os_net::recv_unix(q, OS_MAXSTR, &mut buf) == 0 {
            let e = errno();
            ex.log.error(format!("(1210): Queue '{EXECQUEUE}' not accessible: '{}'", strerror(e)));
            continue;
        }
        let msg = buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())].to_vec();
        ex.log.debug2(format!("Received message: '{}'", String::from_utf8_lossy(&msg)));
        childcount += execd_run(ex, &msg);
    }
}

/// `winexec_queue` (`queue_init(OS_SIZE_128)`: 127 messages; more are
/// dropped).
pub struct ExecQueue {
    q: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
    available: std::sync::Condvar,
}

impl ExecQueue {
    pub fn new() -> ExecQueue {
        ExecQueue { q: std::sync::Mutex::new(Default::default()), available: std::sync::Condvar::new() }
    }

    /// `queue_push_ex`: -1 when full.
    pub fn push(&self, m: &[u8]) -> i32 {
        let mut q = self.q.lock().unwrap();
        if q.len() >= 127 {
            return -1;
        }
        q.push_back(m.to_vec());
        self.available.notify_one();
        0
    }

    /// `queue_pop_ex`
    pub fn pop(&self) -> Vec<u8> {
        let mut q = self.q.lock().unwrap();
        loop {
            if let Some(m) = q.pop_front() {
                return m;
            }
            q = self.available.wait(q).unwrap();
        }
    }
}

impl Default for ExecQueue {
    fn default() -> Self {
        Self::new()
    }
}

static WIN_EXECD: std::sync::OnceLock<Arc<Execd>> = std::sync::OnceLock::new();

extern "C" fn shutdown_hook() {
    if let Some(ex) = WIN_EXECD.get() {
        execd_shutdown(ex);
    }
}

/// `WinExecdStart`: read the configuration, and unless active response is
/// disabled start `win_exec_main` on `queue`. True when it runs.
pub fn win_execd_start(ex: &Arc<Execd>, queue: &Arc<ExecQueue>) -> bool {
    let c = crate::config::execd_config(ex, OSSECCONF);
    if c < 0 {
        ex.exit_error(format!("(1202): Configuration error at '{OSSECCONF}'."));
    }
    if c == 1 {
        ex.log.info(EXEC_DISABLED);
        return false;
    }
    *ex.timeout_list.lock().unwrap() = Some(Vec::new());
    if ex.repeated_offenders_timeout.lock().unwrap()[0] != 0 {
        *ex.repeated_hash.lock().unwrap() = Some(Default::default());
    }
    // Delete pending AR at a successful exit
    let _ = WIN_EXECD.set(Arc::clone(ex));
    siem_log::cexit::register(shutdown_hook);
    ex.log.info(format!("Started (pid: {}).", std::process::id()));
    let (e, q) = (Arc::clone(ex), Arc::clone(queue));
    let _ = std::thread::Builder::new().name("win_exec_main".into()).spawn(move || loop {
        let m = q.pop();
        execd_run(&e, &m);
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_input() {
        let j = get_json_from_input(br#"{"version":1,"origin":{},"command":"check_keys","parameters":{"keys":["1.2.3.4",5,"x"]}}"#)
            .unwrap();
        assert_eq!(get_keys_from_json(&j).as_deref(), Some("-1.2.3.4-x"));
        assert!(get_json_from_input(br#"{"version":"1","origin":{},"command":"x","parameters":{}}"#).is_none());
    }
}
