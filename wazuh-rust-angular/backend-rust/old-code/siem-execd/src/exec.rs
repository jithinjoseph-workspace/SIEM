//! `os_execd/exec.c`: the `ar.conf` table (`ReadExecConfig`,
//! `GetCommandbyName`) and `ExecCmd`.

use crate::*;

/// `EXEC_INV_CONF`
fn inv_conf() -> String {
    format!("(1313): Invalid active response config: '{DEFAULTAR}'.")
}

/// `ReadExecConfig`: 1, or 0 when `ar.conf` cannot be opened.
pub fn read_exec_config(ex: &Execd) -> i32 {
    let mut t = ex.table.lock().unwrap();
    t.names.clear();
    t.cmds.clear();
    t.timeouts.clear();

    let data = match siem_fileop::crt::read_text(DEFAULTAR) {
        Ok(d) => d,
        Err(e) => {
            let n = e.raw_os_error().unwrap_or(0);
            ex.log.error(format!("(1103): Could not open file '{DEFAULTAR}' due to [({n})-({})].", strerror(n)));
            return 0;
        }
    };
    // fgets(buffer, OS_MAXSTR, fp)
    let mut pos = 0;
    while pos < data.len() {
        let mut end = pos;
        while end < data.len() && end - pos < OS_MAXSTR - 1 {
            end += 1;
            if data[end - 1] == b'\n' {
                break;
            }
        }
        let raw = &data[pos..end];
        pos = end;
        let line = String::from_utf8_lossy(&raw[..raw.iter().position(|&c| c == 0).unwrap_or(raw.len())]).into_owned();

        // The command name must not start with '!'
        if line.starts_with('!') {
            ex.log.error(inv_conf());
            continue;
        }
        let Some(p1) = line.find(" - ") else {
            ex.log.error(inv_conf());
            continue;
        };
        let name_full = &line[..p1];
        let rest = &line[p1 + 3..];
        // snprintf(exec_names[i], OS_FLSIZE + 1, "%s", name)
        let name = trunc(name_full, OS_FLSIZE + 1);
        if name_full.len() >= OS_FLSIZE + 1 {
            ex.log.error(format!("(1318): Command name truncated {name}"));
        }
        let Some(p2) = rest.find(" - ") else {
            ex.log.error(inv_conf());
            continue;
        };
        let cmd_name = &rest[..p2];
        let tail = &rest[p2 + 3..];

        let cmd = if siem_fileop::ref_parent_folder(cmd_name) {
            ex.log.error(format!(
                "Active response command '{cmd_name}' vulnerable to directory traversal attack. Ignoring."
            ));
            String::new()
        } else {
            // snprintf(exec_cmd[i], OS_FLSIZE, "%s/%s", AR_BINDIR, cmd)
            let full = trunc(&format!("{AR_BINDIR}/{cmd_name}"), OS_FLSIZE);
            if open_r(&full) {
                full
            } else {
                if t.read_once {
                    ex.log.info(format!(
                        "Active response command not present: '{full}'. Not using it on this system."
                    ));
                }
                String::new()
            }
        };
        let tail = tail.split('\n').next().unwrap_or("");
        let timeout = siem_config::util::atoi(tail);

        // Check if the name is duplicated
        let mut dup = false;
        for j in 0..t.names.len() {
            if t.names[j] == name {
                if t.cmds[j].is_empty() {
                    t.cmds[j] = cmd.clone();
                    dup = true;
                    break;
                } else if cmd.is_empty() {
                    dup = true;
                }
            }
        }
        if !dup && t.names.len() <= MAX_AR {
            t.names.push(name);
            t.cmds.push(cmd);
            t.timeouts.push(timeout);
        }
    }
    t.read_once = false;
    1
}

/// `wfopen(path, "r")` succeeds (network paths are refused on Windows).
fn open_r(path: &str) -> bool {
    #[cfg(windows)]
    if siem_fileop::crt::is_network_path(path) {
        return false;
    }
    std::fs::File::open(path).is_ok()
}

/// `GetCommandbyName`: the command path and its timeout. `!name` runs
/// `active-response/bin/name` with no timeout.
pub fn get_command_by_name(ex: &Execd, name: &str) -> Option<(String, i32)> {
    if let Some(custom) = name.strip_prefix('!') {
        if siem_fileop::ref_parent_folder(custom) {
            ex.log.warn(format!(
                "Active response command '{custom}' vulnerable to directory traversal attack. Ignoring."
            ));
            return None;
        }
        let command = format!("{AR_BINDIR}/{custom}");
        if command.len() >= OS_FLSIZE {
            ex.log.warn(format!("Cannot execute command '{custom:>32}...': path too long."));
            return None;
        }
        return Some((command, 0));
    }
    let t = ex.table.lock().unwrap();
    t.names.iter().position(|n| n == name).map(|i| (t.cmds[i].clone(), t.timeouts[i]))
}

/// `ExecCmd`: fork and run `cmd` without waiting.
#[cfg(unix)]
pub fn exec_cmd(ex: &Execd, cmd: &[&str]) {
    use std::ffi::CString;
    let args: Vec<CString> = cmd.iter().map(|a| CString::new(*a).unwrap_or_default()).collect();
    let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    // SAFETY: fork/execv with NUL-terminated arguments.
    unsafe {
        if libc::fork() == 0 {
            if libc::execv(argv[0], argv.as_ptr()) < 0 {
                let e = errno();
                ex.log.error(format!("(1312): Error executing '{}': {}", cmd[0], strerror(e)));
                libc::_exit(1);
            }
            libc::_exit(0);
        }
    }
}
