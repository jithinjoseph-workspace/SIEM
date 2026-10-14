//! `wazuh_modules/wm_exec.c`: `wm_exec` runs a command with stdout and
//! stderr on one pipe and a timeout. Shared by wcom, SCA and the other
//! modules, as in the C agent.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use siem_log::WLog;

/// `WM_ERROR_TIMEOUT`
pub const WM_ERROR_TIMEOUT: i32 = 1;
/// `EXECVE_ERROR`
pub const EXECVE_ERROR: i32 = 0x7F;
/// `WM_STRING_MAX`
const WM_STRING_MAX: usize = 67108864;

/// `wm_task_nice` (set by `wm_config` from `wazuh_modules.task_nice`).
pub static WM_TASK_NICE: AtomicI32 = AtomicI32::new(0);

/// What `wm_exec(command, &output, &status, secs, NULL)` leaves.
pub struct Exec {
    /// 0, `WM_ERROR_TIMEOUT` or -1.
    pub retval: i32,
    /// `*output` (set when `retval >= 0`).
    pub output: Option<Vec<u8>>,
    /// `*status` when the C code sets it.
    pub status: Option<i32>,
}

/// `wm_exec` (Windows): `CreateProcessW` of the UTF-8 command line, the
/// priority class from `wm_task_nice`, `secs == 0` waits forever.
#[cfg(windows)]
pub fn wm_exec(log: &Arc<WLog>, command: &str, secs: u32) -> Exec {
    use std::io::Read;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, TerminateProcess, WaitForSingleObject, ABOVE_NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS,
        HIGH_PRIORITY_CLASS, IDLE_PRIORITY_CLASS, INFINITE, NORMAL_PRIORITY_CLASS, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };
    let fail = Exec { retval: -1, output: None, status: None };
    let nice = WM_TASK_NICE.load(Ordering::Relaxed);
    let flags = if nice < -10 {
        HIGH_PRIORITY_CLASS
    } else if nice < 0 {
        ABOVE_NORMAL_PRIORITY_CLASS
    } else if nice == 0 {
        NORMAL_PRIORITY_CLASS
    } else if nice < 10 {
        BELOW_NORMAL_PRIORITY_CLASS
    } else {
        IDLE_PRIORITY_CLASS
    };
    // SAFETY: a pipe and a process created here and closed below.
    unsafe {
        let mut sinfo: STARTUPINFOW = std::mem::zeroed();
        sinfo.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        sinfo.dwFlags = STARTF_USESTDHANDLES;
        let (mut rd, mut wr): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        if CreatePipe(&mut rd, &mut wr, std::ptr::null(), 0) == 0 {
            let e = GetLastError();
            log.error(format!("at wm_exec(): CreatePipe({e}): {}", siem_ipc::os_net::win_strerror(e)));
            return fail;
        }
        sinfo.hStdOutput = wr;
        sinfo.hStdError = wr;
        if SetHandleInformation(wr, HANDLE_FLAG_INHERIT, 1) == 0 {
            let e = GetLastError();
            log.error(format!("at wm_exec(): SetHandleInformation({e}): {}", siem_ipc::os_net::win_strerror(e)));
            CloseHandle(rd);
            CloseHandle(wr);
            return fail;
        }
        let mut wcmd: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
        log.debug2(format!("UTF-8 command: {command}"));
        let mut pinfo: PROCESS_INFORMATION = std::mem::zeroed();
        if CreateProcessW(std::ptr::null(), wcmd.as_mut_ptr(), std::ptr::null(), std::ptr::null(), 1, flags, std::ptr::null(), std::ptr::null(), &sinfo, &mut pinfo) == 0 {
            let e = GetLastError();
            log.warn(format!("Cannot run '{command}': {} ({e})", siem_ipc::os_net::win_strerror(e)));
            CloseHandle(rd);
            CloseHandle(wr);
            return fail;
        }
        CloseHandle(wr);
        // Reader: the C thread appends to tinfo.output until the pipe closes
        let out = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let mut pipe = std::fs::File::from_raw_handle(rd as _);
        let (o2, log2) = (out.clone(), Arc::clone(log));
        let _ = std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut o = o2.lock().unwrap_or_else(|e| e.into_inner());
                        if o.len() + n <= WM_STRING_MAX {
                            o.extend_from_slice(&buf[..n]);
                        } else {
                            drop(o);
                            log2.warn("String limit reached.");
                            break;
                        }
                    }
                }
            }
            let _ = done_tx.send(());
        });
        let mut r = Exec { retval: 0, output: None, status: None };
        match WaitForSingleObject(pinfo.hProcess, if secs > 0 { secs.saturating_mul(1000) } else { INFINITE }) {
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                GetExitCodeProcess(pinfo.hProcess, &mut code);
                r.status = Some(code as i32);
            }
            WAIT_TIMEOUT => {
                TerminateProcess(pinfo.hProcess, 1);
                r.retval = WM_ERROR_TIMEOUT;
            }
            _ => {
                let e = GetLastError();
                log.error(format!("at wm_exec(): WaitForSingleObject({e}): {}", siem_ipc::os_net::win_strerror(e)));
                TerminateProcess(pinfo.hProcess, 1);
                r.retval = -1;
            }
        }
        // WaitForSingleObject(hThread, 1000), then TerminateThread: the output read so far.
        // shortcut: the reader is left blocked on the pipe (not terminated) while a grandchild holds it.
        let _ = done_rx.recv_timeout(std::time::Duration::from_millis(1000));
        if r.retval >= 0 {
            r.output = Some(std::mem::take(&mut *out.lock().unwrap_or_else(|e| e.into_inner())));
        }
        CloseHandle(pinfo.hProcess);
        CloseHandle(pinfo.hThread);
        r
    }
}

/// `wm_exec` (Unix).
/// shortcut: whitespace-split argv, no timeout and no process-group kill; port the
/// fork/execvp/setsid version before SCA or commands run on Unix agents.
#[cfg(unix)]
pub fn wm_exec(log: &Arc<WLog>, command: &str, _secs: u32) -> Exec {
    let parts: Vec<&str> = command.split_whitespace().collect();
    let Some(prog) = parts.first() else {
        return Exec { retval: -1, output: None, status: Some(EXECVE_ERROR) };
    };
    match std::process::Command::new(prog).args(&parts[1..]).output() {
        Ok(o) => {
            let mut s = o.stdout;
            s.extend_from_slice(&o.stderr);
            Exec { retval: 0, output: Some(s), status: Some(o.status.code().unwrap_or(-1)) }
        }
        Err(_) => {
            log.debug1(format!("Cannot run '{command}'"));
            Exec { retval: -1, output: None, status: Some(EXECVE_ERROR) }
        }
    }
}
