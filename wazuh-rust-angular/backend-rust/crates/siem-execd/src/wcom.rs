//! `os_execd/wcom.c`: the `com` requests (`unmerge`, `uncompress`,
//! `restart`, `reload`, `lock_restart`, `getconfig`,
//! `check-manager-configuration`) and, on Unix, the `queue/sockets/com`
//! server thread. On Windows agentd calls [`wcom_dispatch`] directly.

use std::io::{Read, Write};
use std::sync::atomic::Ordering;

use crate::*;

/// `PATH_MAX`
#[cfg(unix)]
const PATH_MAX: usize = 4096;
#[cfg(windows)]
const PATH_MAX: usize = 260;
/// `EXECVE_ERROR`
const EXECVE_ERROR: i32 = 0x7F;

/// `_jailfile`: `basedir/filename`, refused when the name has `..` or the
/// path is too long.
fn jailfile(basedir: &str, filename: &str) -> Option<String> {
    if siem_fileop::ref_parent_folder(filename) {
        return None;
    }
    #[cfg(unix)]
    let p = format!("{basedir}/{filename}");
    #[cfg(windows)]
    let p = format!("{basedir}\\{filename}");
    (p.len() <= PATH_MAX).then_some(p)
}

/// `wcom_dispatch`
pub fn wcom_dispatch(ex: &Execd, command: &[u8]) -> Vec<u8> {
    let command = String::from_utf8_lossy(&command[..command.iter().position(|&c| c == 0).unwrap_or(command.len())]).into_owned();
    let (rcv_comm, rcv_args) = match command.find(' ') {
        Some(p) => (&command[..p], Some(&command[p + 1..])),
        None => (command.as_str(), None),
    };
    let out = match rcv_comm {
        "unmerge" => match rcv_args {
            None => {
                ex.log.debug1("WCOM unmerge needs arguments.");
                "err WCOM unmerge needs arguments".to_string()
            }
            Some(a) => wcom_unmerge(ex, a),
        },
        "uncompress" => match rcv_args {
            None => {
                ex.log.debug1("WCOM uncompress needs arguments.");
                "err WCOM uncompress needs arguments".to_string()
            }
            Some(a) => match a.find(' ') {
                Some(p) => wcom_uncompress(ex, &a[..p], &a[p + 1..]),
                None => {
                    ex.log.debug1("Bad WCOM uncompress message.");
                    "err Too few commands".to_string()
                }
            },
        },
        "restart" | "restart-wazuh" => wcom_restart(ex, false),
        "reload" => wcom_restart(ex, true),
        "lock_restart" => {
            let max = ex.define_int("execd", "max_restart_lock", 0, 3600);
            ex.max_restart_lock.store(max, Ordering::SeqCst);
            let mut timeout = rcv_args.map(siem_config::util::atoi).unwrap_or(-2);
            let out = if timeout < -1 {
                "err Invalid timeout".to_string()
            } else {
                if timeout == -1 || timeout > max {
                    if timeout > max {
                        ex.log.warn("Timeout exceeds the maximum allowed.");
                    }
                    timeout = max;
                }
                "ok ".to_string()
            };
            lock_restart(ex, timeout);
            out
        }
        "getconfig" => match rcv_args {
            None => {
                ex.log.debug1("WCOM getconfig needs arguments.");
                "err WCOM getconfig needs arguments".to_string()
            }
            Some(a) => return wcom_getconfig(ex, a),
        },
        "check-manager-configuration" => return wcom_check_manager_config(ex),
        other => {
            ex.log.debug1(format!("WCOM Unrecognized command '{other}'."));
            "err Unrecognized command".to_string()
        }
    };
    out.into_bytes()
}

/// `wcom_unmerge`
fn wcom_unmerge(ex: &Execd, file_path: &str) -> String {
    let Some(final_path) = jailfile(INCOMING_DIR, file_path) else {
        ex.log.error("At WCOM unmerge: Invalid file name");
        return "err Invalid file name".to_string();
    };
    if !siem_fileop::unmerge_files_mode(&final_path, Some(INCOMING_DIR), false).0 {
        ex.log.error(format!("At WCOM unmerge: Error unmerging file '{final_path}.'"));
        return "err Cannot unmerge file".to_string();
    }
    "ok ".to_string()
}

/// `wcom_uncompress`: gunzip `source` into `target` (`gzread` passes
/// non-gzip data through), then remove the source.
fn wcom_uncompress(ex: &Execd, source: &str, target: &str) -> String {
    let (Some(fs), Some(ft)) = (jailfile(INCOMING_DIR, source), jailfile(INCOMING_DIR, target)) else {
        ex.log.error("At WCOM uncompress: Invalid file name");
        return "err Invalid file name".to_string();
    };
    let Ok(mut src) = std::fs::File::open(&fs) else {
        ex.log.error(format!("At WCOM uncompress: Unable to open '{fs}'"));
        return "err Unable to open source".to_string();
    };
    let Ok(mut dst) = std::fs::File::create(&ft) else {
        ex.log.error(format!("At WCOM uncompress: Unable to open '{ft}'"));
        return "err Unable to open target".to_string();
    };
    let mut raw = Vec::new();
    let read_ok = src.read_to_end(&mut raw).is_ok();
    let data = if raw.starts_with(&[0x1f, 0x8b]) {
        let mut d = Vec::new();
        match flate2::read::MultiGzDecoder::new(&raw[..]).read_to_end(&mut d) {
            Ok(_) => Some(d),
            Err(_) => None,
        }
    } else if read_ok {
        Some(raw)
    } else {
        None
    };
    let Some(data) = data else {
        ex.log.error(format!("At WCOM uncompress: Unable to read '{fs}'"));
        return "err Unable to read source".to_string();
    };
    if dst.write_all(&data).is_err() {
        ex.log.error(format!("At WCOM uncompress: Unable to write '{ft}'"));
        return "err Unable to write target".to_string();
    }
    drop(src);
    let _ = std::fs::remove_file(&fs);
    "ok ".to_string()
}

/// `wcom_restart` / `wcom_reload`
fn wcom_restart(ex: &Execd, reload: bool) -> String {
    let lock = ex.pending_upg.load(Ordering::SeqCst) - now();
    if lock > 0 {
        ex.log.info(format!("Agent auto-restart locked for {lock} seconds."));
        return "ok ".to_string();
    }
    #[cfg(unix)]
    {
        let what = if reload { "reload" } else { "restart" };
        let cmd: Vec<&str> = if std::path::Path::new("active-response/bin/restart.sh").exists() {
            if reload {
                vec!["active-response/bin/restart.sh", "agent", "reload"]
            } else {
                vec!["active-response/bin/restart.sh", "agent"]
            }
        } else {
            vec!["bin/wazuh-control", what]
        };
        crate::exec::exec_cmd(ex, &cmd);
        "ok ".to_string()
    }
    #[cfg(windows)]
    {
        let _ = reload;
        let command = trunc(&format!("{AR_BINDIR}/restart-wazuh.exe"), OS_FLSIZE);
        let params = br#"{"version":1,"origin":{"name":"","module":"wazuh-execd"},"command":"add","parameters":{"extra_args":[],"alert":{},"program":"restart-wazuh.exe"}}"#;
        match crate::wfd::wpopenv(&ex.log, &command, &[&command], crate::wfd::W_BIND_STDIN) {
            Some(mut w) => {
                w.write_line(params);
                crate::wfd::wpclose(&ex.log, w);
                "ok ".to_string()
            }
            None => {
                ex.log.error("At WCOM restart: Cannot execute restart process");
                "err Cannot execute restart process".to_string()
            }
        }
    }
}

/// `"ok " + json` (`os_strdup("ok ") + wm_strcat(json, ' ')`: two spaces).
fn ok_json(j: siem_cjson::Json) -> Vec<u8> {
    let mut out = b"ok  ".to_vec();
    out.extend_from_slice(&j.print_unformatted());
    out
}

/// `wcom_getconfig`
fn wcom_getconfig(ex: &Execd, section: &str) -> Vec<u8> {
    match section {
        "active-response" => return ok_json(crate::config::get_ar_config(ex)),
        "logging" => return ok_json(ex.log.config_json()),
        "internal" => return ok_json(crate::config::get_internal_options(ex)),
        #[cfg(unix)]
        "cluster" => {
            let s = siem_ipc::os_net::connect_unix_domain(CLUSTER_SOCK, siem_ipc::os_net::SOCK_STREAM, OS_MAXSTR as i32);
            if s < 0 {
                return b"err Unable to connect with socket. The component might be disabled".to_vec();
            }
            siem_ipc::os_net::close_fd(s);
            if let Some(j) = crate::config::get_cluster_config(ex) {
                return ok_json(j);
            }
        }
        _ => {}
    }
    ex.log.debug1(format!("At WCOM getconfig: Could not get '{section}' section"));
    b"err Could not get requested section".to_vec()
}

/// `wm_exec(command, &output, &status, secs, NULL)`: Err(()) when the
/// command could not run (`status` keeps its value).
#[cfg(unix)]
fn wm_exec(ex: &Execd, command: &str, status: &mut i32) -> Result<String, ()> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    match std::process::Command::new(parts[0]).args(&parts[1..]).output() {
        Ok(o) => {
            *status = o.status.code().unwrap_or(-1);
            let mut s = o.stdout;
            s.extend_from_slice(&o.stderr);
            Ok(String::from_utf8_lossy(&s).into_owned())
        }
        Err(e) => {
            // the child exits with EXECVE_ERROR when execvp fails
            let _ = e;
            *status = EXECVE_ERROR;
            ex.log.debug1(format!("Cannot run '{command}'"));
            Err(())
        }
    }
}

/// `wm_exec` (Windows, `wazuh_modules/wm_exec.c`): `CreateProcessW` of the
/// command line with stdout and stderr on a pipe, waited 2000 s.
#[cfg(windows)]
fn wm_exec(ex: &Execd, command: &str, status: &mut i32) -> Result<String, ()> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, TerminateProcess, WaitForSingleObject, NORMAL_PRIORITY_CLASS,
        PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };
    const SECS: u32 = 2000;
    const WM_STRING_MAX: usize = 67108864;
    // SAFETY: a pipe and a process created here and closed below.
    unsafe {
        let mut sinfo: STARTUPINFOW = std::mem::zeroed();
        sinfo.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        sinfo.dwFlags = STARTF_USESTDHANDLES;
        let (mut rd, mut wr): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        if CreatePipe(&mut rd, &mut wr, std::ptr::null(), 0) == 0 {
            let e = GetLastError();
            ex.log.error(format!("at wm_exec(): CreatePipe({e}): {}", siem_ipc::os_net::win_strerror(e)));
            return Err(());
        }
        sinfo.hStdOutput = wr;
        sinfo.hStdError = wr;
        if SetHandleInformation(wr, HANDLE_FLAG_INHERIT, 1) == 0 {
            let e = GetLastError();
            ex.log.error(format!("at wm_exec(): SetHandleInformation({e}): {}", siem_ipc::os_net::win_strerror(e)));
            CloseHandle(rd);
            CloseHandle(wr);
            return Err(());
        }
        let mut wcmd: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
        ex.log.debug2(format!("UTF-8 command: {command}"));
        let mut pinfo: PROCESS_INFORMATION = std::mem::zeroed();
        if CreateProcessW(
            std::ptr::null(),
            wcmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            NORMAL_PRIORITY_CLASS,
            std::ptr::null(),
            std::ptr::null(),
            &sinfo,
            &mut pinfo,
        ) == 0
        {
            let e = GetLastError();
            ex.log.warn(format!("Cannot run '{command}': {} ({e})", siem_ipc::os_net::win_strerror(e)));
            CloseHandle(rd);
            CloseHandle(wr);
            return Err(());
        }
        CloseHandle(wr);
        let mut pipe = std::fs::File::from_raw_handle(rd as _);
        let log = std::sync::Arc::clone(&ex.log);
        let reader = std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if out.len() + n <= WM_STRING_MAX {
                            out.extend_from_slice(&buf[..n]);
                        } else {
                            log.warn("String limit reached.");
                            break;
                        }
                    }
                }
            }
            out
        });
        let mut retval: Result<(), i32> = Ok(());
        match WaitForSingleObject(pinfo.hProcess, SECS * 1000) {
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                GetExitCodeProcess(pinfo.hProcess, &mut code);
                *status = code as i32;
            }
            WAIT_TIMEOUT => {
                TerminateProcess(pinfo.hProcess, 1);
                retval = Err(1);
            }
            _ => {
                let e = GetLastError();
                ex.log.error(format!("at wm_exec(): WaitForSingleObject({e}): {}", siem_ipc::os_net::win_strerror(e)));
                TerminateProcess(pinfo.hProcess, 1);
                retval = Err(-1);
            }
        }
        let out = reader.join().unwrap_or_default();
        CloseHandle(pinfo.hProcess);
        CloseHandle(pinfo.hThread);
        match retval {
            Ok(()) => Ok(String::from_utf8_lossy(&out).into_owned()),
            // WM_ERROR_TIMEOUT (>= 0): the output is kept, the command "ran"
            Err(1) => Ok(String::from_utf8_lossy(&out).into_owned()),
            Err(_) => Err(()),
        }
    }
}

/// `wcom_check_manager_config`: run every daemon with `-t`.
fn wcom_check_manager_config(ex: &Execd) -> Vec<u8> {
    const DAEMONS: [&str; 13] = [
        "bin/wazuh-authd",
        "bin/wazuh-remoted",
        "bin/wazuh-execd",
        "bin/wazuh-analysisd",
        "bin/wazuh-logcollector",
        "bin/wazuh-integratord",
        "bin/wazuh-syscheckd",
        "bin/wazuh-maild",
        "bin/wazuh-modulesd",
        "bin/wazuh-clusterd",
        "bin/wazuh-agentlessd",
        "bin/wazuh-integratord",
        "bin/wazuh-csyslogd",
    ];
    let mut retval = 0;
    let mut response: Option<String> = None;
    if siem_xml::OsXml::read_file(OSSECCONF, false).is_err() {
        // snprintf(NULL, 0, ...) writes nothing
        retval = EXECVE_ERROR;
    } else {
        for d in DAEMONS {
            retval = 0;
            let command_in = format!("{d} -t");
            match wm_exec(ex, &command_in, &mut retval) {
                Err(()) => {
                    if retval == EXECVE_ERROR {
                        ex.log.warn(format!("Path is invalid or file has insufficient permissions. {command_in}"));
                    } else {
                        ex.log.warn(format!("Error executing [{command_in}]"));
                    }
                    // snprintf(response, size, ...) with size = strlen: the
                    // last character is cut
                    let mut s = format!("Error executing {command_in} - ({retval})");
                    s.pop();
                    response = Some(s);
                    break;
                }
                Ok(mut out) => {
                    if !out.is_empty() {
                        if out.ends_with('\n') {
                            out.pop();
                        }
                        match response.as_mut() {
                            Some(r) => {
                                r.push(' ');
                                r.push_str(&out);
                            }
                            None => response = Some(out),
                        }
                    }
                }
            }
            if retval != 0 {
                break;
            }
        }
    }
    let mut j = siem_cjson::Json::object();
    j.add("error", siem_cjson::Json::number(retval as f64));
    if retval != 0 {
        let msg = trunc(response.as_deref().unwrap_or("(null)"), OS_SIZE_4096 - 27);
        j.add("message", siem_cjson::Json::string(msg));
    } else {
        j.add("message", siem_cjson::Json::string("ok"));
    }
    j.print_unformatted()
}

/// `lock_restart`
pub fn lock_restart(ex: &Execd, timeout: i32) {
    ex.pending_upg.store(now() + timeout as i64, Ordering::SeqCst);
}

/// `wcom_main`: the `queue/sockets/com` server.
#[cfg(unix)]
pub fn wcom_main(ex: &Execd) {
    use siem_ipc::os_net;
    ex.log.debug1("Local requests thread ready");
    let sock = os_net::bind_unix_domain(COM_LOCAL_SOCK, os_net::SOCK_STREAM, OS_MAXSTR as i32);
    if sock < 0 {
        let e = errno();
        ex.log.error(format!("Unable to bind to socket '{COM_LOCAL_SOCK}': ({e}) {}.", strerror(e)));
        return;
    }
    loop {
        // SAFETY: select/accept on our own socket.
        let rc = unsafe {
            let mut set: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut set);
            libc::FD_SET(sock, &mut set);
            libc::select(sock + 1, &mut set, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
        };
        if rc == -1 {
            let e = errno();
            if e != libc::EINTR {
                ex.exit_critical(format!("At wcom_main(): select(): {}", strerror(e)));
            }
            continue;
        } else if rc == 0 {
            continue;
        }
        // SAFETY: accept on our listening socket.
        let peer = unsafe { libc::accept(sock, std::ptr::null_mut(), std::ptr::null_mut()) };
        if peer < 0 {
            let e = errno();
            if e != libc::EINTR {
                ex.log.error(format!("At wcom_main(): accept(): {}", strerror(e)));
            }
            continue;
        }
        let mut buf = Vec::new();
        match os_net::recv_secure_tcp(peer, &mut buf, OS_MAXSTR as u32) {
            r if r == os_net::OS_SOCKTERR as isize => {
                ex.log.error("At wcom_main(): OS_RecvSecureTCP(): response size is bigger than expected");
            }
            -1 => ex.log.error(format!("At wcom_main(): OS_RecvSecureTCP(): {}", strerror(errno()))),
            0 => {
                ex.log.debug1("Empty message from local client.");
                os_net::close_fd(peer);
            }
            _ => {
                let resp = wcom_dispatch(ex, &buf);
                os_net::send_secure_tcp(peer, &resp);
                os_net::close_fd(peer);
            }
        }
    }
}

/// `OS_SendSecureTCPCluster`
#[cfg(unix)]
pub fn send_secure_tcp_cluster(sock: i32, command: &[u8], payload: &[u8]) -> i32 {
    const COMMAND_SIZE: usize = 12;
    let mut seed = [0u8; 4];
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut seed));
    let counter = (i32::from_ne_bytes(seed) % i32::MAX) as u32;
    let mut b = Vec::with_capacity(20 + payload.len());
    b.extend_from_slice(&counter.to_be_bytes());
    b.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    b.extend_from_slice(command);
    b.push(b' ');
    b.resize(8 + COMMAND_SIZE, b'-');
    b.extend_from_slice(payload);
    // SAFETY: send on our own socket.
    let r = unsafe { libc::send(sock, b.as_ptr().cast(), b.len(), 0) };
    if r == b.len() as isize {
        0
    } else {
        siem_ipc::os_net::OS_SOCKTERR
    }
}

/// `OS_RecvSecureClusterTCP`: the payload size, 0, -1, or -2 for an `err`
/// reply.
#[cfg(unix)]
pub fn recv_secure_cluster_tcp(sock: i32, ret: &mut Vec<u8>, length: usize) -> isize {
    let mut hdr = [0u8; 20];
    let r = siem_ipc::os_net::recv_waitall(sock, &mut hdr);
    if r <= 0 {
        return r;
    }
    if r != 20 {
        return -1;
    }
    let size = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    if size > length {
        return -1;
    }
    ret.resize(size, 0);
    let n = siem_ipc::os_net::recv_waitall(sock, ret);
    if &hdr[8..20] == b"err --------" {
        return -2;
    }
    n
}
