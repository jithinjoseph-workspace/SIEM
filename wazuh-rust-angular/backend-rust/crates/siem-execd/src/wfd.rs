//! `shared/exec_op.c`: `wpopenv` / `wpclose`, a process with its stdin and
//! stdout bound to pipes (no shell).
//!
//! Unix: fork + `setsid` + `execvp`, unbound streams on /dev/null (a
//! failed exec is exit status 127, not an error here). Windows:
//! `CreateProcess` of `"path" args...`, the pipes inherited, unbound
//! handles left NULL; the pipe streams are binary.

use std::io::Write;

/// `W_BIND_STDOUT` / `W_BIND_STDERR` / `W_BIND_STDIN`
pub const W_BIND_STDOUT: i32 = 1;
pub const W_BIND_STDERR: i32 = 2;
pub const W_BIND_STDIN: i32 = 4;

/// `wfd_t`
pub struct Wfd {
    pub file_in: Option<std::fs::File>,
    /// `file_out` read line by line with `fgets`
    pub file_out: Option<std::io::BufReader<std::fs::File>>,
    #[cfg(unix)]
    pid: i32,
    #[cfg(windows)]
    process: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(windows)]
    thread: windows_sys::Win32::Foundation::HANDLE,
}

impl Wfd {
    /// `fprintf(file_in, "%s\n", s); fflush(file_in)`
    pub fn write_line(&mut self, s: &[u8]) {
        if let Some(f) = self.file_in.as_mut() {
            let mut b = s.to_vec();
            b.push(b'\n');
            let _ = f.write_all(&b);
            let _ = f.flush();
        }
    }

    /// `fgets(buf, size, file_out)`: up to `size - 1` bytes through a
    /// newline; `None` at EOF with nothing read.
    pub fn fgets(&mut self, size: usize) -> Option<Vec<u8>> {
        use std::io::Read;
        let f = self.file_out.as_mut()?;
        let mut out = Vec::new();
        let mut b = [0u8; 1];
        while out.len() < size - 1 {
            match f.read(&mut b) {
                Ok(1) => {
                    out.push(b[0]);
                    if b[0] == b'\n' {
                        break;
                    }
                }
                _ => break,
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }
}

/// `wpopenv`
#[cfg(unix)]
pub fn wpopenv(_log: &siem_log::WLog, path: &str, argv: &[&str], flags: i32) -> Option<Wfd> {
    use std::ffi::CString;
    use std::os::unix::io::FromRawFd;
    let mut pipe_out = [-1i32; 2];
    let mut pipe_in = [-1i32; 2];
    // SAFETY: pipes, fork and exec on descriptors we own.
    unsafe {
        if flags & (W_BIND_STDOUT | W_BIND_STDERR) != 0 && libc::pipe(pipe_out.as_mut_ptr()) < 0 {
            return None;
        }
        if flags & W_BIND_STDIN != 0 && libc::pipe(pipe_in.as_mut_ptr()) < 0 {
            if pipe_out[0] >= 0 {
                libc::close(pipe_out[0]);
                libc::close(pipe_out[1]);
            }
            return None;
        }
        let cpath = CString::new(path).unwrap_or_default();
        let args: Vec<CString> = argv.iter().map(|a| CString::new(*a).unwrap_or_default()).collect();
        let mut av: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
        av.push(std::ptr::null());
        let pid = libc::fork();
        match pid {
            -1 => {
                for fd in pipe_out.iter().chain(pipe_in.iter()) {
                    if *fd >= 0 {
                        libc::close(*fd);
                    }
                }
                None
            }
            0 => {
                let fd_null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR, 0);
                if fd_null < 0 {
                    libc::_exit(1);
                }
                libc::dup2(if flags & W_BIND_STDOUT != 0 { pipe_out[1] } else { fd_null }, 1);
                libc::dup2(if flags & W_BIND_STDERR != 0 { pipe_out[1] } else { fd_null }, 2);
                if flags & (W_BIND_STDOUT | W_BIND_STDERR) != 0 {
                    libc::close(pipe_out[0]);
                    libc::close(pipe_out[1]);
                }
                if flags & W_BIND_STDIN != 0 {
                    libc::dup2(pipe_in[0], 0);
                    libc::close(pipe_in[0]);
                    libc::close(pipe_in[1]);
                } else {
                    libc::dup2(fd_null, 0);
                }
                libc::close(fd_null);
                libc::setsid();
                libc::execvp(cpath.as_ptr(), av.as_ptr());
                libc::_exit(127);
            }
            _ => {
                let mut w = Wfd { file_in: None, file_out: None, pid };
                if flags & (W_BIND_STDOUT | W_BIND_STDERR) != 0 {
                    libc::close(pipe_out[1]);
                    w.file_out = Some(std::io::BufReader::new(std::fs::File::from_raw_fd(pipe_out[0])));
                }
                if flags & W_BIND_STDIN != 0 {
                    libc::close(pipe_in[0]);
                    w.file_in = Some(std::fs::File::from_raw_fd(pipe_in[1]));
                }
                Some(w)
            }
        }
    }
}

/// `wpclose`: close the streams and wait; the exit status.
#[cfg(unix)]
pub fn wpclose(_log: &siem_log::WLog, mut w: Wfd) -> i32 {
    drop(w.file_in.take());
    drop(w.file_out.take());
    let mut status = 0;
    loop {
        // SAFETY: waiting for our own child.
        let r = unsafe { libc::waitpid(w.pid, &mut status, 0) };
        if r == -1 && siem_ipc::os_net::errno() == libc::EINTR {
            continue;
        }
        return if r == -1 { -1 } else { status };
    }
}

/// `wpopenv` (Windows)
#[cfg(windows)]
pub fn wpopenv(log: &siem_log::WLog, path: &str, argv: &[&str], flags: i32) -> Option<Wfd> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{CreateProcessA, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOA};

    if siem_fileop::crt::is_network_path(path) {
        log.warn(siem_fileop::crt::network_path_executed(path));
        return None;
    }
    // SAFETY: pipes and a process created here; handles closed on every path.
    unsafe {
        let mut sinfo: STARTUPINFOA = std::mem::zeroed();
        sinfo.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        sinfo.dwFlags = STARTF_USESTDHANDLES;
        let (mut out_r, mut out_w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        let (mut in_r, mut in_w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        if flags & (W_BIND_STDOUT | W_BIND_STDERR) != 0 {
            if CreatePipe(&mut out_r, &mut out_w, std::ptr::null(), 0) == 0 {
                log.error(format!("CreatePipe(): {}", GetLastError()));
                return None;
            }
            if SetHandleInformation(out_w, HANDLE_FLAG_INHERIT, 1) == 0 {
                log.error(format!("SetHandleInformation(): {}", GetLastError()));
                CloseHandle(out_r);
                CloseHandle(out_w);
                return None;
            }
            if flags & W_BIND_STDOUT != 0 {
                sinfo.hStdOutput = out_w;
            }
            if flags & W_BIND_STDERR != 0 {
                sinfo.hStdError = out_w;
            }
        }
        let close_out = || {
            if !out_r.is_null() {
                CloseHandle(out_r);
                CloseHandle(out_w);
            }
        };
        if flags & W_BIND_STDIN != 0 {
            if CreatePipe(&mut in_r, &mut in_w, std::ptr::null(), 0) == 0 {
                log.error(format!("CreatePipe(): {}", GetLastError()));
                close_out();
                return None;
            }
            if SetHandleInformation(in_r, HANDLE_FLAG_INHERIT, 1) == 0 {
                log.error(format!("SetHandleInformation(): {}", GetLastError()));
                CloseHandle(in_r);
                CloseHandle(in_w);
                close_out();
                return None;
            }
            sinfo.hStdInput = in_r;
        }
        // "\"argv0\" argv1 argv2..."
        let mut cmdline = format!("\"{}\"", argv.first().copied().unwrap_or(""));
        for a in argv.iter().skip(1) {
            cmdline.push(' ');
            cmdline.push_str(a);
        }
        log.debug2(format!("path = '{path}', command = '{cmdline}'"));
        let mut cl = cmdline.into_bytes();
        cl.push(0);
        let mut pinfo: PROCESS_INFORMATION = std::mem::zeroed();
        if CreateProcessA(
            std::ptr::null(),
            cl.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            0,
            std::ptr::null(),
            std::ptr::null(),
            &sinfo,
            &mut pinfo,
        ) == 0
        {
            log.debug1(format!("CreateProcess(): {}", GetLastError()));
            close_out();
            if !in_r.is_null() {
                CloseHandle(in_r);
                CloseHandle(in_w);
            }
            return None;
        }
        let mut w = Wfd { file_in: None, file_out: None, process: pinfo.hProcess, thread: pinfo.hThread };
        if !out_r.is_null() {
            CloseHandle(out_w);
            w.file_out = Some(std::io::BufReader::new(std::fs::File::from_raw_handle(out_r as _)));
        }
        if !in_r.is_null() {
            CloseHandle(in_r);
            w.file_in = Some(std::fs::File::from_raw_handle(in_w as _));
        }
        Some(w)
    }
}

/// `wpclose` (Windows): close the streams and wait for the process.
#[cfg(windows)]
pub fn wpclose(log: &siem_log::WLog, mut w: Wfd) -> i32 {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    drop(w.file_in.take());
    drop(w.file_out.take());
    // SAFETY: the process handles of this Wfd.
    unsafe {
        let status = if WaitForSingleObject(w.process, INFINITE) == WAIT_OBJECT_0 {
            let mut code = 0u32;
            GetExitCodeProcess(w.process, &mut code);
            code as i32
        } else {
            log.error(format!("WaitForSingleObject(): {}", GetLastError()));
            -1
        };
        CloseHandle(w.process);
        CloseHandle(w.thread);
        status
    }
}

// SAFETY: the process handles are only used by the owner of the Wfd.
#[cfg(windows)]
unsafe impl Send for Wfd {}
