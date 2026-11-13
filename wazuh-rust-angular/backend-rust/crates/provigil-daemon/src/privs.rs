//! Running as a service on Unix: the user and group to run as, the background, signal names.
//! On other systems these do nothing (Windows services are run by the service manager).

/// Whether the process runs as root.
pub fn is_root() -> bool {
    #[cfg(unix)]
    // SAFETY: no arguments, no memory
    return unsafe { libc::geteuid() } == 0;
    #[cfg(not(unix))]
    false
}

/// The id of a group by name.
#[cfg(unix)]
pub fn group_id(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: a valid C string; the result is read before any other call
    let g = unsafe { libc::getgrnam(c.as_ptr()) };
    (!g.is_null()).then(|| unsafe { (*g).gr_gid })
}

/// The id of a user by name.
#[cfg(unix)]
pub fn user_id(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: a valid C string; the result is read before any other call
    let p = unsafe { libc::getpwnam(c.as_ptr()) };
    (!p.is_null()).then(|| unsafe { (*p).pw_uid })
}

/// Makes `gid` the only group of the process.
#[cfg(unix)]
pub fn set_group(gid: u32) -> std::io::Result<()> {
    let g = gid as libc::gid_t;
    // SAFETY: plain system calls with valid arguments
    if unsafe { libc::setgroups(1, &g) == -1 || libc::setegid(g) < 0 || libc::setgid(g) < 0 } {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Runs the process as `uid` from now on.
#[cfg(unix)]
pub fn set_user(uid: u32) -> std::io::Result<()> {
    let u = uid as libc::uid_t;
    // SAFETY: plain system calls
    if unsafe { libc::setuid(u) < 0 || libc::seteuid(u) < 0 } {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Allows `n` open files (both limits); the error text on failure.
pub fn set_nofile(n: u64) -> Result<(), String> {
    #[cfg(unix)]
    {
        let r = libc::rlimit { rlim_cur: n as libc::rlim_t, rlim_max: n as libc::rlim_t };
        // SAFETY: a valid pointer to an initialised rlimit
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &r) } < 0 {
            let e = std::io::Error::last_os_error();
            return Err(format!("Could not set resource limit for file descriptors to {n}: {} ({})", e.to_string().split(" (os error").next().unwrap_or(""), e.raw_os_error().unwrap_or(0)));
        }
    }
    let _ = n;
    Ok(())
}

/// Moves the process to the background: the parent exits, the child leads a new session with
/// its standard streams on the null device. Call before starting threads.
pub fn daemonize() -> std::io::Result<()> {
    #[cfg(unix)]
    // SAFETY: fork before any thread exists; the parent leaves at once
    unsafe {
        match libc::fork() {
            -1 => return Err(std::io::Error::last_os_error()),
            0 => {}
            _ => libc::_exit(0),
        }
        libc::setsid();
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            for fd in 0..3 {
                libc::dup2(null, fd);
            }
            if null > 2 {
                libc::close(null);
            }
        }
    }
    Ok(())
}

/// The system's name for a signal (`Terminated`, ...).
pub fn signal_name(n: i32) -> String {
    #[cfg(unix)]
    // SAFETY: strsignal returns a C string or null
    unsafe {
        let p = libc::strsignal(n);
        if !p.is_null() {
            return std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned();
        }
    }
    let _ = n;
    String::new()
}
