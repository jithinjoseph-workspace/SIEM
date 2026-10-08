//! Start-up plumbing shared by the Wazuh daemons: `w_homedir`
//! (shared/file_op.c), privilege separation (privsep_op.c), PID files
//! (`CreatePID` / `DeletePID` / `DeleteState`), `goDaemon` and `StartSIG`
//! (sig_op.c). The Unix calls are no-ops elsewhere.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use siem_log::WLog;

/// `OS_PIDFILE`
pub const OS_PIDFILE: &str = "var/run";
/// `WAZUH_HOME_ENV`
pub const WAZUH_HOME_ENV: &str = "WAZUH_HOME";
/// `HOME_ERROR`
pub const HOME_ERROR: &str = "(1108): Unable to find Wazuh install directory. Export it to WAZUH_HOME environment variable.";

/// `w_strtok_r_str_delim`'s first token: the text before the first `delim`
/// that is not at the start (leading delimiters are skipped).
fn first_token<'a>(s: &'a str, delim: &str) -> Option<&'a str> {
    let mut rest = s;
    while rest.starts_with(delim) {
        rest = &rest[delim.len()..];
    }
    if rest.is_empty() {
        return None;
    }
    Some(match rest.find(delim) {
        Some(p) => &rest[..p],
        None => rest,
    })
}

/// `w_homedir`: the directory of the executable up to `/bin`, else the
/// `WAZUH_HOME` environment variable; it must be a directory.
pub fn homedir(argv0: &str) -> Result<PathBuf, &'static str> {
    let exe = std::env::current_exe().ok().and_then(|p| p.canonicalize().ok()).or_else(|| Path::new(argv0).canonicalize().ok());
    let cand = match exe {
        Some(p) => {
            let dir = p.parent().map(|d| d.to_string_lossy().replace('\\', "/")).unwrap_or_default();
            first_token(&dir, "/bin").map(PathBuf::from)
        }
        None => std::env::var(WAZUH_HOME_ENV).ok().map(PathBuf::from),
    };
    match cand {
        Some(h) if h.is_dir() => Ok(h),
        _ => Err(HOME_ERROR),
    }
}

/// `strerror`-style text of the last OS error.
#[cfg(unix)]
fn errno_pair() -> (i32, String) {
    let e = std::io::Error::last_os_error();
    let n = e.raw_os_error().unwrap_or(0);
    let t = e.to_string();
    // "No such file or directory (os error 2)" -> glibc wording
    let t = t.split(" (os error").next().unwrap_or("").to_string();
    (n, t)
}

/// `Privsep_GetUser` / `Privsep_GetGroup`.
#[cfg(unix)]
pub fn get_user(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: getpwnam returns a pointer to static storage or NULL.
    let p = unsafe { libc::getpwnam(c.as_ptr()) };
    if p.is_null() {
        None
    } else {
        // SAFETY: non-null pointer from getpwnam.
        Some(unsafe { (*p).pw_uid })
    }
}

#[cfg(unix)]
pub fn get_group(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: getgrnam returns a pointer to static storage or NULL.
    let g = unsafe { libc::getgrnam(c.as_ptr()) };
    if g.is_null() {
        None
    } else {
        // SAFETY: non-null pointer from getgrnam.
        Some(unsafe { (*g).gr_gid })
    }
}

/// The user/group check, `Privsep_SetGroup`, `Privsep_Chroot` and
/// `Privsep_SetUser` of a daemon's `main()`, with the C error texts.
#[cfg(unix)]
pub fn privsep(user: &str, group: &str, home: &Path, chroot: bool) -> Result<(), String> {
    let (Some(uid), Some(gid)) = (get_user(user), get_group(group)) else {
        let (n, t) = errno_pair();
        return Err(format!("(1203): Invalid user '{user}' or group '{group}' given: {t} ({n})"));
    };
    // SAFETY: plain libc calls with valid arguments.
    unsafe {
        let g = gid as libc::gid_t;
        if libc::setgroups(1, &g) == -1 || libc::setegid(g) < 0 || libc::setgid(g) < 0 {
            let (n, t) = errno_pair();
            return Err(format!("(1130): Unable to switch to group '{group}' due to [({n})-({t})]."));
        }
    }
    if chroot {
        let p = std::ffi::CString::new(home.to_string_lossy().as_bytes()).map_err(|_| "bad home".to_string())?;
        // SAFETY: plain libc calls with a valid C string.
        let ok = unsafe { libc::chdir(p.as_ptr()) == 0 && libc::chroot(p.as_ptr()) == 0 && libc::chdir(c"/".as_ptr()) == 0 };
        if !ok {
            let (n, t) = errno_pair();
            return Err(format!("(1132): Unable to chroot to directory '{}' due to [({n})-({t})].", home.display()));
        }
    }
    // SAFETY: plain libc calls.
    unsafe {
        let u = uid as libc::uid_t;
        if libc::setuid(u) < 0 || libc::seteuid(u) < 0 {
            let (n, t) = errno_pair();
            return Err(format!("(1131): Unable to switch to user '{user}' due to [({n})-({t})]."));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn privsep(_user: &str, _group: &str, _home: &Path, _chroot: bool) -> Result<(), String> {
    Ok(())
}

/// `setrlimit(RLIMIT_NOFILE, {n, n})`; the error text of a failure
/// ("Could not set resource limit for file descriptors to ...").
pub fn set_nofile(n: u64) -> Result<(), String> {
    #[cfg(unix)]
    {
        let r = libc::rlimit { rlim_cur: n as libc::rlim_t, rlim_max: n as libc::rlim_t };
        // SAFETY: valid pointer to an initialised rlimit.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &r) } < 0 {
            let (e, t) = errno_pair();
            return Err(format!("Could not set resource limit for file descriptors to {n}: {t} ({e})"));
        }
    }
    let _ = n;
    Ok(())
}

/// The PID file path of `name` for `pid` (relative to the home).
pub fn pid_file(name: &str, pid: u32) -> String {
    format!("{OS_PIDFILE}/{name}-{pid}.pid")
}

/// `CreatePID`
pub fn create_pid(name: &str, pid: u32, log: &WLog) -> Result<(), ()> {
    use std::io::Write;
    let file = pid_file(name, pid);
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&file).map_err(|_| ())?;
    let _ = writeln!(f, "{pid}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)) {
            let n = e.raw_os_error().unwrap_or(0);
            log.error(format!("(1127): Could not chmod object '{file}' due to [({n})-({e})]."));
            return Err(());
        }
    }
    let _ = log;
    Ok(())
}

/// `DeletePID`
pub fn delete_pid(name: &str, log: &WLog) {
    let file = pid_file(name, std::process::id());
    if !Path::new(&file).exists() {
        return;
    }
    if let Err(e) = std::fs::remove_file(&file) {
        let n = e.raw_os_error().unwrap_or(0);
        log.ferror(format!("(1129): Could not unlink file '{file}' due to [({n})-({e})]."));
    }
}

/// `DeleteState`
pub fn delete_state(name: &str) {
    let _ = std::fs::remove_file(format!("{OS_PIDFILE}/{name}.state"));
}

/// `goDaemon`: fork twice with a new session, stdio to /dev/null and stop
/// logging to stderr. Must run before any thread is started.
#[cfg(unix)]
pub fn go_daemon(log: &WLog) {
    // SAFETY: called while the process is single-threaded.
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            let (n, t) = errno_pair();
            log.error(format!("(1101): Could not fork due to [({n})-({t})]."));
            return;
        } else if pid > 0 {
            libc::_exit(0);
        }
        if libc::setsid() < 0 {
            let (n, t) = errno_pair();
            log.error(format!("(1112): Error during setsid()-call due to [({n})-({t})]."));
            return;
        }
        let pid = libc::fork();
        if pid < 0 {
            let (n, t) = errno_pair();
            log.error(format!("(1101): Could not fork due to [({n})-({t})]."));
            return;
        } else if pid > 0 {
            libc::_exit(0);
        }
        let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if fd >= 0 {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            libc::close(fd);
        }
    }
    log.now_daemon();
}

#[cfg(not(unix))]
pub fn go_daemon(log: &WLog) {
    log.now_daemon();
}

struct SigCtx {
    name: String,
    log: std::sync::Arc<WLog>,
}

static SIG: OnceLock<SigCtx> = OnceLock::new();

/// `HandleExit` (the `atexit` hook): remove the PID and state files.
pub fn handle_exit() {
    if let Some(c) = SIG.get() {
        delete_pid(&c.name, &c.log);
        delete_state(&c.name);
    }
}

#[cfg(unix)]
extern "C" fn handle_sig(sig: libc::c_int) {
    if let Some(c) = SIG.get() {
        // SAFETY: strsignal returns a pointer to a string (or NULL).
        let name = unsafe {
            let p = libc::strsignal(sig);
            if p.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };
        c.log.info(format!("(1225): SIGNAL [({sig})-({name})] Received. Exit Cleaning..."));
    }
    handle_exit();
    std::process::exit(1);
}

/// `StartSIG`: SIGHUP and SIGPIPE ignored; SIGINT, SIGQUIT, SIGTERM and
/// SIGALRM log `SIGNAL_RECV` and exit after removing the PID/state files.
pub fn start_sig(name: &str, log: std::sync::Arc<WLog>) {
    let _ = SIG.set(SigCtx { name: name.to_string(), log });
    #[cfg(unix)]
    // SAFETY: installing handlers with valid function pointers.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        let h = handle_sig as extern "C" fn(libc::c_int) as libc::sighandler_t;
        for s in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGALRM] {
            libc::signal(s, h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_token() {
        assert_eq!(first_token("/var/ossec/bin", "/bin"), Some("/var/ossec"));
        assert_eq!(first_token("/opt/wazuh", "/bin"), Some("/opt/wazuh"));
        assert_eq!(first_token("/bin", "/bin"), None);
        assert_eq!(first_token("/bin/x/bin", "/bin"), Some("/x"));
    }

    #[test]
    fn pid_files() {
        let d = tempfile::tempdir().unwrap();
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(d.path()).unwrap();
        std::fs::create_dir_all("var/run").unwrap();
        let log = WLog::new("t", Path::new(""));
        log.now_daemon();
        create_pid("wazuh-test", std::process::id(), &log).unwrap();
        let f = pid_file("wazuh-test", std::process::id());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), format!("{}\n", std::process::id()));
        delete_pid("wazuh-test", &log);
        assert!(!Path::new(&f).exists());
        std::env::set_current_dir(cwd).unwrap();
    }
}
