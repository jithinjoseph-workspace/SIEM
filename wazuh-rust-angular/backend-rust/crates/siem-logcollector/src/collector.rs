//! `logcollector/logcollector.c`: `LogCollectorStart` (set-up and the file
//! check loop), file handling (`handle_file`, `reload_file`, `close_file`,
//! `update_fname`, `set_read`), glob expansion and exclusion, duplicate
//! detection, the binary-file filter, `set_sockets`, the input threads and
//! `check_ignore_and_restrict`.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};

#[cfg(unix)]
use siem_config::localfile::c_glob;
use siem_config::localfile::{EVENTCHANNEL, EVENTLOG, JOURNALD_LOG, MACOS, MULTI_LINE_REGEX};
use siem_regex::Expression;

use crate::output;
use crate::readers;
#[cfg(windows)]
use crate::win;
use crate::status::{set_to_last_line_read, set_to_pos, update_hash_node};
use crate::*;

const MAX_ASCII_LINES: u32 = 10;
const MAX_UTF8_CHARS: u32 = 1400;

/// The daemon, for the `atexit` hook.
pub static LC: OnceLock<Arc<Lc>> = OnceLock::new();

/// `wfopen(path, "rb")`: on Windows network paths are refused (EACCES).
pub fn wfopen_rb(lc: &Lc, path: &str) -> std::io::Result<CFile> {
    #[cfg(windows)]
    if siem_fileop::crt::is_network_path(path) {
        lc.log.warn(siem_fileop::crt::network_path_executed(path));
        return Err(std::io::Error::from_raw_os_error(13));
    }
    let _ = lc;
    CFile::open(path)
}

extern "C" fn save_status_hook() {
    if let Some(lc) = LC.get() {
        crate::status::save_file_status(lc);
    }
}

/// `w_create_thread`
pub fn spawn(lc: &Arc<Lc>, name: &str, f: impl FnOnce(Arc<Lc>) + Send + 'static) {
    let a = Arc::clone(lc);
    let b = std::thread::Builder::new().name(name.to_string());
    #[cfg(unix)]
    let b = {
        let kib = lc.define_int("wazuh", "thread_stack_size", 2048, 65536) as usize;
        lc.log.debug2(format!("Thread stack size set to: {kib} KiB"));
        b.stack_size(kib * 1024)
    };
    // Windows: CreateThread with the default stack
    let _ = b.spawn(move || f(a));
}

/// `check_ignore_and_restrict`: true when the line must be dropped.
pub fn check_ignore_and_restrict(
    lc: &Lc,
    ignore: &Option<Arc<Vec<Expression>>>,
    restrict: &Option<Arc<Vec<Expression>>>,
    line: &[u8],
) -> bool {
    let line = cstr(line);
    if let Some(l) = ignore {
        for e in l.iter() {
            if e.match_bytes(line, None).0 {
                lc.log.debug2(format!(
                    "(1976): Ignoring the log line '{}' due to ignore config: '{}'",
                    String::from_utf8_lossy(line),
                    e.pattern().unwrap_or("")
                ));
                return true;
            }
        }
    }
    if let Some(l) = restrict {
        for e in l.iter() {
            if !e.match_bytes(line, None).0 {
                lc.log.debug2(format!(
                    "(1976): Ignoring the log line '{}' due to restrict config: '{}'",
                    String::from_utf8_lossy(line),
                    e.pattern().unwrap_or("")
                ));
                return true;
            }
        }
    }
    false
}

/// `(fd, dev)` of the open entries other than `(si, sj)` (for
/// `find_duplicate_inode`). Busy entries are skipped.
fn open_inodes(files: &Files, si: i32, sj: i32) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let (mut r, mut k) = (0, -1);
    loop {
        match files.update_current(&mut r, &mut k) {
            It::Next => {
                r += 1;
                continue;
            }
            It::Leave => break,
            It::Continue => {}
        }
        if !(r == si && k == sj) {
            if let Ok(d) = files.entry(r, k).try_lock() {
                if d.fp.is_some() {
                    out.push((d.fd, d.dev));
                }
            }
        }
        r += 1;
    }
    out
}

/// `handle_file(i, j, do_fseek, do_log)` on the entry `lf`.
pub fn handle_file(lc: &Lc, lf: &mut Reader, j: i32, do_fseek: bool, do_log: bool, others: &[(u64, u64)]) -> i32 {
    let file = lf.file().to_string();
    let err = |lc: &Lc, lf: &mut Reader| {
        lf.c.ign += 1;
        let att = get(&lc.ints.open_file_attempts);
        if att != 0 && j < 0 {
            lc.log.debug1(format!("(1962): Unable to open file '{file}'. Remaining attempts: {}", att - lf.c.ign));
        } else {
            lc.log.debug1(format!("(1963): Unable to open file '{file}'."));
        }
        -1
    };
    let fp = match wfopen_rb(lc, &file) {
        Ok(f) => f,
        Err(e) => {
            if do_log && lf.c.exists == 1 {
                lc.log.error(fopen_error(&file, e.raw_os_error().unwrap_or(0)));
                lf.c.exists = 0;
            }
            return err(lc, lf);
        }
    };
    #[cfg(unix)]
    let is_reg = {
        use std::os::unix::fs::MetadataExt;
        let md = match fp.file().unwrap().metadata() {
            Ok(m) => m,
            Err(e) => {
                lc.log.error(fstat_error(&file, e.raw_os_error().unwrap_or(0)));
                return err(lc, lf);
            }
        };
        lf.fd = md.ino();
        lf.size = md.size() as i64;
        lf.dev = md.dev();
        md.file_type().is_file()
    };
    // Windows: the "inode" is nFileIndexLow + nFileIndexHigh
    #[cfg(windows)]
    match win::fp_info(&fp) {
        None => {
            lc.log.error("Unable to get file information by handle.");
            return err(lc, lf);
        }
        Some(i) => {
            lf.fd = i.fd as u64;
            lf.size = i.off_t();
        }
    }
    lf.fp = Some(fp);

    if others.iter().any(|&(fd, dev)| fd == lf.fd && dev == lf.dev) {
        lc.log.debug1(format!("(1966): Inode for file '{file}' already found. Skipping it."));
        close_file(lf);
        return 0;
    }

    // Windows and fseek causes some weird issues: no seek there
    #[cfg(windows)]
    let _ = do_fseek;
    #[cfg(unix)]
    if do_fseek && is_reg {
        if lf.c.future == 0 {
            if set_to_last_line_read(lc, lf) < 0 {
                return err(lc, lf);
            }
        } else {
            let off = set_to_pos(lc, lf, 0, 2);
            if off < 0 {
                return err(lc, lf);
            }
            update_hash_node(lc, &file, off);
        }
    }
    lf.c.ign = 0;
    lf.c.exists = 1;
    0
}

/// `reload_file`
pub fn reload_file(lf: &mut Reader) -> i32 {
    #[cfg(windows)]
    if siem_fileop::crt::is_network_path(lf.file()) {
        return -1;
    }
    match CFile::open(lf.file()) {
        Ok(mut f) => {
            f.fsetpos(lf.position);
            lf.fp = Some(f);
            0
        }
        Err(_) => -1,
    }
}

/// `close_file`
pub fn close_file(lf: &mut Reader) {
    if let Some(fp) = lf.fp.take() {
        lf.position = fp.fgetpos();
    }
}

/// `update_fname`: true when the date-based name changed.
pub fn update_fname(lc: &Lc, lf: &mut Reader) -> bool {
    #[cfg(unix)]
    // SAFETY: time/localtime_r on valid buffers.
    let mday = unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        tm.tm_mday
    };
    #[cfg(windows)]
    let mday = {
        use chrono::Datelike;
        chrono::Local::now().day() as i32
    };
    if mday == lc.cday.load(Ordering::SeqCst) {
        return false;
    }
    let ffile = lf.c.ffile.clone().unwrap_or_default();
    let Some(lfile) = siem_config::localfile::strftime_now(&ffile, 256) else {
        lc.exit_critical(format!("(1906): Error parsing file: '{ffile}'."));
    };
    if lf.c.file.as_deref() != Some(lfile.as_str()) {
        lc.log.info(format!("(1952): Monitoring variable log file: '{lfile}'."));
        lf.c.file = Some(lfile);
        lc.cday.store(0, Ordering::SeqCst);
        return true;
    }
    lc.cday.store(mday, Ordering::SeqCst);
    false
}

/// `set_read`
pub fn set_read(lc: &Lc, lf: &mut Reader, j: i32, others: &[(u64, u64)]) {
    lf.c.command = None;
    lf.c.ign = 0;
    crate::state::update_file(lc, lf.file(), 0);
    if lf.c.ffile.is_some() {
        lc.cday.store(0, Ordering::SeqCst);
        if update_fname(lc, lf) {
            handle_file(lc, lf, j, true, true, others);
        } else {
            let f = lf.c.ffile.clone().unwrap_or_default();
            lc.exit_critical(format!("(1906): Error parsing file: '{f}'."));
        }
    } else {
        handle_file(lc, lf, j, true, true, others);
    }
    if let Some(t) = lf.c.target.clone() {
        for x in t.iter() {
            lc.log.debug1(format!("Socket target for '{}' -> {x}", lf.file()));
            crate::state::update_target(lc, lf.file(), x, false);
        }
    }
    let fmt = lf.c.logformat.clone().unwrap_or_default();
    // Windows: without the ossecalert `if` the chain hangs from the
    // snort-full test (snort-full keeps read_snortfull, ossecalert is read
    // as syslog), and plain files may be UCS-2.
    #[cfg(windows)]
    {
        lf.read = Some(if fmt == "snort-full" {
            readers::read_snortfull
        } else if fmt == "nmapg" {
            readers::read_nmapg
        } else if fmt == "json" {
            readers::read_json
        } else if fmt == "mysql_log" {
            readers::read_mysql_log
        } else if fmt == "mssql_log" {
            readers::read_mssql_log
        } else if fmt == "postgresql_log" {
            readers::read_postgresql_log
        } else if fmt == "djb-multilog" {
            if !readers::init_djbmultilog(lc, lf) {
                lc.log.error(format!("(1953): Invalid DJB multilog file: '{}'.", lf.file()));
                lf.fp = None;
                lf.c.file = None;
            }
            readers::read_djbmultilog
        } else if fmt.starts_with("multi-line:") {
            readers::read_multiline
        } else if fmt == "audit" {
            readers::read_audit
        } else if fmt == MULTI_LINE_REGEX {
            readers::read_multiline_regex
        } else {
            if lf.c.filter_binary != 0 && win::file_size_win(lc, lf.file()) == 0 {
                // If the file is empty, set it to UCS-2 LE
                lf.c.ucs2 = win::UCS2_LE;
                lf.read = Some(readers::ucs2::read_ucs2_le);
                lc.log.debug2(format!("File '{}' is empty. Setting encoding to UCS-2 LE.", lf.file()));
                return;
            }
            if lf.c.ucs2 == win::UCS2_LE {
                lc.log.debug1(format!("File '{}' is UCS-2 LE", lf.file()));
                lf.read = Some(readers::ucs2::read_ucs2_le);
                return;
            }
            if lf.c.ucs2 == win::UCS2_BE {
                lc.log.debug1(format!("File '{}' is UCS-2 BE", lf.file()));
                lf.read = Some(readers::ucs2::read_ucs2_be);
                return;
            }
            readers::read_syslog
        });
        return;
    }
    // C sets read_snortfull in a separate `if`, then the chain below
    // overrides it with read_syslog: snort-full files are read as syslog.
    #[allow(unreachable_code)]
    if fmt == "snort-full" {
        lf.read = Some(readers::read_snortfull);
    }
    lf.read = Some(if fmt == "ossecalert" {
        readers::read_ossecalert
    } else if fmt == "nmapg" {
        readers::read_nmapg
    } else if fmt == "json" {
        readers::read_json
    } else if fmt == "mysql_log" {
        readers::read_mysql_log
    } else if fmt == "mssql_log" {
        readers::read_mssql_log
    } else if fmt == "postgresql_log" {
        readers::read_postgresql_log
    } else if fmt == "djb-multilog" {
        if !readers::init_djbmultilog(lc, lf) {
            lc.log.error(format!("(1953): Invalid DJB multilog file: '{}'.", lf.file()));
            lf.fp = None;
            lf.c.file = None;
        }
        readers::read_djbmultilog
    } else if fmt.starts_with("multi-line:") {
        readers::read_multiline
    } else if fmt == "audit" {
        readers::read_audit
    } else if fmt == MULTI_LINE_REGEX {
        readers::read_multiline_regex
    } else {
        readers::read_syslog
    });
}

/// `Remove_Localfile` on `logff` (`fr = 1`) or a glob (`gl = 1`).
fn remove_entry(lc: &Lc, files: &mut Files, i: i32, j: i32) -> i32 {
    let mut cur = lc.current_files.load(Ordering::SeqCst);
    let r = if j < 0 {
        let mut size = 0;
        while size < files.logff.len() {
            let r = files.logff[size].get_mut().unwrap_or_else(|e| e.into_inner());
            if !(r.c.file.is_some() || r.c.logformat.is_some()) {
                break;
            }
            size += 1;
        }
        if (i as usize) < size {
            files.logff.remove(i as usize);
            cur -= 1;
            0
        } else {
            -1
        }
    } else {
        let g = &mut files.globs[j as usize];
        let mut size = 0;
        while size < g.gfiles.len() && g.gfiles[size].get_mut().unwrap_or_else(|e| e.into_inner()).c.file.is_some() {
            size += 1;
        }
        if (i as usize) < size {
            g.gfiles.remove(i as usize);
            g.num_files -= 1;
            cur -= 1;
            0
        } else {
            -1
        }
    };
    lc.current_files.store(cur, Ordering::SeqCst);
    r
}

/// `remove_duplicates`: true (`NEXT_IT`) when `(i, j)` was removed.
fn remove_duplicates(lc: &Lc, files: &mut Files, i: i32, j: i32) -> bool {
    let (file, is_cmd) = {
        let c = files.entry_mut(i, j);
        (c.c.file.clone(), c.c.command.is_some())
    };
    let Some(file) = file else { return false };
    if is_cmd {
        return false;
    }
    let (mut r, mut k) = (0, -1);
    loop {
        match files.update_current(&mut r, &mut k) {
            It::Next => {
                r += 1;
                continue;
            }
            It::Leave => break,
            It::Continue => {}
        }
        let same = r == i && k == j;
        let dup = !same && files.entry(r, k).lock().unwrap_or_else(|e| e.into_inner()).c.file.as_deref() == Some(&file);
        if dup {
            lc.log.warn(format!("(1958): Log file '{file}' is duplicated."));
            if remove_entry(lc, files, i, j) != 0 {
                lc.exit_critical(format!("(1956): Error removing '{file}' file."));
            }
            lc.log.debug1(lc.current_files_msg());
            return true;
        }
        r += 1;
    }
    false
}

/// `set_sockets`
fn set_sockets(lc: &Lc, files: &mut Files) {
    let logsk = lc.logsk.read().unwrap().clone();
    for s in &logsk {
        lc.log.debug1(format!(
            "Socket '{}' ({}) added. Location: {}",
            s.name,
            if s.mode == siem_config::socket::SocketMode::Udp { "udp" } else { "tcp" },
            s.location
        ));
    }
    let mut work: Vec<(&mut Reader, String)> = Vec::new();
    for m in files.logff.iter_mut() {
        let r = m.get_mut().unwrap_or_else(|e| e.into_inner());
        let Some(f) = r.c.file.clone() else { break };
        work.push((r, f));
    }
    for g in files.globs.iter_mut() {
        let gp = g.gpath.clone();
        if let Some(m) = g.gfiles.first_mut() {
            work.push((m.get_mut().unwrap_or_else(|e| e.into_inner()), gp));
        }
    }
    for (cur, file) in work {
        let targets = cur.c.target.clone().unwrap_or_default();
        let mut lt: Vec<LogTarget> = Vec::new();
        for t in targets.iter() {
            if t == "agent" {
                lt.push(LogTarget { format: None, socket: Arc::clone(&lc.default_agent) });
                output::hash_queues_add_entry(lc, "agent");
                continue;
            }
            match logsk.iter().find(|s| &s.name == t) {
                Some(s) => {
                    lt.push(LogTarget { format: None, socket: Arc::clone(s) });
                    output::hash_queues_add_entry(lc, &s.name);
                }
                None => lc.exit_critical(format!("Socket '{t}' for '{file}' is not defined.")),
            }
        }
        if let Some(of) = cur.c.out_format.clone() {
            for o in of.iter() {
                if let Some(ot) = &o.target {
                    match targets.iter().position(|t| t == ot) {
                        Some(k) => lt[k].format = Some(o.format.clone()),
                        None => lc.log.warn(format!(
                            "Log target '{ot}' not found for the output format of localfile '{}'.",
                            cur.file()
                        )),
                    }
                } else {
                    for x in lt.iter_mut() {
                        if x.format.is_none() {
                            x.format = Some(o.format.clone());
                        }
                    }
                }
            }
        }
        cur.log_target = Some(Arc::new(lt));
    }
}

/// `check_pattern_expand(do_seek)` (Windows): the patterns are expanded
/// with `expand_win32_wildcards`, and a new file must open to be added
/// (Windows caches deleted files).
#[cfg(windows)]
fn check_pattern_expand(lc: &Lc, files: &mut Files, do_seek: bool) -> bool {
    let mut retval = false;
    let maxf = get(&lc.ints.maximum_files);
    let limit = |lc: &Lc| {
        lc.log.warn(format!(
            "(1960): File limit has been reached ({maxf}). Please reduce the number of files or increase \"logcollector.max_files\"."
        ))
    };
    for j in 0..files.globs.len() {
        if lc.current_files.load(Ordering::SeqCst) >= maxf {
            limit(lc);
            break;
        }
        let gpath = files.globs[j].gpath.clone();
        let Some(result) = win::expand_win32_wildcards(lc, &gpath) else { continue };
        for full_path in result {
            if lc.current_files.load(Ordering::SeqCst) >= maxf {
                limit(lc);
                break;
            }
            let g = &mut files.globs[j];
            let i = g
                .gfiles
                .iter_mut()
                .position(|m| m.get_mut().unwrap_or_else(|e| e.into_inner()).c.file.is_none())
                .unwrap_or(g.gfiles.len());
            let found = g.gfiles[..i]
                .iter_mut()
                .any(|m| m.get_mut().unwrap_or_else(|e| e.into_inner()).c.file.as_deref() == Some(full_path.as_str()));
            if found {
                continue;
            }
            retval = true;
            let mut added = false;
            let ex = lc.excluded_files.lock().unwrap().contains(&full_path);
            if !ex {
                if win::Handle::open(lc, &full_path).is_none() {
                    continue;
                }
                lc.log.info(format!("(1957): New file that matches the '{gpath}' pattern: '{full_path}'."));
                insert_glob_file(lc, files, j, i, &full_path, do_seek);
                added = true;
            }
            let bin = lc.excluded_binaries.lock().unwrap().contains(&full_path);
            if bin && !added {
                insert_glob_file(lc, files, j, i, &full_path, do_seek);
            }
        }
    }
    retval
}

/// `check_pattern_expand(do_seek)`: true when new files were found.
#[cfg(unix)]
fn check_pattern_expand(lc: &Lc, files: &mut Files, do_seek: bool) -> bool {
    let mut retval = false;
    let maxf = get(&lc.ints.maximum_files);
    for j in 0..files.globs.len() {
        if lc.current_files.load(Ordering::SeqCst) >= maxf {
            break;
        }
        let gpath = files.globs[j].gpath.clone();
        let paths = match c_glob(&gpath) {
            Ok(p) if !p.is_empty() => p,
            Ok(_) => {
                lc.log.debug1(format!("(1122): No file found by pattern: '{gpath}'."));
                continue;
            }
            Err(()) => {
                lc.log.debug1(format!("(1121): Glob error. Invalid pattern: '{gpath}'."));
                continue;
            }
        };
        for path in paths {
            if lc.current_files.load(Ordering::SeqCst) >= maxf {
                lc.log.warn(format!(
                    "(1960): File limit has been reached ({maxf}). Please reduce the number of files or increase \"logcollector.max_files\"."
                ));
                break;
            }
            let md = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    let n = e.raw_os_error().unwrap_or(0);
                    lc.log.error(format!("Error on stat '{path}' due to [({n})-({})]", strerror(n)));
                    continue;
                }
            };
            if !md.file_type().is_file() {
                lc.log.debug1(format!("File {path} is not a regular file. Skipping it."));
                continue;
            }
            let g = &mut files.globs[j];
            let i = g
                .gfiles
                .iter_mut()
                .position(|m| m.get_mut().unwrap_or_else(|e| e.into_inner()).c.file.is_none())
                .unwrap_or(g.gfiles.len());
            let found = g.gfiles[..i]
                .iter_mut()
                .any(|m| m.get_mut().unwrap_or_else(|e| e.into_inner()).c.file.as_deref() == Some(path.as_str()));
            if found {
                continue;
            }
            retval = true;
            let ex = lc.excluded_files.lock().unwrap().contains(&path);
            let bin = lc.excluded_binaries.lock().unwrap().contains(&path);
            if !ex || bin {
                if !ex {
                    lc.log.info(format!("(1957): New file that matches the '{gpath}' pattern: '{path}'."));
                }
                insert_glob_file(lc, files, j, i, &path, do_seek);
            }
        }
    }
    retval
}

/// The insertion part of `check_pattern_expand`.
fn insert_glob_file(lc: &Lc, files: &mut Files, j: usize, i: usize, path: &str, do_seek: bool) {
    let others = open_inodes(files, -2, -2);
    let g = &mut files.globs[j];
    let mut entry = {
        let tpl = g.gfiles[i].get_mut().unwrap_or_else(|e| e.into_inner());
        let e = tpl.copy();
        tpl.c.target = None;
        e
    };
    entry.c.file = Some(path.to_string());
    entry.fp = None;
    entry.c.exists = 1;
    let has_read = entry.read.is_some();
    g.gfiles.insert(i, Mutex::new(entry));
    lc.current_files.fetch_add(1, Ordering::SeqCst);
    g.num_files += 1;
    lc.log.debug2(lc.current_files_msg());
    let e = g.gfiles[i].get_mut().unwrap_or_else(|e| e.into_inner());
    if !has_read {
        set_read(lc, e, j as i32, &others);
    } else {
        handle_file(lc, e, j as i32, do_seek, true, &others);
    }
}

/// `check_pattern_expand_excluded` (Windows): the files of the exclusion's
/// directory whose names match its last component, as an OS_Regex.
#[cfg(windows)]
fn check_pattern_expand_excluded(lc: &Lc, files: &mut Files) {
    for j in 0..files.globs.len() {
        let Some(ex) = files.globs[j].exclude_path.clone() else { continue };
        let Some(sep) = ex.rfind('\\') else { continue };
        let (global_path, wildcard) = (&ex[..sep], &ex[sep + 1..]);
        let rd = match std::fs::read_dir(global_path) {
            Ok(r) => r,
            Err(_) => {
                lc.log.error(format!(
                    "Couldn't open directory '{global_path}' due to: {}",
                    siem_ipc::os_net::win_strerror(siem_ipc::os_net::wsa_errno() as u32)
                ));
                continue;
            }
        };
        for d in rd.flatten() {
            let name = d.file_name().to_string_lossy().into_owned();
            if name == "." || name == ".." {
                continue;
            }
            let full_path = format!("{global_path}\\{name}");
            if std::fs::metadata(&full_path).map(|m| m.is_dir()).unwrap_or(false) {
                lc.log.debug2(format!("File {full_path} is a directory. Skipping it."));
                continue;
            }
            // The "." replacement is computed and freed: only "*" counts
            let mut regex = format!("^{}", wildcard.replace('*', "\\.*"));
            if regex.len() == 4 {
                regex = regex.replace("\\.*", "\\.*\\.*");
            }
            regex.push('$');
            if !siem_regex::os_regex(&regex, &name) {
                lc.log.debug2(format!("Regex {regex} doesn't match with file '{name}'"));
                continue;
            }
            let g = &mut files.globs[j];
            let mut k = None;
            for (n, m) in g.gfiles.iter_mut().enumerate() {
                match &m.get_mut().unwrap_or_else(|e| e.into_inner()).c.file {
                    None => break,
                    Some(x) if *x == full_path => {
                        k = Some(n);
                        break;
                    }
                    _ => {}
                }
            }
            if let Some(k) = k {
                if remove_entry(lc, files, k as i32, j as i32) != 0 {
                    lc.exit_critical(format!("(1956): Error removing '{full_path}' file."));
                }
                if lc.excluded_files.lock().unwrap().insert(full_path.clone()) {
                    lc.log.info(format!("(1965): File excluded: '{full_path}'."));
                }
                lc.log.debug2(format!("(1965): File excluded: '{full_path}'."));
                lc.log.debug2(lc.current_files_msg());
            }
        }
    }
}

/// `check_pattern_expand_excluded`
#[cfg(unix)]
fn check_pattern_expand_excluded(lc: &Lc, files: &mut Files) {
    for j in 0..files.globs.len() {
        let Some(ex) = files.globs[j].exclude_path.clone() else { continue };
        let paths = match c_glob(&ex) {
            Ok(p) if !p.is_empty() => p,
            Ok(_) => {
                lc.log.debug1(format!("(1122): No file found by pattern: '{ex}'."));
                continue;
            }
            Err(()) => {
                lc.log.debug1(format!("(1121): Glob error. Invalid pattern: '{ex}'."));
                continue;
            }
        };
        for path in paths {
            let g = &mut files.globs[j];
            let mut k = None;
            for (n, m) in g.gfiles.iter_mut().enumerate() {
                let f = &m.get_mut().unwrap_or_else(|e| e.into_inner()).c.file;
                match f {
                    None => break,
                    Some(x) if *x == path => {
                        k = Some(n);
                        break;
                    }
                    _ => {}
                }
            }
            if let Some(k) = k {
                if remove_entry(lc, files, k as i32, j as i32) != 0 {
                    lc.exit_critical(format!("(1956): Error removing '{path}' file."));
                }
                let mut ex = lc.excluded_files.lock().unwrap();
                if ex.insert(path.clone()) {
                    lc.log.info(format!("(1965): File excluded: '{path}'."));
                }
                drop(ex);
                lc.log.debug2(lc.current_files_msg());
            }
        }
    }
}

/// `is_ascii_utf8`: 0 for a text file, 1 otherwise.
pub fn is_ascii_utf8(lc: &Lc, file: &str, max_lines: u32, max_chars: u32) -> i32 {
    let mut fp = match CFile::open(file) {
        Ok(f) => f,
        Err(_) => {
            lc.log.debug1(format!("(1963): Unable to open file '{file}'."));
            return 1;
        }
    };
    let begin = fp.fgetpos();
    let mut buffer = vec![0u8; OS_MAXSTR + 1];
    let mut is_ascii = true;
    let mut lines = 0;
    while fp.fgets(&mut buffer, OS_MAXSTR) {
        if lines >= max_lines {
            break;
        }
        lines += 1;
        // The whole buffer is scanned, old bytes included.
        if buffer[..OS_MAXSTR].iter().any(|&c| c >= 0x80) {
            is_ascii = false;
            break;
        }
    }
    if is_ascii {
        return 0;
    }
    fp.fsetpos(begin);
    let mut chars = 0;
    loop {
        let mut b = [0u8; 4];
        let n = fp.fread(&mut b);
        if n == 0 {
            break;
        }
        if chars >= max_chars {
            break;
        }
        chars += 1;
        let back = |fp: &mut CFile, off: i64, lc: &Lc| {
            if fp.fseek(off, 1) != 0 {
                let e = errno();
                lc.log.error(format!(
                    "(1116): Could not set position in file '{file}' due to [({e})-({})].",
                    strerror(e)
                ));
            }
        };
        let in_r = |c: u8, a: u8, z: u8| c >= a && c <= z;
        if b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
            back(&mut fp, -1, lc);
            continue;
        }
        if b[0] == 0x09 || b[0] == 0x0A || b[0] == 0x0D || in_r(b[0], 0x20, 0x7E) {
            back(&mut fp, -(n as i64) + 1, lc);
            continue;
        }
        if in_r(b[0], 0xC2, 0xDF) && in_r(b[1], 0x80, 0xBF) {
            back(&mut fp, -2, lc);
            continue;
        }
        if b[0] == 0xE0 && in_r(b[1], 0xA0, 0xBF) && in_r(b[2], 0x80, 0xBF) {
            back(&mut fp, -1, lc);
            continue;
        }
        if (in_r(b[0], 0xE1, 0xEC) || b[0] == 0xEE || b[0] == 0xEF) && in_r(b[1], 0x80, 0xBF) && in_r(b[2], 0x80, 0xBF) {
            back(&mut fp, -1, lc);
            continue;
        }
        if b[0] == 0xED && in_r(b[1], 0x80, 0x9F) && in_r(b[2], 0x80, 0xBF) {
            back(&mut fp, -1, lc);
            continue;
        }
        if b[0] == 0xF0 && in_r(b[1], 0x90, 0xBF) && in_r(b[2], 0x80, 0xBF) && in_r(b[3], 0x80, 0xBF) {
            continue;
        }
        if in_r(b[0], 0xF1, 0xF3) && in_r(b[1], 0x80, 0xBF) && in_r(b[2], 0x80, 0xBF) && in_r(b[3], 0x80, 0xBF) {
            continue;
        }
        if b[0] == 0xF4 && in_r(b[1], 0x80, 0x8F) && in_r(b[2], 0x80, 0xBF) && in_r(b[3], 0x80, 0xBF) {
            continue;
        }
        return 1;
    }
    0
}

/// `check_text_only`
fn check_text_only(lc: &Lc, files: &mut Files) {
    let (mut i, mut j) = (0, -1);
    loop {
        match files.update_current(&mut i, &mut j) {
            It::Next => {
                i += 1;
                continue;
            }
            It::Leave => break,
            It::Continue => {}
        }
        let (file, check) = {
            let c = files.entry_mut(i, j);
            (c.c.file.clone(), c.c.command.is_none() && c.c.filter_binary != 0)
        };
        if let (Some(file), true) = (file, check) {
            let excluded = lc.excluded_files.lock().unwrap().contains(&file);
            if is_ascii_utf8(lc, &file, MAX_ASCII_LINES, MAX_UTF8_CHARS) != 0 {
                // Windows: a UCS-2 file is kept
                #[cfg(windows)]
                {
                    let u = win::is_usc2(lc, &file);
                    if u != 0 {
                        files.entry_mut(i, j).c.ucs2 = u;
                        i += 1;
                        continue;
                    }
                }
                if remove_entry(lc, files, i, j) != 0 {
                    lc.exit_critical(format!("(1956): Error removing '{file}' file."));
                }
                lc.log.debug2(format!("(1964): File '{file}' is not ASCII or UTF-8 encoded."));
                lc.log.debug2(lc.current_files_msg());
                if !excluded {
                    lc.excluded_files.lock().unwrap().insert(file.clone());
                }
                lc.excluded_binaries.lock().unwrap().insert(file.clone());
                i -= 1;
            } else if excluded {
                lc.excluded_files.lock().unwrap().remove(&file);
            }
        }
        i += 1;
    }
}

/// The "forget file" steps repeated in the check loop.
fn forget_file(lc: &Lc, file: &str) {
    lc.log.info(format!("(1959): File '{file}' no longer exists."));
    lc.status.delete(file);
    crate::state::delete_file(lc, file);
}

/// After `ign++` in the check loop: remove a glob file, or log the attempts.
/// Returns true when the entry was removed (`i--; continue`).
fn ign_and_maybe_remove(lc: &Lc, files: &mut Files, i: i32, j: i32, file: &str) -> bool {
    if j >= 0 {
        if remove_entry(lc, files, i, j) != 0 {
            lc.log.error(format!("(1956): Error removing '{file}' file."));
        } else {
            lc.log.debug1(lc.current_files_msg());
            return true;
        }
    } else {
        let att = get(&lc.ints.open_file_attempts);
        let ign = files.entry_mut(i, j).c.ign;
        if att != 0 {
            lc.log.debug1(format!("(1962): Unable to open file '{file}'. Remaining attempts: {}", att - ign));
        } else {
            lc.log.debug1(format!("(1963): Unable to open file '{file}'."));
        }
    }
    false
}

/// One pass of the "Check if any file has been renamed/removed" loop
/// (Windows: the file is checked through a new handle).
#[cfg(windows)]
fn check_files(lc: &Lc, files: &mut Files) {
    let att = get(&lc.ints.open_file_attempts);
    let (mut i, mut j) = (0, -1);
    loop {
        match files.update_current(&mut i, &mut j) {
            It::Next => {
                i += 1;
                continue;
            }
            It::Leave => break,
            It::Continue => {}
        }
        let others = open_inodes(files, i, j);
        let cur = files.entry_mut(i, j);
        let Some(file) = cur.c.file.clone() else {
            i += 1;
            continue;
        };

        // Files with date -- check for day change
        if cur.c.ffile.is_some() {
            if update_fname(lc, cur) {
                cur.fp = None;
                cur.c.exists = 1;
                handle_file(lc, cur, j, false, true, &others);
                i += 1;
                continue;
            } else if cur.fp.is_none() && att - cur.c.ign > 0 {
                handle_file(lc, cur, j, true, true, &others);
                i += 1;
                continue;
            }
        }

        if cur.fp.is_some() {
            let info = match win::Handle::open(lc, &file).map(|h| h.info()) {
                Some(Some(i)) => Some(i),
                _ => {
                    cur.fp = None;
                    lc.log.info(format!("(9200): File '{file}' can not be handled."));
                    None
                }
            };
            match info {
                None => {
                    if cur.c.exists == 1 {
                        forget_file(lc, &file);
                        files.entry_mut(i, j).c.exists = 0;
                    }
                    files.entry_mut(i, j).c.ign += 1;
                    if j >= 0 {
                        if remove_entry(lc, files, i, j) != 0 {
                            lc.log.error(format!("(1956): Error removing '{file}' file."));
                        } else {
                            lc.log.debug2(lc.current_files_msg());
                            continue;
                        }
                    } else {
                        let ign = files.entry_mut(i, j).c.ign;
                        if att != 0 {
                            lc.log.debug1(format!("(1962): Unable to open file '{file}'. Remaining attempts: {}", att - ign));
                        } else {
                            lc.log.debug1(format!("(1963): Unable to open file '{file}'."));
                        }
                    }
                }
                Some(st) => {
                    let cur = files.entry_mut(i, j);
                    if cur.fd != st.fd as u64 {
                        cur.c.exists = 1;
                        let mut b = format!("ossec: File rotated (inode changed): '{file}'.").into_bytes();
                        b.truncate(511);
                        output::push(lc, &b, "logcollector", b.len() + 1, &default_target(lc), LOCALFILE_MQ);
                        lc.log.debug1(format!("File inode changed. {file}"));
                        lc.status.delete(&file);
                        crate::state::delete_file(lc, &file);
                        let cur = files.entry_mut(i, j);
                        cur.fp = None;
                        handle_file(lc, cur, j, false, true, &others);
                        i += 1;
                        continue;
                    } else if (cur.size as i32 as u32) > st.size {
                        cur.c.exists = 1;
                        let mut b = format!("ossec: File size reduced (inode remained): '{file}'.").into_bytes();
                        b.truncate(511);
                        output::push(lc, &b, "logcollector", b.len() + 1, &default_target(lc), LOCALFILE_MQ);
                        lc.log.debug1(format!("File size reduced. {file}"));
                        lc.status.delete(&file);
                        crate::state::delete_file(lc, &file);
                        let cur = files.entry_mut(i, j);
                        cur.fp = None;
                        handle_file(lc, cur, j, false, true, &others);
                    } else {
                        cur.size = st.off_t();
                    }
                }
            }
        } else {
            let fmt = cur.c.logformat.clone().unwrap_or_default();
            if cur.c.command.is_none() && fmt != EVENTCHANNEL && fmt != EVENTLOG {
                let exists = matches!(win::Handle::open(lc, &file).map(|h| h.info()), Some(Some(_)));
                if !exists {
                    lc.log.debug1(format!("(9200): File '{file}' can not be handled."));
                    crate::state::delete_file(lc, &file);
                }
                if j >= 0 {
                    if !exists {
                        if remove_entry(lc, files, i, j) != 0 {
                            lc.log.error(format!("(1956): Error removing '{file}' file."));
                        } else {
                            lc.log.debug2(lc.current_files_msg());
                            continue;
                        }
                    }
                } else {
                    let ign = files.entry_mut(i, j).c.ign;
                    if att != 0 {
                        lc.log.debug1(format!("(1962): Unable to open file '{file}'. Remaining attempts: {}", att - ign));
                    } else {
                        lc.log.debug1(format!("(1963): Unable to open file '{file}'."));
                    }
                }
            }
        }

        let cur = files.entry_mut(i, j);
        if att == 0 {
            cur.c.ign = -1;
        }
        if cur.c.ign >= att {
            if cur.c.ign == 999 {
                i += 1;
                continue;
            }
            if cur.c.logformat.as_deref() == Some("eventchannel") {
                lc.log.debug1(format!("(1904): File not available, ignoring it: '{file}'."));
            } else {
                lc.log.info(format!("(1904): File not available, ignoring it: '{file}'."));
            }
            cur.fp = None;
            cur.c.ign = 999;
            // PathFileExists
            if j >= 0 && !std::path::Path::new(&file).exists() {
                lc.status.delete(&file);
                crate::state::delete_file(lc, &file);
                if remove_entry(lc, files, i, j) != 0 {
                    lc.log.error(format!("(1956): Error removing '{file}' file."));
                } else {
                    lc.log.debug1(lc.current_files_msg());
                    i -= 1;
                }
            }
            i += 1;
            continue;
        }

        if cur.fp.is_none() && cur.c.ign < 999 {
            let others = open_inodes(files, i, j);
            handle_file(lc, files.entry_mut(i, j), j, true, true, &others);
        }
        i += 1;
    }
}

/// One pass of the "Check if any file has been renamed/removed" loop.
#[cfg(unix)]
fn check_files(lc: &Lc, files: &mut Files) {
    use std::os::unix::fs::MetadataExt;
    let att = get(&lc.ints.open_file_attempts);
    let (mut i, mut j) = (0, -1);
    loop {
        match files.update_current(&mut i, &mut j) {
            It::Next => {
                i += 1;
                continue;
            }
            It::Leave => break,
            It::Continue => {}
        }
        let others = open_inodes(files, i, j);
        let cur = files.entry_mut(i, j);
        let Some(file) = cur.c.file.clone() else {
            i += 1;
            continue;
        };

        // Files with date -- check for day change
        if cur.c.ffile.is_some() {
            if update_fname(lc, cur) {
                cur.fp = None;
                cur.c.exists = 1;
                handle_file(lc, cur, j, false, true, &others);
                i += 1;
                continue;
            } else if cur.fp.is_none() && att - cur.c.ign > 0 {
                handle_file(lc, cur, j, true, true, &others);
                i += 1;
                continue;
            }
        }

        if cur.fp.is_some() {
            // Open the file a second time to get fresh metadata (hard links).
            match std::fs::File::open(&file) {
                Err(e) => {
                    let n = e.raw_os_error().unwrap_or(0);
                    if n == libc::ENOENT {
                        if cur.c.exists == 1 {
                            forget_file(lc, &file);
                            files.entry_mut(i, j).c.exists = 0;
                        }
                        files.entry_mut(i, j).c.ign += 1;
                        if ign_and_maybe_remove(lc, files, i, j, &file) {
                            continue;
                        }
                    } else {
                        lc.log.error(fopen_error(&file, n));
                    }
                }
                Ok(tf) => match tf.metadata() {
                    Err(e) => {
                        cur.fp = None;
                        lc.log.error(fstat_error(&file, e.raw_os_error().unwrap_or(0)));
                    }
                    Ok(st) => {
                        if cur.fd != st.ino() {
                            cur.c.exists = 1;
                            let msg = format!("ossec: File rotated (inode changed): '{file}'.");
                            let mut b = msg.clone().into_bytes();
                            b.truncate(511);
                            output::push(lc, &b, "logcollector", b.len() + 1, &default_target(lc), LOCALFILE_MQ);
                            lc.log.debug1(format!("File inode changed. {file}"));
                            lc.status.delete(&file);
                            crate::state::delete_file(lc, &file);
                            let cur = files.entry_mut(i, j);
                            cur.fp = None;
                            handle_file(lc, cur, j, false, true, &others);
                            i += 1;
                            continue;
                        } else if cur.size > st.size() as i64 {
                            cur.c.exists = 1;
                            let msg = format!("ossec: File size reduced (inode remained): '{file}'.");
                            let mut b = msg.into_bytes();
                            b.truncate(511);
                            output::push(lc, &b, "logcollector", b.len() + 1, &default_target(lc), LOCALFILE_MQ);
                            lc.log.debug1(format!("File size reduced. {file}"));
                            lc.status.delete(&file);
                            crate::state::delete_file(lc, &file);
                            let cur = files.entry_mut(i, j);
                            cur.fp = None;
                            handle_file(lc, cur, j, false, true, &others);
                        } else {
                            cur.c.exists = 1;
                            cur.size = st.size() as i64;
                        }
                    }
                },
            }
        }

        let cur = files.entry_mut(i, j);
        if att == 0 {
            cur.c.ign = -1;
        }
        if cur.c.ign >= att {
            if cur.c.ign == 999 {
                i += 1;
                continue;
            }
            if cur.c.logformat.as_deref() == Some("eventchannel") {
                lc.log.debug1(format!("(1904): File not available, ignoring it: '{file}'."));
            } else {
                lc.log.info(format!("(1904): File not available, ignoring it: '{file}'."));
            }
            cur.fp = None;
            cur.c.ign = 999;
            if j >= 0 {
                match std::fs::metadata(&file) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        lc.status.delete(&file);
                        crate::state::delete_file(lc, &file);
                        if remove_entry(lc, files, i, j) != 0 {
                            lc.log.error(format!("(1956): Error removing '{file}' file."));
                        } else {
                            lc.log.debug1(lc.current_files_msg());
                            i -= 1;
                        }
                    }
                    _ => {
                        let e = errno();
                        lc.log.error(fstat_error(&file, e));
                    }
                }
            }
            i += 1;
            continue;
        }

        if cur.fp.is_none() && cur.c.ign < 999 {
            let others = open_inodes(files, i, j);
            handle_file(lc, files.entry_mut(i, j), j, true, true, &others);
        }
        i += 1;
    }
}

/// `default_target` (`{ .log_socket = &default_agent }`).
pub fn default_target(lc: &Lc) -> Vec<LogTarget> {
    vec![LogTarget { format: None, socket: Arc::clone(&lc.default_agent) }]
}

/// Iterate entries with `f(files, i, j)`; `f` returns true when it removed
/// the entry (the C `i--; continue`).
fn for_each(files: &mut Files, mut f: impl FnMut(&mut Files, i32, i32) -> bool) {
    let (mut i, mut j) = (0, -1);
    loop {
        match files.update_current(&mut i, &mut j) {
            It::Next => {
                i += 1;
                continue;
            }
            It::Leave => break,
            It::Continue => {}
        }
        if f(files, i, j) {
            continue;
        }
        i += 1;
    }
}

/// `set_can_read(0)` + write lock + `set_can_read(1)`.
fn stop_readers(lc: &Lc) -> std::sync::RwLockWriteGuard<'_, Files> {
    lc.can_read.store(false, Ordering::SeqCst);
    let g = lc.files.write().unwrap_or_else(|e| e.into_inner());
    lc.can_read.store(true, Ordering::SeqCst);
    g
}

/// Windows: the seek `handle_file` does not do (IIS logs end with odd
/// bytes, so the position comes from the file status or the end).
#[cfg(windows)]
fn win_seek_start(lc: &Lc, cur: &mut Reader) {
    if cur.fp.is_some() {
        if cur.c.future == 0 {
            set_to_last_line_read(lc, cur);
        } else {
            let off = set_to_pos(lc, cur, 0, 2);
            update_hash_node(lc, &cur.file().to_string(), off);
        }
    }
}

/// `LogCollectorStart`
pub fn log_collector_start(lc: Arc<Lc>) -> ! {
    let _ = LC.set(Arc::clone(&lc));
    crate::status::initialize_file_status(&lc);
    if siem_log::cexit::register(save_status_hook) != 0 {
        lc.log.error("(1144): Unable to set exit function");
    }

    let si = get(&lc.ints.state_interval);
    if si == 0 {
        crate::state::init(&lc, crate::state::LC_STATE_GLOBAL, false);
    } else if si > 0 {
        crate::state::init(&lc, crate::state::LC_STATE_GLOBAL | crate::state::LC_STATE_INTERVAL, true);
    }
    spawn(&lc, "state", move |a| crate::state::state_main(&a, si));

    {
        let mut files = lc.files.write().unwrap();
        set_sockets(&lc, &mut files);
        check_pattern_expand(&lc, &mut files, true);
        check_pattern_expand_excluded(&lc, &mut files);
        #[cfg(windows)]
        {
            let m_uname = siem_fileop::version_op::getuname();
            // checkVista(): the agent only runs on 6.0 and later
            lc.log.info(format!("Windows version is 6.0 or newer. ({m_uname})."));
            crate::eventlog::win_read_vista_sec(&lc);
        }
        check_text_only(&lc, &mut files);
    }

    lc.log.debug1("Entering LogCollectorStart().");
    {
        let mut files = lc.files.write().unwrap();
        let (mut i, mut j) = (0, -1);
        loop {
            match files.update_current(&mut i, &mut j) {
                It::Next => {
                    i += 1;
                    continue;
                }
                It::Leave => break,
                It::Continue => {}
            }
            if remove_duplicates(&lc, &mut files, i, j) {
                continue;
            }
            let others = open_inodes(&files, i, j);
            let cur = files.entry_mut(i, j);
            let fmt = cur.c.logformat.clone().unwrap_or_default();
            if cur.c.file.is_none() {
                // duplicated entry
            } else if fmt == EVENTLOG || fmt == EVENTCHANNEL {
                #[cfg(windows)]
                {
                    let f = cur.c.file.clone().unwrap_or_default();
                    lc.log.info(format!("(1951): Analyzing event log: '{f}'."));
                    cur.c.channel_str = Some(f.clone());
                    if fmt == EVENTLOG {
                        crate::eventlog::win_startel(&lc, &f);
                    } else {
                        let query = cur.c.query.clone();
                        crate::eventchannel::win_start_event_channel(&lc, &f, cur.c.future != 0, query.as_deref(), cur.c.reconnect_time);
                    }
                }
                cur.c.file = None;
                cur.c.command = None;
                cur.fp = None;
            } else if fmt == "command" || fmt == "full_command" {
                cur.c.file = None;
                cur.fp = None;
                cur.size = 0;
                if let Some(cmd) = cur.c.command.clone() {
                    let full = fmt == "full_command";
                    cur.read = Some(if full { readers::read_fullcommand } else { readers::read_command });
                    lc.log.info(format!(
                        "Monitoring {}output of command({}): {cmd}",
                        if full { "full " } else { "" },
                        cur.c.ign
                    ));
                    if let Some(t) = &cur.c.target {
                        for x in t.iter() {
                            lc.log.debug1(format!("Socket target for '{cmd}' -> {x}"));
                        }
                    }
                    if cur.c.alias.is_none() {
                        cur.c.alias = Some(cmd);
                    }
                } else {
                    lc.log.error("Missing command argument. Ignoring it.");
                }
            } else if fmt == MACOS {
                lc.log.info("(9201): 'macos' log format is only supported on macOS.");
                cur.c.file = None;
                cur.c.command = None;
                cur.fp = None;
            } else if fmt == JOURNALD_LOG && cfg!(not(target_os = "linux")) {
                lc.log.info("(9202): 'Journald' log format is only available on Linux.");
                cur.c.journal_log = None;
                cur.c.file = None;
                cur.c.command = None;
                cur.fp = None;
            } else if fmt == JOURNALD_LOG {
                cur.read = Some(readers::read_journald);
                crate::journal::set_ofe(&lc, cur.c.future != 0);
                if let Some(t) = cur.c.target.clone() {
                    for x in t.iter() {
                        lc.log.debug1(format!("(9001): Socket target for '{JOURNALD_LOG}' -> {x}"));
                        crate::state::update_target(&lc, JOURNALD_LOG, x, false);
                    }
                }
                cur.c.file = None;
                cur.c.command = None;
                cur.fp = None;
            } else if j < 0 {
                set_read(&lc, cur, j, &others);
                if let Some(f) = &cur.c.file {
                    lc.log.info(format!("(1950): Analyzing file: '{f}'."));
                }
                #[cfg(windows)]
                win_seek_start(&lc, cur);
            } else {
                if let Some(f) = &cur.c.file {
                    lc.log.info(format!("(1950): Analyzing file: '{f}'."));
                }
                // On Windows the seek of wildcard files happens here
                #[cfg(windows)]
                win_seek_start(&lc, cur);
            }
            i += 1;
        }
    }

    crate::status::save_file_status(&lc);
    crate::logbuilder::init(&lc, true);

    // Output threads (one per queue)
    let names: Vec<String> = lc.queues.table.lock().unwrap().iter().map(|(n, _)| n.clone()).collect();
    for n in names {
        spawn(&lc, "output", move |a| output::output_thread(&a, &n));
    }
    // Input threads
    let n_in = lc.define_int("logcollector", "input_threads", N_MIN_INPUT_THREADS, 128);
    lc.ints.n_input_threads.store(n_in, Ordering::SeqCst);
    for _ in 0..n_in {
        spawn(&lc, "input", |a| input_thread(&a));
    }

    lc.log.info(format!("Started (pid: {}).", std::process::id()));
    lc.log.debug1(lc.current_files_msg());
    #[cfg(unix)]
    spawn(&lc, "lccom", |a| crate::lccom::lccom_main(&a));
    lc.can_read.store(true, Ordering::SeqCst);

    let (mut f_check, mut f_reload, mut f_free_excluded) = (0, 0, 0);
    loop {
        if f_free_excluded >= get(&lc.ints.free_excluded_files_interval) {
            let g = stop_readers(&lc);
            lc.log.debug1("Refreshing excluded files list.");
            lc.excluded_files.lock().unwrap().clear();
            lc.excluded_binaries.lock().unwrap().clear();
            f_free_excluded = 0;
            drop(g);
        }

        if f_check >= get(&lc.ints.vcheck_files) {
            let mut files = stop_readers(&lc);
            f_reload += f_check;
            lc.log.debug1("Performing file check.");

            if get(&lc.ints.force_reload) != 0 && f_reload >= get(&lc.ints.reload_interval) {
                let delay = get(&lc.ints.reload_delay) as u64;
                for_each(&mut files, |fs, i, j| {
                    let c = fs.entry_mut(i, j);
                    if c.c.file.is_some() && c.fp.is_some() {
                        close_file(c);
                    }
                    false
                });
                drop(files);
                if delay != 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                }
                files = stop_readers(&lc);
                for_each(&mut files, |fs, i, j| {
                    let c = fs.entry_mut(i, j);
                    let Some(file) = c.c.file.clone() else { return false };
                    if c.c.exists != 0 && reload_file(c) == -1 {
                        forget_file(&lc, &file);
                        let c = fs.entry_mut(i, j);
                        c.c.exists = 0;
                        c.c.ign += 1;
                        return ign_and_maybe_remove(&lc, fs, i, j, &file);
                    }
                    false
                });
            }

            check_files(&lc, &mut files);

            if check_pattern_expand(&lc, &mut files, true) {
                let (mut i, mut j) = (0, -1);
                loop {
                    match files.update_current(&mut i, &mut j) {
                        It::Next => {
                            i += 1;
                            continue;
                        }
                        It::Leave => break,
                        It::Continue => {}
                    }
                    if remove_duplicates(&lc, &mut files, i, j) {
                        continue;
                    }
                    i += 1;
                }
            }
            check_pattern_expand_excluded(&lc, &mut files);
            check_text_only(&lc, &mut files);
            drop(files);

            if f_reload >= get(&lc.ints.reload_interval) {
                f_reload = 0;
            }
            crate::status::save_file_status(&lc);
            f_check = 0;
            if crate::logbuilder::update_all(&lc) == -1 {
                lc.log.debug1("Output log pattern data could not be updated.");
            }
        }
        sleep_secs(1);
        f_check += 1;
        f_free_excluded += 1;
    }
}

/// `w_input_thread`
pub fn input_thread(lc: &Lc) {
    #[cfg(unix)]
    let thread_id = {
        // pthread_self() as unsigned long
        // SAFETY: pthread_self has no preconditions.
        unsafe { libc::pthread_self() as u64 }
    };
    #[cfg(not(unix))]
    let thread_id = 0u64;
    let mut r = 0;
    loop {
        sleep_secs(get(&lc.ints.loop_timeout) as i64);
        // Check for messages in the event viewer
        #[cfg(windows)]
        if let Ok(_g) = lc.win_el_mutex.try_lock() {
            crate::eventlog::win_readel(lc);
        }
        let (mut i, mut j) = (0, -1);
        loop {
            let files = lc.files.read().unwrap_or_else(|e| e.into_inner());
            match files.update_current(&mut i, &mut j) {
                It::Next => {
                    i += 1;
                    continue;
                }
                It::Leave => break,
                It::Continue => {}
            }
            let Ok(mut cur) = files.entry(i, j).try_lock() else {
                i += 1;
                continue;
            };
            if cur.fp.is_none() {
                if cur.c.command.is_some() {
                    let t = now();
                    if t - cur.size >= cur.c.ign as i64 {
                        cur.size = t;
                        if let Some(read) = cur.read {
                            read(lc, &mut cur, &mut r, 0);
                        }
                    }
                } else if cur.c.journal_log.is_some() {
                    if crate::journal::can_read(lc, thread_id) {
                        if let Some(read) = cur.read {
                            read(lc, &mut cur, &mut r, 0);
                        }
                    } else {
                        lc.log.debug2("(9005): Skipping is not the owner of the journal log.");
                    }
                }
                i += 1;
                continue;
            }

            // Windows with IIS logs: the reader is always called (no EOF test)
            #[cfg(windows)]
            {
                if cur.c.age != 0 {
                    match cur.fp.as_ref().and_then(win::fp_info) {
                        None => {
                            lc.log.error("Unable to get file information.");
                            i += 1;
                            continue;
                        }
                        Some(info) => {
                            if win::time_epoch() - cur.c.age as i64 >= info.mtime {
                                lc.log.debug1(format!("Ignoring file '{}' due to modification time", cur.file()));
                                cur.fp = None;
                                i += 1;
                                continue;
                            }
                        }
                    }
                }
                let file = cur.file().to_string();
                let ucs2 = win::is_usc2(lc, &file);
                if ucs2 != 0 {
                    cur.c.ucs2 = ucs2;
                    if cur.c.filter_binary != 0 {
                        if win::file_size_win(lc, &file) == 0 {
                            cur.c.ucs2 = win::UCS2_LE;
                            cur.read = Some(readers::ucs2::read_ucs2_le);
                            lc.log.debug2(format!("File '{file}' is empty. Setting encoding to UCS-2 LE."));
                        } else {
                            if cur.c.ucs2 == win::UCS2_LE {
                                lc.log.debug1(format!("File '{file}' is UCS-2 LE"));
                                cur.read = Some(readers::ucs2::read_ucs2_le);
                            }
                            if cur.c.ucs2 == win::UCS2_BE {
                                lc.log.debug1(format!("File '{file}' is UCS-2 BE"));
                                cur.read = Some(readers::ucs2::read_ucs2_be);
                            }
                        }
                    }
                }
                if cur.c.filter_binary != 0 {
                    if win::file_size_win(lc, &file) == 0 {
                        cur.c.ucs2 = win::UCS2_LE;
                        cur.read = Some(readers::ucs2::read_ucs2_le);
                        lc.log.debug2(format!("File '{file}' is empty. Setting encoding to UCS-2 LE."));
                    } else if ucs2 == 0 {
                        let fmt = cur.c.logformat.clone().unwrap_or_default();
                        if fmt == "syslog" || fmt == "generic" {
                            cur.read = Some(readers::read_syslog);
                        } else if fmt == "multi-line" {
                            cur.read = Some(readers::read_multiline);
                        } else if fmt == MULTI_LINE_REGEX {
                            cur.read = Some(readers::read_multiline_regex);
                        }
                    }
                }
            }

            #[cfg(unix)]
            if cur.c.age != 0 {
                use std::os::unix::fs::MetadataExt;
                match cur.fp.as_ref().and_then(|f| f.file()).map(|f| f.metadata()) {
                    Some(Err(e)) => lc.log.error(fstat_error(cur.file(), e.raw_os_error().unwrap_or(0))),
                    Some(Ok(m)) => {
                        if now() - cur.c.age as i32 as i64 >= m.mtime() {
                            lc.log.debug1(format!("Ignoring file '{}' due to modification time", cur.file()));
                            cur.fp = None;
                            i += 1;
                            continue;
                        }
                    }
                    None => {}
                }
            }

            #[cfg(unix)]
            if cur.c.multiline.is_none() {
                let fp = cur.fp.as_mut().unwrap();
                let c = fp.fgetc();
                if c == -1 {
                    fp.clearerr();
                    i += 1;
                    continue;
                }
                fp.ungetc(c);
            }

            if let Some(read) = cur.read {
                read(lc, &mut cur, &mut r, 0);
            }

            let ferror = cur.fp.as_ref().map(|f| f.ferror()).unwrap_or(false);
            if !ferror {
                if let Some(fp) = cur.fp.as_mut() {
                    fp.clearerr();
                }
                if r != 0 {
                    cur.c.ign += 1;
                    let att = get(&lc.ints.open_file_attempts);
                    if att != 0 && j < 0 {
                        lc.log.debug1(format!(
                            "(1962): Unable to open file '{}'. Remaining attempts: {}",
                            cur.file(),
                            att - cur.c.ign
                        ));
                    } else {
                        lc.log.debug1(format!("(1963): Unable to open file '{}'.", cur.file()));
                    }
                }
            } else {
                let e = cur.fp.as_ref().map(|f| f.errno).unwrap_or(0);
                lc.log.error(format!(
                    "(1115): Could not read from file '{}' due to [({e})-({})].",
                    cur.file(),
                    strerror(e)
                ));
                // Windows: no fseek, the file is always reopened
                #[cfg(unix)]
                let seek_failed = cur.fp.as_mut().map(|f| f.fseek(0, 2) < 0).unwrap_or(true);
                #[cfg(windows)]
                let seek_failed = true;
                if seek_failed {
                    #[cfg(unix)]
                    {
                        let e = errno();
                        lc.log.error(format!(
                            "(1116): Could not set position in file '{}' due to [({e})-({})].",
                            cur.file(),
                            strerror(e)
                        ));
                    }
                    cur.fp = None;
                    let others = open_inodes(&files, i, j);
                    if handle_file(lc, &mut cur, j, false, true, &others) != 0 {
                        i += 1;
                        continue;
                    }
                    #[cfg(windows)]
                    win_seek_start(lc, &mut cur);
                }
                cur.c.ign += 1;
                let att = get(&lc.ints.open_file_attempts);
                if att != 0 && j < 0 {
                    lc.log.debug1(format!(
                        "(1962): Unable to open file '{}'. Remaining attempts: {}",
                        cur.file(),
                        att - cur.c.ign
                    ));
                } else {
                    lc.log.debug1(format!("(1963): Unable to open file '{}'.", cur.file()));
                }
                if let Some(fp) = cur.fp.as_mut() {
                    fp.clearerr();
                }
            }
            i += 1;
        }
    }
}

