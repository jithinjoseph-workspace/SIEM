//! `logcollector/journal_log.c` and `read_journald.c`: the systemd journal
//! through `libsystemd.so.0` loaded at run time (only when it is owned by
//! root), filters, syslog-style entries, rotation detection and the
//! only-future-events timestamp saved in `file_status.json`.

use std::ffi::{c_void, CStr, CString};
use std::sync::Mutex;

use siem_cjson::Json;
use siem_config::localfile::{JournalFilter, JOURNALD_LOG};

use crate::*;

type Journal = c_void;
type FnOpen = unsafe extern "C" fn(*mut *mut Journal, i32) -> i32;
type FnClose = unsafe extern "C" fn(*mut Journal);
type FnMove = unsafe extern "C" fn(*mut Journal) -> i32;
type FnSeekTs = unsafe extern "C" fn(*mut Journal, u64) -> i32;
type FnCutoff = unsafe extern "C" fn(*mut Journal, *mut u64, *mut u64) -> i32;
type FnGetTs = unsafe extern "C" fn(*mut Journal, *mut u64) -> i32;
type FnGetData = unsafe extern "C" fn(*mut Journal, *const libc::c_char, *mut *const c_void, *mut usize) -> i32;
type FnRestart = unsafe extern "C" fn(*mut Journal);
type FnEnum = unsafe extern "C" fn(*mut Journal, *mut *const c_void, *mut usize) -> i32;

const LIB_SYSTEMD: &str = "libsystemd.so.0";
const SD_JOURNAL_LOCAL_ONLY: i32 = 1;
const SD_JOURNAL_INVALIDATE: i32 = 2;

/// `w_journal_lib_t`
struct Lib {
    handle: *mut c_void,
    open: FnOpen,
    close: FnClose,
    previous: FnMove,
    next: FnMove,
    seek_tail: FnMove,
    seek_timestamp: FnSeekTs,
    get_cutoff: FnCutoff,
    get_timestamp: FnGetTs,
    get_data: FnGetData,
    _restart_data: FnRestart,
    _enumerate: FnEnum,
    process: FnMove,
    get_fd: FnMove,
}

/// `w_journal_context_t`
struct Ctx {
    lib: Lib,
    journal: *mut Journal,
    timestamp: u64,
}

// SAFETY: the journal is only used by its owner thread (w_journald_can_read).
unsafe impl Send for Ctx {}

#[derive(Default)]
struct Global {
    owner_id: u64,
    is_disabled: bool,
    ctx: Option<Ctx>,
    ts_fail_logged: bool,
}

struct Ofe {
    exist_journal: bool,
    only_future_events: bool,
    last_read_timestamp: u64,
}

impl Default for Ofe {
    fn default() -> Self {
        Ofe { exist_journal: false, only_future_events: true, last_read_timestamp: 0 }
    }
}

#[derive(Default)]
pub struct Journald {
    global: Mutex<Global>,
    ofe: Mutex<Ofe>,
}

fn dlerror() -> String {
    // SAFETY: dlerror returns a static string or NULL.
    unsafe {
        let e = libc::dlerror();
        if e.is_null() {
            "Unknown error".into()
        } else {
            CStr::from_ptr(e).to_string_lossy().into_owned()
        }
    }
}

/// `find_library_path`: the mapped path of the library.
fn find_library_path(name: &str) -> Option<String> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let line = maps.lines().find(|l| l.contains(name))?;
    let p = line.find('/')?;
    Some(line[p..].to_string())
}

fn is_owned_by_root(path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).map(|m| m.uid() == 0).unwrap_or(false)
}

/// `w_journal_lib_init`
fn lib_init(lc: &Lc) -> Option<Lib> {
    let cname = CString::new(LIB_SYSTEMD).unwrap();
    // SAFETY: dlopen/dlsym with valid C strings.
    unsafe {
        let h = libc::dlopen(cname.as_ptr(), libc::RTLD_LAZY);
        if h.is_null() {
            lc.log.warn(format!("(8008): Failed to load '{LIB_SYSTEMD}': '{}'.", dlerror()));
            return None;
        }
        match find_library_path(LIB_SYSTEMD) {
            Some(p) if is_owned_by_root(&p) => {}
            _ => {
                lc.log.warn(format!("(8009): The library '{LIB_SYSTEMD}' is not owned by the root user."));
                libc::dlclose(h);
                return None;
            }
        }
        let sym = |name: &str| -> Option<*mut c_void> {
            let c = CString::new(name).unwrap();
            let p = libc::dlsym(h, c.as_ptr());
            if p.is_null() {
                lc.log.warn(format!("(8008): Failed to load '{name}': '{}'.", dlerror()));
                None
            } else {
                Some(p)
            }
        };
        macro_rules! f {
            ($n:expr, $t:ty) => {
                match sym($n) {
                    Some(p) => std::mem::transmute::<*mut c_void, $t>(p),
                    None => {
                        libc::dlclose(h);
                        return None;
                    }
                }
            };
        }
        Some(Lib {
            handle: h,
            open: f!("sd_journal_open", FnOpen),
            close: f!("sd_journal_close", FnClose),
            previous: f!("sd_journal_previous", FnMove),
            next: f!("sd_journal_next", FnMove),
            seek_tail: f!("sd_journal_seek_tail", FnMove),
            seek_timestamp: f!("sd_journal_seek_realtime_usec", FnSeekTs),
            get_timestamp: f!("sd_journal_get_realtime_usec", FnGetTs),
            get_data: f!("sd_journal_get_data", FnGetData),
            _restart_data: f!("sd_journal_restart_data", FnRestart),
            _enumerate: f!("sd_journal_enumerate_data", FnEnum),
            get_cutoff: f!("sd_journal_get_cutoff_realtime_usec", FnCutoff),
            process: f!("sd_journal_process", FnMove),
            get_fd: f!("sd_journal_get_fd", FnMove),
        })
    }
}

/// `w_journal_context_create`
fn context_create(lc: &Lc) -> Result<Ctx, i32> {
    let lib = lib_init(lc).ok_or(-1)?;
    let mut j: *mut Journal = std::ptr::null_mut();
    // SAFETY: calling sd_journal_open with a valid out pointer.
    let r = unsafe { (lib.open)(&mut j, SD_JOURNAL_LOCAL_ONLY) };
    if r < 0 {
        lc.log.warn(format!("(8010): Failed open journal log: '{}'.", strerror(-r)));
        // SAFETY: closing the handle we opened.
        unsafe { libc::dlclose(lib.handle) };
        return Err(r);
    }
    Ok(Ctx { lib, journal: j, timestamp: 0 })
}

fn epoch_usec() -> u64 {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    d.as_secs() * 1_000_000 + d.subsec_micros() as u64
}

/// `w_journal_context_update_timestamp`
fn update_timestamp(lc: &Lc, g: &mut Global) {
    let ctx = g.ctx.as_mut().unwrap();
    // SAFETY: valid journal and out pointer.
    let err = unsafe { (ctx.lib.get_timestamp)(ctx.journal, &mut ctx.timestamp) };
    if err < 0 {
        ctx.timestamp = epoch_usec();
        if !g.ts_fail_logged {
            g.ts_fail_logged = true;
            lc.log.warn(format!(
                "(8011): Failed to read timestamp from journal log: '{}'. Using current time.",
                strerror(-err)
            ));
        }
    }
}

/// `w_journal_context_seek_most_recent`
fn seek_most_recent(lc: &Lc, g: &mut Global) -> i32 {
    let ctx = g.ctx.as_mut().unwrap();
    // SAFETY: valid journal.
    let err = unsafe { (ctx.lib.seek_tail)(ctx.journal) };
    if err < 0 {
        return err;
    }
    // SAFETY: valid journal.
    let err = unsafe { (ctx.lib.previous)(ctx.journal) };
    if err > 0 {
        update_timestamp(lc, g);
    }
    err
}

/// `w_journal_context_seek_timestamp`
fn seek_timestamp(lc: &Lc, g: &mut Global, mut ts: u64) -> i32 {
    if ts == 0 || ts > epoch_usec() {
        lc.log.warn(format!(
            "(8012): The timestamp '{ts}' is in the future or invalid. Using the most recent entry."
        ));
        return seek_most_recent(lc, g);
    }
    let ctx = g.ctx.as_mut().unwrap();
    let mut oldest = 0u64;
    // SAFETY: valid journal and out pointers.
    let err = unsafe { (ctx.lib.get_cutoff)(ctx.journal, &mut oldest, std::ptr::null_mut()) };
    if err < 0 {
        lc.log.warn(format!("(8013): Failed to read oldest timestamp from journal log: '{}'.", strerror(-err)));
    } else if ts < oldest {
        lc.log.warn(format!(
            "(8014): The timestamp '{ts}' is older than the oldest available in journal. Using the oldest entry."
        ));
        ts = oldest;
    }
    // SAFETY: valid journal.
    let err = unsafe { (ctx.lib.seek_timestamp)(ctx.journal, ts) };
    if err < 0 {
        return err;
    }
    // SAFETY: valid journal.
    let err = unsafe { (ctx.lib.next)(ctx.journal) };
    if err > 0 {
        update_timestamp(lc, g);
    }
    err
}

/// `get_field_ptr`: the value of `field` in the current entry.
fn get_field(ctx: &Ctx, field: &str) -> Option<Vec<u8>> {
    let c = CString::new(field).ok()?;
    let mut data: *const c_void = std::ptr::null();
    let mut len = 0usize;
    // SAFETY: valid journal and out pointers; the data stays valid until the next call.
    let err = unsafe { (ctx.lib.get_data)(ctx.journal, c.as_ptr(), &mut data, &mut len) };
    if err < 0 {
        return None;
    }
    // SAFETY: sd_journal_get_data returned `len` bytes at `data`.
    let b = unsafe { std::slice::from_raw_parts(data as *const u8, len) };
    let eq = b.iter().position(|&c| c == b'=')?;
    // strndup: stops at a NUL byte
    Some(cstr(&b[eq + 1..]).to_vec())
}

/// `w_journal_filter_apply`: 1 match, 0 no match, <0 error.
fn filter_apply(lc: &Lc, ctx: &Ctx, f: &JournalFilter) -> i32 {
    for u in &f.units {
        let c = CString::new(u.field.as_str()).unwrap_or_default();
        let mut data: *const c_void = std::ptr::null();
        let mut len = 0usize;
        // SAFETY: valid journal and out pointers.
        let err = unsafe { (ctx.lib.get_data)(ctx.journal, c.as_ptr(), &mut data, &mut len) };
        if err < 0 {
            if u.ignore_if_missing {
                continue;
            }
            lc.log.debug2(format!(
                "(9003): Failed to get data field '{}' from entry with timestamp '{}'. Error: {}",
                u.field,
                ctx.timestamp,
                strerror(-err)
            ));
            return err;
        }
        // SAFETY: `len` bytes at `data`.
        let b = unsafe { std::slice::from_raw_parts(data as *const u8, len) };
        let key_len = u.field.len().min(len) + 1;
        if key_len > len {
            return -1;
        }
        let value = cstr(&b[key_len..]);
        if !u.exp.match_bytes(value, None).0 {
            return 0;
        }
    }
    1
}

/// `w_timestamp_to_string` ("%b %d %T", UTC)
fn ts_string(ts: u64, fmt: &[u8]) -> Option<String> {
    let t = (ts / 1_000_000) as libc::time_t;
    let mut buf = vec![0u8; 32];
    let c = CString::new(fmt.to_vec()).ok()?;
    // SAFETY: gmtime_r/strftime on valid buffers.
    let n = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::gmtime_r(&t, &mut tm).is_null() {
            return None;
        }
        libc::strftime(buf.as_mut_ptr().cast(), if fmt == b"%b %d %T" { 16 } else { 20 }, c.as_ptr(), &tm)
    };
    buf.truncate(n);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// `entry_as_syslog`
fn entry_as_syslog(lc: &Lc, ctx: &Ctx) -> Option<Vec<u8>> {
    let hostname = get_field(ctx, "_HOSTNAME");
    let ident = get_field(ctx, "SYSLOG_IDENTIFIER");
    let message = get_field(ctx, "MESSAGE");
    let pid = get_field(ctx, "SYSLOG_PID").or_else(|| get_field(ctx, "_PID"));
    let ts = ts_string(ctx.timestamp, b"%b %d %T");
    let (Some(hostname), Some(message), Some(ts)) = (hostname, message, ts) else {
        lc.log.debug2(format!(
            "(9002): Failed to get the required fields, discarted log with timestamp '{}'",
            ctx.timestamp
        ));
        return None;
    };
    let ident = ident.unwrap_or_else(|| b"unknown".to_vec());
    let mut out = format!("{ts} ").into_bytes();
    out.extend_from_slice(&hostname);
    out.push(b' ');
    out.extend_from_slice(&ident);
    if let Some(p) = pid {
        out.push(b'[');
        out.extend_from_slice(&p);
        out.push(b']');
    }
    out.extend_from_slice(b": ");
    out.extend_from_slice(&message);
    Some(out)
}

/// `seek_and_refresh_timestamp`
fn seek_and_refresh(lc: &Lc, g: &mut Global) -> i32 {
    let (ofe, lr) = {
        let o = lc.journald.ofe.lock().unwrap();
        (o.only_future_events, o.last_read_timestamp)
    };
    let r = if ofe { seek_most_recent(lc, g) } else { seek_timestamp(lc, g, lr) };
    if r < 0 {
        lc.log.error(format!(
            "(1609): Failed to move to the end of the journal, disabling journal log: {}.",
            strerror(-r)
        ));
        g.is_disabled = true;
    }
    r
}

/// `w_journald_can_read`
pub fn can_read(lc: &Lc, owner_id: u64) -> bool {
    let mut g = lc.journald.global.lock().unwrap();
    if g.is_disabled {
        return false;
    }
    if g.owner_id == 0 {
        g.owner_id = owner_id;
        if g.ctx.is_none() {
            match context_create(lc) {
                Ok(c) => g.ctx = Some(c),
                Err(_) => {
                    lc.log.error("(1608): Failed to connect to the journal, disabling journal log.");
                    g.is_disabled = true;
                    return false;
                }
            }
        }
        if seek_and_refresh(lc, &mut g) < 0 {
            return false;
        }
        lc.log.info("(9203): Monitoring journal entries.");
    } else if g.owner_id != owner_id {
        return false;
    }
    // w_journal_rotation_detected
    let rotated = {
        let ctx = g.ctx.as_ref().unwrap();
        // SAFETY: valid journal.
        unsafe { (ctx.lib.get_fd)(ctx.journal) >= 0 && (ctx.lib.process)(ctx.journal) == SD_JOURNAL_INVALIDATE }
    };
    if rotated {
        if seek_and_refresh(lc, &mut g) < 0 {
            return false;
        }
        lc.log.info("(9204): 'Journald' timestamp was refreshed due to rotation.");
    }
    true
}

/// `read_journald`
pub fn read_journald(lc: &Lc, lf: &mut Reader, rc: &mut i32) {
    let max_line_len = OS_MAXSTR - OS_LOG_HEADER;
    *rc = 0;
    let maxl = lc.max_lines();
    let mut count = 0;
    let mut g = lc.journald.global.lock().unwrap();
    let Some(jl) = lf.c.journal_log.as_ref() else { return };
    let filters: Option<Vec<&JournalFilter>> = if jl.disable_filters || jl.filters.is_none() {
        None
    } else {
        Some(jl.active_filters())
    };
    while (maxl == 0 || count < maxl) && lc.can_read() {
        // w_journal_context_next_newest_filtered
        let res = loop {
            let ctx = g.ctx.as_mut().unwrap();
            // SAFETY: valid journal.
            let r = unsafe { (ctx.lib.next)(ctx.journal) };
            if r > 0 {
                update_timestamp(lc, &mut g);
            }
            let Some(fs) = &filters else { break r };
            if r <= 0 {
                break r;
            }
            let ctx = g.ctx.as_ref().unwrap();
            if lc.log.is_debug() > 0 {
                let ts = ts_string(ctx.timestamp, b"%Y-%m-%d %T");
                lc.log.debug2(format!(
                    "(9004): Checking filters for timestamp '{}'",
                    ts.as_deref().unwrap_or("unknown")
                ));
            }
            if fs.iter().any(|f| filter_apply(lc, ctx, f) > 0) {
                break 1;
            }
        };
        if res < 0 {
            lc.log.error(format!(
                "(1610): Failed to get the next entry, disabling journal log: {}.",
                strerror(-res)
            ));
            g.is_disabled = true;
            break;
        } else if res == 0 {
            lc.log.debug2("(9006): No new entries in the journal.");
            break;
        }
        let Some(mut entry) = entry_as_syslog(lc, g.ctx.as_ref().unwrap()) else {
            lc.log.debug1("(1611): Failed to get the message from the journal");
            break;
        };
        entry.truncate(strlen(&entry));
        if entry.len() > max_line_len {
            lc.log.debug1("(9007): Message size > maximum allowed, The message will be truncated.");
            entry.truncate(max_line_len);
        }
        if lc.log.is_debug() > 0 {
            lc.log.debug2(format!("(9008): Reading from journal: '{}'.", String::from_utf8_lossy(&entry)));
        }
        output::push(lc, &entry, JOURNALD_LOG, entry.len() + 1, &lf.targets(), LOCALFILE_MQ);
        count += 1;
    }
    let ts = g.ctx.as_ref().map(|c| c.timestamp).unwrap_or(0);
    lc.journald.ofe.lock().unwrap().last_read_timestamp = ts;
}

/// `w_journald_set_ofe`
pub fn set_ofe(lc: &Lc, ofe: bool) {
    let mut o = lc.journald.ofe.lock().unwrap();
    o.only_future_events = ofe;
    o.exist_journal = true;
}

/// `w_journald_get_status_as_JSON`
pub fn get_status_as_json(lc: &Lc) -> Option<Json> {
    let o = lc.journald.ofe.lock().unwrap();
    if !o.exist_journal {
        return None;
    }
    let mut j = Json::object();
    j.add("timestamp", Json::string(o.last_read_timestamp.to_string()));
    Some(j)
}

/// `w_journald_set_status_from_JSON`
pub fn set_status_from_json(lc: &Lc, global: &Json) {
    let Some(ts) = global.get(JOURNALD_LOG).and_then(|j| j.get("timestamp")).and_then(|t| t.as_str()) else {
        return;
    };
    // strtoull(timestamp, NULL, 10)
    let digits: String = ts.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
    let v = digits.parse::<u64>().unwrap_or(if digits.is_empty() { 0 } else { u64::MAX });
    if v == 0 || v == u64::MAX {
        return;
    }
    lc.journald.ofe.lock().unwrap().last_read_timestamp = v;
    lc.log.debug2(format!("(9009): Setting last read timestamp to '{v}'"));
}

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: closing the journal and the library we opened.
        unsafe {
            (self.lib.close)(self.journal);
            libc::dlclose(self.lib.handle);
        }
    }
}
