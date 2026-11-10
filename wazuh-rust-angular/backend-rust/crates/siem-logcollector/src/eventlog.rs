//! `logcollector/read_win_el.c`: the `eventlog` log format (the legacy
//! EventLog API, ANSI functions as in the C build), at most 9 logs, read by
//! whichever input thread takes `win_el_mutex` (`win_readel`), plus the
//! Vista security descriptions (`vista_sec.txt`).
//!
//! The insert strings of a record go to `FormatMessage` through the same
//! pointer array as in C (`el_sstring`, kept for the whole `readel` call),
//! and the message line is
//! `"<date> WinEvtLog: <log>: <category>(<id>): <source>: <user>: <domain>: <computer>: <message>"`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, LocalFree, HANDLE};
use windows_sys::Win32::Security::{LookupAccountSidA, PSID, SID_NAME_USE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    FormatMessageA, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_ARGUMENT_ARRAY, FORMAT_MESSAGE_FROM_HMODULE,
    FORMAT_MESSAGE_FROM_STRING,
};
use windows_sys::Win32::System::EventLog::{
    CloseEventLog, GetNumberOfEventLogRecords, GetOldestEventLogRecord, OpenEventLogA, ReadEventLogA, EVENTLOGRECORD,
    EVENTLOG_AUDIT_FAILURE, EVENTLOG_AUDIT_SUCCESS, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
};

/// `EVENTLOG_SEQUENTIAL_READ` / `EVENTLOG_FORWARDS_READ`
const EVENTLOG_SEQUENTIAL_READ: u32 = 0x0001;
const EVENTLOG_FORWARDS_READ: u32 = 0x0004;
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryExA, DONT_RESOLVE_DLL_REFERENCES, LOAD_LIBRARY_AS_DATAFILE};
use windows_sys::Win32::System::Registry::{RegCloseKey, RegOpenKeyExA, RegQueryValueExA, HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS};

use crate::*;

/// `BUFFER_SIZE`
const BUFFER_SIZE: usize = 2048 * 256;
const OS_FLSIZE: usize = 256;
const MAX_PATH: usize = 260;
const ERROR_HANDLE_EOF: u32 = 38;
const ERROR_EVENTLOG_FILE_CHANGED: u32 = 1503;
const ERROR_INVALID_HANDLE: u32 = 6;
const RPC_S_SERVER_UNAVAILABLE: u32 = 1722;
const RPC_S_UNKNOWN_IF: u32 = 1717;
/// `checkVista()`: the agent runs on 6.0 and later only.
const IS_VISTA: bool = true;

/// `os_el`
struct OsEl {
    name: String,
    h: HANDLE,
}

// SAFETY: the event log handles are used under `EL`'s mutex only.
unsafe impl Send for OsEl {}

/// `el[9]` / `el_last`
static EL: Mutex<Vec<OsEl>> = Mutex::new(Vec::new());
/// `vista_sec_id_hash`: id -> description (NUL-terminated for FormatMessage)
static VISTA_SEC: OnceLock<HashMap<String, Vec<u8>>> = OnceLock::new();
/// `dll_hash`
static DLL_HASH: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);
/// `static int counter` of `readel`
static COUNTER: Mutex<i32> = Mutex::new(0);

fn c(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s.split('\0').next().unwrap_or("")).unwrap()
}

/// `startEL`: the number of records, or -1.
fn start_el(lc: &Lc, app: &str, el: &mut OsEl) -> i32 {
    let ca = c(app);
    // SAFETY: EventLog API on a handle we own.
    unsafe {
        el.h = OpenEventLogA(std::ptr::null(), ca.as_ptr().cast());
        if el.h.is_null() {
            lc.log.error(format!("(4106): Unable to open event log: '{app}'."));
            return -1;
        }
        el.name = app.to_string();
        let mut record = 0u32;
        let mut n = 0u32;
        if GetOldestEventLogRecord(el.h, &mut record) == 0 || GetNumberOfEventLogRecords(el.h, &mut n) == 0 {
            lc.log.error(format!("(4107): Unable to query last event log from: '{app}'."));
            CloseEventLog(el.h);
            el.h = std::ptr::null_mut();
            return -1;
        }
        n as i32
    }
}

/// `epoch_to_human`: "%Y %b %d %H:%M:%S" of the local time.
fn epoch_to_human(epoch: i64) -> String {
    siem_config::localfile::win::strftime_at("%Y %b %d %H:%M:%S", 80, epoch).unwrap_or_default()
}

/// `el_getCategory`
fn el_get_category(t: u16) -> &'static str {
    match t {
        EVENTLOG_ERROR_TYPE => "ERROR",
        EVENTLOG_WARNING_TYPE => "WARNING",
        EVENTLOG_INFORMATION_TYPE => "INFORMATION",
        EVENTLOG_AUDIT_SUCCESS => "AUDIT_SUCCESS",
        EVENTLOG_AUDIT_FAILURE => "AUDIT_FAILURE",
        _ => "Unknown",
    }
}

/// `el_getEventDLL`: the `EventMessageFile` of the source (cached).
fn el_get_event_dll(evt_name: &str, source: &[u8]) -> Option<Vec<u8>> {
    let mut keyname = format!("System\\CurrentControlSet\\Services\\EventLog\\{evt_name}\\").into_bytes();
    keyname.extend_from_slice(source);
    keyname.truncate(509);
    let cache_key = String::from_utf8_lossy(&keyname[42.min(keyname.len())..]).into_owned();
    if let Some(v) = DLL_HASH.lock().unwrap().as_ref().and_then(|h| h.get(&cache_key).cloned()) {
        return Some(v);
    }
    keyname.push(0);
    // SAFETY: registry calls with NUL-terminated names and a MAX_PATH buffer.
    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        if RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyname.as_ptr(), 0, KEY_ALL_ACCESS, &mut key) != 0 {
            return None;
        }
        let mut event = vec![0u8; MAX_PATH + 1];
        let mut ret = (MAX_PATH - 1) as u32;
        let r = RegQueryValueExA(key, c"EventMessageFile".as_ptr().cast(), std::ptr::null(), std::ptr::null_mut(), event.as_mut_ptr(), &mut ret);
        RegCloseKey(key);
        if r != 0 {
            return None;
        }
        let v = cstr(&event).to_vec();
        let mut h = DLL_HASH.lock().unwrap();
        h.get_or_insert_with(HashMap::new).entry(cache_key).or_insert_with(|| v.clone());
        Some(v)
    }
}

/// `FormatMessage` into a `LocalAlloc` buffer: the message bytes.
unsafe fn format_message(flags: u32, source: *const std::ffi::c_void, id: u32, args: *const *const i8) -> Option<Vec<u8>> {
    let mut msg: *mut u8 = std::ptr::null_mut();
    let n = FormatMessageA(
        flags | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY,
        source,
        id,
        0,
        (&mut msg as *mut *mut u8).cast(),
        0,
        args,
    );
    if n == 0 || msg.is_null() {
        return None;
    }
    let v = std::slice::from_raw_parts(msg, n as usize).to_vec();
    LocalFree(msg.cast());
    Some(v)
}

/// `el_vista_getMessage`
unsafe fn el_vista_get_message(evt_id: i32, args: *const *const i8) -> Option<Vec<u8>> {
    let desc = VISTA_SEC.get()?.get(&evt_id.to_string())?;
    format_message(FORMAT_MESSAGE_FROM_STRING, desc.as_ptr().cast(), 0, args)
}

/// `ExpandEnvironmentStrings(src, tmp_str, 255)`
fn expand_255(src: &[u8]) -> Vec<u8> {
    use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsA;
    let mut s = src.to_vec();
    s.push(0);
    let mut out = vec![0u8; 257];
    // SAFETY: NUL-terminated source, 255-byte destination.
    unsafe { ExpandEnvironmentStringsA(s.as_ptr(), out.as_mut_ptr(), 255) };
    let mut v = cstr(&out).to_vec();
    v.push(0);
    v
}

/// `el_getMessage`: the message from each DLL of `EventMessageFile`.
unsafe fn el_get_message(er: &EVENTLOGRECORD, name: &str, source: &[u8], args: *const *const i8) -> Option<Vec<u8>> {
    let dlls = el_get_event_dll(name, source)?;
    let try_dll = |path: &[u8]| -> Option<Vec<u8>> {
        let tmp = expand_255(path);
        let hevt = LoadLibraryExA(tmp.as_ptr(), std::ptr::null_mut(), DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_AS_DATAFILE);
        if hevt.is_null() {
            return None;
        }
        let m = format_message(FORMAT_MESSAGE_FROM_HMODULE, hevt as *const _, er.EventID, args);
        FreeLibrary(hevt);
        m
    };
    let parts: Vec<&[u8]> = dlls.split(|&b| b == b';').collect();
    for (k, p) in parts.iter().enumerate() {
        if let Some(m) = try_dll(p) {
            return Some(m);
        }
        if k + 1 == parts.len() {
            break;
        }
    }
    None
}

/// `readel`
fn readel(lc: &Lc, el: &mut OsEl, printit: bool) {
    if el.h.is_null() {
        return;
    }
    let mut mbuffer = vec![0u32; (BUFFER_SIZE + 4) / 4];
    let mut el_sstring: Vec<*const i8> = vec![std::ptr::null(); OS_FLSIZE + 1];
    let mut el_string: Vec<u8> = vec![0u8; OS_MAXSTR + 1];
    let (mut read, mut needed) = (0u32, 0u32);
    // SAFETY: records parsed inside the buffer ReadEventLog filled.
    unsafe {
        while ReadEventLogA(
            el.h,
            EVENTLOG_FORWARDS_READ | EVENTLOG_SEQUENTIAL_READ,
            0,
            mbuffer.as_mut_ptr().cast(),
            (BUFFER_SIZE - 1) as u32,
            &mut read,
            &mut needed,
        ) != 0
        {
            if !printit {
                continue;
            }
            let base = mbuffer.as_ptr() as *const u8;
            let mut off = 0usize;
            while read > 0 {
                let er = &*(base.add(off) as *const EVENTLOGRECORD);
                let category = el_get_category(er.EventType);
                let src_ptr = base.add(off + std::mem::size_of::<EVENTLOGRECORD>());
                let source = std::ffi::CStr::from_ptr(src_ptr.cast()).to_bytes();
                let computer = std::ffi::CStr::from_ptr(src_ptr.add(source.len() + 1).cast()).to_bytes();
                let id = (er.EventID & 65535) as i32;
                let mut descriptive: Option<Vec<u8>> = None;
                let mut el_user = Vec::new();
                let mut el_domain = Vec::new();

                if er.NumStrings != 0 {
                    let mut size_left: i32 = (OS_MAXSTR - OS_SIZE_1024) as i32;
                    let mut sstr = base.add(off + er.StringOffset as usize);
                    el_string[0] = 0;
                    let mut nstr = 0u32;
                    while nstr < er.NumStrings as u32 && !sstr.is_null() {
                        let s = std::ffi::CStr::from_ptr(sstr.cast()).to_bytes();
                        let str_size = s.len() as i32;
                        // strncat(el_string, sstr, size_left)
                        let cur = strlen(&el_string);
                        if size_left > 1 {
                            let n = s.len().min(size_left as usize).min(OS_MAXSTR - cur);
                            el_string[cur..cur + n].copy_from_slice(&s[..n]);
                            el_string[cur + n] = 0;
                        }
                        let end = strlen(&el_string);
                        if end + 1 < el_string.len() {
                            el_string[end] = b' ';
                            el_string[end + 1] = 0;
                        }
                        size_left -= str_size + 2;
                        if nstr <= 92 {
                            el_sstring[nstr as usize] = sstr.cast();
                            el_sstring[nstr as usize + 1] = std::ptr::null();
                        }
                        sstr = sstr.add(s.len() + 1);
                        nstr += 1;
                    }
                    descriptive = if IS_VISTA && el.name == "Security" {
                        el_vista_get_message(id, el_sstring.as_ptr())
                    } else {
                        el_get_message(er, &el.name, source, el_sstring.as_ptr())
                    };
                    if let Some(d) = descriptive.as_mut() {
                        d.push(0);
                        crate::win::win_format_event_string(d);
                        d.pop();
                    }
                } else {
                    el_string[..13].copy_from_slice(b"(no message)\0");
                }

                let no_user = |u: &mut Vec<u8>, d: &mut Vec<u8>| {
                    *u = b"(no user)".to_vec();
                    *d = b"no domain".to_vec();
                };
                if er.UserSidLength != 0 {
                    let mut user = vec![0u8; OS_FLSIZE + 1];
                    let mut domain = vec![0u8; OS_FLSIZE + 1];
                    let (mut us, mut ds) = (255u32, 255u32);
                    let mut t: SID_NAME_USE = 0;
                    let sid = base.add(off + er.UserSidOffset as usize) as PSID;
                    if LookupAccountSidA(std::ptr::null(), sid, user.as_mut_ptr(), &mut us, domain.as_mut_ptr(), &mut ds, &mut t) == 0 {
                        no_user(&mut el_user, &mut el_domain);
                    } else {
                        el_user = cstr(&user).to_vec();
                        el_domain = cstr(&domain).to_vec();
                    }
                } else if IS_VISTA && el.name == "Security" {
                    let uid: i32 = match id {
                        4624 => 5,
                        4634 | 4647 => 1,
                        4769 => 0,
                        _ => -1,
                    };
                    if uid >= 0 && !el_sstring[uid as usize].is_null() && !el_sstring[uid as usize + 1].is_null() {
                        let take = |p: *const i8| {
                            let mut v = std::ffi::CStr::from_ptr(p).to_bytes().to_vec();
                            v.truncate(OS_FLSIZE);
                            v
                        };
                        el_user = take(el_sstring[uid as usize]);
                        el_domain = take(el_sstring[uid as usize + 1]);
                    } else {
                        no_user(&mut el_user, &mut el_domain);
                    }
                } else {
                    no_user(&mut el_user, &mut el_domain);
                }

                let mut final_msg = format!(
                    "{} WinEvtLog: {}: {}({}): ",
                    epoch_to_human(er.TimeGenerated as i32 as i64),
                    el.name,
                    category,
                    id
                )
                .into_bytes();
                for part in [source, &el_user[..], &el_domain[..], computer] {
                    final_msg.extend_from_slice(part);
                    final_msg.extend_from_slice(b": ");
                }
                match &descriptive {
                    Some(d) => final_msg.extend_from_slice(cstr(d)),
                    None => final_msg.extend_from_slice(cstr(&el_string)),
                }
                // snprintf(final_msg, OS_MAXSTR - OS_LOG_HEADER - 1, ...)
                final_msg.truncate(OS_MAXSTR - OS_LOG_HEADER - 2);
                let final_msg = cstr(&final_msg).to_vec();

                crate::state::update_file(lc, &el.name, final_msg.len() as u64);
                let q = lc.logr_queue.load(std::sync::atomic::Ordering::SeqCst);
                if siem_ipc::mq_op::send_msg(q, &final_msg, "WinEvtLog", LOCALFILE_MQ) < 0 {
                    lc.log.error("(1224): Error sending message to queue.");
                    crate::state::update_target(lc, &el.name, "agent", true);
                } else {
                    crate::state::update_target(lc, &el.name, "agent", false);
                }

                read = read.saturating_sub(er.Length);
                off += er.Length as usize;
            }
        }
        let id = GetLastError();
        if id == ERROR_HANDLE_EOF {
            return;
        } else if id == ERROR_EVENTLOG_FILE_CHANGED {
            lc.log.warn(format!("Event log cleared: '{}'", el.name));
            let mut m = format!("ossec: Event log cleared: '{}'", el.name).into_bytes();
            m.truncate(511);
            let q = lc.logr_queue.load(std::sync::atomic::Ordering::SeqCst);
            siem_ipc::mq_op::send_msg(q, &m, "WinEvtLog", LOCALFILE_MQ);
            CloseEventLog(el.h);
            el.h = std::ptr::null_mut();
            let name = el.name.clone();
            if start_el(lc, &name, el) < 0 {
                lc.log.error(format!("Unable to reopen event log '{name}'"));
            }
        } else if id == ERROR_INVALID_HANDLE {
            lc.log.debug1(format!("The EventLog service has been restarted. Reconnecting to '{}' channel.", el.name));
            CloseEventLog(el.h);
            el.h = std::ptr::null_mut();
            let name = el.name.clone();
            if start_el(lc, &name, el) < 0 {
                lc.log.error(format!("Could not subscribe for ({name}) which returned ({id})"));
            } else {
                *COUNTER.lock().unwrap() = 0;
                lc.log.info(format!("'{name}' channel has been reconnected succesfully."));
            }
        } else if id == RPC_S_SERVER_UNAVAILABLE || id == RPC_S_UNKNOWN_IF {
            let mut c = COUNTER.lock().unwrap();
            if *c == 0 {
                lc.log.warn("The EventLog service is down. Unable to collect logs from its channels.");
                *c = 1;
            }
        } else {
            lc.log.debug1(format!("Error reading event log: {id}"));
        }
    }
}

/// `win_read_vista_sec`: exits when `vista_sec.txt` cannot be read.
pub fn win_read_vista_sec(lc: &Lc) {
    let Ok(data) = siem_fileop::crt::read_text("vista_sec.txt") else {
        lc.exit_critical("Unable to read vista security descriptions.");
    };
    let mut map: HashMap<String, Vec<u8>> = HashMap::new();
    // fgets(buf, OS_MAXSTR, fp)
    let mut pos = 0;
    while pos < data.len() {
        let mut end = pos;
        while end < data.len() && end - pos < OS_MAXSTR - 1 {
            end += 1;
            if data[end - 1] == b'\n' {
                break;
            }
        }
        let mut buf = cstr(&data[pos..end]).to_vec();
        pos = end;
        if let Some(p) = buf.iter().rposition(|&b| b == b'\n') {
            buf.truncate(p);
        }
        let Some(comma) = buf.iter().position(|&b| b == b',') else {
            lc.log.error("Invalid entry on the Vista security description.");
            continue;
        };
        let key = String::from_utf8_lossy(&buf[..comma]).into_owned();
        let mut p = comma + 1;
        while p < buf.len() && buf[p] == b' ' {
            p += 1;
        }
        let mut desc = buf[p..].to_vec();
        desc.push(0);
        // OSHash_Add keeps the first entry
        map.entry(key).or_insert(desc);
    }
    let _ = VISTA_SEC.set(map);
}

/// `win_startel`
pub fn win_startel(lc: &Lc, evt_log: &str) {
    let mut els = EL.lock().unwrap();
    if els.len() == 9 {
        lc.log.error(format!("(4108): Duplicated event log entry: '{evt_log}'."));
        return;
    }
    DLL_HASH.lock().unwrap().get_or_insert_with(HashMap::new);
    crate::state::update_file(lc, evt_log, 0);
    crate::state::update_target(lc, evt_log, "agent", false);
    let mut el = OsEl { name: String::new(), h: std::ptr::null_mut() };
    if start_el(lc, evt_log, &mut el) < 0 {
        lc.log.error(format!("(1903): Invalid event log: '{evt_log}'."));
        return;
    }
    // Going to the last available record
    readel(lc, &mut el, false);
    els.push(el);
}

/// `win_readel`: 2 seconds, then every event log.
pub fn win_readel(lc: &Lc) {
    std::thread::sleep(std::time::Duration::from_secs(2));
    let mut els = EL.lock().unwrap();
    for el in els.iter_mut() {
        readel(lc, el, true);
    }
}
