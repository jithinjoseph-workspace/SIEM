//! Windows realtime: `run_realtime.c` (`realtime_start`, `realtime_adddir`,
//! `RTCallBack`), `fim_run_realtime` and `log_realtime_status` of
//! `run_check.c`, and `fim_realtime_event` / `fim_process_missing_entry` of
//! `create_db.c`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED};
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Threading::{CreateEventA, WaitForSingleObjectEx};
use windows_sys::Win32::System::IO::OVERLAPPED;

use super::cfmt::{cfmt, A};
use super::config::*;
use super::create_db::{fim_configuration_directory, EventData, Fim, FIM_DELETE};
use super::fimdb::{self, FIM_REALTIME, FIM_WHODATA};
use super::{mdebug1, mdebug2, merror, minfo, msgs, mwarn};

const FIM_RT_HANDLE_OPEN: u32 = 0;
const FIM_RT_HANDLE_CLOSED: u32 = 1;
/// `MAX_LINE` (`PATH_MAX + 256`)
const MAX_LINE: usize = 260 + 256;

#[repr(C, align(8))]
struct Buffer([u8; 65536]);

/// `win32rtfim`: boxed, its OVERLAPPED and buffer belong to the pending read.
struct RtFim {
    h: HANDLE,
    overlap: OVERLAPPED,
    dir: Vec<u8>,
    /// What `overlap.hEvent` points to (the hash key, NUL-terminated).
    key: Box<[u8]>,
    buffer: Box<Buffer>,
    watch_status: u32,
}

// SAFETY: the handles and buffers are only used under the RT mutex.
unsafe impl Send for RtFim {}

/// `rtfim`
struct Rt {
    dirtb: HashMap<Vec<u8>, Box<RtFim>>,
    evt: HANDLE,
    queue_overflow: bool,
}

// SAFETY: the event handle is used under the mutex.
unsafe impl Send for Rt {}

/// `syscheck.realtime` (NULL until `realtime_start`)
static RT: Mutex<Option<Rt>> = Mutex::new(None);

fn rt() -> std::sync::MutexGuard<'static, Option<Rt>> {
    RT.lock().unwrap_or_else(|e| e.into_inner())
}

/// `realtime_start`
pub fn realtime_start() {
    // SAFETY: an unnamed manual-reset event.
    let evt = unsafe { CreateEventA(std::ptr::null(), 1, 0, std::ptr::null()) };
    *rt() = Some(Rt { dirtb: HashMap::new(), evt, queue_overflow: false });
}

/// `get_realtime_watches`
fn get_realtime_watches() -> usize {
    rt().as_ref().map(|r| r.dirtb.len()).unwrap_or(0)
}

/// `w_directory_exists`
fn directory_exists(path: &[u8]) -> bool {
    super::win::get_file_attrs(path) & FILE_ATTRIBUTE_DIRECTORY != 0
}

/// `realtime_win32read`
fn win32read(r: &mut RtFim) -> bool {
    // SAFETY: the buffer and OVERLAPPED live in the boxed entry until its handle is closed and the
    // completion routine has run.
    unsafe {
        ReadDirectoryChangesW(
            r.h,
            r.buffer.0.as_mut_ptr().cast(),
            r.buffer.0.len() as u32,
            1,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SECURITY,
            std::ptr::null_mut(),
            &mut r.overlap,
            Some(rt_callback),
        ) != 0
    }
}

/// `snprintf(wdchar, 260, "%s", dir)`
fn wdchar(dir: &[u8]) -> Vec<u8> {
    dir[..dir.len().min(259)].to_vec()
}

/// The realtime (non-whodata) part of `realtime_adddir`.
pub fn realtime_adddir_rt(dir: &[u8], c: &mut Directory, max_fd_win_rt: u32) -> i32 {
    let mut g = rt();
    let Some(r) = g.as_mut() else { return 0 };
    let key = wdchar(dir);
    if let Some(e) = r.dirtb.get_mut(&key) {
        if !directory_exists(&e.dir) {
            if e.watch_status == FIM_RT_HANDLE_CLOSED {
                mdebug2(cfmt(msgs::FIM_REALTIME_CALLBACK, &[A::B(&e.dir)]));
                let d = e.dir.clone();
                r.dirtb.remove(&d);
            } else if !e.h.is_null() && e.h != INVALID_HANDLE_VALUE {
                // SAFETY: the watch handle (the pending read completes as aborted).
                unsafe { CloseHandle(e.h) };
                e.watch_status = FIM_RT_HANDLE_CLOSED;
            }
        }
        return 1;
    }
    if r.dirtb.len() >= max_fd_win_rt as usize {
        mdebug1(cfmt(msgs::FIM_REALTIME_MAXNUM_WATCHES, &[A::B(dir)]));
        return 0;
    }
    let h = match super::win::auto_to_wide(dir) {
        // SAFETY: a NUL-terminated wide path.
        Some(w) => unsafe {
            CreateFileW(
                w.as_ptr(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        },
        None => INVALID_HANDLE_VALUE,
    };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        mdebug2(cfmt(msgs::FIM_REALTIME_ADD, &[A::B(dir)]));
        return 0;
    }
    let mut k = dir.to_vec();
    k.push(0);
    let mut e = Box::new(RtFim {
        h,
        // SAFETY: OVERLAPPED is plain data.
        overlap: unsafe { std::mem::zeroed() },
        dir: dir.to_vec(),
        key: k.into_boxed_slice(),
        buffer: Box::new(Buffer([0; 65536])),
        watch_status: FIM_RT_HANDLE_OPEN,
    });
    // the C stores the directory in hEvent (unused with a completion routine)
    e.overlap.hEvent = e.key.as_ptr() as HANDLE;
    if !win32read(&mut e) {
        // SAFETY: plain Win32 calls.
        let err = unsafe { GetLastError() };
        mdebug1(cfmt(msgs::FIM_REALTIME_DIRECTORYCHANGES, &[A::B(&e.dir), A::U(err as u64), A::S(&siem_ipc::os_net::win_strerror(err))]));
        unsafe { CloseHandle(e.h) };
        if !directory_exists(&e.dir) {
            mwarn(cfmt(msgs::FIM_REALTIME_FILE_NOT_SUPPORTED, &[A::B(&e.dir)]));
            c.options &= !REALTIME_ACTIVE;
            c.options |= SCHEDULED_ACTIVE;
        }
        return 0;
    }
    r.dirtb.insert(key, e);
    mdebug2(cfmt(msgs::FIM_REALTIME_NEWDIRECTORY, &[A::B(dir)]));
    1
}

/// `RTCallBack`
unsafe extern "system" fn rt_callback(dwerror: u32, dwbytes: u32, overlap: *mut OVERLAPPED) {
    if dwerror != 0 {
        let m = super::win::format_message(dwerror);
        if !m.is_empty() {
            merror(cfmt(msgs::FIM_ERROR_REALTIME_WINDOWS_CALLBACK, &[A::S(&m), A::U(dwerror as u64)]));
        }
        return;
    }
    let Some(fim) = super::syscheck::FIM.get() else { return };
    let cfg = fim.sk.cfg.read_recursive();
    let mut g = rt();
    let Some(r) = g.as_mut() else { return };
    // snprintf(wdchar, 260, "%s", (char*)overlap->hEvent)
    let key = {
        let p = (*overlap).hEvent as *const std::ffi::c_char;
        wdchar(std::ffi::CStr::from_ptr(p).to_bytes())
    };
    let Some(e) = r.dirtb.get_mut(&key) else {
        merror(msgs::FIM_ERROR_REALTIME_WINDOWS_CALLBACK_EMPTY);
        return;
    };
    if e.watch_status == FIM_RT_HANDLE_CLOSED {
        r.dirtb.remove(&key);
        mdebug2(cfmt(msgs::FIM_REALTIME_CALLBACK, &[A::B(&key)]));
        return;
    }
    if dwbytes != 0 {
        let mut offset = 0usize;
        loop {
            let b = &e.buffer.0[offset..];
            let next = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
            let name_len = u32::from_le_bytes([b[8], b[9], b[10], b[11]]) as usize;
            let name: Vec<u16> = b[12..12 + name_len].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            offset += next;
            let finalfile = to_acp(&name, 259);
            let mut final_path = e.dir.clone();
            if final_path.last() != Some(&PATH_SEP) {
                final_path.push(b'\\');
            }
            final_path.extend_from_slice(&finalfile);
            final_path.truncate(MAX_LINE - 1);
            final_path.make_ascii_lowercase();
            let index = fim_configuration_directory(&cfg, &key);
            let file_index = fim_configuration_directory(&cfg, &final_path);
            if index == file_index {
                fim.fim_realtime_event(&cfg, &final_path);
            }
            if next == 0 {
                break;
            }
        }
    } else {
        mwarn(msgs::FIM_WARN_REALTIME_OVERFLOW);
    }
    win32read(e);
}

/// `WideCharToMultiByte(CP_ACP, ..., MAX_PATH - 1)`
fn to_acp(w: &[u16], max: usize) -> Vec<u8> {
    use windows_sys::Win32::Globalization::{WideCharToMultiByte, CP_ACP};
    let mut out = vec![0u8; max + 1];
    // SAFETY: an explicit-length input and a buffer of `max` bytes.
    let n = unsafe { WideCharToMultiByte(CP_ACP, 0, w.as_ptr(), w.len() as i32, out.as_mut_ptr(), max as i32, std::ptr::null(), std::ptr::null_mut()) };
    out.truncate(n.max(0) as usize);
    out
}

/// `log_realtime_status`: 0 stop (initial), 1 run, 2 pause.
pub fn log_realtime_status(next: u8) {
    static STATUS: AtomicU8 = AtomicU8::new(0);
    let st = STATUS.load(Ordering::SeqCst);
    let m = match (st, next) {
        (0, 1) => msgs::FIM_REALTIME_STARTED,
        (1, 2) => msgs::FIM_REALTIME_PAUSED,
        (2, 1) => msgs::FIM_REALTIME_RESUMED,
        _ => return,
    };
    minfo(m);
    STATUS.store(next, Ordering::SeqCst);
}

/// After a non-first scan: `fim_realtime_get_queue_overflow` + `fim_realtime_print_watches`.
pub fn after_scan() {
    let mut g = rt();
    if let Some(r) = g.as_mut() {
        // realtime_sanitize_watch_map is empty on Windows
        r.queue_overflow = false;
        mdebug2(cfmt(msgs::FIM_NUM_WATCHES, &[A::U(r.dirtb.len() as u64)]));
    }
}

/// `realtime_adddir` over the realtime directories (under the directories write lock).
fn add_realtime_dirs(fim: &Fim) {
    let mut cfg = fim.sk.cfg.write();
    let max_fd = cfg.max_fd_win_rt;
    for i in 0..cfg.directories.len() {
        if cfg.directories[i].options & REALTIME_ACTIVE != 0 {
            let path = cfg.directories[i].path.clone().into_bytes();
            super::whodata::realtime_adddir(&path, &mut cfg.directories[i], fim, max_fd);
        }
    }
}

/// `fim_run_realtime` (Windows)
fn fim_run_realtime(fim: Arc<Fim>) {
    let prio = fim.sk.cfg.read_recursive().process_priority;
    super::run_check::set_priority_windows_thread(prio);
    add_realtime_dirs(&fim);
    let w = get_realtime_watches();
    if w != 0 {
        mdebug2(cfmt(msgs::FIM_NUM_WATCHES, &[A::U(w as u64)]));
    }
    loop {
        if fim.sk.cfg.read_recursive().realtime_change {
            super::whodata::set_whodata_mode_changes(&fim);
        }
        if get_realtime_watches() > 0 {
            log_realtime_status(1);
            let evt = rt().as_ref().map(|r| r.evt).unwrap_or(std::ptr::null_mut());
            // SAFETY: alertable wait: the completion routines run here.
            if unsafe { WaitForSingleObjectEx(evt, 1000, 1) } == WAIT_FAILED {
                merror(msgs::FIM_ERROR_REALTIME_WAITSINGLE_OBJECT);
            }
        } else {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        add_realtime_dirs(&fim);
    }
}

/// `CreateThread(fim_run_realtime)`
pub fn start_realtime_thread(fim: &Arc<Fim>) {
    let f = fim.clone();
    if std::thread::Builder::new().name("fim_realtime".into()).spawn(move || fim_run_realtime(f)).is_err() {
        merror("(1109): Unable to create new pthread.");
    }
}

impl Fim {
    /// `fim_realtime_event`
    pub fn fim_realtime_event(&self, cfg: &SyscheckConfig, file: &[u8]) {
        if super::win::stat64(file).is_ok() {
            let mut evt = EventData { mode: FIM_REALTIME, report_event: true, ..Default::default() };
            if cfg.rt_delay != 0 {
                std::thread::sleep(std::time::Duration::from_millis(cfg.rt_delay as u64));
            }
            self.fim_checker(cfg, file, &mut evt, None, None);
        } else {
            self.fim_process_missing_entry(cfg, file, FIM_REALTIME, None);
        }
    }

    /// `fim_process_missing_entry`
    pub fn fim_process_missing_entry(&self, cfg: &SyscheckConfig, path: &[u8], mode: i32, w_evt: Option<super::create_db::WhodataEvt>) {
        let mut evt = EventData { mode, w_evt, report_event: true, ..Default::default() };
        let Some(ci) = fim_configuration_directory(cfg, path) else {
            mdebug2(cfmt(msgs::FIM_CONFIGURATION_NOTFOUND, &[A::S("file"), A::B(path)]));
            return;
        };
        let Some(db) = fimdb::instance() else { return };
        // fim_db_get_path(fim_db_process_missing_entry): it exists, check it again
        if let Ok(Some((p, _))) = db.get_path(path) {
            self.fim_checker(cfg, &p, &mut evt, None, None);
            return;
        }
        let o = cfg.directories[ci].options;
        if (mode == FIM_REALTIME && o & REALTIME_ACTIVE == 0) || (mode == FIM_WHODATA && o & WHODATA_ACTIVE == 0) {
            return;
        }
        // a removed directory: the entries below it
        let mut pattern = path.to_vec();
        pattern.push(PATH_SEP);
        pattern.push(b'%');
        evt.type_ = FIM_DELETE;
        if let Ok(paths) = db.search(Some(&pattern), None) {
            for p in paths {
                // fim_generate_delete_event
                if cfg.directories[ci].options & CHECK_SEECHANGES != 0 {
                    self.fim_diff_process_delete_file(&p);
                }
                self.process_delete(cfg, &p, &evt, ci);
            }
        }
    }
}

/// `syscheck.realtime != NULL`
pub fn started() -> bool {
    rt().is_some()
}
