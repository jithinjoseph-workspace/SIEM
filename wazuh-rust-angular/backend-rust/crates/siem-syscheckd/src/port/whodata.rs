//! `syscheckd/src/whodata/win_whodata.c` (Windows whodata), `fim_whodata_initialize`
//! and `set_whodata_mode_changes` of `run_check.c`, `fim_whodata_event` of `create_db.c`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_MORE_DATA, ERROR_NO_MORE_FILES, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authentication::Identity::*;
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidA, GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::EventLog::*;
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::cfmt::{cfmt, A};
use super::config::*;
use super::create_db::{fim_check_depth, fim_configuration_directory, fim_mode, EventData, Fim, WhodataEvt};
use super::fimdb::FIM_WHODATA;
use super::{mdebug1, mdebug2, merror, minfo, msgs, mwarn};

const WPOL_BACKUP_FILE: &str = "tmp\\backup-policies";
const WPOL_NEW_FILE: &str = "tmp\\new-policies";
const DELETE: u32 = 0x0001_0000;
const FILE_WRITE_DATA_: u32 = 0x2;
const FILE_APPEND_DATA_: u32 = 0x4;
const FILE_READ_ATTRIBUTES_: u32 = 0x80;
const FILE_WRITE_ATTRIBUTES_: u32 = 0x100;
const WRITE_DAC_: u32 = 0x0004_0000;
const MODIFY_CRITERIA: u32 = FILE_WRITE_DATA_ | FILE_APPEND_DATA_ | WRITE_DAC_ | FILE_WRITE_ATTRIBUTES_;
const CRITERIA: u32 = DELETE | MODIFY_CRITERIA;
const FILETIME_SECOND: u64 = 10_000_000;
const AUDIT_SUCCESS: u64 = 0x20_0000_0000_0000;
const WDATA_DEFAULT_INTERVAL_SCAN: i32 = 300;
/// `CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`
const INHERIT_FLAG: u8 = 0x2 | 0x1;
const SUCCESSFUL_ACCESS_ACE_FLAG_: u8 = 0x40;
const FAILED_ACCESS_ACE_FLAG_: u8 = 0x80;
const SYSTEM_AUDIT_ACE_TYPE_: u8 = 0x2;
const ACL_REVISION_: u32 = 2;
const PRIV: &[u8] = b"SeSecurityPrivilege\0";

const EVENT_FIELDS: [&str; 9] = [
    "Event/System/EventID",
    "Event/EventData/Data[@Name='SubjectUserName']",
    "Event/EventData/Data[@Name='ObjectName']",
    "Event/EventData/Data[@Name='ProcessName']",
    "Event/EventData/Data[@Name='ProcessId']",
    "Event/EventData/Data[@Name='HandleId']",
    "Event/EventData/Data[@Name='AccessMask']",
    "Event/EventData/Data[@Name='SubjectUserSid']",
    "Event/System/TimeCreated/@SystemTime",
];
const R_EVENT_ID: usize = 0;
const R_USER_NAME: usize = 1;
const R_PATH: usize = 2;
const R_PROCESS_NAME: usize = 3;
const R_PROCESS_ID: usize = 4;
const R_HANDLE_ID: usize = 5;
const R_ACCESS_MASK: usize = 6;
const R_USER_SID: usize = 7;
const R_TIMESTAMP: usize = 8;

/// `syscheck.wdata`
struct WData {
    /// `fd`: the open handles (`OSHash` of `whodata_evt`), None until `whodata_audit_start`.
    fd: Option<HashMap<String, WhodataEvt>>,
    /// `directories`: the last scan time (FILETIME) of each directory.
    directories: HashMap<Vec<u8>, u64>,
    device: Vec<Vec<u8>>,
    drive: Vec<Vec<u8>>,
}

static WDATA: std::sync::LazyLock<Mutex<WData>> = std::sync::LazyLock::new(|| Mutex::new(WData { fd: None, directories: HashMap::new(), device: Vec::new(), drive: Vec::new() }));
static RESTORE_POLICIES: AtomicBool = AtomicBool::new(false);
static POLICIES_CHECKED: AtomicBool = AtomicBool::new(false);
static WHODATA_END: AtomicBool = AtomicBool::new(false);
static CONTEXT: AtomicIsize = AtomicIsize::new(0);
static SUBSCRIBE: AtomicIsize = AtomicIsize::new(0);
/// `everyone_sid` (a leaked `AllocateAndInitializeSid` result)
static EVERYONE: AtomicIsize = AtomicIsize::new(0);

fn wd() -> std::sync::MutexGuard<'static, WData> {
    WDATA.lock().unwrap_or_else(|e| e.into_inner())
}

fn st(d: &Directory) -> u32 {
    d.dirs_status.status.load(Ordering::SeqCst)
}
fn st_set(d: &Directory, on: u32, off: u32) {
    let s = &d.dirs_status.status;
    s.store((s.load(Ordering::SeqCst) & !off) | on, Ordering::SeqCst);
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn wstr(p: *const u16) -> Vec<u16> {
    // SAFETY: a NUL-terminated wide string from the event log.
    unsafe {
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        std::slice::from_raw_parts(p, n + 1).to_vec()
    }
}

/// `check_path_type`: 2 directory, 1 other, 0 missing.
fn check_path_type(path: &[u8]) -> i32 {
    let Some(w) = super::win::auto_to_wide(path) else { return 0 };
    // SAFETY: a NUL-terminated wide path.
    let a = unsafe { GetFileAttributesW(w.as_ptr()) };
    if a == INVALID_FILE_ATTRIBUTES {
        0
    } else if a & FILE_ATTRIBUTE_DIRECTORY != 0 {
        2
    } else {
        1
    }
}

/// `set_privilege`: 0 or 1.
unsafe fn set_privilege(h: HANDLE, enable: bool) -> i32 {
    let mut luid = std::mem::zeroed();
    if LookupPrivilegeValueA(std::ptr::null(), PRIV.as_ptr(), &mut luid) == 0 {
        merror(cfmt(msgs::FIM_ERROR_SACL_FIND_PRIVILEGE, &[A::S("SeSecurityPrivilege"), A::U(GetLastError() as u64)]));
        return 1;
    }
    let tp = TOKEN_PRIVILEGES { PrivilegeCount: 1, Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: if enable { SE_PRIVILEGE_ENABLED } else { 0 } }] };
    if AdjustTokenPrivileges(h, 0, &tp, std::mem::size_of::<TOKEN_PRIVILEGES>() as u32, std::ptr::null_mut(), std::ptr::null_mut()) == 0 {
        merror(cfmt(msgs::FIM_ERROR_WHODATA_TOKENPRIVILEGES, &[A::U(GetLastError() as u64)]));
        return 1;
    }
    mdebug2(cfmt(if enable { msgs::FIM_ELEVATE_PRIVILEGE } else { msgs::FIM_REDUCE_PRIVILEGE }, &[A::S("SeSecurityPrivilege")]));
    0
}

/// `everyone_sid`, allocated once: None when it cannot be built.
unsafe fn everyone_sid(err_msg: &str) -> Option<PSID> {
    let p = EVERYONE.load(Ordering::SeqCst);
    if p != 0 {
        return Some(p as PSID);
    }
    let auth = SID_IDENTIFIER_AUTHORITY { Value: [0, 0, 0, 0, 0, 1] };
    let mut sid: PSID = std::ptr::null_mut();
    if AllocateAndInitializeSid(&auth, 1, 0, 0, 0, 0, 0, 0, 0, 0, &mut sid) == 0 {
        merror(cfmt(err_msg, &[A::U(GetLastError() as u64)]));
        return None;
    }
    EVERYONE.store(sid as isize, Ordering::SeqCst);
    Some(sid)
}

/// `is_valid_sacl`: 0 valid, 1 invalid or NULL, 2 no everyone SID.
unsafe fn is_valid_sacl(sacl: *mut ACL, is_file: bool) -> i32 {
    let Some(everyone) = everyone_sid(msgs::FIM_ERROR_WHODATA_GET_SID) else { return 2 };
    if sacl.is_null() {
        mdebug2(msgs::FIM_SACL_NOT_FOUND);
        return 1;
    }
    for i in 0..(*sacl).AceCount as u32 {
        let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
        if GetAce(sacl, i, &mut ace) == 0 {
            merror(cfmt(msgs::FIM_ERROR_WHODATA_GET_ACE, &[A::U(GetLastError() as u64)]));
            return 1;
        }
        let a = &*(ace as *const ACCESS_ALLOWED_ACE);
        let f = a.Header.AceFlags;
        if (is_file || f & INHERIT_FLAG != 0) && f & SUCCESSFUL_ACCESS_ACE_FLAG_ != 0 && a.Mask & CRITERIA == CRITERIA && EqualSid(&a.SidStart as *const u32 as PSID, everyone) != 0 {
            return 0;
        }
    }
    1
}

/// `utf8_GetNamedSecurityInfo(path, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, ...)`: (sacl, descriptor).
unsafe fn get_sacl(path: &[u8]) -> Result<(*mut ACL, PSECURITY_DESCRIPTOR), u32> {
    let Some(w) = super::win::auto_to_wide(path) else { return Err(87) };
    let mut sacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let r = GetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut sacl, &mut sd);
    if r != 0 {
        return Err(r);
    }
    Ok((sacl, sd))
}

unsafe fn set_sacl(path: &[u8], sacl: *const ACL) -> u32 {
    let Some(w) = super::win::auto_to_wide(path) else { return 87 };
    SetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), sacl, std::ptr::null())
}

/// A new SACL: the old ACEs plus an "Everyone" audit ACE (flags, mask), the new ACE first or last.
unsafe fn build_sacl(old: *mut ACL, in_use: u32, extra: u32, flags: u8, mask: u32, new_first: bool, errs: [&str; 5], path: &[u8]) -> Option<Vec<u32>> {
    let everyone = EVERYONE.load(Ordering::SeqCst) as PSID;
    let sid_size = GetLengthSid(everyone);
    let ace_size = std::mem::size_of::<SYSTEM_AUDIT_ACE>() as u32 + sid_size - 4;
    let size = in_use + std::mem::size_of::<SYSTEM_AUDIT_ACE>() as u32 + sid_size - extra;
    let mut buf = vec![0u32; (size as usize).div_ceil(4)];
    let acl = buf.as_mut_ptr() as *mut ACL;
    if InitializeAcl(acl, size, ACL_REVISION_) == 0 {
        merror(cfmt(errs[0], &[A::B(path), A::U(GetLastError() as u64)]));
        return None;
    }
    let mut ace = vec![0u32; (ace_size as usize).div_ceil(4)];
    let a = ace.as_mut_ptr() as *mut SYSTEM_AUDIT_ACE;
    (*a).Header.AceType = SYSTEM_AUDIT_ACE_TYPE_;
    (*a).Header.AceFlags = flags;
    (*a).Header.AceSize = ace_size as u16;
    (*a).Mask = mask;
    if CopySid(sid_size, &mut (*a).SidStart as *mut u32 as PSID, everyone) == 0 {
        merror(cfmt(errs[1], &[A::B(path), A::U(sid_size as u64), A::U(GetLastError() as u64)]));
        return None;
    }
    let add_new = |at: u32| AddAce(acl, ACL_REVISION_, at, a as *const _, ace_size) != 0;
    if new_first && !add_new(0) {
        merror(cfmt(errs[4], &[A::B(path), A::U(GetLastError() as u64)]));
        return None;
    }
    if !old.is_null() {
        for i in 0..(*old).AceCount as u32 {
            let mut e: *mut std::ffi::c_void = std::ptr::null_mut();
            if GetAce(old, i, &mut e) == 0 {
                merror(cfmt(errs[2], &[A::U(i as u64), A::B(path)]));
                return None;
            }
            if AddAce(acl, ACL_REVISION_, u32::MAX, e, (*(e as *const ACE_HEADER)).AceSize as u32) == 0 {
                merror(cfmt(errs[3], &[A::U(i as u64), A::B(path)]));
                return None;
            }
        }
    }
    if !new_first && !add_new(0) {
        merror(cfmt(errs[4], &[A::B(path), A::U(GetLastError() as u64)]));
        return None;
    }
    Some(buf)
}

/// `OpenProcessToken` + `set_privilege(TRUE)`, the work, then the privilege back off.
unsafe fn with_privilege<T>(open_err: &str, elevate_err: &str, reduce_err: &str, fail: T, f: impl FnOnce() -> T) -> T {
    let mut h: HANDLE = std::ptr::null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut h) == 0 {
        merror(cfmt(open_err, &[A::U(GetLastError() as u64)]));
        return fail;
    }
    if set_privilege(h, true) != 0 {
        merror(cfmt(elevate_err, &[A::U(GetLastError() as u64)]));
        CloseHandle(h);
        return fail;
    }
    let r = f();
    if set_privilege(h, false) != 0 {
        merror(cfmt(reduce_err, &[A::U(GetLastError() as u64)]));
    }
    CloseHandle(h);
    r
}

/// `set_winsacl`: 0 or 1.
fn set_winsacl(dir: &[u8], c: &Directory) -> i32 {
    mdebug2(cfmt(msgs::FIM_SACL_CONFIGURE, &[A::B(dir)]));
    // SAFETY: Win32 security calls on buffers owned here; the descriptor is freed with LocalFree.
    unsafe {
        with_privilege(msgs::FIM_ERROR_SACL_OPENPROCESSTOKEN, msgs::FIM_ERROR_SACL_ELEVATE_PRIVILEGE, msgs::FIM_ERROR_SACL_SET_PRIVILEGE, 1, || {
            let (old, sd) = match get_sacl(dir) {
                Ok(v) => v,
                Err(r) => {
                    merror(cfmt(msgs::FIM_ERROR_SACL_GETSECURITYINFO, &[A::I(r as i64)]));
                    return 1;
                }
            };
            let free = || {
                if !sd.is_null() {
                    LocalFree(sd as _);
                }
            };
            let is_file = c.dirs_status.object_type.load(Ordering::SeqCst) == WD_STATUS_FILE_TYPE;
            let in_use;
            match is_valid_sacl(old, is_file) {
                0 => {
                    free();
                    return 0;
                }
                1 => {
                    mdebug2(cfmt(msgs::FIM_SACL_CHECK_CONFIGURE, &[A::B(dir)]));
                    st_set(c, WD_IGNORE_REST, 0);
                    if old.is_null() {
                        in_use = std::mem::size_of::<ACL>() as u32;
                    } else {
                        let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
                        if GetAclInformation(old, &mut info as *mut _ as *mut _, std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32, AclSizeInformation) == 0 {
                            merror(cfmt(msgs::FIM_ERROR_SACL_GETSIZE, &[A::B(dir)]));
                            free();
                            return 1;
                        }
                        in_use = info.AclBytesInUse;
                    }
                }
                // no everyone SID: the C goes on and fails building the ACE
                _ => {
                    free();
                    return 1;
                }
            }
            let errs = [msgs::FIM_ERROR_SACL_CREATE, "", msgs::FIM_ERROR_SACL_ACE_GET, msgs::FIM_ERROR_SACL_ACE_CPY, msgs::FIM_ERROR_SACL_ACE_ADD];
            let r = match build_sacl(old, in_use, 4, INHERIT_FLAG | SUCCESSFUL_ACCESS_ACE_FLAG_, CRITERIA, false, errs, dir) {
                Some(acl) => {
                    let r = set_sacl(dir, acl.as_ptr() as *const ACL);
                    if r != 0 {
                        merror(cfmt(msgs::FIM_ERROR_SACL_SETSECURITYINFO, &[A::I(r as i64)]));
                        1
                    } else {
                        0
                    }
                }
                None => 1,
            };
            free();
            r
        })
    }
}

/// `w_update_sacl`: 0 or -1 (re-adds an "Everyone" failed-access ACE so the SACL is re-inherited).
pub fn w_update_sacl(path: &[u8]) -> i32 {
    // SAFETY: as in set_winsacl.
    unsafe {
        if everyone_sid(msgs::FIM_ERROR_WHODATA_WIN_SIDERROR).is_none() {
            return -1;
        }
        with_privilege(msgs::FIM_ERROR_WHODATA_OPEN_TOKEN, msgs::FIM_ERROR_WHODATA_ACTIVATE_PRIV, msgs::FIM_ERROR_WHODATA_ACTIVATE_PRIV, -1, || {
            let (old, sd) = match get_sacl(path) {
                Ok(v) => v,
                Err(r) => {
                    merror(cfmt(msgs::FIM_ERROR_WHODATA_GETNAMEDSECURITY, &[A::I(r as i64)]));
                    return -1;
                }
            };
            let mut in_use = std::mem::size_of::<ACL>() as u32;
            if !old.is_null() {
                let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
                if GetAclInformation(old, &mut info as *mut _ as *mut _, std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32, AclSizeInformation) == 0 {
                    merror(cfmt(msgs::FIM_ERROR_WHODATA_SACL_SIZE, &[A::B(path)]));
                    LocalFree(sd as _);
                    return -1;
                }
                in_use = info.AclBytesInUse;
            }
            let errs = [msgs::FIM_ERROR_WHODATA_SACL_NOCREATE, msgs::FIM_ERROR_WHODATA_COPY_SID, msgs::FIM_ERROR_WHODATA_ACE_NOOBTAIN, msgs::FIM_ERROR_WHODATA_ACE_NUMBER, msgs::FIM_ERROR_WHODATA_ACE_NOADDED];
            let r = match build_sacl(old, in_use, 0, FAILED_ACCESS_ACE_FLAG_, 0, false, errs, path) {
                Some(acl) => {
                    let r = set_sacl(path, acl.as_ptr() as *const ACL);
                    if r != 0 {
                        merror(cfmt(msgs::FIM_ERROR_WHODATA_SETNAMEDSECURITY, &[A::I(r as i64)]));
                        -1
                    } else {
                        0
                    }
                }
                None => -1,
            };
            if !sd.is_null() {
                LocalFree(sd as _);
            }
            r
        })
    }
}

/// `check_object_sacl`: 0 valid, 1 invalid, 2 not checked.
fn check_object_sacl(obj: &[u8], is_file: bool) -> i32 {
    // SAFETY: as in set_winsacl.
    unsafe {
        with_privilege(msgs::FIM_ERROR_SACL_OPENPROCESSTOKEN, msgs::FIM_ERROR_SACL_ELEVATE_PRIVILEGE, msgs::FIM_ERROR_SACL_SET_PRIVILEGE, 2, || match get_sacl(obj) {
            Ok((sacl, sd)) => {
                let r = is_valid_sacl(sacl, is_file);
                if !sd.is_null() {
                    LocalFree(sd as _);
                }
                r
            }
            Err(r) => {
                merror(cfmt(msgs::FIM_ERROR_SACL_GETSECURITYINFO, &[A::I(r as i64)]));
                2
            }
        })
    }
}

/// `restore_sacls`: removes the ACE added at position 0.
fn restore_sacls(fim: &Fim) {
    // SAFETY: as in set_winsacl.
    unsafe {
        with_privilege(msgs::FIM_ERROR_SACL_OPENPROCESSTOKEN, msgs::FIM_ERROR_SACL_ELEVATE_PRIVILEGE, msgs::FIM_ERROR_SACL_SET_PRIVILEGE, (), || {
            let cfg = fim.sk.cfg.read_recursive();
            for d in &cfg.directories {
                if st(d) & WD_IGNORE_REST == 0 {
                    continue;
                }
                let (sacl, sd) = match get_sacl(d.path.as_bytes()) {
                    Ok(v) => v,
                    Err(r) => {
                        merror(cfmt(msgs::FIM_ERROR_SACL_GETSECURITYINFO, &[A::I(r as i64)]));
                        break;
                    }
                };
                if DeleteAce(sacl, 0) == 0 {
                    merror(cfmt(msgs::FIM_ERROR_SACL_ACE_DELETE, &[A::U(GetLastError() as u64)]));
                    break;
                }
                let r = set_sacl(d.path.as_bytes(), sacl);
                if r != 0 {
                    merror(cfmt(msgs::FIM_ERROR_SACL_SETSECURITYINFO, &[A::I(r as i64)]));
                    break;
                }
                if !sd.is_null() {
                    LocalFree(sd as _);
                }
                mdebug2(cfmt(msgs::FIM_SACL_RESTORED, &[A::S(&d.path)]));
            }
        })
    }
}

/// `wm_exec(command, NULL, &status, secs, NULL)` with the C retry loop: true on success.
fn auditpol(command: &str, keep_output: bool) -> bool {
    let Some(log) = super::log() else { return false };
    let (retries, timeout) = (5, 5);
    let mut i = 0;
    loop {
        let e = siem_execd::wm_exec::wm_exec(log, command, timeout + i);
        let failed = if !keep_output {
            e.retval != 0 || e.status.unwrap_or(0) != 0
        } else if e.retval < 0 {
            merror(cfmt(msgs::FIM_ERROR_WHODATA_AUDITPOL, &[A::S("failed to execute command")]));
            true
        } else if e.retval == 1 {
            merror(cfmt(msgs::FIM_ERROR_WHODATA_AUDITPOL, &[A::S("time overtaken while running the command")]));
            true
        } else if e.status.unwrap_or(0) != 0 {
            let f = cfmt(msgs::FIM_ERROR_WHODATA_AUDITPOL, &[A::S("command returned failure'. Output: '%s")]);
            merror(cfmt(&String::from_utf8_lossy(&f), &[A::B(e.output.as_deref().unwrap_or(b""))]));
            true
        } else {
            false
        };
        if failed {
            merror(cfmt(msgs::FIM_AUDITPOL_ATTEMPT_FAIL, &[A::I(i as i64 + 1)]));
        }
        i += 1;
        if !(i <= retries && failed) {
            if keep_output && i == retries + 1 {
                merror(cfmt(msgs::FIM_AUDITPOL_FINAL_FAIL, &[A::I(i as i64)]));
            }
            return !failed;
        }
    }
}

/// `restore_audit_policies`
fn restore_audit_policies() -> i32 {
    if !std::path::Path::new(WPOL_BACKUP_FILE).is_file() {
        merror(msgs::FIM_ERROR_WHODATA_RESTORE_POLICIES);
        return 1;
    }
    if auditpol(&format!("auditpol /restore /file:\"{WPOL_BACKUP_FILE}\""), true) {
        0
    } else {
        1
    }
}

/// `audit_restore` (also the `atexit` handler)
fn audit_restore(fim: &Fim) {
    restore_sacls(fim);
    if RESTORE_POLICIES.load(Ordering::SeqCst) {
        restore_audit_policies();
    }
}

extern "C" fn audit_restore_atexit() {
    if let Some(f) = super::syscheck::FIM.get() {
        audit_restore(f);
    }
}

/// `set_policies`: 0 ok, else 1.
fn set_policies() -> i32 {
    let errno_of = |e: &std::io::Error| e.raw_os_error().unwrap_or(0);
    if std::path::Path::new(WPOL_BACKUP_FILE).is_file() {
        if let Err(e) = std::fs::remove_file(WPOL_BACKUP_FILE) {
            let n = errno_of(&e);
            merror(cfmt(msgs::FIM_ERROR_WPOL_BACKUP_FILE_REMOVE, &[A::S(WPOL_BACKUP_FILE), A::S(&siem_ipc::os_net::strerror(n)), A::I(n as i64)]));
            return 1;
        }
    }
    if !auditpol(&format!("auditpol /backup /file:\"{WPOL_BACKUP_FILE}\""), false) {
        merror(msgs::FIM_WARN_WHODATA_AUTOCONF);
        return 1;
    }
    let backup = match std::fs::read(WPOL_BACKUP_FILE) {
        Ok(b) => b,
        Err(e) => {
            let n = errno_of(&e);
            merror(cfmt(msgs::FIM_ERROR_WPOL_BACKUP_FILE_OPEN, &[A::S(WPOL_BACKUP_FILE), A::S(&siem_ipc::os_net::strerror(n)), A::I(n as i64)]));
            return 1;
        }
    };
    // text streams on both sides: CRLF stays CRLF, a lone LF becomes CRLF
    // shortcut: the C prints each line as a format string; a '%' in the backup is copied as is here.
    let mut text: Vec<u8> = Vec::with_capacity(backup.len() + 160);
    let mut lines = backup.split(|&b| b == b'\n').peekable();
    while let Some(l) = lines.next() {
        let l = l.strip_suffix(b"\r").unwrap_or(l);
        text.extend_from_slice(l);
        if lines.peek().is_some() {
            text.extend_from_slice(b"\r\n");
        }
    }
    text.extend_from_slice(b",System,File System,{0CCE921D-69AE-11D9-BED3-505054503030},,,1\r\n,System,Handle Manipulation,{0CCE9223-69AE-11D9-BED3-505054503030},,,1\r\n");
    if let Err(e) = std::fs::write(WPOL_NEW_FILE, &text) {
        let n = errno_of(&e);
        merror(cfmt(msgs::FIM_ERROR_WPOL_BACKUP_FILE_OPEN, &[A::S(WPOL_NEW_FILE), A::S(&siem_ipc::os_net::strerror(n)), A::I(n as i64)]));
        return 1;
    }
    if !auditpol(&format!("auditpol /restore /file:\"{WPOL_NEW_FILE}\""), false) {
        merror(msgs::FIM_WARN_WHODATA_AUTOCONF);
        return 1;
    }
    RESTORE_POLICIES.store(true, Ordering::SeqCst);
    0
}

/// `set_subscription_query`
fn subscription_query() -> String {
    format!(
        "Event[ System[band(Keywords, {AUDIT_SUCCESS})] and ( ( ( EventData/Data[@Name='ObjectType'] = 'File' ) and ( (  System/EventID = 4656 or System/EventID = 4663 ) and ( EventData[band(Data[@Name='AccessMask'], {CRITERIA})] ) ) ) or ( System/EventID = 4658 ) or ( System/EventID = 4719 and ( EventData/Data[@Name='SubcategoryGuid'] = '{{0CCE9223-69AE-11D9-BED3-505054503030}}' or EventData/Data[@Name='SubcategoryGuid'] = '{{0CCE921D-69AE-11D9-BED3-505054503030}}' ) and ( EventData/Data[@Name='AuditPolicyChanges'] = '%%8448'or EventData/Data[@Name='AuditPolicyChanges'] = '%%8448, %%8450'or EventData/Data[@Name='AuditPolicyChanges'] = '%%8448, %%8451' )) ) ]"
    )
}

/// `whodata_check_arch`: 0 or -1.
fn whodata_check_arch() -> i32 {
    use windows_sys::Win32::System::Registry::*;
    let key = b"System\\CurrentControlSet\\Control\\Session Manager\\Environment\0";
    let mut h: HKEY = std::ptr::null_mut();
    // SAFETY: registry reads into a 64-byte buffer.
    unsafe {
        if RegOpenKeyExA(HKEY_LOCAL_MACHINE, key.as_ptr(), 0, KEY_READ, &mut h) != 0 {
            merror(format!("(1758): Unable to open registry key: '{}'.", String::from_utf8_lossy(&key[..key.len() - 1])));
            return -1;
        }
        let mut arch = [0u8; 65];
        let mut n = 64u32;
        let r = RegQueryValueExA(h, b"PROCESSOR_ARCHITECTURE\0".as_ptr(), std::ptr::null(), std::ptr::null_mut(), arch.as_mut_ptr(), &mut n);
        let mut ret = -1;
        if r != 0 {
            merror(cfmt(msgs::FIM_ERROR_WHODATA_WIN_ARCH, &[A::U(r as u64)]));
        } else if arch.starts_with(b"AMD64") || arch.starts_with(b"IA64") || arch.starts_with(b"ARM64") || arch.starts_with(b"x86") {
            ret = 0;
        }
        RegCloseKey(h);
        ret
    }
}

/// `run_whodata_scan`: 0 started, 1 failed.
fn run_whodata_scan() -> i32 {
    if whodata_check_arch() != 0 {
        return 1;
    }
    // SAFETY: registers a plain extern "C" handler.
    unsafe { libc::atexit(audit_restore_atexit) };
    if set_policies() != 0 {
        merror(msgs::FIM_WARN_WHODATA_LOCALPOLICIES);
        return 1;
    }
    let fields: Vec<Vec<u16>> = EVENT_FIELDS.iter().map(|f| wide(f)).collect();
    let ptrs: Vec<*const u16> = fields.iter().map(|f| f.as_ptr()).collect();
    // SAFETY: field paths and the query outlive the calls; the callback is a plain function.
    unsafe {
        let ctx = EvtCreateRenderContext(ptrs.len() as u32, ptrs.as_ptr(), EvtRenderContextValues);
        if ctx == 0 {
            merror(cfmt(msgs::FIM_ERROR_WHODATA_CONTEXT, &[A::U(GetLastError() as u64)]));
            return 1;
        }
        CONTEXT.store(ctx, Ordering::SeqCst);
        let q = wide(&subscription_query());
        let channel = wide("Security");
        let h = EvtSubscribe(0, std::ptr::null_mut(), channel.as_ptr(), q.as_ptr(), 0, std::ptr::null(), Some(whodata_callback), EvtSubscribeToFutureEvents);
        if h == 0 {
            merror(msgs::FIM_ERROR_WHODATA_EVENTCHANNEL);
            return 1;
        }
        SUBSCRIBE.store(h, Ordering::SeqCst);
    }
    minfo(msgs::FIM_WHODATA_STARTED);
    0
}

/// `whodata_audit_start`: the hash tables and the volume names.
fn whodata_audit_start() {
    {
        let mut w = wd();
        w.fd = Some(HashMap::new());
        w.directories.clear();
    }
    minfo(msgs::FIM_WHODATA_VOLUMES);
    get_volume_names();
}

/// `wcstombs` (C locale): ASCII only.
fn wcstombs(w: &[u16]) -> Vec<u8> {
    w.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect()
}

/// `get_volume_names`
fn get_volume_names() -> i32 {
    let mut volume = [0u16; 260];
    // SAFETY: MAX_PATH buffers.
    unsafe {
        let fh = FindFirstVolumeW(volume.as_mut_ptr(), 260);
        if fh == INVALID_HANDLE_VALUE {
            let e = GetLastError();
            mwarn(format!("FindFirstVolumeW failed ({e})'{}'", siem_ipc::os_net::strerror(e as i32)));
            return -1;
        }
        let mut ret = -1;
        loop {
            let n = volume.iter().position(|&c| c == 0).unwrap_or(260);
            let index = n.saturating_sub(1);
            if n < 5 || volume[0] != b'\\' as u16 || volume[1] != b'\\' as u16 || volume[2] != b'?' as u16 || volume[3] != b'\\' as u16 || volume[index] != b'\\' as u16 {
                mwarn(format!("Find Volume returned a bad path: {}", String::from_utf8_lossy(&wcstombs(&volume))));
                break;
            }
            volume[index] = 0;
            let mut device = [0u16; 260];
            let cc = QueryDosDeviceW(volume[4..].as_ptr(), device.as_mut_ptr(), 260);
            volume[index] = b'\\' as u16;
            if cc == 0 {
                let e = GetLastError();
                mwarn(format!("QueryDosDeviceW failed ({e})'{}'", siem_ipc::os_net::strerror(e as i32)));
                break;
            }
            let mut dev = wcstombs(&device);
            dev.push(b'\\');
            get_drive_names(&volume, &dev);
            if FindNextVolumeW(fh, volume.as_mut_ptr(), 260) == 0 {
                let e = GetLastError();
                if e != ERROR_NO_MORE_FILES {
                    mwarn(format!("FindNextVolumeW failed ({e})'{}'", siem_ipc::os_net::strerror(e as i32)));
                    break;
                }
                ret = 0;
                break;
            }
        }
        FindVolumeClose(fh);
        ret
    }
}

/// `get_drive_names`
fn get_drive_names(volume: &[u16], device: &[u8]) {
    let mut cc = 261u32;
    let names = loop {
        let mut names = vec![0u16; cc as usize];
        // SAFETY: a buffer of `cc` wide chars.
        if unsafe { GetVolumePathNamesForVolumeNameW(volume.as_ptr(), names.as_mut_ptr(), cc, &mut cc) } != 0 {
            break names;
        }
        // SAFETY: plain Win32 call.
        let e = unsafe { GetLastError() };
        if e != ERROR_MORE_DATA {
            mwarn(format!("GetVolumePathNamesForVolumeNameW ({e})'{}'", siem_ipc::os_net::strerror(e as i32)));
            return;
        }
    };
    // `convert_name` is reused without a terminator after the first copy, as in the C
    let mut convert = [0u8; 260];
    let mut i = 0;
    while names[i] != 0 {
        let len = names[i..].iter().position(|&c| c == 0).unwrap_or(0);
        for (k, &c) in names[i..i + len].iter().enumerate().take(259) {
            convert[k] = c as u8;
        }
        let name: Vec<u8> = convert.iter().take_while(|&&c| c != 0).copied().collect();
        mdebug1(cfmt(msgs::FIM_WHODATA_DEVICE_LETTER, &[A::B(device), A::B(&name)]));
        let mut w = wd();
        w.device.push(device.to_vec());
        w.drive.push(name);
        i += len + 1;
    }
}

/// `replace_device_path`
fn replace_device_path(path: &mut Vec<u8>) {
    if path.first() != Some(&b'\\') {
        return;
    }
    let w = wd();
    for (dev, drive) in w.device.iter().zip(&w.drive) {
        mdebug2(cfmt(msgs::FIM_WHODATA_DEVICE_PATH, &[A::B(dev), A::B(path)]));
        if path.starts_with(dev) {
            let mut n = drive.clone();
            n.extend_from_slice(&path[dev.len()..]);
            mdebug2(cfmt(msgs::FIM_WHODATA_DEVICE_REPLACE, &[A::B(path), A::B(&n)]));
            *path = n;
            break;
        }
    }
}

/// `get_whodata_path` (CP_ACP)
fn get_whodata_path(w: &[u16]) -> Option<Vec<u8>> {
    use windows_sys::Win32::Globalization::{WideCharToMultiByte, CP_ACP};
    // SAFETY: a NUL-terminated input; the size query, then the conversion.
    unsafe {
        let n = WideCharToMultiByte(CP_ACP, 0, w.as_ptr(), -1, std::ptr::null_mut(), 0, std::ptr::null(), std::ptr::null_mut());
        if n > 0 {
            let mut out = vec![0u8; n as usize + 1];
            if WideCharToMultiByte(CP_ACP, 0, w.as_ptr(), -1, out.as_mut_ptr(), n, std::ptr::null(), std::ptr::null_mut()) > 0 {
                out.truncate(out.iter().position(|&c| c == 0).unwrap_or(out.len()));
                return Some(out);
            }
        }
        mdebug1(cfmt(msgs::FIM_WHODATA_PATH_NOPROCCESED, &[A::I(GetLastError() as i64)]));
        None
    }
}

/// `convert_windows_string` (UTF-8, invalid characters fail)
fn convert_windows_string(w: &[u16]) -> Option<String> {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    match String::from_utf16(&w[..end]) {
        Ok(s) => Some(s),
        Err(_) => {
            merror("Could not WideCharToMultiByte() when determining size which returned (1113)");
            None
        }
    }
}

/// The rendered values (`whodata_event_render`).
struct Rendered(Vec<u64>);

impl Rendered {
    fn v(&self, i: usize) -> &EVT_VARIANT {
        // SAFETY: the buffer holds `EVENT_FIELDS.len()` variants (checked when rendered).
        unsafe { &*(self.0.as_ptr() as *const EVT_VARIANT).add(i) }
    }
}

unsafe fn whodata_event_render(event: EVT_HANDLE) -> Option<Rendered> {
    let ctx = CONTEXT.load(Ordering::SeqCst);
    let (mut used, mut count) = (0u32, 0u32);
    EvtRender(ctx, event, EvtRenderEventValues, 0, std::ptr::null_mut(), &mut used, &mut count);
    let mut buf = vec![0u64; (used as usize).div_ceil(8)];
    if EvtRender(ctx, event, EvtRenderEventValues, used, buf.as_mut_ptr().cast(), &mut used, &mut count) == 0 {
        mwarn(cfmt(msgs::FIM_WHODATA_RENDER_EVENT, &[A::U(GetLastError() as u64)]));
        return None;
    }
    if count as usize != EVENT_FIELDS.len() {
        mwarn(msgs::FIM_WHODATA_RENDER_PARAM);
        return None;
    }
    Some(Rendered(buf))
}

fn bad_param(t: u32, name: &str) {
    mwarn(cfmt(msgs::FIM_WHODATA_PARAMETER, &[A::I(t as i64), A::S(name)]));
}

/// `whodata_get_handle_id` / the process id: HexInt64, SizeT or HexInt32.
#[allow(non_upper_case_globals)]
unsafe fn int64ish(v: &EVT_VARIANT) -> Option<u64> {
    match v.Type as i32 {
        EvtVarTypeHexInt64 => Some(v.Anonymous.UInt64Val),
        EvtVarTypeSizeT => Some(v.Anonymous.SizeTVal as u64),
        EvtVarTypeHexInt32 => Some(v.Anonymous.UInt32Val as u64),
        _ => None,
    }
}

unsafe fn access_mask(r: &Rendered) -> Option<u32> {
    let v = r.v(R_ACCESS_MASK);
    if v.Type as i32 != EvtVarTypeHexInt32 {
        bad_param(v.Type, "mask");
        return None;
    }
    Some(v.Anonymous.UInt32Val)
}

/// `whodata_event_parse`
unsafe fn whodata_event_parse(r: &Rendered) -> Option<WhodataEvt> {
    let mut e = WhodataEvt::default();
    let p = r.v(R_PATH);
    if p.Type as i32 != EvtVarTypeString {
        bad_param(p.Type, "path");
        return None;
    }
    let mut path = get_whodata_path(&wstr(p.Anonymous.XmlVal))?;
    replace_device_path(&mut path);
    path.make_ascii_lowercase();
    if super::win::check_removed_file(&path) {
        mdebug2(cfmt(msgs::FIM_DISCARD_RECYCLEBIN, &[A::B(&path)]));
        return None;
    }
    e.path = path;
    let s = |i: usize, name: &str| -> Option<String> {
        let v = r.v(i);
        if v.Type as i32 != EvtVarTypeString {
            bad_param(v.Type, name);
            None
        } else {
            convert_windows_string(&wstr(v.Anonymous.XmlVal))
        }
    };
    e.user_name = s(R_USER_NAME, "user_name");
    e.process_name = s(R_PROCESS_NAME, "process_name");
    let pid = r.v(R_PROCESS_ID);
    e.process_id = int64ish(pid).unwrap_or_else(|| {
        bad_param(pid.Type, "process_id");
        0
    });
    let sid = r.v(R_USER_SID);
    if sid.Type as i32 != EvtVarTypeSid {
        bad_param(sid.Type, "user_id");
    } else {
        let mut out: *mut u8 = std::ptr::null_mut();
        if ConvertSidToStringSidA(sid.Anonymous.SidVal, &mut out) == 0 {
            match &e.user_name {
                Some(u) => mdebug1(cfmt(msgs::FIM_WHODATA_INVALID_UID, &[A::S(u)])),
                None => mdebug1(msgs::FIM_WHODATA_INVALID_UNKNOWN_UID),
            }
            return None;
        }
        e.user_id = Some(std::ffi::CStr::from_ptr(out as *const std::ffi::c_char).to_string_lossy().into_owned());
        LocalFree(out as _);
    }
    Some(e)
}

/// `whodata_hash_add` on the fd table: 2 added, 1 duplicate.
fn fd_add(w: &mut WData, id: &str, e: WhodataEvt) -> i32 {
    let fd = w.fd.get_or_insert_with(HashMap::new);
    if fd.contains_key(id) {
        mdebug2(cfmt(msgs::FIM_ERROR_WHODATA_EVENTADD_DUP, &[A::S("whodata"), A::S(id)]));
        return 1;
    }
    fd.insert(id.to_string(), e);
    2
}

/// `whodata_callback`
unsafe extern "system" fn whodata_callback(action: EVT_SUBSCRIBE_NOTIFY_ACTION, _ctx: *const std::ffi::c_void, event: EVT_HANDLE) -> u32 {
    if action != EvtSubscribeActionDeliver {
        return 0;
    }
    let Some(fim) = super::syscheck::FIM.get() else { return 1 };
    let Some(r) = whodata_event_render(event) else { return 1 };
    let ev = r.v(R_EVENT_ID);
    if ev.Type as i32 != EvtVarTypeUInt16 {
        bad_param(ev.Type, "event_id");
        return 1;
    }
    let event_id = ev.Anonymous.Int16Val;
    let mut hash_id = String::new();
    if matches!(event_id, 4656 | 4663 | 4658) {
        let h = r.v(R_HANDLE_ID);
        match int64ish(h) {
            Some(id) => hash_id = id.to_string(),
            None => {
                bad_param(h.Type, "handle_id");
                return 1;
            }
        }
    }
    match event_id {
        4656 => {
            let Some(mut w_evt) = whodata_event_parse(&r) else { return 1 };
            let Some(mask) = access_mask(&r) else { return 1 };
            {
                let cfg = fim.sk.cfg.read_recursive();
                match fim_configuration_directory(&cfg, &w_evt.path) {
                    None => {
                        mdebug2(cfmt(msgs::FIM_CONFIGURATION_NOTFOUND, &[A::S("file"), A::B(&w_evt.path)]));
                        if mask & (FILE_APPEND_DATA_ | FILE_WRITE_DATA_) == 0 {
                            mdebug2(cfmt(msgs::FIM_WHODATA_NOT_ACTIVE, &[A::B(&w_evt.path)]));
                            return 1;
                        }
                    }
                    Some(ci) => {
                        let c = &cfg.directories[ci];
                        if st(c) & WD_CHECK_WHODATA == 0 && mask & (FILE_APPEND_DATA_ | FILE_WRITE_DATA_) == 0 {
                            mdebug2(cfmt(msgs::FIM_WHODATA_CANCELED, &[A::B(&w_evt.path)]));
                            return 1;
                        }
                        let depth = fim_check_depth(&w_evt.path, c);
                        if depth > c.recursion_level {
                            mdebug2(cfmt(msgs::FIM_MAX_RECURSION_LEVEL, &[A::I(depth as i64), A::I(c.recursion_level as i64), A::B(&w_evt.path)]));
                            return 1;
                        }
                    }
                }
            }
            let mut is_directory = 0;
            match check_path_type(&w_evt.path) {
                2 => is_directory = 1,
                0 if mask & DELETE != 0 || mask & FILE_APPEND_DATA_ != 0 => {
                    mdebug2(cfmt(msgs::FIM_WHODATA_REMOVE_FOLDEREVENT, &[A::B(&w_evt.path)]));
                    is_directory = 1;
                }
                _ => {}
            }
            w_evt.mask = if mask == DELETE || mask == DELETE | FILE_READ_ATTRIBUTES_ { DELETE } else { 0 };
            w_evt.scan_directory = is_directory;
            let mut w = wd();
            if fd_add(&mut w, &hash_id, w_evt.clone()) == 1 {
                mdebug2(cfmt(msgs::FIM_WHODATA_HANDLE_UPDATE, &[A::S(&hash_id)]));
                if let Some(fd) = w.fd.as_mut() {
                    fd.remove(&hash_id);
                }
                fd_add(&mut w, &hash_id, w_evt);
            }
        }
        4663 => {
            let mut w = wd();
            let Some(fd) = w.fd.as_mut() else { return 1 };
            let Some(w_evt) = fd.get_mut(&hash_id) else { return 1 };
            let Some(mask) = access_mask(&r) else { return 1 };
            if mask == 0 {
                return 1;
            }
            w_evt.mask |= mask;
            let t = r.v(R_TIMESTAMP);
            if t.Type as i32 != EvtVarTypeFileTime {
                bad_param(t.Type, "event_time");
                w_evt.scan_directory = 2;
                return 1;
            }
            if w_evt.scan_directory == 0 || w_evt.mask & (FILE_WRITE_DATA_ | FILE_APPEND_DATA_) == 0 {
                return 1;
            }
            let path = w_evt.path.clone();
            if fim_configuration_directory(&fim.sk.cfg.read_recursive(), &path).is_none() {
                mdebug2(cfmt(msgs::FIM_CONFIGURATION_NOTFOUND, &[A::S("file"), A::B(&path)]));
                mdebug2(cfmt(msgs::FIM_WHODATA_DIRECTORY_DISCARDED, &[A::B(&path)]));
                w_evt.scan_directory = 2;
                return 0;
            }
            let event_time = t.Anonymous.FileTimeVal;
            let w = &mut *w;
            match w.directories.get_mut(&path) {
                Some(last) => {
                    if event_time.wrapping_sub(*last) < FILETIME_SECOND {
                        mdebug2(cfmt(msgs::FIM_WHODATA_DIRECTORY_SCANNED, &[A::B(&path)]));
                        if let Some(e) = w.fd.as_mut().and_then(|fd| fd.get_mut(&hash_id)) {
                            e.scan_directory = 3;
                        }
                        return 0;
                    }
                    *last = filetime_now();
                    mdebug2(cfmt(msgs::FIM_WHODATA_CHECK_NEW_FILES, &[A::B(&path)]));
                }
                None => {
                    w.directories.insert(path.clone(), 0);
                    mdebug2(cfmt(msgs::FIM_WHODATA_CHECK_NEW_FILES, &[A::B(&path)]));
                }
            }
        }
        4658 => {
            let w_evt = wd().fd.as_mut().and_then(|fd| fd.remove(&hash_id));
            if let Some(w_evt) = w_evt {
                match w_evt.scan_directory {
                    0 => fim.fim_whodata_event(&w_evt),
                    1 => {
                        if w_evt.mask & DELETE != 0 || w_evt.mask & (FILE_APPEND_DATA_ | FILE_WRITE_DATA_) != 0 {
                            fim.fim_whodata_event(&w_evt);
                        } else {
                            mdebug2(cfmt(msgs::FIM_WHODATA_NO_NEW_FILES, &[A::B(&w_evt.path), A::U(w_evt.mask as u64)]));
                        }
                    }
                    2 => mdebug1(cfmt(msgs::FIM_WHODATA_SCAN_ABORTED, &[A::B(&w_evt.path)])),
                    _ => {}
                }
            }
        }
        4719 => {
            if POLICIES_CHECKED.load(Ordering::SeqCst) {
                mwarn(msgs::FIM_WHODATA_POLICY_CHANGE_CHANNEL);
                win_whodata_release_resources(fim);
            }
        }
        _ => {
            merror(msgs::FIM_ERROR_WHODATA_EVENTID);
            return 1;
        }
    }
    0
}

fn filetime_now() -> u64 {
    let mut ft = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    // SAFETY: writes the struct.
    unsafe { GetSystemTimeAsFileTime(&mut ft) };
    (ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64
}

/// `win_whodata_release_resources`: every directory moves to realtime.
fn win_whodata_release_resources(fim: &Fim) {
    {
        let mut cfg = fim.sk.cfg.write();
        for d in cfg.directories.iter_mut() {
            st_set(d, WD_CHECK_REALTIME, WD_CHECK_WHODATA | WD_IGNORE_REST);
            d.options &= !WHODATA_ACTIVE;
        }
        if !cfg.directories.is_empty() {
            cfg.realtime_change = true;
        }
    }
    let h = SUBSCRIBE.swap(0, Ordering::SeqCst);
    if h != 0 {
        // SAFETY: the subscription handle.
        unsafe { EvtClose(h) };
    }
    let mut w = wd();
    w.fd = None;
    w.directories.clear();
    w.device.clear();
    w.drive.clear();
    WHODATA_END.store(true, Ordering::SeqCst);
}

/// `policy_check`: 0 configured, 1 not, -1 error.
fn policy_check() -> i32 {
    const OBJECT_ACCESS: &str = "{6997984a-797a-11d9-bed3-505054503030}";
    const FILE_SYSTEM: &str = "{0CCE921D-69AE-11D9-BED3-505054503030}";
    const HANDLE: &str = "{0CCE9223-69AE-11D9-BED3-505054503030}";
    let g = |g: &windows_sys::core::GUID| {
        let d = g.data4;
        format!("{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}", g.data1, g.data2, g.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7])
    };
    // SAFETY: LSA/audit queries; the returned buffers are freed with their own free functions.
    unsafe {
        let err = |code: u32| {
            let m = super::win::format_message(code);
            mwarn(cfmt(msgs::FIM_WHODATA_ERROR_CHECKING_POL, &[A::S(&m), A::U(code as u64)]));
            -1
        };
        let attrs: LSA_OBJECT_ATTRIBUTES = std::mem::zeroed();
        let mut ph: LSA_HANDLE = 0;
        let s = LsaOpenPolicy(std::ptr::null(), &attrs, POLICY_VIEW_AUDIT_INFORMATION as u32, &mut ph);
        if s != 0 {
            return err(LsaNtStatusToWinError(s));
        }
        let mut ae: *mut POLICY_AUDIT_EVENTS_INFO = std::ptr::null_mut();
        let s = LsaQueryInformationPolicy(ph, PolicyAuditEventsInformation, &mut ae as *mut _ as *mut _);
        if s != 0 {
            LsaClose(ph);
            return err(LsaNtStatusToWinError(s));
        }
        let close = || {
            LsaFreeMemory(ae as _);
            LsaClose(ph);
        };
        let (mut fs, mut hm) = (false, false);
        if (*ae).AuditingMode {
            mdebug2(msgs::FIM_WHODATA_POLICY_OPENED);
            for t in 0..(*ae).MaximumAuditEventCount {
                let mut cat = std::mem::zeroed();
                if !AuditLookupCategoryGuidFromCategoryId(t as POLICY_AUDIT_EVENT_TYPE, &mut cat) {
                    let e = GetLastError();
                    close();
                    return err(e);
                }
                let s = g(&cat);
                if !s.eq_ignore_ascii_case(OBJECT_ACCESS) {
                    continue;
                }
                mdebug2(cfmt(msgs::FIM_WHODATA_OBJECT_ACCESS, &[A::S(&s)]));
                let mut subs: *mut windows_sys::core::GUID = std::ptr::null_mut();
                let mut n = 0u32;
                if !AuditEnumerateSubCategories(&cat, false, &mut subs, &mut n) {
                    let e = GetLastError();
                    close();
                    return err(e);
                }
                let mut pol: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();
                if !AuditQuerySystemPolicy(subs, n, &mut pol) {
                    let e = GetLastError();
                    close();
                    return err(e);
                }
                for i in 0..n as usize {
                    let p = &*pol.add(i);
                    let s = g(&p.AuditSubCategoryGuid);
                    if p.AuditingInformation & POLICY_AUDIT_EVENT_SUCCESS as u32 != 0 {
                        if s.eq_ignore_ascii_case(FILE_SYSTEM) {
                            fs = true;
                            mdebug2(cfmt(msgs::FIM_WHODATA_SUCCESS_POLICY, &[A::S("File System"), A::S(&s)]));
                        }
                        if s.eq_ignore_ascii_case(HANDLE) {
                            hm = true;
                            mdebug2(cfmt(msgs::FIM_WHODATA_SUCCESS_POLICY, &[A::S("Handle Manipulation"), A::S(&s)]));
                        }
                        if fs && hm {
                            close();
                            return 0;
                        }
                    }
                }
            }
        }
        close();
        1
    }
}

/// `state_checker`
fn state_checker(fim: Arc<Fim>) {
    let interval = match fim.sk.cfg.read_recursive().wdata_interval_scan {
        0 => WDATA_DEFAULT_INTERVAL_SCAN,
        i => i,
    };
    mdebug1(cfmt(msgs::FIM_WHODATA_CHECKTHREAD, &[A::I(interval as i64)]));
    while !WHODATA_END.load(Ordering::SeqCst) {
        mdebug2(msgs::FIM_WHODATA_STATE_CHECKER);
        if policy_check() == 1 {
            mwarn(msgs::FIM_WHODATA_POLICY_CHANGE_CHECKER);
            win_whodata_release_resources(&fim);
            break;
        }
        {
            let mut cfg = fim.sk.cfg.write();
            let mut changed = false;
            for d in cfg.directories.iter_mut() {
                if st(d) & WD_CHECK_WHODATA == 0 {
                    continue;
                }
                let path = d.path.clone().into_bytes();
                let ty = check_path_type(&path);
                match ty {
                    1 => d.dirs_status.object_type.store(WD_STATUS_FILE_TYPE, Ordering::SeqCst),
                    2 => d.dirs_status.object_type.store(WD_STATUS_DIR_TYPE, Ordering::SeqCst),
                    _ => {}
                }
                if ty != 0 {
                    if st(d) & WD_STATUS_EXISTS == 0 {
                        minfo(cfmt(msgs::FIM_WHODATA_READDED, &[A::S(&d.path)]));
                        if set_winsacl(&path, d) != 0 {
                            merror(cfmt(msgs::FIM_ERROR_WHODATA_ADD_DIRECTORY, &[A::S(&d.path)]));
                            st_set(d, WD_CHECK_REALTIME, WD_CHECK_WHODATA);
                            d.options &= !WHODATA_ACTIVE;
                            changed = true;
                            continue;
                        }
                        st_set(d, WD_STATUS_EXISTS, 0);
                    } else if check_object_sacl(&path, d.dirs_status.object_type.load(Ordering::SeqCst) == WD_STATUS_FILE_TYPE) == 1 {
                        minfo(cfmt(msgs::FIM_WHODATA_SACL_CHANGED, &[A::S(&d.path)]));
                        st_set(d, WD_CHECK_REALTIME, WD_CHECK_WHODATA | WD_IGNORE_REST);
                        d.options &= !WHODATA_ACTIVE;
                        changed = true;
                        notify_sacl_change(&fim, &d.path);
                        continue;
                    }
                } else {
                    mdebug2(cfmt(msgs::FIM_WHODATA_DELETE, &[A::S(&d.path)]));
                    st_set(d, 0, WD_STATUS_EXISTS);
                    d.dirs_status.object_type.store(WD_STATUS_UNK_TYPE, Ordering::SeqCst);
                }
            }
            if changed {
                cfg.realtime_change = true;
            }
        }
        // stale directory entries (scanned more than 5 seconds ago)
        let stale = filetime_now().saturating_sub(5 * FILETIME_SECOND);
        wd().directories.retain(|_, t| *t >= stale);
        std::thread::sleep(std::time::Duration::from_secs(interval as u64));
        POLICIES_CHECKED.store(true, Ordering::SeqCst);
    }
}

/// `notify_SACL_change`
fn notify_sacl_change(fim: &Fim, dir: &str) {
    let mut m = format!("ossec: Audit: The SACL of '{dir}' has been modified and can no longer be scanned in whodata mode.").into_bytes();
    m.truncate(1024);
    (fim.send)(super::create_db::LOCALFILE_MQ, super::create_db::SYSCHECK, &m);
}

/// The whodata part of `realtime_adddir`: 1, 0 or -2.
pub fn whodata_adddir(dir: &[u8], c: &Directory, _fim: &Fim) -> i32 {
    if wd().fd.is_none() {
        whodata_audit_start();
    }
    st_set(c, WD_CHECK_WHODATA, WD_CHECK_REALTIME);
    match check_path_type(dir) {
        2 => {
            c.dirs_status.object_type.store(WD_STATUS_DIR_TYPE, Ordering::SeqCst);
            st_set(c, WD_STATUS_EXISTS, 0);
        }
        1 => {
            c.dirs_status.object_type.store(WD_STATUS_FILE_TYPE, Ordering::SeqCst);
            st_set(c, WD_STATUS_EXISTS, 0);
        }
        _ => {
            mdebug2(cfmt(msgs::FIM_WARN_REALTIME_OPENFAIL, &[A::B(dir)]));
            c.dirs_status.object_type.store(WD_STATUS_UNK_TYPE, Ordering::SeqCst);
            st_set(c, 0, WD_STATUS_EXISTS);
            return 0;
        }
    }
    if set_winsacl(dir, c) != 0 {
        merror(cfmt(msgs::FIM_ERROR_WHODATA_ADD_DIRECTORY, &[A::B(dir)]));
        return -2;
    }
    1
}

/// `realtime_adddir` for any mode.
pub fn realtime_adddir(dir: &[u8], c: &mut Directory, fim: &Fim, max_fd_win_rt: u32) -> i32 {
    if fim_mode(c.options) == FIM_WHODATA {
        return whodata_adddir(dir, c, fim);
    }
    super::realtime::realtime_adddir_rt(dir, c, max_fd_win_rt)
}

/// `set_whodata_mode_changes`
pub fn set_whodata_mode_changes(fim: &Fim) {
    if !super::realtime::started() {
        super::realtime::realtime_start();
    }
    let mut cfg = fim.sk.cfg.write();
    cfg.realtime_change = false;
    let max_fd = cfg.max_fd_win_rt;
    for i in 0..cfg.directories.len() {
        let d = &mut cfg.directories[i];
        if st(d) & WD_CHECK_REALTIME == 0 {
            continue;
        }
        st_set(d, 0, WD_CHECK_REALTIME);
        d.options |= REALTIME_ACTIVE;
        let path = d.path.clone().into_bytes();
        if realtime_adddir(&path, d, fim, max_fd) != 1 {
            merror(cfmt(msgs::FIM_ERROR_REALTIME_ADDDIR_FAILED, &[A::B(&path)]));
        } else {
            mdebug1(cfmt(msgs::FIM_REALTIME_MONITORING, &[A::B(&path)]));
        }
    }
}

/// `fim_whodata_initialize`
pub fn fim_whodata_initialize(fim: &Arc<Fim>) -> i32 {
    {
        let mut cfg = fim.sk.cfg.write();
        let max_fd = cfg.max_fd_win_rt;
        let mut changed = false;
        for i in 0..cfg.directories.len() {
            let d = &mut cfg.directories[i];
            if d.options & WHODATA_ACTIVE == 0 {
                continue;
            }
            let path = d.path.clone().into_bytes();
            if realtime_adddir(&path, d, fim, max_fd) == -2 {
                st_set(d, WD_CHECK_REALTIME, WD_CHECK_WHODATA);
                d.options &= !WHODATA_ACTIVE;
                changed = true;
            }
        }
        if changed {
            cfg.realtime_change = true;
        }
        if wd().fd.is_none() && cfg.wildcards.iter().flatten().any(|w| fim_mode(w.options) == FIM_WHODATA) {
            drop(cfg);
            whodata_audit_start();
        }
    }
    if run_whodata_scan() == 0 {
        let f = fim.clone();
        if std::thread::Builder::new().name("fim_whodata_state".into()).spawn(move || state_checker(f)).is_err() {
            merror(msgs::FIM_ERROR_CHECK_THREAD);
            return -1;
        }
        0
    } else {
        merror(msgs::FIM_ERROR_WHODATA_INIT);
        audit_restore(fim);
        let mut cfg = fim.sk.cfg.write();
        for d in cfg.directories.iter_mut() {
            st_set(d, WD_CHECK_REALTIME, WD_CHECK_WHODATA);
            d.options &= !WHODATA_ACTIVE;
        }
        if !cfg.directories.is_empty() {
            cfg.realtime_change = true;
        }
        -1
    }
}

impl Fim {
    /// `fim_whodata_event`
    pub fn fim_whodata_event(&self, w_evt: &WhodataEvt) {
        let cfg = self.sk.cfg.read_recursive();
        if super::win::stat64(&w_evt.path).is_ok() {
            let mut evt = EventData { mode: FIM_WHODATA, w_evt: Some(w_evt.clone()), report_event: true, ..Default::default() };
            if cfg.rt_delay != 0 {
                std::thread::sleep(std::time::Duration::from_millis(cfg.rt_delay as u64));
            }
            self.fim_checker(&cfg, &w_evt.path, &mut evt, None, None);
        } else {
            self.fim_process_missing_entry(&cfg, &w_evt.path, FIM_WHODATA, Some(w_evt.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn query_matches_c_format() {
        let q = super::subscription_query();
        assert!(q.contains("band(Keywords, 9007199254740992)"));
        assert!(q.contains("'%%8448'or "));
        assert!(q.contains("band(Data[@Name='AccessMask'], 327942)"));
    }
}
