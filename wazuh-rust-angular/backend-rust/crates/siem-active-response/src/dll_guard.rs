//! Windows DLL guard: every module of the process, and every DLL loaded later, must carry a
//! valid Authenticode signature or be listed in a Windows security catalog. Against DLL
//! planting next to a response program. Messages go to the response log.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{GetLastError, HMODULE};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext,
};
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, DRIVER_ACTION_VERIFY, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS};
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::ProcessStatus::EnumProcessModules;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};

use crate::{argv0, write_debug_file};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    /// log a warning naming the file and go on
    Warn,
    /// log and end the program
    Strict,
}

pub const MODE: Mode = Mode::Warn;

static PROGRAM: OnceLock<String> = OnceLock::new();

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

/// Windows' code and message text for `code`, e.g. `0x800B0100 No signature was present in the subject.`
fn reason(code: u32) -> String {
    let mut buf = [0u16; 512];
    // SAFETY: the buffer and its length match; no inserts are read
    let n = unsafe {
        FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, std::ptr::null(), code, 0, buf.as_mut_ptr(), buf.len() as u32, std::ptr::null())
    } as usize;
    let text = String::from_utf16_lossy(&buf[..n.min(buf.len())]);
    let text = text.trim();
    format!("0x{code:08X} {}", if text.is_empty() { "(no message text)" } else { text })
}

/// A valid embedded Authenticode signature, else WinVerifyTrust's code.
fn signed(path: &std::path::Path) -> Result<(), u32> {
    let w = wide(path.as_os_str());
    let mut file = WINTRUST_FILE_INFO { cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32, pcwszFilePath: w.as_ptr(), ..Default::default() };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        // no network: a response must not hang on certificate downloads
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    data.Anonymous.pFile = &mut file;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` and `file` point at locals that outlive both calls
    unsafe {
        let r = WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut data as *mut _ as *mut c_void);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut data as *mut _ as *mut c_void);
        if r == 0 { Ok(()) } else { Err(r as u32) }
    }
}

/// The file's hash listed in a Windows security catalog (SHA-256, then SHA-1), else the last error code.
fn in_catalog(path: &std::path::Path) -> Result<(), u32> {
    let f = std::fs::File::open(path).map_err(|e| e.raw_os_error().unwrap_or(0) as u32)?;
    let sha256 = wide("SHA256".as_ref());
    let mut err = 0u32;
    for alg in [sha256.as_ptr(), std::ptr::null()] {
        // SAFETY: handles are released on every path; buffers are sized by the first call
        unsafe {
            let mut admin: isize = 0;
            if CryptCATAdminAcquireContext2(&mut admin, &DRIVER_ACTION_VERIFY, alg, std::ptr::null(), 0) == 0 {
                err = GetLastError();
                continue;
            }
            let mut len = 0u32;
            CryptCATAdminCalcHashFromFileHandle2(admin, f.as_raw_handle(), &mut len, std::ptr::null_mut(), 0);
            let mut hash = vec![0u8; len as usize];
            let mut found = false;
            if len > 0 && CryptCATAdminCalcHashFromFileHandle2(admin, f.as_raw_handle(), &mut len, hash.as_mut_ptr(), 0) != 0 {
                let mut prev: isize = 0;
                let cat = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), len, 0, &mut prev);
                if cat != 0 {
                    found = true;
                    CryptCATAdminReleaseCatalogContext(admin, cat, 0);
                } else {
                    err = GetLastError();
                }
            } else {
                err = GetLastError();
            }
            CryptCATAdminReleaseContext(admin, 0);
            if found {
                return Ok(());
            }
        }
    }
    Err(err)
}

/// Ok when the file passes; else why each method refused it.
pub fn verify(path: &std::path::Path) -> Result<(), String> {
    let Err(sig) = signed(path) else { return Ok(()) };
    let Err(cat) = in_catalog(path) else { return Ok(()) };
    Err(format!("signature: {}; catalog: {}", reason(sig), reason(cat)))
}

pub fn trusted(path: &std::path::Path) -> bool {
    verify(path).is_ok()
}

fn system_dll(name: &str) -> std::path::PathBuf {
    let mut buf = [0u16; 260];
    // SAFETY: the buffer and its length match
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let dir = if n > 0 && n < buf.len() { String::from_utf16_lossy(&buf[..n]) } else { r"C:\Windows\System32".into() };
    std::path::Path::new(&dir).join(name)
}

fn check(path: &std::path::Path) {
    let Err(why) = verify(path) else { return };
    let program = PROGRAM.get().map_or("dll-guard", String::as_str);
    match MODE {
        Mode::Off => {}
        Mode::Warn => write_debug_file(program, format!("Warning: unsigned DLL loaded: {} ({why})", path.display()).as_bytes()),
        Mode::Strict => {
            write_debug_file(program, format!("Unsigned DLL loaded: {} ({why}); stopping", path.display()).as_bytes());
            // SAFETY: ends this process; no loader callbacks run (we may hold the loader lock)
            unsafe { TerminateProcess(GetCurrentProcess(), u32::MAX) };
        }
    }
}

fn module_path(m: HMODULE) -> Option<std::path::PathBuf> {
    let mut buf = vec![0u16; 32768];
    // SAFETY: the buffer and its length match
    let n = unsafe { GetModuleFileNameW(m, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    (n > 0 && n < buf.len()).then(|| String::from_utf16_lossy(&buf[..n]).into())
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct DllLoadedData {
    flags: u32,
    full_dll_name: *const UnicodeString,
    base_dll_name: *const UnicodeString,
    dll_base: *mut c_void,
    size_of_image: u32,
}

type Notification = unsafe extern "system" fn(reason: u32, data: *const DllLoadedData, context: *mut c_void);
type Register = unsafe extern "system" fn(flags: u32, f: Notification, context: *mut c_void, cookie: *mut *mut c_void) -> i32;

const REASON_LOADED: u32 = 1;

thread_local! {
    /// DLLs the check itself loads (wintrust's helpers) are checked after it, not inside it.
    static BUSY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static PENDING: std::cell::RefCell<Vec<std::path::PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
}

unsafe extern "system" fn on_load(reason: u32, data: *const DllLoadedData, _context: *mut c_void) {
    if reason != REASON_LOADED || data.is_null() {
        return;
    }
    // SAFETY: the loader hands a valid notification for the duration of the call
    let name = unsafe {
        let s = (*data).full_dll_name;
        if s.is_null() || (*s).buffer.is_null() {
            return;
        }
        std::slice::from_raw_parts((*s).buffer, (*s).length as usize / 2)
    };
    let path: std::path::PathBuf = String::from_utf16_lossy(name).into();
    if BUSY.with(|b| b.replace(true)) {
        PENDING.with(|p| p.borrow_mut().push(path));
        return;
    }
    let mut next = Some(path);
    while let Some(p) = next {
        check(&p);
        next = PENDING.with(|q| q.borrow_mut().pop());
    }
    BUSY.with(|b| b.set(false));
}

/// Checks the modules loaded so far, then every DLL loaded later. Call first thing.
pub fn enable() {
    if MODE == Mode::Off {
        return;
    }
    let program = PROGRAM.get_or_init(argv0);
    // a machine that cannot verify its own system DLLs would stop every response
    if !trusted(&system_dll("kernel32.dll")) {
        write_debug_file(program, b"DLL signatures cannot be verified on this machine; DLL checks skipped");
        return;
    }
    // SAFETY: plain Win32 calls with buffers sized as passed
    unsafe {
        let me = GetModuleHandleW(std::ptr::null());
        let mut mods: Vec<HMODULE> = vec![std::ptr::null_mut(); 1024];
        let mut needed = 0u32;
        if EnumProcessModules(GetCurrentProcess(), mods.as_mut_ptr(), (mods.len() * size_of::<HMODULE>()) as u32, &mut needed) != 0 {
            mods.truncate((needed as usize / size_of::<HMODULE>()).min(mods.len()));
            // the program itself is not a DLL: only what it loads is checked
            for m in mods.into_iter().filter(|m| *m != me) {
                if let Some(p) = module_path(m) {
                    check(&p);
                }
            }
        }
        let ntdll = wide("ntdll.dll".as_ref());
        let Some(f) = GetProcAddress(GetModuleHandleW(ntdll.as_ptr()), c"LdrRegisterDllNotification".as_ptr().cast()) else {
            write_debug_file(program, b"DLL load notifications unavailable; later DLLs not checked");
            return;
        };
        let register: Register = std::mem::transmute::<unsafe extern "system" fn() -> isize, Register>(f);
        let mut cookie = std::ptr::null_mut();
        if register(0, on_load, std::ptr::null_mut(), &mut cookie) != 0 {
            write_debug_file(program, b"DLL load notifications could not be registered; later DLLs not checked");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_dlls_pass_and_unsigned_files_do_not() {
        assert!(trusted(&system_dll("kernel32.dll")), "kernel32.dll is catalog-signed");
        let f = std::env::temp_dir().join(format!("dll-guard-test-{}.dll", std::process::id()));
        std::fs::write(&f, b"MZ not really a dll").unwrap();
        let why = verify(&f).unwrap_err();
        // both methods give Windows' code and text (not a PE: 0x800B0003; no catalog entry: ERROR_NOT_FOUND)
        assert!(why.starts_with("signature: 0x800B") && why.contains("; catalog: 0x00000490 "), "{why}");
        assert!(!why.contains("(no message text)"), "{why}");
        let _ = std::fs::remove_file(&f);
    }
}
