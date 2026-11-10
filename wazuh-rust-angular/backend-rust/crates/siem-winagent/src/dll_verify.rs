//! `shared/dll_load_notify.c` (`enable_dll_verification`) and
//! `shared/cryptography.c`: the signature checks of the modules loaded into
//! `wazuh-agent.exe`. Every module already loaded, and every DLL loaded
//! later (`LdrRegisterDllNotification`), must have a valid Authenticode
//! signature or a catalog hash; otherwise a warning (`IMAGE_TRUST_CHECKS=1`,
//! the default) or an exit (`IMAGE_TRUST_CHECKS=2`). The checks only run
//! when the `CA_NAME` root certificate is in the ROOT store.
//!
//! Build-time settings, as the C Makefile variables:
//! `IMAGE_TRUST_CHECKS` (0, 1, 2; default 1) and `CA_NAME`
//! (default "DigiCert Assured ID Root CA"). All messages use the `plain_*`
//! log functions.

use std::ffi::c_void;
use std::sync::{Arc, OnceLock};

use siem_log::WLog;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext, CryptCATAdminCalcHashFromFileHandle, CryptCATAdminEnumCatalogFromHash,
    CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext,
};
use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertGetNameStringA, CertOpenSystemStoreA, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFullPathNameW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleFileNameExW};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// `IMAGE_TRUST_CHECKS`
pub const IMAGE_TRUST_CHECKS: u32 = match option_env!("IMAGE_TRUST_CHECKS") {
    Some(v) if v.len() == 1 && v.as_bytes()[0] == b'0' => 0,
    Some(v) if v.len() == 1 && v.as_bytes()[0] == b'2' => 2,
    _ => 1,
};
/// `CA_NAME`
pub const CA_NAME: &str = match option_env!("CA_NAME") {
    Some(n) => n,
    None => "DigiCert Assured ID Root CA",
};

const GENERIC_READ: u32 = 0x8000_0000;
const MAX_PATH: usize = 260;
const OS_SIZE_1024: usize = 1024;
const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_DATA: u32 = 13;
const ERROR_FILE_NOT_FOUND: u32 = 2;

/// `WINTRUST_ACTION_GENERIC_VERIFY_V2`
const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID = GUID {
    data1: 0x00AAC56B,
    data2: 0xCD44,
    data3: 0x11d0,
    data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};
/// `DRIVER_ACTION_VERIFY`
const DRIVER_ACTION_VERIFY: GUID = GUID {
    data1: 0xF750E6C3,
    data2: 0x38EE,
    data3: 0x11d1,
    data4: [0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

static LOG: OnceLock<Arc<WLog>> = OnceLock::new();

fn log() -> Option<&'static Arc<WLog>> {
    LOG.get()
}

fn plain(level: &str, msg: String) {
    if let Some(l) = log() {
        l.plain(level, msg);
    }
}

/// `plain_merror_exit`
fn plain_exit(msg: String) -> ! {
    plain("CRITICAL", msg);
    siem_log::cexit::fatal_exit()
}

/// `%S` of a wide string.
fn ws(w: &[u16]) -> String {
    let n = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..n])
}

fn win_strerror(e: u32) -> String {
    siem_ipc::os_net::win_strerror(e)
}

/// `snprintf(buf, OS_SIZE_1024, ...)`
fn cap(mut s: String) -> String {
    if s.len() > OS_SIZE_1024 - 1 {
        let mut n = OS_SIZE_1024 - 1;
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        s.truncate(n);
    }
    s
}

fn full_path(path: &[u16]) -> Result<Vec<u16>, u32> {
    let mut full = vec![0u16; MAX_PATH];
    // SAFETY: NUL-terminated input, MAX_PATH output.
    let n = unsafe { GetFullPathNameW(path.as_ptr(), MAX_PATH as u32, full.as_mut_ptr(), std::ptr::null_mut()) };
    if n == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(full)
}

/// `verify_pe_signature`
fn verify_pe_signature(path: &[u16], msg: &mut String) -> u32 {
    let full = match full_path(path) {
        Ok(f) => f,
        Err(e) => {
            *msg = cap(format!("GetFullPathNameW failed with error {e} for '{}': {}", ws(path), win_strerror(e)));
            return ERROR_INVALID_DATA;
        }
    };
    let fp = ws(&full);
    // SAFETY: WINTRUST structures filled as in C, closed below.
    unsafe {
        let mut file_info: WINTRUST_FILE_INFO = std::mem::zeroed();
        file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = full.as_ptr();
        let mut data: WINTRUST_DATA = std::mem::zeroed();
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        data.Anonymous.pFile = &mut file_info;
        let mut guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let mut status = WinVerifyTrust(INVALID_HANDLE_VALUE as _, &mut guid, (&mut data as *mut WINTRUST_DATA).cast()) as u32;
        let m = match status {
            0 => format!("PE signature verification succeeded for {fp}"),
            0x800B0100 => {
                // TRUST_E_NOSIGNATURE
                let le = GetLastError();
                if le == 0x800B0100 || le == 0x800B0003 || le == 0x800B0001 {
                    format!("No signature found for '{fp}'.")
                } else {
                    format!("An unknown error occurred trying to verify the signature of the \"{fp}\" file.")
                }
            }
            0x800B0003 => format!("The form of file '{fp}' is not supported by trust provider."),
            0x800B0002 => format!("Provider doesn't support verify action for file '{fp}'."),
            0x800B0001 => format!("No trusted provider found for file '{fp}'."),
            0x800B0111 => format!("The signature is present, but specifically disallowed for file '{fp}'."),
            0x800B0004 => format!("The signature is present, but not trusted by the user for file '{fp}'."),
            0x800B010B => format!("The signature of file '{fp}' is invalid or not found."),
            0x80096010 => format!("The file '{fp}' or its signature is corrupt."),
            0x800B0101 => format!("The signature of file '{fp}' is expired."),
            0x800B010C => format!("The signature of file '{fp}' was revoked."),
            0x80092010 => format!("The certificate or signature of file '{fp}' has been revoked."),
            0x800B0109 => format!("The signature of file '{fp}' terminated in a root certificate that is not trusted."),
            0x80092026 => {
                format!("The hash representing the subject or the publisher wasn't explicitly trusted for file '{fp}'.")
            }
            0x80096001 => format!("A system-level error occurred while verifying trust for file '{fp}'."),
            0x80096002 => format!("The certificate for the signer of file '{fp}' is invalid or not found."),
            0x80096003 => format!("One of the counter signatures was not valid for file '{fp}'."),
            0x80096004 => format!("The signature of the certificate can not be verified for file '{fp}'."),
            0x80096005 => {
                format!("The timestamp signature or certificate could not be verified or is malformed for file '{fp}'.")
            }
            0x80096019 => format!("The basic constraints of the certificate for file '{fp}' are invalid or missing."),
            0x8009601E => {
                format!("The certificate for file '{fp}' does not meet or contain the Authenticode financial extensions.")
            }
            0x800B010A => format!("The certificate chain to a trusted root authority could not be built for file '{fp}'."),
            0x800B010D => format!(
                "The root certificate for file '{fp}' is a testing certificate, and policy settings disallow test certificates."
            ),
            0x800B0110 => format!("The certificate for file '{fp}' is not valid for the requested usage."),
            0x800B0114 => format!(
                "The certificate name for file '{fp}' is invalid. Either the name is not included in the permitted list, or it is explicitly excluded."
            ),
            0x800B0113 => format!("The certificate policy for file '{fp}' is invalid."),
            0x800B0105 | 0x800B0106 => format!(
                "The certificate for file '{fp}' is being used for a purpose other than the purpose specified by its CA."
            ),
            0x800B0102 => format!("The validity periods of the certification chain do not nest correctly for file '{fp}'."),
            0x80092012 => {
                format!("The revocation function was unable to check revocation for the certificate of file '{fp}'.")
            }
            0x80092013 => format!(
                "It was not possible to check revocation because the revocation server was offline for file '{fp}'."
            ),
            0x800B010E => format!(
                "The revocation process could not continue, and the certificate could not be checked for file '{fp}'."
            ),
            0x800B010F => format!("The certificate's CN name does not match the passed value for file '{fp}'."),
            0x800B0103 => format!(
                "A certificate for file '{fp}' that can only be used as an end-entity is being used as a CA or vice versa."
            ),
            other => {
                let le = GetLastError();
                status = ERROR_INVALID_DATA;
                format!(
                    "WinVerifyTrust returned '{other:X}' for '{fp}'. GetLastError returned '{le:X}'. {}",
                    win_strerror(le)
                )
            }
        };
        *msg = cap(m);
        // Any hWVTStateData must be released by a call with close.
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(INVALID_HANDLE_VALUE as _, &mut guid, (&mut data as *mut WINTRUST_DATA).cast());
        status
    }
}

/// `get_file_hash`
fn get_file_hash(path: &[u16], msg: &mut String) -> Result<Vec<u8>, u32> {
    let full = match full_path(path) {
        Ok(f) => f,
        Err(e) => {
            *msg = cap(format!("GetFullPathNameW failed with error {e} for '{}'. {}", ws(path), win_strerror(e)));
            return Err(ERROR_INVALID_DATA);
        }
    };
    let fp = ws(&full);
    // SAFETY: a file handle we open and close; hash buffers sized as reported.
    unsafe {
        let h: HANDLE = CreateFileW(
            full.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );
        let r = if h == INVALID_HANDLE_VALUE {
            let le = GetLastError();
            *msg = cap(format!("CreateFileW failed with error {le} for '{fp}': {}", win_strerror(le)));
            Err(ERROR_FILE_NOT_FOUND)
        } else {
            let mut size = 0u32;
            if CryptCATAdminCalcHashFromFileHandle(h, &mut size, std::ptr::null_mut(), 0) != 0 {
                if size == 0 {
                    let le = GetLastError();
                    *msg = cap(format!(
                        "CryptCATAdminCalcHashFromFileHandle failed because hash size is zero with error {le} for '{fp}': {}",
                        win_strerror(le)
                    ));
                    Err(ERROR_INVALID_DATA)
                } else {
                    let mut hash = vec![0u8; size as usize];
                    if CryptCATAdminCalcHashFromFileHandle(h, &mut size, hash.as_mut_ptr(), 0) == 0 {
                        let e = GetLastError();
                        *msg = cap(format!(
                            "CryptCATAdminCalcHashFromFileHandle failed trying to calculate hash with error {e} for '{fp}': {}",
                            win_strerror(e)
                        ));
                        Err(e)
                    } else {
                        hash.truncate(size as usize);
                        Ok(hash)
                    }
                }
            } else {
                let e = GetLastError();
                *msg = cap(format!(
                    "CryptCATAdminCalcHashFromFileHandle failed trying to get the hash size with error {e} for '{fp}': {}",
                    win_strerror(e)
                ));
                Err(e)
            }
        };
        CloseHandle(h);
        r
    }
}

/// `verify_hash_catalog`
fn verify_hash_catalog(path: &[u16], msg: &mut String) -> u32 {
    let hash = match get_file_hash(path, msg) {
        Ok(h) => h,
        Err(e) => return e,
    };
    let fp = ws(path);
    // SAFETY: catalog admin context acquired and released here.
    unsafe {
        let mut admin: isize = 0;
        let guid = DRIVER_ACTION_VERIFY;
        if CryptCATAdminAcquireContext(&mut admin, &guid, 0) == 0 {
            let e = GetLastError();
            *msg = cap(format!("CryptCATAdminAcquireContext failed with error {e} for '{fp}': {}", win_strerror(e)));
            return e;
        }
        let ctx = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), hash.len() as u32, 0, std::ptr::null_mut());
        let r = if ctx != 0 {
            CryptCATAdminReleaseCatalogContext(admin, ctx, 0);
            *msg = cap(format!("Hash verification succeeded for '{fp}'"));
            ERROR_SUCCESS
        } else {
            let e = GetLastError();
            *msg = cap(format!("CryptCATAdminEnumCatalogFromHash failed with error {e} for '{fp}': {}", win_strerror(e)));
            e
        };
        CryptCATAdminReleaseContext(admin, 0);
        r
    }
}

/// `verify_hash_and_pe_signature`: true when the file is trusted.
fn verify_hash_and_pe_signature(path: &[u16]) -> bool {
    let mut pe_msg = String::new();
    if verify_pe_signature(path, &mut pe_msg) == ERROR_SUCCESS {
        plain("DEBUG", pe_msg);
        return true;
    }
    let mut hash_msg = String::new();
    if verify_hash_catalog(path, &mut hash_msg) == ERROR_SUCCESS {
        plain("DEBUG", hash_msg);
        return true;
    }
    plain("INFO", format!("Trust verification of a module failed by using the signature method. {pe_msg}"));
    plain("INFO", format!("Trust verification of a module failed by using the hash method. {hash_msg}"));
    false
}

/// `check_ca_available`: ERROR_SUCCESS when `CA_NAME` is in the ROOT store.
fn check_ca_available() -> u32 {
    let mut result = ERROR_INVALID_DATA;
    // SAFETY: store and certificate contexts used as the API requires.
    unsafe {
        let store = CertOpenSystemStoreA(0, c"ROOT".as_ptr().cast());
        if store.is_null() {
            let e = GetLastError();
            plain("ERROR", format!("CertOpenSystemStore failed with error {e}: {}", win_strerror(e)));
            return e;
        }
        let mut cert = CertEnumCertificatesInStore(store, std::ptr::null());
        while !cert.is_null() {
            let req = CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, std::ptr::null(), std::ptr::null_mut(), 0);
            let mut name = vec![0u8; req as usize];
            if CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, std::ptr::null(), name.as_mut_ptr(), req) != 0 {
                // strncmp(ca_name, CA_NAME, sizeof(CA_NAME) - 1)
                if name.starts_with(CA_NAME.as_bytes()) {
                    result = ERROR_SUCCESS;
                    // CertEnumCertificatesInStore frees the context on the
                    // next call only; C leaves it to CertCloseStore
                    break;
                }
            }
            cert = CertEnumCertificatesInStore(store, cert);
        }
        if CertCloseStore(store, 0) == 0 {
            let e = GetLastError();
            plain("ERROR", format!("CertCloseStore failed with error {e}: {}", win_strerror(e)));
        }
    }
    result
}

/// The message of an untrusted module.
fn not_trusted(name: &str) -> String {
    format!("The file '{name}' is not signed or its signature is invalid.")
}

/// `loaded_modules_verification`
fn loaded_modules_verification() {
    // SAFETY: module handles of our own process.
    unsafe {
        let process = GetCurrentProcess();
        let mut modules: Vec<HMODULE> = vec![std::ptr::null_mut(); OS_SIZE_1024];
        let mut needed = 0u32;
        let size = (modules.len() * std::mem::size_of::<HMODULE>()) as u32;
        if EnumProcessModules(process, modules.as_mut_ptr(), size, &mut needed) == 0 {
            let m = format!(
                "The mechanism of signature validation for loaded modules at startup failed because the modules of the process couldn't be enumerated. Error: {}",
                GetLastError()
            );
            if IMAGE_TRUST_CHECKS == 2 {
                plain_exit(m);
            }
            plain("WARNING", m);
            return;
        }
        let n = (needed as usize / std::mem::size_of::<HMODULE>()).min(modules.len());
        for &m in &modules[..n] {
            let mut name = vec![0u16; MAX_PATH];
            if GetModuleFileNameExW(process, m, name.as_mut_ptr(), MAX_PATH as u32) != 0 {
                if !verify_hash_and_pe_signature(&name) {
                    let msg = not_trusted(&ws(&name));
                    if IMAGE_TRUST_CHECKS == 2 {
                        plain_exit(msg);
                    }
                    plain("WARNING", msg);
                } else {
                    plain("DEBUG", format!("The file '{}' is signed and its signature is valid.", ws(&name)));
                }
            }
        }
    }
}

/// `UNICODE_STRING`
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

/// `LDR_DLL_LOADED_NOTIFICATION_DATA` (same layout as the unloaded one)
#[repr(C)]
struct LdrDllNotificationData {
    flags: u32,
    full_dll_name: *const UnicodeString,
    base_dll_name: *const UnicodeString,
    dll_base: *mut c_void,
    size_of_image: u32,
}

const LDR_DLL_NOTIFICATION_REASON_LOADED: u32 = 1;
const LDR_DLL_NOTIFICATION_REASON_UNLOADED: u32 = 2;

type LdrRegisterDllNotification = unsafe extern "system" fn(
    flags: u32,
    callback: unsafe extern "system" fn(u32, *const LdrDllNotificationData, *mut c_void),
    context: *mut c_void,
    cookie: *mut *mut c_void,
) -> i32;

fn unicode(s: *const UnicodeString) -> Vec<u16> {
    // SAFETY: the loader's UNICODE_STRING (Length is in bytes).
    unsafe {
        if s.is_null() || (*s).buffer.is_null() {
            return vec![0];
        }
        let mut v = std::slice::from_raw_parts((*s).buffer, (*s).length as usize / 2).to_vec();
        v.push(0);
        v
    }
}

/// `dll_notification`
unsafe extern "system" fn dll_notification(reason: u32, data: *const LdrDllNotificationData, _ctx: *mut c_void) {
    if data.is_null() {
        return;
    }
    let name = unicode((*data).full_dll_name);
    match reason {
        LDR_DLL_NOTIFICATION_REASON_LOADED => {
            if IMAGE_TRUST_CHECKS != 0 {
                if !verify_hash_and_pe_signature(&name) {
                    let m = not_trusted(&ws(&name));
                    if IMAGE_TRUST_CHECKS == 2 {
                        plain_exit(m);
                    }
                    plain("WARNING", m);
                } else {
                    plain("DEBUG", format!("The file '{}' is signed and its signature is valid.", ws(&name)));
                }
            }
        }
        LDR_DLL_NOTIFICATION_REASON_UNLOADED => plain("DEBUG", format!("Unloaded: '{}'", ws(&name))),
        _ => {}
    }
}

/// `enable_dll_verification`: must be the first thing `local_start` does.
pub fn enable_dll_verification(log: &Arc<WLog>) {
    let _ = LOG.set(Arc::clone(log));
    if IMAGE_TRUST_CHECKS == 0 {
        return;
    }
    if check_ca_available() != ERROR_SUCCESS {
        let m = format!("The dynamic signature validation is not available because the CA name('{CA_NAME}') is not available.");
        if IMAGE_TRUST_CHECKS == 2 {
            plain_exit(m);
        }
        plain("WARNING", m);
        return;
    }
    loaded_modules_verification();
    // Register for DLL load notifications
    // SAFETY: ntdll is always loaded; the callback lives for the process.
    unsafe {
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        if ntdll.is_null() {
            let e = GetLastError();
            let m = format!(
                "The mechanism of dynamic signature validation for loaded modules wasn't initiated because it wasn't possible to get the handle of 'ntdll.dll'. Error {e}: {}",
                win_strerror(e)
            );
            if IMAGE_TRUST_CHECKS == 2 {
                plain_exit(m);
            }
            plain("WARNING", m);
            return;
        }
        match GetProcAddress(ntdll, c"LdrRegisterDllNotification".as_ptr().cast()) {
            Some(f) => {
                let register: LdrRegisterDllNotification = std::mem::transmute(f);
                static mut COOKIE: *mut c_void = std::ptr::null_mut();
                register(0, dll_notification, std::ptr::null_mut(), std::ptr::addr_of_mut!(COOKIE));
            }
            None => {
                let e = GetLastError();
                let m = format!(
                    "The dynamic signature validation is not available for this system. Error {e}: {}",
                    win_strerror(e)
                );
                if IMAGE_TRUST_CHECKS == 2 {
                    plain_exit(m);
                }
                plain("WARNING", m);
            }
        }
    }
}
