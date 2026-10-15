//! The Windows helpers the file scan uses (`shared/utf8_winapi_wrapper.c`,
//! `shared/syscheck_op.c`, `shared/file_op.c`): paths are byte strings that
//! are UTF-8 when valid, else ANSI (`auto_to_wide`).

use siem_cjson::Json;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_NONE_MAPPED, ERROR_SHARING_VIOLATION, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidA, GetSecurityInfo, SE_FILE_OBJECT, SE_OBJECT_TYPE};
use windows_sys::Win32::Security::{
    GetAce, GetAclInformation, GetFileSecurityW, GetSecurityDescriptorDacl, IsValidSid, LookupAccountSidA, AclSizeInformation, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, GetFileAttributesW, GetFileTime, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, INVALID_FILE_ATTRIBUTES, OPEN_EXISTING};
use windows_sys::Win32::System::Diagnostics::Debug::{FormatMessageA, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS};

use super::cfmt::{cfmt, A};
use super::{mdebug1, mdebug2, msgs, mwarn};

const GENERIC_READ: u32 = 0x8000_0000;
const BUFFER_LEN: usize = 1024;
/// `EPOCH_DIFFERENCE`
const EPOCH_DIFFERENCE: i64 = 11644473600;

/// `w_utf8_valid`
pub fn utf8_valid(b: &[u8]) -> bool {
    std::str::from_utf8(b).is_ok()
}

/// `auto_to_wide` (NUL-terminated), None when the conversion fails.
pub fn auto_to_wide(b: &[u8]) -> Option<Vec<u16>> {
    let mut w = if utf8_valid(b) {
        String::from_utf8_lossy(b).encode_utf16().collect::<Vec<u16>>()
    } else {
        siem_sysinfo::win::enc::ansi_to_wstring(b)
    };
    w.push(0);
    Some(w)
}

/// `auto_to_utf8`
pub fn auto_to_utf8(b: &[u8]) -> Vec<u8> {
    if utf8_valid(b) {
        b.to_vec()
    } else {
        siem_sysinfo::win::enc::ansi_to_utf8(b)
    }
}

/// `auto_to_ansi`
pub fn auto_to_ansi(b: &[u8]) -> Vec<u8> {
    if utf8_valid(b) {
        siem_sysinfo::win::enc::utf8_to_ansi(b)
    } else {
        b.to_vec()
    }
}

/// `_wstat64` fields the scan reads.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stat {
    pub mode: u32,
    pub size: i64,
    pub dev: u32,
    pub ino: u16,
}

extern "C" {
    fn _wstat64(path: *const u16, buf: *mut [u8; 56]) -> i32;
    fn _errno() -> *mut i32;
}

/// `w_stat64` (`utf8_stat64`): the stat, or the errno. Network paths are refused (EACCES).
pub fn stat64(path: &[u8]) -> Result<Stat, i32> {
    let p = String::from_utf8_lossy(path);
    if siem_fileop::crt::is_network_path(&p) {
        mwarn(siem_fileop::crt::network_path_executed(&p));
        return Err(13);
    }
    let Some(w) = auto_to_wide(path) else { return Err(12) };
    // struct _stat64: dev(u32) ino(u16) mode(u16) nlink uid gid(i16 x3) rdev(u32) size(i64) times(i64 x3)
    let mut buf = [0u8; 56];
    // SAFETY: a NUL-terminated wide path and a buffer of sizeof(struct _stat64).
    let r = unsafe { _wstat64(w.as_ptr(), &mut buf) };
    if r != 0 {
        // SAFETY: the CRT's per-thread errno.
        return Err(unsafe { *_errno() });
    }
    let u16_at = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]);
    Ok(Stat {
        dev: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        ino: u16_at(4),
        mode: u16_at(6) as u32,
        size: i64::from_le_bytes(buf[24..32].try_into().unwrap_or_default()),
    })
}

/// `get_windows_file_time_epoch`
pub fn file_time_epoch(ft: FILETIME) -> i64 {
    let q = ((ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64) as i64;
    q / 10000000 - EPOCH_DIFFERENCE
}

fn create_file(path: &[u8], share: u32) -> HANDLE {
    let p = String::from_utf8_lossy(path);
    if siem_fileop::crt::is_network_path(&p) {
        mwarn(siem_fileop::crt::network_path_executed(&p));
        return INVALID_HANDLE_VALUE;
    }
    let Some(w) = auto_to_wide(path) else { return INVALID_HANDLE_VALUE };
    // SAFETY: a NUL-terminated wide path.
    unsafe { CreateFileW(w.as_ptr(), GENERIC_READ, share, std::ptr::null(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, std::ptr::null_mut()) }
}

/// `get_UTC_modification_time`
pub fn get_utc_modification_time(path: &[u8]) -> i64 {
    let h = create_file(path, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE);
    let ps = String::from_utf8_lossy(path);
    if h == INVALID_HANDLE_VALUE {
        // SAFETY: plain Win32 call.
        mdebug2(cfmt(msgs::FIM_WARN_OPEN_HANDLE_FILE, &[A::S(&ps), A::U(unsafe { GetLastError() } as u64)]));
        return 0;
    }
    let mut ft = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    // SAFETY: an open handle.
    unsafe {
        if GetFileTime(h, std::ptr::null_mut(), std::ptr::null_mut(), &mut ft) == 0 {
            let e = GetLastError();
            CloseHandle(h);
            mdebug2(cfmt(msgs::FIM_WARN_GET_FILETIME, &[A::S(&ps), A::U(e as u64)]));
            return 0;
        }
        CloseHandle(h);
    }
    file_time_epoch(ft)
}

/// `w_get_file_attrs`
pub fn get_file_attrs(path: &[u8]) -> u32 {
    let attrs = match auto_to_wide(path) {
        // SAFETY: a NUL-terminated wide path.
        Some(w) => unsafe { GetFileAttributesW(w.as_ptr()) },
        None => INVALID_FILE_ATTRIBUTES,
    };
    if attrs == INVALID_FILE_ATTRIBUTES {
        // SAFETY: plain Win32 call.
        let e = unsafe { GetLastError() };
        mdebug2(cfmt("The attributes for '%s' could not be obtained. Error '%d'.", &[A::B(path), A::I(e as i64)]));
        return 0;
    }
    attrs
}

/// `decode_win_attributes` (the result is cut to 255 bytes like the OS_SIZE_256 buffer)
pub fn decode_win_attributes(attrs: u32) -> String {
    const NAMES: [(u32, &str); 19] = [
        (0x20, "ARCHIVE, "),
        (0x800, "COMPRESSED, "),
        (0x40, "DEVICE, "),
        (0x10, "DIRECTORY, "),
        (0x4000, "ENCRYPTED, "),
        (0x2, "HIDDEN, "),
        (0x8000, "INTEGRITY_STREAM, "),
        (0x80, "NORMAL, "),
        (0x2000, "NOT_CONTENT_INDEXED, "),
        (0x20000, "NO_SCRUB_DATA, "),
        (0x1000, "OFFLINE, "),
        (0x1, "READONLY, "),
        (0x400000, "RECALL_ON_DATA_ACCESS, "),
        (0x40000, "RECALL_ON_OPEN, "),
        (0x400, "REPARSE_POINT, "),
        (0x200, "SPARSE_FILE, "),
        (0x4, "SYSTEM, "),
        (0x100, "TEMPORARY, "),
        (0x10000, "VIRTUAL, "),
    ];
    let mut s: String = NAMES.iter().filter(|(b, _)| attrs & b != 0).map(|(_, n)| *n).collect();
    let size = s.len();
    s.truncate(255);
    if size > 2 && size - 2 <= s.len() {
        s.truncate(size - 2);
    }
    s
}

/// `FormatMessage(ALLOCATE_BUFFER | FROM_SYSTEM | IGNORE_INSERTS)` cut at the first '\r'.
pub(super) fn format_message(err: u32) -> String {
    let mut buf: *mut u8 = std::ptr::null_mut();
    // SAFETY: the system allocates the buffer; LocalFree releases it.
    unsafe {
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            std::ptr::null(),
            err,
            0,
            &mut buf as *mut *mut u8 as *mut u8,
            0,
            std::ptr::null(),
        );
        if buf.is_null() {
            return String::new();
        }
        let s = std::ffi::CStr::from_ptr(buf as *const std::ffi::c_char).to_bytes();
        let s = &s[..s.iter().position(|&c| c == b'\r').unwrap_or(s.len())];
        let out = String::from_utf8_lossy(s).into_owned();
        LocalFree(buf as _);
        out
    }
}

/// `ConvertSidToStringSid`
unsafe fn sid_string(sid: PSID) -> Option<String> {
    let mut s: *mut u8 = std::ptr::null_mut();
    if ConvertSidToStringSidA(sid, &mut s) == 0 {
        return None;
    }
    let out = std::ffi::CStr::from_ptr(s as *const std::ffi::c_char).to_string_lossy().into_owned();
    LocalFree(s as _);
    Some(out)
}

/// `get_user(path, &sid, hndl, object_type)`: (escaped account name, SID string).
pub fn get_user(path: &str, hndl: HANDLE, object_type: SE_OBJECT_TYPE) -> (String, String) {
    if hndl == INVALID_HANDLE_VALUE {
        return (String::new(), String::new());
    }
    // SAFETY: Win32 security calls on an open handle; pSD is freed with LocalFree.
    unsafe {
        let mut owner: PSID = std::ptr::null_mut();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let rc = GetSecurityInfo(hndl, object_type, OWNER_SECURITY_INFORMATION, &mut owner, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut psd);
        let sid = match sid_string(owner) {
            Some(s) => s,
            None => {
                mdebug1("The user's SID could not be extracted.");
                String::new()
            }
        };
        let mut name = String::new();
        if rc != 0 {
            mdebug1(format!("GetSecurityInfo error code = ({rc}), '{}'", siem_ipc::os_net::win_strerror(rc)));
        } else {
            let mut acct = [0u8; BUFFER_LEN];
            let mut dom = [0u8; BUFFER_LEN];
            let (mut na, mut nd) = (BUFFER_LEN as u32, BUFFER_LEN as u32);
            let mut use_: SID_NAME_USE = 0;
            if LookupAccountSidA(std::ptr::null(), owner, acct.as_mut_ptr(), &mut na, dom.as_mut_ptr(), &mut nd, &mut use_) == 0 {
                let e = GetLastError();
                if e == ERROR_NONE_MAPPED {
                    mdebug1(format!("Account owner not found for '{path}'"));
                } else {
                    mwarn(cfmt(msgs::FIM_REGISTRY_ACC_SID, &[A::S("user"), A::U(e as u64), A::S(&format_message(e))]));
                }
            } else {
                let end = acct.iter().position(|&c| c == 0).unwrap_or(0);
                name = String::from_utf8_lossy(&acct[..end]).into_owned();
            }
        }
        if !psd.is_null() {
            LocalFree(psd as _);
        }
        (name.replace(' ', "\\ "), sid)
    }
}

/// `get_file_user(path, &sid)`: (user name, SID).
pub fn get_file_user(path: &[u8]) -> (String, String) {
    let h = create_file(path, FILE_SHARE_READ | FILE_SHARE_WRITE);
    let ps = String::from_utf8_lossy(path).into_owned();
    if h == INVALID_HANDLE_VALUE {
        // SAFETY: plain Win32 call.
        let e = unsafe { GetLastError() };
        let m = format!("At get_user({ps}): wCreateFile(): {} ({e})", format_message(e));
        if e == ERROR_ACCESS_DENIED || e == ERROR_SHARING_VIOLATION {
            mdebug1(m);
        } else {
            mwarn(m);
        }
    }
    let r = get_user(&ps, h, SE_FILE_OBJECT);
    if h != INVALID_HANDLE_VALUE {
        // SAFETY: opened above.
        unsafe { CloseHandle(h) };
    }
    r
}

/// `w_get_account_info`: (name, error) — the name is None when the first lookup fails.
unsafe fn account_name(sid: PSID) -> (Option<String>, u32) {
    let (mut na, mut nd) = (0u32, 0u32);
    let mut use_: SID_NAME_USE = 0;
    if LookupAccountSidA(std::ptr::null(), sid, std::ptr::null_mut(), &mut na, std::ptr::null_mut(), &mut nd, &mut use_) == 0 {
        let e = GetLastError();
        if e != ERROR_INSUFFICIENT_BUFFER {
            return (None, GetLastError());
        }
    }
    let mut name = vec![0u8; na.max(1) as usize];
    let mut dom = vec![0u8; nd.max(1) as usize];
    let ok = LookupAccountSidA(std::ptr::null(), sid, name.as_mut_ptr(), &mut na, dom.as_mut_ptr(), &mut nd, &mut use_);
    let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let n = Some(String::from_utf8_lossy(&name[..end]).into_owned());
    if ok == 0 {
        return (n, GetLastError());
    }
    (n, 0)
}

/// `add_ace_to_json`
fn add_ace_to_json(acl: &mut Json, sid: &str, name: Option<&str>, ace_type: &str, mask: i32) {
    if acl.get(sid).is_none() {
        let mut ace = Json::object();
        if let Some(n) = name {
            ace.add("name", Json::string(n));
        }
        acl.add(sid, ace);
    }
    let Some(ace) = acl.get_mut(sid) else { return };
    match ace.get_mut(ace_type) {
        Some(Json::Number { int, .. }) => {
            let v = *int | mask;
            *ace.get_mut(ace_type).expect("present") = Json::number(v as f64);
        }
        _ => {
            ace.add(ace_type, Json::number(mask as f64));
        }
    }
}

/// `get_win_permissions`: the ACL as JSON, or the error code.
unsafe fn get_win_permissions(sd: PSECURITY_DESCRIPTOR) -> Result<Json, i32> {
    let mut acl = Json::object();
    let (mut present, mut defaulted) = (0i32, 0i32);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
        let e = GetLastError();
        mdebug2(format!("GetSecurityDescriptorDacl failed. GetLastError returned: {e}"));
        return Err(e as i32);
    }
    if present == 0 || dacl.is_null() {
        mdebug2("No DACL was found (all access is denied), or a NULL DACL (unrestricted access) was found.");
        return Err(-2);
    }
    let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
    if GetAclInformation(dacl, &mut info as *mut _ as *mut _, std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32, AclSizeInformation) == 0 {
        let e = GetLastError();
        mdebug2(format!("GetAclInformation failed. GetLastError returned: {e}"));
        return Err(e as i32);
    }
    for i in 0..info.AceCount {
        let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
        if GetAce(dacl, i, &mut ace) == 0 {
            mdebug2(format!("GetAce failed. GetLastError returned: {}", GetLastError()));
            continue;
        }
        if process_ace_info(ace, &mut acl) {
            mdebug1(format!("ACE number {i} could not be processed."));
        }
    }
    Ok(acl)
}

/// `process_ace_info`: true on failure.
unsafe fn process_ace_info(ace: *mut std::ffi::c_void, acl: &mut Json) -> bool {
    let header = &*(ace as *const ACE_HEADER);
    let a = &*(ace as *const ACCESS_ALLOWED_ACE);
    let ace_type = match header.AceType {
        0 => "allowed",
        1 => "denied",
        _ => {
            mdebug2("Invalid ACE type.");
            return true;
        }
    };
    let sid = &a.SidStart as *const u32 as PSID;
    if IsValidSid(sid) == 0 {
        mdebug2("Invalid SID found in ACE.");
        return true;
    }
    let (name, err) = account_name(sid);
    if err != 0 {
        mdebug2(format!("No information could be extracted from the account linked to the SID. Error: {}.", err as i32));
    }
    let Some(sid_str) = sid_string(sid) else {
        mdebug2("Could not extract the SID.");
        return true;
    };
    add_ace_to_json(acl, &sid_str, name.as_deref(), ace_type, a.Mask as i32);
    false
}

/// `w_get_file_permissions`: the ACL JSON (masks as numbers), or the error.
pub fn get_file_permissions(path: &[u8]) -> Result<Json, i32> {
    let Some(w) = auto_to_wide(path) else { return Err(0) };
    // SAFETY: the descriptor buffer is sized by the first call.
    unsafe {
        let mut size = 0u32;
        if GetFileSecurityW(w.as_ptr(), DACL_SECURITY_INFORMATION, std::ptr::null_mut(), 0, &mut size) == 0 {
            let e = GetLastError();
            if e != ERROR_INSUFFICIENT_BUFFER {
                return Err(e as i32);
            }
        }
        let mut sd = vec![0u8; size.max(1) as usize];
        if GetFileSecurityW(w.as_ptr(), DACL_SECURITY_INFORMATION, sd.as_mut_ptr() as _, size, &mut size) == 0 {
            return Err(GetLastError() as i32);
        }
        get_win_permissions(sd.as_mut_ptr() as _)
    }
}

/// `get_win_permissions` on a security descriptor buffer (registry keys).
pub fn permissions_from_sd(sd: &mut [u8]) -> Result<Json, i32> {
    // SAFETY: a self-relative security descriptor filled by the caller.
    unsafe { get_win_permissions(sd.as_mut_ptr() as _) }
}

/// `make_mask_readable` + `decode_win_acl_json`
pub fn decode_win_acl_json(acl: &mut Json) {
    const BITS: [(u32, &str); 17] = [
        (0x8000_0000, "generic_read"),
        (0x4000_0000, "generic_write"),
        (0x2000_0000, "generic_execute"),
        (0x1000_0000, "generic_all"),
        (0x0001_0000, "delete"),
        (0x0002_0000, "read_control"),
        (0x0004_0000, "write_dac"),
        (0x0008_0000, "write_owner"),
        (0x0010_0000, "synchronize"),
        (0x0001, "read_data"),
        (0x0002, "write_data"),
        (0x0004, "append_data"),
        (0x0008, "read_ea"),
        (0x0010, "write_ea"),
        (0x0020, "execute"),
        (0x0080, "read_attributes"),
        (0x0100, "write_attributes"),
    ];
    let Json::Object(aces) = acl else { return };
    for (_, ace) in aces.iter_mut() {
        let Json::Object(fields) = ace else { continue };
        for (k, v) in fields.iter_mut() {
            if k == b"allowed" || k == b"denied" {
                if let Json::Number { int, .. } = v {
                    let mask = *int as u32;
                    let mut arr = Json::array();
                    for (b, n) in BITS {
                        if mask & b != 0 {
                            arr.push(Json::string(n));
                        }
                    }
                    *v = arr;
                }
            }
        }
    }
}

/// `compare_win_permissions`
pub fn compare_win_permissions(a: Option<&Json>, b: Option<&Json>) -> bool {
    let (Some(Json::Object(a)), Some(b)) = (a, b) else { return a.is_none() && b.is_none() };
    if a.len() != b.len() {
        return false;
    }
    for (k, ace1) in a {
        let Some(ace2) = b.get_bytes(k) else { return false };
        for f in ["allowed", "denied"] {
            match (ace1.get(f), ace2.get(f)) {
                (None, None) => {}
                (Some(x), Some(y)) if x == y => {}
                _ => return false,
            }
        }
    }
    true
}

/// `check_removed_file`
pub fn check_removed_file(path: &[u8]) -> bool {
    let pat: &[u8] = b":\\$recycle.bin";
    path.windows(pat.len()).any(|w| w == pat)
}

/// `get_registry_group(&sid, hndl)`: (escaped group name, SID string).
pub fn get_registry_group(hndl: HANDLE) -> (String, String) {
    use windows_sys::Win32::Security::Authorization::SE_REGISTRY_KEY;
    use windows_sys::Win32::Security::GROUP_SECURITY_INFORMATION;
    // SAFETY: Win32 security calls on an open key; pSD is freed with LocalFree.
    unsafe {
        let mut group: PSID = std::ptr::null_mut();
        let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let rc = GetSecurityInfo(hndl, SE_REGISTRY_KEY, GROUP_SECURITY_INFORMATION, std::ptr::null_mut(), &mut group, std::ptr::null_mut(), std::ptr::null_mut(), &mut psd);
        let sid = match sid_string(group) {
            Some(s) => s,
            None => {
                mdebug1("The user's SID could not be extracted.");
                String::new()
            }
        };
        let mut name = String::new();
        if rc != 0 {
            mdebug1(format!("GetSecurityInfo error code = ({rc}), '{}'", siem_ipc::os_net::win_strerror(rc)));
        } else {
            let mut grp = [0u8; BUFFER_LEN];
            let mut dom = [0u8; BUFFER_LEN];
            let (mut ng, mut nd) = (BUFFER_LEN as u32, BUFFER_LEN as u32);
            let mut use_: SID_NAME_USE = 0;
            let ok = LookupAccountSidA(std::ptr::null(), group, grp.as_mut_ptr(), &mut ng, dom.as_mut_ptr(), &mut nd, &mut use_);
            let end = grp.iter().position(|&c| c == 0).unwrap_or(0);
            if ok != 0 && !grp.starts_with(b"None") {
                name = String::from_utf8_lossy(&grp[..end]).into_owned();
            }
            if ok == 0 {
                let e = GetLastError();
                if e == ERROR_NONE_MAPPED {
                    mdebug1("Group not found for registry key");
                } else {
                    mwarn(cfmt(msgs::FIM_REGISTRY_ACC_SID, &[A::S("group"), A::U(e as u64), A::S(&format_message(e))]));
                }
                name.clear();
            }
        }
        if !psd.is_null() {
            LocalFree(psd as _);
        }
        (name.replace(' ', "\\ "), sid)
    }
}

/// `get_registry_permissions`: the ACL, or the error code.
pub fn get_registry_permissions(hndl: windows_sys::Win32::System::Registry::HKEY) -> Result<Json, i32> {
    use windows_sys::Win32::System::Registry::RegGetKeySecurity;
    let mut n = 0u32;
    // SAFETY: the size query, then a buffer of that size.
    unsafe {
        let rc = RegGetKeySecurity(hndl, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), &mut n);
        if rc != ERROR_INSUFFICIENT_BUFFER {
            return Err(rc as i32);
        }
        let mut sd = vec![0u8; n as usize];
        let rc = RegGetKeySecurity(hndl, DACL_SECURITY_INFORMATION, sd.as_mut_ptr() as _, &mut n);
        if rc != 0 {
            return Err(rc as i32);
        }
        get_win_permissions(sd.as_mut_ptr() as _)
    }
}

/// `get_registry_mtime` (an `unsigned int`)
pub fn get_registry_mtime(hndl: windows_sys::Win32::System::Registry::HKEY) -> u32 {
    use windows_sys::Win32::System::Registry::RegQueryInfoKeyA;
    let mut ft = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let n = std::ptr::null_mut();
    // SAFETY: only the last write time is requested.
    let rc = unsafe { RegQueryInfoKeyA(hndl, std::ptr::null_mut(), n, n, n, n, n, n, n, n, n, &mut ft) };
    if rc != 0 {
        mwarn("Couldn't get modification time for registry key.");
        return 0;
    }
    file_time_epoch(ft) as u32
}

/// `wide_to_utf8` of a NUL-terminated wide string.
pub fn wide_to_utf8(w: &[u16]) -> Option<Vec<u8>> {
    // -1 reads up to the NUL, which must be inside the slice
    w.iter().position(|&c| c == 0)?;
    use windows_sys::Win32::Globalization::{WideCharToMultiByte, CP_UTF8};
    // SAFETY: the length query, then the conversion into a buffer of that length.
    unsafe {
        let len = WideCharToMultiByte(CP_UTF8, 0, w.as_ptr(), -1, std::ptr::null_mut(), 0, std::ptr::null(), std::ptr::null_mut());
        if len == 0 {
            return None;
        }
        let mut out = vec![0u8; len as usize];
        if WideCharToMultiByte(CP_UTF8, 0, w.as_ptr(), -1, out.as_mut_ptr(), len, std::ptr::null(), std::ptr::null_mut()) == 0 {
            return None;
        }
        out.pop();
        Some(out)
    }
}
