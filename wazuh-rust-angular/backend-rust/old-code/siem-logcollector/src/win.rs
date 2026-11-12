//! The Windows helpers logcollector uses from `shared/file_op.c`
//! (`get_fp_file_information`, `FileSizeWin`, `is_usc2`,
//! `expand_win32_wildcards`, `wCreateFile`) and `win_format_event_string`.
//!
//! The C agent keeps a file's identity as `nFileIndexLow + nFileIndexHigh`
//! in a `DWORD` and its size as `nFileSizeHigh + nFileSizeLow` in a 32-bit
//! `off_t`: both are sums, not the 64-bit values, and they wrap the same way
//! here.

use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FindClose, FindFirstFileW, FindNextFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, WIN32_FIND_DATAW,
};

use crate::*;

/// `GENERIC_READ`
const GENERIC_READ: u32 = 0x8000_0000;
/// `PATH_SEP`
const PATH_SEP: u8 = b'\\';
/// `UCS2_LE` / `UCS2_BE`
pub const UCS2_LE: i32 = 1;
pub const UCS2_BE: i32 = 2;

/// What logcollector keeps of `BY_HANDLE_FILE_INFORMATION`.
#[derive(Debug, Clone, Copy)]
pub struct WinInfo {
    /// `nFileIndexLow + nFileIndexHigh` (`DWORD`)
    pub fd: u32,
    /// `nFileSizeHigh + nFileSizeLow` (`DWORD`)
    pub size: u32,
    /// `ftLastWriteTime` as epoch seconds (`get_windows_file_time_epoch`)
    pub mtime: i64,
}

impl WinInfo {
    fn from(i: &BY_HANDLE_FILE_INFORMATION) -> WinInfo {
        let ft = (i.ftLastWriteTime.dwHighDateTime as u64) << 32 | i.ftLastWriteTime.dwLowDateTime as u64;
        WinInfo {
            fd: i.nFileIndexLow.wrapping_add(i.nFileIndexHigh),
            size: i.nFileSizeHigh.wrapping_add(i.nFileSizeLow),
            mtime: file_time_epoch(ft),
        }
    }

    /// The value C stores in `lf->size` (a 32-bit `off_t`).
    pub fn off_t(&self) -> i64 {
        self.size as i32 as i64
    }
}

/// `get_windows_file_time_epoch`: 100 ns ticks since 1601 to epoch seconds.
pub fn file_time_epoch(ft: u64) -> i64 {
    (ft / 10_000_000) as i64 - 11_644_473_600
}

/// `get_windows_time_epoch`
pub fn time_epoch() -> i64 {
    use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
    // SAFETY: FILETIME is plain data.
    let ft = unsafe {
        let mut ft = std::mem::zeroed();
        GetSystemTimeAsFileTime(&mut ft);
        ft
    };
    file_time_epoch((ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn by_handle(h: HANDLE) -> Option<WinInfo> {
    // SAFETY: plain data filled by the call on a valid handle.
    unsafe {
        let mut i: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        (GetFileInformationByHandle(h, &mut i) != 0).then(|| WinInfo::from(&i))
    }
}

/// `get_fp_file_information`
pub fn fp_info(fp: &CFile) -> Option<WinInfo> {
    let f = fp.file()?;
    by_handle(f.as_raw_handle() as HANDLE)
}

/// An open `wCreateFile(path, GENERIC_READ, share all, OPEN_EXISTING)`.
pub struct Handle(HANDLE);

impl Handle {
    /// `wCreateFile`: network paths are refused with a warning.
    pub fn open(lc: &Lc, path: &str) -> Option<Handle> {
        if siem_fileop::crt::is_network_path(path) {
            lc.log.warn(siem_fileop::crt::network_path_executed(path));
            return None;
        }
        let w = wide(path);
        // SAFETY: NUL-terminated wide path.
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        (h != INVALID_HANDLE_VALUE).then_some(Handle(h))
    }

    /// `GetFileInformationByHandle`
    pub fn info(&self) -> Option<WinInfo> {
        by_handle(self.0)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: a handle we opened.
        unsafe { CloseHandle(self.0) };
    }
}

/// `FileSizeWin`: the summed size, or `(DWORD)-1` when it cannot be read.
pub fn file_size_win(lc: &Lc, file: &str) -> u32 {
    match Handle::open(lc, file).map(|h| h.info()) {
        Some(Some(i)) => i.size,
        _ => {
            lc.log.debug2(format!("(1117): Error handling file '{file}'."));
            u32::MAX
        }
    }
}

/// `is_usc2`: `UCS2_LE` / `UCS2_BE` from the BOM of the text-mode stream,
/// 0 otherwise, and 1 when the file cannot be opened.
pub fn is_usc2(lc: &Lc, file: &str) -> i32 {
    if siem_fileop::crt::is_network_path(file) {
        lc.log.warn(siem_fileop::crt::network_path_executed(file));
        lc.log.debug1(format!("(1963): Unable to open file '{file}'."));
        return 1;
    }
    let Ok(mut f) = std::fs::File::open(file) else {
        lc.log.debug1(format!("(1963): Unable to open file '{file}'."));
        return 1;
    };
    // fread(b, 1, 2, fp) in text mode: read enough raw bytes to translate
    let mut raw = [0u8; 4];
    let mut n = 0;
    while n < raw.len() {
        match std::io::Read::read(&mut f, &mut raw[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    let b = siem_fileop::crt::text_in(&raw[..n]);
    if b.is_empty() {
        return 0;
    }
    let (b0, b1) = (b[0], b.get(1).copied().unwrap_or(0));
    if b0 == 0xFF && b1 == 0xFE {
        UCS2_LE
    } else if b0 == 0xFE && b1 == 0xFF {
        UCS2_BE
    } else {
        0
    }
}

fn from_wide(w: &[u16]) -> Option<String> {
    let n = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16(&w[..n]).ok()
}

/// `expand_win32_wildcards`: every path matching the `*`/`?` components of
/// `path`, directory level by directory level. `None` for a network path.
pub fn expand_win32_wildcards(lc: &Lc, path: &str) -> Option<Vec<String>> {
    if siem_fileop::crt::is_network_path(path) {
        lc.log.warn(siem_fileop::crt::network_path_executed(path));
        return None;
    }
    let mut pending: Vec<String> = vec![path.to_string()];
    loop {
        let Some(first) = pending.first() else { return Some(pending) };
        // No more patterns: done
        if !first.contains(['*', '?']) {
            return Some(pending);
        }
        let mut expanded: Vec<String> = Vec::new();
        for pattern in pending.drain(..) {
            let pb = pattern.as_bytes();
            let glob_pos = pb.iter().position(|&c| c == b'*' || c == b'?').unwrap_or(pb.len());
            // The rest after the component holding the wildcard
            let (pattern, next_glob) = match pb[glob_pos..].iter().position(|&c| c == PATH_SEP) {
                Some(k) => (pattern[..glob_pos + k].to_string(), Some(pattern[glob_pos + k + 1..].to_string())),
                None => (pattern.clone(), None),
            };
            let parent = match pattern.rfind(PATH_SEP as char) {
                Some(k) => pattern[..k].to_string(),
                None => pattern.clone(),
            };
            let w = wide(&pattern);
            // SAFETY: WIN32_FIND_DATAW is plain data; find handle closed below.
            let mut fd: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
            let h = unsafe { FindFirstFileW(w.as_ptr(), &mut fd) };
            if h == INVALID_HANDLE_VALUE {
                let e = unsafe { GetLastError() };
                match e {
                    2 => lc.log.debug2(format!("No file that matches {pattern}.")),
                    3 => lc.log.debug2(format!("No folder that matches {pattern}.")),
                    _ => lc.log.debug2(format!("FindFirstFile failed ({e}) - '{pattern}'\n")),
                }
                continue;
            }
            loop {
                let name = from_wide(&fd.cFileName);
                let skip = matches!(name.as_deref(), Some(".") | Some(".."))
                    || fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                    || (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 && next_glob.is_some());
                if let (false, Some(name)) = (skip, name) {
                    // strdup(parent) + wm_strcat(&path, name, PATH_SEP): the
                    // string is never NULL, so the separator always goes in
                    let mut p = parent.clone();
                    p.push(PATH_SEP as char);
                    p.push_str(&name);
                    if let Some(n) = &next_glob {
                        p.push(PATH_SEP as char);
                        p.push_str(n);
                    }
                    expanded.push(p);
                }
                // SAFETY: the find handle is valid until FindClose.
                if unsafe { FindNextFileW(h, &mut fd) } == 0 {
                    break;
                }
            }
            unsafe { FindClose(h) };
        }
        pending = expanded;
    }
}

/// `win_format_event_string`: newlines become spaces, and the tabs after a
/// newline or a colon become spaces too.
pub fn win_format_event_string(s: &mut [u8]) {
    let mut i = 0;
    while i < s.len() && s[i] != 0 {
        if s[i] == b'\n' || s[i] == b'\r' || s[i] == b':' {
            if s[i] == b'\n' || s[i] == b'\r' {
                s[i] = b' ';
            }
            i += 1;
            while i < s.len() && s[i] == b'\t' {
                s[i] = b' ';
                i += 1;
            }
            continue;
        }
        i += 1;
    }
}

/// One adapter of `sysinfo_networks()` as `get_agent_ip_legacy_win32`
/// reads it: the `gateway` string and the `IPv4` / `IPv6` addresses.
struct Iface {
    gateway: String,
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

fn ntop(family: u16, addr: *const std::ffi::c_void) -> String {
    use windows_sys::Win32::Networking::WinSock::inet_ntop;
    let mut buf = [0u8; 1025]; // NI_MAXHOST
    // SAFETY: address of the given family, buffer of NI_MAXHOST bytes.
    let r = unsafe { inet_ntop(family as i32, addr, buf.as_mut_ptr(), buf.len()) };
    if r.is_null() {
        return String::new();
    }
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// `SysInfo::getNetworks()` (Windows), the fields `get_agent_ip_legacy_win32`
/// uses, in `GetAdaptersAddresses` order. `None` when it throws.
fn sysinfo_networks() -> Option<Vec<Iface>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    };
    /// `IF_TYPE_SOFTWARE_LOOPBACK`
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};

    const WORKING_ADAPTERS_INFO_BUFFER_SIZE: u32 = 15000;
    const MAX_ADAPTERS_INFO_TRIES: i32 = 3;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    let mut len = WORKING_ADAPTERS_INFO_BUFFER_SIZE;
    let mut buf: Vec<u64>;
    let mut attempts = 0;
    let rc = loop {
        buf = vec![0u64; (len as usize + 7) / 8];
        // SAFETY: a buffer of at least `len` bytes, 8-byte aligned.
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
                std::ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        attempts += 1;
        if rc != ERROR_BUFFER_OVERFLOW || attempts >= MAX_ADAPTERS_INFO_TRIES {
            break rc;
        }
    };
    if rc != 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut a = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    // SAFETY: walking the list GetAdaptersAddresses built inside `buf`.
    unsafe {
        while !a.is_null() {
            let ad = &*a;
            let if_index = ad.Anonymous1.Anonymous.IfIndex;
            if ad.IfType != IF_TYPE_SOFTWARE_LOOPBACK || if_index != 0 || ad.Ipv6IfIndex != 0 {
                let mut iface = Iface { gateway: String::new(), ipv4: Vec::new(), ipv6: Vec::new() };
                let mut u = ad.FirstUnicastAddress;
                while !u.is_null() {
                    let sa = (*u).Address.lpSockaddr;
                    if !sa.is_null() {
                        if (*sa).sa_family == AF_INET {
                            let v = ntop(AF_INET, &(*(sa as *const SOCKADDR_IN)).sin_addr as *const _ as *const std::ffi::c_void);
                            if v.is_empty() {
                                return None; // "Invalid IpV4 address."
                            }
                            iface.ipv4.push(v);
                        } else if (*sa).sa_family == AF_INET6 {
                            let v = ntop(AF_INET6, &(*(sa as *const SOCKADDR_IN6)).sin6_addr as *const _ as *const std::ffi::c_void);
                            if v.is_empty() {
                                return None; // "Invalid IpV6 address."
                            }
                            iface.ipv6.push(v);
                        }
                    }
                    u = (*u).Next;
                }
                // gateway(): every gateway followed by ","
                let mut g = ad.FirstGatewayAddress;
                while !g.is_null() {
                    let sa = (*g).Address.lpSockaddr;
                    if (*sa).sa_family == AF_INET {
                        iface.gateway += &ntop(AF_INET, &(*(sa as *const SOCKADDR_IN)).sin_addr as *const _ as *const std::ffi::c_void);
                        iface.gateway.push(',');
                    } else if (*sa).sa_family == AF_INET6 {
                        iface.gateway += &ntop(AF_INET6, &(*(sa as *const SOCKADDR_IN6)).sin6_addr as *const _ as *const std::ffi::c_void);
                        iface.gateway.push(',');
                    }
                    g = (*g).Next;
                }
                out.push(iface);
            }
            a = ad.Next;
        }
    }
    Some(out)
}

/// `get_agent_ip_legacy_win32` (`win32/win_utils.c`): the first address of
/// the first interface with a gateway entry (`" "` excluded, `""` not),
/// IPv6 first when the gateway is IPv6. Never NULL.
pub fn get_agent_ip_legacy_win32(lc: &Lc) -> String {
    let mut agent_ip = String::new();
    match sysinfo_networks() {
        Some(ifaces) => {
            for e in &ifaces {
                if e.gateway == " " {
                    continue;
                }
                let (primary, secondary) = if e.gateway.contains(':') { (&e.ipv6, &e.ipv4) } else { (&e.ipv4, &e.ipv6) };
                // cJSON_GetObjectItem: the array exists only when it has items
                let ip = if !primary.is_empty() {
                    primary
                } else if !secondary.is_empty() {
                    secondary
                } else {
                    continue;
                };
                if let Some(a) = ip.first() {
                    // strncpy(agent_ip, address, IPSIZE)
                    agent_ip = a.chars().take(46).collect();
                }
                if !agent_ip.is_empty() {
                    break;
                }
            }
        }
        None => lc.log.error("Unable to get system network information. Error code: -1."),
    }
    if agent_ip.contains(':') {
        if let Some(x) = siem_regex::os_ip::expand_ipv6(&agent_ip) {
            agent_ip = x;
        }
    }
    agent_ip
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_event_string() {
        let mut s = b"a:\t\tb\r\n\tc\td\0".to_vec();
        win_format_event_string(&mut s);
        assert_eq!(&s, b"a:  b   c\td\0");
    }
}
