//! `w_os_get_process_list` (`shared/os_utils.c`): the `p_path` of each
//! process, which `p:` rules match.

use siem_log::WLog;

/// `ARGV0` of libwazuhshared in the Windows agent (its `mterror(ARGV0, ...)`)
#[cfg(windows)]
const ARGV0: &str = "wazuh-remoted";

/// Windows: a Toolhelp snapshot without its first entry; `p_path` is the
/// first module's `szExePath`, or `szExeFile` when the module snapshot
/// fails. The C agent is a 32-bit process, whose module snapshots of 64-bit
/// processes fail, so those report `szExeFile` here too. None on error.
#[cfg(windows)]
pub fn process_list(log: &WLog) -> Option<Vec<Vec<u8>>> {
    process_list_as(log, ARGV0, "w_os_win32_setdebugpriv")
}

/// The same list for another caller: rootcheck's copy (`os_get_process_list`
/// of `rootcheck/win-process.c`) logs with its own tag and `os_win32_setdebugpriv`.
#[cfg(windows)]
pub fn process_list_as(log: &WLog, tag: &str, setdebugpriv: &str) -> Option<Vec<Vec<u8>>> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_NO_TOKEN, HANDLE, INVALID_HANDLE_VALUE, LUID};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, ImpersonateSelf, LookupPrivilegeValueA, SecurityImpersonation, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32First, Process32First, Process32Next, MODULEENTRY32, PROCESSENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentThread, IsWow64Process, OpenProcess, OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION};

    /// `w_os_win32_setdebugpriv`
    unsafe fn set_debug_priv(token: HANDLE, on: bool) -> bool {
        let mut luid: LUID = std::mem::zeroed();
        if LookupPrivilegeValueA(std::ptr::null(), c"SeDebugPrivilege".as_ptr() as *const u8, &mut luid) == 0 {
            return false;
        }
        // read the current state, then set it: fails (ERROR_NOT_ALL_ASSIGNED) without the privilege
        let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        let mut prev: TOKEN_PRIVILEGES = std::mem::zeroed();
        let mut cb = std::mem::size_of::<TOKEN_PRIVILEGES>() as u32;
        AdjustTokenPrivileges(token, 0, &tp, cb, &mut prev, &mut cb);
        if GetLastError() != 0 {
            return false;
        }
        prev.PrivilegeCount = 1;
        prev.Privileges[0].Luid = luid;
        if on {
            prev.Privileges[0].Attributes |= SE_PRIVILEGE_ENABLED;
        } else {
            prev.Privileges[0].Attributes ^= SE_PRIVILEGE_ENABLED & prev.Privileges[0].Attributes;
        }
        AdjustTokenPrivileges(token, 0, &prev, cb, std::ptr::null_mut(), std::ptr::null_mut());
        GetLastError() == 0
    }

    /// Whether a 32-bit process can snapshot this one's modules (it runs
    /// under WOW64 too, or the system is 32-bit).
    unsafe fn visible_to_wow64(pid: u32) -> bool {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            // the 32-bit agent fails on what it cannot open, as this process does below
            return true;
        }
        let mut wow = 0;
        let ok = IsWow64Process(h, &mut wow);
        CloseHandle(h);
        // a 64-bit Windows runs this 64-bit port natively: only WOW64 targets are visible
        ok == 0 || wow != 0 || cfg!(target_pointer_width = "32")
    }

    let cstr = |b: &[u8]| b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())].to_vec();
    // SAFETY: Win32 calls on handles opened and closed here.
    unsafe {
        let mut hpriv: HANDLE = std::ptr::null_mut();
        if OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 0, &mut hpriv) == 0 {
            if GetLastError() == ERROR_NO_TOKEN {
                if ImpersonateSelf(SecurityImpersonation) == 0 {
                    log.tagged(tag, "ERROR", "os_get_win32_process_list -> ImpersonateSelf");
                    return None;
                }
                if OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 0, &mut hpriv) == 0 {
                    log.tagged(tag, "ERROR", "os_get_win32_process_list -> OpenThread");
                    return None;
                }
            } else {
                log.tagged(tag, "ERROR", "os_get_win32_process_list -> OpenThread");
                return None;
            }
        }
        if !set_debug_priv(hpriv, true) {
            log.tagged(tag, "ERROR", setdebugpriv);
            CloseHandle(hpriv);
            return None;
        }
        let hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if hsnap == INVALID_HANDLE_VALUE {
            log.tagged(tag, "ERROR", "CreateToolhelp32Snapshot");
            return None;
        }
        let mut pe: PROCESSENTRY32 = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        if Process32First(hsnap, &mut pe) == 0 && Process32Next(hsnap, &mut pe) == 0 {
            log.tagged(tag, "ERROR", "Process32First");
            CloseHandle(hsnap);
            return None;
        }
        let mut list = Vec::new();
        while Process32Next(hsnap, &mut pe) != 0 {
            let name = cstr(std::slice::from_raw_parts(pe.szExeFile.as_ptr() as *const u8, pe.szExeFile.len()));
            let mut path = name.clone();
            if visible_to_wow64(pe.th32ProcessID) {
                let hmod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe.th32ProcessID);
                if hmod != INVALID_HANDLE_VALUE {
                    let mut me: MODULEENTRY32 = std::mem::zeroed();
                    me.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;
                    if Module32First(hmod, &mut me) != 0 {
                        path = cstr(std::slice::from_raw_parts(me.szExePath.as_ptr() as *const u8, me.szExePath.len()));
                    }
                    CloseHandle(hmod);
                }
            }
            list.push(path);
        }
        set_debug_priv(hpriv, false);
        CloseHandle(hsnap);
        Some(list)
    }
}

/// Unix: `ps -p PID -o command=` for every live PID up to `MAX_PID`.
/// shortcut: reads /proc/PID/cmdline instead of running ps per PID; matches
/// `ps` except for kernel threads ([name]); port `w_os_get_runps` if it matters.
#[cfg(unix)]
pub fn process_list(log: &WLog) -> Option<Vec<Vec<u8>>> {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        log.error("'ps' not found.");
        return None;
    };
    let mut pids: Vec<u32> = rd.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect();
    pids.sort_unstable();
    Some(
        pids.into_iter()
            .filter_map(|p| {
                let c = std::fs::read(format!("/proc/{p}/cmdline")).ok()?;
                let mut v: Vec<u8> = c.split(|&b| b == 0).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(&b' ');
                if v.is_empty() {
                    v = format!("[{}]", std::fs::read_to_string(format!("/proc/{p}/comm")).ok()?.trim()).into_bytes();
                }
                Some(v)
            })
            .collect(),
    )
}
