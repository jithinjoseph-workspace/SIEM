//! `ServicesProvider::collect()` (services_windows.cpp, with
//! `ServicesHelper` of services_utils_wrapper.cpp) and the mapping of
//! `SysInfo::getServices()`.

use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_SUCCESS, GENERIC_READ};
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::Services::*;

use super::enc;
use crate::json::{i, s, u, value_or, Obj, Value};
use crate::UNKNOWN_VALUE;

const START_TYPE: [&str; 5] = ["BOOT_START", "SYSTEM_START", "AUTO_START", "DEMAND_START", "DISABLED"];
const STATUS: [&str; 8] = ["UNKNOWN", "STOPPED", "START_PENDING", "STOP_PENDING", "RUNNING", "CONTINUE_PENDING", "PAUSE_PENDING", "PAUSED"];

fn service_type(t: u32) -> &'static str {
    match t {
        0x01 => "KERNEL_DRIVER",
        0x02 => "FILE_SYSTEM_DRIVER",
        0x10 => "OWN_PROCESS",
        0x20 => "SHARE_PROCESS",
        0x50 => "USER_OWN_PROCESS",
        0x60 => "USER_SHARE_PROCESS",
        0xd0 => "USER_OWN_PROCESS(Instance)",
        0xe0 => "USER_SHARE_PROCESS(Instance)",
        0x100 => "INTERACTIVE_PROCESS",
        0x110 => "OWN_PROCESS(Interactive)",
        0x120 => "SHARE_PROCESS(Interactive)",
        _ => "UNKNOWN",
    }
}

fn wlen(p: *const u16) -> Vec<u16> {
    if p.is_null() {
        return Vec::new();
    }
    let mut n = 0;
    // SAFETY: a NUL-terminated wide string.
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        std::slice::from_raw_parts(p, n).to_vec()
    }
}

/// `readServiceDllFromParameters`
fn read_service_dll(name: &[u16]) -> Option<Vec<u16>> {
    let mut sub: Vec<u16> = "SYSTEM\\CurrentControlSet\\Services\\".encode_utf16().collect();
    sub.extend_from_slice(name);
    sub.extend("\\Parameters".encode_utf16());
    sub.push(0);
    let value = enc::wz("ServiceDll");
    // SAFETY: valid strings, sized buffers; the key is closed on every path.
    unsafe {
        let mut h: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ | KEY_WOW64_32KEY, &mut h) != ERROR_SUCCESS {
            return None;
        }
        let mut ty = 0u32;
        let mut size = 0u32;
        let st = RegQueryValueExW(h, value.as_ptr(), std::ptr::null(), &mut ty, std::ptr::null_mut(), &mut size);
        if st != ERROR_SUCCESS || (ty != REG_SZ && ty != REG_EXPAND_SZ) || size == 0 || size > 32768 {
            RegCloseKey(h);
            return None;
        }
        let mut buf = vec![0u16; (size / 2) as usize];
        let st = RegQueryValueExW(h, value.as_ptr(), std::ptr::null(), std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut size);
        RegCloseKey(h);
        if st != ERROR_SUCCESS {
            return None;
        }
        if buf.last() == Some(&0) {
            buf.pop();
        }
        Some(buf)
    }
}

/// `ServicesProvider::getService`
unsafe fn get_service(scm: SC_HANDLE, svc: &ENUM_SERVICE_STATUS_PROCESSW) -> Option<Obj> {
    unsafe {
        let h = OpenServiceW(scm, svc.lpServiceName, SERVICE_QUERY_CONFIG);
        if h.is_null() {
            return None;
        }
        let mut need = 0u32;
        QueryServiceConfigW(h, std::ptr::null_mut(), 0, &mut need);
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
            CloseServiceHandle(h);
            return None;
        }
        // make_unique<wchar_t[]>(cbBufSize): twice the bytes needed
        let mut buf = vec![0u64; (need as usize * 2).div_ceil(8).max(1)];
        let cfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
        if QueryServiceConfigW(h, cfg, need, &mut need) == 0 {
            CloseServiceHandle(h);
            return None;
        }
        let cfg = &*cfg;
        let st = &svc.ServiceStatusProcess;
        let mut o = Obj::new();
        o.set("name", s(enc::wstring_to_utf8(&wlen(svc.lpServiceName))));
        o.set("display_name", s(enc::wstring_to_utf8(&wlen(svc.lpDisplayName))));
        o.set("status", s(STATUS.get(st.dwCurrentState as usize).copied().unwrap_or("")));
        o.set("pid", u(st.dwProcessId as u64));
        o.set("win32_exit_code", u(st.dwWin32ExitCode as u64));
        o.set("service_exit_code", u(st.dwServiceSpecificExitCode as u64));
        o.set("start_type", s(START_TYPE.get(cfg.dwStartType as usize).copied().unwrap_or("")));
        o.set("path", s(enc::wstring_to_utf8(&wlen(cfg.lpBinaryPathName))));
        o.set("user_account", s(enc::wstring_to_utf8(&wlen(cfg.lpServiceStartName))));
        o.set("service_type", s(service_type(cfg.dwServiceType)));
        o.set("description", s(""));
        let mut dsize = 0u32;
        QueryServiceConfig2W(h, SERVICE_CONFIG_DESCRIPTION, std::ptr::null_mut(), 0, &mut dsize);
        if GetLastError() == ERROR_INSUFFICIENT_BUFFER && dsize > 0 {
            let mut db = vec![0u64; (dsize as usize).div_ceil(8)];
            if QueryServiceConfig2W(h, SERVICE_CONFIG_DESCRIPTION, db.as_mut_ptr().cast(), dsize, &mut dsize) != 0 {
                let d = &*(db.as_ptr() as *const SERVICE_DESCRIPTIONW);
                if !d.lpDescription.is_null() {
                    o.set("description", s(enc::wstring_to_utf8(&wlen(d.lpDescription))));
                }
            }
        }
        let name = wlen(svc.lpServiceName);
        match read_service_dll(&name) {
            Some(dll) => {
                let fin = enc::expand_env_w32(&dll).unwrap_or(dll);
                o.set("module_path", s(enc::wstring_to_utf8(&fin)));
            }
            None => {
                o.set("module_path", s(""));
            }
        }
        CloseServiceHandle(h);
        Some(o)
    }
}

/// `ServicesProvider::collect()`
fn collect() -> Vec<Obj> {
    let mut results = Vec::new();
    // SAFETY: SCM handle closed on every path; buffers sized by the API.
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), GENERIC_READ);
        if scm.is_null() {
            return results;
        }
        let mut need = 0u32;
        let mut count = 0u32;
        EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL, std::ptr::null_mut(), 0, &mut need, &mut count, std::ptr::null_mut(), std::ptr::null());
        if GetLastError() != ERROR_MORE_DATA {
            CloseServiceHandle(scm);
            return results;
        }
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        if EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL, buf.as_mut_ptr().cast(), need, &mut need, &mut count, std::ptr::null_mut(), std::ptr::null()) == 0 {
            CloseServiceHandle(scm);
            return results;
        }
        let svcs = std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize);
        for svc in svcs {
            if let Some(o) = get_service(scm, svc) {
                results.push(o);
            }
        }
        CloseServiceHandle(scm);
    }
    results
}

/// `SysInfo::getServices()`
pub fn get_services() -> Value {
    let mut out = Vec::new();
    for svc in collect() {
        let uv = || s(UNKNOWN_VALUE);
        // svc.value(k, int) converts to int
        let int_of = |k: &str| match svc.get(k) {
            Some(Value::UInt(n)) => i(*n as i32 as i64),
            Some(Value::Int(n)) => i(*n as i32 as i64),
            _ => i(0),
        };
        let mut o = Obj::new();
        o.set("service_id", crate::json::non_empty_or_unknown(&svc, "name"));
        o.set("service_name", value_or(&svc, "display_name", uv()));
        o.set("service_description", value_or(&svc, "description", uv()));
        o.set("service_type", value_or(&svc, "service_type", uv()));
        o.set("service_state", value_or(&svc, "status", uv()));
        o.set("service_sub_state", uv());
        o.set("service_enabled", uv());
        o.set("service_start_type", value_or(&svc, "start_type", uv()));
        o.set("service_restart", uv());
        o.set("service_frequency", i(0));
        o.set("service_starts_on_mount", i(0));
        o.set("service_starts_on_path_modified", uv());
        o.set("service_starts_on_not_empty_directory", uv());
        o.set("service_inetd_compatibility", i(0));
        o.set("process_pid", int_of("pid"));
        o.set("process_executable", value_or(&svc, "path", uv()));
        o.set("process_args", uv());
        o.set("process_user_name", value_or(&svc, "user_account", uv()));
        o.set("process_group_name", uv());
        o.set("process_working_directory", uv());
        o.set("process_root_directory", uv());
        o.set("file_path", uv());
        o.set("service_address", value_or(&svc, "module_path", uv()));
        o.set("log_file_path", uv());
        o.set("error_log_file_path", uv());
        o.set("service_exit_code", int_of("service_exit_code"));
        o.set("service_win32_exit_code", int_of("win32_exit_code"));
        o.set("service_following", uv());
        o.set("service_object_path", uv());
        o.set("service_target_ephemeral_id", i(0));
        o.set("service_target_type", uv());
        o.set("service_target_address", uv());
        out.push(o.into_value());
    }
    Value::Array(out)
}
