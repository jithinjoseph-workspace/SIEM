//! `win32/win_service.c`: the "WazuhSvc" service (install, uninstall, the
//! control handler and the dispatcher). Every message here uses the
//! `plain_*` log functions, as in C.

use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use siem_log::WLog;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_SERVICE_ALREADY_RUNNING};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2A, CloseServiceHandle, ControlService, CreateServiceA, DeleteService, OpenSCManagerA,
    OpenServiceA, QueryServiceStatus, RegisterServiceCtrlHandlerA, SetServiceStatus, StartServiceA,
    StartServiceCtrlDispatcherA, SC_HANDLE, SC_MANAGER_ALL_ACCESS, SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS,
    SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONA,
    SERVICE_ERROR_NORMAL, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
    SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYA, SERVICE_WIN32, SERVICE_WIN32_OWN_PROCESS,
};

/// `g_lpszServiceName` / `g_lpszServiceDisplayName` / `g_lpszServiceDescription`
const SERVICE_NAME: &[u8] = b"WazuhSvc\0";
const DISPLAY_NAME: &[u8] = b"Wazuh\0";
const DESCRIPTION: &[u8] = b"Wazuh Windows Agent\0";
/// `DELETE` / `SERVICE_STOP`
const DELETE: u32 = 0x0001_0000;
const SERVICE_STOP: u32 = 0x0020;

static LOG: OnceLock<Arc<WLog>> = OnceLock::new();
/// `ossecServiceStatusHandle`
static STATUS_HANDLE: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
/// `ossecServiceStatus`
static STATUS: Mutex<SERVICE_STATUS> = Mutex::new(SERVICE_STATUS {
    dwServiceType: 0,
    dwCurrentState: 0,
    dwControlsAccepted: 0,
    dwWin32ExitCode: 0,
    dwServiceSpecificExitCode: 0,
    dwCheckPoint: 0,
    dwWaitHint: 0,
});
/// What runs on service stop besides the status changes (`OSSECHIDS`:
/// `wm_kill_children`, `stop_wmodules`, `is_fim_shutdown`, `fim_db_teardown`).
static ON_STOP: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();
/// `local_start` for the service thread.
static START: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

pub fn set_logger(log: Arc<WLog>) {
    let _ = LOG.set(log);
}

pub fn set_on_stop(f: Box<dyn Fn() + Send + Sync>) {
    let _ = ON_STOP.set(f);
}

fn log() -> &'static WLog {
    LOG.get().expect("service logger")
}

fn sc_manager() -> SC_HANDLE {
    // SAFETY: plain SCM call.
    unsafe { OpenSCManagerA(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS) }
}

fn service_status(svc: SC_HANDLE) -> Option<SERVICE_STATUS> {
    // SAFETY: SERVICE_STATUS is plain data.
    unsafe {
        let mut s: SERVICE_STATUS = std::mem::zeroed();
        (QueryServiceStatus(svc, &mut s) != 0).then_some(s)
    }
}

/// `os_start_service`: 1 started, -1 already running, 0 otherwise.
pub fn os_start_service() -> i32 {
    let mut rc = 0;
    // SAFETY: SCM handles we open and close.
    unsafe {
        let m = sc_manager();
        if !m.is_null() {
            let s = OpenServiceA(m, SERVICE_NAME.as_ptr(), SC_MANAGER_ALL_ACCESS);
            if !s.is_null() {
                if StartServiceA(s, 0, std::ptr::null()) != 0 {
                    rc = 1;
                } else if GetLastError() == ERROR_SERVICE_ALREADY_RUNNING {
                    rc = -1;
                }
                CloseServiceHandle(s);
            }
            CloseServiceHandle(m);
        }
    }
    rc
}

/// `os_stop_service`
pub fn os_stop_service() -> i32 {
    let mut rc = 0;
    // SAFETY: SCM handles we open and close.
    unsafe {
        let m = sc_manager();
        if !m.is_null() {
            let s = OpenServiceA(m, SERVICE_NAME.as_ptr(), SC_MANAGER_ALL_ACCESS);
            if !s.is_null() {
                let mut st: SERVICE_STATUS = std::mem::zeroed();
                if ControlService(s, SERVICE_CONTROL_STOP, &mut st) != 0 {
                    rc = 1;
                }
                CloseServiceHandle(s);
            }
            CloseServiceHandle(m);
        }
    }
    // Avoid races with newer instances of wazuh-agent
    std::thread::sleep(std::time::Duration::from_millis(300));
    rc
}

/// `CheckServiceRunning`
pub fn check_service_running() -> bool {
    let mut rc = false;
    // SAFETY: SCM handles we open and close.
    unsafe {
        let m = sc_manager();
        if !m.is_null() {
            let s = OpenServiceA(m, SERVICE_NAME.as_ptr(), SC_MANAGER_ALL_ACCESS);
            if !s.is_null() {
                if let Some(st) = service_status(s) {
                    rc = st.dwCurrentState == SERVICE_RUNNING;
                }
                CloseServiceHandle(s);
            }
            CloseServiceHandle(m);
        }
    }
    rc
}

/// `FormatMessage(ALLOCATE_BUFFER | FROM_SYSTEM | IGNORE_INSERTS, err)`
fn system_message(err: u32) -> String {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        FormatMessageA, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
    };
    // SAFETY: FormatMessage allocates the buffer, freed below.
    unsafe {
        let mut p: *mut u8 = std::ptr::null_mut();
        let n = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            std::ptr::null(),
            err,
            0x0400,
            (&mut p as *mut *mut u8).cast(),
            0,
            std::ptr::null(),
        );
        if n == 0 || p.is_null() {
            return "(null)".to_string();
        }
        let s = String::from_utf8_lossy(std::slice::from_raw_parts(p, n as usize)).into_owned();
        LocalFree(p.cast());
        s
    }
}

/// `InstallService`: 1 on success.
pub fn install_service(path: &str) -> i32 {
    if uninstall_service() == 0 {
        log().plain("ERROR", "Failure running UninstallService().");
        return 0;
    }
    let bin = std::ffi::CString::new(path).unwrap_or_default();
    // SAFETY: SCM calls with NUL-terminated strings.
    let ok = unsafe {
        let m = sc_manager();
        if m.is_null() {
            false
        } else {
            let s = CreateServiceA(
                m,
                SERVICE_NAME.as_ptr(),
                DISPLAY_NAME.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                bin.as_ptr().cast(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            );
            if s.is_null() {
                CloseServiceHandle(m);
                false
            } else {
                let mut d = SERVICE_DESCRIPTIONA { lpDescription: DESCRIPTION.as_ptr() as *mut u8 };
                let r = ChangeServiceConfig2A(s, SERVICE_CONFIG_DESCRIPTION, (&mut d as *mut SERVICE_DESCRIPTIONA).cast());
                CloseServiceHandle(s);
                CloseServiceHandle(m);
                r != 0
            }
        }
    };
    if !ok {
        let e = unsafe { GetLastError() };
        log().plain("ERROR", format!("Unable to create service entry: {}", system_message(e)));
        return 0;
    }
    log().plain("INFO", "Successfully added to the service database.");
    1
}

/// `UninstallService`: 1 on success (or when there is nothing to remove).
pub fn uninstall_service() -> i32 {
    let mut rc = 0;
    let name = "WazuhSvc";
    // SAFETY: SCM handles we open and close.
    unsafe {
        let m = sc_manager();
        if !m.is_null() {
            let s = OpenServiceA(m, SERVICE_NAME.as_ptr(), SERVICE_STOP | DELETE);
            if !s.is_null() {
                let ret = if check_service_running() {
                    log().plain("INFO", format!("Found ({name}) service is running going to try and stop it."));
                    let mut st: SERVICE_STATUS = std::mem::zeroed();
                    let r = ControlService(s, SERVICE_CONTROL_STOP, &mut st);
                    if r == 0 {
                        log().plain("ERROR", format!("Failure stopping service ({name}) before removing it ({}).", GetLastError()));
                    } else {
                        log().plain("INFO", format!("Successfully stopped ({name})."));
                    }
                    r
                } else {
                    log().plain("INFO", format!("Found ({name}) service is not running."));
                    1
                };
                if ret != 0 && DeleteService(s) != 0 {
                    log().plain("INFO", format!("Successfully removed ({name}) from the service database."));
                    rc = 1;
                }
                CloseServiceHandle(s);
            } else {
                log().plain("INFO", format!("Service does not exist ({name}) nothing to remove."));
                rc = 1;
            }
            CloseServiceHandle(m);
        }
    }
    if rc == 0 {
        log().plain("ERROR", format!("Failure removing ({name}) from the service database."));
    }
    rc
}

fn set_status(st: &SERVICE_STATUS) {
    let h = STATUS_HANDLE.load(Ordering::SeqCst) as SERVICE_STATUS_HANDLE;
    // SAFETY: the handle RegisterServiceCtrlHandler returned.
    unsafe { SetServiceStatus(h, st) };
}

/// `OssecServiceCtrlHandler`
unsafe extern "system" fn service_ctrl_handler(opcode: u32) {
    if STATUS_HANDLE.load(Ordering::SeqCst).is_null() {
        return;
    }
    if opcode == SERVICE_CONTROL_STOP {
        let mut st = STATUS.lock().unwrap_or_else(|e| e.into_inner());
        st.dwWin32ExitCode = 0;
        st.dwCheckPoint = 0;
        st.dwWaitHint = 0;
        log().plain("INFO", "Received exit signal. Starting exit process.");
        st.dwCurrentState = SERVICE_STOP_PENDING;
        set_status(&st);
        log().plain("INFO", "Set pending exit signal.");
        if let Some(f) = ON_STOP.get() {
            f();
        }
        st.dwCurrentState = SERVICE_STOPPED;
        set_status(&st);
        log().plain("INFO", "Exit completed successfully.");
    }
}

/// `WinSetError`: stop the service (the `*_exit` log functions call it).
pub fn win_set_error() {
    // SAFETY: the handler checks for a registered service.
    unsafe { service_ctrl_handler(SERVICE_CONTROL_STOP) };
}

/// `OssecServiceStart`
unsafe extern "system" fn service_start(_argc: u32, _argv: *mut *mut u8) {
    {
        let mut st = STATUS.lock().unwrap_or_else(|e| e.into_inner());
        st.dwServiceType = SERVICE_WIN32;
        st.dwCurrentState = SERVICE_START_PENDING;
        st.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        st.dwWin32ExitCode = 0;
        st.dwServiceSpecificExitCode = 0;
        st.dwCheckPoint = 0;
        st.dwWaitHint = 0;
    }
    let h = RegisterServiceCtrlHandlerA(SERVICE_NAME.as_ptr(), Some(service_ctrl_handler));
    if h.is_null() {
        log().plain("INFO", "RegisterServiceCtrlHandler failed.");
        return;
    }
    STATUS_HANDLE.store(h, Ordering::SeqCst);
    let st = {
        let mut st = STATUS.lock().unwrap_or_else(|e| e.into_inner());
        st.dwCurrentState = SERVICE_RUNNING;
        st.dwCheckPoint = 0;
        st.dwWaitHint = 0;
        *st
    };
    if SetServiceStatus(h, &st) == 0 {
        log().plain("INFO", "SetServiceStatus error.");
        return;
    }
    // Start process
    if let Some(f) = START.get() {
        f();
    }
}

/// `os_WinMain`: run as a service (`local_start` on the service thread).
pub fn os_win_main(start: Box<dyn Fn() + Send + Sync>) -> i32 {
    let _ = START.set(start);
    let table = [
        SERVICE_TABLE_ENTRYA { lpServiceName: SERVICE_NAME.as_ptr() as *mut u8, lpServiceProc: Some(service_start) },
        SERVICE_TABLE_ENTRYA { lpServiceName: std::ptr::null_mut(), lpServiceProc: None },
    ];
    // SAFETY: a NULL-terminated table of static entries.
    if unsafe { StartServiceCtrlDispatcherA(table.as_ptr()) } == 0 {
        log().plain("INFO", "Unable to set service information.");
    }
    1
}
