//! EDR response (not in Wazuh): ends a process on the endpoint.
//! extra_args: `pid=<n>`, optionally `image=<full path>` (refused when the PID now
//! runs another program: PIDs are reused). Critical Windows processes and the
//! agent are never killed (`edr::kill_refusal`).

#[cfg(windows)]
#[path = "../../../siem-winagent/src/dll_verify.rs"]
#[allow(dead_code)]
mod dll_verify;

#[cfg(windows)]
use siem_active_response::{edr::*, *};

fn main() {
    #[cfg(windows)]
    std::process::exit(win_main());
    #[cfg(not(windows))]
    std::process::exit(-1);
}

#[cfg(windows)]
fn win_main() -> i32 {
    // This must be always the first instruction
    dll_verify::enable_dll_verification(&std::sync::Arc::new(siem_log::WLog::new("unset", std::path::Path::new("."))));
    let argv0 = argv0();
    let Some((action, input)) = setup_and_check_message(&argv0) else { return -1 };
    if action != Action::Add {
        write_debug_file(&argv0, b"Ended");
        return 0;
    }
    let r = kill(&input);
    let m = match &r {
        Ok(m) => format!("{{\"message\":\"Process killed\",{m},\"status\":\"success\",\"script\":\"kill-process\"}}"),
        Err(e) => format!("{{\"message\":{},\"status\":\"failed\",\"script\":\"kill-process\"}}", json_str(e)),
    };
    write_debug_file(&argv0, m.as_bytes());
    write_debug_file(&argv0, b"Ended");
    if r.is_ok() { 0 } else { -1 }
}

/// The killed process (`"pid":..,"image":..`), or why it was not killed.
#[cfg(windows)]
fn kill(input: &siem_cjson::Json) -> Result<String, String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE};

    let pid: u32 = extra_arg(input, "pid").and_then(|p| p.trim().parse().ok()).ok_or("A process id (pid=<n>) is required")?;
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    // SAFETY: plain Win32 calls on a handle this function opens and closes
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return Err(format!("Cannot open process {pid}: {}", std::io::Error::last_os_error()));
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let image = if QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) != 0 {
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            String::new()
        };
        let refused = kill_refusal(pid, &image, &root)
            .map(|why| format!("Process {pid} ({image}) not killed: {why}"))
            .or_else(|| {
                extra_arg(input, "image")
                    .filter(|want| !want.trim().eq_ignore_ascii_case(&image))
                    .map(|want| format!("Process {pid} now runs {image}, not {want}; not killed"))
            });
        let r = match refused {
            Some(m) => Err(m),
            None if TerminateProcess(h, 1) == 0 => Err(format!("Cannot end process {pid} ({image}): {}", std::io::Error::last_os_error())),
            None => Ok(format!("\"pid\":{pid},\"image\":{}", json_str(&image))),
        };
        CloseHandle(h);
        r
    }
}
