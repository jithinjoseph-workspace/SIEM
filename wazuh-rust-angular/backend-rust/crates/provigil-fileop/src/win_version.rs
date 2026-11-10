//! Windows version detection from `GetVersionEx` and the registry.
//!
//! The decisions live in [`win_version_with`] over a [`Registry`], so they can be replayed anywhere.

use crate::version_op::{cut, OsInfo};
use std::sync::OnceLock;

/// Levels of this module's messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Debug1,
    Debug2,
    Warn,
    Error,
}

type Hook = Box<dyn Fn(Level, &str) + Send + Sync>;
static HOOK: OnceLock<Hook> = OnceLock::new();

/// Where detection messages go; the first call wins and without a hook nothing is shown.
pub fn set_logger(hook: Hook) {
    let _ = HOOK.set(hook);
}

fn log(level: Level, msg: &str) {
    if let Some(h) = HOOK.get() {
        h(level, msg);
    }
}

/// `HKEY_LOCAL_MACHINE`, 64-bit view. Errors are the registry's error codes.
pub trait Registry {
    fn open(&self, key: &str) -> Result<(), u32>;
    /// A string value read into a buffer of `max` bytes (longer values fail).
    fn string(&self, key: &str, value: &str, max: usize) -> Result<String, u32>;
    fn dword(&self, key: &str, value: &str) -> Result<u32, u32>;
}

/// What `GetVersionEx` and friends report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VersionInfo {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub platform_id: u32,
    pub product_type: u8,
    pub x64: bool,
    pub server_r2: bool,
}

pub const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
pub const CONTROL_WINDOWS: &str = r"SYSTEM\CurrentControlSet\Control\Windows";
pub const ENVIRONMENT: &str = r"System\CurrentControlSet\Control\Session Manager\Environment";
pub const COMPUTER_NAME: &str = r"System\CurrentControlSet\Control\ComputerName\ActiveComputerName";
const VERSION_MAX: usize = 63;
const VER_NT_WORKSTATION: u8 = 1;
const VER_PLATFORM_WIN32_WINDOWS: u32 = 1;
const VER_PLATFORM_WIN32_NT: u32 = 2;

/// Release id of the Windows 10 builds that have no `ReleaseId` value.
pub fn get_release_from_build(build: Option<&str>) -> Option<&'static str> {
    Some(match build? {
        "10240" => "1507",
        "10586" => "1511",
        "14393" => "1607",
        "15063" => "1709",
        "17134" => "1803",
        "17763" => "1809",
        "18362" => "1903",
        "18363" => "1909",
        _ => return None,
    })
}

/// The fixed names of Windows versions before Vista.
pub fn legacy_name(v: &VersionInfo) -> Option<&'static str> {
    Some(match (v.major, v.minor) {
        (5, 0) => "Microsoft Windows 2000",
        (5, 1) => "Microsoft Windows XP",
        (5, 2) if v.product_type == VER_NT_WORKSTATION && v.x64 => "Microsoft Windows XP Professional x64 Edition",
        (5, 2) if v.server_r2 => "Microsoft Windows Server 2003 R2",
        (5, 2) => "Microsoft Windows Server 2003",
        (5, _) => return None,
        (4, _) if v.platform_id == VER_PLATFORM_WIN32_NT => "Microsoft Windows NT",
        (4, 0) if v.platform_id == VER_PLATFORM_WIN32_WINDOWS => "Microsoft Windows 95",
        (4, 10) if v.platform_id == VER_PLATFORM_WIN32_WINDOWS => "Microsoft Windows 98",
        (4, 90) if v.platform_id == VER_PLATFORM_WIN32_WINDOWS => "Microsoft Windows ME",
        (4, _) => return None,
        _ => "Microsoft Windows",
    })
}

/// Opens a key, logging the (1758) message when it cannot be opened.
fn opened(reg: &dyn Registry, key: &str) -> bool {
    let ok = reg.open(key).is_ok();
    if !ok {
        log(Level::Error, &format!("(1758): Unable to open registry key: '{key}'."));
    }
    ok
}

fn read_error(name: &str, code: u32) {
    log(Level::Error, &format!("Error reading '{name}' from Windows registry. (Error {code})"));
}

fn cut63(mut s: String) -> String {
    cut(&mut s, VERSION_MAX);
    s
}

/// Name, version parts and release from the registry (GetVersionEx major 6).
fn from_registry(i: &mut OsInfo, reg: &dyn Registry) {
    let cv = CURRENT_VERSION;
    let name = if opened(reg, cv) { reg.string(cv, "ProductName", 1024).map_err(|n| read_error("ProductName", n)).ok() } else { None };
    i.os_name = Some(name.map_or_else(|| "Microsoft Windows undefined version".into(), |n| format!("Microsoft {n}")));

    let mut number = None;
    // The key is opened a second time for the version values.
    if opened(reg, cv) {
        let build_number = |number: &mut Option<String>| match reg.string(cv, "CurrentBuildNumber", 30) {
            Ok(b) => {
                *number = Some(b.clone());
                Some(b)
            }
            Err(n) => {
                read_error("CurrentBuildNumber", n);
                None
            }
        };
        // A missing CurrentMajorVersionNumber only selects the 6.2/6.3 path.
        if let Ok(major) = reg.dword(cv, "CurrentMajorVersionNumber") {
            match reg.dword(cv, "CurrentMinorVersionNumber") {
                // Without the minor number, major, minor and build all stay unset.
                Err(n) => read_error("CurrentMinorVersionNumber", n),
                Ok(minor) => {
                    i.os_major = Some(major.to_string());
                    i.os_minor = Some(minor.to_string());
                    i.os_build = build_number(&mut number).map(|b| match reg.dword(cv, "UBR") {
                        Ok(ubr) => cut63(format!("{b}.{ubr}")),
                        Err(_) => b,
                    });
                }
            }
            i.os_release = match reg.string(cv, "ReleaseId", 1024) {
                Ok(r) => Some(r),
                Err(n) => {
                    log(Level::Debug1, &format!("Could not read the 'ReleaseId' key from Windows registry. (Error {n})"));
                    // Looked up with the build including `.<UBR>`.
                    i.os_build.as_deref().and_then(|b| {
                        let r = get_release_from_build(Some(b));
                        if r.is_none() {
                            log(Level::Debug1, &format!("The release associated with the {b} build is not recognized."));
                        }
                        r.map(str::to_string)
                    })
                }
            };
        } else {
            match reg.string(cv, "CurrentVersion", 1024) {
                Err(n) => read_error("Current Version", n),
                Ok(v) => {
                    let (major, minor) = v.split_once('.').map_or((v.as_str(), None), |(a, b)| (a, Some(b)));
                    i.os_major = Some(major.to_string());
                    i.os_minor = minor.map(str::to_string);
                    i.os_build = build_number(&mut number);
                }
            }
        }
    }
    let part = |p: &Option<String>| p.clone().unwrap_or_else(|| "(null)".into());
    i.os_version = Some(cut63(format!("{}.{}.{}", part(&i.os_major), part(&i.os_minor), part(&i.os_build))));
    let build: u32 = number.as_deref().unwrap_or("").parse().unwrap_or(0);
    if build >= 22000 {
        i.os_name = i.os_name.take().map(|n| n.replace("Windows 10", "Windows 11"));
    }
}

/// Detection from the version numbers and the registry; None when the version is unknown.
pub fn win_version_with(v: Option<VersionInfo>, reg: &dyn Registry) -> Option<OsInfo> {
    let v = v?;
    let mut i = OsInfo { version: Some(format!("{}.{}", v.major, v.minor)), ..Default::default() };
    if v.major == 6 {
        from_registry(&mut i, reg);
    } else {
        let build = v.build & 0xFFFF;
        i.os_name = legacy_name(&v).map(str::to_string);
        i.os_major = Some(v.major.to_string());
        i.os_minor = Some(v.minor.to_string());
        i.os_build = Some(build.to_string());
        i.os_version = Some(format!("{}.{}.{build}", v.major, v.minor));
    }
    if i.os_release.is_none() && opened(reg, CONTROL_WINDOWS) {
        i.os_release = match reg.dword(CONTROL_WINDOWS, "CSDVersion") {
            Err(n) => {
                read_error("CSDVersion", n);
                None
            }
            Ok(sp @ (256 | 512 | 768 | 1024 | 1280 | 1536)) => Some(format!("sp{}", sp / 256)),
            Ok(sp) => {
                log(Level::Debug2, &format!("The value of CSDVersion is not a recognizable service pack.: {sp}."));
                None
            }
        };
    }
    let arch = if opened(reg, ENVIRONMENT) {
        reg.string(ENVIRONMENT, "PROCESSOR_ARCHITECTURE", 1024).map_err(|n| read_error("Architecture", n)).ok()
    } else {
        None
    };
    let arch = arch.unwrap_or_default();
    i.machine = Some(
        if ["AMD64", "IA64", "ARM64"].iter().any(|p| arch.starts_with(p)) {
            "x86_64"
        } else if arch.starts_with("x86") {
            "i686"
        } else {
            "unknown"
        }
        .to_string(),
    );
    let node = if opened(reg, COMPUTER_NAME) {
        reg.string(COMPUTER_NAME, "ComputerName", 30).map_err(|n| read_error("hostname", n)).ok()
    } else {
        None
    };
    i.nodename = Some(node.unwrap_or_else(|| "unknown".into()));
    Some(i)
}

#[cfg(windows)]
pub use imp::{get_win_version, getuname, LiveRegistry};

#[cfg(windows)]
mod imp {
    use super::{win_version_with, Registry, VersionInfo};
    use crate::version_op::{cut, OsInfo, AGENT_PRODUCT};
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegGetValueA, RegOpenKeyExA, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, RRF_RT_REG_DWORD,
        RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
    };
    use windows_sys::Win32::System::SystemInformation::{
        GetNativeSystemInfo, GetVersionExW, OSVERSIONINFOEXW, OSVERSIONINFOW, SYSTEM_INFO,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_SERVERR2};

    const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;

    fn c(s: &str) -> Vec<u8> {
        s.bytes().chain(Some(0)).collect()
    }

    /// The registry of this machine.
    pub struct LiveRegistry;

    impl LiveRegistry {
        fn get(&self, key: &str, value: &str, flags: u32, data: *mut core::ffi::c_void, len: &mut u32) -> Result<(), u32> {
            // SAFETY: NUL-terminated names and a buffer of the stated length.
            let r = unsafe {
                RegGetValueA(
                    HKEY_LOCAL_MACHINE,
                    c(key).as_ptr(),
                    c(value).as_ptr(),
                    flags | RRF_SUBKEY_WOW6464KEY,
                    std::ptr::null_mut(),
                    data,
                    len,
                )
            };
            if r == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(r)
            }
        }
    }

    impl Registry for LiveRegistry {
        fn open(&self, key: &str) -> Result<(), u32> {
            let mut h: HKEY = std::ptr::null_mut();
            // SAFETY: NUL-terminated name and a valid out pointer; the key is closed when opened.
            unsafe {
                let r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, c(key).as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut h);
                if r != ERROR_SUCCESS {
                    return Err(r);
                }
                RegCloseKey(h);
            }
            Ok(())
        }

        fn string(&self, key: &str, value: &str, max: usize) -> Result<String, u32> {
            let mut buf = vec![0u8; max];
            let mut len = max as u32;
            self.get(key, value, RRF_RT_REG_SZ, buf.as_mut_ptr().cast(), &mut len)?;
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
        }

        fn dword(&self, key: &str, value: &str) -> Result<u32, u32> {
            let mut v = 0u32;
            let mut len = 4u32;
            self.get(key, value, RRF_RT_REG_DWORD, (&raw mut v).cast(), &mut len)?;
            Ok(v)
        }
    }

    fn version_info() -> Option<VersionInfo> {
        // SAFETY: plain-data structs with their size fields set as the calls require.
        unsafe {
            let mut v: OSVERSIONINFOEXW = std::mem::zeroed();
            v.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
            if GetVersionExW((&raw mut v).cast::<OSVERSIONINFOW>()) == 0 {
                return None;
            }
            let mut si: SYSTEM_INFO = std::mem::zeroed();
            GetNativeSystemInfo(&mut si);
            Some(VersionInfo {
                major: v.dwMajorVersion,
                minor: v.dwMinorVersion,
                build: v.dwBuildNumber,
                platform_id: v.dwPlatformId,
                product_type: v.wProductType,
                x64: si.Anonymous.Anonymous.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64,
                server_r2: GetSystemMetrics(SM_SERVERR2) != 0,
            })
        }
    }

    pub fn get_win_version() -> Option<OsInfo> {
        win_version_with(version_info(), &LiveRegistry)
    }

    pub fn getuname() -> String {
        let mut s = match get_win_version() {
            None => format!("Microsoft Windows - {AGENT_PRODUCT}"),
            Some(i) => format!(
                "{} [Ver: {}] |{} |{} - {AGENT_PRODUCT}",
                i.os_name.as_deref().unwrap_or("Microsoft Windows"),
                i.os_version.as_deref().unwrap_or("unknown"),
                i.nodename.as_deref().unwrap_or("unknown"),
                i.machine.as_deref().unwrap_or("unknown"),
            ),
        };
        cut(&mut s, 1023);
        s
    }
}
