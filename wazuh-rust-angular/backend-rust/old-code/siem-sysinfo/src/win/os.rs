//! `osinfo/sysOsInfoWin.cpp` + `SysOsInfo::setOsInfo`.

use std::collections::BTreeMap;

use windows_sys::Win32::System::SystemInformation::*;

use super::registry::*;
use super::Error;
use crate::json::{s, Obj, Value};
use crate::{strings, UNKNOWN_VALUE};

const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

/// `IsWindowsVersionOrGreater` (versionhelpers.h)
fn is_windows_version_or_greater(major: u32, minor: u32, sp: u16) -> bool {
    // SAFETY: plain struct and calls.
    unsafe {
        let mut osvi: OSVERSIONINFOEXW = std::mem::zeroed();
        osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
        let mask = VerSetConditionMask(
            VerSetConditionMask(VerSetConditionMask(0, VER_MAJORVERSION, 3u8), VER_MINORVERSION, 3u8),
            VER_SERVICEPACKMAJOR,
            3u8,
        );
        osvi.dwMajorVersion = major;
        osvi.dwMinorVersion = minor;
        osvi.wServicePackMajor = sp;
        VerifyVersionInfoW(&mut osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, mask) != 0
    }
}

/// `IsWindowsVistaOrGreater()`
pub fn is_vista_or_greater() -> bool {
    is_windows_version_or_greater(6, 0, 0)
}

/// `IsWindows8OrGreater()`
pub fn is_windows8_or_greater() -> bool {
    is_windows_version_or_greater(6, 2, 0)
}

fn version_ex() -> Option<OSVERSIONINFOEXA> {
    // SAFETY: plain struct and calls.
    unsafe {
        let mut osvi: OSVERSIONINFOEXA = std::mem::zeroed();
        osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXA>() as u32;
        if GetVersionExA(&mut osvi as *mut _ as *mut OSVERSIONINFOA) != 0 {
            return Some(osvi);
        }
        osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOA>() as u32;
        (GetVersionExA(&mut osvi as *mut _ as *mut OSVERSIONINFOA) != 0).then_some(osvi)
    }
}

/// `getVersion(isMinor)`
fn get_version(is_minor: bool) -> Result<String, Error> {
    if is_vista_or_greater() {
        let cv = Registry::read(HKEY_LOCAL_MACHINE, CURRENT_VERSION)?;
        let name = if is_minor { "CurrentMinorVersionNumber" } else { "CurrentMajorVersionNumber" };
        if let Some(v) = is_windows8_or_greater().then(|| cv.dword_opt(name)).flatten() {
            return Ok(v.to_string());
        }
        let full = cv.string("CurrentVersion")?;
        let mm = strings::split(&full, '.');
        if mm.len() == 2 {
            return Ok(if is_minor { mm[1].clone() } else { mm[0].clone() });
        }
        Ok(String::new())
    } else {
        Ok(version_ex().map(|o| if is_minor { o.dwMinorVersion } else { o.dwMajorVersion }.to_string()).unwrap_or_default())
    }
}

/// `getBuild()`
fn get_build() -> Result<String, Error> {
    if is_vista_or_greater() {
        Ok(Registry::read(HKEY_LOCAL_MACHINE, CURRENT_VERSION)?.string("CurrentBuildNumber")?)
    } else {
        Ok(version_ex().map(|o| (o.dwBuildNumber & 0xFFFF).to_string()).unwrap_or_default())
    }
}

/// `getBuildRevision()`
fn get_build_revision() -> Result<String, Error> {
    if is_windows8_or_greater() {
        let cv = Registry::open(HKEY_LOCAL_MACHINE, CURRENT_VERSION, KEY_READ | KEY_WOW64_64KEY)?;
        if let Some(ubr) = cv.dword_opt("UBR") {
            return Ok(ubr.to_string());
        }
    }
    Ok(String::new())
}

/// `getRelease(build)`
fn get_release(build: &str) -> Result<String, Error> {
    const SP: &str = "Service Pack";
    let map: BTreeMap<&str, &str> = [
        ("10240", "1507"),
        ("10586", "1511"),
        ("14393", "1607"),
        ("15063", "1709"),
        ("17134", "1803"),
        ("17763", "1809"),
        ("18362", "1903"),
        ("18363", "1909"),
    ]
    .into_iter()
    .collect();
    let mut release = String::new();
    let cv = Registry::read(HKEY_LOCAL_MACHINE, CURRENT_VERSION)?;
    if is_windows8_or_greater() {
        match cv.string_opt_s("ReleaseId") {
            Some(r) => release = r,
            None => {
                if let Some(r) = map.get(build) {
                    release = r.to_string();
                }
            }
        }
    }
    if release.is_empty() {
        let sp_of = |sp: &str| -> Option<String> {
            strings::starts_with(sp, SP).then(|| format!("sp{}", strings::trim(&sp[SP.len()..], " ")))
        };
        match cv.string_opt_s("CSDVersion") {
            Some(sp) => {
                if let Some(r) = sp_of(&sp) {
                    release = r;
                }
            }
            None => {
                let cv64 = Registry::open(HKEY_LOCAL_MACHINE, CURRENT_VERSION, KEY_READ | KEY_WOW64_64KEY)?;
                if let Some(sp) = cv64.string_opt_s("CSDVersion") {
                    if let Some(r) = sp_of(&sp) {
                        release = r;
                    }
                }
            }
        }
    }
    Ok(release)
}

/// `getDisplayVersion()`
fn get_display_version() -> Result<String, Error> {
    let cv = Registry::read(HKEY_LOCAL_MACHINE, CURRENT_VERSION)?;
    Ok(cv.string_opt_s("DisplayVersion").unwrap_or_else(|| UNKNOWN_VALUE.into()))
}

/// `getName()`
fn get_name() -> Result<String, Error> {
    const MSFT: &str = "Microsoft";
    let mut name = String::new();
    let cv = Registry::open(HKEY_LOCAL_MACHINE, CURRENT_VERSION, KEY_WOW64_64KEY | KEY_READ)?;
    if let Some(n) = cv.string_opt_s("ProductName") {
        name = if strings::starts_with(&n, MSFT) { n } else { format!("{MSFT} {n}") };
        let build = get_build()?;
        if let Ok((value, used)) = strings::stoi(&build) {
            if build.len() == used && value >= 22000 {
                strings::replace_all(&mut name, "Microsoft Windows 10", "Microsoft Windows 11");
            }
        }
    } else if is_vista_or_greater() {
        name = "Windows undefined version".into();
    } else if let Some(o) = version_ex() {
        // (the C checks dwMajorVersion == 5 and then <= 1: never true)
        if o.dwMajorVersion == 5 {
            // SAFETY: plain calls.
            unsafe {
                let mut si: SYSTEM_INFO = std::mem::zeroed();
                GetNativeSystemInfo(&mut si);
                const VER_NT_WORKSTATION: u8 = 1;
                if o.wProductType == VER_NT_WORKSTATION && si.Anonymous.Anonymous.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 {
                    name = "Microsoft Windows XP Professional x64 Edition".into();
                } else if windows_sys_get_system_metrics(89) != 0 {
                    name = "Microsoft Windows Server 2003 R2".into();
                } else {
                    name = "Microsoft Windows Server 2003".into();
                }
            }
        }
    }
    Ok(if name.is_empty() { "Microsoft Windows".into() } else { name })
}

fn windows_sys_get_system_metrics(i: i32) -> i32 {
    extern "system" {
        fn GetSystemMetrics(n: i32) -> i32;
    }
    // SAFETY: plain call.
    unsafe { GetSystemMetrics(i) }
}

/// `getMachine()`
fn get_machine() -> Result<String, Error> {
    let env = Registry::read(HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Session Manager\Environment")?;
    let arch = env.string("PROCESSOR_ARCHITECTURE")?;
    Ok(match arch.as_str() {
        "AMD64" | "IA64" | "ARM64" => "x86_64",
        "x86" => "i686",
        _ => UNKNOWN_VALUE,
    }
    .into())
}

/// `getNodeName()`
fn get_node_name() -> Result<String, Error> {
    let r = Registry::read(HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\ComputerName\ActiveComputerName")?;
    Ok(r.string_opt_s("ComputerName").unwrap_or_else(|| UNKNOWN_VALUE.into()))
}

/// `SysInfo::getOsInfo()`
pub fn get_os_info() -> Result<Value, Error> {
    // SysOsInfoProviderWindows' constructor
    let major = get_version(false)?;
    let minor = get_version(true)?;
    let build = get_build()?;
    let build_revision = get_build_revision()?;
    let full_version = format!("{major}.{minor}.{build}");
    let release = get_release(&build)?;
    let display_version = get_display_version()?;
    let name = get_name()?;
    let machine = get_machine()?;
    let node_name = get_node_name()?;
    let version = if build_revision.is_empty() { full_version } else { format!("{full_version}.{build_revision}") };
    let os_build = if build_revision.is_empty() { build } else { format!("{build}.{build_revision}") };

    let mut o = Obj::new();
    o.set("os_name", s(&name));
    o.set("os_major", s(&major));
    o.set("os_minor", s(&minor));
    o.set("os_build", s(&os_build));
    o.set("os_version", s(&version));
    o.set("hostname", s(&node_name));
    o.set("os_release", s(&release));
    o.set("os_display_version", s(&display_version));
    o.set("release", s(&version));
    o.set("architecture", s(&machine));
    o.set("os_platform", s("windows"));
    Ok(o.into_value())
}
