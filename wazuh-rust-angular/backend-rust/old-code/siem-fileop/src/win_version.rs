//! `get_win_version` / `get_release_from_build` (`shared/version_op.c`) and
//! the Windows `getuname` (`shared/file_op.c`).
//!
//! The registry reads use the same ANSI calls and buffer sizes as the C code
//! (so a computer name of 30 bytes or more fails the 30-byte read and
//! becomes "unknown", as it does there). `GetVersionEx` reports 6.2 to a
//! process without a compatibility manifest, which is how the C agent ends up
//! in the registry branch on Windows 8 and later.

use std::sync::OnceLock;

use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExA, RegQueryValueExA, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY,
};
use windows_sys::Win32::System::SystemInformation::{GetVersionExA, OSVERSIONINFOA, OSVERSIONINFOEXA};

use crate::version_op::{OsInfo, OSSEC_NAME, OSSEC_VERSION};

/// Log levels of the messages these functions print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Debug1,
    Debug2,
    Warn,
    Error,
}

type LogFn = Box<dyn Fn(Level, &str) + Send + Sync>;
static LOG: OnceLock<LogFn> = OnceLock::new();

/// Installs the daemon's logger for the messages of `get_win_version`.
pub fn set_logger(f: LogFn) {
    let _ = LOG.set(f);
}

fn log(l: Level, m: String) {
    if let Some(f) = LOG.get() {
        f(l, &m);
    }
}

/// `SK_REG_OPEN`
fn sk_reg_open(subkey: &str) -> String {
    format!("(1758): Unable to open registry key: '{subkey}'.")
}

struct Key(HKEY);

impl Key {
    fn open(subkey: &str) -> Option<Key> {
        let c = std::ffi::CString::new(subkey).ok()?;
        let mut h: HKEY = std::ptr::null_mut();
        // SAFETY: NUL-terminated subkey, out-pointer to an HKEY.
        let r = unsafe { RegOpenKeyExA(HKEY_LOCAL_MACHINE, c.as_ptr().cast(), 0, KEY_READ | KEY_WOW64_64KEY, &mut h) };
        (r == 0).then_some(Key(h))
    }

    /// `RegQueryValueEx(key, name, NULL, NULL, buf, &count)` with a buffer
    /// of `size` bytes: the C string read, or the error code.
    fn string(&self, name: &str, size: usize) -> Result<String, u32> {
        let c = std::ffi::CString::new(name).unwrap();
        let mut buf = vec![0u8; size];
        let mut count = size as u32;
        // SAFETY: buffer of `count` bytes.
        let r = unsafe {
            RegQueryValueExA(self.0, c.as_ptr().cast(), std::ptr::null(), std::ptr::null_mut(), buf.as_mut_ptr(), &mut count)
        };
        if r != 0 {
            return Err(r);
        }
        let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
    }

    /// A REG_DWORD read into a 4-byte variable.
    fn dword(&self, name: &str, count: u32) -> Result<u32, u32> {
        let c = std::ffi::CString::new(name).unwrap();
        let mut v: u32 = 0;
        let mut count = count;
        // SAFETY: the value is written into a u32 (count says how much room
        // the C code claims, as there).
        let r = unsafe {
            RegQueryValueExA(
                self.0,
                c.as_ptr().cast(),
                std::ptr::null(),
                std::ptr::null_mut(),
                (&mut v as *mut u32).cast(),
                &mut count,
            )
        };
        if r != 0 {
            Err(r)
        } else {
            Ok(v)
        }
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: a key we opened.
        unsafe { RegCloseKey(self.0) };
    }
}

/// `get_release_from_build`
pub fn get_release_from_build(os_build: Option<&str>) -> Option<String> {
    let b = os_build?;
    let r = match b {
        "10240" => "1507",
        "10586" => "1511",
        "14393" => "1607",
        "15063" => "1709",
        "17134" => "1803",
        "17763" => "1809",
        "18362" => "1903",
        "18363" => "1909",
        _ => {
            log(Level::Debug1, format!("The release associated with the {b} build is not recognized."));
            return None;
        }
    };
    Some(r.to_string())
}

fn atoi(s: &str) -> i64 {
    let t = s.trim_start();
    let (neg, t) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let n: i64 = t.bytes().take_while(u8::is_ascii_digit).fold(0, |a, d| a.wrapping_mul(10).wrapping_add((d - b'0') as i64));
    if neg {
        -n
    } else {
        n
    }
}

fn nul(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("(null)")
}

/// The `dwMajorVersion == 5 && dwMinorVersion == 2` names.
fn server_2003_name(osvi: &OSVERSIONINFOEXA) -> &'static str {
    use windows_sys::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};
    use windows_sys::Win32::UI::WindowsAndMessaging::GetSystemMetrics;
    // SAFETY: SYSTEM_INFO is plain data filled by the call.
    let si: SYSTEM_INFO = unsafe {
        let mut si = std::mem::zeroed();
        GetNativeSystemInfo(&mut si);
        si
    };
    // VER_NT_WORKSTATION, PROCESSOR_ARCHITECTURE_AMD64
    let arch = unsafe { si.Anonymous.Anonymous.wProcessorArchitecture };
    if osvi.wProductType == 1 && arch == 9 {
        "Microsoft Windows XP Professional x64 Edition"
    } else if unsafe { GetSystemMetrics(89) } != 0 {
        "Microsoft Windows Server 2003 R2"
    } else {
        "Microsoft Windows Server 2003"
    }
}

/// `get_win_version`
pub fn get_win_version() -> Option<OsInfo> {
    // SAFETY: OSVERSIONINFOEXA with its size set.
    let osvi = unsafe {
        let mut osvi: OSVERSIONINFOEXA = std::mem::zeroed();
        osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXA>() as u32;
        if GetVersionExA((&mut osvi as *mut OSVERSIONINFOEXA).cast::<OSVERSIONINFOA>()) == 0 {
            osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOA>() as u32;
            if GetVersionExA((&mut osvi as *mut OSVERSIONINFOEXA).cast::<OSVERSIONINFOA>()) == 0 {
                return None;
            }
        }
        osvi
    };
    let mut info = OsInfo { version: Some(format!("{}.{}", osvi.dwMajorVersion, osvi.dwMinorVersion)), ..Default::default() };
    const SIZE: u32 = 30;

    if osvi.dwMajorVersion == 6 {
        let subkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        match Key::open(subkey) {
            None => {
                log(Level::Error, sk_reg_open(subkey));
                info.os_name = Some("Microsoft Windows undefined version".into());
            }
            Some(k) => match k.string("ProductName", 1024) {
                Err(e) => {
                    log(Level::Error, format!("Error reading 'ProductName' from Windows registry. (Error {e})"));
                    info.os_name = Some("Microsoft Windows undefined version".into());
                }
                Ok(v) => {
                    // strcpy(temp, "Microsoft ") + strncat(temp, value, 1022)
                    let mut t = format!("Microsoft {v}");
                    let mut n = t.len().min(1023);
                    while !t.is_char_boundary(n) {
                        n -= 1;
                    }
                    t.truncate(n);
                    info.os_name = Some(t);
                }
            },
        }

        let key = Key::open(subkey);
        if key.is_none() {
            log(Level::Error, sk_reg_open(subkey));
        }
        // Windows 10
        let major = key.as_ref().map_or(Err(6), |k| k.dword("CurrentMajorVersionNumber", SIZE));
        if let Ok(win_major) = major {
            let k = key.as_ref().unwrap();
            match k.dword("CurrentMinorVersionNumber", SIZE) {
                Err(e) => log(Level::Error, format!("Error reading 'CurrentMinorVersionNumber' from Windows registry. (Error {e})")),
                Ok(win_minor) => {
                    info.os_major = Some(win_major.to_string());
                    info.os_minor = Some(win_minor.to_string());
                    match k.string("CurrentBuildNumber", SIZE as usize) {
                        Err(e) => log(Level::Error, format!("Error reading 'CurrentBuildNumber' from Windows registry. (Error {e})")),
                        Ok(wincomp) => {
                            let b = match k.dword("UBR", 4) {
                                Ok(ubr) => format!("{wincomp}.{ubr}"),
                                Err(_) => wincomp,
                            };
                            info.os_build = Some(b.chars().take(63).collect());
                        }
                    }
                }
            }
            match k.string("ReleaseId", 1024) {
                Err(e) => {
                    log(Level::Debug1, format!("Could not read the 'ReleaseId' key from Windows registry. (Error {e})"));
                    info.os_release = get_release_from_build(info.os_build.as_deref());
                }
                Ok(v) => info.os_release = Some(v),
            }
        } else if let Some(k) = key.as_ref() {
            // Windows 6.2 or 6.3
            match k.string("CurrentVersion", SIZE as usize) {
                Err(e) => log(Level::Error, format!("Error reading 'Current Version' from Windows registry. (Error {e})")),
                Ok(winver) => {
                    // OS_StrBreak('.', winver, 2)
                    let mut parts = winver.splitn(2, '.');
                    info.os_major = parts.next().map(str::to_string);
                    info.os_minor = parts.next().map(str::to_string);
                    match k.string("CurrentBuildNumber", SIZE as usize) {
                        Err(e) => log(Level::Error, format!("Error reading 'CurrentBuildNumber' from Windows registry. (Error {e})")),
                        Ok(b) => info.os_build = Some(b.chars().take(63).collect()),
                    }
                }
            }
        }
        drop(key);

        let v = format!("{}.{}.{}", nul(&info.os_major), nul(&info.os_minor), nul(&info.os_build));
        info.os_version = Some(v.chars().take(63).collect());

        // Windows 11 starts at build 22000
        if let Some(name) = info.os_name.as_mut() {
            if let Some(pos) = name.find("Windows 10") {
                if atoi(nul(&info.os_build)) >= 22000 {
                    name.replace_range(pos + 9..pos + 10, "1");
                }
            }
        }
    } else {
        let name = match (osvi.dwMajorVersion, osvi.dwMinorVersion) {
            (5, 0) => Some("Microsoft Windows 2000"),
            (5, 1) => Some("Microsoft Windows XP"),
            (5, 2) => Some(server_2003_name(&osvi)),
            (4, _) => match (osvi.dwPlatformId, osvi.dwMinorVersion) {
                (2, _) => Some("Microsoft Windows NT"),
                (1, 0) => Some("Microsoft Windows 95"),
                (1, 10) => Some("Microsoft Windows 98"),
                (1, 90) => Some("Microsoft Windows ME"),
                _ => None,
            },
            (5, _) => None,
            _ => Some("Microsoft Windows"),
        };
        info.os_name = name.map(str::to_string);
        let build = osvi.dwBuildNumber & 0xffff;
        info.os_major = Some(osvi.dwMajorVersion.to_string());
        info.os_minor = Some(osvi.dwMinorVersion.to_string());
        info.os_build = Some(build.to_string());
        info.os_version = Some(format!("{}.{}.{}", osvi.dwMajorVersion, osvi.dwMinorVersion, build));
    }

    // Service pack
    if info.os_release.is_none() {
        let subkey = "SYSTEM\\CurrentControlSet\\Control\\Windows";
        match Key::open(subkey) {
            None => log(Level::Error, sk_reg_open(subkey)),
            Some(k) => match k.dword("CSDVersion", 4) {
                Err(e) => log(Level::Error, format!("Error reading 'CSDVersion' from Windows registry. (Error {e})")),
                Ok(sp) => {
                    info.os_release = match sp {
                        256 => Some("sp1".into()),
                        512 => Some("sp2".into()),
                        768 => Some("sp3".into()),
                        1024 => Some("sp4".into()),
                        1280 => Some("sp5".into()),
                        1536 => Some("sp6".into()),
                        _ => {
                            log(Level::Debug2, format!("The value of CSDVersion is not a recognizable service pack.: {sp}."));
                            None
                        }
                    }
                }
            },
        }
    }
    // Architecture
    let subkey = "System\\CurrentControlSet\\Control\\Session Manager\\Environment";
    match Key::open(subkey) {
        None => log(Level::Error, sk_reg_open(subkey)),
        Some(k) => match k.string("PROCESSOR_ARCHITECTURE", 64) {
            Err(e) => log(Level::Error, format!("Error reading 'Architecture' from Windows registry. (Error {e})")),
            Ok(arch) => {
                if arch.starts_with("AMD64") || arch.starts_with("IA64") || arch.starts_with("ARM64") {
                    info.machine = Some("x86_64".into());
                } else if arch.starts_with("x86") {
                    info.machine = Some("i686".into());
                }
            }
        },
    }
    if info.machine.is_none() {
        info.machine = Some("unknown".into());
    }

    // Hostname (read into a 30-byte count, as in C)
    let subkey = "System\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName";
    match Key::open(subkey) {
        None => log(Level::Error, sk_reg_open(subkey)),
        Some(k) => match k.string("ComputerName", SIZE as usize) {
            Err(e) => log(Level::Error, format!("Error reading 'hostname' from Windows registry. (Error {e})")),
            Ok(n) => info.nodename = Some(n),
        },
    }
    if info.nodename.is_none() {
        info.nodename = Some("unknown".into());
    }
    Some(info)
}

/// `getuname()` (Windows): at most 1023 bytes, computed once.
pub fn getuname() -> &'static str {
    static U: OnceLock<String> = OnceLock::new();
    U.get_or_init(|| {
        let mut s = match get_win_version() {
            Some(i) => format!(
                "{} [Ver: {}] |{} |{} - {OSSEC_NAME} {OSSEC_VERSION}",
                i.os_name.as_deref().unwrap_or("Microsoft Windows"),
                i.os_version.as_deref().unwrap_or("unknown"),
                i.nodename.as_deref().unwrap_or("unknown"),
                i.machine.as_deref().unwrap_or("unknown"),
            ),
            None => format!("Microsoft Windows - {OSSEC_NAME} {OSSEC_VERSION}"),
        };
        let mut n = s.len().min(1023);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        s.truncate(n);
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uname_has_the_c_shape() {
        let u = getuname();
        println!("UNAME={u}");
        assert!(u.starts_with("Microsoft Windows"), "{u}");
        assert!(u.contains(" [Ver: "), "{u}");
        assert!(u.ends_with(" - Wazuh v4.14.7"), "{u}");
    }
}
