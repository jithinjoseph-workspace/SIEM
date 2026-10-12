//! `Utils::Registry` (registryHelper.h), on the ANSI registry API like
//! the C++. Opening a key without a `KEY_WOW64_*` flag reads the 32-bit
//! view, as the 32-bit `sysinfo.dll` of the Windows agent does.

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FILETIME};
use windows_sys::Win32::System::Registry::*;

use super::enc;

pub use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_ENUMERATE_SUB_KEYS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
};

/// A `std::system_error` / `std::runtime_error` from the helper.
#[derive(Debug, Clone)]
pub struct RegError(pub String);

pub type R<T> = Result<T, RegError>;

/// The view a key opened without `KEY_WOW64_*` gets in a 32-bit process.
const DEFAULT_VIEW: u32 = KEY_WOW64_32KEY;

fn with_view(access: u32) -> u32 {
    if access & (KEY_WOW64_32KEY | KEY_WOW64_64KEY) == 0 {
        access | DEFAULT_VIEW
    } else {
        access
    }
}

pub struct Registry {
    key: HKEY,
}

impl Drop for Registry {
    fn drop(&mut self) {
        if !self.key.is_null() {
            // SAFETY: a key this object opened.
            unsafe { RegCloseKey(self.key) };
        }
    }
}

impl Registry {
    /// `Registry(key, subKey, access = KEY_READ)`
    pub fn open(key: HKEY, sub_key: &str, access: u32) -> R<Registry> {
        let mut ret: HKEY = std::ptr::null_mut();
        let sk = enc::az(&enc::utf8_to_ansi(sub_key.as_bytes()));
        // SAFETY: valid NUL-terminated name and out pointer.
        let r = unsafe { RegOpenKeyExA(key, sk.as_ptr(), 0, with_view(access), &mut ret) };
        if r != ERROR_SUCCESS {
            return Err(RegError(format!("Error opening registry: {sub_key}")));
        }
        Ok(Registry { key: ret })
    }

    /// `Registry(key, subKey)` (KEY_READ)
    pub fn read(key: HKEY, sub_key: &str) -> R<Registry> {
        Self::open(key, sub_key, KEY_READ)
    }

    fn query(&self, name: &str, buf: Option<&mut [u8]>, size: &mut u32, ty: Option<&mut u32>) -> u32 {
        let n = enc::az(name.as_bytes());
        let p = buf.map(|b| b.as_mut_ptr()).unwrap_or(std::ptr::null_mut());
        let t = ty.map(|t| t as *mut u32).unwrap_or(std::ptr::null_mut());
        // SAFETY: the buffer (when given) holds `size` bytes.
        unsafe { RegQueryValueExA(self.key, n.as_ptr(), std::ptr::null(), t, p, size) }
    }

    /// `dword(valueName)`: the value or an error.
    pub fn dword(&self, name: &str) -> R<u32> {
        let mut v = [0u8; 4];
        let mut size = 4u32;
        let r = self.query(name, Some(&mut v), &mut size, None);
        if r != ERROR_SUCCESS {
            return Err(RegError(format!("Error reading DWORD value of: {name}")));
        }
        Ok(u32::from_le_bytes(v))
    }

    /// `dword(valueName, value)`
    pub fn dword_opt(&self, name: &str) -> Option<u32> {
        let mut v = [0u8; 4];
        let mut size = 4u32;
        (self.query(name, Some(&mut v), &mut size, None) == ERROR_SUCCESS).then(|| u32::from_le_bytes(v))
    }

    /// `qword(valueName, value)`: Err when the read fails, Ok(None) when not a REG_QWORD.
    pub fn qword(&self, name: &str) -> R<Option<u64>> {
        let mut v = [0u8; 8];
        let mut size = 8u32;
        let mut ty = 0u32;
        let r = self.query(name, Some(&mut v), &mut size, Some(&mut ty));
        if r != ERROR_SUCCESS {
            return Err(RegError(format!("Error reading the value of: {name}")));
        }
        Ok((ty == REG_QWORD).then(|| u64::from_le_bytes(v)))
    }

    /// `string(valueName)`: the raw (ANSI) bytes up to the first NUL.
    pub fn string_raw(&self, name: &str) -> R<Vec<u8>> {
        let mut size = 0u32;
        if self.query(name, None, &mut size, None) != ERROR_SUCCESS {
            return Err(RegError(format!("Error reading the size of: {name}")));
        }
        let mut buf = vec![0u8; size as usize];
        if self.query(name, Some(&mut buf), &mut size, None) != ERROR_SUCCESS {
            return Err(RegError(format!("Error reading String value of: {name}")));
        }
        buf.truncate((size as usize).min(buf.len()));
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        buf.truncate(end);
        Ok(buf)
    }

    /// `string(valueName)` (throws) as text: the ANSI bytes as the C++
    /// `std::string` holds them, lossily shown as UTF-8.
    pub fn string(&self, name: &str) -> R<String> {
        self.string_raw(name).map(|b| String::from_utf8_lossy(&enc::ansi_to_utf8(&b)).into_owned())
    }

    /// `string(valueName, value)`: ANSI converted to UTF-8, or None.
    pub fn string_opt(&self, name: &str) -> Option<Vec<u8>> {
        self.string_raw(name).ok().map(|b| enc::ansi_to_utf8(&b))
    }

    /// `string(valueName, value)` as a String.
    pub fn string_opt_s(&self, name: &str) -> Option<String> {
        self.string_opt(name).map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    /// `enumerate()`: the subkey names (ANSI bytes; at most 254 chars).
    pub fn enumerate_raw(&self) -> R<Vec<Vec<u8>>> {
        let mut ret = Vec::new();
        let mut buf = [0u8; 255];
        let mut index = 0u32;
        loop {
            let mut size = 255u32;
            // SAFETY: the buffer holds `size` bytes.
            let r = unsafe {
                RegEnumKeyExA(
                    self.key,
                    index,
                    buf.as_mut_ptr(),
                    &mut size,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if r != ERROR_SUCCESS {
                if r != ERROR_NO_MORE_ITEMS {
                    return Err(RegError("Error enumerating registry.".into()));
                }
                break;
            }
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            ret.push(buf[..end].to_vec());
            index += 1;
        }
        Ok(ret)
    }

    /// `enumerate()` as Strings (key names are passed back to the A API, so
    /// they stay in the ANSI code page; shown lossily).
    pub fn enumerate(&self) -> R<Vec<String>> {
        self.enumerate_raw().map(|v| v.into_iter().map(|b| String::from_utf8_lossy(&enc::ansi_to_utf8(&b)).into_owned()).collect())
    }

    /// `enumerate(callback)`: the callback runs for each subkey as it is
    /// read; an enumeration error comes after the keys already seen.
    pub fn enumerate_cb(&self, mut f: impl FnMut(&str) -> R<()>) -> R<()> {
        let mut buf = [0u8; 255];
        let mut index = 0u32;
        loop {
            let mut size = 255u32;
            // SAFETY: as above.
            let r = unsafe {
                RegEnumKeyExA(
                    self.key,
                    index,
                    buf.as_mut_ptr(),
                    &mut size,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if r != ERROR_SUCCESS {
                if r != ERROR_NO_MORE_ITEMS {
                    return Err(RegError("Error enumerating registry.".into()));
                }
                return Ok(());
            }
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            let name = String::from_utf8_lossy(&enc::ansi_to_utf8(&buf[..end])).into_owned();
            f(&name)?;
            index += 1;
        }
    }

    /// `enumerateValueKey()`
    pub fn enumerate_value_key(&self) -> R<Vec<String>> {
        let mut ret = Vec::new();
        let mut buf = vec![0u8; 32767];
        let mut index = 0u32;
        loop {
            let mut size = 32767u32;
            // SAFETY: as above.
            let r = unsafe {
                RegEnumValueA(
                    self.key,
                    index,
                    buf.as_mut_ptr(),
                    &mut size,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if r != ERROR_SUCCESS {
                if r != ERROR_NO_MORE_ITEMS {
                    return Err(RegError("Error enumerating Values in registry.".into()));
                }
                break;
            }
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            ret.push(String::from_utf8_lossy(&enc::ansi_to_utf8(&buf[..end])).into_owned());
            index += 1;
        }
        Ok(ret)
    }

    /// `keyModificationDate()`: "YYYY/MM/DD hh:mm:ss" (UTC), "" on error.
    pub fn key_modification_date(&self) -> String {
        let mut ft = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        // SAFETY: only the last-write-time out pointer is set.
        let r = unsafe {
            RegQueryInfoKeyA(
                self.key,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut ft,
            )
        };
        if r == ERROR_SUCCESS {
            super::helpers::build_timestamp(((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64)
        } else {
            String::new()
        }
    }
}

/// `Utils::expandRegistryPath`
pub fn expand_registry_path(key: HKEY, sub_key: &str, out: &mut Vec<String>) -> R<()> {
    let wildcard = sub_key.find(['*', '?']);
    let Some(wp) = wildcard else {
        out.push(sub_key.to_string());
        return Ok(());
    };
    let next_dir = sub_key[wp..].find('\\').map(|p| p + wp);
    let parent = if wp == 0 { Some(0) } else { sub_key[..=wp].rfind('\\') };
    let Some(parent) = parent else {
        return Err(RegError(format!("Invalid path: {sub_key}")));
    };
    let base_dir = if wp == 0 { String::new() } else { sub_key[..parent].to_string() };
    let pstart = if parent == 0 { 0 } else { parent + 1 };
    let pattern = match next_dir {
        Some(n) => &sub_key[pstart..n],
        None => &sub_key[pstart..],
    };
    if let Ok(reg) = Registry::open(key, &base_dir, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY) {
        if let Ok(entries) = reg.enumerate() {
            for entry in entries {
                let entry_name = if base_dir.is_empty() { entry.clone() } else { format!("\\{entry}") };
                if crate::strings::pattern_match(&entry_name, pattern) {
                    let rest = next_dir.map(|n| &sub_key[n..]).unwrap_or("");
                    let _ = expand_registry_path(key, &format!("{base_dir}{entry_name}{rest}"), out);
                }
            }
        }
    }
    Ok(())
}
