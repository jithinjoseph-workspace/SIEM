//! The `r:` rules (`wm_sca_is_registry`, `wm_sca_os_winreg_getkey`,
//! `wm_sca_test_key`, `wm_sca_winreg_querykey`): the ANSI registry API with
//! the C buffers and sizes, so truncation and `ERROR_MORE_DATA` cases match.

use siem_regex::ExpType;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Debug::{FormatMessageA, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS};
/// `FORMAT_MESSAGE_MAX_WIDTH_MASK` (not exported by windows-sys)
const FORMAT_MESSAGE_MAX_WIDTH_MASK: u32 = 0xFF;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumValueA, RegOpenKeyExA, RegQueryInfoKeyA, HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ,
};

use crate::check::{cat, cs, Engine, RETURN_FOUND, RETURN_INVALID, RETURN_NOT_FOUND};

/// `MAX_VALUE_NAME`
const MAX_VALUE_NAME: usize = 16383;
/// `MAX_PATH`
const MAX_PATH: usize = 260;

/// `FormatMessage(FROM_SYSTEM | IGNORE_INSERTS | MAX_WIDTH_MASK, err)` into
/// a 1024-byte buffer.
fn format_message(err: u32) -> Vec<u8> {
    let mut buf = [0u8; 1025];
    // SAFETY: the buffer and its size.
    unsafe {
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            std::ptr::null(),
            err,
            1 << 10, // MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
            buf.as_mut_ptr(),
            1024,
            std::ptr::null(),
        );
    }
    cs(&buf).to_vec()
}

/// `wm_sca_os_winreg_getkey`: the hive and the subkey (None when empty).
fn winreg_getkey(entry: &[u8]) -> (Option<HKEY>, Option<&[u8]>) {
    let (tree, rest) = match entry.iter().position(|&c| c == b'\\') {
        Some(i) => (&entry[..i], Some(&entry[i + 1..])),
        None => (entry, None),
    };
    let hive = match tree {
        b"HKEY_LOCAL_MACHINE" | b"HKLM" => HKEY_LOCAL_MACHINE,
        b"HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
        b"HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG,
        b"HKEY_USERS" => HKEY_USERS,
        b"HKCU" | b"HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        _ => return (None, None),
    };
    (Some(hive), rest.filter(|r| !r.is_empty()))
}

impl Engine<'_> {
    /// `wm_sca_is_registry`
    pub fn is_registry(&mut self, entry: &[u8], option: Option<&[u8]>, value: Option<&[u8]>, exp: ExpType) -> i32 {
        let (hive, rk) = winreg_getkey(entry);
        let (Some(hive), Some(rk)) = (hive, rk) else {
            self.set_reason(cat(&[b"Invalid registry entry: '", entry, b"'"]));
            self.error(cat(&[b"Invalid registry entry: '", entry, b"'"]));
            return RETURN_INVALID;
        };
        let r64 = self.test_key(hive, rk, entry, KEY_WOW64_64KEY, option, value, exp);
        let r32 = if r64 != RETURN_FOUND { self.test_key(hive, rk, entry, KEY_WOW64_32KEY, option, value, exp) } else { RETURN_NOT_FOUND };
        if r32 == RETURN_INVALID && r64 == RETURN_INVALID {
            RETURN_INVALID
        } else if r32 == RETURN_FOUND || r64 == RETURN_FOUND {
            RETURN_FOUND
        } else {
            RETURN_NOT_FOUND
        }
    }

    /// `wm_sca_test_key`
    #[allow(clippy::too_many_arguments)]
    fn test_key(&mut self, hive: HKEY, subkey: &[u8], full: &[u8], arch: u32, option: Option<&[u8]>, value: Option<&[u8]>, exp: ExpType) -> i32 {
        self.d2(cat(&[b"Checking '", full, b"' in the ", if arch == KEY_WOW64_64KEY { b"64" } else { b"32" }, b"BIT subsystem."]));
        let sk = crate::crt::cstring(subkey);
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: NUL-terminated subkey; the key is closed below.
        let err = unsafe { RegOpenKeyExA(hive, sk.as_ptr() as *const u8, 0, KEY_READ | arch, &mut key) };
        if err == ERROR_ACCESS_DENIED {
            self.set_reason(cat(&[b"Access denied for registry '", full, b"'"]));
            self.error(cat(&[b"Access denied for registry '", full, b"'"]));
            return RETURN_INVALID;
        } else if err != ERROR_SUCCESS {
            let em = format_message(err);
            self.d2(cat(&[b"Unable to read registry '", full, b"': ", &em]));
            let Some(_) = option else {
                self.d2(cat(&[b"Registry '", full, b"' not found."]));
                return RETURN_NOT_FOUND;
            };
            self.set_reason(cat(&[b"Unable to read registry '", full, b"' (", &em, b")"]));
            return RETURN_INVALID;
        }
        let r = match option {
            Some(o) => self.winreg_querykey(key, full, o, value, exp),
            None => RETURN_FOUND,
        };
        // SAFETY: opened above.
        unsafe { RegCloseKey(key) };
        r
    }

    /// `wm_sca_winreg_querykey`
    fn winreg_querykey(&mut self, key: HKEY, full: &[u8], option: &[u8], value: Option<&[u8]>, exp: ExpType) -> i32 {
        let mut class_name = [0u8; MAX_PATH + 1];
        let mut class_s = MAX_PATH as u32;
        let (mut subkey_count, mut value_count) = (0u32, 0u32);
        // SAFETY: the C buffers and sizes.
        let rc = unsafe {
            RegQueryInfoKeyA(
                key,
                class_name.as_mut_ptr(),
                &mut class_s,
                std::ptr::null(),
                &mut subkey_count,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut value_count,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS {
            let em = format_message(rc);
            self.set_reason(cat(&[b"Unable to read registry '", full, b"' (", &em, b")"]));
            self.d2(cat(&[b"Unable to read registry '", full, b"': ", &em]));
            return RETURN_INVALID;
        }
        if value_count > 0 {
            let mut value_buffer = vec![0u8; MAX_VALUE_NAME + 1];
            let mut data_buffer = vec![0u8; MAX_VALUE_NAME + 1];
            let mut var_storage = vec![0u8; MAX_VALUE_NAME + 1];
            let mut data_type = 0u32;
            for i in 0..value_count {
                let mut value_size = MAX_VALUE_NAME as u32;
                let mut data_size = MAX_VALUE_NAME as u32;
                value_buffer[0] = 0;
                data_buffer[0] = 0;
                var_storage[0] = 0;
                // SAFETY: the C buffers and sizes.
                let rc = unsafe {
                    RegEnumValueA(key, i, value_buffer.as_mut_ptr(), &mut value_size, std::ptr::null(), &mut data_type, data_buffer.as_mut_ptr(), &mut data_size)
                };
                if rc != ERROR_SUCCESS && rc != ERROR_NO_MORE_ITEMS {
                    let em = format_message(rc);
                    self.set_reason(cat(&[b"Unable to enumerate values of registry '", full, b"' (", &em, b")"]));
                    self.d2(cat(&[b"Unable to enumerate values of registry '", full, b"' -> RETURN_INVALID"]));
                    return RETURN_INVALID;
                }
                if value_buffer[0] == 0 {
                    value_buffer[0] = b'@';
                    value_buffer[1] = 0;
                }
                let name = cs(&value_buffer).to_vec();
                if !name.eq_ignore_ascii_case(option) {
                    self.d2(cat(&[b"Considering value '", full, b"' -> '", &name, b"' != '", option, b"': Skipping value."]));
                    continue;
                }
                self.d2(cat(&[b"Considering value '", full, b"' -> '", &name, b"' == '", option, b"': Value found."]));
                let Some(value) = value else {
                    self.d2(cat(&[b"No value data especified. Existence check for '", full, b"': 1"]));
                    return RETURN_FOUND;
                };
                let mut vs: Vec<u8> = Vec::new();
                match data_type {
                    REG_SZ | REG_EXPAND_SZ => {
                        // snprintf(var_storage, MAX_VALUE_NAME, "%s", data_buffer)
                        vs = cs(&data_buffer).to_vec();
                        vs.truncate(MAX_VALUE_NAME - 1);
                    }
                    REG_MULTI_SZ => {
                        let mut size_available = MAX_VALUE_NAME as isize;
                        let mut p = 0usize;
                        while p < data_buffer.len() && data_buffer[p] != 0 {
                            let s = cs(&data_buffer[p..]);
                            if size_available >= s.len() as isize + 1 {
                                vs.extend_from_slice(s);
                                size_available -= s.len() as isize;
                                vs.push(b' ');
                                size_available -= 1;
                            }
                            p += s.len() + 1;
                        }
                    }
                    REG_DWORD => {
                        vs = u32::from_le_bytes([data_buffer[0], data_buffer[1], data_buffer[2], data_buffer[3]]).to_string().into_bytes();
                    }
                    _ => {
                        let mut size_available = MAX_VALUE_NAME as isize - 2;
                        for &c in &data_buffer[..data_size as usize] {
                            // "%02x" of (unsigned int) of a signed char
                            let t = format!("{:02x}", c as i8 as i32 as u32);
                            if size_available > 2 {
                                let n = t.len().min(size_available as usize);
                                vs.extend_from_slice(&t.as_bytes()[..n]);
                                size_available = MAX_VALUE_NAME as isize - (vs.len() as isize + 2);
                            }
                        }
                    }
                }
                self.d2(cat(&[b"Checking value data '", &vs, b"' with rule '", value, b"'"]));
                return self.pattern_matches(&vs, value, exp);
            }
        }
        if value.is_some() {
            self.set_reason(cat(&[b"Key '", option, b"' not found for registry '", full, b"'"]));
            return RETURN_INVALID;
        }
        RETURN_NOT_FOUND
    }
}
