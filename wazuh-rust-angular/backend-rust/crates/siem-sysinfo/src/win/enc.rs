//! `encodingWindowsHelper.h`: ANSI / UTF-16 / UTF-8 conversions through
//! `MultiByteToWideChar` / `WideCharToMultiByte`, like the C++.

use windows_sys::Win32::Globalization::{MultiByteToWideChar, WideCharToMultiByte, CP_ACP, CP_UTF8};

fn to_wide(cp: u32, input: &[u8]) -> Vec<u16> {
    if input.is_empty() {
        return Vec::new();
    }
    // SAFETY: sizes come from the first call; buffers are owned.
    unsafe {
        let n = MultiByteToWideChar(cp, 0, input.as_ptr(), input.len() as i32, std::ptr::null_mut(), 0);
        if n <= 0 {
            return Vec::new();
        }
        let mut buf = vec![0u16; n as usize];
        if MultiByteToWideChar(cp, 0, input.as_ptr(), input.len() as i32, buf.as_mut_ptr(), n) > 0 {
            buf
        } else {
            Vec::new()
        }
    }
}

fn from_wide(cp: u32, input: &[u16]) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }
    // SAFETY: as above.
    unsafe {
        let n = WideCharToMultiByte(cp, 0, input.as_ptr(), input.len() as i32, std::ptr::null_mut(), 0, std::ptr::null(), std::ptr::null_mut());
        if n <= 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; n as usize];
        if WideCharToMultiByte(cp, 0, input.as_ptr(), input.len() as i32, buf.as_mut_ptr(), n, std::ptr::null(), std::ptr::null_mut()) > 0 {
            buf
        } else {
            Vec::new()
        }
    }
}

/// `wstringToStringAnsi`
pub fn wstring_to_ansi(w: &[u16]) -> Vec<u8> {
    from_wide(CP_ACP, w)
}

/// `wstringToStringUTF8`
pub fn wstring_to_utf8(w: &[u16]) -> Vec<u8> {
    from_wide(CP_UTF8, w)
}

/// `stringToWStringAnsi`
pub fn ansi_to_wstring(a: &[u8]) -> Vec<u16> {
    to_wide(CP_ACP, a)
}

/// `stringToWStringUTF8`
pub fn utf8_to_wstring(a: &[u8]) -> Vec<u16> {
    to_wide(CP_UTF8, a)
}

/// `stringAnsiToStringUTF8`
pub fn ansi_to_utf8(a: &[u8]) -> Vec<u8> {
    wstring_to_utf8(&ansi_to_wstring(a))
}

/// `stringUTF8ToStringAnsi`
pub fn utf8_to_ansi(a: &[u8]) -> Vec<u8> {
    wstring_to_ansi(&utf8_to_wstring(a))
}

/// A NUL-terminated wide string for the W APIs.
pub fn wz(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A NUL-terminated ANSI string for the A APIs (from UTF-8 source text,
/// which is ASCII in every key name the C++ uses).
pub fn az(s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    v.push(0);
    v
}

/// The text of a NUL-terminated wide buffer.
pub fn wide_cstr(w: &[u16]) -> &[u16] {
    &w[..w.iter().position(|&c| c == 0).unwrap_or(w.len())]
}

/// `std::wstring_convert<std::codecvt_utf8<wchar_t>>::to_bytes` (BstrToString):
/// UTF-16 code units encoded one by one as UTF-8 (wchar_t is 16 bits on
/// Windows, so surrogates are encoded individually).
pub fn codecvt_utf8(w: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(w.len());
    for &c in w {
        let c = c as u32;
        if c < 0x80 {
            out.push(c as u8);
        } else if c < 0x800 {
            out.push(0xC0 | (c >> 6) as u8);
            out.push(0x80 | (c & 0x3F) as u8);
        } else {
            out.push(0xE0 | (c >> 12) as u8);
            out.push(0x80 | ((c >> 6) & 0x3F) as u8);
            out.push(0x80 | (c & 0x3F) as u8);
        }
    }
    out
}

/// The variables a 32-bit (WOW64) process sees differently, with what it sees.
fn wow64_env(name: &str) -> Option<String> {
    let get = |n: &str| std::env::var(n).ok();
    match name.to_ascii_lowercase().as_str() {
        "programfiles" => get("ProgramFiles(x86)"),
        "commonprogramfiles" => get("CommonProgramFiles(x86)"),
        "processor_architecture" => Some("x86".into()),
        "processor_architew6432" => get("PROCESSOR_ARCHITECTURE"),
        _ => None,
    }
}

/// `ExpandEnvironmentStringsW` as the 32-bit agent gets it: the WOW64
/// values of `%ProgramFiles%` and friends, the process environment for the
/// rest. None when the API fails.
pub fn expand_env_w32(input: &[u16]) -> Option<Vec<u16>> {
    use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
    // %NAME% references of the WOW64 variables first
    let text = String::from_utf16_lossy(input);
    let mut pre = String::new();
    let mut rest = text.as_str();
    while let Some(a) = rest.find('%') {
        let Some(b) = rest[a + 1..].find('%') else { break };
        let name = &rest[a + 1..a + 1 + b];
        pre.push_str(&rest[..a]);
        if let Some(v) = wow64_env(name) {
            pre.push_str(&v);
            rest = &rest[a + b + 2..];
        } else if std::env::var_os(name).is_some() {
            // a defined variable consumes both '%' (the API expands it)
            pre.push_str(&rest[a..a + b + 2]);
            rest = &rest[a + b + 2..];
        } else {
            // undefined: kept, and its closing '%' may open the next one
            pre.push_str(&rest[a..a + 1 + b]);
            rest = &rest[a + 1 + b..];
        }
    }
    pre.push_str(rest);
    let mut z: Vec<u16> = pre.encode_utf16().collect();
    z.push(0);
    // SAFETY: NUL-terminated input; the output is sized by the first call.
    unsafe {
        let n = ExpandEnvironmentStringsW(z.as_ptr(), std::ptr::null_mut(), 0);
        if n == 0 {
            return None;
        }
        let mut out = vec![0u16; n as usize];
        if ExpandEnvironmentStringsW(z.as_ptr(), out.as_mut_ptr(), n) == 0 {
            return None;
        }
        out.pop();
        Some(out)
    }
}
