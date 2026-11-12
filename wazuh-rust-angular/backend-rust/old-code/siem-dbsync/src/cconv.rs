//! `std::stoi` / `std::stoll` / `std::stoull` / `std::stod` (libstdc++'s
//! `__stoa` over the C library's `strtol` family) and `std::to_string`.

use std::ffi::CString;

use crate::error::{Error, R};

extern "C" {
    fn strtol(s: *const libc::c_char, end: *mut *mut libc::c_char, base: libc::c_int) -> libc::c_long;
    fn strtoll(s: *const libc::c_char, end: *mut *mut libc::c_char, base: libc::c_int) -> libc::c_longlong;
    fn strtoull(s: *const libc::c_char, end: *mut *mut libc::c_char, base: libc::c_int) -> libc::c_ulonglong;
    fn strtod(s: *const libc::c_char, end: *mut *mut libc::c_char) -> libc::c_double;
}

#[cfg(target_os = "linux")]
fn errno_ptr() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
fn errno_ptr() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

#[cfg(windows)]
fn errno_ptr() -> *mut libc::c_int {
    extern "C" {
        fn _errno() -> *mut libc::c_int;
    }
    unsafe { _errno() }
}

const ERANGE: libc::c_int = 34;

/// The `std::string`'s `c_str()`.
fn c(s: &[u8]) -> CString {
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    CString::new(&s[..end]).unwrap()
}

/// `__stoa(conv, name, str)`: the value, `invalid_argument(name)` when
/// nothing converts, `out_of_range(name)` on ERANGE.
fn stoa<T>(s: &[u8], name: &str, conv: impl FnOnce(*const libc::c_char, *mut *mut libc::c_char) -> T) -> R<T> {
    let cs = c(s);
    let saved = unsafe { *errno_ptr() };
    unsafe { *errno_ptr() = 0 };
    let mut end: *mut libc::c_char = std::ptr::null_mut();
    let v = conv(cs.as_ptr(), &mut end);
    let e = unsafe { *errno_ptr() };
    if e == 0 {
        unsafe { *errno_ptr() = saved };
    }
    if end as *const libc::c_char == cs.as_ptr() {
        return Err(Error::std(name));
    }
    if e == ERANGE {
        return Err(Error::std(name));
    }
    Ok(v)
}

/// `std::stoll(s)`
pub fn stoll(s: &[u8]) -> R<i64> {
    stoa(s, "stoll", |p, e| unsafe { strtoll(p, e, 10) } as i64)
}

/// `std::stoull(s)`
pub fn stoull(s: &[u8]) -> R<u64> {
    stoa(s, "stoull", |p, e| unsafe { strtoull(p, e, 10) } as u64)
}

/// `std::stoi(s)`: `strtol` plus the int range check.
pub fn stoi(s: &[u8]) -> R<i32> {
    let v = stoa(s, "stoi", |p, e| unsafe { strtol(p, e, 10) } as i64)?;
    if v < i32::MIN as i64 || v > i32::MAX as i64 {
        return Err(Error::std("stoi"));
    }
    Ok(v as i32)
}

/// `std::stod(s)`
pub fn stod(s: &[u8]) -> R<f64> {
    stoa(s, "stod", |p, e| unsafe { strtod(p, e) })
}

/// `std::to_string(double)` (`%f`).
pub fn double_to_string(d: f64) -> String {
    if d.is_nan() {
        return if d.is_sign_negative() { "-nan".into() } else { "nan".into() };
    }
    if d.is_infinite() {
        return if d < 0.0 { "-inf".into() } else { "inf".into() };
    }
    format!("{d:.6}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions() {
        assert_eq!(stoll(b" 42abc").unwrap(), 42);
        assert_eq!(stoll(b"abc"), Err(Error::std("stoll")));
        assert_eq!(stoll(b"99999999999999999999"), Err(Error::std("stoll")));
        assert_eq!(stoull(b"-1").unwrap(), u64::MAX);
        assert_eq!(stoi(b"4294967296"), Err(Error::std("stoi")));
        assert_eq!(stod(b"1.5x").unwrap(), 1.5);
        assert_eq!(stod(b"1e-400"), Err(Error::std("stod")));
        assert_eq!(double_to_string(1.5), "1.500000");
        assert_eq!(double_to_string(-0.0), "-0.000000");
    }
}
