//! The C runtime calls wm_sca makes, through the CRT the C agent links
//! (msvcrt + mingwex on Windows, glibc on Linux): number conversions, `stat`,
//! `opendir`, `strerror` and local time behave and read the same.

use std::ffi::{c_char, c_int, c_long, CStr, CString};

/// The bytes up to the first NUL, as a C string.
pub fn cstring(b: &[u8]) -> CString {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    CString::new(&b[..n]).unwrap_or_default()
}

#[cfg(windows)]
extern "C" {
    fn _errno() -> *mut c_int;
    #[link_name = "_mktime64"]
    fn crt_mktime(tm: *mut libc::tm) -> i64;
}

/// `errno`
pub fn errno() -> i32 {
    #[cfg(windows)]
    // SAFETY: msvcrt's per-thread errno.
    unsafe {
        *_errno()
    }
    #[cfg(unix)]
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `errno = e`
pub fn set_errno(e: i32) {
    // SAFETY: the CRT's per-thread errno.
    #[cfg(windows)]
    unsafe {
        *_errno() = e
    }
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = e
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    let _ = e;
}

/// `strerror(e)`
pub fn strerror(e: i32) -> String {
    // SAFETY: the CRT returns a static string.
    unsafe { CStr::from_ptr(libc::strerror(e)).to_string_lossy().into_owned() }
}

/// `strtod(s, &end)`: the value and the bytes consumed.
pub fn strtod(s: &[u8]) -> (f64, usize) {
    let c = cstring(s);
    let mut end: *mut c_char = std::ptr::null_mut();
    // SAFETY: NUL-terminated input; end points into it.
    let v = unsafe { libc::strtod(c.as_ptr(), &mut end) };
    (v, end as usize - c.as_ptr() as usize)
}

/// `errno = 0; strtol(s, &end, 10)`: the value (a C `long`), the bytes
/// consumed and the `errno` left.
pub fn strtol(s: &[u8]) -> (c_long, usize, i32) {
    let c = cstring(s);
    let mut end: *mut c_char = std::ptr::null_mut();
    set_errno(0);
    // SAFETY: as above.
    let v = unsafe { libc::strtol(c.as_ptr(), &mut end, 10) };
    (v, end as usize - c.as_ptr() as usize, errno())
}

/// `strtoul(s, &end, 0)` (a C `unsigned long`) and the bytes consumed.
pub fn strtoul0(s: &[u8]) -> (std::ffi::c_ulong, usize) {
    let c = cstring(s);
    let mut end: *mut c_char = std::ptr::null_mut();
    // SAFETY: as above.
    let v = unsafe { libc::strtoul(c.as_ptr(), &mut end, 0) };
    (v, end as usize - c.as_ptr() as usize)
}

/// `atoi(s)`
pub fn atoi(s: &[u8]) -> i32 {
    let c = cstring(s);
    // SAFETY: NUL-terminated input.
    unsafe { libc::atoi(c.as_ptr()) }
}

/// `stat(path).st_mode`, or the `errno` it fails with.
pub fn stat_mode(path: &[u8]) -> Result<u32, i32> {
    let c = cstring(path);
    // SAFETY: an out-buffer of the platform's struct stat.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::stat(c.as_ptr(), &mut st) == 0 {
            Ok(st.st_mode as u32)
        } else {
            Err(errno())
        }
    }
}

pub const S_IFMT: u32 = libc::S_IFMT as u32;
pub const S_IFREG: u32 = libc::S_IFREG as u32;
pub const S_IFDIR: u32 = libc::S_IFDIR as u32;

/// `opendir` + every `readdir` name + `closedir`, or the `errno` of
/// `opendir`.
pub fn read_dir(path: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
    #[cfg(windows)]
    {
        let lossy = String::from_utf8_lossy(path);
        let entries = match std::fs::read_dir(lossy.as_ref()) {
            Ok(rd) => rd,
            Err(e) => return Err(e.raw_os_error().unwrap_or(3)),
        };
        let mut names = Vec::new();
        for entry in entries.flatten() {
            names.push(entry.file_name().to_string_lossy().as_bytes().to_vec());
        }
        Ok(names)
    }
    #[cfg(unix)]
    {
        let c = cstring(path);
        let mut names = Vec::new();
        // SAFETY: a DIR stream opened and closed here; each entry is read before the next call.
        unsafe {
            let d = libc::opendir(c.as_ptr());
            if d.is_null() {
                return Err(errno());
            }
            loop {
                let e = libc::readdir(d);
                if e.is_null() {
                    break;
                }
                names.push(CStr::from_ptr((*e).d_name.as_ptr()).to_bytes().to_vec());
            }
            libc::closedir(d);
        }
        Ok(names)
    }
}

/// `localtime_r(t)`
pub fn localtime(t: i64) -> libc::tm {
    // SAFETY: plain conversions into a zeroed struct tm.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let tt = t as libc::time_t;
        #[cfg(windows)]
        libc::localtime_s(&mut tm, &tt);
        #[cfg(unix)]
        libc::localtime_r(&tt, &mut tm);
        tm
    }
}

/// `mktime(tm)` (normalizes `tm`)
pub fn mktime(tm: &mut libc::tm) -> i64 {
    // SAFETY: a valid struct tm.
    unsafe {
        #[cfg(windows)]
        return crt_mktime(tm);
        #[cfg(unix)]
        return libc::mktime(tm) as i64;
    }
}

/// `time(NULL)`
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
