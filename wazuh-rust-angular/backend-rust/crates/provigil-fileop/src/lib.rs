//! File helpers: shared-configuration bundles (merged.mg), directory cleaning, temporary files,
//! Windows text-mode I/O (`crt`) and the operating-system description (`version_op`).

pub mod crt;
pub mod version_op;
pub mod win_version;

use md5::{Digest, Md5};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, OnceLock};

/// Receives this crate's messages: (level "ERROR" | "WARNING" | "DEBUG2", text).
pub type LogFn = Arc<dyn Fn(&str, &str) + Send + Sync>;

static LOGGER: OnceLock<LogFn> = OnceLock::new();

/// Sends this crate's messages to the daemon's log; the first call wins.
pub fn set_logger(log: LogFn) {
    let _ = LOGGER.set(log);
}

#[derive(Clone, Copy, PartialEq)]
enum Lvl {
    Error,
    Warn,
    Debug2,
}

fn log(lvl: Lvl, msg: &str) {
    let Some(w) = LOGGER.get() else {
        match lvl {
            Lvl::Error => tracing::error!("{msg}"),
            Lvl::Warn => tracing::warn!("{msg}"),
            Lvl::Debug2 => tracing::debug!("{msg}"),
        }
        return;
    };
    let level = match lvl {
        Lvl::Error => "ERROR",
        Lvl::Warn => "WARNING",
        Lvl::Debug2 => "DEBUG2",
    };
    w(level, msg);
}

/// POSIX `dirname` over `/`-separated text.
pub fn dirname(path: &str) -> String {
    let t = path.trim_end_matches('/');
    if t.is_empty() {
        return if path.is_empty() { "." } else { "/" }.into();
    }
    match t.rfind('/') {
        None => ".".into(),
        Some(i) => match t[..i].trim_end_matches('/') {
            "" => "/".into(),
            d => d.into(),
        },
    }
}

/// Where the bundle name of `file` starts: after its directory and the slash.
pub fn default_path_offset(file: &str) -> usize {
    let d = dirname(file);
    d.len() + usize::from(!d.ends_with('/'))
}

/// True when the path has a `..` component (on Windows `\` is a separator too).
pub fn ref_parent_folder(path: &str) -> bool {
    let seps: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    let ends_component = |rest: &str| rest.is_empty() || rest.starts_with(seps);
    if path.strip_prefix("..").is_some_and(ends_component) {
        return true;
    }
    let mut last = 0;
    while let Some(i) = path[last..].find("/..").map(|i| last + i) {
        if ends_component(&path[i + 3..]) {
            return true;
        }
        last = i + 1;
    }
    // `\..` is only looked for after the last `/..` (the old search order; vectors depend on it).
    cfg!(windows) && path[last..].match_indices("\\..").any(|(i, _)| ends_component(&path[last + i + 3..]))
}

/// Appends `!<size> <name>\n<content>`; `name` is `file` from `path_offset` on.
pub fn merge_append_file(out: &mut Vec<u8>, file: &str, path_offset: Option<usize>) -> bool {
    let content = match fs::read(file) {
        Ok(c) => c,
        Err(e) => {
            log(Lvl::Error, &format!("Unable to open file: '{file}' due to [({})-({e})].", wfopen_errno(&e)));
            return false;
        }
    };
    if content.is_empty() {
        log(Lvl::Warn, &format!("File '{file}' is empty."));
    }
    let off = path_offset.unwrap_or_else(|| default_path_offset(file));
    out.extend_from_slice(format!("!{} ", content.len()).as_bytes());
    // An offset past the end or inside a character gives an empty name.
    out.extend_from_slice(file.get(off..).unwrap_or_default().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(&content);
    true
}

/// Splits `data` at `pos` into a line piece of at most `max` bytes (newline included).
fn piece(data: &[u8], pos: usize, max: usize) -> &[u8] {
    let rest = &data[pos..];
    let lim = rest.len().min(max);
    let n = rest[..lim].iter().position(|&b| b == b'\n').map_or(lim, |i| i + 1);
    &rest[..n]
}

/// True when a newline-ended line (read in 64 KiB pieces) holds a NUL, or the file is unreadable.
pub fn check_binary_file(path: &str) -> bool {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            log(Lvl::Error, &format!("Unable to open file '{path}' due to [({})-({e})].", wfopen_errno(&e)));
            return true;
        }
    };
    let mut pos = 0;
    while pos < data.len() {
        let p = piece(&data, pos, 65536);
        pos += p.len();
        if p.ends_with(b"\n") && p.contains(&0) {
            log(Lvl::Debug2, "Line contains some zero-bytes.");
            return true;
        }
    }
    false
}

/// A bundle header `!<size> <name>`: (size, name) or None when there is no space.
fn header(line: &[u8]) -> Option<(usize, &[u8])> {
    let sp = line.iter().position(|&b| b == b' ')?;
    let digits = line[1..].iter().take_while(|b| b.is_ascii_digit()).count();
    // No digits, or more than a number can hold, count as 0.
    let size = std::str::from_utf8(&line[1..1 + digits]).ok().and_then(|d| d.parse().ok()).unwrap_or(0);
    let name = &line[sp + 1..];
    Some((size, name.strip_suffix(b"\n").unwrap_or(name)))
}

const BUNDLE_LINE: usize = 2047;

/// Checks the bundle's structure without writing anything.
pub fn test_unmerge_files(path: &str) -> bool {
    let Ok(data) = fs::read(path) else {
        log(Lvl::Error, &format!("Unable to read merged file: '{path}'."));
        return false;
    };
    let (mut pos, mut ok) = (0, true);
    while pos < data.len() {
        let line = piece(&data, pos, BUNDLE_LINE);
        pos += line.len();
        match line[0] {
            b'#' => continue,
            b'!' => {}
            _ => return false,
        }
        let Some((size, name)) = header(line) else {
            ok = false;
            continue;
        };
        if name.is_empty() || data.len() - pos < size {
            return false;
        }
        pos += size;
    }
    ok
}

/// Unmerges in text mode.
pub fn unmerge_files(path: &str, optdir: Option<&str>) -> (bool, Vec<String>) {
    unmerge_files_mode(path, optdir, true)
}

/// Writes every bundle record under `optdir`; returns (all ok, names written).
pub fn unmerge_files_mode(path: &str, optdir: Option<&str>, text: bool) -> (bool, Vec<String>) {
    let data = match if text { crt::read_text(path) } else { fs::read(path) } {
        Ok(d) => d,
        Err(e) => {
            let n = wfopen_errno(&e);
            log(Lvl::Error, &format!("Unable to read merged file: '{path}' due to [({n})-({})].", strerror(n)));
            return (false, Vec::new());
        }
    };
    let (mut pos, mut ok, mut names) = (0, true, Vec::new());
    while pos < data.len() {
        let line = piece(&data, pos, BUNDLE_LINE);
        pos += line.len();
        if line[0] != b'!' {
            continue;
        }
        let Some((size, name)) = header(line) else {
            ok = false;
            continue;
        };
        let name = String::from_utf8_lossy(name).into_owned();
        let target = match optdir {
            Some(d) => format!("{d}/{name}"),
            None => name.clone(),
        };
        // Refused before anything is created, so nothing lands outside optdir.
        if ref_parent_folder(&target) {
            log(Lvl::Error, &format!("Unmerging '{path}': unable to unmerge '{target}' (it contains '..')"));
            return (false, names);
        }
        if fs::create_dir_all(dirname(&target)).is_err() {
            log(Lvl::Error, &format!("Unmerging '{path}': couldn't create directory '{name}'"));
            return (false, names);
        }
        let end = pos.saturating_add(size).min(data.len());
        let content = &data[pos..end];
        pos = end;
        let Some(tmp) = mkstemp_ex(&format!("{target}XXXXXX")) else {
            log(Lvl::Error, &format!("Unmerging '{path}': could not create temporary file for '{name}'"));
            return (false, names);
        };
        let written = if text { crt::write_text(&tmp, content) } else { fs::write(&tmp, content) };
        if let Err(e) = written {
            let n = wfopen_errno(&e);
            log(Lvl::Error, &format!("Unable to unmerge file '{tmp}' due to [({n})-({})].", strerror(n)));
            ok = false;
        }
        if !rename_ex(&tmp, &target) {
            let _ = fs::remove_file(&tmp);
            return (false, names);
        }
        names.push(name);
    }
    (ok, names)
}

/// Entry names without `.`/`..`, sorted by bytes; None if `dir` cannot be read.
pub fn wreaddir(dir: &str) -> Option<Vec<String>> {
    let mut names: Vec<String> =
        fs::read_dir(dir).ok()?.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    Some(names)
}

/// Copies `src` to `dst` (`'a'` appends, anything else truncates), writing `message` first.
pub fn copy_file(src: &str, dst: &str, mode: char, message: Option<&str>) -> io::Result<()> {
    let data = fs::read(src)?;
    let mut f = if mode == 'a' { OpenOptions::new().append(true).create(true).open(dst)? } else { File::create(dst)? };
    if let Some(m) = message {
        f.write_all(m.as_bytes())?;
    }
    f.write_all(&data)
}

/// Removes a file, link or whole directory tree; a missing path is fine.
pub fn rmdir_ex(path: &str) -> io::Result<()> {
    remove(Path::new(path))
}

fn remove(p: &Path) -> io::Result<()> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(m) if m.is_dir() => fs::remove_dir_all(p),
        // A directory link on Windows needs remove_dir.
        Ok(_) => fs::remove_file(p).or_else(|e| fs::remove_dir(p).map_err(|_| e)),
    }
}

/// Empties `dir` except entries named (relative, `/`-joined) in `ignore`; emptied protected dirs go too.
pub fn cldir_ex_ignore(dir: &str, ignore: &[&str]) -> io::Result<()> {
    clean(Path::new(dir), "", ignore)
}

fn clean(dir: &Path, prefix: &str, ignore: &[&str]) -> io::Result<()> {
    for e in fs::read_dir(dir)? {
        // Entries that cannot be read are skipped.
        let Ok(e) = e else { continue };
        let name = e.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
        let p = e.path();
        let below = format!("{rel}/");
        if !ignore.iter().any(|i| *i == rel || i.starts_with(&below)) {
            remove(&p)?;
        } else if e.file_type().is_ok_and(|t| t.is_dir()) {
            // A protected link is never followed: file_type does not resolve links.
            clean(&p, &rel, ignore)?;
            // Removes it only if it ended up empty; a failure is ignored.
            let _ = fs::remove_dir(&p);
        }
    }
    Ok(())
}

/// MD5 of the file read in text mode; None if unreadable.
pub fn md5_file(path: &str) -> Option<String> {
    crt::read_text(path).ok().map(|d| md5_hex(&d))
}

pub fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", Md5::digest(data))
}

/// Modification time in whole seconds since 1970 (0 before 1970); None if it cannot be stat'ed.
pub fn mtime(path: &str) -> Option<i64> {
    let m = fs::metadata(path).ok()?;
    Some(m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs() as i64))
}

/// `<template minus XXXXXX><letter><pid mod 100000>` for the first letter not taken; creates nothing.
pub fn mktemp(template: &str) -> Option<String> {
    let base = template.strip_suffix("XXXXXX")?;
    let pid = std::process::id() % 100_000;
    (b'a'..=b'z').map(|c| format!("{base}{}{pid:05}", c as char)).find(|p| !Path::new(p).exists())
}

/// Creates a new empty file named after `template` (ending in `XXXXXX`) and returns its name.
#[cfg(unix)]
pub fn mkstemp_ex(template: &str) -> Option<String> {
    use std::hash::{BuildHasher, RandomState};
    use std::os::unix::fs::OpenOptionsExt;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let base = template.strip_suffix("XXXXXX")?;
    for _ in 0..100 {
        // RandomState gives fresh random keys; enough for names that are created exclusively.
        let mut r = RandomState::new().hash_one(0u8);
        let suffix: String = (0..6)
            .map(|_| {
                let c = CHARS[(r % 62) as usize] as char;
                r /= 62;
                c
            })
            .collect();
        let name = format!("{base}{suffix}");
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&name) {
            Ok(_) => return Some(name),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                let n = wfopen_errno(&e);
                log(Lvl::Error, &format!("(1128): Could not create temporary file '{name}' due to [({n})-({})].", strerror(n)));
                return None;
            }
        }
    }
    None
}

/// Creates a new empty file named after `template` that only Administrators and SYSTEM can use.
#[cfg(windows)]
pub fn mkstemp_ex(template: &str) -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL};
    // No `XXXXXX`, or all 26 names taken.
    let Some(name) = mktemp(template) else {
        log(Lvl::Error, &format!("Could not create temporary file ({template}) which returned 22 [(22)-({})].", strerror(22)));
        return None;
    };
    // Protected DACL: full control for BUILTIN\Administrators and SYSTEM only, nothing inherited.
    let sddl = wide("D:P(A;;FA;;;BA)(A;;FA;;;SY)");
    let mut sd = std::ptr::null_mut();
    // SAFETY: valid NUL-terminated input and out pointer; the descriptor is freed below.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) } == 0 {
        log(Lvl::Error, &format!("Could not set ACL entries which returned ({})", unsafe { GetLastError() }));
        return None;
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let wname = wide(&name);
    // SAFETY: all pointers are valid for the call; the handle is closed right away.
    let h = unsafe {
        CreateFileW(wname.as_ptr(), GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, std::ptr::null_mut())
    };
    let err = unsafe { GetLastError() };
    unsafe { LocalFree(sd) };
    if h == INVALID_HANDLE_VALUE {
        log(Lvl::Error, &format!("Could not create temporary file ({name}) which returned ({err})"));
        return None;
    }
    unsafe { CloseHandle(h) };
    Some(name)
}

#[cfg(windows)]
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Renames `src` over `dst`.
#[cfg(unix)]
pub fn rename_ex(src: &str, dst: &str) -> bool {
    match fs::rename(src, dst) {
        Ok(()) => true,
        Err(e) => {
            let n = wfopen_errno(&e);
            log(Lvl::Error, &format!("(1124): Could not rename file '{src}' to '{dst}' due to [({n})-({})].", strerror(n)));
            false
        }
    }
}

/// Replaces `dst` with `src`, keeping the destination's security settings.
#[cfg(windows)]
pub fn rename_ex(src: &str, dst: &str) -> bool {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
    let created = if Path::new(dst).exists() {
        false
    } else if let Err(e) = OpenOptions::new().write(true).create_new(true).open(dst) {
        log(Lvl::Debug2, &format!("Could not create file ({dst}) which returned ({})", e.raw_os_error().unwrap_or(0)));
        return false;
    } else {
        true
    };
    let (wdst, wsrc) = (wide(dst), wide(src));
    use std::ptr::null;
    // SAFETY: NUL-terminated paths; the optional arguments are null.
    if unsafe { ReplaceFileW(wdst.as_ptr(), wsrc.as_ptr(), null(), 0, null(), null()) } == 0 {
        log(Lvl::Debug2, &format!("Could not move ({src}) to ({dst}) which returned ({})", unsafe { GetLastError() }));
        if created {
            let _ = fs::remove_file(dst);
        }
        return false;
    }
    true
}

/// The C library's message for error number `n`.
pub fn strerror(n: i32) -> String {
    // SAFETY: strerror returns a valid NUL-terminated string for any number.
    unsafe { std::ffi::CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned()
}

/// The error number the C runtime would report for `e`.
pub fn wfopen_errno(e: &io::Error) -> i32 {
    if cfg!(windows) {
        return e.raw_os_error().unwrap_or(0);
    }
    match e.kind() {
        io::ErrorKind::NotFound => libc::ENOENT,
        io::ErrorKind::PermissionDenied => libc::EACCES,
        io::ErrorKind::AlreadyExists => libc::EEXIST,
        _ => e.raw_os_error().unwrap_or(0),
    }
}
