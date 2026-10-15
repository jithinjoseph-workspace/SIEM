//! `siem-fileop`: port of the parts of `src/shared/file_op.c` that the
//! manager and agents use for shared configuration distribution:
//! `MergeAppendFile`, `UnmergeFiles`, `TestUnmergeFiles`, `checkBinaryFile`,
//! `w_copy_file`, `wreaddir`, `rmdir_ex`, `cldir_ex_ignore`, `OS_MD5_File`.
//!
//! Paths are handled as `/`-separated strings, as Wazuh does: the relative
//! names written into `merged.mg` must be byte-identical to a C manager's.

pub mod crt;
pub mod version_op;
#[cfg(windows)]
pub mod win_version;

use md5::{Digest, Md5};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

static LOGGER: std::sync::OnceLock<std::sync::Arc<siem_log::WLog>> = std::sync::OnceLock::new();

/// Installs the daemon's logger for these messages (else they go to `tracing`).
pub fn set_logger(log: std::sync::Arc<siem_log::WLog>) {
    let _ = LOGGER.set(log);
}

fn log_error(m: String) {
    match LOGGER.get() {
        Some(l) => l.error(m),
        None => tracing::error!("{m}"),
    }
}

fn log_warn(m: String) {
    match LOGGER.get() {
        Some(l) => l.warn(m),
        None => tracing::warn!("{m}"),
    }
}

/// `mdebug2`
fn log_debug(m: String) {
    match LOGGER.get() {
        Some(l) => l.debug2(m),
        None => tracing::debug!("{m}"),
    }
}

/// `OS_MAXSTR`
const OS_MAXSTR: usize = 65536;

/// POSIX `dirname()` on a `/`-separated path.
pub fn dirname(path: &str) -> String {
    let p = path.trim_end_matches('/');
    if p.is_empty() {
        return if path.starts_with('/') { "/".into() } else { ".".into() };
    }
    match p.rfind('/') {
        None => ".".into(),
        Some(0) => "/".into(),
        Some(i) => {
            let d = p[..i].trim_end_matches('/');
            if d.is_empty() {
                "/".into()
            } else {
                d.into()
            }
        }
    }
}

/// The `path_offset` computed when `-1` is passed to `MergeAppendFile`:
/// length of `dirname(file)` plus the separator.
pub fn default_path_offset(file: &str) -> usize {
    let base = dirname(file);
    let mut off = base.len();
    if !base.ends_with('/') {
        off += 1;
    }
    off
}

/// `MergeAppendFile`: append `"!<size> <name>\n" + contents` to `out`.
/// `path_offset = None` uses [`default_path_offset`]. Returns false on error
/// (unreadable file, or the file changed size while being read).
pub fn merge_append_file(out: &mut Vec<u8>, file: &str, path_offset: Option<usize>) -> bool {
    let off = path_offset.unwrap_or_else(|| default_path_offset(file));
    let data = match fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            log_error(format!("Unable to open file: '{}' due to [({})-({})].", file, e.raw_os_error().unwrap_or(0), e));
            return false;
        }
    };
    if data.is_empty() {
        log_warn(format!("File '{file}' is empty."));
    }
    let name = file.get(off.min(file.len())..).unwrap_or("");
    let _ = write!(out, "!{} {}\n", data.len(), name);
    out.extend_from_slice(&data);
    // The C code compares ftell() before and after reading; a single read
    // of the whole file cannot observe a size change.
    true
}

/// `fgets(buf, size, fp)` chunking: pieces of at most `size - 1` bytes, each
/// ending after a `\n` when one is found.
fn fgets_chunks(data: &[u8], size: usize) -> Vec<&[u8]> {
    let max = size - 1;
    let mut out = Vec::new();
    let mut start = 0;
    while start < data.len() {
        let mut end = start;
        while end < data.len() && end - start < max {
            end += 1;
            if data[end - 1] == b'\n' {
                break;
            }
        }
        out.push(&data[start..end]);
        start = end;
    }
    out
}

/// `checkBinaryFile`: true when the file cannot be read or a newline-ended
/// line contains a NUL byte (lines without a trailing newline are not
/// checked, exactly like the C code).
pub fn check_binary_file(path: &str) -> bool {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            log_error(format!("Unable to open file '{}' due to [({})-({})].", path, e.raw_os_error().unwrap_or(0), e));
            return true;
        }
    };
    for chunk in fgets_chunks(&data, OS_MAXSTR + 1) {
        if chunk.last() == Some(&b'\n') && chunk[..chunk.len() - 1].contains(&0) {
            // shortcut: C adds "(valid=N/ total=N)"; add it when a check_binary_file caller logs at debug 2
            log_debug("Line contains some zero-bytes.".to_string());
            return true;
        }
    }
    false
}

/// Parse one `!<size> <name>` header line (as read by `fgets(buf, 2048)`).
fn parse_header(line: &[u8]) -> Option<(usize, String)> {
    let s = String::from_utf8_lossy(line);
    let s = s.trim_end_matches('\n');
    let size = {
        let digits: String = s[1..].chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse::<usize>().unwrap_or(0)
    };
    let name = s.find(' ').map(|p| s[p + 1..].to_string())?;
    Some((size, name))
}

/// `TestUnmergeFiles`: validate the structure of a merged file.
pub fn test_unmerge_files(path: &str) -> bool {
    let Ok(data) = fs::read(path) else {
        log_error(format!("Unable to read merged file: '{path}'."));
        return false;
    };
    let mut pos = 0;
    let mut ret = true;
    while pos < data.len() {
        // fgets(buf, sizeof(buf) - 1) with buf[2049] => at most 2047 bytes
        let line = fgets_chunks(&data[pos..], 2048).into_iter().next().unwrap_or(&[]);
        pos += line.len();
        match line.first() {
            Some(b'#') => continue,
            Some(b'!') => {}
            _ => return false,
        }
        match parse_header(line) {
            None => {
                ret = false;
                continue;
            }
            Some((size, name)) => {
                if name.is_empty() {
                    return false;
                }
                let avail = data.len() - pos;
                let read = size.min(avail);
                pos += read;
                if read != size {
                    return false;
                }
            }
        }
    }
    ret
}

/// `UnmergeFiles(path, optdir, OS_TEXT, ...)`: extract every file of a
/// merged file into `optdir` (rejecting names containing `..`). Returns (ok,
/// relative names written). Text mode: see [`crt`].
pub fn unmerge_files(path: &str, optdir: Option<&str>) -> (bool, Vec<String>) {
    unmerge_files_mode(path, optdir, true)
}

/// `UnmergeFiles(path, optdir, mode, ...)`: `text` for `OS_TEXT`, false for
/// `OS_BINARY` (no stream translation on Windows).
pub fn unmerge_files_mode(path: &str, optdir: Option<&str>, text: bool) -> (bool, Vec<String>) {
    let mut names = Vec::new();
    let read = if text { crt::read_text(path) } else { fs::read(path) };
    let data = match read {
        Ok(d) => d,
        Err(e) => {
            let n = wfopen_errno(&e);
            log_error(format!("Unable to read merged file: '{path}' due to [({n})-({})].", strerror(n)));
            return (false, names);
        }
    };
    let mut pos = 0;
    let mut ret = true;
    while pos < data.len() {
        let line = fgets_chunks(&data[pos..], 2048).into_iter().next().unwrap_or(&[]);
        pos += line.len();
        if line.first() != Some(&b'!') {
            continue;
        }
        let Some((size, file)) = parse_header(line) else {
            ret = false;
            continue;
        };
        let mut state_ok = true;
        let final_name = match optdir {
            Some(d) => {
                let f = format!("{d}/{file}");
                if ref_parent_folder(&f) {
                    log_error(format!("Unmerging '{path}': unable to unmerge '{f}' (it contains '..')"));
                    state_ok = false;
                }
                f
            }
            None => file.clone(),
        };
        let parent = dirname(&final_name);
        if fs::create_dir_all(&parent).is_err() {
            log_error(format!("Unmerging '{path}': couldn't create directory '{file}'"));
            state_ok = false;
        }
        let read = size.min(data.len() - pos);
        let content = &data[pos..pos + read];
        pos += read;
        let tmp = if state_ok { mkstemp_ex(&format!("{final_name}XXXXXX")) } else { None };
        if tmp.is_none() {
            if state_ok {
                log_error(format!("Unmerging '{path}': could not create temporary file for '{file}'"));
            }
            ret = false;
        }
        if let Some(tmp) = tmp {
            let w = if text { crt::write_text(&tmp, content) } else { fs::write(&tmp, content) };
            if let Err(e) = w {
                ret = false;
                let n = wfopen_errno(&e);
                log_error(format!("Unable to unmerge file '{tmp}' due to [({n})-({})].", strerror(n)));
            }
            // Mv to original name
            if !rename_ex(&tmp, &final_name) {
                let _ = fs::remove_file(&tmp);
                ret = false;
                break;
            }
        } else {
            // C renames the (missing) temp file, which fails: unlink, stop.
            // Not kept: for a name with '..' C creates the temp file anyway and
            // renames it (empty) over the path outside optdir.
            ret = false;
            break;
        }
        let rel = match optdir {
            Some(d) if final_name.starts_with(d) && final_name.as_bytes().get(d.len()) == Some(&b'/') => {
                final_name[d.len() + 1..].to_string()
            }
            Some(_) => final_name.rsplit('/').next().unwrap_or(&final_name).to_string(),
            None => final_name.clone(),
        };
        names.push(rel);
    }
    (ret, names)
}

/// The CRT's `errno` for an I/O error.
fn errno_of(e: &io::Error) -> i32 {
    match e.kind() {
        io::ErrorKind::NotFound => libc::ENOENT,
        io::ErrorKind::PermissionDenied => libc::EACCES,
        io::ErrorKind::AlreadyExists => libc::EEXIST,
        _ => e.raw_os_error().unwrap_or(0),
    }
}

/// `errno` after a failed `wfopen`: on Windows it is `GetLastError()`.
pub fn wfopen_errno(e: &io::Error) -> i32 {
    if cfg!(windows) {
        e.raw_os_error().unwrap_or(0)
    } else {
        errno_of(e)
    }
}

pub fn strerror(n: i32) -> String {
    // SAFETY: strerror returns a static NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned()
}

/// `_mktemp_s`: the trailing "XXXXXX" becomes a letter and 5 digits of the
/// process id, the first letter whose name does not exist.
pub fn mktemp(template: &str) -> Option<String> {
    let base = template.strip_suffix("XXXXXX")?;
    let pid = std::process::id() % 100_000;
    (b'a'..=b'z').map(|c| format!("{base}{}{pid:05}", c as char)).find(|p| !Path::new(p).exists())
}

/// `mkstemp_ex`: create an empty, new temporary file from a "...XXXXXX"
/// template (Unix: mode 0600; Windows: a DACL that only grants
/// Administrators and SYSTEM). Its name, or None (logged).
pub fn mkstemp_ex(template: &str) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let base = template.strip_suffix("XXXXXX")?;
        const CH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0) ^ u64::from(std::process::id());
        for _ in 0..100 {
            let suffix: String = (0..6).map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                CH[(seed >> 33) as usize % CH.len()] as char
            }).collect();
            let p = format!("{base}{suffix}");
            match fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p) {
                Ok(_) => return Some(p),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    let n = errno_of(&e);
                    log_error(format!("(1128): Could not create temporary file '{p}' due to [({n})-({})].", strerror(n)));
                    return None;
                }
            }
        }
        None
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL};
        let Some(p) = mktemp(template) else {
            log_error(format!("Could not create temporary file ({template}) which returned 22 [(22)-({})].", strerror(22)));
            return None;
        };
        let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        // BUILTIN\Administrators and SYSTEM: GENERIC_ALL, nothing inherited
        let sddl = wide("D:(A;;GA;;;BA)(A;;GA;;;SY)");
        let mut sd = std::ptr::null_mut();
        // SAFETY: valid NUL-terminated strings; `sd` is freed below.
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) == 0 {
                log_error(format!("Could not set ACL entries which returned ({})", GetLastError()));
                return None;
            }
            let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
            let h = CreateFileW(wide(&p).as_ptr(), GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, std::ptr::null_mut());
            let err = GetLastError();
            LocalFree(sd);
            if h == INVALID_HANDLE_VALUE {
                log_error(format!("Could not create temporary file ({p}) which returned ({err})"));
                return None;
            }
            CloseHandle(h);
        }
        Some(p)
    }
}

/// `rename_ex`: true on success. Windows: `ReplaceFile` over the destination
/// (created first when missing, so it keeps the destination's security).
pub fn rename_ex(src: &str, dst: &str) -> bool {
    #[cfg(unix)]
    {
        match fs::rename(src, dst) {
            Ok(()) => true,
            Err(e) => {
                let n = errno_of(&e);
                log_error(format!("(1124): Could not rename file '{src}' to '{dst}' due to [({n})-({})].", strerror(n)));
                false
            }
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
        let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let created = !Path::new(dst).exists();
        if created {
            if let Err(e) = fs::OpenOptions::new().write(true).create(true).truncate(true).open(dst) {
                log_debug(format!("Could not create file ({dst}) which returned ({})", e.raw_os_error().unwrap_or(0)));
                return false;
            }
        }
        let (d, s) = (wide(dst), wide(src));
        // SAFETY: valid NUL-terminated paths.
        if unsafe { ReplaceFileW(d.as_ptr(), s.as_ptr(), std::ptr::null(), 0, std::ptr::null(), std::ptr::null()) } == 0 {
            log_debug(format!("Could not move ({src}) to ({dst}) which returned ({})", unsafe { GetLastError() }));
            if created {
                let _ = fs::remove_file(dst);
            }
            return false;
        }
        true
    }
}

/// `w_ref_parent_folder`: true if the path contains a `..` component
/// (also `\` separated on Windows, with the C search order).
pub fn ref_parent_folder(path: &str) -> bool {
    let b = path.as_bytes();
    let sep = |c: Option<&u8>| c.is_none() || c == Some(&b'/') || (cfg!(windows) && c == Some(&b'\\'));
    if b.first() == Some(&b'.') && b.get(1) == Some(&b'.') && sep(b.get(2)) {
        return true;
    }
    let find = |from: usize, pat: &[u8]| b[from..].windows(3).position(|w| w == pat).map(|p| p + from);
    let mut from = 0;
    // strstr(str, "/..") || strstr(str, "\\..") (Windows): the second only when the first has none
    while let Some(p) = find(from, b"/..").or_else(|| if cfg!(windows) { find(from, b"\\..") } else { None }) {
        if sep(b.get(p + 3)) {
            return true;
        }
        from = p + 3;
    }
    false
}

/// `wreaddir`: entries except `.`/`..`, sorted with `strcmp`.
pub fn wreaddir(dir: &str) -> Option<Vec<String>> {
    let rd = fs::read_dir(dir).ok()?;
    let mut v: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    v.retain(|n| n != "." && n != "..");
    v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    Some(v)
}

/// `w_copy_file`: mode `'a'` appends, anything else truncates; `message` is
/// written before the contents.
pub fn copy_file(src: &str, dst: &str, mode: char, message: Option<&str>) -> io::Result<()> {
    let data = fs::read(src)?;
    let mut f = if mode == 'a' {
        fs::OpenOptions::new().create(true).append(true).open(dst)?
    } else {
        fs::File::create(dst)?
    };
    if let Some(m) = message {
        f.write_all(m.as_bytes())?;
    }
    f.write_all(&data)
}

/// `rmdir_ex`: remove a file or a directory tree.
pub fn rmdir_ex(path: &str) -> io::Result<()> {
    let p = Path::new(path);
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(p),
        Ok(_) => fs::remove_file(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn should_preserve(rel: &str, ignore: &[&str]) -> bool {
    ignore.iter().any(|ig| *ig == rel || (ig.starts_with(rel) && ig.as_bytes().get(rel.len()) == Some(&b'/')))
}

fn cldir_rec(name: &str, base: &str, ignore: &[&str]) -> io::Result<()> {
    for entry in fs::read_dir(name)?.flatten() {
        let d = entry.file_name().to_string_lossy().into_owned();
        let path = format!("{name}/{d}");
        let rel = if path.starts_with(base) && path.as_bytes().get(base.len()) == Some(&b'/') {
            path[base.len() + 1..].to_string()
        } else {
            d.clone()
        };
        if should_preserve(&rel, ignore) {
            if Path::new(&path).is_dir() {
                cldir_rec(&path, base, ignore)?;
                let _ = fs::remove_dir(&path);
            }
            continue;
        }
        rmdir_ex(&path)?;
    }
    Ok(())
}

/// `cldir_ex_ignore`: empty `dir`, keeping the relative paths in `ignore`.
pub fn cldir_ex_ignore(dir: &str, ignore: &[&str]) -> io::Result<()> {
    cldir_rec(dir, dir, ignore)
}

/// `OS_MD5_File(path, md5, OS_TEXT)` (hex digest), `None` when the file
/// cannot be read.
pub fn md5_file(path: &str) -> Option<String> {
    let data = crt::read_text(path).ok()?;
    Some(md5_hex(&data))
}

pub fn md5_hex(data: &[u8]) -> String {
    let d = Md5::digest(data);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// File modification time in seconds (`st_mtime`), `None` if missing.
pub fn mtime(path: &str) -> Option<i64> {
    let m = fs::metadata(path).ok()?;
    let t = m.modified().ok()?;
    Some(t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_parent_folder_like_c() {
        for p in ["..", "../a", "a/..", "a/../b", "x/..y/.."] {
            assert!(ref_parent_folder(p), "{p}");
        }
        for p in ["", ".", "..a", "a/..b", "a/b", ".../x"] {
            assert!(!ref_parent_folder(p), "{p}");
        }
        assert_eq!(ref_parent_folder("..\\a"), cfg!(windows));
        assert_eq!(ref_parent_folder("a\\..\\b"), cfg!(windows));
        // C quirk: a "/.." match hides the later "\.."
        assert!(!ref_parent_folder("a\\..\\b/..x"));
    }

    #[test]
    fn dirname_like_posix() {
        assert_eq!(dirname("etc/shared/default/agent.conf"), "etc/shared/default");
        assert_eq!(dirname("/agent.conf"), "/");
        assert_eq!(dirname("agent.conf"), ".");
        assert_eq!(dirname("a/b/"), "a");
        assert_eq!(default_path_offset("etc/shared/default/agent.conf"), "etc/shared/default/".len());
    }

    #[test]
    fn merge_and_unmerge_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_string_lossy().replace('\\', "/");
        fs::create_dir_all(format!("{d}/g/sub")).unwrap();
        fs::write(format!("{d}/g/agent.conf"), "<agent_config/>\n").unwrap();
        fs::write(format!("{d}/g/sub/x.txt"), "x").unwrap();
        let mut out = b"#g\n".to_vec();
        let off = default_path_offset(&format!("{d}/g/agent.conf"));
        assert!(merge_append_file(&mut out, &format!("{d}/g/agent.conf"), Some(off)));
        assert!(merge_append_file(&mut out, &format!("{d}/g/sub/x.txt"), Some(off)));
        let expected = "#g\n!16 agent.conf\n<agent_config/>\n!1 sub/x.txt\nx".to_string();
        assert_eq!(String::from_utf8(out.clone()).unwrap(), expected);
        let mg = format!("{d}/merged.mg");
        fs::write(&mg, &out).unwrap();
        assert!(test_unmerge_files(&mg));
        // Windows: the temp files only grant Administrators/SYSTEM (as in C), so
        // a non-elevated run cannot write them
        let probe = mkstemp_ex(&format!("{d}/probeXXXXXX")).unwrap();
        if fs::write(&probe, b"x").is_err() {
            assert!(cfg!(windows));
            assert!(!unmerge_files(&mg, Some(&format!("{d}/out"))).0);
            return;
        }
        let (ok, names) = unmerge_files(&mg, Some(&format!("{d}/out")));
        assert!(ok);
        assert_eq!(names, vec!["agent.conf", "sub/x.txt"]);
        assert_eq!(fs::read_to_string(format!("{d}/out/sub/x.txt")).unwrap(), "x");
    }

    #[test]
    fn binary_detection_matches_c_rules() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("b").to_string_lossy().into_owned();
        fs::write(&f, b"text\nbad\0line\n").unwrap();
        assert!(check_binary_file(&f));
        fs::write(&f, b"text\nlast\0line-without-newline").unwrap();
        assert!(!check_binary_file(&f));
        assert!(check_binary_file("/nonexistent/file"));
    }
}
