//! `syscheckd/src/fim_diff_changes.c` (report_changes) and the file helpers
//! it calls (`w_compress_gzfile`, `w_uncompress_gzfile`, `abspath`, `mkdir_ex`,
//! `remove_empty_folders`, `FileSizeWin`, `DirSize`).

use std::os::raw::{c_char, c_int, c_uint, c_void};

use super::cfmt::{cfmt, A};
use super::config::*;
use super::create_db::{Fim, DIFF_DIR};
use super::{mdebug1, mdebug2, merror, msgs, mwarn};

const STR_MORE_CHANGES: &[u8] = b"More changes...";
/// `OS_MAXSTR - OS_SK_HEADER - 1`
const MAX_DIFF: usize = 65536 - 6144 - 1;
const OS_MAXSTR: usize = 65536;
const MIN_COMP_ESTIM: f32 = 0.4;
const OS_SIZE_8192: usize = 8192;

/// The `syscheck` fields report_changes updates.
#[derive(Debug)]
pub struct DiffState {
    pub folder_size: f32,
    pub comp_estimation_perc: f32,
    pub disk_quota_full_msg: bool,
}

mod gz {
    use super::*;
    // link the bundled zlib
    use libz_sys as _;
    pub type GzFile = *mut c_void;
    extern "C" {
        pub fn gzopen(path: *const c_char, mode: *const c_char) -> GzFile;
        pub fn gzwrite(file: GzFile, buf: *const c_void, len: c_uint) -> c_int;
        pub fn gzread(file: GzFile, buf: *mut c_void, len: c_uint) -> c_int;
        pub fn gzclose(file: GzFile) -> c_int;
        pub fn gzerror(file: GzFile, errnum: *mut c_int) -> *const c_char;
        pub fn gzeof(file: GzFile) -> c_int;
    }
    #[cfg(windows)]
    extern "C" {
        fn _errno() -> *mut c_int;
    }
    /// The CRT `errno`.
    pub fn errno() -> i32 {
        #[cfg(windows)]
        // SAFETY: the CRT's thread errno slot.
        return unsafe { *_errno() };
        #[cfg(unix)]
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }
}

fn strerror(e: i32) -> String {
    siem_ipc::os_net::strerror(e)
}

fn io_errno(e: &std::io::Error) -> i32 {
    // the CRT maps Win32 errors to errno; the common ones
    match e.kind() {
        std::io::ErrorKind::NotFound => 2,
        std::io::ErrorKind::PermissionDenied => 13,
        std::io::ErrorKind::AlreadyExists => 17,
        _ => e.raw_os_error().unwrap_or(0),
    }
}

/// A path for std (UTF-8 when valid, else ANSI).
fn p(b: &[u8]) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let mut w = super::win::auto_to_wide(b).unwrap_or_default();
        w.pop();
        return std::ffi::OsString::from_wide(&w).into();
    }
    #[cfg(unix)]
    <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(b).into()
}

fn cstr(b: &[u8]) -> std::ffi::CString {
    std::ffi::CString::new(b.iter().copied().take_while(|&c| c != 0).collect::<Vec<u8>>()).expect("no NUL")
}

/// `os_sha1` of a string
fn sha1(b: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    Sha1::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

/// `w_compress_gzfile`
fn compress_gzfile(src: &[u8], dst: &[u8]) -> i32 {
    use std::io::Read;
    let mut fd = match std::fs::File::open(p(src)) {
        Ok(f) => f,
        Err(e) => {
            let n = io_errno(&e);
            merror(cfmt("in w_compress_gzfile(): fopen error %s (%d):'%s'", &[A::B(src), A::I(n as i64), A::S(&strerror(n))]));
            return -1;
        }
    };
    let d = cstr(dst);
    // SAFETY: zlib calls on a handle opened here.
    unsafe {
        let gz = gz::gzopen(d.as_ptr(), c"w".as_ptr());
        if gz.is_null() {
            let n = gz::errno();
            merror(cfmt("in w_compress_gzfile(): gzopen error %s (%d):'%s'", &[A::B(dst), A::I(n as i64), A::S(&strerror(n))]));
            return -1;
        }
        let mut buf = vec![0u8; OS_SIZE_8192];
        loop {
            let len = match fd.read(&mut buf) {
                Ok(n) if n > 0 => n,
                _ => break,
            };
            if gz::gzwrite(gz, buf.as_ptr().cast(), len as u32) != len as i32 {
                let mut err = 0;
                let m = gz::gzerror(gz, &mut err);
                let m = if m.is_null() { String::new() } else { std::ffi::CStr::from_ptr(m).to_string_lossy().into_owned() };
                merror(format!("in w_compress_gzfile(): Compression error: {m}"));
                gz::gzclose(gz);
                return -1;
            }
        }
        gz::gzclose(gz);
    }
    0
}

/// `w_uncompress_gzfile`
fn uncompress_gzfile(src: &[u8], dst: &[u8]) -> i32 {
    use std::io::Write;
    if std::fs::metadata(p(src)).is_err() {
        return -1;
    }
    let mut fd = match std::fs::File::create(p(dst)) {
        Ok(f) => f,
        Err(e) => {
            let n = io_errno(&e);
            merror(cfmt("in w_uncompress_gzfile(): fopen error %s (%d):'%s'", &[A::B(dst), A::I(n as i64), A::S(&strerror(n))]));
            return -1;
        }
    };
    let c = cstr(src);
    // SAFETY: zlib calls on a handle opened here.
    unsafe {
        let gz = gz::gzopen(c.as_ptr(), c"rb".as_ptr());
        if gz.is_null() {
            let n = gz::errno();
            merror(cfmt("in w_uncompress_gzfile(): gzopen error %s (%d):'%s'", &[A::B(src), A::I(n as i64), A::S(&strerror(n))]));
            return -1;
        }
        let mut buf = vec![0u8; OS_SIZE_8192];
        loop {
            let len = gz::gzread(gz, buf.as_mut_ptr().cast(), OS_SIZE_8192 as u32);
            if len > 0 {
                let _ = fd.write_all(&buf[..len as usize]);
            }
            if len != OS_SIZE_8192 as i32 {
                break;
            }
        }
        if gz::gzeof(gz) == 0 {
            let mut err = 0;
            let m = gz::gzerror(gz, &mut err);
            if err != 0 {
                let m = if m.is_null() { String::new() } else { std::ffi::CStr::from_ptr(m).to_string_lossy().into_owned() };
                merror(format!("in w_uncompress_gzfile(): gzread error: '{m}'"));
                gz::gzclose(gz);
                return -1;
            }
        }
        gz::gzclose(gz);
    }
    0
}

/// `FileSizeWin`: a DWORD (`nFileSizeHigh + nFileSizeLow`), `(DWORD)-1` on error.
fn file_size(f: &[u8]) -> u32 {
    match std::fs::metadata(p(f)) {
        Ok(m) if m.is_file() => {
            let n = m.len();
            ((n >> 32) as u32).wrapping_add(n as u32)
        }
        _ => {
            mdebug2(cfmt("(1117): Error handling file '%s'.", &[A::B(f)]));
            u32::MAX
        }
    }
}

/// `DirSize` (bytes, as a float)
pub(super) fn dir_size(path: &[u8]) -> f32 {
    let Ok(rd) = std::fs::read_dir(p(path)) else {
        mdebug2(cfmt("(1117): Error handling file '%s'.", &[A::B(path)]));
        return 0.0;
    };
    let mut total = 0.0f32;
    for e in rd.flatten() {
        let mut child = path.to_vec();
        child.push(b'\\');
        child.extend_from_slice(e.file_name().to_string_lossy().as_bytes());
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            total += dir_size(&child);
        } else {
            let n = file_size(&child);
            // `file_size != -1` compares the float conversion of the DWORD
            if n as f32 != -1.0 {
                total += n as f32;
            }
        }
    }
    total
}

/// `IsDir(p) == 0`
fn is_dir(path: &[u8]) -> bool {
    std::fs::metadata(p(path)).map(|m| m.is_dir()).unwrap_or(false)
}

/// `mkdir_ex`
fn mkdir_ex(path: &[u8]) -> i32 {
    match std::fs::create_dir_all(p(path)) {
        Ok(()) => 0,
        Err(e) => {
            merror(cfmt("Couldn't make dir '%s': %s", &[A::B(path), A::S(&strerror(io_errno(&e)))]));
            -1
        }
    }
}

/// `rmdir_ex`: 0 or -1 (with the errno).
fn rmdir_ex(path: &[u8]) -> Result<(), i32> {
    let pb = p(path);
    let r = match std::fs::symlink_metadata(&pb) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(&pb),
        Ok(_) => std::fs::remove_file(&pb),
        Err(e) => Err(e),
    };
    r.map_err(|e| io_errno(&e))
}

/// `abspath`
fn abspath(path: &[u8]) -> Option<Vec<u8>> {
    let is_abs = path.len() >= 3 && path[0].is_ascii_alphabetic() && path[1] == b':' && (path[2] == b'\\' || path[2] == b'/');
    if is_abs {
        let mut b = path.to_vec();
        b[0] = b[0].to_ascii_lowercase();
        return Some(b);
    }
    let cwd = std::env::current_dir().ok()?;
    let mut cwd = cwd.to_string_lossy().into_owned().into_bytes();
    match path.first() {
        Some(b'/') | Some(b'\\') => {
            let mut b = vec![cwd[0], b':'];
            b.extend_from_slice(path);
            Some(b)
        }
        _ => {
            if cwd.last() == Some(&b'\\') {
                cwd.pop();
            }
            cwd.push(b'\\');
            cwd.extend_from_slice(path);
            Some(cwd)
        }
    }
}

/// `remove_empty_folders`
fn remove_empty_folders(path: &[u8]) -> i32 {
    let Some(c) = path.iter().rposition(|&b| b == PATH_SEP) else { return 0 };
    let parent = &path[..c];
    if parent == DIFF_DIR.as_bytes() {
        return 0;
    }
    let empty = std::fs::read_dir(p(parent)).map(|mut d| d.next().is_none()).unwrap_or(true);
    if !empty {
        return 0;
    }
    mdebug1(cfmt("Removing empty directory '%s'.", &[A::B(parent)]));
    match rmdir_ex(parent) {
        Ok(()) => remove_empty_folders(parent),
        Err(e) => {
            mwarn(cfmt("Empty directory '%s' couldn't be deleted. ('%s')", &[A::B(parent), A::S(&strerror(e))]));
            -1
        }
    }
}

/// `utf8_GetShortPathName`
#[cfg(windows)]
fn short_path(path: &[u8]) -> Option<Vec<u8>> {
    use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
    let w = super::win::auto_to_wide(path)?;
    let mut out = [0u16; 260];
    // SAFETY: a NUL-terminated input and a MAX_PATH buffer.
    let len = unsafe { GetShortPathNameW(w.as_ptr(), out.as_mut_ptr(), 260) };
    if len == 0 || len >= 260 {
        return None;
    }
    super::win::wide_to_utf8(&out)
}

/// `filter` (Windows): no `%`, and `/` becomes `\`.
fn filter(b: &[u8]) -> Option<Vec<u8>> {
    if b.contains(&b'%') {
        return None;
    }
    Some(b.iter().map(|&c| if c == b'/' { b'\\' } else { c }).collect())
}

/// `diff_data`
struct DiffData {
    file_size: f32,
    size_limit: i32,
    compress_folder: Vec<u8>,
    compress_file: Vec<u8>,
    tmp_folder: Vec<u8>,
    file_origin: Vec<u8>,
    uncompress_file: Vec<u8>,
    compress_tmp_file: Vec<u8>,
    diff_file: Vec<u8>,
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

impl DiffData {
    fn tail(compress_folder: Vec<u8>, tmp_folder: Vec<u8>, file_origin: Vec<u8>, size_limit: i32) -> DiffData {
        DiffData {
            file_size: 0.0,
            size_limit,
            compress_file: cat(&[&compress_folder, b"/last-entry.gz"]),
            uncompress_file: cat(&[&tmp_folder, b"/tmp-entry"]),
            compress_tmp_file: cat(&[&tmp_folder, b"/tmp-entry.gz"]),
            diff_file: cat(&[&tmp_folder, b"/diff-file"]),
            compress_folder,
            tmp_folder,
            file_origin,
        }
    }
}

/// `initialize_file_diff_data`
fn initialize_file_diff_data(cfg: &SyscheckConfig, filename: &[u8], dir: &Directory) -> Option<DiffData> {
    #[cfg(windows)]
    let path = super::win::auto_to_ansi(filename);
    #[cfg(unix)]
    let path = filename.to_vec();
    let size_limit = if cfg.file_size_enabled { dir.diff_size_limit } else { 0 };
    let Some(abs) = abspath(&path) else {
        merror(cfmt(msgs::FIM_ERROR_GET_ABSOLUTE_PATH, &[A::B(filename), A::S(&strerror(2)), A::I(2)]));
        return None;
    };
    let Some(abs_diff) = abspath(DIFF_DIR.as_bytes()) else {
        merror(cfmt(msgs::FIM_ERROR_GET_ABSOLUTE_PATH, &[A::S(""), A::S(&strerror(2)), A::I(2)]));
        return None;
    };
    let enc = sha1(&abs);
    Some(DiffData::tail(cat(&[&abs_diff, b"/file/", enc.as_bytes()]), cat(&[&abs_diff, b"/tmp"]), abs, size_limit))
}

/// `initialize_registry_diff_data`
fn initialize_registry_diff_data(key: &[u8], value: &[u8], c: &Registry) -> DiffData {
    let (ek, ev) = (sha1(key), sha1(value));
    let a: &[u8] = if c.arch != 0 { b"[x64] " } else { b"[x32] " };
    let tmp = format!("{DIFF_DIR}/tmp").into_bytes();
    let folder = cat(&[DIFF_DIR.as_bytes(), b"/registry/", a, ek.as_bytes(), b"/", ev.as_bytes()]);
    let origin = cat(&[&tmp, b"/", a, ek.as_bytes(), ev.as_bytes()]);
    DiffData::tail(folder, tmp, origin, c.diff_size_limit)
}

impl Fim {
    fn ds(&self) -> std::sync::MutexGuard<'_, DiffState> {
        self.diff.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `fim_diff_check_limits`: 0, 1 (file size) or 2 (disk quota).
    fn diff_check_limits(&self, cfg: &SyscheckConfig, d: &mut DiffData) -> i32 {
        d.file_size = file_size(&d.file_origin) as f32 / 1024.0;
        if cfg.file_size_enabled && d.file_size > d.size_limit as f32 {
            self.diff_delete_compress_folder(&d.compress_folder);
            return 1;
        }
        if cfg.disk_quota_enabled {
            let st = self.ds();
            let est = d.file_size - st.comp_estimation_perc * d.file_size;
            if st.folder_size + est > cfg.disk_quota_limit as f32 {
                return 2;
            }
        }
        0
    }

    /// `fim_diff_delete_compress_folder`: 0, -1 or -2 (no folder).
    fn diff_delete_compress_folder(&self, folder: &[u8]) -> i32 {
        if !is_dir(folder) {
            return -2;
        }
        let size = dir_size(folder) / 1024.0;
        if let Err(e) = rmdir_ex(folder) {
            mdebug2(cfmt("(1143): Unable to delete folder '%s' due to [(%d)-(%s)].", &[A::B(folder), A::I(e as i64), A::S(&strerror(e))]));
            return -1;
        } else if size != -1.0 {
            let mut st = self.ds();
            st.folder_size -= size;
            st.disk_quota_full_msg = true;
            if st.folder_size < 0.0 {
                st.folder_size = 0.0;
            }
        }
        if remove_empty_folders(folder) == -1 {
            return -1;
        }
        mdebug2(cfmt(msgs::FIM_DIFF_FOLDER_DELETED, &[A::B(folder)]));
        0
    }

    /// `fim_diff_create_compress_file`: 0, -1 or -2 (disk quota).
    fn diff_create_compress_file(&self, cfg: &SyscheckConfig, d: &DiffData) -> i32 {
        if compress_gzfile(&d.file_origin, &d.compress_tmp_file) != 0 {
            mwarn(cfmt(msgs::FIM_WARN_GENDIFF_SNAPSHOT, &[A::B(&d.file_origin)]));
            return -1;
        }
        if cfg.disk_quota_enabled {
            let zip = file_size(&d.compress_tmp_file) / 1024;
            let mut st = self.ds();
            if st.folder_size + zip as f32 > cfg.disk_quota_limit as f32 {
                if st.disk_quota_full_msg {
                    st.disk_quota_full_msg = false;
                    mdebug2(cfmt(msgs::FIM_DISK_QUOTA_LIMIT_REACHED, &[A::S("calculate"), A::B(&d.file_origin)]));
                }
                // fim_diff_modify_compress_estimation
                let rate = 1.0 - (zip as f32 / d.file_size);
                if rate >= 0.1 {
                    st.comp_estimation_perc = ((rate + st.comp_estimation_perc) / 2.0).max(MIN_COMP_ESTIM);
                }
                return -2;
            }
        }
        0
    }

    /// `save_compress_file`
    fn save_compress_file(&self, cfg: &SyscheckConfig, d: &DiffData) {
        if let Err(e) = rename_ex(&d.compress_tmp_file, &d.compress_file) {
            mdebug2(cfmt("(1124): Could not rename file '%s' to '%s' due to [(%d)-(%s)].", &[A::B(&d.compress_tmp_file), A::B(&d.compress_file), A::I(e as i64), A::S(&strerror(e))]));
            return;
        }
        if cfg.disk_quota_enabled {
            self.ds().folder_size += file_size(&d.compress_file) as f32 / 1024.0;
        }
    }

    /// The common tail of `fim_file_diff` / `fim_registry_value_diff`.
    fn diff_run(&self, cfg: &SyscheckConfig, d: &mut DiffData, what: &str, name: &[u8], nodiff: bool, is_file: bool) -> Option<Vec<u8>> {
        let r = self.diff_check_limits(cfg, d);
        if r == 1 {
            mdebug2(cfmt(msgs::FIM_BIG_FILE_REPORT_CHANGES, &[A::B(name)]));
            return Some(b"Unable to calculate diff due to 'file_size' limit has been reached.".to_vec());
        } else if r == 2 {
            mdebug2(cfmt(msgs::FIM_DISK_QUOTA_LIMIT_REACHED, &[A::S("estimation"), A::B(name)]));
            return Some(b"Unable to calculate diff due to 'disk_quota' limit has been reached.".to_vec());
        }
        if uncompress_gzfile(&d.compress_file, &d.uncompress_file) != 0 {
            match self.diff_create_compress_file(cfg, d) {
                0 => {
                    mkdir_ex(&d.compress_folder);
                    self.save_compress_file(cfg, d);
                    return Some(format!("Unable to calculate diff due to no previous data stored for this {what}.").into_bytes());
                }
                -2 => return Some(b"Unable to calculate diff due to 'disk_quota' limit has been reached.".to_vec()),
                _ => return None,
            }
        }
        let backup = file_size(&d.compress_file) as f32 / 1024.0;
        self.ds().folder_size -= backup;
        let r = self.diff_create_compress_file(cfg, d);
        if r != 0 {
            self.ds().folder_size += backup;
            return (r == -2).then(|| b"Unable to calculate diff due to 'disk_quota' limit has been reached.".to_vec());
        }
        if !diff_compare(d) {
            mdebug2(msgs::FIM_DIFF_IDENTICAL_MD5_FILES);
            self.ds().folder_size += backup;
            return Some(format!("No content changes were found for this {what}.").into_bytes());
        }
        if nodiff {
            self.ds().folder_size += backup;
            return Some(format!("Diff truncated due to 'nodiff' configuration detected for this {what}.").into_bytes());
        }
        match diff_generate(d, is_file) {
            Some(out) => {
                self.save_compress_file(cfg, d);
                Some(out)
            }
            None => {
                self.ds().folder_size += backup;
                None
            }
        }
    }

    /// `fim_file_diff`
    pub fn fim_file_diff(&self, cfg: &SyscheckConfig, filename: &[u8], dir: &Directory) -> Option<Vec<u8>> {
        let mut d = initialize_file_diff_data(cfg, filename, dir)?;
        mkdir_ex(&d.tmp_folder);
        let nodiff = is_file_nodiff(cfg, &d.file_origin);
        let out = self.diff_run(cfg, &mut d, "file", filename, nodiff, true);
        if let Err(e) = rmdir_ex(&d.tmp_folder) {
            mdebug2(cfmt("(1143): Unable to delete folder '%s' due to [(%d)-(%s)].", &[A::B(&d.tmp_folder), A::I(e as i64), A::S(&strerror(e))]));
        }
        out
    }

    /// `fim_registry_value_diff`: `data` is the raw value buffer.
    #[cfg(windows)]
    pub fn fim_registry_value_diff(&self, cfg: &SyscheckConfig, key: &[u8], value: &[u8], data: &[u8], data_type: u32, c: &Registry) -> Option<Vec<u8>> {
        // REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_MULTI_SZ, REG_QWORD
        if !matches!(data_type, 1 | 2 | 4 | 5 | 7 | 11) {
            mdebug2(cfmt(msgs::FIM_REG_VAL_INVALID_TYPE, &[A::B(key), A::B(value)]));
            return None;
        }
        let mut d = initialize_registry_diff_data(key, value, c);
        let full = cat(&[key, b"\\", value]);
        let out = if registry_tmp(data, data_type, &d) == -1 {
            None
        } else {
            let nodiff = is_registry_nodiff(cfg, key, value, c.arch);
            self.diff_run(cfg, &mut d, "registry value", &full, nodiff, false)
        };
        if let Err(e) = rmdir_ex(&d.tmp_folder) {
            mdebug2(cfmt("(1143): Unable to delete folder '%s' due to [(%d)-(%s)].", &[A::B(&d.tmp_folder), A::I(e as i64), A::S(&strerror(e))]));
        }
        out
    }

    /// The deletion helpers: `fim_diff_process_delete_*`.
    fn delete_diff_folder(&self, folder: &[u8]) {
        match self.diff_delete_compress_folder(folder) {
            -1 => merror(cfmt(msgs::FIM_DIFF_DELETE_DIFF_FOLDER_ERROR, &[A::B(folder)])),
            -2 => mdebug2(cfmt(msgs::FIM_DIFF_FOLDER_NOT_EXIST, &[A::B(folder)])),
            _ => {}
        }
    }

    /// `fim_diff_process_delete_file`
    pub fn fim_diff_process_delete_file(&self, filename: &[u8]) {
        #[cfg(windows)]
        let path = super::win::auto_to_ansi(filename);
        #[cfg(unix)]
        let path = filename.to_vec();
        let Some(abs) = abspath(&path) else {
            merror(cfmt(msgs::FIM_ERROR_GET_ABSOLUTE_PATH, &[A::B(filename), A::S(&strerror(2)), A::I(2)]));
            return;
        };
        let folder = cat(&[DIFF_DIR.as_bytes(), b"/file/", sha1(&abs).as_bytes()]);
        self.delete_diff_folder(&folder);
    }

    /// `fim_diff_process_delete_registry`
    pub fn fim_diff_process_delete_registry(&self, key: &[u8], arch: i32) {
        let a: &[u8] = if arch != 0 { b"[x64] " } else { b"[x32] " };
        self.delete_diff_folder(&cat(&[DIFF_DIR.as_bytes(), b"/registry/", a, sha1(key).as_bytes()]));
    }

    /// `fim_diff_process_delete_value`
    pub fn fim_diff_process_delete_value(&self, key: &[u8], value: &[u8], arch: i32) {
        let a: &[u8] = if arch != 0 { b"[x64] " } else { b"[x32] " };
        self.delete_diff_folder(&cat(&[DIFF_DIR.as_bytes(), b"/registry/", a, sha1(key).as_bytes(), b"/", sha1(value).as_bytes()]));
    }
}

/// `rename_ex` (Windows: `ReplaceFile` over an existing or new destination).
fn rename_ex(src: &[u8], dst: &[u8]) -> Result<(), i32> {
    std::fs::rename(p(src), p(dst)).map_err(|e| io_errno(&e))
}

/// `fim_diff_compare`: true when the contents differ.
fn diff_compare(d: &DiffData) -> bool {
    use md5::{Digest, Md5};
    let md5 = |f: &[u8]| std::fs::read(p(f)).ok().map(|b| Md5::digest(&b).to_vec());
    match (md5(&d.uncompress_file), md5(&d.file_origin)) {
        (Some(a), Some(b)) => a != b,
        _ => false,
    }
}

/// `fim_diff_generate`
fn diff_generate(d: &DiffData, is_file: bool) -> Option<Vec<u8>> {
    let unc = filter(&d.uncompress_file);
    #[cfg(windows)]
    let origin = if is_file { short_path(&d.file_origin) } else { None }.or_else(|| filter(&d.file_origin));
    #[cfg(unix)]
    let origin = filter(&d.file_origin);
    let df = filter(&d.diff_file);
    let (Some(unc), Some(origin), Some(df)) = (unc, origin, df) else {
        mdebug1(msgs::FIM_DIFF_SKIPPED);
        return None;
    };
    let cmd = cat(&[b"fc /n \"", &unc, b"\" \"", &origin, b"\" > \"", &df, b"\" 2> nul"]);
    let _ = is_file;
    match system(&cmd) {
        0 => {
            mdebug2(msgs::FIM_DIFF_COMMAND_OUTPUT_EQUAL);
            None
        }
        1 => gen_diff_str(d),
        _ => {
            merror(msgs::FIM_DIFF_COMMAND_OUTPUT_ERROR);
            None
        }
    }
}

/// `system(cmd)`: `cmd.exe /c <cmd>`, the exit code.
#[cfg(windows)]
fn system(cmd: &[u8]) -> i32 {
    use std::os::windows::process::CommandExt;
    let comspec = std::env::var_os("COMSPEC").unwrap_or_else(|| "cmd.exe".into());
    // the command line is ANSI in the C; ours is the same bytes
    let line = String::from_utf8_lossy(cmd).into_owned();
    match std::process::Command::new(comspec).raw_arg("/c").raw_arg(line).status() {
        Ok(st) => st.code().unwrap_or(-1),
        Err(_) => -1,
    }
}

#[cfg(unix)]
fn system(_cmd: &[u8]) -> i32 {
    -1
}

/// `gen_diff_str` (Windows: `fc` output)
fn gen_diff_str(d: &DiffData) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut buf = Vec::new();
    match std::fs::File::open(p(&d.diff_file)) {
        Ok(f) => {
            let _ = f.take(MAX_DIFF as u64).read_to_end(&mut buf);
        }
        Err(_) => {
            merror(cfmt(msgs::FIM_ERROR_GENDIFF_OPEN, &[A::B(&d.diff_file)]));
            return None;
        }
    }
    let _ = std::fs::remove_file(p(&d.diff_file));
    if buf.is_empty() {
        merror(msgs::FIM_ERROR_GENDIFF_READ);
        return None;
    }
    buf.push(0);
    let mut out = adapt_win_fc_output(&mut buf);
    let mut n = out.len();
    let nl = buf.iter().take_while(|&&c| c != 0).position(|&c| c == b'\n');
    if let Some(i) = nl {
        if buf[i + 1] != b'*' {
            if n + STR_MORE_CHANGES.len() >= MAX_DIFF {
                n -= STR_MORE_CHANGES.len();
                while n > 0 && out[n - 1] != b'\n' {
                    n -= 1;
                }
            }
            out.truncate(n);
            out.extend_from_slice(STR_MORE_CHANGES);
        }
    }
    Some(out)
}

/// `strstr(b + from, pat)` on a NUL-terminated buffer.
fn c_strstr(b: &[u8], from: usize, pat: &[u8]) -> Option<usize> {
    let end = from + b[from..].iter().position(|&c| c == 0).unwrap_or(b.len() - from);
    b[from..end].windows(pat.len()).position(|w| w == pat).map(|i| from + i)
}

/// The NUL-terminated string at `from`.
fn c_str(b: &[u8], from: usize) -> &[u8] {
    let end = from + b[from..].iter().position(|&c| c == 0).unwrap_or(b.len() - from);
    &b[from..end]
}

/// `adapt_win_fc_output` (it writes NULs into `buf`, as the C does)
fn adapt_win_fc_output(buf: &mut [u8]) -> Vec<u8> {
    let Some(first) = c_str(buf, 0).iter().position(|&c| c == b'\n') else {
        mdebug2(cfmt("%s: %s", &[A::S(msgs::FIM_ERROR_GENDIFF_SECONDLINE_MISSING), A::B(c_str(buf, 0))]));
        return c_str(buf, 0).to_vec();
    };
    let mut out: Vec<u8> = Vec::new();
    let put = |out: &mut Vec<u8>, b: &[u8]| {
        // snprintf(adapted_output + written, OS_MAXSTR - written, ...)
        let room = OS_MAXSTR.saturating_sub(out.len() + 1);
        out.extend_from_slice(&b[..b.len().min(room)]);
    };
    let (mut mode, mut first_line) = (0u8, false);
    let mut line = Some(first);
    while let Some(l) = line {
        let l = l + 1;
        let mut next = c_strstr(buf, l, b"\r\n");
        if buf[l] == b'*' {
            if let Some(n) = next {
                next = Some(n + 1);
            }
            if mode == 0 {
                if first_line {
                    put(&mut out, b"---\n");
                }
                first_line = true;
            } else if mode == 1 {
                put(&mut out, b"---\n");
            }
            mode = (mode + 1) % 3;
            line = next;
            continue;
        }
        if let Some(n) = next {
            buf[n] = 0;
            buf[n + 1] = 0;
            next = Some(n + 1);
        }
        if let Some(t) = c_strstr(buf, l, b":  ") {
            let text = c_str(buf, t + 3).to_vec();
            put(&mut out, &cat(&[if mode == 1 { b"< " } else { b"> " }, &text, if next.is_some() { b"\n" } else { b"" }]));
        }
        line = next;
    }
    out
}

/// `is_file_nodiff`
fn is_file_nodiff(cfg: &SyscheckConfig, filename: &[u8]) -> bool {
    cfg.nodiff.iter().flatten().any(|n| n.as_bytes() == filename) || cfg.nodiff_regex.iter().flatten().any(|r| r.is_match_bytes(filename))
}

/// `is_registry_nodiff`
fn is_registry_nodiff(cfg: &SyscheckConfig, key: &[u8], value: &[u8], arch: i32) -> bool {
    let full = cat(&[key, b"\\", value]);
    cfg.registry_nodiff.iter().flatten().any(|n| n.arch == arch && n.entry.as_bytes() == full.as_slice())
        || cfg.registry_nodiff_regex.iter().flatten().any(|r| r.arch == arch && r.regex.is_match_bytes(&full))
}

/// `fim_diff_registry_tmp`: the value as text in the tmp file (text mode: `\n` -> `\r\n`).
#[cfg(windows)]
fn registry_tmp(data: &[u8], data_type: u32, d: &DiffData) -> i32 {
    mkdir_ex(&d.tmp_folder);
    let u32_at = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let wide = |off: usize| -> Vec<u16> { data[off.min(data.len())..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect() };
    let mut ret = 0;
    let text: Vec<u8> = match data_type {
        // fim_registry_convert_value_for_diff: a NULL conversion skips the diff in the caller
        1 | 2 => match super::win::wide_to_utf8(&wide(0)) {
            Some(u) => u,
            None => return -1,
        },
        7 => {
            let w = wide(0);
            let mut out = Vec::new();
            let mut i = 0;
            while i < w.len() && w[i] != 0 {
                let Some(u) = super::win::wide_to_utf8(&w[i..]) else { return -1 };
                out.extend_from_slice(&u);
                out.push(b'\n');
                i += w[i..].iter().position(|&c| c == 0).unwrap_or(w.len() - i) + 1;
            }
            out
        }
        4 => format!("{:04x}", u32_at(data)).into_bytes(),
        5 => format!("{:04x}", u32::from_be_bytes([data[0], data[1], data[2], data[3]])).into_bytes(),
        11 => format!("{:x}", u64::from_le_bytes(data[..8].try_into().expect("8 bytes"))).into_bytes(),
        _ => {
            mwarn(msgs::FIM_REG_VAL_WRONG_TYPE);
            ret = -1;
            Vec::new()
        }
    };
    // fopen(.., "w") is a text stream
    let text: Vec<u8> = text.iter().flat_map(|&c| if c == b'\n' { vec![b'\r', b'\n'] } else { vec![c] }).collect();
    if let Err(e) = std::fs::write(p(&d.file_origin), &text) {
        let n = io_errno(&e);
        merror(cfmt("(1103): Could not open file '%s' due to [(%d)-(%s)].", &[A::B(&d.file_origin), A::I(n as i64), A::S(&strerror(n))]));
        return -1;
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fc_output() {
        let mut b = b"Comparing files A and B\r\n***** A\r\n    1:  hello\r\n***** B\r\n    1:  hello world\r\n*****\r\n\r\n\0".to_vec();
        assert_eq!(adapt_win_fc_output(&mut b), b"< hello\n---\n> hello world\n".to_vec());
    }
}
