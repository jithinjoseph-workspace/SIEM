//! `config/syscheck-config.c` (the `<syscheck>` reader) and
//! `syscheckd/src/config.c` (`Read_Syscheck_Config`, `getSyscheckConfig`,
//! `getSyscheckInternalOptions`), as the Windows agent builds them; the Unix
//! branches are kept where they are small.

use siem_cjson::Json;
use siem_config::{messages, ConfigContext, ConfigError, Result as CResult};
use siem_regex::OsMatch;
use siem_xml::{OsXml, XmlNode};

pub const CHECK_SIZE: i32 = 0o0000001;
pub const CHECK_PERM: i32 = 0o0000002;
pub const CHECK_OWNER: i32 = 0o0000004;
pub const CHECK_GROUP: i32 = 0o0000010;
pub const CHECK_MTIME: i32 = 0o0000020;
pub const CHECK_INODE: i32 = 0o0000040;
pub const CHECK_MD5SUM: i32 = 0o0000100;
pub const CHECK_SHA1SUM: i32 = 0o0000200;
pub const CHECK_SHA256SUM: i32 = 0o0000400;
pub const CHECK_ATTRS: i32 = 0o0010000;
pub const CHECK_SEECHANGES: i32 = 0o0020000;
pub const CHECK_FOLLOW: i32 = 0o0040000;
pub const REALTIME_ACTIVE: i32 = 0o0100000;
pub const WHODATA_ACTIVE: i32 = 0o0200000;
pub const SCHEDULED_ACTIVE: i32 = 0o0400000;
pub const CHECK_TYPE: i32 = 0o1000000;
pub const CHECK_SUM: i32 = CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM;
pub const REGISTRY_CHECK_ALL: i32 = CHECK_SUM | CHECK_SIZE | CHECK_OWNER | CHECK_GROUP | CHECK_PERM | CHECK_MTIME | CHECK_TYPE;

pub const EBPF_PROVIDER: u8 = 0;
pub const AUDIT_PROVIDER: u8 = 1;
pub const ARCH_32BIT: i32 = 0;
pub const ARCH_64BIT: i32 = 1;
pub const ARCH_BOTH: i32 = 2;
pub const SK_CONF_UNPARSED: i32 = -2;
pub const SK_CONF_UNDEFINED: i32 = -1;
pub const FIM_DB_MEMORY: i32 = 1;
pub const FIM_DB_DISK: i32 = 0;
pub const MAX_DEPTH_ALLOWED: i32 = 320;
pub const MAX_REGISTRY_DEPTH: i32 = 512;
pub const MAX_DIR_SIZE: usize = 64;
pub const MAX_FILE_LIMIT: i32 = i32::MAX;
#[cfg(windows)]
pub const PATH_SEP: u8 = b'\\';
#[cfg(unix)]
pub const PATH_SEP: u8 = b'/';
/// `PATH_MAX` of the agent build
#[cfg(windows)]
const PATH_MAX: usize = 260;
#[cfg(unix)]
const PATH_MAX: usize = 4096;
const OS_MAXSTR: usize = 65536;

/// `directory_t`
#[derive(Debug)]
pub struct Directory {
    pub path: String,
    pub options: i32,
    pub diff_size_limit: i32,
    pub symbolic_links: Option<String>,
    pub filerestrict: Option<OsMatch>,
    pub recursion_level: i32,
    pub tag: Option<String>,
    pub is_wildcard: bool,
    pub is_expanded: bool,
    /// `dirs_status` (whodata): written while the directories are only read-locked, as in the C.
    pub dirs_status: DirStatus,
}

/// `whodata_dir_status` (`last_check` is never read)
#[derive(Debug, Default)]
pub struct DirStatus {
    pub status: std::sync::atomic::AtomicU32,
    pub object_type: std::sync::atomic::AtomicI32,
}

pub const WD_STATUS_FILE_TYPE: i32 = 1;
pub const WD_STATUS_DIR_TYPE: i32 = 2;
pub const WD_STATUS_UNK_TYPE: i32 = 3;
pub const WD_STATUS_EXISTS: u32 = 0x1;
pub const WD_CHECK_WHODATA: u32 = 0x2;
pub const WD_CHECK_REALTIME: u32 = 0x4;
pub const WD_IGNORE_REST: u32 = 0x8;

/// `registry_t`
#[derive(Debug)]
pub struct Registry {
    pub entry: String,
    pub arch: i32,
    pub opts: i32,
    pub recursion_level: i32,
    pub diff_size_limit: i32,
    pub restrict_key: Option<OsMatch>,
    pub restrict_value: Option<OsMatch>,
    pub tag: Option<String>,
}

/// `registry_ignore` (and `registry_t` as a nodiff entry)
#[derive(Debug, Clone)]
pub struct RegistryIgnore {
    pub entry: String,
    pub arch: i32,
}

/// `registry_ignore_regex`
#[derive(Debug)]
pub struct RegistryIgnoreRegex {
    pub regex: OsMatch,
    pub arch: i32,
}

/// `fs_set`
#[derive(Debug, Clone, Copy)]
pub struct SkipFs {
    pub nfs: bool,
    pub dev: bool,
    pub sys: bool,
    pub proc_: bool,
}

/// `syscheck_config` (the configuration fields)
#[derive(Debug)]
pub struct SyscheckConfig {
    pub rootcheck: i32,
    pub disabled: i32,
    pub scan_on_start: bool,
    pub max_depth: i32,
    pub file_max_size: usize,
    pub skip_fs: SkipFs,
    pub rt_delay: i32,
    pub time: i32,
    pub restart_audit: bool,
    pub enable_whodata: bool,
    pub whodata_provider: u8,
    pub enable_synchronization: bool,
    pub enable_registry_synchronization: bool,
    pub realtime_change: bool,
    /// Sorted by `strcmp` of the path (`fim_insert_directory`).
    pub directories: Vec<Directory>,
    pub wildcards: Option<Vec<Directory>>,
    pub scan_day: Option<Vec<u8>>,
    pub scan_time: Option<String>,
    pub scan_day_str: Option<String>,
    pub scan_time_str: Option<String>,
    pub file_limit_enabled: bool,
    pub file_entry_limit: i32,
    pub ignore: Option<Vec<String>>,
    pub ignore_regex: Option<Vec<OsMatch>>,
    pub disk_quota_enabled: bool,
    pub disk_quota_limit: i32,
    pub file_size_enabled: bool,
    pub file_size_limit: i32,
    pub diff_folder_size: f32,
    pub comp_estimation_perc: f32,
    pub disk_quota_full_msg: bool,
    pub max_files_per_second: u32,
    pub nodiff: Option<Vec<String>>,
    pub nodiff_regex: Option<Vec<OsMatch>>,
    pub sync_interval: u32,
    pub sync_response_timeout: u32,
    pub sync_max_interval: u32,
    pub sync_thread_pool: i32,
    pub sync_max_eps: i64,
    pub max_eps: i32,
    pub sync_queue_size: u32,
    pub registry_limit_enabled: bool,
    pub db_entry_registry_limit: i32,
    pub key_ignore: Option<Vec<RegistryIgnore>>,
    pub key_ignore_regex: Option<Vec<RegistryIgnoreRegex>>,
    pub value_ignore: Option<Vec<RegistryIgnore>>,
    pub value_ignore_regex: Option<Vec<RegistryIgnoreRegex>>,
    /// None until a `<windows_registry>` is read (then `REGISTRY_EMPTY` is not used).
    pub registry: Option<Vec<Registry>>,
    pub max_fd_win_rt: u32,
    /// `wdata.interval_scan`
    pub wdata_interval_scan: i32,
    pub registry_nodiff: Option<Vec<RegistryIgnore>>,
    pub registry_nodiff_regex: Option<Vec<RegistryIgnoreRegex>>,
    pub max_audit_entries: i32,
    pub audit_key: Vec<String>,
    pub audit_healthcheck: bool,
    pub sym_checker_interval: i32,
    pub queue_size: u32,
    pub database_store: i32,
    pub prefilter_cmd: Option<Vec<String>>,
    pub process_priority: i32,
    pub allow_remote_prefilter_cmd: bool,
}

impl Default for SyscheckConfig {
    /// `initialize_syscheck_configuration`
    fn default() -> Self {
        SyscheckConfig {
            rootcheck: 0,
            disabled: SK_CONF_UNPARSED,
            scan_on_start: true,
            max_depth: 0,
            file_max_size: 0,
            skip_fs: SkipFs { nfs: true, dev: true, sys: true, proc_: true },
            rt_delay: 0,
            time: 43200,
            restart_audit: true,
            enable_whodata: false,
            whodata_provider: AUDIT_PROVIDER,
            enable_synchronization: true,
            enable_registry_synchronization: true,
            realtime_change: false,
            directories: Vec::new(),
            wildcards: None,
            scan_day: None,
            scan_time: None,
            scan_day_str: None,
            scan_time_str: None,
            file_limit_enabled: true,
            file_entry_limit: 100000,
            ignore: None,
            ignore_regex: None,
            disk_quota_enabled: true,
            disk_quota_limit: 1024 * 1024,
            file_size_enabled: true,
            file_size_limit: 50 * 1024,
            diff_folder_size: 0.0,
            comp_estimation_perc: 0.9,
            disk_quota_full_msg: true,
            max_files_per_second: 0,
            nodiff: None,
            nodiff_regex: None,
            sync_interval: 300,
            sync_response_timeout: 30,
            sync_max_interval: 3600,
            sync_thread_pool: 1,
            sync_max_eps: 10,
            max_eps: 50,
            sync_queue_size: 16384,
            registry_limit_enabled: true,
            db_entry_registry_limit: 100000,
            key_ignore: None,
            key_ignore_regex: None,
            value_ignore: None,
            value_ignore_regex: None,
            registry: None,
            max_fd_win_rt: 0,
            wdata_interval_scan: 0,
            registry_nodiff: None,
            registry_nodiff_regex: None,
            max_audit_entries: 0,
            audit_key: Vec::new(),
            audit_healthcheck: true,
            sym_checker_interval: 0,
            queue_size: 16384,
            database_store: FIM_DB_DISK,
            prefilter_cmd: None,
            process_priority: 10,
            allow_remote_prefilter_cmd: false,
        }
    }
}

// ───────────────────────── small C helpers ─────────────────────────

/// `w_strtrim`: leading and trailing spaces only.
fn strtrim_sp(s: &str) -> &str {
    s.trim_matches(' ')
}

/// `str_lowercase` (C locale)
fn lowercase(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// `os_strip_char`
fn strip_char(s: &str, c: char) -> String {
    s.chars().filter(|&x| x != c).collect()
}

/// `atoi` of the C runtime (saturating like strtol, then truncated to int).
fn atoi(s: &str) -> i32 {
    siem_config::util::strtol(s).0 as i32
}

/// `strtol(s, &end, 10)`: the value as a C `long` and whether `*end` is NUL.
fn strtol_full(s: &str) -> (i64, bool) {
    let (v, end) = siem_config::util::strtol(s);
    #[cfg(windows)]
    let v = v.clamp(i32::MIN as i64, i32::MAX as i64);
    (v, end == s.len() || (end == 0 && s.is_empty()))
}

fn regex_compile(ctx: &mut ConfigContext, pattern: &str) -> Option<OsMatch> {
    match OsMatch::compile(pattern, 0) {
        Ok(m) => Some(m),
        Err(e) => {
            ctx.error(messages::regex_compile(pattern, e as i32));
            None
        }
    }
}

/// `read_data_unit`: KB, -1 on error.
pub fn read_data_unit(content: &str) -> i32 {
    let b = content.as_bytes();
    let len = b.len();
    let last = if len > 0 { b[len - 1] } else { 0 };
    if last == b'B' || last == b'b' {
        let unit = if len >= 2 { b[len - 2] } else { 0 };
        if unit.is_ascii_alphabetic() {
            let num = &content[..len - 2];
            if !siem_regex::str_is_num(num) {
                return -1;
            }
            let read_value = atoi(num);
            let mut converted = match unit {
                b'M' | b'm' => read_value.wrapping_mul(1024),
                b'G' | b'g' => read_value.wrapping_mul(1024 * 1024),
                b'T' | b't' => read_value.wrapping_mul(1024 * 1024 * 1024),
                _ => read_value,
            };
            if converted < 0 && read_value > 0 {
                converted = i32::MAX;
            }
            converted
        } else if unit.is_ascii_digit() {
            -1
        } else {
            // "B" alone or a non-alphanumeric before it: converted_value stays 0
            0
        }
    } else if last.is_ascii_digit() {
        if !siem_regex::str_is_num(content) {
            return -1;
        }
        atoi(content)
    } else {
        -1
    }
}

/// `fim_adjust_path`: lowercase, `sysnative` -> `system32`.
pub fn fim_adjust_path(ctx: &mut ConfigContext, path: &str) -> String {
    let p = lowercase(path);
    if p.contains("sysnative") {
        let n = p.replace("sysnative", "system32");
        ctx.debug2(format!("(6307): Convert '{p}' to '{n}' to process the FIM events."));
        return n;
    }
    p
}

/// `GetFullPathName(dir, PATH_MAX, ...)`
#[cfg(windows)]
fn full_path_name(dir: &str) -> Option<String> {
    let c = std::ffi::CString::new(dir).ok()?;
    let mut buf = [0u8; PATH_MAX];
    // SAFETY: the C buffer and its size.
    let n = unsafe { windows_sys::Win32::Storage::FileSystem::GetFullPathNameA(c.as_ptr() as *const u8, PATH_MAX as u32, buf.as_mut_ptr(), std::ptr::null_mut()) };
    if n == 0 {
        return None;
    }
    let end = buf.iter().position(|&x| x == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// `format_path`
pub fn format_path(dir: &str) -> Option<String> {
    if dir.is_empty() {
        return None;
    }
    #[cfg(windows)]
    let mut clean = {
        let mut d = dir.replace('/', "\\");
        if d.len() == 2 {
            d.push('\\');
        }
        lowercase(&full_path_name(&d)?)
    };
    #[cfg(unix)]
    let mut clean = dir.to_string();
    let keep = if cfg!(windows) { 3 } else { 1 };
    if clean.len() != keep && clean.as_bytes().last() == Some(&PATH_SEP) {
        clean.pop();
    }
    Some(clean)
}

/// `ExpandEnvironmentStrings` of the 32-bit agent (WOW64 values of `%ProgramFiles%`, ...).
#[cfg(windows)]
pub fn expand_env(s: &str) -> Option<String> {
    use siem_sysinfo::win::enc::{ansi_to_wstring, expand_env_w32, wstring_to_ansi};
    let w = expand_env_w32(&ansi_to_wstring(s.as_bytes()))?;
    Some(String::from_utf8_lossy(&wstring_to_ansi(&w)).into_owned())
}

/// `get_paths_from_env_variable`
fn get_paths_from_env_variable(ctx: &mut ConfigContext, var: &str) -> Vec<String> {
    #[cfg(windows)]
    let (expanded, delim) = match expand_env(var) {
        Some(e) => (lowercase(&e), ';'),
        None => {
            // SAFETY: plain Win32 call.
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            ctx.error(format!("(6718): Could not expand the environment variable {var} ({err})."));
            return vec![var.to_string()];
        }
    };
    #[cfg(unix)]
    let (expanded, delim) = {
        let Some(name) = var.strip_prefix('$') else { return vec![var.to_string()] };
        match std::env::var(name) {
            Ok(v) => (v, ':'),
            Err(_) => {
                ctx.error(format!("(6718): Could not expand the environment variable {name}."));
                return vec![var.to_string()];
            }
        }
    };
    let _ = &ctx;
    let mut paths: Vec<String> = expanded.split(delim).filter(|t| !t.is_empty()).map(|t| strtrim_sp(t).to_string()).collect();
    if paths.is_empty() {
        paths.push(var.to_string());
    }
    paths
}

/// `expand_wildcards` (Windows: `expand_win32_wildcards`, `FindFirstFileW`).
#[cfg(windows)]
pub fn expand_wildcards(ctx: &mut ConfigContext, path: &str) -> Option<Vec<String>> {
    use windows_sys::Win32::Storage::FileSystem::{FindClose, FindFirstFileW, FindNextFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, WIN32_FIND_DATAW};
    if siem_fileop::crt::is_network_path(path) {
        ctx.warn(siem_fileop::crt::network_path_executed(path));
        return None;
    }
    let mut pending: Vec<String> = vec![path.to_string()];
    loop {
        let Some(first) = pending.first() else { return Some(pending) };
        if !first.contains(['*', '?']) {
            return Some(pending);
        }
        let mut expanded: Vec<String> = Vec::new();
        for pattern in std::mem::take(&mut pending) {
            let gpos = pattern.find(['*', '?']).unwrap_or(pattern.len());
            let (pat, next_glob) = match pattern[gpos..].find('\\') {
                Some(i) => (pattern[..gpos + i].to_string(), Some(pattern[gpos + i + 1..].to_string())),
                None => (pattern.clone(), None),
            };
            let mut parent = pat.clone();
            if let Some(i) = parent.rfind('\\') {
                parent.truncate(i);
            }
            let wpat: Vec<u16> = pat.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: a find handle opened and closed here.
            unsafe {
                let mut fd: WIN32_FIND_DATAW = std::mem::zeroed();
                let h = FindFirstFileW(wpat.as_ptr(), &mut fd);
                if h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                    let e = windows_sys::Win32::Foundation::GetLastError();
                    match e {
                        2 => ctx.debug2(format!("No file that matches {pat}.")),
                        3 => ctx.debug2(format!("No folder that matches {pat}.")),
                        _ => ctx.debug2(format!("FindFirstFile failed ({e}) - '{pat}'\n")),
                    }
                    continue;
                }
                loop {
                    let n = fd.cFileName.iter().position(|&c| c == 0).unwrap_or(fd.cFileName.len());
                    let name = String::from_utf16_lossy(&fd.cFileName[..n]);
                    let skip = name == "."
                        || name == ".."
                        || fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                        || (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 && next_glob.is_some());
                    if !skip {
                        let mut p = format!("{parent}\\{name}");
                        if let Some(g) = &next_glob {
                            p.push('\\');
                            p.push_str(g);
                        }
                        expanded.push(p);
                    }
                    if FindNextFileW(h, &mut fd) == 0 {
                        break;
                    }
                }
                FindClose(h);
            }
        }
        if expanded.is_empty() {
            return None;
        }
        pending = expanded;
    }
}

/// `expand_wildcards` (Unix: `glob`).
#[cfg(unix)]
pub fn expand_wildcards(ctx: &mut ConfigContext, path: &str) -> Option<Vec<String>> {
    let c = std::ffi::CString::new(path).ok()?;
    // SAFETY: glob_t filled by glob and freed by globfree.
    unsafe {
        let mut g: libc::glob_t = std::mem::zeroed();
        let st = libc::glob(c.as_ptr(), 0, None, &mut g);
        if st == libc::GLOB_NOMATCH {
            ctx.debug2(format!("(6359): No matches found for the glob pattern: '{path}'"));
            return None;
        } else if st != 0 {
            ctx.error(format!("(1121): Glob error. Invalid pattern: '{path}'."));
            return None;
        }
        let mut out = Vec::new();
        for i in 0..g.gl_pathc {
            out.push(std::ffi::CStr::from_ptr(*g.gl_pathv.add(i)).to_string_lossy().into_owned());
        }
        libc::globfree(&mut g);
        if out.is_empty() {
            ctx.error(format!("(1122): No file found by pattern: '{path}'."));
            return None;
        }
        Some(out)
    }
}

// ───────────────────────── directories ─────────────────────────

/// `fim_create_directory`
#[allow(clippy::too_many_arguments)]
pub fn fim_create_directory(ctx: &mut ConfigContext, path: &str, options: i32, filerestrict: Option<&str>, recursion_level: i32, tag: Option<&str>, diff_size_limit: i32, is_wildcard: bool) -> Directory {
    #[cfg(unix)]
    let symbolic_links = (options & CHECK_FOLLOW != 0).then(|| std::fs::canonicalize(path).ok().map(|p| p.to_string_lossy().into_owned())).flatten();
    #[cfg(windows)]
    let symbolic_links = None;
    Directory {
        path: path.to_string(),
        options,
        diff_size_limit,
        symbolic_links,
        filerestrict: filerestrict.and_then(|r| regex_compile(ctx, r)),
        recursion_level,
        tag: tag.map(str::to_string),
        is_wildcard,
        is_expanded: false,
        dirs_status: DirStatus::default(),
    }
}

/// `fim_copy_directory`
fn fim_copy_directory(ctx: &mut ConfigContext, d: &Directory) -> Directory {
    fim_create_directory(ctx, &d.path, d.options, d.filerestrict.as_ref().map(|m| m.raw()), d.recursion_level, d.tag.as_deref(), d.diff_size_limit, d.is_wildcard)
}

/// `fim_insert_directory`: sorted by `strcmp`, duplicates replaced.
pub fn fim_insert_directory(list: &mut Vec<Directory>, mut new_entry: Directory) {
    for i in 0..list.len() {
        match list[i].path.as_bytes().cmp(new_entry.path.as_bytes()) {
            std::cmp::Ordering::Equal => {
                if list[i].is_wildcard == new_entry.is_wildcard || !new_entry.is_wildcard {
                    new_entry.symbolic_links = list[i].symbolic_links.clone();
                    list[i] = new_entry;
                }
                return;
            }
            std::cmp::Ordering::Greater => {
                list.insert(i, new_entry);
                return;
            }
            std::cmp::Ordering::Less => {}
        }
    }
    list.push(new_entry);
}

fn fim_set_check_all(opts: &mut i32) {
    *opts |= CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM | CHECK_PERM | CHECK_SIZE | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_INODE;
    #[cfg(windows)]
    {
        *opts |= CHECK_ATTRS;
    }
}

/// `read_attr`: the `<directories>` element. Always true (the C returns 1).
fn read_attr(ctx: &mut ConfigContext, sc: &mut SyscheckConfig, dirs: &str, attrs: &[String], values: &[String]) -> bool {
    let Some(dir_list) = siem_regex::strings::str_break(',', dirs, MAX_DIR_SIZE + 1) else { return false };
    let mut restrictfile: Option<String> = None;
    let mut recursion_limit = sc.max_depth;
    let mut tag: Option<String> = None;
    let mut tmp_diff_size = -1;
    let mut opts = SCHEDULED_ACTIVE;
    fim_set_check_all(&mut opts);

    macro_rules! yes_no {
        ($v:expr, $a:expr, $yes:block, $no:block) => {
            if $v == "yes" {
                $yes
            } else if $v == "no" {
                $no
            } else {
                ctx.warn(format!("(6924): Invalid option '{}' for attribute '{}'. The paths '{}' will not be monitored.", $v, $a, dirs));
                return true;
            }
        };
    }
    for (a, v) in attrs.iter().zip(values.iter()) {
        let (a, v) = (a.as_str(), v.as_str());
        match a {
            "check_all" => yes_no!(v, a, { fim_set_check_all(&mut opts) }, {
                opts &= !(CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_PERM | CHECK_SHA256SUM | CHECK_SIZE | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_INODE);
                #[cfg(windows)]
                {
                    opts &= !CHECK_ATTRS;
                }
            }),
            "check_sum" => yes_no!(v, a, { opts |= CHECK_SUM }, { opts &= !CHECK_SUM }),
            "check_md5sum" => yes_no!(v, a, { opts |= CHECK_MD5SUM }, { opts &= !CHECK_MD5SUM }),
            "check_sha1sum" => yes_no!(v, a, { opts |= CHECK_SHA1SUM }, { opts &= !CHECK_SHA1SUM }),
            "check_sha256sum" => yes_no!(v, a, { opts |= CHECK_SHA256SUM }, { opts &= !CHECK_SHA256SUM }),
            "whodata" => yes_no!(
                v,
                a,
                {
                    opts &= !SCHEDULED_ACTIVE;
                    opts |= WHODATA_ACTIVE;
                },
                { opts &= !WHODATA_ACTIVE }
            ),
            "check_perm" => yes_no!(v, a, { opts |= CHECK_PERM }, { opts &= !CHECK_PERM }),
            "check_size" => yes_no!(v, a, { opts |= CHECK_SIZE }, { opts &= !CHECK_SIZE }),
            "check_owner" => yes_no!(v, a, { opts |= CHECK_OWNER }, { opts &= !CHECK_OWNER }),
            "check_group" => yes_no!(v, a, { opts |= CHECK_GROUP }, { opts &= !CHECK_GROUP }),
            "check_mtime" => yes_no!(v, a, { opts |= CHECK_MTIME }, { opts &= !CHECK_MTIME }),
            "check_inode" => yes_no!(v, a, { opts |= CHECK_INODE }, { opts &= !CHECK_INODE }),
            "check_attrs" => {
                #[cfg(windows)]
                yes_no!(v, a, { opts |= CHECK_ATTRS }, { opts &= !CHECK_ATTRS });
                #[cfg(unix)]
                ctx.debug1("Option 'check_attrs' is only available on Windows systems.");
            }
            "realtime" => yes_no!(
                v,
                a,
                {
                    opts &= !SCHEDULED_ACTIVE;
                    opts |= REALTIME_ACTIVE;
                },
                { opts &= !REALTIME_ACTIVE }
            ),
            "report_changes" => yes_no!(v, a, { opts |= CHECK_SEECHANGES }, { opts &= !CHECK_SEECHANGES }),
            "restrict" => {
                restrictfile = Some(if cfg!(windows) { lowercase(v) } else { v.to_string() });
            }
            "recursion_level" => {
                if !siem_regex::str_is_num(v) {
                    ctx.warn(messages::xml_valueerr("recursion_level", v));
                    return true;
                }
                recursion_limit = atoi(v);
                if recursion_limit < 0 {
                    ctx.warn(format!("Invalid recursion level value: {recursion_limit}. Setting default ({}).", sc.max_depth));
                    recursion_limit = sc.max_depth;
                } else if recursion_limit > MAX_DEPTH_ALLOWED {
                    ctx.warn(format!("Recursion level '{recursion_limit}' exceeding limit. Setting {MAX_DEPTH_ALLOWED}."));
                    recursion_limit = sc.max_depth;
                }
            }
            "tags" => tag = Some(v.to_string()),
            "follow_symbolic_link" => yes_no!(v, a, { opts |= CHECK_FOLLOW }, { opts &= !CHECK_FOLLOW }),
            "diff_size_limit" => {
                tmp_diff_size = read_data_unit(v);
                if tmp_diff_size == -1 {
                    ctx.warn(format!("(6924): Invalid option '{v}' for attribute '{a}'. The paths '{dirs}' will not be monitored."));
                    return true;
                }
                if tmp_diff_size < 1 {
                    tmp_diff_size = 1;
                }
            }
            _ => ctx.warn(format!("(6701): Unknown attribute '{a}' for directory option.")),
        }
    }
    if opts == 0 {
        ctx.warn(format!("(6677): No option provided for directories: '{dirs}', ignoring it."));
        return true;
    }
    if opts & WHODATA_ACTIVE != 0 && opts & REALTIME_ACTIVE != 0 {
        opts &= !REALTIME_ACTIVE;
    }
    // os_strip_char(' '), then '!', then ':' (the last result is the tag used)
    let clean_tag = tag.as_deref().map(|t| strip_char(&strip_char(&strip_char(t, ' '), '!'), ':'));

    for (j, d) in dir_list.iter().enumerate() {
        if j >= MAX_DIR_SIZE {
            ctx.warn(format!("(6930): Maximum number of directories to be monitored in the same tag reached ({MAX_DIR_SIZE}) Excess are discarded: '{d}'"));
            continue;
        }
        let tmp_dir = strtrim_sp(d);
        if tmp_dir.is_empty() {
            ctx.debug2("(6338): Empty directories tag found in the configuration.");
            continue;
        }
        for p in get_paths_from_env_variable(ctx, tmp_dir) {
            if p.is_empty() {
                ctx.warn(format!("(6947): Error formatting path: '{p}'"));
                continue;
            }
            let Some(clean_path) = format_path(&p) else { continue };
            if clean_path.contains(['*', '?', '[']) {
                let wildcard = fim_create_directory(ctx, &clean_path, opts, restrictfile.as_deref(), recursion_limit, clean_tag.as_deref(), tmp_diff_size, true);
                if wildcard.options & WHODATA_ACTIVE != 0 {
                    sc.enable_whodata = true;
                }
                if let Some(paths) = expand_wildcards(ctx, &clean_path) {
                    for ep in paths {
                        let mut e = fim_copy_directory(ctx, &wildcard);
                        e.path = ep;
                        #[cfg(unix)]
                        if e.options & CHECK_FOLLOW != 0 {
                            e.symbolic_links = std::fs::canonicalize(&e.path).ok().map(|p| p.to_string_lossy().into_owned());
                        }
                        if e.diff_size_limit == -1 {
                            e.diff_size_limit = sc.file_size_limit;
                        }
                        fim_insert_directory(&mut sc.directories, e);
                    }
                }
                fim_insert_directory(sc.wildcards.get_or_insert_with(Vec::new), wildcard);
            } else {
                let e = fim_create_directory(ctx, &clean_path, opts, restrictfile.as_deref(), recursion_limit, clean_tag.as_deref(), tmp_diff_size, false);
                fim_insert_directory(&mut sc.directories, e);
            }
        }
    }
    true
}

// ───────────────────────── registry (Windows) ─────────────────────────

/// `dump_syscheck_registry`
#[allow(clippy::too_many_arguments)]
fn dump_syscheck_registry(ctx: &mut ConfigContext, sc: &mut SyscheckConfig, entry: &str, opts: i32, restrict_key: Option<&str>, restrict_value: Option<&str>, recursion_level: i32, tag: Option<&str>, arch: i32, diff_size: i32) {
    let reg = sc.registry.get_or_insert_with(Vec::new);
    let pos = reg.iter().position(|r| r.entry.eq_ignore_ascii_case(entry) && r.arch == arch);
    if let Some(p) = pos {
        ctx.debug2(format!("Duplicated registration entry: {}", reg[p].entry));
    }
    let r = Registry {
        entry: entry.to_string(),
        arch,
        opts,
        recursion_level,
        diff_size_limit: diff_size,
        restrict_key: restrict_key.and_then(|k| regex_compile(ctx, k)),
        restrict_value: restrict_value.and_then(|k| regex_compile(ctx, k)),
        tag: tag.map(str::to_string),
    };
    let reg = sc.registry.get_or_insert_with(Vec::new);
    match pos {
        Some(p) => reg[p] = r,
        None => reg.push(r),
    }
}

fn dump_registry_ignore(sc: &mut SyscheckConfig, entry: &str, arch: i32, value: bool) {
    let list = if value { &mut sc.value_ignore } else { &mut sc.key_ignore };
    let list = list.get_or_insert_with(Vec::new);
    if !list.iter().any(|i| i.arch == arch && i.entry == entry) {
        list.push(RegistryIgnore { entry: entry.to_string(), arch });
    }
}

fn dump_registry_ignore_regex(ctx: &mut ConfigContext, sc: &mut SyscheckConfig, regex: &str, arch: i32, value: bool) {
    let m = regex_compile(ctx, regex);
    let list = if value { &mut sc.value_ignore_regex } else { &mut sc.key_ignore_regex };
    let list = list.get_or_insert_with(Vec::new);
    if let Some(regex) = m {
        list.push(RegistryIgnoreRegex { regex, arch });
    }
}

fn dump_registry_nodiff(sc: &mut SyscheckConfig, entry: &str, arch: i32) {
    let list = sc.registry_nodiff.get_or_insert_with(Vec::new);
    if !list.iter().any(|i| i.arch == arch && i.entry == entry) {
        list.push(RegistryIgnore { entry: entry.to_string(), arch });
    }
}

fn dump_registry_nodiff_regex(ctx: &mut ConfigContext, sc: &mut SyscheckConfig, regex: &str, arch: i32) {
    let m = regex_compile(ctx, regex);
    let list = sc.registry_nodiff_regex.get_or_insert_with(Vec::new);
    if let Some(regex) = m {
        list.push(RegistryIgnoreRegex { regex, arch });
    }
}

/// `expand_wildcard_registers` (`shared/syscheck_op.c`)
#[cfg(windows)]
pub fn expand_wildcard_registers(entry: &str) -> Vec<String> {
    use windows_sys::Win32::System::Registry::{RegCloseKey, RegEnumKeyExA, RegOpenKeyExA, RegQueryInfoKeyA, HKEY, KEY_READ, KEY_WOW64_64KEY};
    struct P {
        path: String,
        has_wildcard: bool,
        checked: bool,
    }
    let check_wildcard = |s: &str| s.contains(['*', '?']);
    let root_key = |s: &str| -> Option<HKEY> {
        use windows_sys::Win32::System::Registry::*;
        match s {
            "HKEY_CLASSES_ROOT" => Some(HKEY_CLASSES_ROOT),
            "HKEY_CURRENT_CONFIG" => Some(HKEY_CURRENT_CONFIG),
            "HKEY_CURRENT_USER" => Some(HKEY_CURRENT_USER),
            "HKEY_LOCAL_MACHINE" => Some(HKEY_LOCAL_MACHINE),
            "HKEY_USERS" => Some(HKEY_USERS),
            _ => None,
        }
    };
    // get_subkey: the path between the root and the first wildcard component
    let get_subkey = |key: &str| -> String {
        let rest = key.split_once('\\').map(|(_, r)| r).unwrap_or("");
        let mut sub = String::new();
        for t in rest.split('\\').filter(|t| !t.is_empty()) {
            if t.contains(['?', '*']) {
                break;
            }
            sub.push_str(t);
            sub.push('\\');
        }
        if sub.len() > 1 {
            sub.pop();
            sub
        } else {
            String::new()
        }
    };
    let list_all_keys = |root: HKEY, sub: &str| -> Vec<String> {
        let mut out = Vec::new();
        let c = std::ffi::CString::new(sub).unwrap_or_default();
        // SAFETY: a key opened and closed here; the C buffer sizes.
        unsafe {
            let mut h: HKEY = std::ptr::null_mut();
            if RegOpenKeyExA(root, c.as_ptr() as *const u8, 0, KEY_READ | KEY_WOW64_64KEY, &mut h) == 0 {
                let mut class = [0u8; 256];
                let mut class_n = 256u32;
                let mut subkeys = 0u32;
                if RegQueryInfoKeyA(h, class.as_mut_ptr(), &mut class_n, std::ptr::null(), &mut subkeys, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) == 0 {
                    for i in 0..subkeys {
                        let mut name = [0u8; 256];
                        let mut n = 256u32;
                        if RegEnumKeyExA(h, i, name.as_mut_ptr(), &mut n, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) == 0 {
                            out.push(String::from_utf8_lossy(&name[..n as usize]).into_owned());
                        }
                    }
                }
                RegCloseKey(h);
            }
        }
        out
    };
    let path_match_spec = |name: &str, spec: &str| -> bool {
        let (n, s) = (std::ffi::CString::new(name).unwrap_or_default(), std::ffi::CString::new(spec).unwrap_or_default());
        // SAFETY: NUL-terminated strings.
        unsafe { windows_sys::Win32::UI::Shell::PathMatchSpecA(n.as_ptr() as *const u8, s.as_ptr() as *const u8) != 0 }
    };

    let mut v: Vec<P> = vec![P { path: entry.to_string(), has_wildcard: check_wildcard(entry), checked: false }];
    let mut cur = 0;
    while v[cur..].iter().any(|p| p.has_wildcard && !p.checked) {
        let path = v[cur].path.clone();
        let (q, s) = (path.find('?'), path.find('*'));
        let wc = match (q, s) {
            (Some(a), Some(b)) => Some(if a < b { '?' } else { '*' }),
            (None, Some(_)) => Some('*'),
            (Some(_), None) => Some('?'),
            (None, None) => None,
        };
        if let Some(wc) = wc {
            // first_part: up to the first wildcard, cut back to the last '\'
            let fp_raw = path.split(wc).next().unwrap_or("");
            let first_part = match fp_raw.rfind('\\') {
                Some(i) => fp_raw[..=i].to_string(),
                None => String::new(),
            };
            let matcher = (wc == '?').then(|| path.split('\\').find(|t| t.contains('?')).unwrap_or("").to_string());
            let second_part = path[path.find(wc).unwrap_or(0)..].find('\\').map(|i| path[path.find(wc).unwrap_or(0) + i..].to_string());
            let subkey = get_subkey(&path);
            let root = root_key(first_part.split('\\').next().unwrap_or(""));
            v[cur].checked = true;
            if let Some(root) = root {
                for k in list_all_keys(root, &subkey) {
                    if let Some(m) = &matcher {
                        if !path_match_spec(&k, m) {
                            continue;
                        }
                    }
                    let mut full = format!("{first_part}{k}{}", second_part.as_deref().unwrap_or(""));
                    if full.ends_with('\\') {
                        full.pop();
                    }
                    let hw = check_wildcard(&full) && !check_wildcard(&k);
                    v.push(P { path: full, has_wildcard: hw, checked: !hw });
                }
            }
        }
        cur += 1;
        if cur >= v.len() {
            break;
        }
    }
    v.into_iter().filter(|p| !p.has_wildcard && p.checked).map(|p| p.path).collect()
}

/// `read_reg`: the `<windows_registry>` element.
#[cfg(windows)]
fn read_reg(ctx: &mut ConfigContext, sc: &mut SyscheckConfig, entries: &str, attrs: &[String], values: &[String]) -> bool {
    let mut tag: Option<String> = None;
    let mut restrict_key: Option<String> = None;
    let mut restrict_value: Option<String> = None;
    let mut arch = ARCH_32BIT;
    let mut recursion_level = MAX_REGISTRY_DEPTH;
    let mut opts = REGISTRY_CHECK_ALL;
    let mut tmp_diff_size = -1;
    for (i, a) in attrs.iter().enumerate() {
        let Some(v) = values.get(i) else {
            ctx.debug1(format!("Empty value for attribute {a}"));
            break;
        };
        let bad = |ctx: &mut ConfigContext| ctx.warn(format!("(6937): Invalid option '{v}' for attribute '{a}'. The registry '{entries}' not be monitored."));
        let flag = |opt: &mut i32, bit: i32, ctx: &mut ConfigContext| -> bool {
            match v.as_str() {
                "yes" => *opt |= bit,
                "no" => *opt &= !bit,
                _ => {
                    bad(ctx);
                    return false;
                }
            }
            true
        };
        let ok = match a.as_str() {
            "tags" => {
                tag = Some(strip_char(v, ' '));
                true
            }
            "arch" => match v.as_str() {
                "32bit" => true,
                "64bit" => {
                    arch = ARCH_64BIT;
                    true
                }
                "both" => {
                    arch = ARCH_BOTH;
                    true
                }
                _ => {
                    ctx.warn(messages::xml_invattr(a, entries));
                    false
                }
            },
            "recursion_level" => {
                if !siem_regex::str_is_num(v) {
                    ctx.warn(messages::xml_valueerr("recursion_level", entries));
                    false
                } else {
                    recursion_level = atoi(v);
                    if !(0..=MAX_REGISTRY_DEPTH).contains(&recursion_level) {
                        ctx.warn(format!("Invalid recursion level value: {recursion_level}. Setting default ({MAX_REGISTRY_DEPTH})."));
                        recursion_level = MAX_REGISTRY_DEPTH;
                    }
                    true
                }
            }
            "report_changes" => flag(&mut opts, CHECK_SEECHANGES, ctx),
            "restrict_key" => {
                restrict_key = Some(v.clone());
                true
            }
            "restrict_value" => {
                restrict_value = Some(v.clone());
                true
            }
            "check_all" => flag(&mut opts, REGISTRY_CHECK_ALL, ctx),
            "check_sum" => flag(&mut opts, CHECK_SUM, ctx),
            "check_md5sum" => flag(&mut opts, CHECK_MD5SUM, ctx),
            "check_sha1sum" => flag(&mut opts, CHECK_SHA1SUM, ctx),
            "check_sha256sum" => flag(&mut opts, CHECK_SHA256SUM, ctx),
            "check_size" => flag(&mut opts, CHECK_SIZE, ctx),
            "check_owner" => flag(&mut opts, CHECK_OWNER, ctx),
            "check_group" => flag(&mut opts, CHECK_GROUP, ctx),
            "check_perm" => flag(&mut opts, CHECK_PERM, ctx),
            "check_mtime" => flag(&mut opts, CHECK_MTIME, ctx),
            "check_type" => flag(&mut opts, CHECK_TYPE, ctx),
            "diff_size_limit" => {
                tmp_diff_size = read_data_unit(v);
                if tmp_diff_size == -1 {
                    bad(ctx);
                    false
                } else {
                    tmp_diff_size = tmp_diff_size.max(1);
                    true
                }
            }
            _ => {
                ctx.warn(messages::xml_invattr(a, entries));
                false
            }
        };
        if !ok {
            return false;
        }
    }
    let Some(list) = siem_regex::strings::str_break(',', entries, MAX_DIR_SIZE + 1) else { return false };
    for (i, e) in list.iter().enumerate() {
        if i >= MAX_DIR_SIZE {
            ctx.warn(format!("(6931): Maximum number of registries to be monitored in the same tag reached ({MAX_DIR_SIZE}) Excess are discarded: '{e}'"));
            continue;
        }
        let tmp = e.trim_end_matches(' ').trim_start_matches(' ');
        if tmp.is_empty() {
            ctx.debug2("(6353): Empty windows_registry tag found in the configuration.");
            continue;
        }
        // the wildcard expansion reads the untrimmed entry; the plain entry is the trimmed one
        let expanded = expand_wildcard_registers(e.trim_end_matches(' '));
        let add = |ctx: &mut ConfigContext, sc: &mut SyscheckConfig, p: &str| {
            if arch == ARCH_BOTH {
                dump_syscheck_registry(ctx, sc, p, opts, restrict_key.as_deref(), restrict_value.as_deref(), recursion_level, tag.as_deref(), ARCH_64BIT, tmp_diff_size);
                dump_syscheck_registry(ctx, sc, p, opts, restrict_key.as_deref(), restrict_value.as_deref(), recursion_level, tag.as_deref(), ARCH_32BIT, tmp_diff_size);
            } else {
                dump_syscheck_registry(ctx, sc, p, opts, restrict_key.as_deref(), restrict_value.as_deref(), recursion_level, tag.as_deref(), arch, tmp_diff_size);
            }
        };
        if !expanded.is_empty() {
            ctx.debug1("(6372): Starting configuration for Windows registry wildcards.");
            for p in &expanded {
                ctx.debug2(format!("(6373): Expanding entry '{}' to '{p}' to monitor FIM events.", e.trim_end_matches(' ')));
                add(ctx, sc, p);
            }
            ctx.debug1("(6374): Wildcard configuration successfully completed.");
        } else {
            add(ctx, sc, tmp);
        }
    }
    true
}

// ───────────────────────── sub-blocks ─────────────────────────

/// `parse_synchronization`
fn parse_synchronization(ctx: &mut ConfigContext, sc: &mut SyscheckConfig, nodes: &[XmlNode]) {
    for n in nodes {
        let c = n.content.as_deref().unwrap_or("");
        let err = |ctx: &mut ConfigContext| ctx.warn(messages::xml_valueerr(&n.element, c));
        match n.element.as_str() {
            "enabled" => match c {
                "yes" => sc.enable_synchronization = true,
                "no" => sc.enable_synchronization = false,
                _ => err(ctx),
            },
            "interval" => match siem_config::util::parse_time(c) {
                t if t <= 0 => err(ctx),
                t => sc.sync_interval = t as u32,
            },
            "max_interval" => match siem_config::util::parse_time(c) {
                t if t < 0 => err(ctx),
                t => sc.sync_max_interval = t as u32,
            },
            "response_timeout" => match siem_config::util::parse_time(c) {
                t if t < 0 => err(ctx),
                t => sc.sync_response_timeout = t as u32,
            },
            "queue_size" => {
                let (v, full) = strtol_full(c);
                if !(2..=1000000).contains(&v) || !full {
                    err(ctx)
                } else {
                    sc.sync_queue_size = v as u32
                }
            }
            "max_eps" => {
                let (v, full) = strtol_full(c);
                if !(0..=1000000).contains(&v) || !full {
                    err(ctx)
                } else {
                    sc.sync_max_eps = v
                }
            }
            "registry_enabled" => {
                #[cfg(windows)]
                match c {
                    "yes" => sc.enable_registry_synchronization = true,
                    "no" => sc.enable_registry_synchronization = false,
                    _ => err(ctx),
                }
            }
            "thread_pool" => {
                if !siem_regex::str_is_num(c) {
                    err(ctx)
                } else {
                    let v = atoi(c);
                    if v < 1 {
                        err(ctx)
                    } else {
                        sc.sync_thread_pool = v
                    }
                }
            }
            e => ctx.warn(messages::xml_invelem(e)),
        }
    }
    if sc.sync_max_interval < sc.sync_interval {
        sc.sync_max_interval = sc.sync_interval;
        ctx.warn(format!("'max_interval' cannot be less than 'interval'. New 'max_interval' value: '{}'", sc.sync_interval));
    }
}

/// `process_option_regex`: false on a compile error.
fn process_option_regex(ctx: &mut ConfigContext, option: &str, list: &mut Option<Vec<OsMatch>>, content: &str) -> bool {
    let l = list.get_or_insert_with(Vec::new);
    let n = l.len();
    ctx.debug1(format!("Found {option} regex node {content}"));
    let Some(m) = regex_compile(ctx, content) else { return false };
    l.push(m);
    ctx.debug1(format!("Found {option} regex node {content} OK?"));
    ctx.debug1(format!("Found {option} regex size {n}"));
    true
}

/// `process_option`: plain `<ignore>` / `<nodiff>` entries.
fn process_option(ctx: &mut ConfigContext, list: &mut Option<Vec<String>>, content: &str) {
    let dir = content;
    let tmp = strtrim_sp(dir);
    for p in get_paths_from_env_variable(ctx, tmp) {
        if p.is_empty() {
            continue;
        }
        let Some(clean) = format_path(&p) else {
            ctx.warn(format!("(6947): Error formatting path: '{p}'"));
            continue;
        };
        // os_IsStrOnArray(dir, ...): the raw content is what is looked up
        if !list.as_ref().is_some_and(|l| l.iter().any(|x| x == dir)) {
            list.get_or_insert_with(Vec::new).push(clean);
        }
    }
}

/// `parse_diff`
fn parse_diff(ctx: &mut ConfigContext, xml: &OsXml, sc: &mut SyscheckConfig, nodes: &[XmlNode]) {
    for n in nodes {
        let raw = n.content.clone().unwrap_or_default();
        if n.element == "nodiff" {
            #[cfg(windows)]
            let content = match expand_env(&raw) {
                Some(e) => lowercase(&e[..e.len().min(2046)]),
                None => {
                    // SAFETY: plain Win32 call.
                    let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                    ctx.error(format!("Could not expand the environment variable {raw} ({err})"));
                    continue;
                }
            };
            #[cfg(unix)]
            let content = raw.clone();
            if let (Some(a), Some(v)) = (n.attributes.first(), n.values.first()) {
                if a == "type" && v == "sregex" {
                    ctx.debug1(format!("Found nodiff regex node {content}"));
                    match regex_compile(ctx, &content) {
                        Some(m) => sc.nodiff_regex.get_or_insert_with(Vec::new).push(m),
                        None => return,
                    }
                } else {
                    ctx.warn(format!("(6679): Invalid attribute '{a}' for '{}' option.", n.element));
                    return;
                }
            } else if !sc.nodiff.as_ref().is_some_and(|l| l.contains(&content)) {
                sc.nodiff.get_or_insert_with(Vec::new).push(content);
            }
        }
        #[cfg(windows)]
        if n.element == "registry_nodiff" {
            let Some(content) = expand_env(&raw).map(|e| e[..e.len().min(2046)].to_string()) else {
                // SAFETY: plain Win32 call.
                let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                ctx.error(format!("Could not expand the environment variable {raw} ({err})"));
                continue;
            };
            let (mut sregex, mut arch) = (false, ARCH_32BIT);
            for (a, v) in n.attributes.iter().zip(n.values.iter()) {
                if a == "type" && v == "sregex" {
                    sregex = true;
                } else if a == "arch" {
                    arch = match v.as_str() {
                        "32bit" => ARCH_32BIT,
                        "64bit" => ARCH_64BIT,
                        "both" => ARCH_BOTH,
                        _ => {
                            ctx.warn(messages::xml_invattr(a, &content));
                            return;
                        }
                    };
                } else {
                    ctx.warn(messages::xml_invattr(a, &content));
                    return;
                }
            }
            let archs: &[i32] = if arch == ARCH_BOTH { &[ARCH_32BIT, ARCH_64BIT] } else { std::slice::from_ref(&arch) };
            for &a in archs {
                if sregex {
                    dump_registry_nodiff_regex(ctx, sc, &content, a);
                } else {
                    dump_registry_nodiff(sc, &content, a);
                }
            }
            continue;
        }
        let limits = |ctx: &mut ConfigContext, enabled: &mut bool, limit: &mut i32| -> bool {
            let Some(ch) = xml.get_elements_by_node(Some(n)) else { return true };
            for c in &ch {
                let cc = c.content.as_deref().unwrap_or("");
                if c.element == "enabled" {
                    match cc {
                        "yes" => *enabled = true,
                        "no" => *enabled = false,
                        _ => {
                            ctx.warn(messages::xml_valueerr(&c.element, cc));
                            return false;
                        }
                    }
                } else if c.element == "limit" {
                    if c.content.is_none() {
                        ctx.warn(messages::xml_valueerr(&c.element, ""));
                        return false;
                    }
                    *limit = read_data_unit(cc);
                    if *limit == -1 {
                        ctx.warn(messages::xml_valueerr(&c.element, cc));
                        return false;
                    }
                    *limit = (*limit).max(1);
                }
            }
            true
        };
        if n.element == "disk_quota" {
            let (mut e, mut l) = (sc.disk_quota_enabled, sc.disk_quota_limit);
            let ok = limits(ctx, &mut e, &mut l);
            sc.disk_quota_enabled = e;
            sc.disk_quota_limit = l;
            if !ok {
                return;
            }
        } else if n.element == "file_size" {
            let (mut e, mut l) = (sc.file_size_enabled, sc.file_size_limit);
            let ok = limits(ctx, &mut e, &mut l);
            sc.file_size_enabled = e;
            sc.file_size_limit = l;
            if !ok {
                return;
            }
        }
    }
    if sc.file_size_enabled && sc.disk_quota_limit < sc.file_size_limit {
        sc.disk_quota_limit = sc.file_size_limit;
        ctx.debug2(format!("Setting 'disk_quota' to {}, 'disk_quota' must be greater than 'file_size'", sc.disk_quota_limit));
    }
}

// ───────────────────────── Read_Syscheck ─────────────────────────

/// `Read_Syscheck`. `agent_config`: the read is of `agent.conf` (`CAGENT_CONFIG`).
pub fn read_syscheck(ctx: &mut ConfigContext, xml: &OsXml, nodes: Option<&[XmlNode]>, sc: &mut SyscheckConfig, agent_config: bool) -> CResult<()> {
    let invalid = || Err(ConfigError::new(""));
    if sc.disabled == SK_CONF_UNPARSED {
        sc.disabled = SK_CONF_UNDEFINED;
    }
    let mut prefilter_cmd = String::new();
    let nodes = nodes.unwrap_or(&[]);
    let mut i = 0;
    while i < nodes.len() {
        let n = &nodes[i];
        i += 1;
        if n.element.is_empty() {
            ctx.warn("(1231): Invalid NULL element in the configuration.");
            return invalid();
        }
        let Some(content) = n.content.as_deref() else {
            ctx.warn(messages::xml_valuenull(&n.element));
            return invalid();
        };
        let yes_no = |ctx: &mut ConfigContext| -> Option<bool> {
            match content {
                "yes" => Some(true),
                "no" => Some(false),
                _ => {
                    ctx.warn(messages::xml_valueerr(&n.element, content));
                    None
                }
            }
        };
        match n.element.as_str() {
            "directories" => {
                #[cfg(windows)]
                let content = {
                    if siem_fileop::crt::is_network_path(content) {
                        ctx.warn(format!("(9801): Network path not allowed in configuration. '{}': {content}.", n.element));
                        continue;
                    }
                    fim_adjust_path(ctx, content)
                };
                // strncpy(dirs, content, OS_MAXSTR - 1)
                let mut dirs = content.to_string();
                if dirs.len() > OS_MAXSTR - 1 {
                    let mut k = OS_MAXSTR - 1;
                    while !dirs.is_char_boundary(k) {
                        k -= 1;
                    }
                    dirs.truncate(k);
                }
                if !read_attr(ctx, sc, &dirs, &n.attributes, &n.values) {
                    return invalid();
                }
            }
            "windows_registry" => {
                #[cfg(windows)]
                if !read_reg(ctx, sc, content, &n.attributes, &n.values) {
                    return invalid();
                }
            }
            "windows_audit_interval" => {
                #[cfg(windows)]
                {
                    if !siem_regex::str_is_num(content) {
                        ctx.warn(messages::xml_valueerr(&n.element, content));
                        return invalid();
                    }
                    sc.wdata_interval_scan = atoi(content);
                }
            }
            "database" => match content {
                "memory" => sc.database_store = FIM_DB_MEMORY,
                "disk" => sc.database_store = FIM_DB_DISK,
                _ => {}
            },
            "frequency" => {
                if !siem_regex::str_is_num(content) {
                    ctx.warn(messages::xml_valueerr(&n.element, content));
                    return invalid();
                }
                sc.time = atoi(content);
            }
            "scan_time" => {
                // OS_IsValidUniqueTime: "!" refused, else OS_IsValidTime("t-t")
                sc.scan_time = if content.starts_with('!') {
                    None
                } else {
                    let mut t = format!("{content}-{content}");
                    t.truncate(128);
                    siem_config::timeday::os_is_valid_time(&t)
                };
                if sc.scan_time.is_none() {
                    ctx.warn(messages::xml_valueerr(&n.element, content));
                    return invalid();
                }
                sc.scan_time_str = Some(content.to_string());
            }
            "scan_day" => {
                sc.scan_day = siem_config::timeday::os_is_valid_day(content);
                if sc.scan_day.is_none() {
                    ctx.warn(format!("(1241): Invalid day format: '{content}'."));
                    ctx.warn(messages::xml_valueerr(&n.element, content));
                    return invalid();
                }
                sc.scan_day_str = Some(content.to_string());
            }
            "file_limit" | "registry_limit" => {
                let Some(ch) = xml.get_elements_by_node(Some(n)) else { continue };
                let file = n.element == "file_limit";
                for c in &ch {
                    let cc = c.content.as_deref().unwrap_or("");
                    if c.element == "enabled" {
                        let v = match cc {
                            "yes" => true,
                            "no" => false,
                            _ => {
                                ctx.warn(messages::xml_valueerr(&c.element, cc));
                                return invalid();
                            }
                        };
                        if file {
                            sc.file_limit_enabled = v;
                        } else if cfg!(windows) {
                            sc.registry_limit_enabled = v;
                        }
                    } else if c.element == "entries" {
                        if !siem_regex::str_is_num(cc) {
                            ctx.warn(messages::xml_valueerr(&c.element, cc));
                            return invalid();
                        }
                        let mut v = atoi(cc);
                        if v < 0 {
                            ctx.debug2(format!("Maximum value allowed for {} is '{MAX_FILE_LIMIT}'", n.element));
                            v = MAX_FILE_LIMIT;
                        }
                        if file {
                            sc.file_entry_limit = v;
                        } else if cfg!(windows) {
                            sc.db_entry_registry_limit = v;
                        }
                    }
                }
                if file && !sc.file_limit_enabled {
                    sc.file_entry_limit = 0;
                }
                if !file && cfg!(windows) && !sc.registry_limit_enabled {
                    sc.db_entry_registry_limit = 0;
                }
            }
            "scan_on_start" => match yes_no(ctx) {
                Some(v) => sc.scan_on_start = v,
                None => return invalid(),
            },
            "disabled" => match yes_no(ctx) {
                Some(v) => sc.disabled = v as i32,
                None => return invalid(),
            },
            "skip_nfs" => match yes_no(ctx) {
                Some(v) => sc.skip_fs.nfs = v,
                None => return invalid(),
            },
            "skip_dev" => match yes_no(ctx) {
                Some(v) => sc.skip_fs.dev = v,
                None => return invalid(),
            },
            "skip_sys" => match yes_no(ctx) {
                Some(v) => sc.skip_fs.sys = v,
                None => return invalid(),
            },
            "skip_proc" => match yes_no(ctx) {
                Some(v) => sc.skip_fs.proc_ = v,
                None => return invalid(),
            },
            "ignore" | "nodiff" => {
                let ignore = n.element == "ignore";
                if let (Some(a), Some(v)) = (n.attributes.first(), n.values.first()) {
                    if a == "type" && v == "sregex" {
                        let list = if ignore { &mut sc.ignore_regex } else { &mut sc.nodiff_regex };
                        if !process_option_regex(ctx, &n.element, list, content) {
                            // `return result` with result 0: success, the rest of the block is not read
                            return Ok(());
                        }
                    } else {
                        ctx.warn(format!("(6679): Invalid attribute '{a}' for '{}' option.", n.element));
                        return invalid();
                    }
                } else {
                    let list = if ignore { &mut sc.ignore } else { &mut sc.nodiff };
                    process_option(ctx, list, content);
                }
            }
            e if e.starts_with("registry_ignore") => {
                #[cfg(windows)]
                {
                    let value = e == "registry_ignore_value";
                    let (mut sregex, mut arch) = (false, ARCH_32BIT);
                    for (a, v) in n.attributes.iter().zip(n.values.iter()) {
                        if a == "type" && v == "sregex" {
                            sregex = true;
                        } else if a == "arch" {
                            arch = match v.as_str() {
                                "32bit" => ARCH_32BIT,
                                "64bit" => ARCH_64BIT,
                                "both" => ARCH_BOTH,
                                _ => {
                                    ctx.warn(messages::xml_invattr(a, content));
                                    return invalid();
                                }
                            };
                        } else {
                            ctx.warn(messages::xml_invattr(a, content));
                            return invalid();
                        }
                    }
                    let archs: &[i32] = if arch == ARCH_BOTH { &[ARCH_32BIT, ARCH_64BIT] } else { std::slice::from_ref(&arch) };
                    for &a in archs {
                        if sregex {
                            dump_registry_ignore_regex(ctx, sc, content, a, value);
                        } else {
                            dump_registry_ignore(sc, content, a, value);
                        }
                    }
                }
            }
            "auto_ignore" | "alert_new_files" | "remove_old_diff" => {}
            "prefilter_cmd" => {
                #[cfg(windows)]
                {
                    match expand_env(content) {
                        Some(e) => {
                            let mut e = lowercase(&e);
                            e.truncate(OS_MAXSTR - 1);
                            prefilter_cmd = e;
                        }
                        None => {
                            // SAFETY: plain Win32 call.
                            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                            ctx.error(format!("Could not expand the environment variable {content} ({err})"));
                            continue;
                        }
                    }
                }
                #[cfg(unix)]
                {
                    prefilter_cmd = content.chars().take(OS_MAXSTR - 1).collect();
                }
                if !prefilter_cmd.is_empty() {
                    let statcmd = prefilter_cmd.split(' ').next().unwrap_or("");
                    if std::fs::metadata(statcmd).is_err() {
                        ctx.warn(messages::xml_valueerr(&n.element, content));
                        return invalid();
                    }
                }
            }
            "restart_audit" => match yes_no(ctx) {
                Some(v) => sc.restart_audit = v,
                None => return invalid(),
            },
            "whodata" => {
                let Some(ch) = xml.get_elements_by_node(Some(n)) else { continue };
                for c in &ch {
                    let cc = c.content.as_deref().unwrap_or("");
                    let bad = |ctx: &mut ConfigContext| ctx.warn(messages::xml_valueerr(&c.element, cc));
                    match c.element.as_str() {
                        "audit_key" => {
                            for k in cc.split(',').filter(|k| !k.is_empty()) {
                                sc.audit_key.push(k.to_string());
                            }
                        }
                        "startup_healthcheck" | "restart_audit" => {
                            let v = match cc {
                                "yes" => true,
                                "no" => false,
                                _ => {
                                    bad(ctx);
                                    return invalid();
                                }
                            };
                            if c.element == "startup_healthcheck" {
                                sc.audit_healthcheck = v;
                            } else {
                                sc.restart_audit = v;
                            }
                        }
                        "provider" => match cc {
                            "ebpf" => sc.whodata_provider = EBPF_PROVIDER,
                            "audit" => sc.whodata_provider = AUDIT_PROVIDER,
                            _ => {
                                bad(ctx);
                                return invalid();
                            }
                        },
                        #[cfg(unix)]
                        "queue_size" => {
                            let (v, full) = strtol_full(cc);
                            if !full || !(10..=1024 * 1024).contains(&v) {
                                ctx.error(messages::xml_valueerr(&c.element, cc));
                                return invalid();
                            }
                            sc.queue_size = v as u32;
                        }
                        _ => {
                            ctx.warn("(1231): Invalid NULL element in the configuration.");
                            return invalid();
                        }
                    }
                }
            }
            "process_priority" => {
                let (v, full) = strtol_full(content);
                if !(-20..=19).contains(&v) || !full {
                    ctx.warn(messages::xml_valueerr(&n.element, content));
                    return invalid();
                }
                sc.process_priority = v as i32;
            }
            "synchronization" => {
                if let Some(ch) = xml.get_elements_by_node(Some(n)) {
                    parse_synchronization(ctx, sc, &ch);
                }
            }
            "diff" => {
                if let Some(ch) = xml.get_elements_by_node(Some(n)) {
                    parse_diff(ctx, xml, sc, &ch);
                }
            }
            "max_eps" => {
                let (v, full) = strtol_full(content);
                if !(0..=1000000).contains(&v) || !full {
                    ctx.warn(messages::xml_valueerr(&n.element, content));
                } else {
                    sc.max_eps = v as i32;
                }
            }
            "allow_remote_prefilter_cmd" => {
                if agent_config {
                    ctx.warn("'allow_remote_prefilter_cmd' option can't be changed using centralized configuration (agent.conf).");
                    // the C skips the next element too (i++ before continue)
                    i += 1;
                    continue;
                }
                match yes_no(ctx) {
                    Some(v) => sc.allow_remote_prefilter_cmd = v,
                    None => return invalid(),
                }
            }
            "max_files_per_second" => {
                if !siem_regex::str_is_num(content) {
                    ctx.warn(messages::xml_valueerr(&n.element, content));
                    return invalid();
                }
                sc.max_files_per_second = atoi(content) as u32;
            }
            e => ctx.warn(messages::xml_invelem(e)),
        }
    }
    if !prefilter_cmd.is_empty() {
        if !agent_config || sc.allow_remote_prefilter_cmd {
            // strtok_r(" ") for the program, then each remaining tail as one argument
            let mut v: Vec<String> = Vec::new();
            let trimmed = prefilter_cmd.trim_start_matches(' ');
            let (first, mut rest) = match trimmed.find(' ') {
                Some(k) => (&trimmed[..k], &trimmed[k + 1..]),
                None => (trimmed, ""),
            };
            v.push(first.to_string());
            while !rest.is_empty() {
                v.push(rest.to_string());
                let r = rest.trim_start_matches(' ');
                rest = match r.find(' ') {
                    Some(k) => &r[k + 1..],
                    None => "",
                };
            }
            sc.prefilter_cmd = Some(v);
        } else if !sc.allow_remote_prefilter_cmd {
            ctx.warn(format!("(6905): Ignoring prefilter option '{prefilter_cmd}'. Enable <allow_remote_prefilter_cmd> to use it."));
        }
    }
    Ok(())
}

/// The adjustments `Read_Syscheck_Config` makes after both reads. Returns 1
/// when nothing is configured (as the C), else 0. `max_fd_win_rt` is the
/// value of `syscheck.max_fd_win_rt`.
pub fn finish_config(sc: &mut SyscheckConfig, max_fd_win_rt: u32) -> i32 {
    let limit = sc.file_size_limit;
    for d in &mut sc.directories {
        if d.diff_size_limit == -1 {
            d.diff_size_limit = limit;
        }
        if d.options & WHODATA_ACTIVE != 0 {
            sc.enable_whodata = true;
        }
    }
    match sc.disabled {
        SK_CONF_UNPARSED => sc.disabled = 1,
        SK_CONF_UNDEFINED => sc.disabled = 0,
        _ => {}
    }
    if cfg!(unix) {
        return if sc.directories.is_empty() && sc.wildcards.is_none() { 1 } else { 0 };
    }
    if let Some(r) = &mut sc.registry {
        for e in r.iter_mut() {
            if e.diff_size_limit == -1 {
                e.diff_size_limit = limit;
            }
        }
    }
    let no_registry = sc.registry.as_ref().map(|r| r.is_empty()).unwrap_or(true);
    if sc.directories.is_empty() && no_registry && sc.wildcards.is_none() {
        return 1;
    }
    sc.max_fd_win_rt = max_fd_win_rt;
    0
}

// ───────────────────────── getconfig dumps ─────────────────────────

/// `getSyscheckConfig` (Windows: always an object).
pub fn get_syscheck_config(sc: &SyscheckConfig) -> Option<Json> {
    if cfg!(unix) && sc.directories.is_empty() {
        return None;
    }
    let yn = |b: bool| Json::string(if b { "yes" } else { "no" });
    let num = |v: f64| Json::number(v);
    let mut s = Json::object();
    s.add("disabled", yn(sc.disabled != 0));
    s.add("frequency", num(sc.time as f64));
    s.add("skip_nfs", yn(sc.skip_fs.nfs));
    s.add("skip_dev", yn(sc.skip_fs.dev));
    s.add("skip_sys", yn(sc.skip_fs.sys));
    s.add("skip_proc", yn(sc.skip_fs.proc_));
    s.add("scan_on_start", yn(sc.scan_on_start));
    if let Some(d) = &sc.scan_day_str {
        s.add("scan_day", Json::string(d));
    }
    if let Some(t) = &sc.scan_time_str {
        s.add("scan_time", Json::string(t));
    }
    s.add("max_files_per_second", num(sc.max_files_per_second as f64));
    let mut fl = Json::object();
    fl.add("enabled", yn(sc.file_limit_enabled));
    fl.add("entries", num(sc.file_entry_limit as f64));
    s.add("file_limit", fl);
    if cfg!(windows) {
        let mut rl = Json::object();
        rl.add("enabled", yn(sc.registry_limit_enabled));
        rl.add("entries", num(sc.db_entry_registry_limit as f64));
        s.add("registry_limit", rl);
    }
    let mut diff = Json::object();
    let mut dq = Json::object();
    dq.add("enabled", yn(sc.disk_quota_enabled));
    dq.add("limit", num(sc.disk_quota_limit as f64));
    diff.add("disk_quota", dq);
    let mut fs = Json::object();
    fs.add("enabled", yn(sc.file_size_enabled));
    fs.add("limit", num(sc.file_size_limit as f64));
    diff.add("file_size", fs);
    s.add("diff", diff);
    if !sc.directories.is_empty() {
        let mut dirs = Json::array();
        const NAMES: [(i32, &str, bool); 15] = [
            (CHECK_MD5SUM, "check_md5sum", true),
            (CHECK_SHA1SUM, "check_sha1sum", true),
            (CHECK_PERM, "check_perm", true),
            (CHECK_SIZE, "check_size", true),
            (CHECK_OWNER, "check_owner", true),
            (CHECK_GROUP, "check_group", true),
            (CHECK_MTIME, "check_mtime", true),
            (CHECK_INODE, "check_inode", true),
            (REALTIME_ACTIVE, "realtime", true),
            (CHECK_SEECHANGES, "report_changes", true),
            (CHECK_SHA256SUM, "check_sha256sum", true),
            (WHODATA_ACTIVE, "check_whodata", true),
            (CHECK_ATTRS, "check_attrs", cfg!(windows)),
            (CHECK_FOLLOW, "follow_symbolic_link", true),
            (0, "", false),
        ];
        for d in &sc.directories {
            let mut pair = Json::object();
            let mut opts = Json::array();
            for (bit, name, on) in NAMES {
                if on && d.options & bit != 0 {
                    opts.push(Json::string(name));
                }
            }
            pair.add("opts", opts);
            pair.add("dir", Json::string(&d.path));
            if let Some(l) = &d.symbolic_links {
                pair.add("symbolic_link", Json::string(l));
            }
            pair.add("recursion_level", num(d.recursion_level as f64));
            if let Some(r) = &d.filerestrict {
                pair.add("restrict", Json::string(r.raw()));
            }
            if let Some(t) = &d.tag {
                pair.add("tags", Json::string(t));
            }
            if sc.file_size_enabled && d.diff_size_limit != 0 {
                pair.add("diff_size_limit", num(d.diff_size_limit as f64));
            }
            dirs.push(pair);
        }
        s.add("directories", dirs);
    }
    let strs = |l: &[String]| {
        let mut a = Json::array();
        for x in l {
            a.push(Json::string(x));
        }
        a
    };
    if let Some(l) = &sc.nodiff {
        s.add("nodiff", strs(l));
    }
    if let Some(l) = &sc.ignore {
        s.add("ignore", strs(l));
    }
    if let Some(l) = &sc.ignore_regex {
        let mut a = Json::array();
        for m in l {
            a.push(Json::string(m.raw()));
        }
        s.add("ignore_sregex", a);
    }
    if cfg!(unix) {
        let mut w = Json::object();
        w.add("restart_audit", yn(sc.restart_audit));
        if !sc.audit_key.is_empty() {
            w.add("audit_key", strs(&sc.audit_key));
        }
        w.add("startup_healthcheck", yn(sc.audit_healthcheck));
        w.add("queue_size", num(sc.queue_size as f64));
        w.add("provider", Json::string(if sc.whodata_provider == EBPF_PROVIDER { "ebpf" } else { "audit" }));
        s.add("whodata", w);
    }
    if cfg!(windows) {
        s.add("windows_audit_interval", num(sc.wdata_interval_scan as f64));
        let arch = |a: i32| Json::string(if a == 0 { "32bit" } else { "64bit" });
        // REGISTRY_EMPTY when nothing was read: an empty array
        let mut rg = Json::array();
        for r in sc.registry.iter().flatten() {
            let mut pair = Json::object();
            let mut opts = Json::array();
            for (bit, name) in [
                (CHECK_MD5SUM, "check_md5sum"),
                (CHECK_SHA1SUM, "check_sha1sum"),
                (CHECK_SHA256SUM, "check_sha256sum"),
                (CHECK_SIZE, "check_size"),
                (CHECK_OWNER, "check_owner"),
                (CHECK_GROUP, "check_group"),
                (CHECK_PERM, "check_perm"),
                (CHECK_MTIME, "check_mtime"),
                (CHECK_TYPE, "check_type"),
                (CHECK_SEECHANGES, "report_changes"),
            ] {
                if r.opts & bit != 0 {
                    opts.push(Json::string(name));
                }
            }
            pair.add("opts", opts);
            pair.add("entry", Json::string(&r.entry));
            pair.add("arch", arch(r.arch));
            if let Some(t) = &r.tag {
                pair.add("tags", Json::string(t));
            }
            if let Some(k) = &r.restrict_key {
                pair.add("restrict_key", Json::string(k.raw()));
            }
            if let Some(k) = &r.restrict_value {
                pair.add("restrict_value", Json::string(k.raw()));
            }
            if sc.file_size_enabled && r.diff_size_limit != 0 {
                pair.add("diff_size_limit", num(r.diff_size_limit as f64));
            }
            pair.add("recursion_level", num(r.recursion_level as f64));
            rg.push(pair);
        }
        s.add("registry", rg);
        let ign = |l: &[RegistryIgnore]| {
            let mut a = Json::array();
            for i in l {
                let mut p = Json::object();
                p.add("entry", Json::string(&i.entry));
                p.add("arch", arch(i.arch));
                a.push(p);
            }
            a
        };
        let ign_re = |l: &[RegistryIgnoreRegex]| {
            let mut a = Json::array();
            for i in l {
                let mut p = Json::object();
                p.add("entry", Json::string(i.regex.raw()));
                p.add("arch", arch(i.arch));
                a.push(p);
            }
            a
        };
        if let Some(l) = &sc.key_ignore {
            s.add("key_ignore", ign(l));
        }
        if let Some(l) = &sc.key_ignore_regex {
            s.add("key_ignore_sregex", ign_re(l));
        }
        if let Some(l) = &sc.value_ignore {
            s.add("value_ignore", ign(l));
        }
        if let Some(l) = &sc.value_ignore_regex {
            s.add("value_ignore_sregex", ign_re(l));
        }
        if let Some(l) = &sc.registry_nodiff {
            s.add("registry_nodiff", ign(l));
        }
        if let Some(l) = &sc.registry_nodiff_regex {
            s.add("registry_nodiff_sregex", ign_re(l));
        }
    }
    s.add("allow_remote_prefilter_cmd", yn(sc.allow_remote_prefilter_cmd));
    if let Some(p) = &sc.prefilter_cmd {
        s.add("prefilter_cmd", Json::string(p.join(" ")));
    }
    let mut sync = Json::object();
    sync.add("enabled", yn(sc.enable_synchronization));
    if cfg!(windows) {
        sync.add("registry_enabled", yn(sc.enable_registry_synchronization));
    }
    sync.add("queue_size", num(sc.sync_queue_size as f64));
    sync.add("interval", num(sc.sync_interval as f64));
    sync.add("max_eps", num(sc.sync_max_eps as f64));
    sync.add("response_timeout", num(sc.sync_response_timeout as f64));
    sync.add("max_interval", num(sc.sync_max_interval as f64));
    sync.add("thread_pool", num(sc.sync_thread_pool as f64));
    s.add("synchronization", sync);
    s.add("max_eps", num(sc.max_eps as f64));
    s.add("process_priority", num(sc.process_priority as f64));
    s.add("database", Json::string(if sc.database_store != 0 { "memory" } else { "disk" }));
    let mut root = Json::object();
    root.add("syscheck", s);
    Some(root)
}

/// `getSyscheckInternalOptions`. `debug` is `sys_debug_level`, `rootcheck_sleep` `rootcheck.tsleep`.
pub fn get_syscheck_internal_options(sc: &SyscheckConfig, debug: i32, rootcheck_sleep: i32) -> Json {
    let num = |v: f64| Json::number(v);
    let mut sd = Json::object();
    sd.add("rt_delay", num(sc.rt_delay as f64));
    sd.add("default_max_depth", num(sc.max_depth as f64));
    sd.add("symlink_scan_interval", num(sc.sym_checker_interval as f64));
    sd.add("debug", num(debug as f64));
    sd.add("file_max_size", num(sc.file_max_size as f64));
    if cfg!(windows) {
        sd.add("max_fd_win_rt", num(sc.max_fd_win_rt as f64));
    } else {
        sd.add("max_audit_entries", num(sc.max_audit_entries as f64));
    }
    let mut internals = Json::object();
    internals.add("syscheck", sd);
    let mut rc = Json::object();
    rc.add("sleep", num(rootcheck_sleep as f64));
    internals.add("rootcheck", rc);
    let mut root = Json::object();
    root.add("internal", internals);
    root
}

/// `syscheck_opts2str`
pub fn syscheck_opts2str(opts: i32) -> String {
    const BITS: [(i32, &str); 16] = [
        (CHECK_SIZE, "size"),
        (CHECK_PERM, "permissions"),
        (CHECK_OWNER, "owner"),
        (CHECK_GROUP, "group"),
        (CHECK_MTIME, "mtime"),
        (CHECK_INODE, "inode"),
        (CHECK_MD5SUM, "hash_md5"),
        (CHECK_SHA1SUM, "hash_sha1"),
        (CHECK_SHA256SUM, "hash_sha256"),
        (CHECK_ATTRS, "attributes"),
        (CHECK_SEECHANGES, "report_changes"),
        (CHECK_FOLLOW, "follow_symbolic_link"),
        (REALTIME_ACTIVE, "realtime"),
        (WHODATA_ACTIVE, "whodata"),
        (SCHEDULED_ACTIVE, "scheduled"),
        (CHECK_TYPE, "reg_value_type"),
    ];
    BITS.iter().filter(|(b, _)| opts & b != 0).map(|(_, n)| *n).collect::<Vec<_>>().join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_units() {
        assert_eq!(read_data_unit("10"), 10);
        assert_eq!(read_data_unit("2MB"), 2048);
        assert_eq!(read_data_unit("1gb"), 1024 * 1024);
        assert_eq!(read_data_unit("5B"), -1);
        assert_eq!(read_data_unit("x"), -1);
        assert_eq!(read_data_unit("3TB"), i32::MAX);
    }

    #[test]
    fn insert_sorted() {
        let mut ctx = ConfigContext::new(siem_config::Platform::AGENT);
        let mut l = Vec::new();
        for p in ["c", "a", "b", "a"] {
            let d = fim_create_directory(&mut ctx, p, 1, None, 0, None, -1, false);
            fim_insert_directory(&mut l, d);
        }
        assert_eq!(l.iter().map(|d| d.path.as_str()).collect::<Vec<_>>(), ["a", "b", "c"]);
    }

    #[test]
    fn opts2str() {
        assert_eq!(syscheck_opts2str(CHECK_SIZE | REALTIME_ACTIVE), "size | realtime");
    }
}
