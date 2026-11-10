//! The rule evaluators of `wm_sca.c`: files (`f:`), directories (`d:`),
//! commands (`c:`), processes (`p:`), the Windows registry (`r:`), and the
//! pattern language (`r:` regex, `n:` numeric compare, literal, `!`, ` && `).
//!
//! Results are the C integers: `RETURN_NOT_FOUND` 0, `RETURN_FOUND` 1,
//! `RETURN_INVALID` 2; `wm_sca_pattern_matches` can also yield other values
//! (a negated invalid minterm), which callers treat as the C code does.

use siem_log::WLog;
use siem_regex::{ExpType, Expression, OS_RETURN_SUBSTRING};

use crate::crt;

pub const RETURN_NOT_FOUND: i32 = 0;
pub const RETURN_FOUND: i32 = 1;
pub const RETURN_INVALID: i32 = 2;

/// `WM_SCA_LOGTAG`
pub const TAG: &str = "sca";

/// `PATH_MAX` of the `snprintf(f_name, PATH_MAX + 1, "%s/%s", ...)`
#[cfg(windows)]
const PATH_MAX: usize = 260;
#[cfg(unix)]
const PATH_MAX: usize = 4096;

/// Byte strings joined (the `sprintf` of a reason).
pub fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// The bytes up to the first NUL (a C string).
pub fn cs(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

fn ci_prefix(s: &[u8], p: &[u8]) -> bool {
    s.len() >= p.len() && s[..p.len()].eq_ignore_ascii_case(p)
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() {
        return Some(0);
    }
    h.windows(n.len()).position(|w| w == n)
}

/// `wm_sca_get_pattern`: `value` cut at the first " -> ", and what follows.
pub fn get_pattern(value: &[u8]) -> (&[u8], Option<&[u8]>) {
    match find(value, b" -> ") {
        Some(i) => (&value[..i], Some(&value[i + 4..])),
        None => (value, None),
    }
}

/// `w_strtok_r_str_delim(delim, &rest)` over the whole string.
pub fn strtok_str_delim<'a>(s: &'a [u8], delim: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = Some(s);
    while let Some(mut r) = rest {
        while r.starts_with(delim) {
            r = &r[delim.len()..];
        }
        if r.is_empty() {
            break;
        }
        match find(r, delim) {
            Some(i) => {
                out.push(&r[..i]);
                rest = Some(&r[i + delim.len()..]);
            }
            None => {
                out.push(r);
                rest = None;
            }
        }
    }
    out
}

/// `strtok_r(s, ",")`: the non-empty tokens.
fn strtok_comma(s: &[u8]) -> impl Iterator<Item = &[u8]> {
    s.split(|&c| c == b',').filter(|t| !t.is_empty())
}

/// `os_trimcrlf`
fn trimcrlf(mut s: &[u8]) -> &[u8] {
    while let [rest @ .., b'\n' | b'\r'] = s {
        s = rest;
    }
    s
}

/// `snprintf(buf, OS_SIZE_1024, ...)`: at most 1023 bytes.
pub fn msg1024(b: Vec<u8>) -> Vec<u8> {
    let mut b = b;
    b.truncate(1023);
    b
}

/// The state one check's rules share: `reason`, `data->alert_msg`, the
/// lazily read process list and the module options the rules read.
pub struct Engine<'a> {
    pub log: &'a std::sync::Arc<WLog>,
    pub skip_nfs: bool,
    pub commands_timeout: u32,
    pub reason: Option<Vec<u8>>,
    /// `data->alert_msg` (up to 255)
    pub alert_msg: Vec<Vec<u8>>,
    /// `p_list` (read by each process rule while it is NULL)
    pub p_list: Option<Vec<Vec<u8>>>,
}

impl<'a> Engine<'a> {
    pub fn new(log: &'a std::sync::Arc<WLog>, skip_nfs: bool, commands_timeout: u32) -> Self {
        Engine { log, skip_nfs, commands_timeout, reason: None, alert_msg: Vec::new(), p_list: None }
    }

    pub fn d1(&self, m: impl AsRef<[u8]>) {
        self.log.tagged(TAG, "DEBUG", m);
    }
    pub fn d2(&self, m: impl AsRef<[u8]>) {
        self.log.tagged(TAG, "DEBUG2", m);
    }
    pub fn warn(&self, m: impl AsRef<[u8]>) {
        self.log.tagged(TAG, "WARNING", m);
    }
    pub fn error(&self, m: impl AsRef<[u8]>) {
        self.log.tagged(TAG, "ERROR", m);
    }

    /// `if (*reason == NULL) { sprintf(*reason, ...) }`
    pub fn set_reason(&mut self, r: Vec<u8>) {
        if self.reason.is_none() {
            self.reason = Some(r);
        }
    }

    /// `append_msg_to_vm_scat`
    pub fn append_msg(&mut self, msg: Vec<u8>) {
        if !self.alert_msg.contains(&msg) && self.alert_msg.len() < 255 {
            self.alert_msg.push(msg);
        }
    }

    /// `wm_sca_pattern_matches`
    pub fn pattern_matches(&mut self, s: &[u8], pattern: &[u8], exp: ExpType) -> i32 {
        let s = cs(s);
        let mut test_result = RETURN_FOUND;
        for minterm in strtok_str_delim(cs(pattern), b" && ") {
            let (negated, minterm) = match minterm.strip_prefix(b"!") {
                Some(m) => (1, m),
                None => (0, minterm),
            };
            let minterm_result = negated ^ self.test_positive_minterm(minterm, s, exp);
            test_result = test_result.wrapping_mul(minterm_result);
            self.d2(cat(&[
                b"Testing minterm (",
                if negated == 1 { b"!" } else { b"" },
                minterm,
                b")(",
                if s.is_empty() { b"EMPTY_LINE" } else { s },
                b") -> ",
                minterm_result.to_string().as_bytes(),
            ]));
        }
        self.d2(cat(&[b"Pattern test result: (", pattern, b")(", if s.is_empty() { b"EMPTY_LINE" } else { s }, b") -> ", test_result.to_string().as_bytes()]));
        test_result
    }

    /// `wm_sca_test_positive_minterm`
    fn test_positive_minterm(&mut self, minterm: &[u8], s: &[u8], exp: ExpType) -> i32 {
        if ci_prefix(minterm, b"r:") {
            let p = String::from_utf8_lossy(&minterm[2..]);
            let Ok(e) = Expression::compile(exp, &p, OS_RETURN_SUBSTRING) else {
                self.d2(format!("Failed to compile regex '{p}'"));
                return RETURN_NOT_FOUND;
            };
            if e.match_bytes(s, None).0 {
                return RETURN_FOUND;
            }
        } else if ci_prefix(minterm, b"n:") {
            return self.regex_numeric_comparison(&minterm[2..], s, exp);
        } else if minterm.eq_ignore_ascii_case(s) {
            return RETURN_FOUND;
        }
        RETURN_NOT_FOUND
    }

    /// `wm_sca_regex_numeric_comparison`
    fn regex_numeric_comparison(&mut self, pattern: &[u8], s: &[u8], exp: ExpType) -> i32 {
        let Some(i) = find(pattern, b" compare ") else {
            let m = cat(&[b"Keyword 'compare' not found. Did you forget adding 'compare COMPARATOR VALUE' to your rule?' ", pattern, b"'"]);
            self.d2(&m);
            self.set_reason(m);
            return RETURN_INVALID;
        };
        let (regex, partial) = (&pattern[..i], &pattern[i + 9..]);
        self.d2(cat(&[b"REGEX: '", regex, b"'. Partial comparison: '", partial, b"'"]));
        let rs = String::from_utf8_lossy(regex);
        let Ok(e) = Expression::compile(exp, &rs, OS_RETURN_SUBSTRING) else {
            self.d2(format!("Cannot compile regex '{rs}'"));
            self.set_reason(cat(&[b"Cannot compile regex '", regex, b"'"]));
            return RETURN_INVALID;
        };
        let mut subs: Vec<Vec<u8>> = Vec::new();
        if !e.match_bytes(s, Some(&mut subs)).0 {
            self.d2(format!("No match found for regex '{rs}'"));
            return RETURN_NOT_FOUND;
        }
        let Some(sub) = subs.first() else {
            let m = cat(&[b"Regex '", regex, b"' matched, but no string was captured by it. Did you forget specifying a capture group?"]);
            self.d2(&m);
            self.set_reason(m);
            return RETURN_INVALID;
        };
        self.d2(cat(&[b"Captured value: '", sub, b"'"]));
        let (value, used, err) = crt::strtol(sub);
        if err != 0 || used == 0 {
            let m = cat(&[b"Conversion error. Cannot convert '", sub, b"' to integer."]);
            self.d2(&m);
            self.set_reason(m);
            return RETURN_INVALID;
        }
        self.d2(format!("Converted value: '{value}'"));
        let result = self.apply_numeric_partial_comparison(partial, value as i64, exp);
        self.d2(cat(&[b"Comparison result '", value.to_string().as_bytes(), b" ", partial, b"' -> ", result.to_string().as_bytes()]));
        result
    }

    /// `wm_sca_apply_numeric_partial_comparison`
    fn apply_numeric_partial_comparison(&mut self, partial: &[u8], number: i64, exp: ExpType) -> i32 {
        self.d2(cat(&[b"Partial comparison '", partial, b"'"]));
        let Ok(e) = Expression::compile(exp, "(\\d+)", OS_RETURN_SUBSTRING) else {
            self.set_reason(b"Cannot compile regex.".to_vec());
            self.warn("Cannot compile regex");
            return RETURN_INVALID;
        };
        let mut subs: Vec<Vec<u8>> = Vec::new();
        if !e.match_bytes(partial, Some(&mut subs)).0 {
            let m = cat(&[b"No integer was found within the comparison '", partial, b"' "]);
            self.set_reason(m.clone());
            self.warn(m);
            return RETURN_INVALID;
        }
        let Some(sub) = subs.first() else {
            self.set_reason(b"No number was captured.".to_vec());
            self.warn("No number was captured.");
            return RETURN_INVALID;
        };
        self.d2(cat(&[b"Value given for comparison: '", sub, b"'"]));
        let (given, used, err) = crt::strtol(sub);
        if err != 0 || used == 0 {
            let m = cat(&[b"Conversion error. Cannot convert '", sub, b"' to integer."]);
            self.set_reason(m.clone());
            self.warn(m);
            return RETURN_INVALID;
        }
        let given = given as i64;
        self.d2(format!("Value converted: '{given}'"));
        let r = |b: bool| if b { RETURN_FOUND } else { RETURN_NOT_FOUND };
        if partial.first() == Some(&b'=') {
            self.d2(format!("Operation is '{number} == {given}'"));
            return r(number == given);
        } else if find(partial, b"!=").is_some() {
            self.d2(format!("Operation is '{number} != {given}'"));
            return r(number != given);
        } else if find(partial, b"<=").is_some() {
            self.d2(format!("Operation is '{number} <= {given}'"));
            return r(number <= given);
        } else if find(partial, b">=").is_some() {
            self.d2(format!("Operation is '{number} >= {given}'"));
            return r(number >= given);
        } else if find(partial, b"<").is_some() {
            self.d2(format!("Operation is '{number} < {given}'"));
            return r(number < given);
        } else if find(partial, b">").is_some() {
            self.d2(format!("Operation is '{number} > {given}'"));
            return r(number > given);
        }
        let m = cat(&[b"Unrecognized operation: '", partial, b"'"]);
        self.d2(&m);
        self.set_reason(m);
        RETURN_INVALID
    }

    /// `lstat` (`w_stat` on Windows): the mode or the errno.
    fn stat(&self, path: &[u8]) -> Result<u32, i32> {
        #[cfg(windows)]
        if let Some(e) = self.network_path(path) {
            return Err(e);
        }
        #[cfg(unix)]
        {
            let c = crt::cstring(path);
            // SAFETY: an out-buffer of struct stat.
            unsafe {
                let mut st: libc::stat = std::mem::zeroed();
                return if libc::lstat(c.as_ptr(), &mut st) == 0 { Ok(st.st_mode as u32) } else { Err(crt::errno()) };
            }
        }
        #[cfg(windows)]
        crt::stat_mode(path)
    }

    /// `is_network_path` refusal of the Windows wrappers: EACCES.
    #[cfg(windows)]
    fn network_path(&self, path: &[u8]) -> Option<i32> {
        let p = String::from_utf8_lossy(path);
        if siem_fileop::crt::is_network_path(&p) {
            self.log.warn(siem_fileop::crt::network_path_executed(&p));
            return Some(13);
        }
        None
    }

    /// `wm_sca_resolve_symlink` (Unix): the real path, or the result.
    #[cfg(unix)]
    fn resolve_symlink(&mut self, file: &[u8]) -> Result<Vec<u8>, i32> {
        self.d2(cat(&[b"Resolving real path of '", file, b"'"]));
        match std::fs::canonicalize(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(file)) {
            Ok(p) => {
                let p = p.into_os_string().into_encoded_bytes();
                self.d2(cat(&[b"Real path of '", file, b"' is '", &p, b"'"]));
                Ok(p)
            }
            Err(e) => {
                let n = e.raw_os_error().unwrap_or(0);
                if n == libc::ENOENT {
                    self.d2(cat(&[b"Path '", file, b"' does not exists, or points to an unexistent path -> RETURN_NOT_FOUND: ", crt::strerror(n).as_bytes()]));
                    return Err(RETURN_NOT_FOUND);
                }
                let m = cat(&[b"Could not resolve the real path of '", file, b"': ", crt::strerror(n).as_bytes()]);
                self.d2(&m);
                self.set_reason(m);
                Err(RETURN_INVALID)
            }
        }
    }

    /// `wm_sca_check_file_existence`
    fn check_file_existence(&mut self, file: &[u8]) -> i32 {
        #[cfg(unix)]
        let real = match self.resolve_symlink(file) {
            Ok(p) => p,
            Err(r) => return r,
        };
        #[cfg(windows)]
        let real = file.to_vec();
        match self.stat(&real) {
            Err(e) => {
                let es = crt::strerror(e);
                if e == libc::ENOENT {
                    self.d2(cat(&[b"FILE_EXISTS(", file, b") -> RETURN_NOT_FOUND: ", es.as_bytes()]));
                    return RETURN_NOT_FOUND;
                }
                self.set_reason(cat(&[b"Could not open '", file, b"': ", es.as_bytes()]));
                self.d2(cat(&[b"FILE_EXISTS(", file, b") -> RETURN_INVALID: ", es.as_bytes()]));
                RETURN_INVALID
            }
            Ok(m) if m & crt::S_IFMT == crt::S_IFREG => {
                self.d2(cat(&[b"FILE_EXISTS(", file, b") -> RETURN_FOUND"]));
                RETURN_FOUND
            }
            Ok(_) => {
                self.set_reason(cat(&[b"FILE_EXISTS(", file, b") -> RETURN_INVALID: Not a regular file."]));
                self.d2(cat(&[b"FILE_EXISTS(", file, b") -> RETURN_INVALID: Not a regular file."]));
                RETURN_INVALID
            }
        }
    }

    /// `wfopen(file, "r")` + every `fgets(buf, OS_SIZE_2048, fp)` chunk.
    fn read_lines(&self, file: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
        #[cfg(windows)]
        if let Some(e) = self.network_path(file) {
            return Err(e);
        }
        let path = String::from_utf8_lossy(file).into_owned();
        // Windows: errno = GetLastError() of CreateFile
        let raw = std::fs::read(&path).map_err(|e| e.raw_os_error().unwrap_or(0))?;
        let data = if siem_fileop::crt::TEXT_TRANSLATION { siem_fileop::crt::text_in(&raw) } else { raw };
        let mut out = Vec::new();
        let mut rest = data.as_slice();
        while !rest.is_empty() {
            let mut n = rest.iter().position(|&c| c == b'\n').map(|i| i + 1).unwrap_or(rest.len());
            n = n.min(2047);
            out.push(cs(&rest[..n]).to_vec());
            rest = &rest[n..];
        }
        Ok(out)
    }

    /// `wm_sca_check_file_contents`
    fn check_file_contents(&mut self, file: &[u8], pattern: &[u8], exp: ExpType) -> i32 {
        self.d2(cat(&[b"Checking contents of file '", file, b"' against pattern '", pattern, b"'"]));
        #[cfg(unix)]
        let real = match self.resolve_symlink(file) {
            Ok(p) => p,
            Err(_) => {
                self.set_reason(cat(&[b"Could not open file '", file, b"'"]));
                self.d2(cat(&[b"Could not open file '", file, b"'"]));
                return RETURN_INVALID;
            }
        };
        #[cfg(windows)]
        let real = file.to_vec();
        let lines = match self.read_lines(&real) {
            Ok(l) => l,
            Err(e) => {
                let m = cat(&[b"Could not open file '", file, b"': ", crt::strerror(e).as_bytes()]);
                self.set_reason(m.clone());
                self.d2(m);
                return RETURN_INVALID;
            }
        };
        let mut result = RETURN_NOT_FOUND;
        for buf in &lines {
            let line = trimcrlf(buf);
            result = self.pattern_matches(line, pattern, exp);
            self.d2(cat(&[b"(", pattern, b")(", if line.is_empty() { b"EMPTY_LINE" } else { line }, b") -> ", result.to_string().as_bytes()]));
            if result != 0 {
                self.d2("Match found. Skipping the rest.");
                break;
            }
        }
        self.d2(cat(&[b"Result for (", pattern, b")(", file, b") -> ", result.to_string().as_bytes()]));
        result
    }

    /// `wm_sca_check_file_list`
    pub fn check_file_list(&mut self, file_list: &[u8], pattern: Option<&[u8]>, exp: ExpType) -> i32 {
        match pattern {
            Some(p) => self.check_file_list_for_contents(file_list, p, exp),
            None => self.check_file_list_for_existence(file_list),
        }
    }

    /// `wm_sca_check_file_list_for_existence`
    fn check_file_list_for_existence(&mut self, file_list: &[u8]) -> i32 {
        self.d1(cat(&[b"Checking file list '", file_list, b"' for existence."]));
        let mut acc = RETURN_NOT_FOUND;
        for file in strtok_comma(file_list) {
            let r = self.check_file_existence(file);
            if r == RETURN_FOUND {
                acc = RETURN_FOUND;
                self.d2(cat(&[b"File '", file, b"' found. Skipping the rest."]));
                break;
            }
            if r == RETURN_INVALID {
                acc = RETURN_INVALID;
                self.d2(cat(&[b"Could not open file '", file, b"'. Continuing."]));
            } else {
                self.d2(cat(&[b"File '", file, b"' does not exists. Continuing."]));
            }
        }
        self.d1(cat(&[b"Result for FILES_EXIST(", file_list, b") -> ", acc.to_string().as_bytes()]));
        acc
    }

    /// `wm_sca_check_file_list_for_contents`
    fn check_file_list_for_contents(&mut self, file_list: &[u8], pattern: &[u8], exp: ExpType) -> i32 {
        self.d1(cat(&[b"Checking file list '", file_list, b"' with '", pattern, b"'"]));
        let mut acc = RETURN_NOT_FOUND;
        for file in strtok_comma(file_list) {
            if self.check_file_existence(file) != RETURN_FOUND {
                acc = RETURN_INVALID;
                self.set_reason(cat(&[b"Could not open file '", file, b"'"]));
                self.d2(cat(&[b"Could not open file '", file, b"'. Skipping."]));
                continue;
            }
            let r = self.check_file_contents(file, pattern, exp);
            if r == RETURN_FOUND {
                acc = RETURN_FOUND;
                self.d2(cat(&[b"Match found in '", file, b"'. Skipping the rest."]));
                break;
            }
            if r == RETURN_INVALID {
                self.d2(cat(&[b"Check was invalid in file '", file, b"'. Continuing."]));
                acc = RETURN_INVALID;
            } else {
                self.d2(cat(&[b"Match not found in file '", file, b"'. Continuing."]));
            }
        }
        self.d1(cat(&[b"Result for (", pattern, b")(", file_list, b") -> ", acc.to_string().as_bytes()]));
        acc
    }

    /// `wm_sca_read_command`
    pub fn read_command(&mut self, command: &[u8], pattern: Option<&[u8]>, exp: ExpType) -> i32 {
        let Some(pattern) = pattern else {
            self.d1("No pattern given. Returning FOUND.");
            return RETURN_FOUND;
        };
        self.d1(cat(&[b"Executing command '", command, b"', and testing output with pattern '", pattern, b"'"]));
        let cmd = String::from_utf8_lossy(command).into_owned();
        let r = siem_execd::wm_exec::wm_exec(self.log, &cmd, self.commands_timeout);
        // shortcut: result_code is uninitialized in the C when wm_exec fails before setting it; 0 here
        let result_code = r.status.unwrap_or(0);
        match r.retval {
            0 => self.d1(format!("Command '{cmd}' returned code {result_code}")),
            siem_execd::wm_exec::WM_ERROR_TIMEOUT => {
                self.d1(format!("Timeout overtaken running command '{cmd}'"));
                self.set_reason(cat(&[b"Timeout overtaken running command '", command, b"'"]));
                return RETURN_INVALID;
            }
            _ => {
                if result_code == siem_execd::wm_exec::EXECVE_ERROR {
                    self.d1(format!("Invalid path or wrong permissions to run command '{cmd}'"));
                    self.set_reason(cat(&[b"Invalid path or wrong permissions to run command '", command, b"'"]));
                } else {
                    self.d1(format!("Failed to run command '{cmd}'. Returned code {result_code}"));
                    self.set_reason(cat(&[b"Failed to run command '", command, b"'. Returned code ", result_code.to_string().as_bytes()]));
                }
                return RETURN_INVALID;
            }
        }
        let Some(output) = r.output else {
            self.d2("Command yielded no output. Returning.");
            return RETURN_NOT_FOUND;
        };
        let lines = siem_regex::strings::str_break_bytes(b'\n', &output, 256).unwrap_or_default();
        let mut result = RETURN_NOT_FOUND;
        for l in &lines {
            result = self.pattern_matches(trimcrlf(l), pattern, exp);
            if result == RETURN_FOUND {
                break;
            }
        }
        self.d2(cat(&[b"Result for (", pattern, b")(", command, b") -> ", result.to_string().as_bytes()]));
        result
    }

    /// `IsNFS`
    fn is_nfs(&self, dir: &[u8]) -> i32 {
        #[cfg(target_os = "linux")]
        {
            // NFS (0x6969) and CIFS (0xFF534D42) mounts
            let c = crt::cstring(dir);
            // SAFETY: an out-buffer of struct statfs.
            unsafe {
                let mut st: libc::statfs = std::mem::zeroed();
                if libc::statfs(c.as_ptr(), &mut st) == 0 {
                    return matches!(st.f_type as i64, 0x6969 | 0xFF534D42) as i32;
                }
            }
            let e = crt::errno();
            if e != libc::ENOENT {
                self.log.error(cat(&[b"statfs('", dir, b"') produced error: ", crt::strerror(e).as_bytes()]));
            }
            -1
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.log.debug2(cat(&[b"Attempted to check NFS status for '", dir, b"', but we don't know how on this OS."]));
            0
        }
    }

    /// `wm_sca_check_dir_list`
    pub fn check_dir_list(&mut self, dir_list: &[u8], file: Option<&[u8]>, pattern: Option<&[u8]>, exp: ExpType) -> i32 {
        let mut found = RETURN_NOT_FOUND;
        self.d2(cat(&[b"Exploring directories [", dir_list, b"]"]));
        for dir in strtok_str_delim(dir_list, b",") {
            let is_nfs = self.is_nfs(dir);
            self.d2(cat(&[b"Checking directory '", dir, b"' => is_nfs=", is_nfs.to_string().as_bytes(), b", skip_nfs=", (self.skip_nfs as i32).to_string().as_bytes()]));
            if self.skip_nfs && is_nfs == 1 {
                self.d2(cat(&[b"Directory '", dir, b"' flagged as NFS and skip_nfs is enabled."]));
                self.set_reason(cat(&[b"Directory '", dir, b"' flagged as NFS and skip_nfs is enabled"]));
                found = RETURN_INVALID;
            } else {
                let r = match file {
                    None => self.check_dir_existence(dir),
                    Some(f) => self.check_dir(dir, f, pattern, exp),
                };
                if r == RETURN_FOUND {
                    found = RETURN_FOUND;
                    self.d2(cat(&[b"Found match in directory '", dir, b"'"]));
                } else if r == RETURN_INVALID {
                    found = RETURN_INVALID;
                    self.d2(cat(&[b"Check returned not applicable for directory '", dir, b"'"]));
                }
            }
            self.append_msg(msg1024(cat(&[b" Directory: ", dir])));
            if found == RETURN_FOUND {
                break;
            }
        }
        found
    }

    /// `wopendir`: the entry names or the errno.
    fn opendir(&self, dir: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
        #[cfg(windows)]
        if let Some(e) = self.network_path(dir) {
            return Err(e);
        }
        crt::read_dir(dir)
    }

    /// `wm_sca_check_dir_existence`
    fn check_dir_existence(&mut self, dir: &[u8]) -> i32 {
        #[cfg(unix)]
        let real = match self.resolve_symlink(dir) {
            Ok(p) => p,
            Err(r) => return r,
        };
        #[cfg(windows)]
        let real = dir.to_vec();
        match self.opendir(&real) {
            Ok(_) => {
                self.d2(cat(&[b"DIR_EXISTS(", dir, b") -> RETURN_FOUND"]));
                RETURN_FOUND
            }
            Err(e) if e == libc::ENOENT => {
                self.d2(cat(&[b"DIR_EXISTS(", dir, b") -> RETURN_NOT_FOUND. Reason: ", crt::strerror(e).as_bytes()]));
                RETURN_NOT_FOUND
            }
            Err(e) => {
                let m = cat(&[b"Could not check directory existence for '", dir, b"': ", crt::strerror(e).as_bytes()]);
                self.set_reason(m.clone());
                self.d2(m);
                RETURN_INVALID
            }
        }
    }

    /// `wm_sca_check_dir`
    fn check_dir(&mut self, dir: &[u8], file: &[u8], pattern: Option<&[u8]>, exp: ExpType) -> i32 {
        self.d2(cat(&[b"Checking directory '", dir, b"' -> ", file, if pattern.is_some() { b" -> " } else { b"" }, pattern.unwrap_or(b"")]));
        #[cfg(unix)]
        let real = match self.resolve_symlink(dir) {
            Ok(p) => p,
            Err(_) => {
                self.set_reason(cat(&[b"Could not open dir '", dir, b"'"]));
                self.d2(cat(&[b"Could not open dir '", dir, b"'"]));
                return RETURN_INVALID;
            }
        };
        #[cfg(windows)]
        let real = dir.to_vec();
        let names = match self.opendir(&real) {
            Ok(n) => n,
            Err(e) => {
                let m = cat(&[b"Could not open '", dir, b"': ", crt::strerror(e).as_bytes()]);
                self.set_reason(m.clone());
                self.d2(m);
                return RETURN_INVALID;
            }
        };
        let mut acc = RETURN_NOT_FOUND;
        let file_s = String::from_utf8_lossy(file).into_owned();
        for name in names {
            if name == b"." || name == b".." {
                continue;
            }
            let mut f_name = cat(&[dir, b"/", &name]);
            f_name.truncate(PATH_MAX);
            self.d2(cat(&[b"Considering directory entry '", &f_name, b"'"]));
            let Ok(mode) = self.stat(&f_name) else {
                self.d2(cat(&[b"Cannot check directory entry '", &f_name, b"'"]));
                self.set_reason(cat(&[b"Cannot check directory entry '", &f_name]));
                acc = RETURN_INVALID;
                continue;
            };
            let name_s = String::from_utf8_lossy(&name);
            let r = if mode & crt::S_IFMT == crt::S_IFDIR {
                self.check_dir(&f_name, file, pattern, exp)
            } else if (ci_prefix(file, b"r:") && siem_regex::os_regex(&file_s[2..], &name_s)) || siem_regex::os_match2(&file_s, &name_s) {
                self.check_file_list(&f_name, pattern, exp)
            } else {
                self.d2(cat(&[b"Skipping directory entry '", &f_name, b"'"]));
                continue;
            };
            self.d2(cat(&[b"Result for entry '", &f_name, b"': ", r.to_string().as_bytes()]));
            if r == RETURN_FOUND {
                self.d2(cat(&[b"Match found in '", &f_name, b"', skipping the rest."]));
                acc = RETURN_FOUND;
                break;
            } else if r == RETURN_INVALID {
                acc = RETURN_INVALID;
            }
        }
        self.d2(cat(&[b"Check result for dir '", dir, b"': ", acc.to_string().as_bytes()]));
        acc
    }

    /// `wm_sca_check_process_is_running` (the list is read on first use)
    /// `if (!p_list) p_list = w_os_get_process_list();` (lazy, per process rule)
    pub fn load_process_list(&mut self) {
        if self.p_list.is_none() {
            self.p_list = crate::proc::process_list(self.log);
        }
    }

    pub fn check_process_is_running(&mut self, value: &[u8], exp: ExpType) -> i32 {
        let Some(list) = self.p_list.clone() else {
            self.set_reason(b"Process list is empty.".to_vec());
            return RETURN_INVALID;
        };
        for p in &list {
            if self.pattern_matches(p, value, exp) != 0 {
                return RETURN_FOUND;
            }
        }
        RETURN_NOT_FOUND
    }
}
