//! `get_unix_version` / `OSX_ReleaseName` (`shared/version_op.c`) and
//! `getuname` (`shared/file_op.c`): the OS description agents put in their
//! keep-alive messages ("Linux |host |5.15 |#1 SMP ... |x86_64 [Ubuntu|ubuntu:
//! 22.04.3 LTS (Jammy Jellyfish)] - Wazuh v4.14.7").
//!
//! The release files are read with `fgets` into a 256-byte buffer (so long
//! lines come in 254-byte pieces) and tokenized with `strtok_r`; the
//! patterns are POSIX extended regular expressions run by the C library,
//! like the C code. File reads, commands and `uname` go through [`Probe`],
//! so tests can feed any system.

#[cfg(unix)]
use std::ffi::CString;

/// `__ossec_name`
pub const OSSEC_NAME: &str = "Wazuh";
/// `__ossec_version`
pub const OSSEC_VERSION: &str = "v4.14.7";

/// `os_info`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsInfo {
    pub os_name: Option<String>,
    pub os_major: Option<String>,
    pub os_minor: Option<String>,
    pub os_patch: Option<String>,
    pub os_build: Option<String>,
    pub os_version: Option<String>,
    pub os_codename: Option<String>,
    pub os_platform: Option<String>,
    pub sysname: Option<String>,
    pub nodename: Option<String>,
    pub release: Option<String>,
    pub version: Option<String>,
    pub machine: Option<String>,
}

/// `struct utsname`
#[derive(Debug, Clone, Default)]
pub struct UtsName {
    pub sysname: String,
    pub nodename: String,
    pub release: String,
    pub version: String,
    pub machine: String,
}

/// What `get_unix_version` asks the system.
pub trait Probe {
    /// `wfopen(path, "r")` + read: the whole file.
    fn read_file(&self, path: &str) -> Option<Vec<u8>>;
    /// `popen(cmd, "r")` + read: the command's output.
    fn popen(&self, cmd: &str) -> Option<Vec<u8>>;
    /// `uname(&uts_buf)`
    fn uname(&self) -> Option<UtsName>;
    /// `getenv("PATH")`
    fn path_env(&self) -> Option<String>;
    /// `IsFile(path) == 0`
    fn is_file(&self, path: &str) -> bool;
}

/// The running system.
pub struct System;

impl Probe for System {
    fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        std::fs::read(path).ok()
    }

    fn popen(&self, cmd: &str) -> Option<Vec<u8>> {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(cmd)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .output()
            .ok()
            .map(|o| o.stdout)
    }

    #[cfg(unix)]
    fn uname(&self) -> Option<UtsName> {
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut u) } < 0 {
            return None;
        }
        let f = |a: &[libc::c_char]| -> String {
            let b: Vec<u8> = a.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
            String::from_utf8_lossy(&b).into_owned()
        };
        Some(UtsName {
            sysname: f(&u.sysname),
            nodename: f(&u.nodename),
            release: f(&u.release),
            version: f(&u.version),
            machine: f(&u.machine),
        })
    }

    #[cfg(not(unix))]
    fn uname(&self) -> Option<UtsName> {
        None
    }

    fn path_env(&self) -> Option<String> {
        std::env::var("PATH").ok()
    }

    fn is_file(&self, path: &str) -> bool {
        std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
    }
}

/// `fgets(buff, sizeof(buff) - 1, fp)` with a 256-byte buffer: pieces of
/// at most 254 bytes, each ending at a newline when one comes first.
struct Fgets<'a> {
    data: &'a [u8],
    pos: usize,
    max: usize,
}

impl<'a> Fgets<'a> {
    fn new(data: &'a [u8], size: usize) -> Self {
        Fgets { data, pos: 0, max: size - 1 }
    }
}

impl<'a> Iterator for Fgets<'a> {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Vec<u8>> {
        if self.pos >= self.data.len() {
            return None;
        }
        let start = self.pos;
        let mut end = start;
        while end < self.data.len() && end - start < self.max {
            end += 1;
            if self.data[end - 1] == b'\n' {
                break;
            }
        }
        self.pos = end;
        // a NUL byte ends the C string
        let mut v = self.data[start..end].to_vec();
        if let Some(z) = v.iter().position(|&c| c == 0) {
            v.truncate(z);
        }
        Some(v)
    }
}

/// `strtok_r` over a byte buffer.
struct Strtok {
    buf: Vec<u8>,
    pos: usize,
}

impl Strtok {
    fn new(buf: Vec<u8>) -> Self {
        Strtok { buf, pos: 0 }
    }

    fn next(&mut self, delims: &[u8]) -> Option<Vec<u8>> {
        while self.pos < self.buf.len() && delims.contains(&self.buf[self.pos]) {
            self.pos += 1;
        }
        if self.pos >= self.buf.len() {
            return None;
        }
        let start = self.pos;
        while self.pos < self.buf.len() && !delims.contains(&self.buf[self.pos]) {
            self.pos += 1;
        }
        let tok = self.buf[start..self.pos].to_vec();
        if self.pos < self.buf.len() {
            self.pos += 1;
        }
        Some(tok)
    }
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// `if (v[0] == '"' && (end = strchr(++v, '"'), end)) *end = '\0';`
fn unquote(v: &[u8]) -> Vec<u8> {
    if v.first() == Some(&b'"') {
        let rest = &v[1..];
        match rest.iter().position(|&c| c == b'"') {
            Some(p) => rest[..p].to_vec(),
            None => rest.to_vec(),
        }
    } else {
        v.to_vec()
    }
}

/// `regcomp(REG_EXTENDED)` + `regexec`: the (start, end) of the first
/// `nmatch` groups (-1 when unset), or None without a match.
#[cfg(unix)]
pub fn w_regexec(pattern: &str, string: &[u8], nmatch: usize) -> Option<Vec<(i64, i64)>> {
    let p = CString::new(pattern).ok()?;
    let end = string.iter().position(|&c| c == 0).unwrap_or(string.len());
    let st = CString::new(&string[..end]).ok()?;
    unsafe {
        let mut re: libc::regex_t = std::mem::zeroed();
        if libc::regcomp(&mut re, p.as_ptr(), libc::REG_EXTENDED) != 0 {
            return None;
        }
        let mut m: Vec<libc::regmatch_t> = vec![std::mem::zeroed(); nmatch.max(1)];
        let r = libc::regexec(&re, st.as_ptr(), nmatch, m.as_mut_ptr(), 0);
        libc::regfree(&mut re);
        if r != 0 {
            return None;
        }
        Some(m.iter().take(nmatch).map(|x| (x.rm_so as i64, x.rm_eo as i64)).collect())
    }
}

#[cfg(not(unix))]
pub fn w_regexec(_pattern: &str, _string: &[u8], _nmatch: usize) -> Option<Vec<(i64, i64)>> {
    None
}

/// `snprintf(out, n + 1, "%.*s", n, buff + rm_so)` of a group.
fn group(buff: &[u8], m: &[(i64, i64)], i: usize) -> String {
    let (so, eo) = m[i];
    let n = (eo - so).max(0) as usize;
    let so = so.max(0) as usize;
    s(&buff[so.min(buff.len())..(so + n).min(buff.len())])
}

/// `get_binary_path(binary, &validated)`: the full path when found in
/// PATH, the name itself otherwise.
pub fn get_binary_path(p: &dyn Probe, binary: &str) -> (bool, String) {
    if binary.starts_with('/') {
        return (p.is_file(binary), binary.to_string());
    }
    let Some(env) = p.path_env() else {
        return (false, binary.to_string());
    };
    for dir in env.split(':').filter(|d| !d.is_empty()) {
        let full = format!("{dir}/{binary}");
        if p.is_file(&full) {
            return (true, full);
        }
    }
    (false, binary.to_string())
}

/// `OSX_ReleaseName(version)`
pub fn osx_release_name(version: i32) -> &'static str {
    const R_NAMES: [&str; 15] = [
        "Snow Leopard",
        "Lion",
        "Mountain Lion",
        "Mavericks",
        "Yosemite",
        "El Capitan",
        "Sierra",
        "High Sierra",
        "Mojave",
        "Catalina",
        "Big Sur",
        "Monterey",
        "Ventura",
        "Sonoma",
        "Sequoia",
    ];
    let v = version - 10;
    if v >= 0 && (v as usize) < R_NAMES.len() {
        R_NAMES[v as usize]
    } else {
        "Unknown"
    }
}

/// The first line of a file matching a pattern: group `g` of it.
fn first_match(data: &[u8], pattern: &str, nmatch: usize, g: usize) -> Option<String> {
    for line in Fgets::new(data, 255) {
        if let Some(m) = w_regexec(pattern, &line, nmatch) {
            return Some(group(&line, &m, g));
        }
    }
    None
}

/// `atoi`
fn atoi(s: &str) -> i32 {
    let t = s.trim_start();
    let (neg, d) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let n: i64 = d.bytes().take_while(|c| c.is_ascii_digit()).fold(0i64, |a, c| a.wrapping_mul(10).wrapping_add((c - b'0') as i64));
    (if neg { -n } else { n }) as i32
}

/// `get_unix_version()`
pub fn get_unix_version(p: &dyn Probe) -> Option<OsInfo> {
    let mut info = OsInfo::default();
    let os_release = p.read_file("/etc/os-release").or_else(|| p.read_file("/usr/lib/os-release"));
    if let Some(data) = os_release {
        let (mut name, mut id, mut version, mut version_id) = (false, false, false, false);
        for line in Fgets::new(&data, 255) {
            let mut t = Strtok::new(line);
            let Some(tag) = t.next(b"=") else { continue };
            match tag.as_slice() {
                b"NAME" if !name => {
                    let v = t.next(b"\n").expect("get_unix_version(): NAME without value (NULL dereference in the C)");
                    name = true;
                    info.os_name = Some(s(&unquote(&v)));
                }
                b"VERSION" if !version => {
                    if version_id {
                        info.os_version = None;
                    }
                    let v = t.next(b"\n").expect("get_unix_version(): VERSION without value (NULL dereference in the C)");
                    version = true;
                    info.os_version = Some(s(&unquote(&v)));
                }
                b"VERSION_ID" if !version && !version_id => {
                    let v = t.next(b"\n").expect("get_unix_version(): VERSION_ID without value (NULL dereference in the C)");
                    version_id = true;
                    info.os_version = Some(s(&unquote(&v)));
                }
                b"ID" if !id => {
                    let v = t.next(b" \n").expect("get_unix_version(): ID without value (NULL dereference in the C)");
                    id = true;
                    info.os_platform = Some(s(&unquote(&v)));
                }
                _ => {}
            }
        }
        if let Some(plat) = info.os_platform.clone() {
            if plat == "centos" {
                if let Some(rel) = p.read_file("/etc/centos-release") {
                    info.os_version = first_match(&rel, "([0-9][0-9]*\\.?[0-9]*)\\.*", 2, 1);
                }
            } else if plat == "opensuse-tumbleweed" || plat == "arch" {
                info.os_version = Some(String::new());
            }
        }
    }

    if info.os_name.is_none() || (info.os_version.is_none() && info.os_build.is_none()) || info.os_platform.is_none() {
        info.os_name = None;
        info.os_version = None;
        info.os_platform = None;
        info.os_build = None;
        let set = |info: &mut OsInfo, name: &str, plat: &str| {
            info.os_name = Some(name.into());
            info.os_platform = Some(plat.into());
        };
        if let Some(rel) = p.read_file("/etc/centos-release") {
            set(&mut info, "CentOS Linux", "centos");
            info.os_version = first_match(&rel, "([0-9][0-9]*\\.?[0-9]*)\\.*", 2, 1);
        } else if let Some(rel) = p.read_file("/etc/fedora-release") {
            set(&mut info, "Fedora", "fedora");
            info.os_version = first_match(&rel, " ([0-9][0-9]*) ", 2, 1);
        } else if let Some(rel) = p.read_file("/etc/redhat-release") {
            for line in Fgets::new(&rel, 255) {
                let has = |n: &[u8]| line.windows(n.len()).any(|w| w == n);
                if has(b"CentOS") {
                    set(&mut info, "CentOS Linux", "centos");
                } else if has(b"Fedora") {
                    set(&mut info, "Fedora", "fedora");
                } else {
                    info.os_name =
                        Some(if has(b"Server") { "Red Hat Enterprise Linux Server" } else { "Red Hat Enterprise Linux" }.into());
                    info.os_platform = Some("rhel".into());
                }
                if let Some(m) = w_regexec("([0-9][0-9]*\\.?[0-9]*)\\.*", &line, 2) {
                    info.os_version = Some(group(&line, &m, 1));
                    break;
                }
            }
        } else if let Some(rel) = p.read_file("/etc/arch-release") {
            set(&mut info, "Arch Linux", "arch");
            info.os_version = first_match(&rel, "([0-9][0-9]*\\.?[0-9]*)\\.*", 2, 1);
            if info.os_version.is_none() {
                info.os_version = Some(String::new());
            }
        } else if let Some(rel) = p.read_file("/etc/gentoo-release") {
            set(&mut info, "Gentoo", "gentoo");
            info.os_version = first_match(&rel, " ([0-9][0-9]*\\.?[0-9]*)\\.*", 2, 1);
        } else if let Some(rel) = p.read_file("/etc/SuSE-release") {
            set(&mut info, "SuSE Linux", "suse");
            info.os_version = first_match(&rel, ".*VERSION = ([0-9][0-9]*)", 2, 1);
        } else if let Some(rel) = p.read_file("/etc/lsb-release") {
            set(&mut info, "Ubuntu", "ubuntu");
            for line in Fgets::new(&rel, 255) {
                let mut t = Strtok::new(line);
                if t.next(b"=").as_deref() == Some(b"DISTRIB_RELEASE") {
                    let v = t.next(b"\n").expect("get_unix_version(): DISTRIB_RELEASE without value (NULL strdup in the C)");
                    info.os_version = Some(s(&v));
                    break;
                }
            }
        } else if let Some(rel) = p.read_file("/etc/debian_version") {
            set(&mut info, "Debian GNU/Linux", "debian");
            info.os_version = first_match(&rel, "([0-9][0-9]*\\.?[0-9]*)\\.*", 2, 1);
        } else if let Some(rel) = p.read_file("/etc/slackware-version") {
            set(&mut info, "Slackware", "slackware");
            info.os_version = first_match(&rel, " ([0-9][0-9]*\\.?[0-9]*)\\.*", 2, 1);
        } else if let Some(rel) = p.read_file("/etc/alpine-release") {
            set(&mut info, "Alpine Linux", "alpine");
            info.os_version = first_match(&rel, "([0-9]+\\.)?([0-9]+\\.)?([0-9]+)", 4, 0);
        } else if !uname_command(p, &mut info) {
            return None;
        }
    }

    let u = p.uname()?;
    info.sysname = Some(u.sysname);
    info.nodename = Some(u.nodename);
    info.release = Some(u.release);
    info.version = Some(u.version);
    info.machine = Some(u.machine);

    match info.os_version.clone() {
        Some(ver) => {
            if !ver.is_empty() {
                // os_major.os_minor (os_codename)
                if let Some(pos) = ver.find(" (") {
                    let mut cn = ver[pos + 2..].to_string();
                    // *(codename + strlen(codename) - 1) = '\0'
                    cn.pop();
                    info.os_codename = Some(cn);
                }
                let vb = ver.as_bytes();
                if let Some(m) = w_regexec("^([0-9]+)\\.*", vb, 2) {
                    info.os_major = Some(group(vb, &m, 1));
                }
                if let Some(m) = w_regexec("^[0-9]+\\.([0-9]+)\\.*", vb, 2) {
                    info.os_minor = Some(group(vb, &m, 1));
                }
                if let Some(m) = w_regexec("^[0-9]+\\.[0-9]+\\.([0-9]+)*", vb, 2) {
                    info.os_patch = Some(group(vb, &m, 1));
                }
                if info.os_platform.as_deref() == Some("darwin") {
                    if let Some(cn) = &info.os_codename {
                        info.os_version = Some(format!("{ver} ({cn})"));
                    }
                }
            }
        }
        None => info.os_version = Some("0.0".into()),
    }
    Some(info)
}

/// The `uname` command branch: false for `goto free_os_info`.
fn uname_command(p: &dyn Probe, info: &mut OsInfo) -> bool {
    let (_, uname_path) = get_binary_path(p, "uname");
    let Some(out) = p.popen(&uname_path) else { return true };
    let Some(line) = Fgets::new(&out, 255).next() else { return true };
    let first = {
        let mut t = Strtok::new(line);
        t.next(b"\n").unwrap_or_default()
    };
    let run_first = |cmd: &str| -> Option<Vec<u8>> { p.popen(cmd).and_then(|o| Fgets::new(&o, 255).next()) };
    match first.as_slice() {
        b"Darwin" => {
            info.os_platform = Some("darwin".into());
            let (_, sp) = get_binary_path(p, "system_profiler");
            if let Some(o) = p.popen(&format!("{sp} SPSoftwareDataType")) {
                for line in Fgets::new(&o, 256) {
                    let mut t = Strtok::new(line);
                    if let Some(key) = t.next(b":") {
                        let k = s(&key);
                        if k.trim().starts_with("System Version") {
                            if let Some(v) = t.next(b" ") {
                                info.os_name = Some(s(&v));
                            }
                        }
                        if info.os_name.is_some() {
                            break;
                        }
                    }
                }
            }
            let (_, sw) = get_binary_path(p, "sw_vers");
            if let Some(l) = run_first(&format!("{sw} -productVersion")) {
                info.os_version = Strtok::new(l).next(b"\n").map(|v| s(&v));
            }
            if let Some(l) = run_first(&format!("{sw} -buildVersion")) {
                info.os_build = Strtok::new(l).next(b"\n").map(|v| s(&v));
            }
            if let Some(l) = run_first(&format!("{uname_path} -r")) {
                if let Some(m) = w_regexec("([0-9][0-9]*\\.?[0-9]*)\\.*", &l, 2) {
                    info.os_codename = Some(osx_release_name(atoi(&group(&l, &m, 1))).to_string());
                }
            }
        }
        b"SunOS" => {
            info.os_name = Some("SunOS".into());
            info.os_platform = Some("sunos".into());
            let Some(rel) = p.read_file("/etc/release") else { return false };
            let Some(line) = Fgets::new(&rel, 255).next() else { return false };
            let tag = b"Solaris";
            let Some(f) = line.windows(tag.len()).position(|w| w == tag) else { return false };
            let mut i = f + tag.len();
            while i < line.len() && line[i] == b' ' {
                i += 1;
            }
            let base = i;
            while i < line.len() && line[i] != b' ' {
                i += 1;
            }
            info.os_version = Some(s(&line[base..i]));
        }
        b"HP-UX" => {
            info.os_name = Some("HP-UX".into());
            info.os_platform = Some("hp-ux".into());
            if let Some(l) = run_first(&format!("{uname_path} -r")) {
                if let Some(m) = w_regexec("B\\.([0-9][0-9]*\\.[0-9]*)", &l, 2) {
                    info.os_version = Some(group(&l, &m, 1));
                }
            }
        }
        b"OpenBSD" | b"NetBSD" | b"FreeBSD" => {
            info.os_name = Some("BSD".into());
            info.os_platform = Some("bsd".into());
            if let Some(l) = run_first(&format!("{uname_path} -r")) {
                if let Some(m) = w_regexec("([0-9][0-9]*\\.?[0-9]*)\\.*", &l, 2) {
                    info.os_version = Some(group(&l, &m, 1));
                }
            }
        }
        b"ZscalerOS" => {
            info.os_name = Some("BSD".into());
            info.os_platform = Some("bsd".into());
            if let Some(l) = run_first(&format!("{uname_path} -r")) {
                if let Some(m) = w_regexec("([0-9]+-\\S*).*", &l, 2) {
                    info.os_version = Some(group(&l, &m, 1));
                }
            }
        }
        b"AIX" => {
            info.os_name = Some("AIX".into());
            info.os_platform = Some("aix".into());
            let (_, ol) = get_binary_path(p, "oslevel");
            if let Some(mut l) = run_first(&ol) {
                if !l.is_empty() {
                    l.pop();
                    info.os_version = Some(s(&l));
                }
            }
        }
        b"Linux" => {
            info.os_name = Some("Linux".into());
            info.os_platform = Some("linux".into());
        }
        _ => {}
    }
    true
}

fn opt(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("(null)")
}

/// `getuname()` (Unix): at most 511 bytes.
pub fn getuname_with(p: &dyn Probe) -> String {
    let mut out = if let Some(i) = get_unix_version(p) {
        format!(
            "{} |{} |{} |{} |{} [{}|{}: {}] - {} {}",
            opt(&i.sysname),
            opt(&i.nodename),
            opt(&i.release),
            opt(&i.version),
            opt(&i.machine),
            opt(&i.os_name),
            opt(&i.os_platform),
            opt(&i.os_version),
            OSSEC_NAME,
            OSSEC_VERSION
        )
    } else if let Some(u) = p.uname() {
        format!("{} {} {} {} {} - {} {}", u.sysname, u.nodename, u.release, u.version, u.machine, OSSEC_NAME, OSSEC_VERSION)
    } else {
        format!("No system info available - {OSSEC_NAME} {OSSEC_VERSION}")
    };
    if out.len() > 511 {
        let mut n = 511;
        while !out.is_char_boundary(n) {
            n -= 1;
        }
        out.truncate(n);
    }
    out
}

/// `getuname()`: computed once per process.
pub fn getuname() -> &'static str {
    static U: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    U.get_or_init(|| getuname_with(&System))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fake {
        files: HashMap<&'static str, &'static str>,
    }

    impl Probe for Fake {
        fn read_file(&self, path: &str) -> Option<Vec<u8>> {
            self.files.get(path).map(|s| s.as_bytes().to_vec())
        }
        fn popen(&self, _cmd: &str) -> Option<Vec<u8>> {
            Some(b"Linux\n".to_vec())
        }
        fn uname(&self) -> Option<UtsName> {
            Some(UtsName {
                sysname: "Linux".into(),
                nodename: "h".into(),
                release: "5.15.0".into(),
                version: "#1 SMP".into(),
                machine: "x86_64".into(),
            })
        }
        fn path_env(&self) -> Option<String> {
            None
        }
        fn is_file(&self, _path: &str) -> bool {
            false
        }
    }

    #[cfg(unix)]
    #[test]
    fn ubuntu() {
        let f = Fake {
            files: [(
                "/etc/os-release",
                "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nVERSION_ID=\"22.04\"\n",
            )]
            .into_iter()
            .collect(),
        };
        let i = get_unix_version(&f).unwrap();
        assert_eq!(i.os_version.as_deref(), Some("22.04.3 LTS (Jammy Jellyfish)"));
        assert_eq!(i.os_codename.as_deref(), Some("Jammy Jellyfish"));
        assert_eq!(i.os_major.as_deref(), Some("22"));
        assert_eq!(i.os_minor.as_deref(), Some("04"));
        assert_eq!(i.os_patch.as_deref(), Some("3"));
        assert_eq!(
            getuname_with(&f),
            "Linux |h |5.15.0 |#1 SMP |x86_64 [Ubuntu|ubuntu: 22.04.3 LTS (Jammy Jellyfish)] - Wazuh v4.14.7"
        );
        let g = Fake { files: HashMap::new() };
        assert_eq!(getuname_with(&g), "Linux |h |5.15.0 |#1 SMP |x86_64 [Linux|linux: 0.0] - Wazuh v4.14.7");
    }
}
