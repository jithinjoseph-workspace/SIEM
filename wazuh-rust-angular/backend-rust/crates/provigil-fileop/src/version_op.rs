//! The operating-system description string, computed once per process.
//!
//! Unix detection reads everything through [`System`] so it can be replayed over a fake system.

use std::sync::OnceLock;

macro_rules! product {
    (name) => {
        "Wazuh"
    };
    (version) => {
        "v4.14.7"
    };
}

/// Product name and version at the end of the description. Agents and stored data may compare
/// this text, so it stays as is for now.
pub const PRODUCT_NAME: &str = product!(name);
pub const PRODUCT_VERSION: &str = product!(version);
pub const AGENT_PRODUCT: &str = concat!(product!(name), " ", product!(version));

const NUMBER: &str = r"([0-9][0-9]*\.?[0-9]*)\.*";
/// Lines of release files and command outputs are read in pieces of at most this many bytes.
const LINE_PIECE: usize = 254;
const PROFILER_PIECE: usize = 255;
const UNIX_NAME_MAX: usize = 511;

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
    pub os_release: Option<String>,
    pub sysname: Option<String>,
    pub nodename: Option<String>,
    pub release: Option<String>,
    pub version: Option<String>,
    pub machine: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UtsName {
    pub sysname: String,
    pub nodename: String,
    pub release: String,
    pub version: String,
    pub machine: String,
}

/// What detection may look at.
pub trait System {
    fn read(&self, path: &str) -> Option<Vec<u8>>;
    /// Runs `cmd` (words separated by spaces); its output, None if it could not be run.
    fn run(&self, cmd: &str) -> Option<String>;
    fn is_executable(&self, path: &str) -> bool;
    fn path_env(&self) -> Option<String>;
    fn uname(&self) -> Option<UtsName>;
}

/// The machine this process runs on.
pub struct Live;

impl System for Live {
    fn read(&self, path: &str) -> Option<Vec<u8>> {
        std::fs::read(path).ok()
    }

    /// The output counts even when the command exits with an error status.
    fn run(&self, cmd: &str) -> Option<String> {
        let mut words = cmd.split_whitespace();
        let out = std::process::Command::new(words.next()?).args(words).stderr(std::process::Stdio::null()).output().ok()?;
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Any regular file counts (no execute-bit test).
    fn is_executable(&self, path: &str) -> bool {
        std::fs::metadata(path).is_ok_and(|m| m.is_file())
    }

    fn path_env(&self) -> Option<String> {
        std::env::var("PATH").ok()
    }

    #[cfg(unix)]
    fn uname(&self) -> Option<UtsName> {
        use std::ffi::{c_char, CStr};
        let text = |f: &[c_char]| unsafe { CStr::from_ptr(f.as_ptr()) }.to_string_lossy().into_owned();
        // SAFETY: utsname is plain data, filled by uname; its fields are NUL-terminated.
        let u = unsafe {
            let mut u: libc::utsname = std::mem::zeroed();
            if libc::uname(&mut u) != 0 {
                return None;
            }
            u
        };
        Some(UtsName {
            sysname: text(&u.sysname),
            nodename: text(&u.nodename),
            release: text(&u.release),
            version: text(&u.version),
            machine: text(&u.machine),
        })
    }

    #[cfg(not(unix))]
    fn uname(&self) -> Option<UtsName> {
        None
    }
}

/// Cuts to at most `max` bytes on a character boundary.
pub(crate) fn cut(s: &mut String, max: usize) {
    let mut n = s.len().min(max);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    s.truncate(n);
}

/// POSIX extended regex search: (start, end) of the first `nmatch` groups, -1 when unset.
/// Unix only, as Unix detection is; elsewhere nothing matches.
#[cfg(unix)]
pub fn w_regexec(pattern: &str, subject: &str, nmatch: usize) -> Option<Vec<(i64, i64)>> {
    use std::ffi::CString;
    let pattern = CString::new(pattern).ok()?;
    let subject = subject.split('\0').next().and_then(|s| CString::new(s).ok())?;
    let mut groups = vec![libc::regmatch_t { rm_so: -1, rm_eo: -1 }; nmatch];
    // SAFETY: regex_t is filled by regcomp and freed once; strings and the group array stay alive.
    unsafe {
        let mut re: libc::regex_t = std::mem::zeroed();
        if libc::regcomp(&mut re, pattern.as_ptr(), libc::REG_EXTENDED) != 0 {
            return None;
        }
        let r = libc::regexec(&re, subject.as_ptr(), nmatch, groups.as_mut_ptr(), 0);
        libc::regfree(&mut re);
        (r == 0).then(|| groups.iter().map(|g| (i64::from(g.rm_so), i64::from(g.rm_eo))).collect())
    }
}

#[cfg(not(unix))]
pub fn w_regexec(_pattern: &str, _subject: &str, _nmatch: usize) -> Option<Vec<(i64, i64)>> {
    None
}

/// The text of group `group` of the first match; a group that took no part gives "".
fn capture(pattern: &str, subject: &str, group: usize) -> Option<String> {
    let (start, end) = *w_regexec(pattern, subject, group + 1)?.get(group)?;
    if start < 0 {
        return Some(String::new());
    }
    let span = subject.as_bytes().get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)?;
    Some(String::from_utf8_lossy(span).into_owned())
}

/// Lines as C reads them: pieces of at most 254 bytes (newline kept), each ending at a NUL.
fn pieces(data: &[u8]) -> Vec<String> {
    pieces_of(data, LINE_PIECE)
}

fn pieces_of(data: &[u8], max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let p = crate::piece(data, pos, max);
        pos += p.len();
        out.push(String::from_utf8_lossy(p.split(|&b| b == 0).next().unwrap_or_default()).into_owned());
    }
    out
}

/// Group `group` of the last match in `subject` (several matches on one line: the last counts).
fn last_capture(pattern: &str, subject: &str, group: usize) -> Option<String> {
    let (mut rest, mut last) = (subject, None);
    while let Some(g) = w_regexec(pattern, rest, group + 1) {
        let (start, end) = (g[group].0, g[group].1);
        last = Some(if start < 0 { String::new() } else { rest.get(start as usize..end as usize).unwrap_or_default().to_string() });
        let whole_end = g[0].1 as usize;
        if whole_end == 0 {
            break;
        }
        rest = &rest[whole_end..];
    }
    last
}

/// Group `group` of the pattern in the first piece that matches.
fn first_match(lines: &[String], pattern: &str, group: usize) -> Option<String> {
    lines.iter().find_map(|l| capture(pattern, l, group))
}

/// Full path of `binary` through PATH: Ok when found, Err(binary) otherwise.
pub fn get_binary_path(binary: &str, sys: &dyn System) -> Result<String, String> {
    if binary.starts_with('/') {
        return if sys.is_executable(binary) { Ok(binary.into()) } else { Err(binary.into()) };
    }
    let Some(path) = sys.path_env() else { return Err(binary.into()) };
    let found = path.split(':').filter(|d| !d.is_empty()).map(|d| format!("{d}/{binary}")).find(|p| sys.is_executable(p));
    found.ok_or_else(|| binary.into())
}

pub fn osx_release_name(major: i32) -> &'static str {
    match major {
        10 => "Snow Leopard",
        11 => "Lion",
        12 => "Mountain Lion",
        13 => "Mavericks",
        14 => "Yosemite",
        15 => "El Capitan",
        16 => "Sierra",
        17 => "High Sierra",
        18 => "Mojave",
        19 => "Catalina",
        20 => "Big Sur",
        21 => "Monterey",
        22 => "Ventura",
        23 => "Sonoma",
        24 => "Sequoia",
        _ => "Unknown",
    }
}

/// The value after `KEY=`: a leading quote is dropped and the value ends at the next one.
fn release_value(v: &str) -> &str {
    let v = v.split('\n').next().unwrap_or_default();
    match v.strip_prefix('"') {
        Some(q) => q.split('"').next().unwrap_or_default(),
        None => v,
    }
}

/// `KEY=value` of a piece; leading `=` characters are skipped before the key.
fn key_value(piece: &str) -> Option<(&str, &str)> {
    piece.trim_start_matches('=').split_once('=')
}

/// Step 1: `/etc/os-release` or `/usr/lib/os-release`.
fn from_os_release(sys: &dyn System, i: &mut OsInfo) {
    let Some(data) = sys.read("/etc/os-release").or_else(|| sys.read("/usr/lib/os-release")) else { return };
    let mut got_version = false;
    for line in pieces(&data) {
        let Some((key, value)) = key_value(&line) else { continue };
        let raw = value;
        let value = release_value(value);
        match key {
            "NAME" if i.os_name.is_none() => i.os_name = Some(value.into()),
            "VERSION" if !got_version => {
                i.os_version = Some(value.into());
                got_version = true;
            }
            "VERSION_ID" if i.os_version.is_none() => i.os_version = Some(value.into()),
            "ID" if i.os_platform.is_none() => {
                // First word after `=`, then its quotes dropped: `ID= "rhel"` gives rhel.
                let word = raw.trim_start_matches(' ').split([' ', '\n']).next().unwrap_or_default();
                let id = match word.strip_prefix('"') {
                    Some(q) => q.split('"').next().unwrap_or_default(),
                    None => word,
                };
                i.os_platform = Some(id.into());
            }
            _ => {}
        }
    }
    match i.os_platform.as_deref() {
        Some("centos") => {
            if let Some(d) = sys.read("/etc/centos-release") {
                i.os_version = first_match(&pieces(&d), NUMBER, 1);
            }
        }
        Some("opensuse-tumbleweed" | "arch") => i.os_version = Some(String::new()),
        _ => {}
    }
}

fn named(i: &mut OsInfo, name: &str, platform: &str) {
    i.os_name = Some(name.into());
    i.os_platform = Some(platform.into());
}

/// Step 2: the first release file that exists decides. False when there is none.
fn from_release_files(sys: &dyn System, i: &mut OsInfo) -> bool {
    let read = |p: &str| sys.read(p).map(|d| pieces(&d));
    if let Some(t) = read("/etc/centos-release") {
        named(i, "CentOS Linux", "centos");
        i.os_version = first_match(&t, NUMBER, 1);
    } else if let Some(t) = read("/etc/fedora-release") {
        named(i, "Fedora", "fedora");
        i.os_version = first_match(&t, " ([0-9][0-9]*) ", 1);
    } else if let Some(t) = read("/etc/redhat-release") {
        for line in &t {
            if line.contains("CentOS") {
                named(i, "CentOS Linux", "centos");
            } else if line.contains("Fedora") {
                named(i, "Fedora", "fedora");
            } else if line.contains("Server") {
                named(i, "Red Hat Enterprise Linux Server", "rhel");
            } else {
                named(i, "Red Hat Enterprise Linux", "rhel");
            }
            i.os_version = capture(NUMBER, line, 1);
            if i.os_version.is_some() {
                break;
            }
        }
    } else if let Some(t) = read("/etc/arch-release") {
        named(i, "Arch Linux", "arch");
        i.os_version = Some(first_match(&t, NUMBER, 1).unwrap_or_default());
    } else if let Some(t) = read("/etc/gentoo-release") {
        named(i, "Gentoo", "gentoo");
        i.os_version = first_match(&t, r" ([0-9][0-9]*\.?[0-9]*)\.*", 1);
    } else if let Some(t) = read("/etc/SuSE-release") {
        named(i, "SuSE Linux", "suse");
        i.os_version = t.iter().find_map(|l| last_capture("VERSION = ([0-9]+)", l, 1));
    } else if let Some(t) = read("/etc/lsb-release") {
        named(i, "Ubuntu", "ubuntu");
        // The value exactly as written, quotes included.
        let value = t.iter().find_map(|l| l.trim_start_matches('=').strip_prefix("DISTRIB_RELEASE="));
        i.os_version = value.map(|v| v.split('\n').next().unwrap_or_default().to_string());
    } else if let Some(t) = read("/etc/debian_version") {
        named(i, "Debian GNU/Linux", "debian");
        i.os_version = first_match(&t, NUMBER, 1);
    } else if let Some(t) = read("/etc/slackware-version") {
        named(i, "Slackware", "slackware");
        i.os_version = first_match(&t, r" ([0-9][0-9]*\.?[0-9]*)\.*", 1);
    } else if let Some(t) = read("/etc/alpine-release") {
        named(i, "Alpine Linux", "alpine");
        i.os_version = first_match(&t, r"([0-9]+\.)?([0-9]+\.)?([0-9]+)", 0);
    } else {
        return false;
    }
    true
}

/// The first line of a command's output: its first piece without the newline; nothing when empty.
fn first_line(sys: &dyn System, cmd: &str) -> Option<String> {
    let first = pieces(sys.run(cmd)?.as_bytes()).into_iter().next()?;
    let line = first.strip_suffix('\n').unwrap_or(&first);
    (!line.is_empty()).then(|| line.to_string())
}

/// Step 3: asks the `uname` command. False when detection fails outright (Solaris without release).
fn from_uname_command(sys: &dyn System, i: &mut OsInfo) -> bool {
    // Every command runs through its PATH location (full path when found, plain name otherwise).
    let resolve = |name: &str| get_binary_path(name, sys).unwrap_or_else(|b| b);
    let bin = resolve("uname");
    let uname_r = format!("{bin} -r");
    let release = |pattern: &str, group| first_line(sys, &uname_r).and_then(|r| capture(pattern, &r, group));
    match first_line(sys, &bin).as_deref() {
        Some("Darwin") => {
            i.os_platform = Some("darwin".into());
            let profiler = format!("{} SPSoftwareDataType", resolve("system_profiler"));
            let profile = sys.run(&profiler).map(|o| pieces_of(o.as_bytes(), PROFILER_PIECE)).unwrap_or_default();
            i.os_name = profile.iter().find_map(|l| {
                let (key, rest) = l.trim_start_matches(':').split_once(':')?;
                if !key.trim().starts_with("System Version") {
                    return None;
                }
                // No word after the colon: this line gives no name, later lines are tried.
                let rest = rest.trim_start_matches(' ');
                (!rest.is_empty()).then(|| rest.split(' ').next().unwrap_or_default().to_string())
            });
            let sw_vers = resolve("sw_vers");
            i.os_version = first_line(sys, &format!("{sw_vers} -productVersion"));
            i.os_build = first_line(sys, &format!("{sw_vers} -buildVersion"));
            let number = first_line(sys, &uname_r).and_then(|r| capture(NUMBER, &r, 1));
            i.os_codename = number.map(|n| {
                let digits: String = n.chars().take_while(char::is_ascii_digit).collect();
                osx_release_name(digits.parse().unwrap_or(0)).to_string()
            });
        }
        Some("SunOS") => {
            named(i, "SunOS", "sunos");
            let first = sys.read("/etc/release").and_then(|d| pieces(&d).into_iter().next());
            let Some((_, after)) = first.as_deref().and_then(|l| l.split_once("Solaris")) else { return false };
            // Tabs and the newline belong to the version; only spaces end it.
            i.os_version = Some(after.trim_start_matches(' ').split(' ').next().unwrap_or_default().to_string());
        }
        Some("HP-UX") => {
            named(i, "HP-UX", "hp-ux");
            i.os_version = release(r"B\.([0-9][0-9]*\.[0-9]*)", 1);
        }
        Some("OpenBSD" | "NetBSD" | "FreeBSD") => {
            named(i, "BSD", "bsd");
            i.os_version = release(NUMBER, 1);
        }
        Some("ZscalerOS") => {
            named(i, "BSD", "bsd");
            i.os_version = release("([0-9]+-[^[:space:]]*)", 1);
        }
        Some("AIX") => {
            named(i, "AIX", "aix");
            let first = sys.run(&resolve("oslevel")).and_then(|o| pieces(o.as_bytes()).into_iter().next());
            i.os_version = first.map(|mut l| {
                l.pop();
                l
            });
        }
        Some("Linux") => named(i, "Linux", "linux"),
        _ => {}
    }
    true
}

/// Step 5: `0.0` default, codename and version parts.
fn finish_version(i: &mut OsInfo) {
    let Some(v) = i.os_version.clone() else {
        i.os_version = Some("0.0".into());
        return;
    };
    if v.is_empty() {
        return;
    }
    if let Some((_, c)) = v.split_once(" (") {
        let mut c = c.to_string();
        c.pop();
        i.os_codename = Some(c);
    }
    i.os_major = capture("^([0-9]+)", &v, 1);
    i.os_minor = capture(r"^[0-9]+\.([0-9]+)", &v, 1);
    i.os_patch = capture(r"^[0-9]+\.[0-9]+\.([0-9]+)?", &v, 1);
    if let (Some("darwin"), Some(c)) = (i.os_platform.as_deref(), &i.os_codename) {
        i.os_version = Some(format!("{v} ({c})"));
    }
}

/// Detects the Unix flavour; None when nothing usable is known.
pub fn get_unix_version(sys: &dyn System) -> Option<OsInfo> {
    let mut i = OsInfo::default();
    from_os_release(sys, &mut i);
    if i.os_name.is_none() || i.os_platform.is_none() || (i.os_version.is_none() && i.os_build.is_none()) {
        i = OsInfo::default();
        if !from_release_files(sys, &mut i) && !from_uname_command(sys, &mut i) {
            return None;
        }
    }
    let u = sys.uname()?;
    i.sysname = Some(u.sysname);
    i.nodename = Some(u.nodename);
    i.release = Some(u.release);
    i.version = Some(u.version);
    i.machine = Some(u.machine);
    finish_version(&mut i);
    Some(i)
}

/// The Unix description string over any [`System`].
pub fn getuname_with(sys: &dyn System) -> String {
    let f = |o: &Option<String>| o.clone().unwrap_or_else(|| "(null)".into());
    let mut s = match get_unix_version(sys) {
        Some(i) => format!(
            "{} |{} |{} |{} |{} [{}|{}: {}] - {AGENT_PRODUCT}",
            f(&i.sysname),
            f(&i.nodename),
            f(&i.release),
            f(&i.version),
            f(&i.machine),
            f(&i.os_name),
            f(&i.os_platform),
            f(&i.os_version),
        ),
        None => match sys.uname() {
            Some(u) => format!("{} {} {} {} {} - {AGENT_PRODUCT}", u.sysname, u.nodename, u.release, u.version, u.machine),
            None => format!("No system info available - {AGENT_PRODUCT}"),
        },
    };
    cut(&mut s, UNIX_NAME_MAX);
    s
}

/// This machine's description, computed once per process.
pub fn getuname() -> &'static str {
    static NAME: OnceLock<String> = OnceLock::new();
    NAME.get_or_init(|| {
        #[cfg(windows)]
        return crate::win_version::getuname();
        #[cfg(not(windows))]
        getuname_with(&Live)
    })
}
