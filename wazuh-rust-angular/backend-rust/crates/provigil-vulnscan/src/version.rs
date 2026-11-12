//! Version comparison: six version types and seven strategies.

use crate::log::Log;
use regex::Regex;
use std::cmp::Ordering;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    Unspecified,
    Windows,
    MacOs,
    Pacman,
    Snap,
    Pkg,
    Apk,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Calendar,
    Python,
    MajorMinor,
    Semantic,
    Debian,
    Rpm,
    Strategy(Strategy),
}

impl Kind {
    /// Version kind used for a package format.
    pub fn for_format(format: &str) -> Kind {
        match format {
            "deb" => Kind::Debian,
            "rpm" => Kind::Rpm,
            "pypi" => Kind::Python,
            "npm" => Kind::Semantic,
            "pacman" => Kind::Strategy(Strategy::Pacman),
            "snap" => Kind::Strategy(Strategy::Snap),
            "pkg" => Kind::Strategy(Strategy::Pkg),
            "win" => Kind::Strategy(Strategy::Windows),
            "macports" => Kind::Strategy(Strategy::MacOs),
            "apk" => Kind::Strategy(Strategy::Apk),
            _ => Kind::Strategy(Strategy::Unspecified),
        }
    }
}

const TRY_ALL: [Kind; 6] = [Kind::Calendar, Kind::Python, Kind::MajorMinor, Kind::Semantic, Kind::Debian, Kind::Rpm];

/// Error text of a number above 64 bits.
pub const NUMBER_TOO_LARGE: &str = "Version number out of range";
/// Error text of an RPM epoch that is not a number or out of range.
pub const BAD_INTEGER: &str = "Invalid integer value";

fn type_name(k: Kind) -> &'static str {
    match k {
        Kind::Calendar => "CalVer",
        Kind::Python => "PEP440",
        Kind::MajorMinor => "MajorMinor",
        Kind::Semantic => "SemVer",
        Kind::Debian => "DPKG",
        Kind::Rpm => "RPM",
        Kind::Strategy(_) => "Unspecified",
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Parsed {
    Cal([u64; 4]),
    Py(Py),
    Mm(u64, u64),
    Sem(Sem),
    Deb(Deb),
    Rpm(Rpm),
}

#[derive(Debug, Clone, PartialEq)]
struct Py {
    epoch: u32,
    release: Vec<u32>,
    pre: Option<(String, u32)>,
    post: Option<u32>,
    dev: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
struct Sem {
    nums: [u64; 3],
    pre: String,
}

#[derive(Debug, Clone, PartialEq)]
struct Deb {
    epoch: u64,
    version: String,
    revision: String,
}

#[derive(Debug, Clone, PartialEq)]
struct Rpm {
    epoch: u32,
    version: String,
    release: String,
}

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).expect("valid pattern"))
}

fn num64(t: &str) -> Result<u64, String> {
    t.parse::<u64>().map_err(|_| NUMBER_TOO_LARGE.to_string())
}

/// Above 64 bits is a parse error, else truncated to 32 bits.
fn num32(t: &str) -> Result<u64, String> {
    Ok(u64::from(num64(t)? as u32))
}

/// Python release numbers: built digit by digit in wrapping 32-bit arithmetic (any length).
fn release_num(t: &str) -> u32 {
    t.bytes().fold(0u32, |n, d| n.wrapping_mul(10).wrapping_add(u32::from(d - b'0')))
}

fn parse_cal(v: &str) -> Result<Option<Parsed>, String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = re(&R, r"^(\d{2}|\d{4})(?:\.(\d{1,2}))?(?:\.(\d{1,2}))?(?:\.(\d+))?$");
    let Some(c) = r.captures(v) else { return Ok(None) };
    let mut year = num64(&c[1])?;
    if c[1].len() == 2 {
        year += 2000;
    }
    let month = c.get(2).map_or(0, |m| m.as_str().parse::<u64>().unwrap_or(0));
    let day = c.get(3).map_or(0, |m| m.as_str().parse::<u64>().unwrap_or(0));
    if c.get(2).is_some() && !(1..=12).contains(&month) {
        return Ok(None);
    }
    if c.get(3).is_some() && !(1..=31).contains(&day) {
        return Ok(None);
    }
    let micro = match c.get(4) {
        Some(m) => num32(m.as_str())?,
        None => 0,
    };
    Ok(Some(Parsed::Cal([year, month, day, micro])))
}

fn parse_py(v: &str) -> Result<Option<Parsed>, String> {
    static R: OnceLock<Regex> = OnceLock::new();
    // Either nothing at all after the optional `v`, or a required release with optional parts.
    let r = re(
        &R,
        r"(?i)^v?(?:(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d+)?)?(?:[-_.]?(dev)[-_.]?(\d+)?)?)?$",
    );
    let Some(c) = r.captures(v) else { return Ok(None) };
    let n = |i: usize| -> Result<u32, String> {
        match c.get(i) {
            Some(m) => Ok(num64(m.as_str())? as u32),
            None => Ok(0),
        }
    };
    let epoch = n(1)?;
    let release: Vec<u32> = c.get(2).map(|m| m.as_str().split('.').map(release_num).collect()).unwrap_or_default();
    let pre = match c.get(3) {
        Some(m) => {
            let name = match m.as_str().to_ascii_lowercase().as_str() {
                "alpha" | "a" => "a",
                "beta" | "b" => "b",
                _ => "rc",
            };
            Some((name.to_string(), n(4)?))
        }
        None => None,
    };
    let post = if c.get(5).is_some() {
        Some(n(5)?)
    } else if c.get(6).is_some() {
        Some(n(7)?)
    } else {
        None
    };
    let dev = if c.get(8).is_some() { Some(n(9)?) } else { None };
    Ok(Some(Parsed::Py(Py { epoch, release, pre, post, dev })))
}

fn parse_mm(v: &str) -> Result<Option<Parsed>, String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = re(&R, r"^(\d+)[.-](\d+)$");
    let Some(c) = r.captures(v) else { return Ok(None) };
    Ok(Some(Parsed::Mm(num32(&c[1])?, num32(&c[2])?)))
}

fn parse_sem(v: &str) -> Result<Option<Parsed>, String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = re(
        &R,
        r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$",
    );
    let Some(c) = r.captures(v) else { return Ok(None) };
    let (a, b, d) = (num32(&c[1])?, num32(&c[2])?, num32(&c[3])?);
    Ok(Some(Parsed::Sem(Sem { nums: [a, b, d], pre: c.get(4).map_or(String::new(), |m| m.as_str().to_string()) })))
}

/// Whitespace as the C library sees it (space, tab, LF, VT, FF, CR).
fn deb_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

fn parse_deb(v: &str, log: &Log) -> Option<Parsed> {
    let v = v.split('\0').next().unwrap_or("");
    let t = v.trim_start_matches(deb_ws);
    if t.is_empty() {
        return None;
    }
    let end = t.find(deb_ws).unwrap_or(t.len());
    if !t[end..].chars().all(deb_ws) {
        return None;
    }
    let t = &t[..end];
    let (epoch, rest) = match t.find(':') {
        Some(p) => {
            let e = t[..p].strip_prefix('+').unwrap_or(&t[..p]);
            if e.is_empty() || !e.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let n: u64 = e.parse().ok().filter(|n| *n <= u32::MAX as u64)?;
            if p + 1 >= t.len() {
                return None;
            }
            (n, &t[p + 1..])
        }
        None => (0, t),
    };
    let (version, revision) = match rest.rfind('-') {
        Some(p) => {
            if p + 1 == rest.len() {
                return None;
            }
            (&rest[..p], &rest[p + 1..])
        }
        None => (rest, ""),
    };
    if !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    if version.chars().any(|c| !(c.is_ascii_alphanumeric() || ".-+~:".contains(c))) {
        vs!(log, Debug, "Invalid character in version number: {version} in {v}.");
        return None;
    }
    if revision.chars().any(|c| !(c.is_ascii_alphanumeric() || ".+~".contains(c))) {
        vs!(log, Debug, "Invalid character in revision: {revision} in {v}.");
        return None;
    }
    Some(Parsed::Deb(Deb { epoch, version: version.into(), revision: revision.into() }))
}

/// Reads an integer the way C does (leading spaces, sign, digits, rest ignored); 32-bit range.
fn c_int(t: &str) -> Result<i32, String> {
    let t = t.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let n = digits.bytes().take_while(u8::is_ascii_digit).count();
    if n == 0 {
        return Err(BAD_INTEGER.into());
    }
    let mut v: i64 = 0;
    for b in digits[..n].bytes() {
        v = v * 10 + (b - b'0') as i64;
        if v > i32::MAX as i64 + 1 {
            return Err(BAD_INTEGER.into());
        }
    }
    let v = if neg { -v } else { v };
    i32::try_from(v).map_err(|_| BAD_INTEGER.to_string())
}

fn parse_rpm(v: &str) -> Result<Option<Parsed>, String> {
    let colon = v.find(':');
    let epoch = match colon {
        Some(p) => c_int(&v[..p])? as u32,
        None => 0,
    };
    let start = colon.map_or(0, |p| p + 1);
    // A `-` before the colon does not end the version: it is the whole rest after the colon.
    let (version, release) = match v.find('-') {
        Some(d) if d >= start => (&v[start..d], &v[d + 1..]),
        Some(d) => (&v[start..], &v[d + 1..]),
        None => (&v[start..], ""),
    };
    Ok(Some(Parsed::Rpm(Rpm { epoch, version: version.into(), release: release.into() })))
}

fn parse_as(k: Kind, v: &str, log: &Log) -> Result<Option<Parsed>, String> {
    let r = match k {
        Kind::Calendar => parse_cal(v)?,
        Kind::Python => parse_py(v)?,
        Kind::MajorMinor => parse_mm(v)?,
        Kind::Semantic => parse_sem(v)?,
        Kind::Debian => parse_deb(v, log),
        Kind::Rpm => parse_rpm(v)?,
        Kind::Strategy(_) => None,
    };
    if r.is_none() {
        vs!(log, Debug2, "Error creating version value ({}). Version string doesn't match the specified type. Version string: {v}", type_name(k));
    }
    Ok(r)
}

fn parse(kind: Kind, v: &str, log: &Log) -> Result<Option<Parsed>, String> {
    match kind {
        Kind::Strategy(s) => match s {
            Strategy::Windows | Strategy::MacOs | Strategy::Pkg | Strategy::Pacman | Strategy::Snap => {
                parse_as(Kind::Debian, v, log)
            }
            Strategy::Apk | Strategy::Unspecified => {
                for k in TRY_ALL {
                    if let Some(p) = parse_as(k, v, log)? {
                        return Ok(Some(p));
                    }
                }
                vs!(log, Debug2, "Error creating version value (Unspecified). Version string doesn't match any of the specified types. Version string: {v}");
                Ok(None)
            }
        },
        k => parse_as(k, v, log),
    }
}

/// A version parsed once with a kind; `None` when it does not parse as that kind.
pub struct Installed(Option<Parsed>);

/// Parses `v` with the kind; a parse error (e.g. a number out of range) is returned.
pub fn parse_installed(v: &str, kind: Kind, log: &Log) -> Result<Installed, String> {
    parse(kind, v, log).map(Installed)
}

/// Compares an already parsed `a` with `b`; `b` is parsed only when `a` parsed.
pub fn compare_installed(a: &Installed, a_text: &str, b: &str, kind: Kind, log: &Log) -> Result<Ordering, String> {
    let fail = || format!("Unable to compare versions ({a_text} vs {b}).");
    let Some(x) = &a.0 else { return Err(fail()) };
    match parse(kind, b, log)? {
        Some(y) => cmp_parsed(x, &y).ok_or_else(fail),
        None => Err(fail()),
    }
}

/// Compares `a` with `b`: `a` is parsed first and `b` only when `a` parsed.
pub fn compare(a: &str, b: &str, kind: Kind, log: &Log) -> Result<Ordering, String> {
    compare_installed(&parse_installed(a, kind, log)?, a, b, kind, log)
}

fn cmp_parsed(a: &Parsed, b: &Parsed) -> Option<Ordering> {
    Some(match (a, b) {
        (Parsed::Cal(x), Parsed::Cal(y)) => x.cmp(y),
        (Parsed::Mm(a1, a2), Parsed::Mm(b1, b2)) => (a1, a2).cmp(&(b1, b2)),
        (Parsed::Py(x), Parsed::Py(y)) => cmp_py(x, y),
        (Parsed::Sem(x), Parsed::Sem(y)) => x.nums.cmp(&y.nums).then_with(|| match (x.pre.is_empty(), y.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (false, true) => Ordering::Less,
            (true, false) => Ordering::Greater,
            (false, false) => x.pre.as_bytes().cmp(y.pre.as_bytes()),
        }),
        (Parsed::Deb(x), Parsed::Deb(y)) => x
            .epoch
            .cmp(&y.epoch)
            .then_with(|| deb_cmp(&x.version, &y.version))
            .then_with(|| deb_cmp(&x.revision, &y.revision)),
        (Parsed::Rpm(x), Parsed::Rpm(y)) => x
            .epoch
            .cmp(&y.epoch)
            .then_with(|| rpm_cmp(&x.version, &y.version))
            .then_with(|| rpm_cmp(&x.release, &y.release)),
        _ => return None,
    })
}

fn cmp_py(a: &Py, b: &Py) -> Ordering {
    let n = a.release.len().max(b.release.len());
    let at = |r: &Vec<u32>, i: usize| r.get(i).copied().unwrap_or(0);
    a.epoch
        .cmp(&b.epoch)
        .then_with(|| (0..n).map(|i| at(&a.release, i).cmp(&at(&b.release, i))).find(|o| o.is_ne()).unwrap_or(Ordering::Equal))
        .then_with(|| match (&a.pre, &b.pre) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some((x, i)), Some((y, j))) => x.as_bytes().cmp(y.as_bytes()).then(i.cmp(j)),
        })
        .then_with(|| match (a.post, b.post) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(x), Some(y)) => x.cmp(&y),
        })
        .then_with(|| match (a.dev, b.dev) {
            (None, None) => Ordering::Equal,
            // With exactly one dev part, the one without it is the smaller.
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(x), Some(y)) => x.cmp(&y),
        })
}

fn deb_order(c: u8) -> i32 {
    if c.is_ascii_digit() {
        0
    } else if c.is_ascii_alphabetic() {
        c as i32
    } else if c == b'~' {
        -1
    } else if c != 0 {
        c as i32 + 256
    } else {
        0
    }
}

fn deb_cmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let at = |s: &[u8], i: usize| s.get(i).copied().unwrap_or(0);
    let (mut i, mut j) = (0, 0);
    while at(a, i) != 0 || at(b, j) != 0 {
        let mut first_diff = 0i32;
        while (at(a, i) != 0 && !at(a, i).is_ascii_digit()) || (at(b, j) != 0 && !at(b, j).is_ascii_digit()) {
            let (ac, bc) = (deb_order(at(a, i)), deb_order(at(b, j)));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while at(a, i) == b'0' {
            i += 1;
        }
        while at(b, j) == b'0' {
            j += 1;
        }
        while at(a, i).is_ascii_digit() && at(b, j).is_ascii_digit() {
            if first_diff == 0 {
                first_diff = at(a, i) as i32 - at(b, j) as i32;
            }
            i += 1;
            j += 1;
        }
        if at(a, i).is_ascii_digit() {
            return Ordering::Greater;
        }
        if at(b, j).is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != 0 {
            return first_diff.cmp(&0);
        }
    }
    Ordering::Equal
}

fn rpm_cmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let at = |s: &[u8], i: usize| s.get(i).copied().unwrap_or(0);
    let keep = |c: u8| c.is_ascii_alphanumeric() || c == b'~' || c == b'^';
    let (mut i, mut j) = (0, 0);
    while at(a, i) != 0 || at(b, j) != 0 {
        while at(a, i) != 0 && !keep(at(a, i)) {
            i += 1;
        }
        while at(b, j) != 0 && !keep(at(b, j)) {
            j += 1;
        }
        let (x, y) = (at(a, i), at(b, j));
        if x == b'~' || y == b'~' {
            if x != b'~' {
                return Ordering::Greater;
            }
            if y != b'~' {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if x == b'^' || y == b'^' {
            if x == 0 {
                return Ordering::Less;
            }
            if y == 0 {
                return Ordering::Greater;
            }
            if x != b'^' {
                return Ordering::Greater;
            }
            if y != b'^' {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if x == 0 || y == 0 {
            break;
        }
        let (si, sj) = (i, j);
        let isnum = x.is_ascii_digit();
        let class = |c: u8| if isnum { c.is_ascii_digit() } else { c.is_ascii_alphabetic() };
        while at(a, i) != 0 && class(at(a, i)) {
            i += 1;
        }
        while at(b, j) != 0 && class(at(b, j)) {
            j += 1;
        }
        if sj == j {
            return if isnum { Ordering::Greater } else { Ordering::Less };
        }
        let (mut s1, mut s2) = (&a[si..i], &b[sj..j]);
        if isnum {
            while s1.first() == Some(&b'0') {
                s1 = &s1[1..];
            }
            while s2.first() == Some(&b'0') {
                s2 = &s2[1..];
            }
            match s1.len().cmp(&s2.len()) {
                Ordering::Equal => {}
                o => return o,
            }
        }
        match s1.cmp(s2) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    match (at(a, i) == 0, at(b, j) == 0) {
        (true, true) => Ordering::Equal,
        (false, _) => Ordering::Greater,
        _ => Ordering::Less,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::{Level, MemoryLogger};
    use std::sync::Arc;
    use Ordering::*;

    fn c(a: &str, b: &str, k: Kind) -> Result<Ordering, String> {
        compare(a, b, k, &Log::null())
    }

    #[test]
    fn worked_examples() {
        let u = Kind::Strategy(Strategy::Unspecified);
        let rows: Vec<(Kind, &str, &str, Ordering)> = vec![
            (Kind::Debian, "1:2.0-1", "2.0-1", Greater),
            (Kind::Debian, "1.0~rc1", "1.0", Less),
            (Kind::Debian, "1.0", "1.0-0", Equal),
            (Kind::Debian, "2:8.2.3995-1ubuntu2", "2:8.2.3995-1ubuntu10", Less),
            (Kind::Rpm, "1.0.10", "1.0.9", Greater),
            (Kind::Rpm, "1.0^git1", "1.0", Greater),
            (Kind::Rpm, "1.0~rc1", "1.0", Less),
            (Kind::Rpm, "1.0a", "1.0", Greater),
            (Kind::Rpm, "1.0", "1.0.0", Less),
            (Kind::Rpm, "1.a", "1.1", Less),
            (Kind::Rpm, "2.0-1.el8", "2.0-1.el9", Less),
            (Kind::Python, "1.0a1", "1.0", Less),
            (Kind::Python, "1.0.post1", "1.0", Greater),
            (Kind::Python, "1.0", "1.0.0", Equal),
            (Kind::Python, "1.0alpha1", "1.0a1", Equal),
            (Kind::Python, "1.0-1", "1.0.post1", Equal),
            (Kind::Python, "2!1.0", "3.0", Greater),
            (Kind::Python, "1.0.dev1", "1.0a1", Greater),
            (Kind::Semantic, "1.0.0-alpha", "1.0.0", Less),
            (Kind::Semantic, "1.0.0+build.1", "1.0.0", Equal),
            (Kind::Semantic, "1.0.0-alpha.10", "1.0.0-alpha.9", Less),
            (Kind::MajorMinor, "3-4", "3.4", Equal),
            (u, "2023.10.01", "2023.9.1", Greater),
            (u, "23.10", "2023.10", Equal),
            (Kind::Strategy(Strategy::Windows), "120.0.6099.71", "120.0.6099.109", Less),
        ];
        for (k, a, b, want) in rows {
            assert_eq!(c(a, b, k), Ok(want), "{k:?} {a} {b}");
        }
        assert_eq!(c("1.0-", "1.0", Kind::Debian), Err("Unable to compare versions (1.0- vs 1.0).".into()));
        assert_eq!(c("x:1.0", "1.0", Kind::Rpm), Err(BAD_INTEGER.into()));
        assert_eq!(c("abc", "1.0", u), Err("Unable to compare versions (abc vs 1.0).".into()));
        assert!(c("16.4.1", "16.10.0", u).is_err());
    }

    #[test]
    fn debian_parsing() {
        let l = Arc::new(MemoryLogger::default());
        let log = Log::new(l.clone());
        for bad in ["1:", "-1:1.0", "1.0 2", "a1", "1.0_1", ""] {
            assert!(parse_deb(bad, &log).is_none(), "{bad}");
        }
        assert!(parse_deb(" 1.0 ", &log).is_some());
        assert!(l.has(Level::Debug, "Invalid character in version number: 1.0_1 in 1.0_1."));
        for s in [Strategy::Windows, Strategy::MacOs, Strategy::Pkg, Strategy::Pacman, Strategy::Snap] {
            assert_eq!(c("10.0.19041.3693", "10.0.22621.2715", Kind::Strategy(s)), Ok(Less));
        }
    }

    #[test]
    fn corrections_d1_d2_d8_d9() {
        let u = Kind::Strategy(Strategy::Unspecified);
        // D1: with exactly one dev part, the one without it is the smaller.
        assert_eq!(c("1", "1.0.dev1", Kind::Python), Ok(Less));
        assert_eq!(c("1.0.dev1", "1.0a1", Kind::Python), Ok(Greater));
        // D2: pre/post/dev without a release is not Python.
        assert_eq!(c("", "dev", Kind::Python), Err("Unable to compare versions ( vs dev).".into()));
        assert_eq!(c("post1", "-1", u), Ok(Greater));
        assert_eq!(c("", "v", Kind::Python), Ok(Equal));
        // D8/D53: release numbers wrap digit by digit in 32 bits, no error.
        assert_eq!(release_num("18446744073709551616"), 0);
        assert_eq!(release_num("4294967296"), 0);
        assert_eq!(release_num("99999999999999999999"), 1661992959);
        assert_eq!(c("18446744073709551616", "0", Kind::Python), Ok(Equal));
        assert_eq!(c("1.99999999999999999999", "1.18446744073709551616", Kind::Python), Ok(Greater));
        assert_eq!(c("1", "18446744073709551616", Kind::Python), Ok(Greater));
        assert_eq!(c("99999999999999999999999!1", "1", Kind::Python), Err(NUMBER_TOO_LARGE.into()));
        // D9: a `-` before the colon leaves the whole rest as the version.
        assert_eq!(c("1-2:3.0", "1:1.0", Kind::Rpm), Ok(Greater));
    }

    #[test]
    fn corrections_low() {
        // D24/D25: 32-bit truncation; above 64 bits is a parse error.
        assert_eq!(parse_cal("2023.1.1.4294967297").unwrap(), Some(Parsed::Cal([2023, 1, 1, 1])));
        assert_eq!(c("4294967296.1", "0.1", Kind::MajorMinor), Ok(Equal));
        assert_eq!(c("1.0.99999999999999999999", "1.0.0", Kind::Semantic), Err(NUMBER_TOO_LARGE.into()));
        // D26: VT is whitespace; `+` epoch accepted.
        assert!(parse_deb("1.0\x0b", &Log::null()).is_some());
        assert_eq!(c("+1:2.0", "1:2.0", Kind::Debian), Ok(Equal));
        // D27: A's failure wins, B is not parsed.
        assert_eq!(c("x:1", "y:2", Kind::Rpm), Err(BAD_INTEGER.into()));
        assert_eq!(c("1.0-", "x", Kind::Debian), Err("Unable to compare versions (1.0- vs x).".into()));
    }

    #[test]
    fn calendar_and_debug_lines() {
        assert_eq!(parse_cal("2023.13").unwrap(), None);
        assert_eq!(parse_cal("99.12.31.123456").unwrap(), Some(Parsed::Cal([2099, 12, 31, 123456])));
        assert_eq!(parse_cal("2023.1.1.99999999999999999999999").unwrap_err(), NUMBER_TOO_LARGE);
        let l = Arc::new(MemoryLogger::default());
        let _ = compare("abc!", "1", Kind::Strategy(Strategy::Unspecified), &Log::new(l.clone()));
        assert!(l.has(Level::Debug2, "Error creating version value (CalVer). Version string doesn't match the specified type. Version string: abc!"));
    }
}
