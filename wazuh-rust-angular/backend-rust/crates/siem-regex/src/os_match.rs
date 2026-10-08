//! Faithful port of Wazuh `OSMatch` (`src/os_regex/os_match_compile.c`,
//! `os_match_execute.c`) and `OS_WordMatch` (`os_regex_match.c`).
//!
//! OSMatch is the matcher behind `<match>`: case-insensitive substring search
//! with `|` alternation, `^` / `$` anchors and a leading `!` for negation.

use crate::maps::CHARMAP;
use crate::os_regex::{signed_eq, RegexError, OS_CASE_SENSITIVE, OS_PATTERN_MAXSIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchFn {
    /// `_OS_Match`: substring search.
    Contains,
    /// `_os_strncmp`: `^pattern`.
    StartsWith,
    /// `_os_strcmp`: `^pattern$`.
    Equals,
    /// `_os_strcmp_last`: `pattern$`.
    EndsWith,
    /// `_os_strmatch`: empty pattern, always true.
    Always,
}

#[derive(Debug, Clone)]
struct MatchPattern {
    pat: Vec<u8>,
    size: usize,
    f: MatchFn,
}

#[derive(Debug, Clone)]
pub struct OsMatch {
    raw: String,
    negate: bool,
    patterns: Vec<MatchPattern>,
}

/// `strncasecmp(a, b, n) == 0` with C-locale ASCII folding; both are NUL-terminated views.
fn strncasecmp_eq(a: &[u8], b: &[u8], n: usize) -> bool {
    for i in 0..n {
        let ca = a.get(i).copied().unwrap_or(0);
        let cb = b.get(i).copied().unwrap_or(0);
        if ca.to_ascii_lowercase() != cb.to_ascii_lowercase() {
            return false;
        }
        if ca == 0 {
            return true;
        }
    }
    true
}

fn strcasecmp_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

/// `_OS_Match`
fn os_match_contains(pattern: &[u8], s: &[u8], size: usize) -> bool {
    let str_len = s.len();
    if str_len < size {
        return false;
    }
    let limit = str_len - size;
    let at_s = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut i = 0usize;
    loop {
        if signed_eq(pattern.first().copied().unwrap_or(0), CHARMAP[at_s(i) as usize]) {
            let mut pt = 1usize;
            let mut j = i + 1;
            let mut matched = true;
            while pt < pattern.len() {
                if at_s(j) == 0 {
                    return false;
                } else if !signed_eq(pattern[pt], CHARMAP[at_s(j) as usize]) {
                    matched = false;
                    break;
                }
                j += 1;
                pt += 1;
            }
            if matched {
                return true;
            }
        }
        i += 1;
        if i > limit {
            break;
        }
    }
    false
}

impl OsMatch {
    /// `OSMatch_Compile`.
    pub fn compile(pattern: &str, flags: u32) -> Result<Self, RegexError> {
        if pattern.len() > OS_PATTERN_MAXSIZE {
            return Err(RegexError::MaxSize);
        }
        let mut bytes = pattern.as_bytes();
        let mut negate = false;
        if bytes.first() == Some(&b'!') {
            negate = true;
            bytes = &bytes[1..];
        }
        let mut buf = bytes.to_vec();
        if flags & OS_CASE_SENSITIVE == 0 {
            for b in buf.iter_mut() {
                *b = CHARMAP[*b as usize];
            }
        }

        let mut patterns = Vec::new();
        for part in buf.split(|&b| b == b'|') {
            let begins = part.first() == Some(&b'^');
            let ends = part.last() == Some(&b'$');
            let body: &[u8] = if begins { &part[1..] } else { part };

            let mp = if begins && ends {
                // "^$"-style: strip the trailing '$'. A lone "^" never has ends==true
                // because *(pt-1) is the '^' itself.
                let size = body.len().saturating_sub(1);
                MatchPattern { pat: body[..size].to_vec(), size, f: MatchFn::Equals }
            } else if part.is_empty() {
                MatchPattern { pat: Vec::new(), size: 0, f: MatchFn::Always }
            } else if ends {
                let size = body.len() - 1;
                MatchPattern { pat: body[..size].to_vec(), size, f: MatchFn::EndsWith }
            } else if begins {
                MatchPattern { pat: body.to_vec(), size: body.len(), f: MatchFn::StartsWith }
            } else {
                MatchPattern { pat: body.to_vec(), size: body.len(), f: MatchFn::Contains }
            };
            patterns.push(mp);
        }

        Ok(Self { raw: pattern.to_string(), negate, patterns })
    }

    /// `OSMatch.patterns`: the compiled pieces (anchors stripped, folded
    /// with the charmap when case-insensitive).
    pub fn patterns(&self) -> Vec<&[u8]> {
        self.patterns.iter().map(|p| &p.pat[..]).collect()
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn is_negated(&self) -> bool {
        self.negate
    }

    /// `OSMatch_Execute`.
    pub fn is_match(&self, s: &str) -> bool {
        self.is_match_bytes(s.as_bytes())
    }

    pub fn is_match_bytes(&self, s: &[u8]) -> bool {
        // A C string stops at the first NUL.
        let s = match s.iter().position(|&b| b == 0) {
            Some(n) => &s[..n],
            None => s,
        };
        for mp in &self.patterns {
            let hit = match mp.f {
                MatchFn::Contains => os_match_contains(&mp.pat, s, mp.size),
                MatchFn::StartsWith => strncasecmp_eq(&mp.pat, s, mp.size),
                MatchFn::Equals => strcasecmp_eq(&mp.pat, s),
                MatchFn::EndsWith => s.len() >= mp.size && strcasecmp_eq(&mp.pat, &s[s.len() - mp.size..]),
                MatchFn::Always => true,
            };
            if hit {
                return !self.negate;
            }
        }
        self.negate
    }
}

/// `OS_Match2`: compile + execute once.
pub fn os_match2(pattern: &str, s: &str) -> bool {
    OsMatch::compile(pattern, 0).map(|m| m.is_match(s)).unwrap_or(false)
}

/// `OS_WordMatch` (a.k.a. `OS_Match`): fast case-insensitive search with `|` and `^`.
pub fn os_word_match(pattern: &str, s: &str) -> bool {
    let pattern = pattern.as_bytes();
    let s = s.as_bytes();
    if pattern.is_empty() {
        return false;
    }
    let pc = |p: &[u8], i: usize| p.get(i).copied().unwrap_or(0);

    let mut pat = pattern;
    let mut count = 0usize;
    loop {
        if pc(pat, count) == b'|' {
            if internal_match(pat, s, count) {
                return true;
            }
            pat = &pat[count + 1..];
            count = 0;
            // `continue` in a do/while jumps to the condition.
            if pc(pat, count) == 0 {
                break;
            }
            continue;
        }
        count += 1;
        if pc(pat, count) == 0 {
            break;
        }
    }
    internal_match(pat, s, count)
}

/// `_InternalMatch`
fn internal_match(pattern: &[u8], s: &[u8], pattern_size: usize) -> bool {
    let pc = |i: usize| pattern.get(i).copied().unwrap_or(0);
    let sc = |i: usize| s.get(i).copied().unwrap_or(0);
    let last_char = pc(pattern_size);

    if pc(0) == 0 {
        return true;
    } else if pc(0) == b'^' {
        let size = pattern_size.saturating_sub(1);
        return strncasecmp_eq(&pattern[1..], s, size);
    } else if sc(0) == 0 {
        return false;
    }

    let mut st = 0usize;
    loop {
        if CHARMAP[sc(st) as usize] == CHARMAP[pc(0) as usize] {
            let start = st;
            st += 1;
            let mut pt = 1usize;
            let mut ok = true;
            while pc(pt) != last_char {
                if sc(st) == 0 {
                    return false;
                } else if CHARMAP[pc(pt) as usize] != CHARMAP[sc(st) as usize] {
                    ok = false;
                    break;
                }
                st += 1;
                pt += 1;
            }
            if ok {
                return true;
            }
            st = start;
        }
        st += 1;
        if sc(st) == 0 {
            break;
        }
    }
    false
}
