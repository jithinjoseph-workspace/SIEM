//! Faithful port of Wazuh `OSRegex` (`src/os_regex/os_regex_compile.c`,
//! `os_regex_execute.c`).
//!
//! The matching algorithm is *not* a regular backtracking regex engine: it is a
//! greedy single-pass scanner with up to four back-tracking points. Rules and
//! decoders in the stock ruleset depend on its exact quirks, so this module
//! mirrors the C code statement by statement, using byte indices in place of
//! pointers (a `0` byte past the end of a buffer plays the role of the C NUL
//! terminator).
//!
//! Supported syntax (see the Wazuh "Regular Expression Syntax" docs):
//! `\w \d \s \p \W \D \S \. \t \$ \( \) \\ \| \<`, the `+` / `*` modifiers on an
//! escape, `^` / `$` anchors, `|` alternation and one level of `( )` capture.

use crate::maps::{CHARMAP, REGEXMAP};

/// `OS_RETURN_SUBSTRING`: capture the text inside `( )` groups.
pub const OS_RETURN_SUBSTRING: u32 = 0o200;
/// `OS_CASE_SENSITIVE`: do not lower-case the pattern.
pub const OS_CASE_SENSITIVE: u32 = 0o400;
/// `OS_PATTERN_MAXSIZE`
pub const OS_PATTERN_MAXSIZE: usize = 20480;

const BACKSLASH: u8 = b'\\';
const BEGINREGEX: u8 = b'^';
const ENDREGEX: u8 = b'$';
const OR: u8 = b'|';

const BEGIN_SET: u32 = 0o200;
const END_SET: u32 = 0o400;

/// Error codes, identical to `OS_REGEX_*` in `os_regex.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegexError {
    #[error("pattern is null")]
    PatternNull = 2,
    #[error("pattern exceeds maximum size")]
    MaxSize = 3,
    #[error("out of memory")]
    OutOfMemory = 4,
    #[error("string is null")]
    StrNull = 5,
    #[error("bad regex (unknown escape sequence)")]
    BadRegex = 6,
    #[error("bad parenthesis")]
    BadParenthesis = 7,
}

#[inline]
pub(crate) fn at(buf: &[u8], i: isize) -> u8 {
    if i < 0 {
        return 0;
    }
    buf.get(i as usize).copied().unwrap_or(0)
}

/// On x86 `char` is signed: comparing a pattern `char` holding a byte >= 0x80
/// with an `unsigned char` from `charmap` never succeeds. Wazuh's ruleset is
/// validated against that behaviour, so literal non-ASCII bytes never match.
#[inline]
pub(crate) fn signed_eq(pattern_byte: u8, mapped: u8) -> bool {
    (pattern_byte as i8 as i32) == mapped as i32
}

#[inline]
fn regex_class(code: u8, ch: u8) -> bool {
    let row = code as usize;
    row < REGEXMAP.len() && REGEXMAP[row][ch as usize] == 1
}

#[inline]
fn is_plus(c: u8) -> bool {
    c == b'+' || c == b'*'
}

#[inline]
fn prts(c: u8) -> bool {
    c == b'('
}

#[derive(Debug, Clone)]
struct SubPattern {
    /// Pattern bytes after escape translation (escapes are `\` + class code).
    pat: Vec<u8>,
    flags: u32,
    /// Offsets of every `(` (open and close are both stored as `(`).
    closure: Option<Vec<usize>>,
}

/// A compiled OSRegex. Immutable after compilation and safe to share between
/// threads (the C version needs a mutex for its scratch buffers; here they are
/// allocated per call).
#[derive(Debug, Clone)]
pub struct OsRegex {
    raw: String,
    subs: Vec<SubPattern>,
    returns_substrings: bool,
}

/// Result of a successful [`OsRegex::execute`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegexMatch {
    /// Byte offset of the last character the matcher consumed. This is the
    /// value of the pointer returned by `OSRegex_Execute`; decoders use it as
    /// the starting point for `offset="after_regex"`.
    ///
    /// It can be `-1`: for patterns that begin with `\x*` and match zero
    /// characters, the C code returns a pointer one byte *before* the input.
    pub end: isize,
    /// Captured `( )` groups (only with [`OS_RETURN_SUBSTRING`]).
    pub sub_strings: Vec<String>,
    /// The same captures as raw bytes (C strings are not UTF-8).
    pub sub_bytes: Vec<Vec<u8>>,
}

impl OsRegex {
    /// `OSRegex_Compile`.
    pub fn compile(pattern: &str, flags: u32) -> Result<Self, RegexError> {
        if pattern.len() > OS_PATTERN_MAXSIZE {
            return Err(RegexError::MaxSize);
        }

        let mut buf: Vec<u8> = pattern.as_bytes().to_vec();
        let mut parenthesis: i32 = 0;
        let mut prts_size: u32 = 0;
        let mut i = 0usize;

        while i < buf.len() {
            if buf[i] == BACKSLASH {
                i += 1;
                let code = match buf.get(i).copied().unwrap_or(0) {
                    b'd' => 1,
                    b'w' => 2,
                    b's' => 3,
                    b'p' => 4,
                    b'(' => 5,
                    b')' => 6,
                    b'\\' => 7,
                    b'D' => 8,
                    b'W' => 9,
                    b'S' => 10,
                    b'.' => 11,
                    b't' => 12,
                    b'$' => 13,
                    b'|' => 14,
                    b'<' => 15,
                    _ => return Err(RegexError::BadRegex),
                };
                buf[i] = code;
                i += 1;
                continue;
            } else if buf[i] == b'(' {
                parenthesis += 1;
            } else if buf[i] == b')' {
                buf[i] = b'(';
                parenthesis -= 1;
                prts_size += 1;
            }

            if parenthesis != 0 && parenthesis != 1 {
                return Err(RegexError::BadParenthesis);
            }

            if flags & OS_CASE_SENSITIVE == 0 {
                buf[i] = CHARMAP[buf[i] as usize];
            }

            if buf[i] == OR && parenthesis != 0 {
                return Err(RegexError::BadParenthesis);
            }
            i += 1;
        }

        if parenthesis != 0 {
            return Err(RegexError::BadParenthesis);
        }

        let with_closure = prts_size > 0 && (flags & OS_RETURN_SUBSTRING != 0);

        // Split on '|' (escaped '|' has already become code 14).
        let mut subs = Vec::new();
        for part in buf.split(|&b| b == OR) {
            let mut start = 0usize;
            let mut end = part.len();
            let mut sflags = 0u32;
            if part.first() == Some(&BEGINREGEX) {
                start = 1;
                sflags |= BEGIN_SET;
            }
            if end > start && part[end - 1] == ENDREGEX {
                end -= 1;
                sflags |= END_SET;
            }
            let pat = part[start..end].to_vec();

            let closure = if with_closure {
                let positions: Vec<usize> = pat
                    .iter()
                    .enumerate()
                    .filter(|(_, &c)| prts(c))
                    .map(|(idx, _)| idx)
                    .collect();
                Some(positions)
            } else {
                None
            };

            subs.push(SubPattern { pat, flags: sflags, closure });
        }

        Ok(Self {
            raw: pattern.to_string(),
            subs,
            returns_substrings: with_closure,
        })
    }

    /// `d_sub_strings != NULL`: compiled with `OS_RETURN_SUBSTRING` and the
    /// pattern has at least one `( )` group.
    pub fn has_sub_strings(&self) -> bool {
        self.returns_substrings
    }

    /// Raw pattern as written in the rule / decoder.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// `OSRegex_Execute_ex`. Returns `None` when there is no match.
    pub fn execute(&self, s: &str) -> Option<RegexMatch> {
        self.execute_bytes(s.as_bytes())
    }

    /// Boolean convenience wrapper.
    pub fn is_match(&self, s: &str) -> bool {
        self.execute(s).is_some()
    }

    pub fn execute_bytes(&self, s: &[u8]) -> Option<RegexMatch> {
        if self.returns_substrings {
            for sub in &self.subs {
                let closure = sub.closure.as_deref().unwrap_or(&[]);
                let mut prts_str: Vec<Option<isize>> = vec![None; closure.len() + 1];
                if let Some(ret) = os_regex_internal(&sub.pat, s, Some(closure), &mut prts_str, sub.flags) {
                    let mut sub_strings = Vec::new();
                    let mut sub_bytes = Vec::new();
                    let mut j = 0usize;
                    while j + 1 < prts_str.len() {
                        match (prts_str[j], prts_str[j + 1]) {
                            (Some(a), Some(b)) => {
                                // A capture that closes before it opens has a
                                // negative length. In C, `malloc(length + 1)` then
                                // fails (returns NULL => no match) or, for length
                                // -1, malloc(0) succeeds and strncpy crashes. Both
                                // are reported here as "no match".
                                if b < a {
                                    return None;
                                }
                                let a = (a.max(0) as usize).min(s.len());
                                let b = (b.max(0) as usize).min(s.len());
                                sub_strings.push(String::from_utf8_lossy(&s[a..b]).into_owned());
                                sub_bytes.push(s[a..b].to_vec());
                            }
                            _ => break,
                        }
                        j += 2;
                    }
                    return Some(RegexMatch { end: ret, sub_strings, sub_bytes });
                }
            }
            return None;
        }

        for sub in &self.subs {
            let mut none: Vec<Option<isize>> = Vec::new();
            if let Some(ret) = os_regex_internal(&sub.pat, s, None, &mut none, sub.flags) {
                return Some(RegexMatch { end: ret, sub_strings: Vec::new(), sub_bytes: Vec::new() });
            }
        }
        None
    }
}

/// `OS_Regex`: compile + execute once.
pub fn os_regex(pattern: &str, s: &str) -> bool {
    OsRegex::compile(pattern, 0).map(|r| r.is_match(s)).unwrap_or(false)
}

fn set_closure(closure: Option<&[usize]>, prts_str: &mut [Option<isize>], pt: isize, value: isize) {
    if let Some(cl) = closure {
        if let Some(idx) = cl.iter().position(|&p| p as isize == pt) {
            prts_str[idx] = Some(value);
        }
    }
}

/// `_OS_Regex` — returns the `r_code` pointer as an offset, `None` for NULL.
// `next_pt` keeps a dead store the C code also has.
#[allow(unused_assignments)]
fn os_regex_internal(
    pattern: &[u8],
    s: &[u8],
    closure: Option<&[usize]>,
    prts_str: &mut [Option<isize>],
    flags: u32,
) -> Option<isize> {
    let p = |i: isize| at(pattern, i);
    let sc = |i: isize| at(s, i);

    let mut r_code: Option<isize> = Some(0);
    let mut regex_matched = 0i32;
    let mut st: isize = 0;
    let mut st_error: Option<isize> = None;
    let mut pt: isize = 0;
    let mut next_pt: isize;
    let mut pt_error: [Option<isize>; 4] = [None; 4];
    let mut pt_error_str: [isize; 4] = [0; 4];

    let end_ok = |st_ch: u8| (flags & END_SET == 0) || st_ch == 0;

    while sc(st) != 0 {
        'body: {
            match p(pt) {
                0 => {
                    if end_ok(sc(st)) {
                        return r_code;
                    }
                }
                b'(' => {
                    set_closure(closure, prts_str, pt, st);
                    pt += 1;
                    if p(pt) == 0 && end_ok(sc(st)) {
                        return r_code;
                    }
                }
                _ => {}
            }

            if p(pt) == BACKSLASH {
                if regex_class(p(pt + 1), sc(st)) {
                    next_pt = pt + 2;

                    if !is_plus(p(next_pt)) {
                        pt = next_pt;
                        if st_error.is_none() {
                            st_error = Some(st);
                        }
                        r_code = Some(st);
                        break 'body;
                    }

                    if p(next_pt) == b'*' {
                        regex_matched = 1;
                    }

                    if regex_matched != 0 {
                        next_pt += 1;
                        let mut ok_here: i32 = -1;

                        if prts(p(next_pt)) {
                            next_pt += 1;
                        }

                        if p(next_pt) == 0 {
                            ok_here = 1;
                        } else if p(next_pt) == BACKSLASH {
                            if regex_class(p(next_pt + 1), sc(st)) {
                                ok_here = if !is_plus(p(next_pt + 2)) { 2 } else { 0 };
                            }
                        } else if signed_eq(p(next_pt), CHARMAP[sc(st) as usize]) {
                            regex_matched = 0;
                            ok_here = 1;
                        }

                        if ok_here >= 0 {
                            if closure.is_some() && prts(p(next_pt - 1)) {
                                let v = if regex_matched != 0 && ok_here == 1 { st + 1 } else { st };
                                set_closure(closure, prts_str, next_pt - 1, v);
                            }

                            if p(next_pt) == 0 {
                                break 'body;
                            }

                            if ok_here != 0 {
                                next_pt += ok_here as isize;
                            }

                            if pt_error[0].is_none() {
                                pt_error[0] = Some(pt);
                                pt_error_str[0] = st;
                            } else if pt_error[1].is_none() {
                                pt_error[1] = Some(pt);
                                pt_error_str[1] = st;
                            } else if pt_error[2].is_none() {
                                pt_error[2] = Some(pt);
                                pt_error_str[2] = st;
                            } else if pt_error[3].is_none() {
                                pt_error[3] = Some(pt);
                                pt_error_str[3] = st;
                            }

                            pt = next_pt;
                        }
                    } else {
                        next_pt += 1;

                        if closure.is_some() && prts(p(next_pt)) {
                            let v = if sc(st + 1) == 0 { st + 1 } else { st };
                            set_closure(closure, prts_str, next_pt, v);
                            next_pt += 1;
                        }

                        regex_matched = 1;
                    }

                    r_code = Some(st);
                    break 'body;
                } else if (p(pt + 2) == 0 || p(pt + 3) == 0) && regex_matched == 1 && r_code.is_some() {
                    r_code = Some(st);
                    if end_ok(sc(st)) {
                        return r_code;
                    }
                } else if p(pt + 2) == b'+' && regex_matched == 1 {
                    pt += 3;
                    st -= 1;
                    regex_matched = 0;
                    break 'body;
                } else if p(pt + 2) == b'*' {
                    pt += 3;
                    st -= 1;
                    r_code = Some(st);
                    regex_matched = 0;
                    break 'body;
                }

                regex_matched = 0;
            } else if signed_eq(p(pt), CHARMAP[sc(st) as usize]) {
                pt += 1;
                if st_error.is_none() {
                    st_error = Some(st);
                }
                r_code = Some(st);
                break 'body;
            }

            // Error handling
            let mut resumed = false;
            for k in (0..4).rev() {
                if let Some(e) = pt_error[k] {
                    pt = e;
                    st = pt_error_str[k];
                    pt_error[k] = None;
                    resumed = true;
                    break;
                }
            }
            if resumed {
                break 'body;
            }
            if flags & BEGIN_SET != 0 {
                return None;
            } else if let Some(e) = st_error {
                st = e;
                st_error = None;
            }
            pt = 0;
            r_code = None;
        }
        st += 1;
    }

    // Match for a possible last parenthesis
    if closure.is_some() {
        while !prts(p(pt)) && p(pt) != 0 {
            if p(pt) == BACKSLASH && p(pt + 2) == b'*' {
                pt += 3;
            } else {
                break;
            }
        }
        if prts(p(pt)) {
            set_closure(closure, prts_str, pt, st);
        }
    }

    // ENDOFFILE(x): skip one '(' then test for NUL (the macro mutates x).
    let eof = |pt: &mut isize| -> bool {
        if prts(p(*pt)) {
            *pt += 1;
        }
        p(*pt) == 0
    };

    let cleanup_ok = eof(&mut pt)
        || (p(pt) == BACKSLASH && regex_matched != 0 && {
            pt += 2;
            is_plus(p(pt))
        } && {
            pt += 1;
            eof(&mut pt)
                || (p(pt) == BACKSLASH && {
                    pt += 2;
                    p(pt) == b'*'
                } && {
                    pt += 1;
                    eof(&mut pt)
                })
        })
        || (p(pt) == BACKSLASH && {
            pt += 2;
            p(pt) == b'*'
        } && {
            pt += 1;
            eof(&mut pt)
        });

    if cleanup_ok {
        return r_code;
    }
    None
}
