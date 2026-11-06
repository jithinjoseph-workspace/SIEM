use crate::os_ip::{ip_found_list, is_valid_ip, OsIp};
use crate::{until_nul, OsMatch, OsRegex, RegexError};
use pcre2::bytes::{Regex, RegexBuilder};

pub const OSMATCH_STR: &str = "osmatch";
pub const OSREGEX_STR: &str = "osregex";
pub const PCRE2_STR: &str = "pcre2";
pub const STRING_STR: &str = "string";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpType {
    OsRegex,
    OsMatch,
    String,
    OsIpArray,
    Pcre2,
}

impl ExpType {
    /// Reads a `type` attribute value, ignoring case; only the three pattern dialects are names.
    pub fn from_attr(name: &str) -> Option<ExpType> {
        [(OSMATCH_STR, ExpType::OsMatch), (OSREGEX_STR, ExpType::OsRegex), (PCRE2_STR, ExpType::Pcre2)]
            .into_iter()
            .find_map(|(n, t)| n.eq_ignore_ascii_case(name).then_some(t))
    }
}

#[derive(Debug, Clone)]
pub struct Pcre2Code {
    pub code: Regex,
    pub raw_pattern: String,
}

/// Result of [`Expression::matches`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpressionMatch {
    pub matched: bool,
    /// Offset of the last byte the match took, for the two regex dialects.
    pub end_match: Option<isize>,
    pub sub_strings: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum ExpressionKind {
    OsRegex(OsRegex),
    OsMatch(OsMatch),
    String(String),
    OsIpArray(Vec<OsIp>),
    Pcre2(Pcre2Code),
}

#[derive(Debug, Clone)]
pub struct Expression {
    pub kind: ExpressionKind,
    pub negate: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ExpressionError {
    #[error("OS_Regex error: {0}")]
    Regex(#[from] RegexError),
    #[error("PCRE2 compile error: {0}")]
    Pcre2(String),
    #[error("invalid IP: {0}")]
    InvalidIp(String),
}

impl Expression {
    pub fn compile(t: ExpType, pattern: &str, flags: u32) -> Result<Expression, ExpressionError> {
        let kind = match t {
            ExpType::OsRegex => ExpressionKind::OsRegex(OsRegex::compile(pattern, flags)?),
            ExpType::OsMatch => ExpressionKind::OsMatch(OsMatch::compile(pattern, flags)?),
            ExpType::String => ExpressionKind::String(pattern.to_string()),
            ExpType::OsIpArray => ExpressionKind::OsIpArray(vec![parse_ip(pattern)?]),
            ExpType::Pcre2 => {
                let code = RegexBuilder::new()
                    .build(pattern)
                    .map_err(|e| ExpressionError::Pcre2(e.to_string()))?;
                ExpressionKind::Pcre2(Pcre2Code { code, raw_pattern: pattern.to_string() })
            }
        };
        Ok(Expression { kind, negate: false })
    }

    pub fn add_osip(this: &mut Option<Expression>, ip: &str) -> Result<(), ExpressionError> {
        let entry = match parse_ip(ip) {
            Ok(entry) => entry,
            Err(e) => {
                *this = None;
                return Err(e);
            }
        };
        if let Some(Expression { kind: ExpressionKind::OsIpArray(list), .. }) = this {
            list.push(entry);
        } else {
            *this = Some(Expression { kind: ExpressionKind::OsIpArray(vec![entry]), negate: false });
        }
        Ok(())
    }

    pub fn match_bytes(&self, s: &[u8], captures: Option<&mut Vec<Vec<u8>>>) -> (bool, Option<isize>) {
        let s = until_nul(s);
        match &self.kind {
            ExpressionKind::OsMatch(m) => (m.is_match_bytes(s), None),
            ExpressionKind::OsRegex(r) => {
                let found = r.execute_bytes(s);
                let (matched, end) = (found.is_some(), found.as_ref().map(|m| m.end));
                if let Some(c) = captures {
                    c.clear();
                    if let Some(m) = found {
                        *c = m.sub_bytes;
                    }
                }
                (matched, end)
            }
            ExpressionKind::Pcre2(p) => pcre2_match(&p.code, s, captures),
            ExpressionKind::String(text) => (text.as_bytes() == s, None),
            ExpressionKind::OsIpArray(list) => (ip_found_list(&String::from_utf8_lossy(s), list), None),
        }
    }

    pub fn exp_type(&self) -> ExpType {
        match self.kind {
            ExpressionKind::OsRegex(_) => ExpType::OsRegex,
            ExpressionKind::OsMatch(_) => ExpType::OsMatch,
            ExpressionKind::String(_) => ExpType::String,
            ExpressionKind::OsIpArray(_) => ExpType::OsIpArray,
            ExpressionKind::Pcre2(_) => ExpType::Pcre2,
        }
    }

    /// Text form of a match, without `negate`. Unlike [`Expression::match_bytes`] the text is not
    /// cut at a NUL for the string, PCRE2 and IP kinds.
    pub fn matches(&self, s: &str) -> ExpressionMatch {
        let plain = |matched| ExpressionMatch { matched, ..Default::default() };
        match &self.kind {
            ExpressionKind::OsMatch(m) => plain(m.is_match(s)),
            ExpressionKind::OsRegex(r) => r.execute(s).map_or_else(ExpressionMatch::default, |m| ExpressionMatch {
                matched: true,
                end_match: Some(m.end),
                sub_strings: m.sub_strings,
            }),
            ExpressionKind::Pcre2(p) => {
                let mut groups = Vec::new();
                match pcre2_match(&p.code, s.as_bytes(), Some(&mut groups)) {
                    (true, end) => ExpressionMatch {
                        matched: true,
                        end_match: end,
                        sub_strings: groups.iter().map(|g| String::from_utf8_lossy(g).into_owned()).collect(),
                    },
                    _ => ExpressionMatch::default(),
                }
            }
            ExpressionKind::String(text) => plain(text == s),
            ExpressionKind::OsIpArray(list) => plain(ip_found_list(s, list)),
        }
    }

    /// [`Expression::matches`] with `negate` applied.
    pub fn is_match(&self, s: &str) -> bool {
        self.matches(s).matched != self.negate
    }

    pub fn pattern(&self) -> Option<&str> {
        match &self.kind {
            ExpressionKind::OsRegex(r) => Some(r.raw()),
            ExpressionKind::OsMatch(m) => Some(m.raw()),
            ExpressionKind::Pcre2(p) => Some(&p.raw_pattern),
            ExpressionKind::String(text) => Some(text),
            ExpressionKind::OsIpArray(_) => None,
        }
    }

    pub fn type_str(&self) -> Option<&'static str> {
        match self.kind {
            ExpressionKind::OsRegex(_) => Some(OSREGEX_STR),
            ExpressionKind::OsMatch(_) => Some(OSMATCH_STR),
            ExpressionKind::Pcre2(_) => Some(PCRE2_STR),
            ExpressionKind::String(_) => Some(STRING_STR),
            ExpressionKind::OsIpArray(_) => None,
        }
    }
}

fn parse_ip(text: &str) -> Result<OsIp, ExpressionError> {
    is_valid_ip(text).1.ok_or_else(|| ExpressionError::InvalidIp(text.to_string()))
}

fn pcre2_match(code: &Regex, s: &[u8], captures: Option<&mut Vec<Vec<u8>>>) -> (bool, Option<isize>) {
    let Ok(Some(caps)) = code.captures(s) else {
        return (false, None);
    };
    let end = caps.get(0).map_or(0, |m| m.end()) as isize - 1;
    let last = (1..caps.len()).rev().find(|&k| caps.get(k).is_some()).unwrap_or(0);
    if let (Some(c), true) = (captures, last >= 1) {
        *c = (1..=last)
            .map(|k| caps.get(k).map_or_else(Vec::new, |m| m.as_bytes().to_vec()))
            .collect();
    }
    (true, Some(end))
}
