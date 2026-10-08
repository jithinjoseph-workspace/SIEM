//! Port of Wazuh `w_expression_t` (`src/shared/expression.c`): the
//! polymorphic matcher behind every rule / decoder field that accepts a
//! `type="osmatch|osregex|pcre2"` attribute.

use crate::os_ip::{ip_found_list, is_valid_ip, OsIp};
use crate::os_match::OsMatch;
use crate::os_regex::{OsRegex, RegexError};

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
    /// Parse the `type` attribute value (case-insensitive, as `strcasecmp`).
    pub fn from_attr(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            OSMATCH_STR => Some(Self::OsMatch),
            OSREGEX_STR => Some(Self::OsRegex),
            PCRE2_STR => Some(Self::Pcre2),
            _ => None,
        }
    }
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

#[derive(Debug, Clone)]
pub struct Pcre2Code {
    pub code: pcre2::bytes::Regex,
    pub raw_pattern: String,
}

#[derive(Debug, Clone)]
pub enum ExpressionKind {
    OsRegex(OsRegex),
    OsMatch(OsMatch),
    String(String),
    OsIpArray(Vec<OsIp>),
    Pcre2(Pcre2Code),
}

/// `w_expression_t`
#[derive(Debug, Clone)]
pub struct Expression {
    pub kind: ExpressionKind,
    /// Set from the `negate="yes"` attribute; applied by the caller (analysisd
    /// checks `negate` after `w_expression_match`).
    pub negate: bool,
}

/// Outcome of [`Expression::matches`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpressionMatch {
    pub matched: bool,
    /// Offset of the last consumed byte (`end_match`), when the matcher reports one.
    pub end_match: Option<isize>,
    /// Captured groups (OSRegex with substrings, or PCRE2 groups 1..n).
    pub sub_strings: Vec<String>,
}

impl Expression {
    /// `w_calloc_expression_t` + `w_expression_compile`.
    pub fn compile(exp_type: ExpType, pattern: &str, flags: u32) -> Result<Self, ExpressionError> {
        let kind = match exp_type {
            ExpType::OsMatch => ExpressionKind::OsMatch(OsMatch::compile(pattern, flags)?),
            ExpType::OsRegex => ExpressionKind::OsRegex(OsRegex::compile(pattern, flags)?),
            ExpType::Pcre2 => {
                let code = pcre2::bytes::RegexBuilder::new()
                    .build(pattern)
                    .map_err(|e| ExpressionError::Pcre2(e.to_string()))?;
                ExpressionKind::Pcre2(Pcre2Code { code, raw_pattern: pattern.to_string() })
            }
            ExpType::String => ExpressionKind::String(pattern.to_string()),
            ExpType::OsIpArray => {
                let mut v = Vec::new();
                let (ok, ip) = is_valid_ip(pattern);
                match (ok, ip) {
                    (0, _) | (_, None) => return Err(ExpressionError::InvalidIp(pattern.to_string())),
                    (_, Some(ip)) => v.push(ip),
                }
                ExpressionKind::OsIpArray(v)
            }
        };
        Ok(Self { kind, negate: false })
    }

    /// `w_expression_add_osip`: append one IP to an IP-array expression,
    /// creating it when `this` is `None`.
    pub fn add_osip(this: &mut Option<Expression>, ip: &str) -> Result<(), ExpressionError> {
        let (ok, parsed) = is_valid_ip(ip);
        let parsed = match (ok, parsed) {
            (0, _) | (_, None) => {
                *this = None;
                return Err(ExpressionError::InvalidIp(ip.to_string()));
            }
            (_, Some(p)) => p,
        };
        match this {
            Some(Expression { kind: ExpressionKind::OsIpArray(v), .. }) => v.push(parsed),
            _ => *this = Some(Expression { kind: ExpressionKind::OsIpArray(vec![parsed]), negate: false }),
        }
        Ok(())
    }

    pub fn exp_type(&self) -> ExpType {
        match &self.kind {
            ExpressionKind::OsRegex(_) => ExpType::OsRegex,
            ExpressionKind::OsMatch(_) => ExpType::OsMatch,
            ExpressionKind::String(_) => ExpType::String,
            ExpressionKind::OsIpArray(_) => ExpType::OsIpArray,
            ExpressionKind::Pcre2(_) => ExpType::Pcre2,
        }
    }

    /// `w_expression_match`. Does **not** apply `negate` (same as C).
    pub fn matches(&self, s: &str) -> ExpressionMatch {
        match &self.kind {
            ExpressionKind::OsMatch(m) => ExpressionMatch { matched: m.is_match(s), ..Default::default() },
            ExpressionKind::OsRegex(r) => match r.execute(s) {
                Some(rm) => ExpressionMatch { matched: true, end_match: Some(rm.end), sub_strings: rm.sub_strings },
                None => ExpressionMatch::default(),
            },
            ExpressionKind::Pcre2(p) => match p.code.captures(s.as_bytes()) {
                Ok(Some(caps)) => {
                    let whole = caps.get(0).expect("group 0");
                    // ret_match = str + ovector[1] - 1
                    let end = whole.end() as isize - 1;
                    // captured_groups = rc = highest participating group + 1
                    let mut last = 0;
                    for i in 1..caps.len() {
                        if caps.get(i).is_some() {
                            last = i;
                        }
                    }
                    let sub_strings = (1..=last)
                        .map(|i| {
                            caps.get(i)
                                .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
                                .unwrap_or_default()
                        })
                        .collect();
                    ExpressionMatch { matched: true, end_match: Some(end), sub_strings }
                }
                _ => ExpressionMatch::default(),
            },
            ExpressionKind::String(st) => ExpressionMatch { matched: st == s, ..Default::default() },
            ExpressionKind::OsIpArray(ips) => ExpressionMatch { matched: ip_found_list(s, ips), ..Default::default() },
        }
    }

    /// `w_expression_match` on a byte string with the caller's
    /// `regex_matching` context. Returns `(matched, end_match)`.
    ///
    /// Like C, an OSRegex always resets `sub_strings` before matching, while a
    /// PCRE2 expression only replaces them when it captured at least one group
    /// (otherwise the previous captures are left in place).
    pub fn match_bytes(&self, s: &[u8], regex_match: Option<&mut Vec<Vec<u8>>>) -> (bool, Option<isize>) {
        let s = match s.iter().position(|&b| b == 0) {
            Some(n) => &s[..n],
            None => s,
        };
        match &self.kind {
            ExpressionKind::OsMatch(m) => (m.is_match_bytes(s), None),
            ExpressionKind::OsRegex(r) => {
                let res = r.execute_bytes(s);
                if let Some(rm_out) = regex_match {
                    rm_out.clear();
                    if let Some(rm) = &res {
                        *rm_out = rm.sub_bytes.clone();
                    }
                }
                match res {
                    Some(rm) => (true, Some(rm.end)),
                    None => (false, None),
                }
            }
            ExpressionKind::Pcre2(p) => match p.code.captures(s) {
                Ok(Some(caps)) => {
                    let end = caps.get(0).expect("group 0").end() as isize - 1;
                    let mut last = 0;
                    for i in 1..caps.len() {
                        if caps.get(i).is_some() {
                            last = i;
                        }
                    }
                    if last >= 1 {
                        if let Some(out) = regex_match {
                            *out = (1..=last)
                                .map(|i| caps.get(i).map(|m| m.as_bytes().to_vec()).unwrap_or_default())
                                .collect();
                        }
                    }
                    (true, Some(end))
                }
                _ => (false, None),
            },
            ExpressionKind::String(st) => (st.as_bytes() == s, None),
            ExpressionKind::OsIpArray(ips) => (ip_found_list(&String::from_utf8_lossy(s), ips), None),
        }
    }

    /// Boolean match with `negate` applied — what rule evaluation actually uses.
    pub fn is_match(&self, s: &str) -> bool {
        self.matches(s).matched != self.negate
    }

    /// `w_expression_get_regex_pattern`
    pub fn pattern(&self) -> Option<&str> {
        match &self.kind {
            ExpressionKind::OsRegex(r) => Some(r.raw()),
            ExpressionKind::OsMatch(m) => Some(m.raw()),
            ExpressionKind::Pcre2(p) => Some(&p.raw_pattern),
            ExpressionKind::String(s) => Some(s),
            ExpressionKind::OsIpArray(_) => None,
        }
    }

    /// `w_expression_get_regex_type`
    pub fn type_str(&self) -> Option<&'static str> {
        match &self.kind {
            ExpressionKind::OsMatch(_) => Some(OSMATCH_STR),
            ExpressionKind::OsRegex(_) => Some(OSREGEX_STR),
            ExpressionKind::Pcre2(_) => Some(PCRE2_STR),
            ExpressionKind::String(_) => Some(STRING_STR),
            ExpressionKind::OsIpArray(_) => None,
        }
    }
}
