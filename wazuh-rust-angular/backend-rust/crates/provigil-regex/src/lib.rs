//! Pattern matchers used by rules and decoders, plus IP and string helpers.

pub mod expression;
pub mod maps;
pub mod os_ip;
pub mod os_match;
pub mod os_regex;
pub mod strings;

pub use expression::{ExpType, Expression, ExpressionError, ExpressionKind, ExpressionMatch, Pcre2Code};
pub use maps::is_valid_hostname_char;
pub use os_ip::{ip_found, ip_found_list, is_valid_ip, IpNet, OsIp};
pub use os_match::{os_match2, OsMatch};
pub use os_regex::{os_regex, os_word_match, OsRegex, RegexMatch};
pub use strings::{str_break, str_how_closed_match, str_is_num, str_starts_with};

pub const OS_RETURN_SUBSTRING: u32 = 128;
pub const OS_CASE_SENSITIVE: u32 = 256;
pub const OS_PATTERN_MAXSIZE: usize = 20480;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegexError {
    /// Never produced; kept so the numbering stays complete.
    #[error("pattern is null")]
    PatternNull = 2,
    #[error("pattern exceeds maximum size")]
    MaxSize = 3,
    /// Never produced.
    #[error("out of memory")]
    OutOfMemory = 4,
    /// Never produced.
    #[error("string is null")]
    StrNull = 5,
    #[error("bad regex (unknown escape sequence)")]
    BadRegex = 6,
    #[error("bad parenthesis")]
    BadParenthesis = 7,
}

/// Cut a subject at its first NUL byte.
pub(crate) fn until_nul(s: &[u8]) -> &[u8] {
    s.iter().position(|&b| b == 0).map_or(s, |z| &s[..z])
}
