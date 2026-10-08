//! `siem-regex`: Wazuh-compatible pattern matching.
//!
//! Port of `src/os_regex/` (OSRegex, OSMatch, OS_WordMatch and string helpers),
//! the `w_expression_t` wrapper from `src/shared/expression.c` (OSRegex /
//! OSMatch / PCRE2 / string / IP list) and the `os_ip` helpers from
//! `src/shared/validate_op.c`.
//!
//! The stock Wazuh ruleset relies on OSRegex's exact (and unusual) semantics,
//! so rules and decoders must use this crate rather than the `regex` crate.

pub mod expression;
pub mod maps;
pub mod os_ip;
pub mod os_match;
pub mod os_regex;
pub mod strings;

pub use expression::{ExpType, Expression, ExpressionError, ExpressionKind, ExpressionMatch};
pub use os_ip::{ip_found, ip_found_list, is_valid_ip, IpNet, OsIp};
pub use os_match::{os_match2, os_word_match, OsMatch};
pub use os_regex::{os_regex, OsRegex, RegexError, RegexMatch, OS_CASE_SENSITIVE, OS_PATTERN_MAXSIZE, OS_RETURN_SUBSTRING};
pub use strings::{str_break, str_how_closed_match, str_is_num, str_starts_with};

/// `isValidChar(c)` used as a truth value (non-zero). Note that
/// cleanevent.c compares `isValidChar(c) == 1`, which is stricter: use
/// `maps::HOSTNAME_MAP[c] == 1` for that.
pub fn is_valid_hostname_char(c: u8) -> bool {
    maps::HOSTNAME_MAP[c as usize] != 0
}
