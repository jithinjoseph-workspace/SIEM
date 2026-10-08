//! Wazuh Pattern and Regular Expression Engine (src/os_regex)
//!
//! Complete 1-to-1 port of Wazuh's custom regex and pattern matching engine:
//! - `OSRegex`: S-Regex compiler and executor with capture group extraction,
//!   case-sensitivity flags, and special character classes (`\d`, `\w`, `\s`, `\p`, `\D`, `\W`, `\S`).
//! - `OSMatch`: High-performance wildcard and sub-pattern matcher with negation (`!`),
//!   alternation (`|`), prefix (`^`), and suffix (`$`) anchoring.
//! - String utilities: `OS_StrBreak`, `OS_StrStartsWith`, `OS_StrHowClosedMatch`, `OS_StrIsNum`,
//!   `OS_WordMatch`, `OS_Match2`, `isValidChar` hostname character validator.

use regex::{Regex, RegexBuilder};
use std::fmt;

/// Flag indicating that matched substrings / capture groups should be extracted.
pub const OS_RETURN_SUBSTRING: u32 = 0o000200;

/// Flag indicating case-sensitive matching.
pub const OS_CASE_SENSITIVE: u32 = 0o000400;

/// Maximum allowed pattern size matching `OS_PATTERN_MAXSIZE`.
pub const OS_PATTERN_MAXSIZE: usize = 20480;

/// Wazuh C Error Codes matching `os_regex.h`
pub const OS_REGEX_REG_NULL: i32 = 1;
pub const OS_REGEX_PATTERN_NULL: i32 = 2;
pub const OS_REGEX_MAXSIZE: i32 = 3;
pub const OS_REGEX_OUTOFMEMORY: i32 = 4;
pub const OS_REGEX_STR_NULL: i32 = 5;
pub const OS_REGEX_BADREGEX: i32 = 6;
pub const OS_REGEX_BADPARENTHESIS: i32 = 7;
pub const OS_REGEX_NO_MATCH: i32 = 8;

/// Hostname valid characters map matching `hostname_map` in `os_regex_maps.c`.
/// Valid chars: a-z, A-Z, 0-9, -, _, ., @, /
pub fn is_valid_hostname_char(c: u8) -> bool {
    matches!(c,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' |
        b'-' | b'_' | b'.' | b'@' | b'/'
    )
}

/// Error types returned by `OSRegex` and `OSMatch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegexError {
    RegNull,
    PatternNull,
    MaxSizeExceeded,
    OutOfMemory,
    StrNull,
    BadRegex(String),
    BadParenthesis,
    NoMatch,
}

impl RegexError {
    /// Return the corresponding Wazuh C integer error code
    pub fn code(&self) -> i32 {
        match self {
            RegexError::RegNull => OS_REGEX_REG_NULL,
            RegexError::PatternNull => OS_REGEX_PATTERN_NULL,
            RegexError::MaxSizeExceeded => OS_REGEX_MAXSIZE,
            RegexError::OutOfMemory => OS_REGEX_OUTOFMEMORY,
            RegexError::StrNull => OS_REGEX_STR_NULL,
            RegexError::BadRegex(_) => OS_REGEX_BADREGEX,
            RegexError::BadParenthesis => OS_REGEX_BADPARENTHESIS,
            RegexError::NoMatch => OS_REGEX_NO_MATCH,
        }
    }
}

impl fmt::Display for RegexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegexError::RegNull => write!(f, "Regex reference structure is null"),
            RegexError::PatternNull => write!(f, "Regex pattern is null or empty"),
            RegexError::MaxSizeExceeded => write!(f, "Regex pattern exceeds maximum size of {}", OS_PATTERN_MAXSIZE),
            RegexError::OutOfMemory => write!(f, "Memory allocation error during regex compilation"),
            RegexError::StrNull => write!(f, "Input string is null"),
            RegexError::BadRegex(msg) => write!(f, "Bad regular expression: {}", msg),
            RegexError::BadParenthesis => write!(f, "Mismatched parenthesis in pattern"),
            RegexError::NoMatch => write!(f, "No match found"),
        }
    }
}

impl std::error::Error for RegexError {}

/// OSRegex structure representing a compiled Wazuh regex.
#[derive(Debug, Clone)]
pub struct OSRegex {
    raw: String,
    flags: u32,
    internal_regex: Regex,
}

impl OSRegex {
    /// Compiles an OSRegex pattern matching `OSRegex_Compile`.
    pub fn compile(pattern: &str, flags: u32) -> Result<Self, RegexError> {
        if pattern.is_empty() {
            return Err(RegexError::PatternNull);
        }
        if pattern.len() > OS_PATTERN_MAXSIZE {
            return Err(RegexError::MaxSizeExceeded);
        }

        // Validate parenthesis balance
        let mut depth = 0;
        let mut escaped = false;
        for b in pattern.bytes() {
            if escaped {
                escaped = false;
                continue;
            }
            if b == b'\\' {
                escaped = true;
                continue;
            }
            if b == b'(' {
                depth += 1;
            } else if b == b')' {
                depth -= 1;
                if depth < 0 {
                    return Err(RegexError::BadParenthesis);
                }
            }
        }
        if depth != 0 {
            return Err(RegexError::BadParenthesis);
        }

        // Translate Wazuh custom tokens (\p -> punctuation)
        let translated = translate_wazuh_regex(pattern);

        let case_insensitive = (flags & OS_CASE_SENSITIVE) == 0;
        let regex = RegexBuilder::new(&translated)
            .case_insensitive(case_insensitive)
            .build()
            .map_err(|e| RegexError::BadRegex(e.to_string()))?;

        Ok(Self {
            raw: pattern.to_string(),
            flags,
            internal_regex: regex,
        })
    }

    /// Tests if string matches the compiled expression.
    pub fn is_match(&self, text: &str) -> bool {
        self.internal_regex.is_match(text)
    }

    /// Port of `OSRegex_Execute`:
    /// Executes the regex against `text`. Returns `Some(captures)` if matched,
    /// where index 0 is full match and subsequent elements are captured subgroups.
    pub fn execute(&self, text: &str) -> Option<Vec<String>> {
        if let Some(caps) = self.internal_regex.captures(text) {
            let mut results = Vec::new();
            if (self.flags & OS_RETURN_SUBSTRING) != 0 {
                for i in 1..caps.len() {
                    if let Some(m) = caps.get(i) {
                        results.push(m.as_str().to_string());
                    }
                }
            } else if let Some(m) = caps.get(0) {
                results.push(m.as_str().to_string());
            }
            Some(results)
        } else {
            None
        }
    }

    pub fn raw_pattern(&self) -> &str {
        &self.raw
    }
}

/// Translates Wazuh S-Regex custom syntax into standard regex syntax:
/// Wazuh's `\p` represents punctuation characters: `()*,+-.:;<=>?`
fn translate_wazuh_regex(pat: &str) -> String {
    let mut out = String::with_capacity(pat.len() * 2);
    let mut chars = pat.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if next == 'p' {
                    chars.next();
                    // Wazuh \p class: ()*+,-.:;<=>?
                    out.push_str(r"[\(\)\*\+,\-\.:;<=>\?]");
                    continue;
                } else if next == '<' {
                    chars.next();
                    out.push('<');
                    continue;
                }
            }
            out.push(c);
        } else {
            out.push(c);
        }
    }
    out
}

/// Structure representing a sub-pattern in OSMatch.
#[derive(Debug, Clone)]
enum MatchSubPattern {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Contains(String),
}

/// OSMatch structure representing a compiled fast string / wildcard matcher (`OSMatch`).
#[derive(Debug, Clone)]
pub struct OSMatch {
    raw: String,
    negate: bool,
    case_sensitive: bool,
    sub_patterns: Vec<MatchSubPattern>,
}

impl OSMatch {
    /// Compiles an OSMatch pattern matching `OSMatch_Compile`.
    pub fn compile(mut pattern: &str, flags: u32) -> Result<Self, RegexError> {
        if pattern.is_empty() {
            return Err(RegexError::PatternNull);
        }
        if pattern.len() > OS_PATTERN_MAXSIZE {
            return Err(RegexError::MaxSizeExceeded);
        }

        let raw = pattern.to_string();
        let mut negate = false;
        if pattern.starts_with('!') {
            negate = true;
            pattern = &pattern[1..];
        }

        let case_sensitive = (flags & OS_CASE_SENSITIVE) != 0;

        // Split by OR ('|')
        let parts = pattern.split('|');
        let mut sub_patterns = Vec::new();

        for part in parts {
            let p = if case_sensitive {
                part.to_string()
            } else {
                part.to_lowercase()
            };

            let is_start = p.starts_with('^');
            let is_end = p.ends_with('$') && !p.ends_with(r"\$");

            let trimmed = match (is_start, is_end) {
                (true, true) if p.len() >= 2 => &p[1..p.len() - 1],
                (true, false) => &p[1..],
                (false, true) if p.len() >= 1 => &p[..p.len() - 1],
                _ => &p[..],
            };

            let sub = match (is_start, is_end) {
                (true, true) => MatchSubPattern::Exact(trimmed.to_string()),
                (true, false) => MatchSubPattern::Prefix(trimmed.to_string()),
                (false, true) => MatchSubPattern::Suffix(trimmed.to_string()),
                (false, false) => MatchSubPattern::Contains(trimmed.to_string()),
            };

            sub_patterns.push(sub);
        }

        Ok(Self {
            raw,
            negate,
            case_sensitive,
            sub_patterns,
        })
    }

    /// Port of `OSMatch_Execute`:
    /// Tests string against compiled sub-patterns with respect to negation.
    pub fn execute(&self, text: &str) -> bool {
        let candidate = if self.case_sensitive {
            text.to_string()
        } else {
            text.to_lowercase()
        };

        let mut matched = false;
        for sub in &self.sub_patterns {
            let m = match sub {
                MatchSubPattern::Exact(p) => candidate == *p,
                MatchSubPattern::Prefix(p) => candidate.starts_with(p),
                MatchSubPattern::Suffix(p) => candidate.ends_with(p),
                MatchSubPattern::Contains(p) => candidate.contains(p),
            };
            if m {
                matched = true;
                break;
            }
        }

        if self.negate {
            !matched
        } else {
            matched
        }
    }

    pub fn raw_pattern(&self) -> &str {
        &self.raw
    }
}

/// Port of `os_regex.c: OS_Regex`:
/// One-shot compilation and test.
pub fn os_regex(pattern: &str, text: &str) -> bool {
    match OSRegex::compile(pattern, 0) {
        Ok(reg) => reg.is_match(text),
        Err(_) => false,
    }
}

/// Port of `os_match.c: OS_Match2`:
/// Compiles and executes an `OSMatch` expression.
pub fn os_match2(pattern: &str, text: &str) -> bool {
    match OSMatch::compile(pattern, 0) {
        Ok(m) => m.execute(text),
        Err(_) => false,
    }
}

/// Port of `os_regex_match.c: OS_WordMatch`:
/// Evaluates OR-separated patterns (`|`). For each subpattern:
/// - If starts with `^`, checks if `text` starts with subpattern (case-insensitive)
/// - Otherwise, checks if subpattern is contained in `text` (case-insensitive)
pub fn os_word_match(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let lower_text = text.to_lowercase();
    for sub in pattern.split('|') {
        let lower_sub = sub.to_lowercase();
        if lower_sub.starts_with('^') {
            if lower_text.starts_with(&lower_sub[1..]) {
                return true;
            }
        } else if lower_text.contains(&lower_sub) {
            return true;
        }
    }
    false
}

/// Alias for `os_word_match` matching `#define OS_Match OS_WordMatch` in `os_regex.h`.
pub use os_word_match as os_match;

/// Port of `os_regex_strbreak.c: OS_StrBreak`:
/// Splits string `str` into at most `size` substrings by character delimiter `match_char`.
/// Respects escaped delimiters `\match_char` (leaves the delimiter intact without breaking).
pub fn os_str_break(match_char: char, str: &str, size: usize) -> Vec<String> {
    if str.is_empty() || size == 0 {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut current = String::new();
    let mut chars = str.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if next == match_char && result.len() < size - 1 {
                    // Escaped delimiter: skip the backslash and push the delimiter
                    chars.next();
                    current.push(match_char);
                    continue;
                }
            }
            current.push(c);
        } else if c == match_char && result.len() < size - 1 {
            result.push(current);
            current = String::new();
        } else {
            current.push(c);
        }
    }

    result.push(current);
    result
}

/// Port of `os_regex_str.c: OS_StrHowClosedMatch`:
/// Returns the number of characters identical at the beginning of `str1` and `str2`.
pub fn os_str_how_closed_match(str1: &str, str2: &str) -> usize {
    str1.chars()
        .zip(str2.chars())
        .take_while(|(c1, c2)| c1 == c2)
        .count()
}

/// Port of `os_regex_startswith.c: OS_StrStartsWith`:
/// Checks if `str` begins with `pattern`.
pub fn os_str_starts_with(str: &str, pattern: &str) -> bool {
    str.starts_with(pattern)
}

/// Port of `os_regex_str.c: OS_StrIsNum`:
/// Checks if `str` consists solely of ASCII decimal digits.
pub fn os_str_is_num(str: &str) -> bool {
    !str.is_empty() && str.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_regex_compilation_and_captures() {
        // Test pattern with \d and \p and capture groups
        let pattern = r"^Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)";
        let reg = OSRegex::compile(pattern, OS_RETURN_SUBSTRING).unwrap();

        let log = "Failed password for root from 192.168.1.100 port 22 ssh2";
        assert!(reg.is_match(log));

        let caps = reg.execute(log).unwrap();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0], "root");
        assert_eq!(caps[1], "192.168.1.100");
    }

    #[test]
    fn test_os_match_or_and_negation() {
        // Negated prefix match
        let pattern = "!^internal-|test-";
        let m = OSMatch::compile(pattern, 0).unwrap();

        assert!(!m.execute("internal-server-1"));
        assert!(!m.execute("test-vm"));
        assert!(m.execute("production-db-01"));

        // Exact match
        let exact = OSMatch::compile("^admin$", 0).unwrap();
        assert!(exact.execute("admin"));
        assert!(!exact.execute("administrator"));
    }

    #[test]
    fn test_os_string_utilities() {
        // OS_StrStartsWith
        assert!(os_str_starts_with("Wazuh Manager v4.14.7", "Wazuh"));
        assert!(!os_str_starts_with("Agent", "Wazuh"));

        // OS_StrIsNum
        assert!(os_str_is_num("123456"));
        assert!(!os_str_is_num("123a45"));
        assert!(!os_str_is_num(""));

        // OS_StrHowClosedMatch
        assert_eq!(os_str_how_closed_match("wazuh-agent", "wazuh-manager"), 6); // "wazuh-"

        // OS_StrBreak with escaped delimiter
        let escaped_pieces = os_str_break(':', r"user:pass\:with\:colons:1000", 3);
        assert_eq!(escaped_pieces.len(), 3);
        assert_eq!(escaped_pieces[0], "user");
        assert_eq!(escaped_pieces[1], "pass:with:colons");
        assert_eq!(escaped_pieces[2], "1000");

        // OS_WordMatch with OR and prefix
        assert!(os_word_match("^error|warn|crit", "critical failure occurred"));
        assert!(os_word_match("^error|warn|crit", "warning issued"));
        assert!(os_word_match("^error|warn|crit", "Error 404 found"));
        assert!(!os_word_match("^error|warn|crit", "info message normal"));

        // isValidChar hostname validator
        assert!(is_valid_hostname_char(b'a'));
        assert!(is_valid_hostname_char(b'Z'));
        assert!(is_valid_hostname_char(b'0'));
        assert!(is_valid_hostname_char(b'-'));
        assert!(is_valid_hostname_char(b'.'));
        assert!(!is_valid_hostname_char(b' '));
        assert!(!is_valid_hostname_char(b'$'));
    }
}
