use crate::{until_nul, RegexError, OS_CASE_SENSITIVE, OS_PATTERN_MAXSIZE};
pub use crate::os_regex::os_word_match;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Anchor {
    Always,
    Equals,
    StartsWith,
    EndsWith,
    Contains,
}

#[derive(Debug, Clone)]
struct Piece {
    text: Vec<u8>,
    anchor: Anchor,
}

#[derive(Debug, Clone)]
pub struct OsMatch {
    raw: String,
    negated: bool,
    pieces: Vec<Piece>,
}

impl OsMatch {
    pub fn compile(pattern: &str, flags: u32) -> Result<OsMatch, RegexError> {
        if pattern.len() > OS_PATTERN_MAXSIZE {
            return Err(RegexError::MaxSize);
        }
        let (negated, body) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern),
        };
        let body = if flags & OS_CASE_SENSITIVE != 0 {
            body.as_bytes().to_vec()
        } else {
            body.as_bytes().to_ascii_lowercase()
        };
        let pieces = body.split(|&b| b == b'|').map(piece).collect();
        Ok(OsMatch { raw: pattern.to_string(), negated, pieces })
    }

    pub fn is_match_bytes(&self, s: &[u8]) -> bool {
        let s = until_nul(s);
        self.pieces.iter().any(|p| p.matches(s)) != self.negated
    }

    pub fn is_match(&self, s: &str) -> bool {
        self.is_match_bytes(s.as_bytes())
    }

    /// The pattern started with `!`.
    pub fn is_negated(&self) -> bool {
        self.negated
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn patterns(&self) -> Vec<&[u8]> {
        self.pieces.iter().map(|p| p.text.as_slice()).collect()
    }
}

fn piece(p: &[u8]) -> Piece {
    let (anchor, text) = match (p.first(), p.last()) {
        (None, _) => (Anchor::Always, p),
        (Some(b'^'), Some(b'$')) if p.len() > 1 => (Anchor::Equals, &p[1..p.len() - 1]),
        (_, Some(b'$')) => (Anchor::EndsWith, &p[..p.len() - 1]),
        (Some(b'^'), _) => (Anchor::StartsWith, &p[1..]),
        _ => (Anchor::Contains, p),
    };
    Piece { text: text.to_vec(), anchor }
}

impl Piece {
    fn matches(&self, s: &[u8]) -> bool {
        let t = &self.text;
        match self.anchor {
            Anchor::Always => true,
            Anchor::Equals => s.eq_ignore_ascii_case(t),
            // A NUL in the piece ends it, and the subject must end at the same place.
            Anchor::StartsWith => match t.iter().position(|&b| b == 0) {
                Some(cut) => s.eq_ignore_ascii_case(&t[..cut]),
                None => s.len() >= t.len() && s[..t.len()].eq_ignore_ascii_case(t),
            },
            Anchor::EndsWith => s.len() >= t.len() && s[s.len() - t.len()..].eq_ignore_ascii_case(t),
            // A contains piece holding a byte >= 0x80 never matches, and an upper-case one only
            // meets a lower-cased subject.
            Anchor::Contains => {
                t.is_ascii()
                    && s.len() >= t.len()
                    && (t.is_empty()
                        || s.windows(t.len()).any(|w| w.iter().zip(t).all(|(a, b)| a.to_ascii_lowercase() == *b)))
            }
        }
    }
}

pub fn os_match2(pattern: &str, s: &str) -> bool {
    OsMatch::compile(pattern, 0).is_ok_and(|m| m.is_match(s))
}
