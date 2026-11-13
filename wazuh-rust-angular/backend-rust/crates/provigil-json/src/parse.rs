//! Reading documents.
//!
//! The text ends at its first zero byte. Before the value: a UTF-8 byte-order mark is skipped
//! when the text has at least 4 bytes, and every byte up to 0x20 counts as white space. The
//! grammar is JSON's, with these readings:
//!
//! * a number is the longest decimal number (`[+-]digits[.digits][e[+-]digits]`, `1.` and `-.5`
//!   included) among its first 63 bytes from the set `0-9 + - . e E`; it must start with `-` or a
//!   digit;
//! * a string may hold any raw byte except `"`; `\u` with a non-hex digit reads as `\u0000`;
//!   a lone low surrogate, or a high one without its low pair, is an error;
//! * containers nest at most [`MAX_DEPTH`] deep.

use crate::{clamp_i32, Json};

/// The deepest nesting of arrays and objects.
pub const MAX_DEPTH: usize = 1000;

/// A document from the start of `input`. `whole`: only white space may follow the value.
///
/// Ok: the value and the offset just after it. Err: the offset where reading failed, at most
/// the text's length: the byte that is not a value, separator or closing bracket expected there,
/// the first byte of a number that has no digits, the opening quote's next byte for an
/// unterminated string, the backslash of a bad escape, one byte past a key that is not a string.
pub fn parse_with_opts(input: &[u8], whole: bool) -> Result<(Json, usize), usize> {
    let text = &input[..input.iter().position(|&b| b == 0).unwrap_or(input.len())];
    let mut r = Reader { b: text, pos: 0, depth: 0 };
    if text.len() >= 4 && text.starts_with(b"\xEF\xBB\xBF") {
        r.pos = 3;
    }
    r.ws();
    let fail = |r: &Reader| r.pos.min(text.len());
    let v = r.value().ok_or_else(|| fail(&r))?;
    if whole {
        r.ws();
        if r.peek() != 0 {
            return Err(fail(&r));
        }
    }
    Ok((v, r.pos))
}

/// [`parse_with_opts`] without the end check, the offsets dropped.
pub fn parse(input: &[u8]) -> Option<Json> {
    parse_with_opts(input, false).ok().map(|(v, _)| v)
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
    depth: usize,
}

impl Reader<'_> {
    /// The current byte; 0 at the end.
    fn peek(&self) -> u8 {
        self.b.get(self.pos).copied().unwrap_or(0)
    }

    fn ws(&mut self) {
        while self.pos < self.b.len() && self.b[self.pos] <= b' ' {
            self.pos += 1;
        }
    }

    fn value(&mut self) -> Option<Json> {
        let rest = self.b.get(self.pos..).unwrap_or(&[]);
        for (word, v) in [(&b"null"[..], Json::Null), (b"false", Json::False), (b"true", Json::True)] {
            if rest.starts_with(word) {
                self.pos += word.len();
                return Some(v);
            }
        }
        match self.peek() {
            b'"' => self.string().map(Json::String),
            b'-' | b'0'..=b'9' => self.number(),
            b'[' => self.container(b']'),
            b'{' => self.container(b'}'),
            _ => None,
        }
    }

    fn number(&mut self) -> Option<Json> {
        let rest = &self.b[self.pos..];
        let n = rest.iter().take(63).take_while(|c| matches!(c, b'0'..=b'9' | b'+' | b'-' | b'.' | b'e' | b'E')).count();
        let len = decimal_prefix(&rest[..n])?;
        let d: f64 = std::str::from_utf8(&rest[..len]).ok()?.parse().ok()?;
        self.pos += len;
        Some(Json::Number { double: d, int: clamp_i32(d) })
    }

    fn string(&mut self) -> Option<Vec<u8>> {
        if self.peek() != b'"' {
            self.pos += 1;
            return None;
        }
        let start = self.pos + 1;
        // the closing quote: the first one not escaped by a backslash
        let mut end = start;
        while end < self.b.len() && self.b[end] != b'"' {
            end += if self.b[end] == b'\\' { 2 } else { 1 };
        }
        if end >= self.b.len() {
            self.pos = start;
            return None;
        }
        let b = self.b;
        let mut out = Vec::with_capacity(end - start);
        let mut i = start;
        while i < end {
            if b[i] != b'\\' {
                out.push(b[i]);
                i += 1;
                continue;
            }
            let plain = match b[i + 1] {
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                c @ (b'"' | b'\\' | b'/') => c,
                b'u' => match unicode_escape(&b[i..end], &mut out) {
                    Some(used) => {
                        i += used;
                        continue;
                    }
                    None => {
                        self.pos = i;
                        return None;
                    }
                },
                _ => {
                    self.pos = i;
                    return None;
                }
            };
            out.push(plain);
            i += 2;
        }
        // a string ends at a zero byte, also one written as an escape
        if let Some(z) = out.iter().position(|&c| c == 0) {
            out.truncate(z);
        }
        self.pos = end + 1;
        Some(out)
    }

    /// An array (`close` = `]`) or an object (`}`) starting at the current byte.
    fn container(&mut self, close: u8) -> Option<Json> {
        if self.depth >= MAX_DEPTH {
            return None;
        }
        self.depth += 1;
        self.pos += 1;
        self.ws();
        let (mut items, mut members) = (Vec::new(), Vec::new());
        if self.peek() != close {
            loop {
                self.ws();
                if close == b']' {
                    items.push(self.value()?);
                } else {
                    let key = self.string()?;
                    self.ws();
                    if self.peek() != b':' {
                        return None;
                    }
                    self.pos += 1;
                    self.ws();
                    members.push((key, self.value()?));
                }
                self.ws();
                if self.peek() != b',' {
                    break;
                }
                self.pos += 1;
            }
            if self.peek() != close {
                return None;
            }
        }
        self.pos += 1;
        self.depth -= 1;
        Some(if close == b']' { Json::Array(items) } else { Json::Object(members) })
    }
}

/// The length of the longest decimal number at the start of `s` (see the module notes).
fn decimal_prefix(s: &[u8]) -> Option<usize> {
    let digits = |from: usize| s[from..].iter().take_while(|c| c.is_ascii_digit()).count();
    let mut i = usize::from(matches!(s.first(), Some(b'+' | b'-')));
    let whole = digits(i);
    i += whole;
    let mut frac = 0;
    if s.get(i) == Some(&b'.') {
        frac = digits(i + 1);
        if whole + frac > 0 {
            i += 1 + frac;
        }
    }
    if whole + frac == 0 {
        return None;
    }
    if matches!(s.get(i), Some(b'e' | b'E')) {
        let sign = usize::from(matches!(s.get(i + 1), Some(b'+' | b'-')));
        let exp = digits(i + 1 + sign);
        if exp > 0 {
            i += 1 + sign + exp;
        }
    }
    Some(i)
}

/// The value of four hex digits; any other byte among them makes it 0.
fn hex4(s: &[u8]) -> u32 {
    s.iter().try_fold(0u32, |acc, &c| (c as char).to_digit(16).map(|d| acc * 16 + d)).unwrap_or(0)
}

/// `s` starts with `\u` and ends before the closing quote. Writes the UTF-8 of the escape (two
/// for a surrogate pair) and returns the bytes used: 6 or 12. None: cut short, or bad surrogates.
fn unicode_escape(s: &[u8], out: &mut Vec<u8>) -> Option<usize> {
    let first = hex4(s.get(2..6)?);
    let (cp, used) = match first {
        0xDC00..=0xDFFF => return None,
        0xD800..=0xDBFF => {
            if s.get(6..8)? != b"\\u" {
                return None;
            }
            let low = hex4(s.get(8..12)?);
            if !(0xDC00..=0xDFFF).contains(&low) {
                return None;
            }
            (0x10000 + ((first & 0x3FF) << 10 | (low & 0x3FF)), 12)
        }
        cp => (cp, 6),
    };
    let ch = char::from_u32(cp)?;
    out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
    Some(used)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_like_the_protocol() {
        let j = parse(" {\"a\":1,\"A\":[true,null,\"x\u{e9}\n\"],\"a\":2.5} trailing".as_bytes()).unwrap();
        assert_eq!(j.get("a").unwrap().as_f64(), Some(1.0));
        assert_eq!(j.len(), 3);
        assert_eq!(j.print_unformatted(), "{\"a\":1,\"A\":[true,null,\"x\u{e9}\\n\"],\"a\":2.5}".as_bytes());
        assert_eq!(j.print(), "{\n\t\"a\":\t1,\n\t\"A\":\t[true, null, \"x\u{e9}\\n\"],\n\t\"a\":\t2.5\n}".as_bytes());
        assert_eq!(parse_with_opts(b"{} x", true), Err(3));
        assert_eq!(parse_with_opts(b"[1] x", false).unwrap().1, 3);
        assert_eq!(parse_with_opts(b"{\"a\" 1}", true), Err(5));
        assert_eq!(parse_with_opts(b"{1:2}", true), Err(2));
        assert_eq!(parse_with_opts(b"\"abc", true), Err(1));
        assert_eq!(parse(b"\"a\\u00e9\\ud83d\\ude00b\\uZZZZc\""), Some(Json::string("a\u{e9}\u{1F600}b")));
        assert_eq!(parse(b"1.e3x"), Some(Json::number(1000.0)));
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(parse(deep(MAX_DEPTH).as_bytes()).is_some());
        assert!(parse(deep(MAX_DEPTH + 1).as_bytes()).is_none());
    }
}
