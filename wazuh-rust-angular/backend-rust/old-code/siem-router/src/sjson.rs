//! The part of simdjson 3.13.0's DOM API the router's `SchemaAdapter` uses:
//! `dom::parser::parse` (what it accepts), `element[key]`, `get_string`,
//! `get_object` and `internal::string_builder` (minified serialization).
//!
//! Accepted documents: RFC 8259 JSON, valid UTF-8 as a whole, nesting depth
//! below 1024, integers in [-2^63, 2^64), finite doubles (a value that rounds
//! to infinity is an error, an underflow is 0), surrogate escapes only in
//! valid pairs. Integers are INT64 (UINT64 above INT64_MAX), `-0` is the
//! integer 0, anything with a fraction or an exponent is a DOUBLE.

/// simdjson `error_code` messages (`error_message(code)`, the `what()` of
/// `simdjson_error`).
pub const INCORRECT_TYPE: &str = "INCORRECT_TYPE: The JSON element does not have the requested type.";
pub const NO_SUCH_FIELD: &str = "NO_SUCH_FIELD: The JSON field referenced does not exist in this object.";

/// `DEFAULT_MAX_DEPTH`
const MAX_DEPTH: usize = 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum Element {
    Null,
    Bool(bool),
    Int64(i64),
    Uint64(u64),
    Double(f64),
    Str(Vec<u8>),
    Array(Vec<Element>),
    /// Keys in document order, duplicates kept.
    Object(Vec<(Vec<u8>, Element)>),
}

impl Element {
    /// `element[key]` / `at_key`: the first field with exactly this
    /// (unescaped) key.
    pub fn at_key(&self, key: &[u8]) -> Result<&Element, &'static str> {
        match self {
            Element::Object(o) => o.iter().find(|(k, _)| k == key).map(|(_, v)| v).ok_or(NO_SUCH_FIELD),
            _ => Err(INCORRECT_TYPE),
        }
    }

    /// `get_string()`
    pub fn get_string(&self) -> Result<&[u8], &'static str> {
        match self {
            Element::Str(s) => Ok(s),
            _ => Err(INCORRECT_TYPE),
        }
    }

    /// `get_object()` (the element itself when it is an object)
    pub fn get_object(&self) -> Result<&Element, &'static str> {
        match self {
            Element::Object(_) => Ok(self),
            _ => Err(INCORRECT_TYPE),
        }
    }

    /// `string_builder<>::append(element)`: minified JSON.
    pub fn append_to(&self, out: &mut Vec<u8>) {
        match self {
            Element::Null => out.extend_from_slice(b"null"),
            Element::Bool(true) => out.extend_from_slice(b"true"),
            Element::Bool(false) => out.extend_from_slice(b"false"),
            Element::Int64(i) => out.extend_from_slice(i.to_string().as_bytes()),
            Element::Uint64(u) => out.extend_from_slice(u.to_string().as_bytes()),
            Element::Double(d) => siem_njson::dtoa::to_chars(out, *d),
            Element::Str(s) => append_string(out, s),
            Element::Array(a) => {
                out.push(b'[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    v.append_to(out);
                }
                out.push(b']');
            }
            Element::Object(o) => {
                out.push(b'{');
                for (i, (k, v)) in o.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    append_string(out, k);
                    out.push(b':');
                    v.append_to(out);
                }
                out.push(b'}');
            }
        }
    }
}

/// `base_formatter::string`: escapes `"`, `\` and the control characters.
fn append_string(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'"');
    for &c in s {
        match c {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0a => out.extend_from_slice(b"\\n"),
            0x0c => out.extend_from_slice(b"\\f"),
            0x0d => out.extend_from_slice(b"\\r"),
            0..=0x1f => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(c >> 4) as usize]);
                out.push(HEX[(c & 0xf) as usize]);
            }
            _ => out.push(c),
        }
    }
    out.push(b'"');
}

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

/// `structural_or_whitespace`
fn is_structural_or_ws(c: u8) -> bool {
    is_ws(c) || matches!(c, b',' | b':' | b'[' | b']' | b'{' | b'}')
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> P<'a> {
    /// Past the end reads as the space padding of the root scalars.
    fn at(&self, i: usize) -> u8 {
        self.s.get(i).copied().unwrap_or(b' ')
    }

    fn skip_ws(&mut self) {
        while self.i < self.s.len() && is_ws(self.s[self.i]) {
            self.i += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<Element, ()> {
        self.skip_ws();
        match self.s.get(self.i).copied() {
            Some(b'{') => {
                let depth = depth + 1;
                if depth >= MAX_DEPTH {
                    return Err(());
                }
                self.i += 1;
                let mut o = Vec::new();
                self.skip_ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Element::Object(o));
                }
                loop {
                    self.skip_ws();
                    if self.s.get(self.i) != Some(&b'"') {
                        return Err(());
                    }
                    let k = self.string()?;
                    self.skip_ws();
                    if self.s.get(self.i) != Some(&b':') {
                        return Err(());
                    }
                    self.i += 1;
                    let v = self.value(depth)?;
                    o.push((k, v));
                    self.skip_ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Element::Object(o));
                        }
                        _ => return Err(()),
                    }
                }
            }
            Some(b'[') => {
                let depth = depth + 1;
                if depth >= MAX_DEPTH {
                    return Err(());
                }
                self.i += 1;
                let mut a = Vec::new();
                self.skip_ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Element::Array(a));
                }
                loop {
                    a.push(self.value(depth)?);
                    self.skip_ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Element::Array(a));
                        }
                        _ => return Err(()),
                    }
                }
            }
            Some(b'"') => Ok(Element::Str(self.string()?)),
            Some(b't') => self.atom(b"true", Element::Bool(true)),
            Some(b'f') => self.atom(b"false", Element::Bool(false)),
            Some(b'n') => self.atom(b"null", Element::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(()),
        }
    }

    fn atom(&mut self, lit: &[u8], v: Element) -> Result<Element, ()> {
        if self.s[self.i..].starts_with(lit) && is_structural_or_ws(self.at(self.i + lit.len())) {
            self.i += lit.len();
            Ok(v)
        } else {
            Err(())
        }
    }

    fn hex4(&self, at: usize) -> Option<u32> {
        let mut v = 0u32;
        for k in 0..4 {
            let d = (self.s.get(at + k).copied()? as char).to_digit(16)?;
            v = v << 4 | d;
        }
        Some(v)
    }

    /// `parse_string` (no replacement of invalid surrogates)
    fn string(&mut self) -> Result<Vec<u8>, ()> {
        self.i += 1;
        let mut out = Vec::new();
        loop {
            let c = *self.s.get(self.i).ok_or(())?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                0..=0x1f => return Err(()),
                b'\\' => {
                    let e = *self.s.get(self.i + 1).ok_or(())?;
                    if e == b'u' {
                        let mut cp = self.hex4(self.i + 2).ok_or(())?;
                        self.i += 6;
                        if (0xd800..0xdc00).contains(&cp) {
                            if self.s.get(self.i) != Some(&b'\\') || self.s.get(self.i + 1) != Some(&b'u') {
                                return Err(());
                            }
                            let lo = self.hex4(self.i + 2).ok_or(())?;
                            if !(0xdc00..0xe000).contains(&lo) {
                                return Err(());
                            }
                            cp = (((cp - 0xd800) << 10) | (lo - 0xdc00)) + 0x10000;
                            self.i += 6;
                        } else if (0xdc00..0xe000).contains(&cp) {
                            return Err(());
                        }
                        let ch = char::from_u32(cp).ok_or(())?;
                        let mut b = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
                    } else {
                        let r = match e {
                            b'"' => b'"',
                            b'\\' => b'\\',
                            b'/' => b'/',
                            b'b' => 0x08,
                            b'f' => 0x0c,
                            b'n' => b'\n',
                            b'r' => b'\r',
                            b't' => b'\t',
                            _ => return Err(()),
                        };
                        out.push(r);
                        self.i += 2;
                    }
                }
                _ => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
    }

    /// `parse_number`
    fn number(&mut self) -> Result<Element, ()> {
        let start = self.i;
        let negative = self.s[self.i] == b'-';
        let mut p = self.i + negative as usize;
        let start_digits = p;
        while self.at(p).is_ascii_digit() {
            p += 1;
        }
        let digit_count = p - start_digits;
        if digit_count == 0 || (self.s[start_digits] == b'0' && digit_count > 1) {
            return Err(());
        }
        let mut is_float = false;
        if self.at(p) == b'.' {
            is_float = true;
            p += 1;
            let d = p;
            while self.at(p).is_ascii_digit() {
                p += 1;
            }
            if p == d {
                return Err(());
            }
        }
        if matches!(self.at(p), b'e' | b'E') {
            is_float = true;
            p += 1;
            if matches!(self.at(p), b'+' | b'-') {
                p += 1;
            }
            let d = p;
            while self.at(p).is_ascii_digit() {
                p += 1;
            }
            if p == d {
                return Err(());
            }
        }
        if !is_structural_or_ws(self.at(p)) {
            return Err(());
        }
        let text = std::str::from_utf8(&self.s[start..p]).map_err(|_| ())?;
        self.i = p;
        if is_float {
            // correctly rounded like simdjson; infinite results are refused
            let d: f64 = text.parse().map_err(|_| ())?;
            if d.is_infinite() {
                return Err(());
            }
            return Ok(Element::Double(d));
        }
        if negative {
            text.parse::<i64>().map(Element::Int64).map_err(|_| ())
        } else {
            let u: u64 = text.parse().map_err(|_| ())?;
            Ok(if u > i64::MAX as u64 { Element::Uint64(u) } else { Element::Int64(u as i64) })
        }
    }
}

/// `dom::parser::parse(std::string_view)`: `Err` for any error code.
pub fn parse(input: &[u8]) -> Result<Element, ()> {
    if std::str::from_utf8(input).is_err() {
        return Err(());
    }
    let mut p = P { s: input, i: 0 };
    p.skip_ws();
    if p.i == input.len() {
        return Err(());
    }
    let v = p.value(0)?;
    p.skip_ws();
    if p.i != input.len() {
        return Err(());
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn min(s: &str) -> String {
        let mut o = Vec::new();
        parse(s.as_bytes()).unwrap().append_to(&mut o);
        String::from_utf8(o).unwrap()
    }

    #[test]
    fn accepts_and_minifies() {
        assert_eq!(min(r#" { "a" : [1, -0, 1.50, 1e2, 18446744073709551615, -9223372036854775808], "b":"\u00e9\n\u0001\/" } "#), "{\"a\":[1,0,1.5,100.0,18446744073709551615,-9223372036854775808],\"b\":\"\u{e9}\\n\\u0001/\"}");
        assert_eq!(min("\"\\ud83d\\ude00\""), "\"\u{1f600}\"");
        assert_eq!(min("-0.0"), "-0.0");
        assert_eq!(min("1e-400"), "0.0");
    }

    #[test]
    fn rejects() {
        for s in [
            "", "  ", "01", "1.", "-", "1e", "1e400", "18446744073709551616", "-9223372036854775809", "[1,]", "{\"a\"}", "tru",
            "truex", "\"\\ud800\"", "\"\\udc00\"", "\"\\ud800\\u0041\"", "\"\\x\"", "\"a\u{1}\"", "{} x", "[1 2]", "\"\\u12\"",
        ] {
            assert!(parse(s.as_bytes()).is_err(), "{s:?}");
        }
        assert!(parse(&[b'"', 0xff, b'"']).is_err());
        let deep = "[".repeat(1023) + &"]".repeat(1023);
        assert!(parse(deep.as_bytes()).is_ok());
        let deeper = "[".repeat(1024) + &"]".repeat(1024);
        assert!(parse(deeper.as_bytes()).is_err());
    }
}
