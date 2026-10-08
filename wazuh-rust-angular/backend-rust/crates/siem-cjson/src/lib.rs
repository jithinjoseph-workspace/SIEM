//! `siem-cjson`: port of cJSON 1.7.18 as pinned by Wazuh (deps v54).
//!
//! Wazuh's JSON output (alerts, archives, wazuh-db payloads, API responses
//! produced in C) and the JSON *decoder* depend on cJSON's exact behaviour:
//! objects keep insertion order and may contain duplicate keys, lookups are
//! case-insensitive, numbers print through `%d` / `%1.15g` / `%1.17g`, control
//! characters escape as `\u00xx`, non-ASCII bytes pass through untouched, and
//! the formatted printer uses tabs. Strings are byte vectors because cJSON
//! never validates UTF-8.

mod number;
pub use number::{fmt_f6, fmt_g, strtod_prefix};

/// `CJSON_NESTING_LIMIT`
pub const NESTING_LIMIT: usize = 1000;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    False,
    True,
    Null,
    /// `valuedouble` and the saturated `valueint`.
    Number { double: f64, int: i32 },
    String(Vec<u8>),
    Array(Vec<Json>),
    /// Members in document order; keys may repeat.
    Object(Vec<(Vec<u8>, Json)>),
    /// `cJSON_Raw`: printed verbatim.
    Raw(Vec<u8>),
}

/// `cJSON_SetNumberHelper` saturation.
pub fn saturate(d: f64) -> i32 {
    if d >= i32::MAX as f64 {
        i32::MAX
    } else if d <= i32::MIN as f64 {
        i32::MIN
    } else if d.is_nan() {
        // (int)NaN is UB in C; x86 gives INT_MIN.
        i32::MIN
    } else {
        d as i32
    }
}

impl Json {
    pub fn number(d: f64) -> Json {
        Json::Number { double: d, int: saturate(d) }
    }

    pub fn string(s: impl AsRef<[u8]>) -> Json {
        Json::String(s.as_ref().to_vec())
    }

    pub fn object() -> Json {
        Json::Object(Vec::new())
    }

    pub fn array() -> Json {
        Json::Array(Vec::new())
    }

    pub fn bool(b: bool) -> Json {
        if b {
            Json::True
        } else {
            Json::False
        }
    }

    /// `cJSON_AddItemToObject` (appends; duplicates allowed).
    pub fn add(&mut self, key: impl AsRef<[u8]>, v: Json) -> &mut Self {
        if let Json::Object(m) = self {
            m.push((key.as_ref().to_vec(), v));
        }
        self
    }

    /// `cJSON_AddStringToObject`; a `None` value adds nothing (as with NULL).
    pub fn add_str(&mut self, key: &str, v: Option<&str>) -> &mut Self {
        if let Some(v) = v {
            self.add(key, Json::string(v));
        }
        self
    }

    /// `cJSON_AddItemToArray`
    pub fn push(&mut self, v: Json) -> &mut Self {
        if let Json::Array(a) = self {
            a.push(v);
        }
        self
    }

    /// `cJSON_GetObjectItem`: first member whose key matches case-insensitively.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.iter().find(|(k, _)| k.eq_ignore_ascii_case(key.as_bytes())).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Json> {
        self.get_mut_bytes(key.as_bytes())
    }

    /// `cJSON_GetObjectItem` with a byte-string key (C keys need not be UTF-8).
    pub fn get_bytes(&self, key: &[u8]) -> Option<&Json> {
        match self {
            Json::Object(m) => m.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_mut_bytes(&mut self, key: &[u8]) -> Option<&mut Json> {
        match self {
            Json::Object(m) => m.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v),
            _ => None,
        }
    }

    /// `cJSON_GetObjectItemCaseSensitive`
    pub fn get_exact(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.iter().find(|(k, _)| k == key.as_bytes()).map(|(_, v)| v),
            _ => None,
        }
    }

    /// `cJSON_DeleteItemFromObject` (first case-insensitive match).
    pub fn remove(&mut self, key: &str) -> Option<Json> {
        if let Json::Object(m) = self {
            if let Some(p) = m.iter().position(|(k, _)| k.eq_ignore_ascii_case(key.as_bytes())) {
                return Some(m.remove(p).1);
            }
        }
        None
    }

    /// `valuestring` as UTF-8 text (lossy).
    pub fn as_str(&self) -> Option<std::borrow::Cow<'_, str>> {
        match self {
            Json::String(s) => Some(String::from_utf8_lossy(s)),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_string(&self) -> bool {
        matches!(self, Json::String(_))
    }

    pub fn is_number(&self) -> bool {
        matches!(self, Json::Number { .. })
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Json::Object(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, Json::Array(_))
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number { double, .. } => Some(*double),
            _ => None,
        }
    }

    /// `valueint`
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Json::Number { int, .. } => Some(*int),
            Json::True => Some(1),
            _ => None,
        }
    }

    /// Children of an array or values of an object.
    pub fn children(&self) -> Vec<&Json> {
        match self {
            Json::Array(a) => a.iter().collect(),
            Json::Object(m) => m.iter().map(|(_, v)| v).collect(),
            _ => Vec::new(),
        }
    }

    /// `cJSON_GetArraySize`
    pub fn len(&self) -> usize {
        match self {
            Json::Array(a) => a.len(),
            Json::Object(m) => m.len(),
            _ => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `cJSON_Print`
    pub fn print(&self) -> Vec<u8> {
        let mut out = Vec::new();
        print_value(self, &mut out, true, 0);
        out
    }

    /// `cJSON_PrintUnformatted`
    pub fn print_unformatted(&self) -> Vec<u8> {
        let mut out = Vec::new();
        print_value(self, &mut out, false, 0);
        out
    }

    pub fn to_string_unformatted(&self) -> String {
        String::from_utf8_lossy(&self.print_unformatted()).into_owned()
    }

    pub fn to_string_formatted(&self) -> String {
        String::from_utf8_lossy(&self.print()).into_owned()
    }
}

// ------------------------------------------------------------------ parsing

struct P<'a> {
    /// Input plus the terminating NUL (`strlen + 1`).
    s: &'a [u8],
    off: usize,
    depth: usize,
}

impl P<'_> {
    fn can_access(&self, i: usize) -> bool {
        self.off + i < self.s.len()
    }
    fn can_read(&self, n: usize) -> bool {
        self.off + n <= self.s.len()
    }
    fn at(&self, i: usize) -> u8 {
        self.s.get(self.off + i).copied().unwrap_or(0)
    }
    fn skip_ws(&mut self) {
        if !self.can_access(0) {
            return;
        }
        while self.can_access(0) && self.at(0) <= 32 {
            self.off += 1;
        }
        if self.off == self.s.len() {
            self.off -= 1;
        }
    }
}

/// `cJSON_ParseWithOpts`. On success returns the item and the offset where
/// parsing stopped (`return_parse_end`); on failure the error offset.
pub fn parse_with_opts(input: &[u8], require_null_terminated: bool) -> Result<(Json, usize), usize> {
    // The C API takes a NUL-terminated string.
    let n = input.iter().position(|&b| b == 0).unwrap_or(input.len());
    let mut buf = input[..n].to_vec();
    buf.push(0);
    let mut p = P { s: &buf, off: 0, depth: 0 };
    // skip_utf8_bom
    if p.can_access(4) && buf.starts_with(b"\xEF\xBB\xBF") {
        p.off += 3;
    }
    p.skip_ws();
    let fail = |p: &P| -> usize {
        if p.off < p.s.len() {
            p.off
        } else {
            p.s.len().saturating_sub(1)
        }
    };
    let item = match parse_value(&mut p) {
        Some(v) => v,
        None => return Err(fail(&p)),
    };
    if require_null_terminated {
        p.skip_ws();
        if p.off >= p.s.len() || p.at(0) != 0 {
            return Err(fail(&p));
        }
    }
    Ok((item, p.off))
}

/// `cJSON_Parse`
pub fn parse(input: &[u8]) -> Option<Json> {
    parse_with_opts(input, false).ok().map(|(j, _)| j)
}

pub fn parse_str(input: &str) -> Option<Json> {
    parse(input.as_bytes())
}

fn parse_value(p: &mut P) -> Option<Json> {
    if p.can_read(4) && &p.s[p.off..p.off + 4] == b"null" {
        p.off += 4;
        return Some(Json::Null);
    }
    if p.can_read(5) && &p.s[p.off..p.off + 5] == b"false" {
        p.off += 5;
        return Some(Json::False);
    }
    if p.can_read(4) && &p.s[p.off..p.off + 4] == b"true" {
        p.off += 4;
        return Some(Json::True);
    }
    if p.can_access(0) && p.at(0) == b'"' {
        return parse_string(p).map(Json::String);
    }
    if p.can_access(0) && (p.at(0) == b'-' || p.at(0).is_ascii_digit()) {
        return parse_number(p);
    }
    if p.can_access(0) && p.at(0) == b'[' {
        return parse_array(p);
    }
    if p.can_access(0) && p.at(0) == b'{' {
        return parse_object(p);
    }
    None
}

fn parse_number(p: &mut P) -> Option<Json> {
    let mut tmp = Vec::new();
    let mut i = 0;
    while i < 63 && p.can_access(i) {
        let c = p.at(i);
        match c {
            b'0'..=b'9' | b'+' | b'-' | b'e' | b'E' | b'.' => tmp.push(c),
            _ => break,
        }
        i += 1;
    }
    let (d, used) = strtod_prefix(&tmp)?;
    p.off += used;
    Some(Json::Number { double: d, int: saturate(d) })
}

fn parse_hex4(s: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for (i, &c) in s.iter().take(4).enumerate() {
        let v = match c {
            b'0'..=b'9' => (c - b'0') as u32,
            b'A'..=b'F' => (c - b'A' + 10) as u32,
            b'a'..=b'f' => (c - b'a' + 10) as u32,
            _ => return 0,
        };
        h += v;
        if i < 3 {
            h <<= 4;
        }
    }
    h
}

/// `utf16_literal_to_utf8`: returns the consumed length (0 = failure).
fn utf16_to_utf8(s: &[u8], pos: usize, end: usize, out: &mut Vec<u8>) -> usize {
    if end < pos + 6 {
        return 0;
    }
    let first = parse_hex4(&s[pos + 2..pos + 6]);
    if (0xDC00..=0xDFFF).contains(&first) {
        return 0;
    }
    let (cp, seq) = if (0xD800..=0xDBFF).contains(&first) {
        let second_pos = pos + 6;
        if end < second_pos + 6 {
            return 0;
        }
        if s[second_pos] != b'\\' || s[second_pos + 1] != b'u' {
            return 0;
        }
        let second = parse_hex4(&s[second_pos + 2..second_pos + 6]);
        if !(0xDC00..=0xDFFF).contains(&second) {
            return 0;
        }
        (0x10000 + (((first & 0x3FF) << 10) | (second & 0x3FF)), 12)
    } else {
        (first, 6)
    };
    let mut cp = cp as u64;
    let (len, mark): (usize, u64) = if cp < 0x80 {
        (1, 0)
    } else if cp < 0x800 {
        (2, 0xC0)
    } else if cp < 0x10000 {
        (3, 0xE0)
    } else if cp <= 0x10FFFF {
        (4, 0xF0)
    } else {
        return 0;
    };
    let mut bytes = [0u8; 4];
    for k in (1..len).rev() {
        bytes[k] = ((cp | 0x80) & 0xBF) as u8;
        cp >>= 6;
    }
    bytes[0] = if len > 1 { ((cp | mark) & 0xFF) as u8 } else { (cp & 0x7F) as u8 };
    out.extend_from_slice(&bytes[..len]);
    seq
}

fn parse_string(p: &mut P) -> Option<Vec<u8>> {
    if p.at(0) != b'"' {
        // fail: offset = input_pointer (one past the current character)
        p.off += 1;
        return None;
    }
    let start = p.off + 1;
    let mut end = start;
    while end < p.s.len() && p.s[end] != b'"' {
        if p.s[end] == b'\\' {
            if end + 1 >= p.s.len() {
                p.off = start;
                return None;
            }
            end += 1;
        }
        end += 1;
    }
    if end >= p.s.len() || p.s[end] != b'"' {
        p.off = start;
        return None;
    }
    let mut out = Vec::with_capacity(end - start);
    let mut i = start;
    while i < end {
        if p.s[i] != b'\\' {
            out.push(p.s[i]);
            i += 1;
            continue;
        }
        let seq = match p.s.get(i + 1).copied().unwrap_or(0) {
            b'b' => {
                out.push(8);
                2
            }
            b'f' => {
                out.push(12);
                2
            }
            b'n' => {
                out.push(b'\n');
                2
            }
            b'r' => {
                out.push(b'\r');
                2
            }
            b't' => {
                out.push(b'\t');
                2
            }
            c @ (b'"' | b'\\' | b'/') => {
                out.push(c);
                2
            }
            b'u' => {
                let n = utf16_to_utf8(p.s, i, end, &mut out);
                if n == 0 {
                    p.off = i;
                    return None;
                }
                n
            }
            _ => {
                p.off = i;
                return None;
            }
        };
        i += seq;
    }
    // A NUL produced by \u0000 terminates the C string.
    if let Some(z) = out.iter().position(|&b| b == 0) {
        out.truncate(z);
    }
    p.off = end + 1;
    Some(out)
}

fn parse_array(p: &mut P) -> Option<Json> {
    if p.depth >= NESTING_LIMIT {
        return None;
    }
    p.depth += 1;
    if p.at(0) != b'[' {
        return None;
    }
    p.off += 1;
    p.skip_ws();
    let mut items = Vec::new();
    if p.can_access(0) && p.at(0) == b']' {
        p.depth -= 1;
        p.off += 1;
        return Some(Json::Array(items));
    }
    if !p.can_access(0) {
        p.off -= 1;
        return None;
    }
    p.off -= 1;
    loop {
        p.off += 1;
        p.skip_ws();
        items.push(parse_value(p)?);
        p.skip_ws();
        if !(p.can_access(0) && p.at(0) == b',') {
            break;
        }
    }
    if !p.can_access(0) || p.at(0) != b']' {
        return None;
    }
    p.depth -= 1;
    p.off += 1;
    Some(Json::Array(items))
}

fn parse_object(p: &mut P) -> Option<Json> {
    if p.depth >= NESTING_LIMIT {
        return None;
    }
    p.depth += 1;
    if !p.can_access(0) || p.at(0) != b'{' {
        return None;
    }
    p.off += 1;
    p.skip_ws();
    let mut items = Vec::new();
    if p.can_access(0) && p.at(0) == b'}' {
        p.depth -= 1;
        p.off += 1;
        return Some(Json::Object(items));
    }
    if !p.can_access(0) {
        p.off -= 1;
        return None;
    }
    p.off -= 1;
    loop {
        if !p.can_access(1) {
            return None;
        }
        p.off += 1;
        p.skip_ws();
        let key = parse_string(p)?;
        p.skip_ws();
        if !p.can_access(0) || p.at(0) != b':' {
            return None;
        }
        p.off += 1;
        p.skip_ws();
        let v = parse_value(p)?;
        items.push((key, v));
        p.skip_ws();
        if !(p.can_access(0) && p.at(0) == b',') {
            break;
        }
    }
    if !p.can_access(0) || p.at(0) != b'}' {
        return None;
    }
    p.depth -= 1;
    p.off += 1;
    Some(Json::Object(items))
}

// ----------------------------------------------------------------- printing

/// `print_string_ptr` (stops at the first NUL like a C string).
pub fn print_string(s: &[u8], out: &mut Vec<u8>) {
    out.push(b'"');
    for &c in s {
        if c == 0 {
            break;
        }
        match c {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            8 => out.extend_from_slice(b"\\b"),
            12 => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            c if c < 32 => out.extend_from_slice(format!("\\u{c:04x}").as_bytes()),
            c => out.push(c),
        }
    }
    out.push(b'"');
}

/// `print_number`
pub fn print_number(d: f64, int: i32, out: &mut Vec<u8>) {
    if d.is_nan() || d.is_infinite() {
        out.extend_from_slice(b"null");
    } else if d == int as f64 {
        out.extend_from_slice(int.to_string().as_bytes());
    } else {
        let s15 = fmt_g(d, 15);
        let back = strtod_prefix(s15.as_bytes()).map(|(v, _)| v);
        let ok = match back {
            Some(t) => {
                let max = d.abs().max(t.abs());
                (t - d).abs() <= max * f64::EPSILON
            }
            None => false,
        };
        let s = if ok { s15 } else { fmt_g(d, 17) };
        out.extend_from_slice(s.as_bytes());
    }
}

fn print_value(v: &Json, out: &mut Vec<u8>, fmt: bool, depth: usize) {
    match v {
        Json::Null => out.extend_from_slice(b"null"),
        Json::False => out.extend_from_slice(b"false"),
        Json::True => out.extend_from_slice(b"true"),
        Json::Number { double, int } => print_number(*double, *int, out),
        Json::Raw(r) => out.extend_from_slice(r.split(|&b| b == 0).next().unwrap_or(&[])),
        Json::String(s) => print_string(s, out),
        Json::Array(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                print_value(e, out, fmt, depth + 1);
                if i + 1 < a.len() {
                    out.push(b',');
                    if fmt {
                        out.push(b' ');
                    }
                }
            }
            out.push(b']');
        }
        Json::Object(m) => {
            let d = depth + 1;
            out.push(b'{');
            if fmt {
                out.push(b'\n');
            }
            for (i, (k, val)) in m.iter().enumerate() {
                if fmt {
                    out.extend(std::iter::repeat_n(b'\t', d));
                }
                print_string(k, out);
                out.push(b':');
                if fmt {
                    out.push(b'\t');
                }
                print_value(val, out, fmt, d);
                if i + 1 < m.len() {
                    out.push(b',');
                }
                if fmt {
                    out.push(b'\n');
                }
            }
            if fmt {
                out.extend(std::iter::repeat_n(b'\t', d - 1));
            }
            out.push(b'}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        let input = " {\"a\":1,\"A\":[true,null,\"x\u{e9}\n\"],\"a\":2.5} trailing";
        let j = parse(input.as_bytes()).unwrap();
        assert_eq!(j.get("a").unwrap().as_f64(), Some(1.0));
        assert_eq!(j.len(), 3);
        // cJSON accepts a raw newline inside a string and escapes it on output.
        assert_eq!(j.to_string_unformatted(), "{\"a\":1,\"A\":[true,null,\"x\u{e9}\\n\"],\"a\":2.5}");
        assert_eq!(j.to_string_formatted(), "{\n\t\"a\":\t1,\n\t\"A\":\t[true, null, \"x\u{e9}\\n\"],\n\t\"a\":\t2.5\n}");
        assert!(parse_with_opts(b"{} x", true).is_err());
        assert_eq!(parse_with_opts(b"[1] x", false).unwrap().1, 3);
    }
}
